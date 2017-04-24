/*
 * linux/fs/ext4/readpage.c
 *
 * Copyright (C) 2002, Linus Torvalds.
 * Copyright (C) 2015, Google, Inc.
 *
 * This was originally taken from fs/mpage.c
 *
 * The intent is the ext4_mpage_readpages() function here is intended
 * to replace mpage_readpages() in the general case, not just for
 * encrypted files.  It has some limitations (see below), where it
 * will fall back to read_block_full_page(), but these limitations
 * should only be hit when page_size != block_size.
 *
 * This will allow us to attach a callback function to support ext4
 * encryption.
 *
 * If anything unusual happens, such as:
 *
 * - encountering a page which has buffers
 * - encountering a page which has a non-hole after a hole
 * - encountering a page with non-contiguous blocks
 *
 * then this code just gives up and calls the buffer_head-based read function.
 * It does handle a page which has holes at the end - that is a common case:
 * the end-of-file on blocksize < PAGE_SIZE setups.
 *
 */

#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/mm.h>
#include <linux/kdev_t.h>
#include <linux/gfp.h>
#include <linux/bio.h>
#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <linux/blkdev.h>
#include <linux/highmem.h>
#include <linux/prefetch.h>
#include <linux/mpage.h>
#include <linux/writeback.h>
#include <linux/backing-dev.h>
#include <linux/pagevec.h>
#include <linux/cleancache.h>

#include "ext4.h"

static inline bool ext4_bio_encrypted(struct bio *bio)
{
#ifdef CONFIG_EXT4_FS_ENCRYPTION
	return unlikely(bio->bi_private != NULL);
#else
	return false;
#endif
}

/*
 * I/O completion handler for multipage BIOs.
 *
 * The mpage code never puts partial pages into a BIO (except for end-of-file).
 * If a page does not map to a contiguous run of blocks then it simply falls
 * back to block_read_full_page().
 *
 * Why is this?  If a page's completion depends on a number of different BIOs
 * which can complete in any order (or at the same time) then determining the
 * status of that page is hard.  See end_buffer_async_read() for the details.
 * There is no point in duplicating all that complexity.
 */
static void mpage_end_io(struct bio *bio)
{
	struct bio_vec *bv;
	int i;

	if (ext4_bio_encrypted(bio)) {
		if (bio->bi_error) {
			fscrypt_release_ctx(bio->bi_private);
		} else {
			fscrypt_decrypt_bio_pages(bio->bi_private, bio);
			return;
		}
	}
	bio_for_each_segment_all(bv, bio, i) {
		struct page *page = bv->bv_page;

		if (!bio->bi_error) {
			SetPageUptodate(page);
		} else {
			ClearPageUptodate(page);
			SetPageError(page);
		}
		unlock_page(page);
	}

	bio_put(bio);
}

/*
 * OyTao: 如果是读一个page，则nr_pages = 1, page不为空；
 * 如果nr_pages > 1, 则page = NULL, pages包括多个page.
 * pages当中包含的pages都没有加入到pagecache中。
 */
int ext4_mpage_readpages(struct address_space *mapping,
			 struct list_head *pages, struct page *page,
			 unsigned nr_pages)
{
	struct bio *bio = NULL;
	sector_t last_block_in_bio = 0;

	struct inode *inode = mapping->host;
	const unsigned blkbits = inode->i_blkbits;
	const unsigned blocks_per_page = PAGE_SIZE >> blkbits;
	const unsigned blocksize = 1 << blkbits;

	sector_t block_in_file;
	sector_t last_block;
	sector_t last_block_in_file;
	sector_t blocks[MAX_BUF_PER_PAGE];
	unsigned page_block;
	struct block_device *bdev = inode->i_sb->s_bdev;
	int length;
	unsigned relative_block = 0;
	struct ext4_map_blocks map;

	map.m_pblk = 0;
	map.m_lblk = 0;
	map.m_len = 0;
	map.m_flags = 0;

	for (; nr_pages; nr_pages--) {
		int fully_mapped = 1;
		unsigned first_hole = blocks_per_page;

		prefetchw(&page->flags);

		if (pages) {
			page = list_entry(pages->prev, struct page, lru);
			/*
			 * OyTao: page目前只在list @pages上，首先从该链表中删除，然后加入到
			 * pagecache中。
			 */
			list_del(&page->lru);

			/*
			 * OyTao: 将该page添加到page cache中。hold pages.
       * 如果返回值不等于0,则表示已经有page加入到page cache 中。
       * 否则，page locked, 并且加入到了page cache中。
			 */
			if (add_to_page_cache_lru(page, mapping, page->index,
				  readahead_gfp_mask(mapping)))
				goto next_page;
		}

		/* OyTao: 如果对应的page有了buffer head */
		if (page_has_buffers(page))
			goto confused;

		/*
		 * OyTao: @block_in_file: page所对应的block idx
		 */
		block_in_file = (sector_t)page->index << (PAGE_SHIFT - blkbits);

		/*
		 * OyTao: @last_block: nr pages最后一个对应的block idx, 
		 * 会与文件的大小进行比较
		 */
		last_block = block_in_file + nr_pages * blocks_per_page;
		last_block_in_file = (i_size_read(inode) + blocksize - 1) >> blkbits;
		if (last_block > last_block_in_file)
			last_block = last_block_in_file;

		/* OyTao: page中已经读完的blocks数目 */
		page_block = 0;

		/*
		 * Map blocks using the previous result first.
		 */
		/*
		 * OyTao: 如果block_in_file已经在 map_blocks 中, 
		 */
		if ((map.m_flags & EXT4_MAP_MAPPED) &&
		    block_in_file > map.m_lblk &&
		    block_in_file < (map.m_lblk + map.m_len)) {
			unsigned map_offset = block_in_file - map.m_lblk;
			unsigned last = map.m_len - map_offset;

			for (relative_block = 0; ; relative_block++) {
        /* OyTao: 如果整个map都已经读取完了，则取消EXT4_MAP_MAPPED flag */
				if (relative_block == last) {
					/* needed? */
					map.m_flags &= ~EXT4_MAP_MAPPED;
					break;
				}

        /* OyTao: 如果已经拿到一个page所有的blocks physical address, 则退出 */
				if (page_block == blocks_per_page)
					break;
        
        /* OyTao: 对应block的physical address */
				blocks[page_block] = map.m_pblk + map_offset +
					relative_block;
				page_block++;
				block_in_file++;
			}
		}

		/*
		 * Then do more ext4_map_blocks() calls until we are
		 * done with this page.
		 */
		while (page_block < blocks_per_page) {

			if (block_in_file < last_block) {
        /*
         * OyTao: 从@block_in_file ---> last,通过map_blocks查找对应的physical blocks,
         * 如果没有则退出 flag= 0 
         */
				map.m_lblk = block_in_file;
				map.m_len = last_block - block_in_file;
				if (ext4_map_blocks(NULL, inode, &map, 0) < 0) {

				set_error_page:
					SetPageError(page);
					zero_user_segment(page, 0,
							  PAGE_SIZE);
					unlock_page(page);
					goto next_page;
				}
			}

      /* OyTao: block_in_file --> last没有mapped  */
			if ((map.m_flags & EXT4_MAP_MAPPED) == 0) {
				fully_mapped = 0;
        /* OyTao: first_hole初始化为block_per_page */
				if (first_hole == blocks_per_page)
					first_hole = page_block;
				page_block++;
				block_in_file++;
				continue;
			}

      /* OyTao: 如果此时map_mapped,与上次ext4_map_blocks不一致 */
			if (first_hole != blocks_per_page)
				goto confused;		/* hole -> non-hole */

			/* Contiguous blocks? */
      /* OyTao: 如果一个page内部的block不连续， 则submit 之前的bio */
			if (page_block && blocks[page_block-1] != map.m_pblk-1)
				goto confused;

      /* 
       * OyTao: 此时，map.flags & EXT4_MAP_MAPPED,所以为当前paged的blocks获取对应的physical
       * blocks address。并且与之前的block在physical address上连续。
       */
			for (relative_block = 0; ; relative_block++) {
				if (relative_block == map.m_len) {
					/* needed? */
					map.m_flags &= ~EXT4_MAP_MAPPED;
					break;
				} else if (page_block == blocks_per_page)
					break;
				blocks[page_block] = map.m_pblk+relative_block;
				page_block++;
				block_in_file++;
			}
		}

    /* 
     * OyTao: first_hole初始话为blocks_per_page,如果不等于，则表示file中有一部分没有
     * 映射physical blocks,存在空洞
     */
		if (first_hole != blocks_per_page) {
      
      /* OyTao: 从fist_hole开始到page结束，填写0 */
			zero_user_segment(page, first_hole << blkbits,
					  PAGE_SIZE);

      /* OyTao: 如果是整个page hole */
			if (first_hole == 0) {
				SetPageUptodate(page);
				unlock_page(page);
				goto next_page;
			}

		} else if (fully_mapped) {
      /* OyTao:如果page都已经mapped, 则设置mappedTODisk flag */
			SetPageMappedToDisk(page);
		}

    /* OyTao: TODO */
		if (fully_mapped && blocks_per_page == 1 &&
		    !PageUptodate(page) && cleancache_get_page(page) == 0) {
			SetPageUptodate(page);
			goto confused;
		}

		/*
		 * This page will go to BIO.  Do we need to send this
		 * BIO off first?
		 */
    /* OyTao:如果当前page所在的第一个block physical address 与上一个page最后block对应的
     * physical address 不连续，则submit bio 
     */
		if (bio && (last_block_in_bio != blocks[0] - 1)) {
		submit_and_realloc:
			submit_bio(bio);
			bio = NULL;
		}

		if (bio == NULL) {
      /* OyTao: encrypted features TODO */
			struct fscrypt_ctx *ctx = NULL;
			if (ext4_encrypted_inode(inode) &&
			    S_ISREG(inode->i_mode)) {
				ctx = fscrypt_get_ctx(inode, GFP_NOFS);
				if (IS_ERR(ctx))
					goto set_error_page;
			}

      /*
       * OyTao: 分配@nr_pages个page,如果后续的pages在physcial address上连续，则不需要再额外分配
       * bio,只需要add_pages
       */ 
			bio = bio_alloc(GFP_KERNEL,
				min_t(int, nr_pages, BIO_MAX_PAGES));

			if (!bio) {
				if (ctx)
					fscrypt_release_ctx(ctx);
				goto set_error_page;
			}

			bio->bi_bdev = bdev;
			bio->bi_iter.bi_sector = blocks[0] << (blkbits - 9);
			bio->bi_end_io = mpage_end_io;
			bio->bi_private = ctx;
			bio_set_op_attrs(bio, REQ_OP_READ, 0);
		}

		length = first_hole << blkbits;

		if (bio_add_page(bio, page, length, 0) < length)
			goto submit_and_realloc;

    /* OyTao: TODO BOUNDARY_FLAG, 如果有空洞，也需要提交submit bio */
		if (((map.m_flags & EXT4_MAP_BOUNDARY) &&
		     (relative_block == map.m_len)) ||
		    (first_hole != blocks_per_page)) {
			submit_bio(bio);
			bio = NULL;
		} else
      /* OyTao: @last_block_in_bio */
			last_block_in_bio = blocks[blocks_per_page - 1];

    /* OyTao: 当前Page已经处理完成 */
		goto next_page;

	confused:
		if (bio) {
			submit_bio(bio);
			bio = NULL;
		}

		if (!PageUptodate(page))
			block_read_full_page(page, ext4_get_block);
		else
			unlock_page(page);

	next_page:
		if (pages)
			put_page(page);
	}


	BUG_ON(pages && !list_empty(pages));
	if (bio)
		submit_bio(bio);
	return 0;
}
