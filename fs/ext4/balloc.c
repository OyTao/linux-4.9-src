/*
 *  linux/fs/ext4/balloc.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  Enhanced block allocation by Stephen Tweedie (sct@redhat.com), 1993
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 */

#include <linux/time.h>
#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/quotaops.h>
#include <linux/buffer_head.h>
#include "ext4.h"
#include "ext4_jbd2.h"
#include "mballoc.h"

#include <trace/events/ext4.h>

static unsigned ext4_num_base_meta_clusters(struct super_block *sb,
					    ext4_group_t block_group);
/*
 * balloc.c contains the blocks allocation and deallocation routines
 */

/*
 * Calculate block group number for a given block number
 */
ext4_group_t ext4_get_group_number(struct super_block *sb,
				   ext4_fsblk_t block)
{
	ext4_group_t group;

	if (test_opt2(sb, STD_GROUP_SIZE))
		group = (block -
			 le32_to_cpu(EXT4_SB(sb)->s_es->s_first_data_block)) >>
			(EXT4_BLOCK_SIZE_BITS(sb) + EXT4_CLUSTER_BITS(sb) + 3);
	else
		ext4_get_group_no_and_offset(sb, block, &group, NULL);
	return group;
}

/*
 * Calculate the block group number and offset into the block/cluster
 * allocation bitmap, given a block number
 */
/* OyTao: 根据block idx @blocknr，计算对应的group idx以及在group中的cluster idx*/
void ext4_get_group_no_and_offset(struct super_block *sb, ext4_fsblk_t blocknr,
		ext4_group_t *blockgrpp, ext4_grpblk_t *offsetp)
{
	struct ext4_super_block *es = EXT4_SB(sb)->s_es;
	ext4_grpblk_t offset;

	blocknr = blocknr - le32_to_cpu(es->s_first_data_block);

	/* OyTao: */
	offset = do_div(blocknr, EXT4_BLOCKS_PER_GROUP(sb)) >>
		EXT4_SB(sb)->s_cluster_bits;

	if (offsetp)
		*offsetp = offset;

	if (blockgrpp)
		*blockgrpp = blocknr;

}

/*
 * Check whether the 'block' lives within the 'block_group'. Returns 1 if so
 * and 0 otherwise.
 */
static inline int ext4_block_in_group(struct super_block *sb,
				      ext4_fsblk_t block,
				      ext4_group_t block_group)
{
	ext4_group_t actual_group;

	actual_group = ext4_get_group_number(sb, block);
	return (actual_group == block_group) ? 1 : 0;
}

/* Return the number of clusters used for file system metadata; this
 * represents the overhead needed by the file system.
 */
/* OyTao: TODO */
static unsigned ext4_num_overhead_clusters(struct super_block *sb,
					   ext4_group_t block_group,
					   struct ext4_group_desc *gdp)
{
	unsigned num_clusters;
	int block_cluster = -1, inode_cluster = -1, itbl_cluster = -1, i, c;
	ext4_fsblk_t start = ext4_group_first_block_no(sb, block_group);
	ext4_fsblk_t itbl_blk;
	struct ext4_sb_info *sbi = EXT4_SB(sb);

	/* This is the number of clusters used by the superblock,
	 * block group descriptors, and reserved block group
	 * descriptor blocks */
	num_clusters = ext4_num_base_meta_clusters(sb, block_group);

	/*
	 * For the allocation bitmaps and inode table, we first need
	 * to check to see if the block is in the block group.  If it
	 * is, then check to see if the cluster is already accounted
	 * for in the clusters used for the base metadata cluster, or
	 * if we can increment the base metadata cluster to include
	 * that block.  Otherwise, we will have to track the cluster
	 * used for the allocation bitmap or inode table explicitly.
	 * Normally all of these blocks are contiguous, so the special
	 * case handling shouldn't be necessary except for *very*
	 * unusual file system layouts.
	 */
	if (ext4_block_in_group(sb, ext4_block_bitmap(sb, gdp), block_group)) {
		block_cluster = EXT4_B2C(sbi,
					 ext4_block_bitmap(sb, gdp) - start);
		if (block_cluster < num_clusters)
			block_cluster = -1;
		else if (block_cluster == num_clusters) {
			num_clusters++;
			block_cluster = -1;
		}
	}

	if (ext4_block_in_group(sb, ext4_inode_bitmap(sb, gdp), block_group)) {
		inode_cluster = EXT4_B2C(sbi,
					 ext4_inode_bitmap(sb, gdp) - start);
		if (inode_cluster < num_clusters)
			inode_cluster = -1;
		else if (inode_cluster == num_clusters) {
			num_clusters++;
			inode_cluster = -1;
		}
	}

	itbl_blk = ext4_inode_table(sb, gdp);
	for (i = 0; i < sbi->s_itb_per_group; i++) {
		if (ext4_block_in_group(sb, itbl_blk + i, block_group)) {
			c = EXT4_B2C(sbi, itbl_blk + i - start);
			if ((c < num_clusters) || (c == inode_cluster) ||
			    (c == block_cluster) || (c == itbl_cluster))
				continue;
			if (c == num_clusters) {
				num_clusters++;
				continue;
			}
			num_clusters++;
			itbl_cluster = c;
		}
	}

	if (block_cluster != -1)
		num_clusters++;
	if (inode_cluster != -1)
		num_clusters++;

	return num_clusters;
}

static unsigned int num_clusters_in_group(struct super_block *sb,
					  ext4_group_t block_group)
{
	unsigned int blocks;

	if (block_group == ext4_get_groups_count(sb) - 1) {
		/*
		 * Even though mke2fs always initializes the first and
		 * last group, just in case some other tool was used,
		 * we need to make sure we calculate the right free
		 * blocks.
		 */
		blocks = ext4_blocks_count(EXT4_SB(sb)->s_es) -
			ext4_group_first_block_no(sb, block_group);
	} else
		blocks = EXT4_BLOCKS_PER_GROUP(sb);
	return EXT4_NUM_B2C(EXT4_SB(sb), blocks);
}

/* Initializes an uninitialized block bitmap */
/* OyTao: 初始化group对应的block bitmap */
static int ext4_init_block_bitmap(struct super_block *sb,
				   struct buffer_head *bh,
				   ext4_group_t block_group,
				   struct ext4_group_desc *gdp)
{
	unsigned int bit, bit_max;
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	ext4_fsblk_t start, tmp;
	int flex_bg = 0;
	struct ext4_group_info *grp;

	J_ASSERT_BH(bh, buffer_locked(bh));

	/* If checksum is bad mark all blocks used to prevent allocation
	 * essentially implementing a per-group read-only flag. */
	if (!ext4_group_desc_csum_verify(sb, block_group, gdp)) {
		/* OyTao: TODO */
		grp = ext4_get_group_info(sb, block_group);

		if (!EXT4_MB_GRP_BBITMAP_CORRUPT(grp))
			percpu_counter_sub(&sbi->s_freeclusters_counter,
					   grp->bb_free);

		set_bit(EXT4_GROUP_INFO_BBITMAP_CORRUPT_BIT, &grp->bb_state);
		if (!EXT4_MB_GRP_IBITMAP_CORRUPT(grp)) {
			int count;
			count = ext4_free_inodes_count(sb, gdp);
			percpu_counter_sub(&sbi->s_freeinodes_counter,
					   count);
		}

		set_bit(EXT4_GROUP_INFO_IBITMAP_CORRUPT_BIT, &grp->bb_state);

		return -EFSBADCRC;
	}

	/* OyTao:首先把对应的bitmap对应的buffer head 清零 */
	memset(bh->b_data, 0, sb->s_blocksize);

	/* OyTao: @bit_max: (superblock + gdt blocks) in cluster unit */
	bit_max = ext4_num_base_meta_clusters(sb, block_group);

	/*
	 * OyTao: 每一个cluster对应一个bit,所以meta clusters对应的bytes是
	 * bit_max >> 3(每一个byte 8个bits). 如果meta clusters所占的bytes超过了
	 * buffer head对应的size. 设置EFSCORRUPTED.
	 */
	if ((bit_max >> 3) >= bh->b_size)
		return -EFSCORRUPTED;

	/* OyTao: 所有的meta clusters是紧挨着的。在bitmap中对应的bit设置上 */
	for (bit = 0; bit < bit_max; bit++)
		ext4_set_bit(bit, bh->b_data);

	/* OyTao: first data block idx of group @block_group */
	start = ext4_group_first_block_no(sb, block_group);

	/* OyTao: flex block group feature  TODO */
	if (ext4_has_feature_flex_bg(sb))
		flex_bg = 1;

	/* Set bits for block and inode bitmaps, and inode table */
	/*
	 * OyTao: 分别对data block bitmap(1 block), 
	 *        inode bitmap(1 block ), inode tables包含的blocks(多个block)
	 *		  在group bitmap置上.
	 * TODO
	 * 为什么需要tmp - start.(first data block),如果是first block则合理。
	 */
	tmp = ext4_block_bitmap(sb, gdp);
	if (!flex_bg || ext4_block_in_group(sb, tmp, block_group))
		ext4_set_bit(EXT4_B2C(sbi, tmp - start), bh->b_data);

	tmp = ext4_inode_bitmap(sb, gdp);
	if (!flex_bg || ext4_block_in_group(sb, tmp, block_group))
		ext4_set_bit(EXT4_B2C(sbi, tmp - start), bh->b_data);

	tmp = ext4_inode_table(sb, gdp);
	for (; tmp < ext4_inode_table(sb, gdp) +
		     sbi->s_itb_per_group; tmp++) {
		if (!flex_bg || ext4_block_in_group(sb, tmp, block_group))
			ext4_set_bit(EXT4_B2C(sbi, tmp - start), bh->b_data);
	}

	/*
	 * Also if the number of blocks within the group is less than
	 * the blocksize * 8 ( which is the size of bitmap ), set rest
	 * of the block bitmap to 1
	 */
	ext4_mark_bitmap_end(num_clusters_in_group(sb, block_group),
			     sb->s_blocksize * 8, bh->b_data);
	ext4_block_bitmap_csum_set(sb, block_group, gdp, bh);
	ext4_group_desc_csum_set(sb, block_group, gdp);
	return 0;
}

/* Return the number of free blocks in a block group.  It is used when
 * the block bitmap is uninitialized, so we can't just count the bits
 * in the bitmap. */
unsigned ext4_free_clusters_after_init(struct super_block *sb,
				       ext4_group_t block_group,
				       struct ext4_group_desc *gdp)
{
	return num_clusters_in_group(sb, block_group) - 
		ext4_num_overhead_clusters(sb, block_group, gdp);
}

/*
 * The free blocks are managed by bitmaps.  A file system contains several
 * blocks groups.  Each group contains 1 bitmap block for blocks, 1 bitmap
 * block for inodes, N blocks for the inode table and data blocks.
 *
 * The file system contains group descriptors which are located after the
 * super block.  Each descriptor contains the number of the bitmap block and
 * the free blocks count in the block.  The descriptors are loaded in memory
 * when a file system is mounted (see ext4_fill_super).
 */

/**
 * ext4_get_group_desc() -- load group descriptor from disk
 * @sb:			super block
 * @block_group:	given block group
 * @bh:			pointer to the buffer head to store the block
 *			group descriptor
 */
/*
 * OyTao: 根据group的索引@block_group,在super_info中的s_group_desc数组中找到对应的
 * group_desc 所在的buffer head(包含有效数据）以及对应的group desc数据。
 *
 * block descriptors 都是在ext4_fill_super时候处理的。
 */
struct ext4_group_desc * ext4_get_group_desc(struct super_block *sb,
					     ext4_group_t block_group,
					     struct buffer_head **bh)
{
	unsigned int group_desc;
	unsigned int offset;
	ext4_group_t ngroups = ext4_get_groups_count(sb);
	struct ext4_group_desc *desc;
	struct ext4_sb_info *sbi = EXT4_SB(sb);

	if (block_group >= ngroups) {
		ext4_error(sb, "block_group >= groups_count - block_group = %u,"
			   " groups_count = %u", block_group, ngroups);

		return NULL;
	}

	/* 
	 * OyTao:s_group_desc是在ext4_fill_super中分配 
	 * @group_desc表示在第几个block(group descriptor有多个blocks)
	 * @offset: 表示block_group descriptor 在block中第几个
	 */
	group_desc = block_group >> EXT4_DESC_PER_BLOCK_BITS(sb);
	offset = block_group & (EXT4_DESC_PER_BLOCK(sb) - 1);
	if (!sbi->s_group_desc[group_desc]) {
		ext4_error(sb, "Group descriptor not loaded - "
			   "block_group = %u, group_desc = %u, desc = %u",
			   block_group, group_desc, offset);
		return NULL;
	}

	/*
	 * OyTao: EXT4_DESC_SIZE(sb): group descript 大小。
	 * 获取到对应的desc
	 */
	desc = (struct ext4_group_desc *)(
		(__u8 *)sbi->s_group_desc[group_desc]->b_data +
		offset * EXT4_DESC_SIZE(sb));

	/* OyTao: @*bh,是block group desc所在的block的buffer head */
	if (bh)
		*bh = sbi->s_group_desc[group_desc];

	return desc;
}

/*
 * Return the block number which was discovered to be invalid, or 0 if
 * the block bitmap is valid.
 */
static ext4_fsblk_t ext4_valid_block_bitmap(struct super_block *sb,
					    struct ext4_group_desc *desc,
					    ext4_group_t block_group,
					    struct buffer_head *bh)
{
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	ext4_grpblk_t offset;
	ext4_grpblk_t next_zero_bit;
	ext4_fsblk_t blk;
	ext4_fsblk_t group_first_block;

	if (ext4_has_feature_flex_bg(sb)) {
		/* with FLEX_BG, the inode/block bitmaps and itable
		 * blocks may not be in the group at all
		 * so the bitmap validation will be skipped for those groups
		 * or it has to also read the block group where the bitmaps
		 * are located to verify they are set.
		 */
		return 0;
	}
	group_first_block = ext4_group_first_block_no(sb, block_group);

	/* check whether block bitmap block number is set */
	/* OyTao: 检查data block bitmap 所占的block在group bitmap中是否设置 */
	blk = ext4_block_bitmap(sb, desc);
	offset = blk - group_first_block;
	if (!ext4_test_bit(EXT4_B2C(sbi, offset), bh->b_data))
		/* bad block bitmap */
		return blk;

	/* check whether the inode bitmap block number is set */
	/* OyTao: 检查inode bitmap block对应的cluster, 在group bitmap中是否设置 */
	blk = ext4_inode_bitmap(sb, desc);
	offset = blk - group_first_block;
	if (!ext4_test_bit(EXT4_B2C(sbi, offset), bh->b_data))
		/* bad block bitmap */
		return blk;

	/* check whether the inode table block number is set */
	/* OyTao: 检查inode table所包含的blocks，在group bitmap中是否设置 */
	blk = ext4_inode_table(sb, desc);
	offset = blk - group_first_block;
	next_zero_bit = ext4_find_next_zero_bit(bh->b_data,
			EXT4_B2C(sbi, offset + EXT4_SB(sb)->s_itb_per_group),
			EXT4_B2C(sbi, offset));
	if (next_zero_bit <
	    EXT4_B2C(sbi, offset + EXT4_SB(sb)->s_itb_per_group))
		/* bad bitmap for inode tables */
		return blk;
	return 0;
}

/* 
 * OyTao: 检查block group对应的bitmap的csum, 同时valid meta data 是否已经在bitmap
 * 上已经设置,如果验证通过，设置buffer head verified flag.
 */
static int ext4_validate_block_bitmap(struct super_block *sb,
				      struct ext4_group_desc *desc,
				      ext4_group_t block_group,
				      struct buffer_head *bh)
{
	ext4_fsblk_t	blk;
	struct ext4_group_info *grp = ext4_get_group_info(sb, block_group);
	struct ext4_sb_info *sbi = EXT4_SB(sb);

	if (buffer_verified(bh))
		return 0;
	if (EXT4_MB_GRP_BBITMAP_CORRUPT(grp))
		return -EFSCORRUPTED;

	ext4_lock_group(sb, block_group);
	if (unlikely(!ext4_block_bitmap_csum_verify(sb, block_group,
			desc, bh))) {
		ext4_unlock_group(sb, block_group);
		ext4_error(sb, "bg %u: bad block bitmap checksum", block_group);
		if (!EXT4_MB_GRP_BBITMAP_CORRUPT(grp))
			percpu_counter_sub(&sbi->s_freeclusters_counter,
					   grp->bb_free);
		set_bit(EXT4_GROUP_INFO_BBITMAP_CORRUPT_BIT, &grp->bb_state);
		return -EFSBADCRC;
	}

	blk = ext4_valid_block_bitmap(sb, desc, block_group, bh);
	if (unlikely(blk != 0)) {
		ext4_unlock_group(sb, block_group);
		ext4_error(sb, "bg %u: block %llu: invalid block bitmap",
			   block_group, blk);
		if (!EXT4_MB_GRP_BBITMAP_CORRUPT(grp))
			percpu_counter_sub(&sbi->s_freeclusters_counter,
					   grp->bb_free);
		set_bit(EXT4_GROUP_INFO_BBITMAP_CORRUPT_BIT, &grp->bb_state);
		return -EFSCORRUPTED;
	}

	/* OyTao: 设置buffer header 已经verified */
	set_buffer_verified(bh);

	ext4_unlock_group(sb, block_group);
	return 0;
}

/**
 * ext4_read_block_bitmap_nowait()
 * @sb:			super block
 * @block_group:	given block group
 *
 * Read the bitmap for a given block_group,and validate the
 * bits for block/inode/inode tables are set in the bitmaps
 *
 * Return buffer_head on success or NULL in case of failure.
 */

/* 
 * 获取对应group bitmap对应的buffer head.
 * 如果group_desc中没有设置INIT的标记，则需要初始化对应的bitmap.(metadata clusters
 * 需要在对应的bitmap设置上，同时设置csum。
 * 
 * 如果获取的buffer head没有包含最新数据，则需要读磁盘。
 * 读完成之后，需要validate buffer head.如果通过，需要设置validted flag.
 *
 * buffer head拥有了bitmap最新的数据，则设置了bitmap_uptodate以及buffer_uptodate
 * flags.
 *
 * 在操作对应的buffer head 已经group时候，
 * -- lock buffer head
 *    -- lock group 
 */
struct buffer_head *
ext4_read_block_bitmap_nowait(struct super_block *sb, ext4_group_t block_group)
{
	struct ext4_group_desc *desc;
	struct buffer_head *bh;
	ext4_fsblk_t bitmap_blk;
	int err;

	/* OyTao: 得到group对应的group descriptor. 在s_group_desc中 */
	desc = ext4_get_group_desc(sb, block_group, NULL);
	if (!desc)
		return ERR_PTR(-EFSCORRUPTED);

	/* OyTao: 获取对应group的 bitmap 所在的physical block idx */
	bitmap_blk = ext4_block_bitmap(sb, desc);

	/* OyTao; 获取group bitmap对应的buffer head */
	bh = sb_getblk(sb, bitmap_blk);
	if (unlikely(!bh)) {
		ext4_error(sb, "Cannot get buffer for block bitmap - "
			   "block_group = %u, block_bitmap = %llu",
			   block_group, bitmap_blk);
		return ERR_PTR(-ENOMEM);
	}

	if (bitmap_uptodate(bh))
		goto verify;

	/*
	 * OyTao: locked buffer head, 如果下发了request, 则回在回调函数中
	 * unlock buffer. 
	 * wait_on_buffer 函数会一直阻塞等待buffer unlock
	 */
	lock_buffer(bh);

	if (bitmap_uptodate(bh)) {
		unlock_buffer(bh);
		goto verify;
	}

	/* OyTao: 在操作group bitmap对应的bufferhead, 需要
	 * -- lock buffer head
	 *     -- lock block_group
	 */
	ext4_lock_group(sb, block_group);

	if (desc->bg_flags & cpu_to_le16(EXT4_BG_BLOCK_UNINIT)) {
		/* OyTao: 如果是uninit状态，则需要初始化。首先清零。
		 * 然后把对应的meta blocks (cluster unit)对应的bitmap设置上。
		 * 同时设置csum.
		 */
		err = ext4_init_block_bitmap(sb, bh, block_group, desc);

		/* OyTao: 如果buffer head包含最新的bitmap.设置bitmap_uptodate,
		 * buffer_uptodate flags.
		 */
		set_bitmap_uptodate(bh);

		set_buffer_uptodate(bh);

		ext4_unlock_group(sb, block_group);
		unlock_buffer(bh);
		if (err) {
			ext4_error(sb, "Failed to init block bitmap for group "
				   "%u: %d", block_group, err);
			goto out;
		}
		goto verify;
	}

	ext4_unlock_group(sb, block_group);

	if (buffer_uptodate(bh)) {
		/*
		 * if not uninit if bh is uptodate,
		 * bitmap is also uptodate
		 */
		set_bitmap_uptodate(bh);
		unlock_buffer(bh);
		goto verify;
	}

	/* 
	 * OyTao:如果buffer head不包含最新的数据，但是group bitmap对应的block已经
	 * 初始化过。则需要读取对应的physical block. 读完成后，设置buffer head update.
	 * bitmap update.
	 */
	/*
	 * submit the buffer_head for reading
	 */
	set_buffer_new(bh);
	trace_ext4_read_block_bitmap_load(sb, block_group);
	bh->b_end_io = ext4_end_bitmap_read;
	get_bh(bh);

	submit_bh(REQ_OP_READ, REQ_META | REQ_PRIO, bh);
	return bh;

verify:
	err = ext4_validate_block_bitmap(sb, desc, block_group, bh);
	if (err)
		goto out;
	return bh;
out:
	put_bh(bh);
	return ERR_PTR(err);
}

/* Returns 0 on success, 1 on error */
int ext4_wait_block_bitmap(struct super_block *sb, ext4_group_t block_group,
			   struct buffer_head *bh)
{
	struct ext4_group_desc *desc;

	if (!buffer_new(bh))
		return 0;
	desc = ext4_get_group_desc(sb, block_group, NULL);
	if (!desc)
		return -EFSCORRUPTED;

	/* OyTao: 等待unlock buffer head*/
	wait_on_buffer(bh);

	if (!buffer_uptodate(bh)) {
		ext4_error(sb, "Cannot read block bitmap - "
			   "block_group = %u, block_bitmap = %llu",
			   block_group, (unsigned long long) bh->b_blocknr);
		return -EIO;
	}

	clear_buffer_new(bh);

	/* Panic or remount fs read-only if block bitmap is invalid */
	return ext4_validate_block_bitmap(sb, desc, block_group, bh);
}

/*
 * OyTao: 确保block bitmap对应的buffer head已经拥有了最新的数据。
 * 不管是刚初始化的，或者是page-cache,亦或者是从磁盘上读取的。
 */
struct buffer_head *
ext4_read_block_bitmap(struct super_block *sb, ext4_group_t block_group)
{
	struct buffer_head *bh;
	int err;

	bh = ext4_read_block_bitmap_nowait(sb, block_group);
	if (IS_ERR(bh))
		return bh;

	err = ext4_wait_block_bitmap(sb, block_group, bh);
	if (err) {
		put_bh(bh);
		return ERR_PTR(err);
	}

	return bh;
}

/**
 * ext4_has_free_clusters()
 * @sbi:	in-core super block structure.
 * @nclusters:	number of needed blocks
 * @flags:	flags from ext4_mb_new_blocks()
 *
 * Check if filesystem has nclusters free & available for allocation.
 * On success return 1, return 0 on failure.
 */
/*
 * OyTao: 
 * 有几种情况： 
 * 1. free > dirty + need + s_resverd(sb_info) + resvered(super_block)
 * 2. free > dirty + need + s_resverd(sb_info) (需要一些条件)
 * 3. free > dirty + need
 *	
 *	如果per_cpu_free - per_cpu_dirty - (s_reverd + reverd) < EXT4_FREECLUSTERS_WATERMARK
 *	则free = all_cpu_free, dirty = all_cpu_dirty
 *	
 *	TODO
 */
static int ext4_has_free_clusters(struct ext4_sb_info *sbi,
				  s64 nclusters, unsigned int flags)
{
	/* OyTao: free, dirty, reserved ??? TODO */
	s64 free_clusters, dirty_clusters, rsv, resv_clusters;

	struct percpu_counter *fcc = &sbi->s_freeclusters_counter;
	struct percpu_counter *dcc = &sbi->s_dirtyclusters_counter;

	free_clusters  = percpu_counter_read_positive(fcc);
	dirty_clusters = percpu_counter_read_positive(dcc);
	resv_clusters = atomic64_read(&sbi->s_resv_clusters);

	/*
	 * r_blocks_count should always be multiple of the cluster ratio so
	 * we are safe to do a plane bit shift only.
	 */
	rsv = (ext4_r_blocks_count(sbi->s_es) >> sbi->s_cluster_bits) +
	      resv_clusters;

	if (free_clusters - (nclusters + rsv + dirty_clusters) <
					EXT4_FREECLUSTERS_WATERMARK) {
		free_clusters  = percpu_counter_sum_positive(fcc);
		dirty_clusters = percpu_counter_sum_positive(dcc);
	}

	/* Check whether we have space after accounting for current
	 * dirty clusters & root reserved clusters.
	 */
	if (free_clusters >= (rsv + nclusters + dirty_clusters))
		return 1;

	/* Hm, nope.  Are (enough) root reserved clusters available? */
	/* OyTao: TODO */
	if (uid_eq(sbi->s_resuid, current_fsuid()) ||
	    (!gid_eq(sbi->s_resgid, GLOBAL_ROOT_GID) && in_group_p(sbi->s_resgid)) ||
	    capable(CAP_SYS_RESOURCE) ||
	    (flags & EXT4_MB_USE_ROOT_BLOCKS)) {

		if (free_clusters >= (nclusters + dirty_clusters +
				      resv_clusters))
			return 1;
	}

	/* No free blocks. Let's see if we can dip into reserved pool */
	if (flags & EXT4_MB_USE_RESERVED) {
		if (free_clusters >= (nclusters + dirty_clusters))
			return 1;
	}

	return 0;
}

/*
 * OyTao: 尝试分配@nclusters.
 * 如果有足够的cluster,则分配，将@nclusters 加入per_cpu dirty clusters计数中。
 */
int ext4_claim_free_clusters(struct ext4_sb_info *sbi,
			     s64 nclusters, unsigned int flags)
{
	if (ext4_has_free_clusters(sbi, nclusters, flags)) {
		percpu_counter_add(&sbi->s_dirtyclusters_counter, nclusters);
		return 0;
	} else
		return -ENOSPC;
}

/**
 * ext4_should_retry_alloc()
 * @sb:			super block
 * @retries		number of attemps has been made
 *
 * ext4_should_retry_alloc() is called when ENOSPC is returned, and if
 * it is profitable to retry the operation, this function will wait
 * for the current or committing transaction to complete, and then
 * return TRUE.
 *
 * if the total number of retries exceed three times, return FALSE.
 */
int ext4_should_retry_alloc(struct super_block *sb, int *retries)
{
	if (!ext4_has_free_clusters(EXT4_SB(sb), 1, 0) ||
	    (*retries)++ > 3 ||
	    !EXT4_SB(sb)->s_journal)
		return 0;

	jbd_debug(1, "%s: retrying operation after ENOSPC\n", sb->s_id);

	smp_mb();
	if (EXT4_SB(sb)->s_mb_free_pending)
		jbd2_journal_force_commit_nested(EXT4_SB(sb)->s_journal);
	return 1;
}

/*
 * ext4_new_meta_blocks() -- allocate block for meta data (indexing) blocks
 *
 * @handle:             handle to this transaction
 * @inode:              file inode
 * @goal:               given target block(filesystem wide)
 * @count:		pointer to total number of clusters needed
 * @errp:               error code
 *
 * Return 1st allocated block number on success, *count stores total account
 * error stores in errp pointer
 */
ext4_fsblk_t ext4_new_meta_blocks(handle_t *handle, struct inode *inode,
				  ext4_fsblk_t goal, unsigned int flags,
				  unsigned long *count, int *errp)
{
	struct ext4_allocation_request ar;
	ext4_fsblk_t ret;

	memset(&ar, 0, sizeof(ar));
	/* Fill with neighbour allocated blocks */
	ar.inode = inode;
	ar.goal = goal;
	ar.len = count ? *count : 1;
	ar.flags = flags;

	ret = ext4_mb_new_blocks(handle, &ar, errp);
	if (count)
		*count = ar.len;
	/*
	 * Account for the allocated meta blocks.  We will never
	 * fail EDQUOT for metdata, but we do account for it.
	 */
	if (!(*errp) && (flags & EXT4_MB_DELALLOC_RESERVED)) {
		dquot_alloc_block_nofail(inode,
				EXT4_C2B(EXT4_SB(inode->i_sb), ar.len));
	}
	return ret;
}

/**
 * ext4_count_free_clusters() -- count filesystem free clusters
 * @sb:		superblock
 *
 * Adds up the number of free clusters from each block group.
 */
ext4_fsblk_t ext4_count_free_clusters(struct super_block *sb)
{
	ext4_fsblk_t desc_count;
	struct ext4_group_desc *gdp;
	ext4_group_t i;
	ext4_group_t ngroups = ext4_get_groups_count(sb);
	struct ext4_group_info *grp;
#ifdef EXT4FS_DEBUG
	struct ext4_super_block *es;
	ext4_fsblk_t bitmap_count;
	unsigned int x;
	struct buffer_head *bitmap_bh = NULL;

	es = EXT4_SB(sb)->s_es;
	desc_count = 0;
	bitmap_count = 0;
	gdp = NULL;

	for (i = 0; i < ngroups; i++) {
		gdp = ext4_get_group_desc(sb, i, NULL);
		if (!gdp)
			continue;
		grp = NULL;
		if (EXT4_SB(sb)->s_group_info)
			grp = ext4_get_group_info(sb, i);
		if (!grp || !EXT4_MB_GRP_BBITMAP_CORRUPT(grp))
			desc_count += ext4_free_group_clusters(sb, gdp);
		brelse(bitmap_bh);
		bitmap_bh = ext4_read_block_bitmap(sb, i);
		if (IS_ERR(bitmap_bh)) {
			bitmap_bh = NULL;
			continue;
		}

		x = ext4_count_free(bitmap_bh->b_data,
				    EXT4_CLUSTERS_PER_GROUP(sb) / 8);
		printk(KERN_DEBUG "group %u: stored = %d, counted = %u\n",
			i, ext4_free_group_clusters(sb, gdp), x);
		bitmap_count += x;
	}
	brelse(bitmap_bh);
	printk(KERN_DEBUG "ext4_count_free_clusters: stored = %llu"
	       ", computed = %llu, %llu\n",
	       EXT4_NUM_B2C(EXT4_SB(sb), ext4_free_blocks_count(es)),
	       desc_count, bitmap_count);
	return bitmap_count;
#else
	desc_count = 0;
	for (i = 0; i < ngroups; i++) {
		gdp = ext4_get_group_desc(sb, i, NULL);
		if (!gdp)
			continue;
		grp = NULL;
		if (EXT4_SB(sb)->s_group_info)
			grp = ext4_get_group_info(sb, i);
		if (!grp || !EXT4_MB_GRP_BBITMAP_CORRUPT(grp))
			desc_count += ext4_free_group_clusters(sb, gdp);
	}

	return desc_count;
#endif
}

static inline int test_root(ext4_group_t a, int b)
{
	while (1) {
		if (a < b)
			return 0;
		if (a == b)
			return 1;
		if ((a % b) != 0)
			return 0;
		a = a / b;
	}
}

/**
 *	ext4_bg_has_super - number of blocks used by the superblock in group
 *	@sb: superblock for filesystem
 *	@group: group number to check
 *
 *	Return the number of blocks used by the superblock (primary or backup)
 *	in this group.  Currently this will be only 0 or 1.
 */
int ext4_bg_has_super(struct super_block *sb, ext4_group_t group)
{
	struct ext4_super_block *es = EXT4_SB(sb)->s_es;

	/* OyTao: group 0拥有super block */
	if (group == 0)
		return 1;

	/* OyTao: sparse super2 feature TODO */
	if (ext4_has_feature_sparse_super2(sb)) {
		if (group == le32_to_cpu(es->s_backup_bgs[0]) ||
		    group == le32_to_cpu(es->s_backup_bgs[1]))
			return 1;
		return 0;
	}

	/* OyTao: TODO */
	if ((group <= 1) || !ext4_has_feature_sparse_super(sb))
		return 1;

	if (!(group & 1))
		return 0;

	/* 
	 * OyTao:如果是3, 3 * 3, 3 * 3 .. 3,
	 *			   5, 5 * 5, 5 * 5 .. 5,
	 *			   7, 7 * 7, 7 * 7 .. 7
	 * 都包含super block 
	 */
	if (test_root(group, 3) || (test_root(group, 5)) ||
	    test_root(group, 7))
		return 1;

	return 0;
}

static unsigned long ext4_bg_num_gdb_meta(struct super_block *sb,
					ext4_group_t group)
{
	unsigned long metagroup = group / EXT4_DESC_PER_BLOCK(sb);
	ext4_group_t first = metagroup * EXT4_DESC_PER_BLOCK(sb);
	ext4_group_t last = first + EXT4_DESC_PER_BLOCK(sb) - 1;

	if (group == first || group == first + 1 || group == last)
		return 1;
	return 0;
}

static unsigned long ext4_bg_num_gdb_nometa(struct super_block *sb,
					ext4_group_t group)
{
	if (!ext4_bg_has_super(sb, group))
		return 0;

	if (ext4_has_feature_meta_bg(sb))
		return le32_to_cpu(EXT4_SB(sb)->s_es->s_first_meta_bg);
	else
		return EXT4_SB(sb)->s_gdb_count;
}

/**
 *	ext4_bg_num_gdb - number of blocks used by the group table in group
 *	@sb: superblock for filesystem
 *	@group: group number to check
 *
 *	Return the number of blocks used by the group descriptor table
 *	(primary or backup) in this group.  In the future there may be a
 *	different number of descriptor blocks in each group.
 */
unsigned long ext4_bg_num_gdb(struct super_block *sb, ext4_group_t group)
{
	unsigned long first_meta_bg =
			le32_to_cpu(EXT4_SB(sb)->s_es->s_first_meta_bg);
	unsigned long metagroup = group / EXT4_DESC_PER_BLOCK(sb);

	if (!ext4_has_feature_meta_bg(sb) || metagroup < first_meta_bg)
		return ext4_bg_num_gdb_nometa(sb, group);

	return ext4_bg_num_gdb_meta(sb,group);

}

/*
 * This function returns the number of file system metadata clusters at
 * the beginning of a block group, including the reserved gdt blocks.
 */

/*
 * OyTao: meta block group feature TODO
 */
/* 
 * OyTao:确定在@block_group中，包含的super block 以及group descriptors Table
 * 所占的blocks number.
 * 返回的是cluster numbers.(block numbers --> cluster numbers) 
 */
static unsigned ext4_num_base_meta_clusters(struct super_block *sb,
				     ext4_group_t block_group)
{
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	unsigned num;

	/* Check for superblock and gdt backups in this group */
	/* OyTao: 确定是否包含super block */
	num = ext4_bg_has_super(sb, block_group);

	/* OyTao: 计算在该group中包含的gdt所占的blocks */
	if (!ext4_has_feature_meta_bg(sb) ||
	    block_group < le32_to_cpu(sbi->s_es->s_first_meta_bg) *
			  sbi->s_desc_per_block) {

		if (num) {
			num += ext4_bg_num_gdb(sb, block_group);
			num += le16_to_cpu(sbi->s_es->s_reserved_gdt_blocks);
		}

	} else { /* For META_BG_BLOCK_GROUPS */
		/* OyTao: meta block group feature TODO */
		num += ext4_bg_num_gdb(sb, block_group);
	}

	/* OyTao: block --> chunk */
	return EXT4_NUM_B2C(sbi, num);
}
/**
 *	ext4_inode_to_goal_block - return a hint for block allocation
 *	@inode: inode for block allocation
 *
 *	Return the ideal location to start allocating blocks for a
 *	newly created inode.
 */
/* OyTao: 根据inode所在的block group，返回随机的goal block idx ,
 * 如果是DelayAllocate， 则设置为block group first data block */
ext4_fsblk_t ext4_inode_to_goal_block(struct inode *inode)
{
	struct ext4_inode_info *ei = EXT4_I(inode);
	ext4_group_t block_group;
	ext4_grpblk_t colour;
	int flex_size = ext4_flex_bg_size(EXT4_SB(inode->i_sb));
	ext4_fsblk_t bg_start;
	ext4_fsblk_t last_block;

	block_group = ei->i_block_group;

	/* OyTao: flexible group 机制 */ 
	if (flex_size >= EXT4_FLEX_SIZE_DIR_ALLOC_SCHEME) {
		/*
		 * If there are at least EXT4_FLEX_SIZE_DIR_ALLOC_SCHEME
		 * block groups per flexgroup, reserve the first block
		 * group for directories and special files.  Regular
		 * files will start at the second block group.  This
		 * tends to speed up directory access and improves
		 * fsck times.
		 */
		block_group &= ~(flex_size-1);
		if (S_ISREG(inode->i_mode))
			block_group++;
	}

	/* OyTao: 获取inode所在的block group第一个data block */
	bg_start = ext4_group_first_block_no(inode->i_sb, block_group);

	/* OyTao: */
	last_block = ext4_blocks_count(EXT4_SB(inode->i_sb)->s_es) - 1;

	/*
	 * If we are doing delayed allocation, we don't need take
	 * colour into account.
	 */
	/* OyTao: 如果设置了延迟分配，则返回对应的第一个data block位置 */
	if (test_opt(inode->i_sb, DELALLOC))
		return bg_start;

	/* OyTao: 增加colour,减少在同一个block group内部申请goal的竞争 */
	/* OyTao: TODO why bg_start + BLOCKS_PER_GROUP <　last_block */
	if (bg_start + EXT4_BLOCKS_PER_GROUP(inode->i_sb) <= last_block)
		colour = (current->pid % 16) *
			(EXT4_BLOCKS_PER_GROUP(inode->i_sb) / 16);
	else
		colour = (current->pid % 16) * ((last_block - bg_start) / 16);

	return bg_start + colour;
}

