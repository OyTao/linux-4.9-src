#ifndef _UAPI_LINUX_STAT_H
#define _UAPI_LINUX_STAT_H


#if defined(__KERNEL__) || !defined(__GLIBC__) || (__GLIBC__ < 2)

#define S_IFMT  00170000
#define S_IFSOCK 0140000
#define S_IFLNK	 0120000
#define S_IFREG  0100000
#define S_IFBLK  0060000
#define S_IFDIR  0040000
#define S_IFCHR  0020000
#define S_IFIFO  0010000
#define S_ISUID  0004000
#define S_ISGID  0002000
#define S_ISVTX  0001000

/*
 * OyTao: S_ISLNK: 链接文件
 *		  S_ISDIR: 目录文件
 *		  S_ISREG: 常规文件
 *		  S_ISCHR：字符文件
 *		  S_ISBLK：块设备
 *		  S_ISFIFO: FIFO文件
 *		  S_ISSOCK: sock文件
 */
#define S_ISLNK(m)	(((m) & S_IFMT) == S_IFLNK)
#define S_ISREG(m)	(((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m)	(((m) & S_IFMT) == S_IFDIR)
#define S_ISCHR(m)	(((m) & S_IFMT) == S_IFCHR)
#define S_ISBLK(m)	(((m) & S_IFMT) == S_IFBLK)
#define S_ISFIFO(m)	(((m) & S_IFMT) == S_IFIFO)
#define S_ISSOCK(m)	(((m) & S_IFMT) == S_IFSOCK)

#define S_IRWXU 00700 /* OyTao: 该文件拥有者拥有读，写，执行的权限 */
#define S_IRUSR 00400 /* OyTao: 该文件拥有者拥有可读的权限 */
#define S_IWUSR 00200 /* OyTao: 该文件拥有者拥有可写的权限 */
#define S_IXUSR 00100 /* OyTao: 该文件拥有者拥有可执行的权限 */

#define S_IRWXG 00070 /* OyTao: 类似上面，只不过是表示该文件用户组 */
#define S_IRGRP 00040
#define S_IWGRP 00020
#define S_IXGRP 00010

#define S_IRWXO 00007 /* OyTao: 表示的是其他用户拥有的权限 */
#define S_IROTH 00004
#define S_IWOTH 00002
#define S_IXOTH 00001

#endif


#endif /* _UAPI_LINUX_STAT_H */
