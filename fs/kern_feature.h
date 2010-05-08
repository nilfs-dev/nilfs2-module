/*
 * kern_feature.h - Kernel-version dependent features definition for NILFS
 *                  (would be removed in a future release)
 *
 * Copyright (C) 2006-2008 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Written by Seiji Kihara <kihara@osrg.net>
 * Maintained by Ryusuke Konishi <ryusuke@osrg.net>
 */

#ifndef NILFS_KERN_FEATURE_H
#define NILFS_KERN_FEATURE_H

#include <linux/version.h>

/*
 * Please define as 0/1 here if you want to override
 */

/*
 * for Red Hat Enterprise Linux / CentOS 5.x
 */
#if defined(RHEL_MAJOR) && (RHEL_MAJOR == 5)
# define	NEED_MOUNT_SEMAPHORE	1
# define	NEED_INODE_GENERIC_IP	0
# define	NEED_INODE_BLKSIZE	0
# if (RHEL_MINOR < 1)
#  define	PageChecked	PageFsMisc
#  define	SetPageChecked	SetPageFsMisc
#  define	ClearPageChecked	ClearPageFsMisc
# endif
# if (RHEL_MINOR > 0)
#  define	NEED_INC_NLINK		0
#  if (RHEL_MINOR > 2)
#   define	NEED_DROP_NLINK		0
#   define	HAVE_LE32_64_ADD_CPU	1
#  endif
#  if (RHEL_MINOR > 3)
#   define	HAVE_D_OBTAIN_ALIAS	1
#   define	HAVE_BLOCK_PAGE_MKWRITE	1
#  endif
# endif
#endif

/*
 * defaults dependent to kernel versions
 */
#ifdef LINUX_VERSION_CODE
/*
 * memdup_user() was introduced in linux-2.6.30
 */
#ifndef HAVE_MEMDUP_USER
# define HAVE_MEMDUP_USER \
	(LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 29))
#endif
/*
 * BIO_RW_SYNC was removed in linux-2.6.29; BIO_RW_SYNCIO and 
 * BIO_RW_UNPLUG was introduced instead.
 */
#ifndef NEED_BIO_RW_SYNC
# define NEED_BIO_RW_SYNC \
	(LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29))
#endif
/*
 * In kernels prior to linux-2.6.29, do_sync_mapping_range() calls
 * writepages() with WB_SYNC_NONE intead of WB_SYNC_ALL.
 */
#ifndef NEED_WB_SYNC_NONE_CHECK_FOR_DO_SYNC_MAPPING_RANGE
# define NEED_WB_SYNC_NONE_CHECK_FOR_DO_SYNC_MAPPING_RANGE \
	(LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29))
#endif
/*
 * In linux-2.6.28, d_alloc_anon() was removed and d_obtain_alias()
 * was introduced to find or allocate dentry for a given inode.
 */
#ifndef HAVE_D_OBTAIN_ALIAS
# define HAVE_D_OBTAIN_ALIAS \
	(LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 27))
#endif
/*
 * Kernels prior to 2.6.28 use open_bdev_excl()/close_bdev_excl()
 * instead of open_bdev_exclusive()/close_bdev_exclusive(), and need
 * stab code to convert a file mode argument to mount flags.
 */
#ifndef NEED_OPEN_CLOSE_BDEV_EXCLUSIVE
# define NEED_OPEN_CLOSE_BDEV_EXCLUSIVE \
	(LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 28))
#endif

#ifndef HAVE_SB_S_MODE
# define HAVE_SB_S_MODE !NEED_OPEN_CLOSE_BDEV_EXCLUSIVE
#endif
/*
 * Kernels later than 2.6.26 have aops->is_partially_uptodate method
 */
#ifndef HAVE_IS_PARTIALLY_UPTODATE
# define HAVE_IS_PARTIALLY_UPTODATE \
	(LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 26))
#endif
/*
 * Page trylock and buffer trylock were renamed at linux-2.6.27-rc2.
 */
#ifndef HAVE_NEW_TRYLOCKS
# define HAVE_NEW_TRYLOCKS \
	(LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 26))
#endif
/*
 * The lockless page cache was merged at linux-2.6.27-rc1.
 */
#ifndef HAVE_LOCKLESS_PAGECACHE
# define HAVE_LOCKLESS_PAGECACHE \
	(LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 26))
#endif
/*
 * linux-2.6.26 and the later kernels have mnt_want_write() and
 * mnt_drop_write().
 */
#ifndef HAVE_MNT_WANT_DROP_WRITE
# define HAVE_MNT_WANT_DROP_WRITE \
	(LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 25))
#endif
/*
 * linux-2.6.25 and the later kernels have le32_add_cpu() and le64_add_cpu().
 */
#ifndef HAVE_LE32_64_ADD_CPU
# define HAVE_LE32_64_ADD_CPU \
	(LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 24))
#endif
/*
 * The definition of init_once() callback function used by kmem_cache_create()
 * changed again in linux-2.6.27; kmem_cache struct dropped from the arguments.
 */
#ifndef NEED_OLD_INIT_ONCE_ARGS2
# define NEED_OLD_INIT_ONCE_ARGS2 \
	(LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27) && \
	 LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24))
#endif
/*
 * s_op->read_inode() was removed and replaced with xxxfs_iget() since
 * linux-2.6.25.
 */
#ifndef NEED_READ_INODE
# define NEED_READ_INODE \
	(LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25))
#endif
/*
 * Two methods, fh_to_entry and fh_to_parent were added to export_operations
 * in linux-2.6.24.
 */
#ifndef NEED_FH_TO_DENTRY
# define NEED_FH_TO_DENTRY \
	(LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 23))
#endif
/*
 * write_begin/write_end which are the replacement of
 * prepare_write/commit_write was introduced in linux-2.6.24.
 */
#ifndef HAVE_WRITE_BEGIN_WRITE_END
# define HAVE_WRITE_BEGIN_WRITE_END \
	(LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 23))
#endif
/*
 * Linux-2.6.24 and later kernels initialize locks on inode
 * in alloc_inode() instead of inode_init_once().
 */
#ifndef NEED_LOCK_INITIALIZATIONS_FOR_NEW_INODE
# define NEED_LOCK_INITIALIZATIONS_FOR_NEW_INODE \
	(LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 23))
#endif
/*
 * Interface of the bio completion callback function
 * (bio->bi_end_bio) was changed at linux-2.6.24.
 * Partial completion of bio became obsolete.
 */
#ifndef NEED_OLD_BIO_END_IO
# define NEED_OLD_BIO_END_IO \
	(LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24))
#endif
/*
 * Arguments of init_once() callback function of kmem_cache_create()
 * was changed at linux-2.6.24.  The flags argument was removed and
 * kmem_cache struct argument was moved forward.
 */
#ifndef NEED_OLD_INIT_ONCE_ARGS
# define NEED_OLD_INIT_ONCE_ARGS \
	(LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24))
#endif
/*
 * Declarations for exportfs was moved to exportfs.h at linux-2.6.23.
 */
#ifndef HAVE_EXPORT_FS_H
# define HAVE_EXPORT_FS_H \
	(LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 22))
#endif
/*
 * radix_tree_preload() became available from kernel modules
 * since linux-2.6.23.
 */
#ifndef HAVE_EXPORTED_RADIX_TREE_PRELOAD
# define HAVE_EXPORTED_RADIX_TREE_PRELOAD \
	(LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 22))
#endif
/*
 * mark_buffer_dirty() calls __set_page_dirty() instead of
 * __set_page_dirty_nobuffer() since linux-2.6.23, and this
 * leads to a NULL pointer dereference for the pages whose
 * mapping->host == NULL.
 */
#ifndef NEED_OLD_MARK_BUFFER_DIRTY
# define NEED_OLD_MARK_BUFFER_DIRTY \
	(LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 22))
#endif
/*
 * vm_ops.populate and vm_ops.nopage were replaced with
 * vm_ops.fault at linux-2.6.23.  filemap_nopage() and
 * filemap_populate() were also removed along with these
 * changes.
 */
#ifndef HAVE_VMOPS_FAULT
# define HAVE_VMOPS_FAULT \
	(LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 22))
#endif
/*
 * block_page_mkwrite() was introduced at linux-2.6.23.
 */
#ifndef HAVE_BLOCK_PAGE_MKWRITE
# define HAVE_BLOCK_PAGE_MKWRITE \
	(LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 22))
#endif
/*
 * SLAB destructor argument was removed from kmem_cache_create()
 * at linux-2.6.23.
 */
#ifndef NEED_SLAB_DESTRUCTOR_ARG
# define NEED_SLAB_DESTRUCTOR_ARG \
	(LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 23))
#endif
/*
 * generic_file_sendfile() and .sendfile method were removed
 * at linux-2.6.23.  They were replaced with splice_read.
 */
#ifndef NEED_SENDFILE
# define NEED_SENDFILE \
	(LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 23))
#endif
/*
 * SetPageWriteback() and ClearPageWriteback() were removed
 * at linux-2.6.23.
 */
#ifndef HAVE_SET_CLEAR_PAGE_WRITEBACK
# define HAVE_SET_CLEAR_PAGE_WRITEBACK \
	(LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 23))
#endif
/*
 * KOBJ_MOUNT and KOBJ_UMOUNT uevent were removed at linux-2.6.22.
 */
#ifndef NEED_KOBJECT_MOUNT_UEVENT
# define NEED_KOBJECT_MOUNT_UEVENT \
	(LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 22))
#endif
/*
 * SLAB_CTOR_CONSTRUCTOR and SLAB_CTOR_VERIFY were removed
 * at linux-2.6.22.
 */
#ifndef NEED_SLAB_CTOR_CONSTRUCTOR
# define NEED_SLAB_CTOR_CONSTRUCTOR \
	(LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 22))
#endif
/*
 * In Linux-2.6.21, invalidate_inode_pages() was deprecated
 * and invalidate_mapping_pages() was exported instead.
 */
#ifndef NEED_INVALIDATE_INODE_PAGES
# define NEED_INVALIDATE_INODE_PAGES \
	(LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 21))
#endif
/*
 * clear_page_dirty() and test_clear_page_dirty() were removed
 * in linux-2.6.20
 */
#ifndef HAVE_CLEAR_PAGE_DIRTY
# define HAVE_CLEAR_PAGE_DIRTY \
	(LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20))
#endif
/*
 * Freezer declarations were moved to include/linux/freezer.h in
 * linux-2.6.20
 */
#ifndef NEED_FREEZER_H
# define NEED_FREEZER_H \
	(LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 19))
#endif
/*
 * inode->i_security became configurable since linux-2.6.19
 */
#if !defined(CONFIG_SECURITY) && \
    (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19))
# define CONFIG_SECURITY
#endif
/*
 * inode->u.generic_ip was renamed to inode->i_private in linux-2.6.19
 */
#ifndef NEED_INODE_GENERIC_IP
# define NEED_INODE_GENERIC_IP \
	(LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19))
#endif
/*
 * inc_nlink()/drop_nlink() replaced link count operations at linux-2.6.19
 */
#ifndef NEED_INC_NLINK
# define NEED_INC_NLINK \
	(LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19))
#endif
#ifndef NEED_DROP_NLINK
# define NEED_DROP_NLINK \
	(LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19))
#endif
/*
 * readv/writev file operations were removed in linux-2.6.19
 */
#ifndef NEED_READV_WRITEV
# define NEED_READV_WRITEV \
	(LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19))
#endif
/*
 * inode->i_blksize was removed in linux-2.6.19
 */
#ifndef NEED_INODE_BLKSIZE
# define NEED_INODE_BLKSIZE \
	(LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19))
#endif
#endif /* LINUX_VERSION_CODE */


#include <linux/fs.h>
#include <linux/pagevec.h>
#include <linux/buffer_head.h>
#include <linux/mount.h>

/*
 * definitions dependent to above macros
 */
#if NEED_INC_NLINK
static inline void inc_nlink(struct inode *inode)
{
	inode->i_nlink++;
}
#endif

#if NEED_DROP_NLINK
static inline void drop_nlink(struct inode *inode)
{
	inode->i_nlink--;
}
#endif

#if !HAVE_D_OBTAIN_ALIAS
static inline struct dentry *d_obtain_alias(struct inode *inode)
{
	struct dentry *parent = d_alloc_anon(inode);

	if (!parent) {
		iput(inode);
		parent = ERR_PTR(-ENOMEM);
	}
	return parent;
}
#endif

#if !HAVE_LE32_64_ADD_CPU
static inline void le32_add_cpu(__le32 *var, u32 val)
{
	*var = cpu_to_le32(le32_to_cpu(*var) + val);
}

static inline void le64_add_cpu(__le64 *var, u64 val)
{
	*var = cpu_to_le64(le64_to_cpu(*var) + val);
}
#endif

#if !HAVE_NEW_TRYLOCKS
# define trylock_page(page)		(!TestSetPageLocked(page))
# define trylock_buffer(bh)		(!test_set_buffer_locked(bh))
#endif

#if HAVE_LOCKLESS_PAGECACHE
# define WRITE_LOCK_IRQ(x)	spin_lock_irq((x))
# define WRITE_UNLOCK_IRQ(x)	spin_unlock_irq((x))
#else
# define READ_LOCK_IRQ(x)	read_lock_irq((x))
# define READ_UNLOCK_IRQ(x)	read_unlock_irq((x))
# define WRITE_LOCK_IRQ(x)	write_lock_irq((x))
# define WRITE_UNLOCK_IRQ(x)	write_unlock_irq((x))
#endif

#ifndef DIV_ROUND_UP
# define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#endif

#if NEED_OPEN_CLOSE_BDEV_EXCLUSIVE
typedef mode_t fmode_t;

static inline struct block_device *
open_bdev_exclusive(const char *path, fmode_t mode, void *holder)
{
	int flags = (mode & FMODE_WRITE) ? 0 : MS_RDONLY;

	return open_bdev_excl(path, flags, holder);
}

#define close_bdev_exclusive(path, mode) close_bdev_excl(path)
#endif

#ifndef current_fsuid
# define current_fsuid()	(current->fsuid)
# define current_fsgid()	(current->fsgid)
#endif

#if !HAVE_MEMDUP_USER  /* back-ported from 2.6.30 */
static inline void *memdup_user(const void __user *src, size_t len)
{
	void *p;

	/*
	 * Always use GFP_KERNEL, since copy_from_user() can sleep and
	 * cause pagefault, which makes it pointless to use GFP_NOFS
	 * or GFP_ATOMIC.
	 */
	p = kmalloc(len, GFP_KERNEL);
	if (!p)
		return ERR_PTR(-ENOMEM);

	if (copy_from_user(p, src, len)) {
		kfree(p);
		return ERR_PTR(-EFAULT);
	}

	return p;
}
#endif

#if !HAVE_MNT_WANT_DROP_WRITE
# define mnt_want_write(mnt) \
	((mnt)->mnt_sb->s_flags & MS_RDONLY ? -EROFS : 0)
# define mnt_drop_write(mnt)	do {} while(0)
#endif

#endif /* NILFS_KERN_FEATURE_H */
