/*
 * kern_feature.h - Kernel-version dependent features definition for NILFS
 *                  (would be removed in a future release)
 *
 * Copyright (C) 2006, 2007 Nippon Telegraph and Telephone Corporation.
 *
 * This file is part of NILFS.
 *
 * NILFS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * NILFS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with NILFS; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * kern_feature.h,v 1.49 2008-02-12 08:38:22 ryusuke Exp
 *
 * Written by Seiji Kihara <kihara@osrg.net>
 * Maintained by Ryusuke Konishi <ryusuke@osrg.net>
 */

#ifndef NILFS_KERN_FEATURE_H
#define NILFS_KERN_FEATURE_H

#include <linux/version.h>

/*
 * This file gives backward compatibility against past kernel versions, and
 * will be removed if merged into the mainline.
 */
#ifndef NILFS_BUILT_INTERNAL
# define NILFS_BUILT_INTERNAL \
	(defined(CONFIG_NILFS) && CONFIG_NILFS == y)
#endif

/*
 * Unsupported features
 */
#ifndef HAVE_EXPORTED_FIND_GET_PAGES
# define HAVE_EXPORTED_FIND_GET_PAGES  NILFS_BUILT_INTERNAL
#endif

/*
 * Please define as 0/1 here if you want to override
 */

/*
 * s_op->read_inode() was removed and replaced with xxxfs_iget() since
 * linux-2.6.25.
 */
#ifdef LINUX_VERSION_CODE
#ifndef NEED_READ_INODE
# define NEED_READ_INODE \
	(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25))
#endif
/*
 * write_begin/write_end which are the replacement of
 * prepare_write/commit_write was introduced in linux-2.6.24.
 */
#ifndef HAVE_WRITE_BEGIN_WRITE_END
# define HAVE_WRITE_BEGIN_WRITE_END \
	(LINUX_VERSION_CODE > KERNEL_VERSION(2,6,23))
#endif
/*
 * Linux-2.6.24 and later kernels initialize locks on inode
 * in alloc_inode() instead of inode_init_once().
 */
#ifndef NEED_LOCK_INITIALIZATIONS_FOR_NEW_INODE
# define NEED_LOCK_INITIALIZATIONS_FOR_NEW_INODE \
	(LINUX_VERSION_CODE > KERNEL_VERSION(2,6,23))
#endif
/*
 * Interface of the bio completion callback function
 * (bio->bi_end_bio) was changed at linux-2.6.24.
 * Partial completion of bio became obsolete.
 */
#ifndef NEED_OLD_BIO_END_IO
# define NEED_OLD_BIO_END_IO \
	(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
#endif
/*
 * Arguments of init_once() callback function of kmem_cache_create()
 * was changed at linux-2.6.24.  The flags argument was removed and
 * kmem_cache struct argument was moved forward.
 */
#ifndef NEED_OLD_INIT_ONCE_ARGS
# define NEED_OLD_INIT_ONCE_ARGS \
	(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
#endif
/*
 * radix_tree_preload() became available from kernel modules
 * since linux-2.6.23.
 */
#ifndef HAVE_EXPORTED_RADIX_TREE_PRELOAD
# define HAVE_EXPORTED_RADIX_TREE_PRELOAD \
	(LINUX_VERSION_CODE > KERNEL_VERSION(2,6,22))
#endif
/*
 * mark_buffer_dirty() calls __set_page_dirty() instead of
 * __set_page_dirty_nobuffer() since linux-2.6.23, and this
 * leads to a NULL pointer dereference for the pages whose
 * mapping->host == NULL.
 */
#ifndef NEED_OLD_MARK_BUFFER_DIRTY
# define NEED_OLD_MARK_BUFFER_DIRTY \
	(LINUX_VERSION_CODE > KERNEL_VERSION(2,6,22))
#endif
/*
 * vm_ops.populate and vm_ops.nopage were replaced with
 * vm_ops.fault at linux-2.6.23.  filemap_nopage() and
 * filemap_populate() were also removed along with these
 * changes.
 */
#ifndef HAVE_VMOPS_FAULT
# define HAVE_VMOPS_FAULT \
	(LINUX_VERSION_CODE > KERNEL_VERSION(2,6,22))
#endif
/*
 * set_shrinker() and remove_shrinker() were replaced with
 * register_shrinker() and unregister_shrinker(), respectively,
 * at linux-2.6.23.
 */
#ifndef HAVE_REGISTER_SHRINKER
# define HAVE_REGISTER_SHRINKER \
	(LINUX_VERSION_CODE > KERNEL_VERSION(2,6,22))
#endif
/*
 * SLAB destructor argument was removed from kmem_cache_create()
 * at linux-2.6.23.
 */
#ifndef NEED_SLAB_DESTRUCTOR_ARG
# define NEED_SLAB_DESTRUCTOR_ARG \
	(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23))
#endif
/*
 * generic_file_sendfile() and .sendfile method were removed
 * at linux-2.6.23.  They were replaced with splice_read.
 */
#ifndef NEED_SENDFILE
# define NEED_SENDFILE \
	(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23))
#endif
/*
 * SetPageWriteback() and ClearPageWriteback() were removed
 * at linux-2.6.23.
 */
#ifndef HAVE_SET_CLEAR_PAGE_WRITEBACK
# define HAVE_SET_CLEAR_PAGE_WRITEBACK \
	(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23))
#endif
/*
 * KOBJ_MOUNT and KOBJ_UMOUNT uevent were removed at linux-2.6.22.
 */
#ifndef NEED_KOBJECT_MOUNT_UEVENT
# define NEED_KOBJECT_MOUNT_UEVENT \
	(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22))
#endif
/*
 * SLAB_CTOR_CONSTRUCTOR and SLAB_CTOR_VERIFY were removed 
 * at linux-2.6.22.
 */
#ifndef NEED_SLAB_CTOR_CONSTRUCTOR
# define NEED_SLAB_CTOR_CONSTRUCTOR \
	(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22))
#endif
/*
 * find_get_pages_tag() and find_get_pages_contig() became available for
 * modules in linux-2.6.22.
 */
#ifndef HAVE_EXPORTED_FIND_GET_PAGES_TAG
# define HAVE_EXPORTED_FIND_GET_PAGES_TAG \
	(LINUX_VERSION_CODE > KERNEL_VERSION(2,6,21) || NILFS_BUILT_INTERNAL)
#endif
/*
 * In Linux-2.6.21, invalidate_inode_pages() was deprecated
 * and invalidate_mapping_pages() was exported instead.
 */
#ifndef NEED_INVALIDATE_INODE_PAGES
# define NEED_INVALIDATE_INODE_PAGES \
	(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,21))
#endif
/*
 * clear_page_dirty() and test_clear_page_dirty() were removed
 * in linux-2.6.20
 */
#ifndef HAVE_CLEAR_PAGE_DIRTY
# define HAVE_CLEAR_PAGE_DIRTY \
	(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20))
#endif
/*
 * Freezer declarations were moved to include/linux/freezer.h in
 * linux-2.6.20
 */
#ifndef NEED_FREEZER_H
# define NEED_FREEZER_H \
	(LINUX_VERSION_CODE > KERNEL_VERSION(2,6,19))
#endif
/*
 * inode->i_security became configurable since linux-2.6.19
 */
#if !defined(CONFIG_SECURITY) && \
    (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19))
# define CONFIG_SECURITY
#endif
/*
 * inode->u.generic_ip was renamed to inode->i_private in linux-2.6.19
 */
#ifndef NEED_INODE_GENERIC_IP
# define NEED_INODE_GENERIC_IP \
	(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19))
#endif
/*
 * inc_nlink()/drop_nlink() replaced link count operations at linux-2.6.19
 */
#ifndef NEED_INC_NLINK
# define NEED_INC_NLINK \
	(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19))
#endif
#ifndef NEED_DROP_NLINK
# define NEED_DROP_NLINK \
	(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19))
#endif
/*
 * readv/writev file operations were removed in linux-2.6.19
 */
#ifndef NEED_READV_WRITEV
# define NEED_READV_WRITEV \
	(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19))
#endif
/*
 * inode->i_blksize was removed in linux-2.6.19
 */
#ifndef NEED_INODE_BLKSIZE
# define NEED_INODE_BLKSIZE \
	(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19))
#endif
/*
 * list_replace() was introduced at linux-2.6.18
 */
#ifndef NEED_LIST_REPLACE
# define NEED_LIST_REPLACE \
	(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18))
#endif
/*
 * page_mkwrite() method was added to vm_operations_struct in linux-2.6.18
 */
#ifndef HAVE_PAGE_MKWRITE
# define HAVE_PAGE_MKWRITE \
	(LINUX_VERSION_CODE > KERNEL_VERSION(2,6,17))
#endif
/*
 * inode_inc_link_count()/inode_dec_link_count() was introduced
 * at linux-2.6.17
 */
#ifndef NEED_INODE_INC_DEC_LINK_COUNT
# define NEED_INODE_INC_DEC_LINK_COUNT \
	(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17))
#endif
/*
 * atomic_inc_not_zero() macro included since linux-2.6.17
 */
#ifndef HAVE_GET_PAGE_UNLESS_ZERO
# define HAVE_GET_PAGE_UNLESS_ZERO \
	(LINUX_VERSION_CODE > KERNEL_VERSION(2,6,16))
#endif
/*
 * __ClearPageLRU and __ClearPageActive is defined since linux-2.6.17
 */
#ifndef NEED_X_CLEAR_PAGE_BITOPS
# define NEED_X_CLEAR_PAGE_BITOPS \
	(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17))
#endif
/*
 * get_sb() sets a super-block to vfsmount by using simple_set_mnt() since
 * linux-2.6.18
 */
#ifndef NEED_SIMPLE_SET_MNT
# define NEED_SIMPLE_SET_MNT \
	(LINUX_VERSION_CODE > KERNEL_VERSION(2,6,17))
#endif
/*
 * statfs() takes a dentry argument instead of a superblock since linux-2.6.18
 */
#ifndef NEED_STATFS_DENTRY_ARG
# define NEED_STATFS_DENTRY_ARG	\
	(LINUX_VERSION_CODE > KERNEL_VERSION(2,6,17))
#endif
/*
 * some bit operation macros for page were obsoleted in linux-2.6.17
 */
#ifndef NEED_TEST_CLEAR_PAGE_BITOPS
# define NEED_TEST_CLEAR_PAGE_BITOPS \
	(LINUX_VERSION_CODE > KERNEL_VERSION(2,6,16))
#endif
/*
 * find_trylock_page will be deprecated in linux-2.6.17
 */
#ifndef NEED_FIND_TRYLOCK_PAGE
# define NEED_FIND_TRYLOCK_PAGE	\
	(LINUX_VERSION_CODE > KERNEL_VERSION(2,6,16))
#endif
/*
 * A return value of sync_page() disappeared in linux-2.6.17
 */
#ifndef NEED_SYNC_PAGE_RETVAL
# define NEED_SYNC_PAGE_RETVAL	\
	(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17))
#endif
/*
 * bd_mount_mutex replaced semaphore counterpart in linux-2.6.17,
 * and was reverted to the semaphore in linux-2.6.20
 */
#ifndef NEED_MOUNT_SEMAPHORE
# define NEED_MOUNT_SEMAPHORE		\
	(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17) || \
	 LINUX_VERSION_CODE > KERNEL_VERSION(2,6,19))
#endif
/*
 * get_blocks_t was unified to get_block_t in linux-2.6.17
 */
#ifndef NEED_GET_BLOCKS_T
# define NEED_GET_BLOCKS_T	\
	(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17))
#endif
/*
 * A return value of invalidatepage() was done away with linux-2.6.17
 */
#ifndef NEED_INVALIDATEPAGE_RETVAL
# define NEED_INVALIDATEPAGE_RETVAL	\
	(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17))
#endif
/*
 * A measure against a buffer overrun problem around sysfs write 
 * for linux-2.6.16 and older versions.
 */
#ifndef NEED_SYSFS_TERMINATOR_CHECK
# define NEED_SYSFS_TERMINATOR_CHECK	\
	(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17))
#endif
/*
 * GFP_NOWAIT flag was introduced at linux-2.6.17
 */
#ifndef NEED_GFP_NOWAIT
# define NEED_GFP_NOWAIT	\
	(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17))
#endif
/*
 * mutex replaced semaphore since linux-2.6.16
 */
#ifndef NEED_INODE_SEMAPHORE
# define NEED_INODE_SEMAPHORE		\
	(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16))
#endif
/*
 * attribute argument was removed from kobject_uevent since linux-2.6.16
 */
#ifndef NEED_KOBJECT_UEVENT_ATTRIBUTE_ARG
# define NEED_KOBJECT_UEVENT_ATTRIBUTE_ARG		\
	(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16))
#endif
/*
 * s_old_blocksize was removed since linux-2.6.16
 */
#ifndef NEED_S_OLD_BLOCKSIZE
# define NEED_S_OLD_BLOCKSIZE				\
	(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16))
#endif
/*
 * AOP_TRUNCATED_PAGE status value was introduced for aop->prepare_write
 * at linux-2.6.16
 */
#ifndef HAVE_AOP_TRUNCATED_PAGE
# define HAVE_AOP_TRUNCATED_PAGE			\
	(LINUX_VERSION_CODE > KERNEL_VERSION(2,6,15))
#endif
/*
 * typedef gfp_t included since linux-2.6.15
 */
#ifndef NEED_GFP_T
# define NEED_GFP_T					\
	(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15))
#endif
/*
 * kmem_cache_s struct is renamed to kmem_cache in linux-2.6.15
 */
#ifndef NEED_KMEM_CACHE_S
# define NEED_KMEM_CACHE_S				\
	(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15))
#endif
/*
 * kzalloc() was introduced in linux-2.6.14
 */
#ifndef HAVE_KZALLOC
# define HAVE_KZALLOC					\
	(LINUX_VERSION_CODE > KERNEL_VERSION(2,6,13))
#endif
/*
 * truncate_inode_pages() should be called in each fs since linux-2.6.14.
 */
#ifndef NEED_TRUNCATE_INODE_PAGES
# define NEED_TRUNCATE_INODE_PAGES			\
	(LINUX_VERSION_CODE > KERNEL_VERSION(2,6,13))
#endif
/*
 * refrigerator() have no arguments since linux-2.6.13.
 */
#ifndef NEED_REFRIGERATOR_ARGS
# define NEED_REFRIGERATOR_ARGS				\
	(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,13))
#endif
/*
 * task member of wait_queue_t was replaced with private in linux-2.6.13.
 */
#ifndef NEED_WAIT_QUEUE_TASK
# define NEED_WAIT_QUEUE_TASK				\
	(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,13))
#endif
/*
 * linux-2.6.11 and earlier versions don't have
 * invalidate_inode_pages2_range()
 */
#ifndef HAVE_INVALIDATE_INODE_PAGES2_RANGE
# define HAVE_INVALIDATE_INODE_PAGES2_RANGE 		\
	(LINUX_VERSION_CODE > KERNEL_VERSION(2,6,11))
#endif
/*
 * r/w spinlock is used for standard radix-tree since linux-2.6.12.
 */
#ifndef NEED_RWLOCK_FOR_PAGECACHE_LOCK
# define NEED_RWLOCK_FOR_PAGECACHE_LOCK			\
	(LINUX_VERSION_CODE > KERNEL_VERSION(2,6,11))
#endif
#endif /* LINUX_VERSION_CODE */


#include <linux/list.h>
#include <linux/fs.h>

/*
 * definitions dependent to above macros
 */
#if NEED_GFP_T
#define gfp_t int
#define GFP_T unsigned int
#else
#define GFP_T gfp_t
#endif

#if NEED_GFP_NOWAIT
#define GFP_NOWAIT (GFP_ATOMIC & ~__GFP_HIGH)
#endif

#if NEED_KMEM_CACHE_S
#define kmem_cache kmem_cache_s
#endif

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

#if NEED_INODE_INC_DEC_LINK_COUNT
static inline void inode_inc_link_count(struct inode *inode)
{
	inc_nlink(inode);
	mark_inode_dirty(inode);
}

static inline void inode_dec_link_count(struct inode *inode)
{
	drop_nlink(inode);
	mark_inode_dirty(inode);
}
#endif

#if !HAVE_KZALLOC
static inline void *kzalloc(size_t size, gfp_t flags)
{
	void *ret = kmalloc(size, flags);
	if (likely(ret))
		memset(ret, 0, size);
	return ret;
}
#endif

#if NEED_X_CLEAR_PAGE_BITOPS
# define __ClearPageActive(page)	__clear_bit(PG_active, &(page)->flags)
#endif

#if !HAVE_EXPORTED_FIND_GET_PAGES
extern unsigned __nilfs_find_get_pages(struct address_space *, pgoff_t,
				       unsigned int, struct page **);
# define find_get_pages(m,i,n,p)  __nilfs_find_get_pages(m,i,n,p)
#endif

#if !HAVE_EXPORTED_FIND_GET_PAGES_TAG
extern unsigned __nilfs_find_get_pages_tag(struct address_space *, pgoff_t *,
					   int, unsigned int, struct page **);
# define find_get_pages_tag(m,i,t,n,p)  __nilfs_find_get_pages_tag(m,i,t,n,p)
#endif

#if !HAVE_INVALIDATE_INODE_PAGES2_RANGE
#define invalidate_inode_pages2_range(mapping, start, end)   (0)
#endif

#if NEED_MOUNT_SEMAPHORE
#define nilfs_lock_bdev(bdev)  do { down(&(bdev)->bd_mount_sem); } while(0)
#define nilfs_unlock_bdev(bdev)  do { up(&(bdev)->bd_mount_sem); } while(0)
#else
#define nilfs_lock_bdev(bdev)  do { mutex_lock(&(bdev)->bd_mount_mutex); } while(0)
#define nilfs_unlock_bdev(bdev)  do { mutex_unlock(&(bdev)->bd_mount_mutex); } while(0)
#endif

#if NEED_RWLOCK_FOR_PAGECACHE_LOCK
# define READ_LOCK_IRQ(x)	read_lock_irq((x))
# define READ_UNLOCK_IRQ(x)	read_unlock_irq((x))
# define WRITE_LOCK_IRQ(x)	write_lock_irq((x))
# define WRITE_UNLOCK_IRQ(x)	write_unlock_irq((x))
#else
# define READ_LOCK_IRQ(x)	spin_lock_irq((x))
# define READ_UNLOCK_IRQ(x)	spin_unlock_irq((x))
# define WRITE_LOCK_IRQ(x)	spin_lock_irq((x))
# define WRITE_UNLOCK_IRQ(x)	spin_unlock_irq((x))
#endif

#if NEED_WAIT_QUEUE_TASK
# define WAIT_QUEUE_TASK(x)	((x)->task)
#else
# define WAIT_QUEUE_TASK(x)	((x)->private)
#endif

/* Extended list operations supported for the recent kernels */
#if NEED_LIST_REPLACE
static inline void list_replace(struct list_head *old,
				struct list_head *new)
{
	new->next = old->next;
	new->next->prev = new;
	new->prev = old->prev;
	new->prev->next = new;
}

static inline void list_replace_init(struct list_head *old,
					struct list_head *new)
{
	list_replace(old, new);
	INIT_LIST_HEAD(old);
}
#endif

#ifndef list_for_each_entry_safe_continue
#define list_for_each_entry_safe_continue(pos, n, head, member)			\
	for (pos = list_entry(pos->member.next, typeof(*pos), member),		\
		n = list_entry(pos->member.next, typeof(*pos), member);		\
	     &pos->member != (head);						\
	     pos = n, n = list_entry(n->member.next, typeof(*n), member))
#endif

#endif /* NILFS_KERN_FEATURE_H */

/* Local Variables:		*/
/* eval: (c-set-style "linux")	*/
/* End:				*/
