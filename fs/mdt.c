/*
 * mdt.c - meta data file for NILFS (The prefix mdt is provisional)
 *
 * Copyright (C) 2005-2007 Nippon Telegraph and Telephone Corporation.
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
 * Written by Ryusuke Konishi <ryusuke@osrg.net>
 */

#include <linux/buffer_head.h>
#include <linux/mpage.h>
#include <linux/mm.h>
#include <linux/writeback.h>
#include <linux/backing-dev.h>
#include <linux/swap.h>
#include "nilfs.h"
#include "page.h"
#include "mdt.h"


#define NILFS_MDT_MAX_RA_BLOCKS		(16 - 1)

#define USE_DEFAULT_BDEV_INFO
#define INIT_UNUSED_INODE_FIELDS


#ifndef INIT_UNUSED_INODE_FIELDS
static struct backing_dev_info nilfs_mdt_bdi =
{
	.ra_pages       = (VM_MAX_READAHEAD * 1024) / PAGE_CACHE_SIZE,
	.state          = 0,
	.capabilities   = BDI_CAP_MAP_COPY,
	.unplug_io_fn   = default_unplug_io_fn,
};
#endif

#if NEED_OLD_MARK_BUFFER_DIRTY
void nilfs_mdt_mark_buffer_dirty(struct buffer_head *bh)
{
	if (!buffer_dirty(bh) && !test_set_buffer_dirty(bh))
		__set_page_dirty_nobuffers(bh->b_page);
}
#endif

static int
nilfs_mdt_insert_new_block(struct inode *inode, nilfs_blkoff_t block,
			   struct buffer_head *bh,
			   nilfs_mdt_init_block_t *init_block)
{
	struct nilfs_inode_info *ii = NILFS_I(inode);
	void *kaddr;
	int ret;

	/* Caller exclude read accesses using page lock */

	/* set_buffer_new(bh); */
	bh->b_blocknr = 0;

	ret = nilfs_bmap_insert(
		ii->i_bmap, (unsigned long)block, (unsigned long)bh);

	mdt_debug(3, "nilfs_bmap_insert() returned %d"
		  " (blkoff=%llu, blocknr=%llu)\n",
 		  ret, (unsigned long long)block,
		  (unsigned long long)bh->b_blocknr);
	if (unlikely(ret))
		return ret;

	set_buffer_mapped(bh);

	kaddr = kmap_atomic(bh->b_page, KM_USER0);
	memset(kaddr + bh_offset(bh), 0, 1 << inode->i_blkbits);
	if (init_block)
		init_block(inode, bh, kaddr);
	flush_dcache_page(bh->b_page);
	kunmap_atomic(kaddr, KM_USER0);

	set_buffer_uptodate(bh);
	nilfs_mdt_mark_buffer_dirty(bh);
	nilfs_mdt_mark_dirty(inode);
	return 0;
}

static struct buffer_head *
nilfs_mdt_get_page_block(struct inode *inode, nilfs_blkoff_t blkoff)
{
	int blkbits = inode->i_blkbits;
	pgoff_t index = blkoff >> (PAGE_CACHE_SHIFT - blkbits);
	struct inode *orig_inode;
	struct page *page, *opage;
	struct buffer_head *bh, *obh;

	page = grab_cache_page(inode->i_mapping, index);
	if (unlikely(!page))
		return NULL;

	bh = nilfs_get_page_block(page, blkoff, index, blkbits);
	if (unlikely(!bh)) {
		unlock_page(page);
		page_cache_release(page);
		return NULL;
	}
	if (!buffer_uptodate(bh) &&
	    (orig_inode = NILFS_MDT(inode)->mi_orig_inode) != NULL) {
		/* check original cache */
		opage = find_lock_page(orig_inode->i_mapping, index);
		if (opage) {
			obh = nilfs_get_page_block(opage, blkoff, index,
						   blkbits);
			if (buffer_uptodate(obh)) {
				mdt_debug(3, "hit orig cache. (ino=%lu, "
					  "blkoff=%llu)\n", inode->i_ino,
					  (unsigned long long)blkoff);
				nilfs_copy_buffer(obh, bh);
				if (buffer_dirty(obh)) {
					/* Since all dirty buffers are copied
					   in preparation phase, the
					   followings would be omissible. */
					nilfs_mdt_mark_buffer_dirty(bh);
					nilfs_mdt_mark_dirty(inode);
				}
			}
			brelse(obh);
			unlock_page(opage);
			page_cache_release(opage);
		}
	}
	return bh;
}

static inline void
nilfs_mdt_put_page_block(struct inode *inode, struct buffer_head *bh)
{
	unlock_page(bh->b_page);
	page_cache_release(bh->b_page);
	brelse(bh);
}

/**
 * nilfs_mdt_create_block - allocate a data block of the meta data file
 * @inode: inode of the meta data file
 * @block: block offset
 * @out_bh: output of a pointer to the buffer_head
 * @init_block: initializer of newly allocated block
 *
 * Return Value: On success, it returns 0.  On error, the following negative
 * error code is returned.
 * 
 * %-ENOMEM - Insufficient memory available.
 *
 * %-EIO - I/O error
 *
 * %-EEXIST - the specified block already exists.
 *
 * %-EINVAL - bmap is broken. (the caller should call nilfs_error())
 *
 * %-EROFS - Read only filesystem.
 */
int nilfs_mdt_create_block(struct inode *inode, nilfs_blkoff_t block, 
			   struct buffer_head **out_bh,
			   nilfs_mdt_init_block_t *init_block)
{
	struct the_nilfs *nilfs = NILFS_MDT(inode)->mi_nilfs;
	struct nilfs_sb_info *sbi = NULL;
	struct super_block *sb = inode->i_sb;
	struct nilfs_transaction_info ti;
	struct buffer_head *bh;
	int err;

	mdt_debug(3, "called (ino=%lu, blkoff=%llu)\n",
		  inode->i_ino, (unsigned long long)block);

	if (!sb) {
		sbi = nilfs_get_writer(nilfs);
		if (!sbi) {
			err = -EROFS;
			goto out;
		}
		sb = sbi->s_super;
	}

	nilfs_transaction_begin(sb, &ti, 0);

	err = -ENOMEM;
	bh = nilfs_mdt_get_page_block(inode, block);
	if (unlikely(!bh))
		goto failed_unlock;

	err = -EEXIST;
	if (buffer_uptodate(bh) || buffer_mapped(bh))
		goto failed_bh;
#if 0
	/* The uptodate flag is not protected by the page lock, but
	   the mapped flag is.  Thus, we don't have to wait the buffer. */
	wait_on_buffer(bh);
	if (buffer_uptodate(bh))
		goto failed_bh;
#endif

	bh->b_bdev = nilfs->ns_bdev;
	err = nilfs_mdt_insert_new_block(inode, block, bh, init_block);
	if (likely(!err)) {
		get_bh(bh);
		*out_bh = bh;
	}

 failed_bh:
	nilfs_mdt_put_page_block(inode, bh);

 failed_unlock:
	nilfs_transaction_end(sb, !err);
	if (sbi)
		nilfs_put_writer(nilfs);
 out:
	mdt_debug(3, "done (err=%d)\n", err);
	return err;
}

static int
nilfs_mdt_submit_block(struct inode *inode, nilfs_blkoff_t blkoff,
		       int mode, struct buffer_head **out_bh)
{
	struct buffer_head *bh;
	unsigned long blknum = 0;
	int ret = -ENOMEM;

	bh = nilfs_mdt_get_page_block(inode, blkoff);
	if (unlikely(!bh))
		goto failed;

	ret = -EEXIST; /* internal code */
	if (buffer_uptodate(bh))
		goto out;

	if (mode == READA) {
		if (test_set_buffer_locked(bh)) {
			ret = -EBUSY;
			goto failed_bh;
		}
	} else {
		BUG_ON(mode != READ);
		lock_buffer(bh);
	}

	if (buffer_uptodate(bh)) {
		unlock_buffer(bh);
		goto out;
	}
	if (!buffer_mapped(bh)) { /* unused buffer */
		ret = nilfs_bmap_lookup(NILFS_I(inode)->i_bmap,
					(unsigned long)blkoff, &blknum);
		mdt_debug(3, "lookup: blkoff=%llu -> blocknr=%lu "
			  "(ret=%d, ino=%lu)\n",
			  (unsigned long long)blkoff, blknum, ret,
			  inode->i_ino);
		if (unlikely(ret)) {
			unlock_buffer(bh);
			goto failed_bh;
		}
		bh->b_bdev = NILFS_MDT(inode)->mi_nilfs->ns_bdev;
		bh->b_blocknr = blknum;
		set_buffer_mapped(bh);
	}

	bh->b_end_io = end_buffer_read_sync;
	get_bh(bh);
	submit_bh(mode, bh);
	ret = 0;
 out:
	get_bh(bh);
	*out_bh = bh;

 failed_bh:
	nilfs_mdt_put_page_block(inode, bh);
 failed:
	return ret;
}


/**
 * nilfs_mdt_read_block - read a block on the meta data file.
 * @inode: inode of the meta data file
 * @block: block offset
 * @out_bh: output of a pointer to the buffer_head
 *
 * nilfs_mdt_read_block() looks up the specified buffer.
 * When the block is not mapped on disk, it returns ERR_PTR(-ENOENT).
 * Since the buffer is taken exclusively by a page and buffer lock, it is assured to
 * be either existing or formatted through nilfs_mdt_create_block().
 *
 * Return Value: On success, it returns 0. On error, the following negative
 * error code is returned.
 * 
 * %-ENOMEM - Insufficient memory available.
 *
 * %-EIO - I/O error
 *
 * %-ENOENT - the specified block does not exist (hole block)
 *
 * %-EINVAL - bmap is broken. (the caller should call nilfs_error())
 */
int nilfs_mdt_read_block(struct inode *inode, nilfs_blkoff_t block,
			 struct buffer_head **out_bh)
{
	struct buffer_head *first_bh, *bh;
	nilfs_blkoff_t blkoff;
	int i, nr_ra_blocks = NILFS_MDT_MAX_RA_BLOCKS;
	int err;

	mdt_debug(3, "called (ino=%lu, blkoff=%llu)\n",
		  inode->i_ino, (unsigned long long)block);

	err = nilfs_mdt_submit_block(inode, block, READ, &first_bh);
	if (err == -EEXIST) { /* internal code */
		mdt_debug(3, "hit cache (ino=%lu, blkoff=%llu)\n",
			  inode->i_ino, (unsigned long long)block);
		goto out;
	}
	if (unlikely(err))
		goto failed;

	mdt_debug(2, "reading: blocknr=%llu (ino=%lu, blkoff=%llu)\n",
		  (unsigned long long)first_bh->b_blocknr, inode->i_ino,
		  (unsigned long long)block);

	blkoff = block + 1;
	for (i = 0; i < nr_ra_blocks; i++, blkoff++) {
		err = nilfs_mdt_submit_block(inode, blkoff, READA, &bh);
		if (likely(!err || err == -EEXIST)) {
			if (!err)
				mdt_debug(3, "requested readahead "
					  "(ino=%lu, blkfoff=%llu)\n",
					  inode->i_ino,
					  (unsigned long long)blkoff);
			brelse(bh);
		} else if (err != -EBUSY) {
			mdt_debug(3, "abort readahead due to an error "
				  "(err=%d, ino=%lu, blkfoff=%llu)\n", err,
				  inode->i_ino, (unsigned long long)blkoff);
			break; /* abort readahead if bmap lookup failed */
		}
		if (!buffer_locked(first_bh))
			goto out_no_wait;
	}

	wait_on_buffer(first_bh);

 out_no_wait:
	err = -EIO;
	if (!buffer_uptodate(first_bh))
		goto failed_bh;
 out:
	*out_bh = first_bh;
	mdt_debug(3, "done (bh=%p)\n", first_bh);
	return 0;

 failed_bh:
	brelse(first_bh);
 failed:
	mdt_debug(3, "failed (err=%d)\n", err);
	return err;
}

/**
 * nilfs_mdt_get_block - read or create a block on the meta data file.
 * @inode: inode of the meta data file
 * @block: block offset
 * @create: create flag
 * @init_block: initializer used for newly allocated block
 * @out_bh: output of a pointer to the buffer_head
 *
 * The returned buffer is assured to be either existing or formatted using
 * a buffer lock on success. out_bh is substituted only when zero is returned.
 *
 * %-ENOMEM - Insufficient memory available.
 *
 * %-EIO - I/O error
 *
 * %-ENOENT - the specified block does not exist
 *
 * %-EINVAL - bmap is broken. (the caller should call nilfs_error())
 */
int nilfs_mdt_get_block(struct inode *inode, nilfs_blkoff_t block, int create,
			nilfs_mdt_init_block_t *init_block,
			struct buffer_head **out_bh)
{
	int ret;

	/* Should be rewritten with merging nilfs_mdt_read_block() */
 retry:
	ret = nilfs_mdt_read_block(inode, block, out_bh);
	if (!create || ret != -ENOENT)
		return ret;

	ret = nilfs_mdt_create_block(inode, block, out_bh, init_block);
	if (unlikely(ret == -EEXIST)) {
		/* create = 0; */  /* limit read-create loop retries */
		goto retry;
	}
	return ret;
}

/**
 * nilfs_mdt_delete_block - make a hole on the meta data file.
 * @inode: inode of the meta data file
 * @block: block offset
 *
 * Return Value: On success, zero is returned.
 * On error, one of the following negative error code is returned.
 * 
 * %-ENOMEM - Insufficient memory available.
 *
 * %-EIO - I/O error
 *
 * %-EINVAL - bmap is broken. (the caller should call nilfs_error())
 */
int nilfs_mdt_delete_block(struct inode *inode, nilfs_blkoff_t block)
{
	struct nilfs_inode_info *ii = NILFS_I(inode);
	int err;

	mdt_debug(3, "called (ino=%lu, blkoff=%llu)\n",
		  inode->i_ino, (unsigned long long)block);
	err = nilfs_bmap_delete(ii->i_bmap, (unsigned long)block);
	if (likely(!err)) {
		nilfs_mdt_mark_dirty(inode);
		nilfs_mdt_forget_block(inode, block);
	}
	mdt_debug(3, "done (err=%d)\n", err);
	return err;
}

/**
 * nilfs_mdt_truncate_blocks - truncate meta data file.
 * @inode: inode of the meta data file
 * @block: block offset
 *
 * Return Value: On success, zero is returned.
 * On error, one of the following negative error code is returned.
 * 
 * %-ENOMEM - Insufficient memory available.
 *
 * %-EIO - I/O error
 *
 * %-EINVAL - bmap is broken. (the caller should call nilfs_error())
 */
int nilfs_mdt_truncate_blocks(struct inode *inode, nilfs_blkoff_t block)
{
	struct nilfs_inode_info *ii = NILFS_I(inode);
	int err;

	mdt_debug(3, "called (ino=%lu, blkoff=%llu)\n",
		  inode->i_ino, (unsigned long long)block);
	err = nilfs_bmap_truncate(ii->i_bmap, (unsigned long)block);
	if (likely(!err)) {
#if 0  /* XXX: truncation of page cache should be delayed to avoid excessive
	  page removals and insertions */
		truncate_inode_pages(inode->i_mapping,
				     (loff_t)block << inode->i_blkbits);
#endif
		nilfs_mdt_mark_dirty(inode);
	}
	mdt_debug(3, "done (err=%d)\n", err);
	return err;
}

/**
 * nilfs_mdt_forget_block - discard dirty state and try to remove the page
 * @inode: inode of the meta data file
 * @block: block offset
 *
 * nilfs_mdt_forget_block() clears a dirty flag of the specified buffer, and
 * tries to release the page including the buffer from a page cache.
 *
 * Return Value: On success, 0 is returned. On error, one of the following
 * negative error code is returned.
 *
 * %-EBUSY - page has an active buffer.
 *
 * %-ENOENT - page cache has no page addressed by the offset.
 */
int nilfs_mdt_forget_block(struct inode *inode, nilfs_blkoff_t block)
{
	pgoff_t index = (pgoff_t)block >>
		(PAGE_CACHE_SHIFT - inode->i_blkbits);
	struct page *page;
	nilfs_blkoff_t first_block;
	int ret = 0;
	int still_dirty;

	mdt_debug(3, "called (ino=%lu, blkoff=%llu)\n",
		  inode->i_ino, (unsigned long long)block);
	page = find_lock_page(inode->i_mapping, index);
	if (!page)
		return -ENOENT;

	wait_on_page_writeback(page);

	first_block = (nilfs_blkoff_t)index <<
		(PAGE_CACHE_SHIFT - inode->i_blkbits);
	if (page_has_buffers(page)) {
		struct buffer_head *bh;

		bh = nilfs_page_get_nth_block(page, block - first_block);
		lock_buffer(bh);
		if (test_clear_buffer_dirty(bh) &&
		    nilfs_page_buffers_clean(page)) {
#if HAVE_CLEAR_PAGE_DIRTY
			clear_page_dirty(page);
#else
			cancel_dirty_page(page, PAGE_CACHE_SIZE);
#endif
		}
		clear_buffer_uptodate(bh);
		clear_buffer_mapped(bh);
		ClearPageUptodate(page);
		unlock_buffer(bh);
		brelse(bh);
	}
	still_dirty = PageDirty(page);
	unlock_page(page);
	page_cache_release(page);

	if (still_dirty ||
	    invalidate_inode_pages2_range(inode->i_mapping, index, index) != 0)
		ret = -EBUSY;
	mdt_debug(3, "done (err=%d)\n", ret);
	return ret;
}

/**
 * nilfs_mdt_mark_block_dirty - mark a block on the meta data file dirty.
 * @inode: inode of the meta data file
 * @block: block offset
 *
 * Return Value: On success, it returns 0. On error, the following negative
 * error code is returned.
 *
 * %-ENOMEM - Insufficient memory available.
 *
 * %-EIO - I/O error
 *
 * %-ENOENT - the specified block does not exist (hole block)
 *
 * %-EINVAL - bmap is broken. (the caller should call nilfs_error())
 */
int nilfs_mdt_mark_block_dirty(struct inode *inode, nilfs_blkoff_t block)
{
	struct buffer_head *bh;
	int err;

	err = nilfs_mdt_read_block(inode, block, &bh);
	if (unlikely(err))
		return err;
	nilfs_mdt_mark_buffer_dirty(bh);
	nilfs_mdt_mark_dirty(inode);
	brelse(bh);
	return 0;
}

static int
nilfs_mdt_write_page(struct page *page, struct writeback_control *wbc)
{
	struct inode *inode = container_of(page->mapping,
					   struct inode, i_data);
	int err;

	mdt_debug(2, "called (page=%p, index=%lu, wbc nonblocking %d, "
		  "wbc for_reclaim %d)\n",
		  page, page->index, wbc->nonblocking, wbc->for_reclaim);
	redirty_page_for_writepage(wbc, page);
	unlock_page(page);

	if (!inode->i_sb)
		return 0;
	if (wbc->sync_mode == WB_SYNC_ALL) {
		err = nilfs_construct_segment(inode->i_sb);
		if (unlikely(err))
			return err;
	} else if (wbc->for_reclaim)
		nilfs_flush_segment(NILFS_SB(inode->i_sb), inode->i_ino);
	return 0;
}


static struct address_space_operations def_mdt_aops = {
	.writepage		= nilfs_mdt_write_page,
	.releasepage		= nilfs_releasepage,
};

static struct inode_operations def_mdt_iops;
static struct file_operations def_mdt_fops;


struct inode *
nilfs_mdt_new_common(struct the_nilfs *nilfs, struct super_block *sb,
		     ino_t ino, gfp_t gfp_mask)
{
	struct inode *inode = nilfs_alloc_inode(sb);

	if (!inode)
		return NULL;
	else {
		struct address_space * const mapping = &inode->i_data;
		struct nilfs_mdt_info *mi = kzalloc(sizeof(*mi), GFP_NOFS);

		if (!mi) {
			nilfs_destroy_inode(inode);
			return NULL;
		}
		mi->mi_nilfs = nilfs;
		init_rwsem(&mi->mi_sem);

		inode->i_sb = sb; /* sb may be NULL for some meta data files */
		inode->i_blkbits = nilfs->ns_blocksize_bits;
		inode->i_flags = 0;
		atomic_set(&inode->i_count, 1);
		inode->i_nlink = 1;
		inode->i_ino = ino;
		inode->i_mode = S_IFREG;
#if NEED_INODE_GENERIC_IP
		inode->u.generic_ip = mi;
#else
		inode->i_private = mi;
#endif

#ifdef INIT_UNUSED_INODE_FIELDS
		atomic_set(&inode->i_writecount, 0);
		inode->i_size = 0;
		inode->i_blocks = 0;
		inode->i_bytes = 0;
		inode->i_generation = 0;
#ifdef CONFIG_QUOTA
		memset(&inode->i_dquot, 0, sizeof(inode->i_dquot));
#endif
		inode->i_pipe = NULL;
		inode->i_bdev = NULL;
		inode->i_cdev = NULL;
		inode->i_rdev = 0;
#ifdef CONFIG_SECURITY
		inode->i_security = NULL;
#endif
		inode->dirtied_when = 0;

		INIT_LIST_HEAD(&inode->i_list);
		INIT_LIST_HEAD(&inode->i_sb_list);
		inode->i_state = 0;
#endif

#if NEED_LOCK_INITIALIZATIONS_FOR_NEW_INODE
		spin_lock_init(&inode->i_lock);
		mutex_init(&inode->i_mutex);
		init_rwsem(&inode->i_alloc_sem);
#endif

		mapping->host = NULL;  /* instead of inode */
		mapping->flags = 0;
		mapping_set_gfp_mask(mapping, gfp_mask);
		mapping->assoc_mapping = NULL;
#ifdef USE_DEFAULT_BDEV_INFO
		mapping->backing_dev_info = nilfs->ns_bdi;
#else
		mapping->backing_dev_info = &nilfs_mdt_bdi;
#endif

		inode->i_mapping = mapping;
	}

	return inode;
}

struct inode *nilfs_mdt_new(struct the_nilfs *nilfs, struct super_block *sb,
			    ino_t ino, gfp_t gfp_mask)
{
	struct inode *inode = nilfs_mdt_new_common(nilfs, sb, ino, gfp_mask);

	if (!inode)
		return NULL;

	inode->i_op = &def_mdt_iops;
	inode->i_fop = &def_mdt_fops;
	inode->i_mapping->a_ops = &def_mdt_aops;
	return inode;
}


struct inode *
nilfs_mdt_new_with_blockgroup(struct the_nilfs *nilfs, struct super_block *sb,
			      ino_t ino, gfp_t gfp_mask, unsigned entry_size, 
			      unsigned long groups_count)
{
	struct inode *inode = nilfs_mdt_new(nilfs, sb, ino, gfp_mask);

	if (inode) {
		struct nilfs_mdt_info *mi = NILFS_MDT(inode);
		unsigned long blocksize = 1 << inode->i_blkbits;
		unsigned long entries_per_group = blocksize * 8 /* CHAR_BIT */;

		mi->mi_bgl = kmalloc(sizeof(struct blockgroup_lock), GFP_NOFS);
		if (!mi->mi_bgl) {
			nilfs_mdt_destroy(inode);
			return NULL;
		}
		bgl_lock_init(mi->mi_bgl);
		mi->mi_entry_size = entry_size;
		mi->mi_entries_per_block = blocksize / entry_size;
		mi->mi_blocks_per_group =
			entries_per_group / mi->mi_entries_per_block + 1;
		mi->mi_groups_count = groups_count;
	}
	return inode;
}

void nilfs_mdt_clear(struct inode *inode)
{
	struct nilfs_inode_info *ii = NILFS_I(inode);

	mdt_debug(2, "called (ino=%lu)\n", inode->i_ino);
#if NEED_INVALIDATE_INODE_PAGES
	invalidate_inode_pages(inode->i_mapping);
#else
	invalidate_mapping_pages(inode->i_mapping, 0, -1);
#endif
	truncate_inode_pages(inode->i_mapping, 0);
	mdt_debug(3, "called truncate_inode_pages()\n");

	nilfs_bmap_clear(ii->i_bmap);
	mdt_debug(3, "called nilfs_bmap_clear()\n");
	nilfs_btnode_cache_clear(&ii->i_btnode_cache);

	NILFS_CHECK_PAGE_CACHE(inode->i_mapping, -1);
	mdt_debug(2, "done (ino=%lu)\n", inode->i_ino);
}
