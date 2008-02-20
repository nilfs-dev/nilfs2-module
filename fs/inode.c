/*
 * inode.c - NILFS inode operations.
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
 * inode.c,v 1.63 2008-02-12 08:38:22 ryusuke Exp
 *
 * Written by Ryusuke Konishi <ryusuke@osrg.net>
 *
 */

#include <linux/buffer_head.h>
#include <linux/mpage.h>
#include <linux/writeback.h>
#include "nilfs.h"
#include "page.h"
#include "mdt.h"
#include "cpfile.h"
#include "ifile.h"


/**
 * nilfs_get_block() - get a file block on the filesystem (callback function)
 * @inode - inode struct of the target file
 * @blkoff - file block number
 * @bh_result - buffer head to be mapped on
 * @create - indicate whether allocating the block or not when it has not
 *      been allocated yet.
 *
 * This function does not issue actual read request of the specified data
 * block. It is done by VFS.
 * Bulk read for direct-io is not supported yet. (should be supported)
 */
int nilfs_get_block(struct inode *inode, sector_t blkoff, 
		    struct buffer_head *bh_result, int create)
{
	struct nilfs_inode_info *ii = NILFS_I(inode);
	unsigned long blknum = 0;
	int err = 0, ret;
	struct inode *dat = nilfs_dat_inode(NILFS_I_NILFS(inode));

	/* This exclusion control is a workaround; should be revised */
	down_read(&NILFS_MDT(dat)->mi_sem);	/* XXX */
	ret = nilfs_bmap_lookup(ii->i_bmap, (unsigned long)blkoff, &blknum);
	up_read(&NILFS_MDT(dat)->mi_sem);	/* XXX */
	if (ret == 0) {	/* found */
		map_bh(bh_result, inode->i_sb, blknum);
		goto out;
	}
	if (unlikely(ret == 1)) {
		printk(KERN_ERR "nilfs_get_block: bmap_lookup returns "
		       "buffer_head pointer (blkoff=%llu, blknum=%lu)\n",
		       (unsigned long long)blkoff, blknum);
		BUG();
	}
	/* data block was not found */
	if (ret == -ENOENT && create) {
		struct nilfs_transaction_info ti;

		bh_result->b_blocknr = 0;
		ret = nilfs_transaction_begin(inode->i_sb, &ti, 1);
		if (unlikely(ret))
			goto out;
		ret = nilfs_bmap_insert(ii->i_bmap, (unsigned long)blkoff, 
					(unsigned long)bh_result);
		nilfs_transaction_end(inode->i_sb, !ret);
		/* How can we recover dirtied btree, if inserted block is 
		   abandoned without being dirtied ?? */
		if (unlikely(ret != 0)) {
			if (ret == -EEXIST) {
				/*
				 * The get_block() function could be called
				 * from multiple callers for an inode.
				 * However, the page having this block must
				 * be locked in this case.
				 */
				printk(KERN_ERR
				       "nilfs_get_block: a race condition "
				       "while inserting a data block. "
				       "(inode number=%lu, file block "
				       "offset=%llu)\n",
				       inode->i_ino,
				       (unsigned long long)blkoff);
				BUG();
			}
			err = nilfs_handle_bmap_error(ret, __FUNCTION__,
						      inode, inode->i_sb);
			goto out;
		}
		/* Error handling should be detailed */
		set_buffer_new(bh_result);
		map_bh(bh_result, inode->i_sb, 0); /* dbn must be changed
						      to proper value */
	} else if (ret == -ENOENT) {
                /* not found is not error (e.g. hole); must return without 
                   the mapped state flag. */
		;
	} else {
		err = ret;
	}

 out:
	return err;
}

/**
 * nilfs_readpage() - implement readpage() method of nilfs_aops {}
 * address_space_operations.
 * @file - file struct of the file to be read
 * @page - the page to be read
 */
static int nilfs_readpage(struct file *file, struct page *page)
{
	return mpage_readpage(page, nilfs_get_block);
}

/**
 * nilfs_readpages() - implement readpages() method of nilfs_aops {}
 * address_space_operations.
 * @file - file struct of the file to be read
 * @mapping - address_space struct used for reading multiple pages
 * @pages - the pages to be read
 * @nr_pages - number of pages to be read
 */
static int nilfs_readpages(struct file *file, struct address_space *mapping,
			   struct list_head *pages, unsigned nr_pages)
{
	return mpage_readpages(mapping, pages, nr_pages, nilfs_get_block);
}

static int nilfs_writepages(struct address_space *mapping,
			    struct writeback_control *wbc)
{
	/* This empty method is required not to call generic_writepages() */
	page_debug(3, "called but ignored (mapping=%p)\n", mapping);
	return 0;
}

static int nilfs_writepage(struct page *page, struct writeback_control *wbc)
{
	struct inode *inode = page->mapping->host;
	int err;

	page_debug(3, "called (page=%p, index=%lu, wbc nonblocking %d, "
		   "wbc for_reclaim %d)\n",
		    page, page->index, wbc->nonblocking, wbc->for_reclaim);
	redirty_page_for_writepage(wbc, page);
	unlock_page(page);

	if (wbc->sync_mode == WB_SYNC_ALL) {
		err = nilfs_construct_segment(inode->i_sb);
		if (unlikely(err))
			return err;
	} else if (wbc->for_reclaim)
		nilfs_flush_segment(NILFS_SB(inode->i_sb), inode->i_ino);

	return 0;
}

static int nilfs_set_page_dirty(struct page *page)
{
	int ret = __set_page_dirty_buffers(page);

	page_debug(3, "called (page=%p)\n", page);
	if (ret) {
		struct inode *inode = page->mapping->host;
		struct nilfs_sb_info *sbi = NILFS_SB(inode->i_sb);
		unsigned nr_dirty = 1 << (PAGE_SHIFT - inode->i_blkbits);

		nilfs_set_file_dirty(sbi, inode, nr_dirty);
	}
	page_debug(3, "done (ret=%d, page=%p)\n", ret, page);
	return ret;
}

#if HAVE_WRITE_BEGIN_WRITE_END
static int nilfs_write_begin(struct file *file, struct address_space *mapping,
			     loff_t pos, unsigned len, unsigned flags,
			     struct page **pagep, void **fsdata)

{
	struct inode *inode = mapping->host;
	int err = nilfs_prepare_file_dirty(inode);

	if (unlikely(err))
		return err;

	*pagep = NULL;
	err = block_write_begin(file, mapping, pos, len, flags, pagep,
				fsdata, nilfs_get_block);
	if (unlikely(err))
		nilfs_cancel_file_dirty(inode);
	return err;
}

static int nilfs_write_end(struct file *file, struct address_space *mapping,
			   loff_t pos, unsigned len, unsigned copied,
			   struct page *page, void *fsdata)
{
	struct inode *inode = mapping->host;
	unsigned start = pos & (PAGE_CACHE_SIZE - 1);
	unsigned nr_dirty;
	int err;

	nr_dirty = nilfs_page_count_clean_buffers(page, start,
						  start + copied);
	copied = generic_write_end(file, mapping, pos, len, copied, page,
				   fsdata);
	err = nilfs_commit_dirty_file(inode, nr_dirty);
	return err ? : copied;
}
#else /* HAVE_WRITE_BEGIN_WRITE_END */
static int nilfs_prepare_write(struct file *file, struct page *page,
			       unsigned from, unsigned to)
{
	struct address_space *mapping = page->mapping;
	pgoff_t offset = page->index;
	struct inode *inode = mapping->host;
	int err;
#if !HAVE_AOP_TRUNCATED_PAGE
	struct buffer_head *bh;

	if (!page_has_buffers(page))
		create_empty_buffers(page, 1 << inode->i_blkbits, 0);
	bh = page_buffers(page);
	get_bh(bh); /* workaround to prevent the page from being released. */
#endif

	unlock_page(page);
	err = nilfs_prepare_file_dirty(inode);
	lock_page(page);
#if HAVE_AOP_TRUNCATED_PAGE
	if (unlikely(page->mapping != mapping || page->index != offset)) {
		unlock_page(page);
		if (likely(!err))
			nilfs_cancel_file_dirty(inode);
		return AOP_TRUNCATED_PAGE;
	}
#else
	brelse(bh);
	if (unlikely(page->mapping != mapping || page->index != offset)) {
		PAGE_DEBUG(page, "page was truncated unexpectedly");
		BUG();
	}
#endif
	if (unlikely(err))
		return err;

 	err = block_prepare_write(page, from, to, nilfs_get_block);
	if (unlikely(err))
		nilfs_cancel_file_dirty(inode);
	return err;
}

static int nilfs_commit_write(struct file *file, struct page *page,
			      unsigned from, unsigned to)
{
	struct inode *inode = page->mapping->host;
	unsigned nr_dirty = nilfs_page_count_clean_buffers(page, from, to);

	generic_commit_write(file, page, from, to);
	return nilfs_commit_dirty_file(inode, nr_dirty);
}
#endif /* HAVE_WRITE_BEGIN_WRITE_END */

#if NEED_GET_BLOCKS_T
static int nilfs_get_blocks(struct inode *inode, sector_t blkoff,
			    unsigned long max_blocks,
			    struct buffer_head *bh_result, int create)
{
	int ret;

	ret = nilfs_get_block(inode, blkoff, bh_result, create);
	if (likely(ret == 0))
		bh_result->b_size = (1 << inode->i_blkbits);
	return ret;
}
#endif

static ssize_t
nilfs_direct_IO(int rw, struct kiocb *iocb, const struct iovec *iov,
		loff_t offset, unsigned long nr_segs)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	ssize_t size;
	int err;

	err = nilfs_construct_dsync_segment(inode->i_sb, inode);
	if (unlikely(err))
		return err;

	if (rw == WRITE) {
		inode_debug(2, "falling back to buffered write."
			    "(ino=%lu, offset=%llu, nseg=%lu)\n",
			    inode->i_ino, offset, nr_segs);
		return 0;
	}
	/* Needs synchronization with the cleaner */
	size = blockdev_direct_IO(rw, iocb, inode, inode->i_sb->s_bdev, iov,
				  offset, nr_segs,
#if NEED_GET_BLOCKS_T
				  nilfs_get_blocks,
#else
				  nilfs_get_block,
#endif
				  NULL);
	inode_debug(3, "called blockdev_direct_IO() for a read request."
		    "(ino=%lu, offset=%llu, nr_segs=%lu, result=%Zd)\n",
		    inode->i_ino, offset, nr_segs, size);
	return size;
}

struct address_space_operations nilfs_aops = {
	.writepage		= nilfs_writepage,
	.readpage		= nilfs_readpage,
	.sync_page		= nilfs_sync_page,
	.writepages		= nilfs_writepages,
	.set_page_dirty         = nilfs_set_page_dirty,
	.readpages		= nilfs_readpages,
#if HAVE_WRITE_BEGIN_WRITE_END
	.write_begin		= nilfs_write_begin,
	.write_end		= nilfs_write_end,
#else
	.prepare_write		= nilfs_prepare_write,
	.commit_write		= nilfs_commit_write,
#endif
	.releasepage		= nilfs_releasepage,
	.invalidatepage		= nilfs_invalidatepage,
        .direct_IO		= nilfs_direct_IO,
};

struct inode *nilfs_new_inode(struct inode *dir, int mode)
{
	struct super_block *sb = dir->i_sb;
	struct nilfs_sb_info *sbi = NILFS_SB(sb);
	struct inode *inode;
	struct nilfs_inode_info *ii;
	int err = -ENOMEM;
	ino_t ino;

	inode_debug(3, "called (dir-ino=%lu, mode=0%o)\n",
		    dir->i_ino, mode);
	inode = new_inode(sb);
	if (unlikely(!inode))
		goto failed;

	mapping_set_gfp_mask(inode->i_mapping,
			     mapping_gfp_mask(inode->i_mapping) & ~__GFP_FS);
	
	ii = NILFS_I(inode);
	ii->i_state = 1 << NILFS_I_NEW;

	err = nilfs_ifile_create_inode(sbi->s_ifile, &ino, &ii->i_bh);
	if (unlikely(err))
		goto failed_ifile_create_inode;
	/* reference count of i_bh inherits from nilfs_mdt_read_block() */

	atomic_inc(&sbi->s_inodes_count);

	inode->i_uid = current->fsuid;
	if (dir->i_mode & S_ISGID) {
		inode->i_gid = dir->i_gid;
		if (S_ISDIR(mode))
			mode |= S_ISGID;
	} else
		inode->i_gid = current->fsgid;

	inode->i_mode = mode;
	inode->i_ino = ino;
#if NEED_INODE_BLKSIZE
	inode->i_blksize = PAGE_SIZE;	/* This is the optimal IO size 
					   (for stat), not fs block size */
#endif
	inode->i_mtime = inode->i_atime = inode->i_ctime = CURRENT_TIME;

	if (S_ISREG(mode) || S_ISDIR(mode) || S_ISLNK(mode)) {
		err = nilfs_bmap_read(ii->i_bmap, NULL);
		if (err < 0) {
			inode_debug(1, "nilfs_bmap_read failed "
				    "(err=%d, ino=%lu)\n", err, inode->i_ino);
			goto failed_bmap;
		}
		set_bit(NILFS_I_BMAP, &ii->i_state);
		/* No lock is needed; iget() ensures it. */
	}

	ii->i_flags = NILFS_I(dir)->i_flags;
	if (S_ISLNK(mode))
		ii->i_flags &= ~(NILFS_IMMUTABLE_FL | NILFS_APPEND_FL);
	if (!S_ISDIR(mode))
		ii->i_flags &= ~NILFS_DIRSYNC_FL;

	/* ii->i_file_acl = 0; */
	/* ii->i_dir_acl = 0; */
	ii->i_dtime = 0;
	ii->i_dir_start_lookup = 0;
#ifdef CONFIG_NILFS_FS_POSIX_ACL
	ii->i_acl = NULL;
	ii->i_default_acl = NULL;
#endif
	ii->i_cno = 0;
	nilfs_set_inode_flags(inode);
	spin_lock(&sbi->s_next_gen_lock);
	inode->i_generation = sbi->s_next_generation++;
	spin_unlock(&sbi->s_next_gen_lock);
	insert_inode_hash(inode);

	err = nilfs_init_acl(inode, dir);
	if (unlikely(err))
		goto failed_acl; /* never occur. When supporting
				    nilfs_init_acl(), proper cancellation of
				    above jobs should be considered */

	mark_inode_dirty(inode);
	inode_debug(3, "done (ino=%lu, dir-ino=%lu)\n",
		    inode->i_ino, dir->i_ino);
	return inode;

 failed_acl:
 failed_bmap:
	inode->i_nlink = 0;
	iput(inode);  /* raw_inode will be deleted through
			 generic_delete_inode() */
	goto failed;

 failed_ifile_create_inode:
	make_bad_inode(inode);
	iput(inode);  /* if i_nlink == 1, generic_forget_inode() will be
			 called */
 failed:
	inode_debug(1, "failed (err=%d, dir-ino=%lu)\n", err, dir->i_ino);
	return ERR_PTR(err);
}

void nilfs_free_inode(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct nilfs_sb_info *sbi = NILFS_SB(sb);

	clear_inode(inode);
	/* XXX: check error code? Is there any thing can I do? */
	(void) nilfs_ifile_delete_inode(sbi->s_ifile, inode->i_ino);
	atomic_dec(&sbi->s_inodes_count);
}

void nilfs_set_inode_flags(struct inode *inode)
{
	unsigned int flags = NILFS_I(inode)->i_flags;

	inode->i_flags &= ~(S_SYNC | S_APPEND | S_IMMUTABLE | S_NOATIME |
			    S_DIRSYNC);
	if (flags & NILFS_SYNC_FL)
		inode->i_flags |= S_SYNC;
	if (flags & NILFS_APPEND_FL)
		inode->i_flags |= S_APPEND;
	if (flags & NILFS_IMMUTABLE_FL)
		inode->i_flags |= S_IMMUTABLE;
#ifndef NILFS_ATIME_DISABLE
	if (flags & NILFS_NOATIME_FL)
#endif
		inode->i_flags |= S_NOATIME;
	if (flags & NILFS_DIRSYNC_FL)
		inode->i_flags |= S_DIRSYNC;
	mapping_set_gfp_mask(inode->i_mapping,
			     mapping_gfp_mask(inode->i_mapping) & ~__GFP_FS);
}

int nilfs_read_inode_common(struct inode *inode,
			    struct nilfs_inode *raw_inode)
{
	struct nilfs_inode_info *ii = NILFS_I(inode);
	int err;

	inode_debug(3, "called (ino=%lu, raw_inode=%p)\n",
		    inode->i_ino, raw_inode);
	inode->i_mode = le16_to_cpu(raw_inode->i_mode);
	inode->i_uid = (uid_t)le32_to_cpu(raw_inode->i_uid);
	inode->i_gid = (gid_t)le32_to_cpu(raw_inode->i_gid);
	inode->i_nlink = le16_to_cpu(raw_inode->i_links_count);
	inode->i_size = le64_to_cpu(raw_inode->i_size);
	inode->i_atime.tv_sec = le64_to_cpu(raw_inode->i_mtime);
	inode->i_ctime.tv_sec = le64_to_cpu(raw_inode->i_ctime);
	inode->i_mtime.tv_sec = le64_to_cpu(raw_inode->i_mtime);
	inode->i_atime.tv_nsec = 0;
	inode->i_ctime.tv_nsec = 0;
	inode->i_mtime.tv_nsec = 0;
	ii->i_dtime = le64_to_cpu(raw_inode->i_dtime);
	if (inode->i_nlink == 0 && (inode->i_mode == 0 || ii->i_dtime))
		return -EINVAL; /* this inode is deleted */

#if NEED_INODE_BLKSIZE
	inode->i_blksize = PAGE_SIZE; /* optimal IO size (for stat), not the
					 fs block size */
#endif
	inode->i_blocks = le64_to_cpu(raw_inode->i_blocks);
	ii->i_flags = le32_to_cpu(raw_inode->i_flags);
#if 0
	ii->i_file_acl = le32_to_cpu(raw_inode->i_file_acl);
	ii->i_dir_acl = S_ISREG(inode->i_mode) ?
		0 : le32_to_cpu(raw_inode->i_dir_acl);
#endif
	ii->i_cno = 0;
	inode->i_generation = le32_to_cpu(raw_inode->i_generation);

	if (S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode) ||
	    S_ISLNK(inode->i_mode)) {
		err = nilfs_bmap_read(ii->i_bmap, raw_inode);
		if (err < 0) {
			inode_debug(1, "nilfs_bmap_read failed "
				    "(err=%d, ino=%lu)\n", err, inode->i_ino);
			return err;
		}
		set_bit(NILFS_I_BMAP, &ii->i_state);
		/* No lock is needed; iget() ensures it. */
	}
	inode_debug(3, "done\n");
	return 0;
}

static int nilfs_read_sketch_inode(struct inode *inode)
{
	struct nilfs_sb_info *sbi = NILFS_SB(inode->i_sb);
	int err = 0;

	if (sbi->s_snapshot_cno) {
		struct the_nilfs *nilfs = sbi->s_nilfs;
		struct buffer_head *bh_cp;
		struct nilfs_checkpoint *raw_cp;

		err = nilfs_cpfile_get_checkpoint(
			nilfs->ns_cpfile, sbi->s_snapshot_cno, 0, &raw_cp,
			&bh_cp);
		if (likely(!err)) {
			if (!nilfs_checkpoint_sketch(raw_cp))
				inode->i_size = 0;
			nilfs_cpfile_put_checkpoint(
				nilfs->ns_cpfile, sbi->s_snapshot_cno, bh_cp);
		}
		inode->i_flags |= S_NOCMTIME;
	}
	return err;
}

static inline int __nilfs_read_inode(struct super_block *sb, unsigned long ino,
				     struct inode *inode)
{
	struct nilfs_sb_info *sbi = NILFS_SB(sb);
	struct inode *dat = nilfs_dat_inode(sbi->s_nilfs);
	struct buffer_head *bh;
	struct nilfs_inode *raw_inode;
	int err;

	down_read(&NILFS_MDT(dat)->mi_sem);	/* XXX */
	err = nilfs_ifile_get_inode_block(sbi->s_ifile, ino, &bh);
	if (unlikely(err))
		goto bad_inode;

	raw_inode = nilfs_ifile_map_inode(sbi->s_ifile, ino, bh);

	if (unlikely(raw_inode->i_flags & 
		     cpu_to_le32(NILFS_INODE_NEW | NILFS_INODE_UNUSED))) {
		nilfs_warning(sb, __FUNCTION__,
			      "read request for unused inode: %lu", ino);
		goto failed_unmap;
	}

#ifdef CONFIG_NILFS_FS_POSIX_ACL
	ii->i_acl = NILFS_ACL_NOT_CACHED;
	ii->i_default_acl = NILFS_ACL_NOT_CACHED;
#endif
	if (nilfs_read_inode_common(inode, raw_inode))
		goto failed_unmap;

	if (S_ISREG(inode->i_mode)) {
		inode->i_op = &nilfs_file_inode_operations;
		inode->i_fop = &nilfs_file_operations;
		inode->i_mapping->a_ops = &nilfs_aops;
		if (unlikely(inode->i_ino == NILFS_SKETCH_INO)) {
			err = nilfs_read_sketch_inode(inode);
			if (unlikely(err))
				goto failed_unmap;
		}
	} else if (S_ISDIR(inode->i_mode)) {
		inode->i_op = &nilfs_dir_inode_operations;
		inode->i_fop = &nilfs_dir_operations;
		inode->i_mapping->a_ops = &nilfs_aops;
	} else if (S_ISLNK(inode->i_mode)) {
		inode->i_op = &nilfs_symlink_inode_operations;
		inode->i_mapping->a_ops = &nilfs_aops;
	} else {
		inode->i_op = &nilfs_special_inode_operations;
		init_special_inode(
			inode, inode->i_mode,
			new_decode_dev(le64_to_cpu(raw_inode->i_device_code)));
	}
	nilfs_ifile_unmap_inode(sbi->s_ifile, ino, bh);
	brelse(bh);
	up_read(&NILFS_MDT(dat)->mi_sem);	/* XXX */
	nilfs_set_inode_flags(inode);
	return 0;

 failed_unmap:
	nilfs_ifile_unmap_inode(sbi->s_ifile, ino, bh);
	brelse(bh);

 bad_inode:
	up_read(&NILFS_MDT(dat)->mi_sem);	/* XXX */
	return err;
}

#if NEED_READ_INODE
void nilfs_read_inode(struct inode *inode)
{
	if (__nilfs_read_inode(inode->i_sb, inode->i_ino, inode) < 0)
		make_bad_inode(inode);
}
#else
struct inode *nilfs_iget(struct super_block *sb, unsigned long ino)
{
	struct inode *inode;
	int err;

	inode = iget_locked(sb, ino);
	if (unlikely(!inode))
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	err = __nilfs_read_inode(sb, ino, inode);
	if (unlikely(err)) {
		iget_failed(inode);
		return ERR_PTR(err);
	}
	unlock_new_inode(inode);
	return inode;
}
#endif /* NEED_READ_INODE */

void nilfs_write_inode_common(struct inode *inode,
			      struct nilfs_inode *raw_inode, int has_bmap)
{
	struct nilfs_inode_info *ii = NILFS_I(inode);

	raw_inode->i_mode = cpu_to_le16(inode->i_mode);
	raw_inode->i_uid = cpu_to_le32(inode->i_uid);
	raw_inode->i_gid = cpu_to_le32(inode->i_gid);
	raw_inode->i_links_count = cpu_to_le16(inode->i_nlink);
	raw_inode->i_size = cpu_to_le64(inode->i_size);
	raw_inode->i_ctime = cpu_to_le64(inode->i_ctime.tv_sec);
	raw_inode->i_mtime = cpu_to_le64(inode->i_mtime.tv_sec);
	raw_inode->i_blocks = cpu_to_le64(inode->i_blocks);

	raw_inode->i_dtime = cpu_to_le64(ii->i_dtime);
	raw_inode->i_flags = cpu_to_le32(ii->i_flags);
	raw_inode->i_generation = cpu_to_le32(inode->i_generation);

	if (has_bmap) {
		nilfs_bmap_write(ii->i_bmap, raw_inode);
		nilfs_print_bmap_direct_pointers(inode, raw_inode);
	} else if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode))
		raw_inode->i_device_code =
			cpu_to_le64(new_encode_dev(inode->i_rdev));
	/* When extending inode, nilfs->ns_inode_size should be checked
	   for substitutions of appended fields */
}

void nilfs_update_inode(struct inode *inode, struct buffer_head *ibh)
{
	ino_t ino = inode->i_ino;
	struct nilfs_inode_info *ii = NILFS_I(inode);
	struct super_block *sb = inode->i_sb;
	struct nilfs_sb_info *sbi = NILFS_SB(sb);
	struct nilfs_inode *raw_inode;

	raw_inode = nilfs_ifile_map_inode(sbi->s_ifile, ino, ibh);

	/* The buffer is guarded with lock_buffer() by the caller */
	if (test_and_clear_bit(NILFS_I_NEW, &ii->i_state))
		memset(raw_inode, 0, NILFS_MDT(sbi->s_ifile)->mi_entry_size);
	set_bit(NILFS_I_INODE_DIRTY, &ii->i_state);

	nilfs_write_inode_common(inode, raw_inode, 0);
		/* XXX: call with has_bmap = 0 is a workaround to avoid
		   deadlock of bmap. This delays update of i_bmap to just
		   before writing */
	nilfs_ifile_unmap_inode(sbi->s_ifile, ino, ibh);
}

void nilfs_truncate(struct inode *inode)
{
	nilfs_blkoff_t blkoff;
	unsigned int blocksize;
	struct nilfs_transaction_info ti;
	struct super_block *sb = inode->i_sb;
	struct nilfs_inode_info *ii = NILFS_I(inode);
	int ret;

	inode_debug(2, "called. (ino=%lu)\n", inode->i_ino);
	if (!test_bit(NILFS_I_BMAP, &ii->i_state))
		return;
	if (IS_APPEND(inode) || IS_IMMUTABLE(inode))
		return;

	blocksize = sb->s_blocksize;
	blkoff = (inode->i_size + blocksize - 1) >> NILFS_BLOCK_SIZE_BITS(sb);
	ret = nilfs_transaction_begin(sb, &ti, 0);
	BUG_ON(ret);

	block_truncate_page(inode->i_mapping, inode->i_size, nilfs_get_block);

	ret = nilfs_bmap_truncate(ii->i_bmap, blkoff);

	inode->i_mtime = inode->i_ctime = CURRENT_TIME;
	if (IS_SYNC(inode))
		nilfs_set_transaction_flag(NILFS_TI_SYNC);
		
	nilfs_commit_dirty_file(inode, 0);
        /* May construct a logical segment and may fail in sync mode.
	   But truncate has no return value. */
}

void nilfs_delete_inode(struct inode *inode)
{
	struct nilfs_transaction_info ti;
	struct super_block *sb = inode->i_sb;
	struct nilfs_inode_info *ii = NILFS_I(inode);
	int err;

	if (unlikely(is_bad_inode(inode))) {
#if NEED_TRUNCATE_INODE_PAGES
		if (inode->i_data.nrpages)
			truncate_inode_pages(&inode->i_data, 0);
#endif
		clear_inode(inode);
		return;
	}
	err = nilfs_transaction_begin(sb, &ti, 0);
	BUG_ON(err);
#if NEED_TRUNCATE_INODE_PAGES
	if (inode->i_data.nrpages)
		truncate_inode_pages(&inode->i_data, 0);
#endif
	if (test_bit(NILFS_I_BMAP, &ii->i_state)) {
		err = nilfs_bmap_terminate(ii->i_bmap);
		if (unlikely(err)) {
			if (err == -EINVAL)
				nilfs_error(sb, __FUNCTION__,
					    "bmap is broken (ino=%lu)",
					    inode->i_ino);
			else
				nilfs_warning(sb, __FUNCTION__,
					      "failed to terminate bmap "
					      "(ino=%lu, err=%d)",
					      inode->i_ino, err);
		}
	}

	nilfs_free_inode(inode);
	/* nilfs_free_inode() marks inode buffer dirty */
	if (IS_SYNC(inode))
		nilfs_set_transaction_flag(NILFS_TI_SYNC);
	nilfs_transaction_end(sb, 1);
        /* May construct a logical segment and may fail in sync mode.
	   But delete_inode has no return value. */
}

int nilfs_setattr(struct dentry *dentry, struct iattr *iattr)
{
	struct nilfs_transaction_info ti;
	struct inode *inode = dentry->d_inode;
	struct super_block *sb = inode->i_sb;
	int err, err2;

	err = inode_change_ok(inode, iattr);
	if (err)
		return err;

	err = nilfs_transaction_begin(sb, &ti, 0);
	if (unlikely(err))
		return err;
	err = inode_setattr(inode, iattr);
	if (!err && (iattr->ia_valid & ATTR_MODE))
		err = nilfs_acl_chmod(inode);
	err2 = nilfs_transaction_end(sb, 1);
	return (err ? : err2);
}

int nilfs_load_inode_block_nolock(struct nilfs_sb_info *sbi,
				  struct inode *inode,
				  struct buffer_head **pbh)
{
	struct nilfs_inode_info *ii = NILFS_I(inode);
	int err;

	/* Caller of this function MUST lock s_inode_lock */
	if (ii->i_bh == NULL) {
		spin_unlock(&sbi->s_inode_lock);
		err = nilfs_ifile_get_inode_block(sbi->s_ifile, inode->i_ino,
						  pbh);
		spin_lock(&sbi->s_inode_lock);
		if (unlikely(err))
			return err;
		if (ii->i_bh == NULL)
			ii->i_bh = *pbh;
		else {
			brelse(*pbh);
			*pbh = ii->i_bh;
		}
	} else
		*pbh = ii->i_bh;

	get_bh(*pbh);
	return 0;
}
