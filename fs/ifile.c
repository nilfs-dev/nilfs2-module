/*
 * ifile.c - NILFS file operations.
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
 * Written by Amagai Yoshiji <amagai@osrg.net>,
 *            Ryusuke Konishi <ryusuke@osrg.net>
 */

#include <linux/buffer_head.h>
#include "nilfs.h"
#include "page.h"
#include "mdt.h"
#include "ifile.h"

static inline void
nilfs_ifile_entry_set_flags(struct inode *ifile, struct nilfs_inode *entry,
			    unsigned int flags)
{
	entry->i_flags = cpu_to_le32(flags);
}

struct nilfs_inode *
nilfs_ifile_map_inode(struct inode *ifile, ino_t ino, struct buffer_head *ibh)
{
	void *kaddr = kmap(ibh->b_page);
	void *raw_inode = (kaddr + bh_offset(ibh)) +
		(ino % NILFS_MDT(ifile)->mi_entries_per_block)
		* NILFS_MDT(ifile)->mi_entry_size;

	return (struct nilfs_inode *)raw_inode;
}

void nilfs_ifile_unmap_inode(struct inode *ifile, ino_t ino,
			     struct buffer_head *ibh)
{
	kunmap(ibh->b_page);
}

static void
nilfs_ifile_entry_block_init(struct inode *ifile, struct buffer_head *bh,
			     void *kaddr)
{
	struct nilfs_inode *entry = kaddr + bh_offset(bh);
	int i;

	for (i = 0; i < NILFS_MDT(ifile)->mi_entries_per_block; i++) {
		nilfs_ifile_entry_set_flags(ifile, entry, 0);
				/* XXX: set USED flag */
		entry++;
	}
}

static int nilfs_ifile_prepare_alloc_ino(struct inode *ifile,
					 struct nilfs_persistent_req *req)
{
	int entries_per_group = nilfs_persistent_entries_per_group(ifile);
	unsigned long group = req->pr_ino / entries_per_group;
	int target = req->pr_ino % entries_per_group;
	int ret;

	ret = nilfs_persistent_prepare_alloc_entry(ifile, req, &group,
						   &target);
	if (!ret)
		req->pr_ino = entries_per_group * group + target;
	return ret;
}

static void nilfs_ifile_abort_alloc_ino(struct inode *ifile,
					struct nilfs_persistent_req *req)
{
	int entries_per_group = nilfs_persistent_entries_per_group(ifile);
	unsigned long group = req->pr_ino / entries_per_group;
	int grpoff = req->pr_ino % entries_per_group;

	nilfs_persistent_abort_alloc_entry(ifile, req, group, grpoff);
}

static unsigned long nilfs_ifile_entry_blkoff(struct inode *ifile, ino_t ino)
{
	int entries_per_group = nilfs_persistent_entries_per_group(ifile);
	unsigned long group = ino / entries_per_group;
	int grpoff = ino % entries_per_group;

	return nilfs_persistent_group_bitmap_blkoff(ifile, group) + 1 +
		grpoff / NILFS_MDT(ifile)->mi_entries_per_block;
}

static int nilfs_ifile_prepare_entry(struct inode *ifile,
				     struct nilfs_persistent_req *req)
{
	unsigned long blkoff = nilfs_ifile_entry_blkoff(ifile, req->pr_ino);

	return nilfs_mdt_get_block(ifile, blkoff, 1,
				   nilfs_ifile_entry_block_init,
				   &req->pr_entry_bh);
}

static int nilfs_ifile_prepare_alloc(struct inode *ifile,
				     struct nilfs_persistent_req *req)
{
	int ret;

	ret = nilfs_ifile_prepare_alloc_ino(ifile, req);
	if (!ret) {
		ret = nilfs_ifile_prepare_entry(ifile, req);
		if (ret < 0)
			nilfs_ifile_abort_alloc_ino(ifile, req);
	}
	return ret;
}

static void
nilfs_ifile_commit_alloc(struct inode *ifile, struct nilfs_persistent_req *req)
{
	nilfs_persistent_commit_alloc_entry(ifile, req);
	nilfs_mdt_mark_buffer_dirty(req->pr_entry_bh);
}

static int
nilfs_ifile_prepare_free(struct inode *ifile, struct nilfs_persistent_req *req)
{
	unsigned long group =
		req->pr_ino / nilfs_persistent_entries_per_group(ifile);
	int ret;

	ret = nilfs_persistent_prepare_free_entry(ifile, req, group);
	if (!ret) {
		ret = nilfs_ifile_prepare_entry(ifile, req);
		if (ret < 0)
			nilfs_persistent_abort_free_entry(ifile, req);
	}
	return ret;
}

static void nilfs_ifile_commit_free_ino(struct inode *ifile,
					struct nilfs_persistent_req *req)
{
	struct nilfs_persistent_group_desc *desc;
	unsigned long group;
	char *bitmap_buffer;
	int grpoff;

	group = req->pr_ino / nilfs_persistent_entries_per_group(ifile);
	grpoff = req->pr_ino % nilfs_persistent_entries_per_group(ifile);
	bitmap_buffer =
		nilfs_persistent_get_group_bitmap_buffer(ifile,
							 req->pr_bitmap_bh);

	if (!nilfs_persistent_clear_bit_atomic(nilfs_mdt_bgl_lock(ifile,
								  group),
					       grpoff, bitmap_buffer))
		printk(KERN_WARNING "inode number %lu already freed\n",
		       req->pr_ino);

	desc = nilfs_persistent_get_group_desc(ifile, group, req->pr_desc_bh);
	spin_lock(nilfs_mdt_bgl_lock(ifile, group));
	desc->pg_nfrees = cpu_to_le32(le32_to_cpu(desc->pg_nfrees) + 1);
	spin_unlock(nilfs_mdt_bgl_lock(ifile, group));

	nilfs_mdt_mark_buffer_dirty(req->pr_entry_bh);
	nilfs_mdt_mark_buffer_dirty(req->pr_bitmap_bh);

	nilfs_persistent_put_group_bitmap_buffer(ifile, req->pr_bitmap_bh);
	nilfs_persistent_put_group_bitmap_block(ifile, req->pr_bitmap_bh);
	nilfs_persistent_put_group_desc(ifile, req->pr_desc_bh);
	nilfs_persistent_put_group_desc_block(ifile, req->pr_desc_bh);
}

static void
nilfs_ifile_commit_free(struct inode *ifile, struct nilfs_persistent_req *req)
{
	struct nilfs_inode *entry;

	entry = nilfs_ifile_map_inode(ifile, req->pr_ino, req->pr_entry_bh);
	/* XXX: flags == 0 means unused ?? */
	nilfs_ifile_entry_set_flags(ifile, entry, 0);
	nilfs_ifile_unmap_inode(ifile, req->pr_ino, req->pr_entry_bh);

	nilfs_mdt_mark_buffer_dirty(req->pr_entry_bh);
	nilfs_ifile_commit_free_ino(ifile, req);
}

void
nilfs_ifile_abort_free(struct inode *ifile, struct nilfs_persistent_req *req)
{
	nilfs_persistent_put_entry_block(ifile, req->pr_entry_bh);
	nilfs_persistent_abort_free_entry(ifile, req);
}

/**
 * nilfs_ifile_create_inode - create a NILFS disk inode
 * @ifile: ifile inode
 * @ino: inode number
 * @out_bh: buffer_head contains newly allocated disk inode
 *
 * Description: nilfs_ifile_create_inode() creates a new disk inode.
 * preferably @ino.
 *
 * Return Value: On success, 0 is returned and the newly allocated inode
 * number is stored in the place pointed by @ino, and buffer_head pointer
 * that contains newly allocated disk inode structure is stored in the
 * place pointed by @out_bh
 * On error, one of the following negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 *
 * %-ENOSPC - No inode left.
 */

int nilfs_ifile_create_inode(struct inode *ifile, ino_t *out_ino,
			     struct buffer_head **out_bh)
{
	struct nilfs_persistent_req req;
	int ret;

	req.pr_ino = 0;	/* 0 says find free inode from beginning of
			   a group. dull code!! */
	req.pr_entry_bh = NULL;

	ret = nilfs_ifile_prepare_alloc(ifile, &req);
	if (ret < 0) {
		inode_debug(1, "failed (ret=%d)\n", ret);
		brelse(req.pr_entry_bh);
		return ret;
	}
	nilfs_ifile_commit_alloc(ifile, &req);
	nilfs_mdt_mark_dirty(ifile);
	*out_ino = req.pr_ino;
	*out_bh = req.pr_entry_bh;

	inode_debug(2, "allocated ino=%lu\n", *out_ino);
	return 0;
}

/**
 * nilfs_ifile_delete_inode - delete a inode
 * @ifile: ifile inode
 * @ino: inode number
 *
 * Description: nilfs_ifile_delete_inode() deletes the disk inode specified by
 * @ino, which must have been allocated by a call to nilfs_ifile_create_inode().
 *
 * Return Value: On success, 0 is returned. On error, one of the following
 * negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 *
 * %-ENOENT - The inode number @ino have not been allocated.
 */

int nilfs_ifile_delete_inode(struct inode *ifile, ino_t ino)
{
	struct nilfs_persistent_req req;
	int ret;

	req.pr_ino = ino;
	req.pr_entry_bh = NULL;
	ret = nilfs_ifile_prepare_free(ifile, &req);
	if (ret < 0) {
		brelse(req.pr_entry_bh);
		return ret;
	}

	/* XXX: check! race condition mark dirty and put_bh() */
	nilfs_ifile_commit_free(ifile, &req);
	brelse(req.pr_entry_bh);

	nilfs_mdt_mark_dirty(ifile);

	return 0;
}

int nilfs_ifile_get_inode_block(struct inode *ifile, ino_t ino,
				struct buffer_head **out_bh)
{
	struct super_block *sb = ifile->i_sb;
	unsigned long blkoff;
	int err;

	if (unlikely(!NILFS_VALID_INODE(sb, ino))) {
		nilfs_error(sb, __func__, "bad inode number: %lu",
			    (unsigned long) ino);
		return -EINVAL;
	}

	blkoff = nilfs_ifile_entry_blkoff(ifile, ino);
	err = nilfs_mdt_read_block(ifile, blkoff, out_bh);
	if (unlikely(err)) {
		if (err == -EINVAL)
			nilfs_error(sb, __func__, "ifile is broken");
		else
			nilfs_warning(sb, __func__,
				      "unable to read inode: %lu",
				      (unsigned long) ino);
	}
	return err;
}
