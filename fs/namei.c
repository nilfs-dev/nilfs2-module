/*
 * namei.c - NILFS pathname lookup operations.
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
 * Modified for NILFS by Amagai Yoshiji <amagai@osrg.net>,
 *                       Ryusuke Konishi <ryusuke@osrg.net>
 */
/*
 *  linux/fs/ext2/namei.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/namei.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 */

#include <linux/pagemap.h>
#include "nilfs.h"


static inline int nilfs_add_nondir(struct dentry *dentry, struct inode *inode)
{
	int err = nilfs_add_link(dentry, inode);
	if (!err) {
		d_instantiate(dentry, inode);
		return 0;
	}
	inode_dec_link_count(inode);
	iput(inode);
	return err;
}

/*
 * Methods themselves.
 */

static struct dentry *
nilfs_lookup(struct inode * dir, struct dentry *dentry, struct nameidata *nd)
{
	struct inode * inode;
	ino_t ino;

	if (dentry->d_name.len > NILFS_NAME_LEN)
		return ERR_PTR(-ENAMETOOLONG);

	ino = nilfs_inode_by_name(dir, dentry);
	inode = NULL;
	if (ino) {
#if NEED_READ_INODE
		inode = iget(dir->i_sb, ino);
		if (!inode)
			return ERR_PTR(-EACCES);
#else
		inode = nilfs_iget(dir->i_sb, ino);
		if (IS_ERR(inode))
			return ERR_CAST(inode);
#endif
	}
	return d_splice_alias(inode, dentry);
}

/*
 * By the time this is called, we already have created
 * the directory cache entry for the new file, but it
 * is so far negative - it has no inode.
 *
 * If the create succeeds, we fill in the inode information
 * with d_instantiate().
 */
static int nilfs_create(struct inode * dir, struct dentry * dentry, int mode,
			struct nameidata *nd)
{
	struct inode *inode;
	struct nilfs_transaction_info ti;
	int err, err2;

	err = nilfs_transaction_begin(dir->i_sb, &ti, 1);
	if (err)
		return err;
	inode = nilfs_new_inode(dir, mode);
	err = PTR_ERR(inode);
	if (!IS_ERR(inode)) {
		inode->i_op = &nilfs_file_inode_operations;
		inode->i_fop = &nilfs_file_operations;
		inode->i_mapping->a_ops = &nilfs_aops;
		mark_inode_dirty(inode);
		err = nilfs_add_nondir(dentry, inode);
	}
	err2 = nilfs_transaction_end(dir->i_sb, !err);
	return (err ? : err2);
}

static int
nilfs_mknod(struct inode * dir, struct dentry *dentry, int mode, dev_t rdev)
{
	struct inode * inode;
	struct nilfs_transaction_info ti;
	int err, err2;

	if (!new_valid_dev(rdev))
		return -EINVAL;

	err = nilfs_transaction_begin(dir->i_sb, &ti, 1);
	if (err)
		return err;
	inode = nilfs_new_inode(dir, mode);
	err = PTR_ERR(inode);
	if (!IS_ERR(inode)) {
		init_special_inode(inode, inode->i_mode, rdev);
		mark_inode_dirty(inode);
		err = nilfs_add_nondir(dentry, inode);
	}
	err2 = nilfs_transaction_end(dir->i_sb, !err);
	return (err ? : err2);
}

static int nilfs_symlink(struct inode *dir, struct dentry *dentry,
			 const char *symname)
{
	struct nilfs_transaction_info ti;
	struct super_block *sb = dir->i_sb;
	unsigned l = strlen(symname)+1;
	struct inode * inode;
	int err, err2;

	if (l > sb->s_blocksize)
		return -ENAMETOOLONG;

	err = nilfs_transaction_begin(dir->i_sb, &ti, 1);
	if (err)
		return err;

	inode = nilfs_new_inode(dir, S_IFLNK | S_IRWXUGO);
	err = PTR_ERR(inode);
	if (IS_ERR(inode))
		goto out;

	/* slow symlink */
	inode->i_op = &nilfs_symlink_inode_operations;
	inode->i_mapping->a_ops = &nilfs_aops;
	err = page_symlink(inode, symname, l);
	if (err)
		goto out_fail;

	/* mark_inode_dirty(inode); */
	/* nilfs_new_inode() and page_symlink() do this */

	err = nilfs_add_nondir(dentry, inode);
out:
	err2 = nilfs_transaction_end(dir->i_sb, !err);
	return (err ? : err2);

out_fail:
	inode_dec_link_count(inode);
	iput(inode);
	goto out;
}

static int nilfs_link(struct dentry *old_dentry, struct inode *dir,
		      struct dentry *dentry)
{
	struct inode *inode = old_dentry->d_inode;
	struct nilfs_transaction_info ti;
	int err, err2;

	if (inode->i_nlink >= NILFS_LINK_MAX)
		return -EMLINK;

	err = nilfs_transaction_begin(dir->i_sb, &ti, 1);
	if (err)
		return err;

	inode->i_ctime = CURRENT_TIME;
	inode_inc_link_count(inode);
	atomic_inc(&inode->i_count);

	err = nilfs_add_nondir(dentry, inode);
	err2 = nilfs_transaction_end(dir->i_sb, !err);
	return (err ? : err2);
}

static int nilfs_mkdir(struct inode *dir, struct dentry *dentry, int mode)
{
	struct inode * inode;
	struct nilfs_transaction_info ti;
	int err, err2;

	if (dir->i_nlink >= NILFS_LINK_MAX)
		return -EMLINK;

	err = nilfs_transaction_begin(dir->i_sb, &ti, 1);
	if (err)
		return err;

	inode_inc_link_count(dir);

	inode = nilfs_new_inode(dir, S_IFDIR | mode);
	err = PTR_ERR(inode);
	if (IS_ERR(inode))
		goto out_dir;

	inode->i_op = &nilfs_dir_inode_operations;
	inode->i_fop = &nilfs_dir_operations;
	inode->i_mapping->a_ops = &nilfs_aops;

	inode_inc_link_count(inode);

	err = nilfs_make_empty(inode, dir);
	if (err)
		goto out_fail;

	err = nilfs_add_link(dentry, inode);
	if (err)
		goto out_fail;

	d_instantiate(dentry, inode);
out:
	err2 = nilfs_transaction_end(dir->i_sb, !err);
	return (err ? : err2);

out_fail:
	inode_dec_link_count(inode);
	inode_dec_link_count(inode);
	iput(inode);
out_dir:
	inode_dec_link_count(dir);
	goto out;
}

static int nilfs_unlink(struct inode *dir, struct dentry *dentry)
{
	struct inode * inode;
	struct nilfs_dir_entry * de;
	struct page * page;
	struct nilfs_transaction_info ti;
	int err, err2;

	err = nilfs_transaction_begin(dir->i_sb, &ti, 0);
	if (err)
		return err;

	err = -ENOENT;
	de = nilfs_find_entry(dir, dentry, &page);
	if (!de)
		goto out;

	inode = dentry->d_inode;
	err = -EIO;
	if (le64_to_cpu(de->inode) != inode->i_ino)
		goto out;

	if (!inode->i_nlink) {
		nilfs_warning(inode->i_sb, __FUNCTION__,
			      "deleting nonexistent file (%lu), %d\n",
			      inode->i_ino, inode->i_nlink);
		inode->i_nlink = 1;
	}
	err = nilfs_delete_entry(de, page);
	if (err)
		goto out;

	inode->i_ctime = dir->i_ctime;
	inode_dec_link_count(inode);
	err = 0;
out:
	err2 = nilfs_transaction_end(dir->i_sb, !err);
	return (err ? : err2);
}

static int nilfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct inode * inode = dentry->d_inode;
	struct nilfs_transaction_info ti;
	int err, err2;

	err = nilfs_transaction_begin(dir->i_sb, &ti, 0);
	if (err)
		return err;

	err = -ENOTEMPTY;
	if (nilfs_empty_dir(inode)) {
		err = nilfs_unlink(dir, dentry);
		if (!err) {
			inode->i_size = 0;
			inode_dec_link_count(inode);
			inode_dec_link_count(dir);
		}
	}
	err2 = nilfs_transaction_end(dir->i_sb, !err);
	return (err ? : err2);
}

static int nilfs_rename(struct inode *old_dir, struct dentry *old_dentry,
			struct inode *new_dir,	struct dentry *new_dentry)
{
	struct inode * old_inode = old_dentry->d_inode;
	struct inode * new_inode = new_dentry->d_inode;
	struct page * dir_page = NULL;
	struct nilfs_dir_entry * dir_de = NULL;
	struct page * old_page;
	struct nilfs_dir_entry * old_de;
	struct nilfs_transaction_info ti;
	int err;

	err = nilfs_transaction_begin(old_dir->i_sb, &ti, 1);
	if (unlikely(err))
		return err;

	err = -ENOENT;
	old_de = nilfs_find_entry(old_dir, old_dentry, &old_page);
	if (!old_de)
		goto out;

	if (S_ISDIR(old_inode->i_mode)) {
		err = -EIO;
		dir_de = nilfs_dotdot(old_inode, &dir_page);
		if (!dir_de)
			goto out_old;
	}

	if (new_inode) {
		struct page *new_page;
		struct nilfs_dir_entry *new_de;

		err = -ENOTEMPTY;
		if (dir_de && !nilfs_empty_dir(new_inode))
			goto out_dir;

		err = -ENOENT;
		new_de = nilfs_find_entry(new_dir, new_dentry, &new_page);
		if (!new_de)
			goto out_dir;
		inode_inc_link_count(old_inode);
		nilfs_set_link(new_dir, new_de, new_page, old_inode);
		new_inode->i_ctime = CURRENT_TIME;
		if (dir_de)
			drop_nlink(new_inode);
		inode_dec_link_count(new_inode);
	} else {
		if (dir_de) {
			err = -EMLINK;
			if (new_dir->i_nlink >= NILFS_LINK_MAX)
				goto out_dir;
		}
		inode_inc_link_count(old_inode);
		err = nilfs_add_link(new_dentry, old_inode);
		if (err) {
			inode_dec_link_count(old_inode);
			goto out_dir;
		}
		if (dir_de)
			inode_inc_link_count(new_dir);
	}

	/*
	 * Like most other Unix systems, set the ctime for inodes on a
	 * rename.
	 * inode_dec_link_count() will mark the inode dirty.
	 */
	old_inode->i_ctime = CURRENT_TIME;

	nilfs_delete_entry(old_de, old_page);
	inode_dec_link_count(old_inode);

	if (dir_de) {
		nilfs_set_link(old_inode, dir_de, dir_page, new_dir);
		inode_dec_link_count(old_dir);
	}

	err = nilfs_transaction_end(old_dir->i_sb, 1);
	return err;

out_dir:
	if (dir_de) {
		kunmap(dir_page);
		page_cache_release(dir_page);
	}
out_old:
	kunmap(old_page);
	page_cache_release(old_page);
out:
	nilfs_transaction_end(old_dir->i_sb, 0);
	return err;
}

struct inode_operations nilfs_dir_inode_operations = {
	.create		= nilfs_create,
	.lookup		= nilfs_lookup,
	.link		= nilfs_link,
	.unlink		= nilfs_unlink,
	.symlink	= nilfs_symlink,
	.mkdir		= nilfs_mkdir,
	.rmdir		= nilfs_rmdir,
	.mknod		= nilfs_mknod,
	.rename		= nilfs_rename,
	.setattr	= nilfs_setattr,
	.permission	= nilfs_permission,
};

struct inode_operations nilfs_special_inode_operations = {
	.setattr	= nilfs_setattr,
	.permission	= nilfs_permission,
};

struct inode_operations nilfs_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= page_follow_link_light,
	.put_link	= page_put_link,
};
