/*
 * gcinode.c - NILFS memory inode for GC
 *
 * Copyright (C) 2005-2008 Nippon Telegraph and Telephone Corporation.
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
 * Written by Seiji Kihara <kihara@osrg.net>, Amagai Yoshiji <amagai@osrg.net>,
 *            and Ryusuke Konishi <ryusuke@osrg.net>.
 *
 */

#include <linux/buffer_head.h>
#include <linux/mpage.h>
#include <linux/hash.h>
#include <linux/swap.h>
#include "nilfs.h"
#include "page.h"
#include "mdt.h"
#include "ifile.h"

static struct address_space_operations def_gcinode_aops = {
	/* .writepage should be NULL because not writable */
	.releasepage		= nilfs_releasepage,
};
/* XXX need def_gcinode_iops/fops? */

/*
 * nilfs_gccache_add_data() - add data on pbn to cache
 * @inode - gc inode
 * @offset - dummy offset treated as the key for the page cache
 * @pbn - physical block number for the block
 * @vbn - virtual block number for the block, 0 for non-virtual block
 *
 * Description: nilfs_gccache_add_data() registers the data buffer
 * specified by @pbn to the GC pagecache with the key @offset.
 * The function set @vbn (@pbn if @vbn is zero) to b_blocknr in the buffer.
 *
 * Return Value: On success, 0 is returned. On Error, one of the following
 * negative error code is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 *
 * %-ENOENT - The block specified with @pbn does not exist.
 *
 * %-EEXIST - The block specified with @vbn already exist.
 *
 * Note: pages should be removed by truncate_inode_pages().
 */
int nilfs_gccache_add_data(struct inode *inode, sector_t offset, sector_t pbn,
			   __u64 vbn)
{
	struct page *page = NULL;
	struct buffer_head *bh;
	int blkbits = inode->i_blkbits, err = -ENOMEM;
	unsigned long index = offset >> (PAGE_CACHE_SHIFT - blkbits);

	page = grab_cache_page(inode->i_mapping, index);
	if (!page)
		goto failed;

	bh = nilfs_get_page_block(page, offset, index, blkbits);
	if (!bh)
		goto out_unlock;

	if (!buffer_uptodate(bh)) {
		if (pbn == 0) {
			struct inode *dat_inode;

			/* use original dat, not gc dat. */
			dat_inode = NILFS_I_NILFS(inode)->ns_dat;
			err = nilfs_dat_translate(dat_inode, vbn, &pbn);
			if (unlikely(err)) /* -EIO, -ENOMEM, -ENOENT */
				goto out_free_bh;
		}
		bh->b_blocknr = pbn;
		if (!buffer_mapped(bh)) {
			bh->b_bdev = NILFS_I_NILFS(inode)->ns_bdev;
			set_buffer_mapped(bh);
		}
		err = -EIO;
		page_debug(3, "reading: pbn=%llu (ino=%lu, vbn=%llu)\n",
			   (unsigned long long)bh->b_blocknr, inode->i_ino,
			   (unsigned long long)vbn);
		bh = nilfs_bread_slow(bh);
		if (unlikely(!bh))
			goto out_unlock;
	}
	bh->b_blocknr = vbn ? vbn : pbn;
	err = -EEXIST;
	if (!buffer_dirty(bh)) {
		nilfs_mdt_mark_buffer_dirty(bh);
		err = 0;
	}
out_free_bh:
	brelse(bh);
out_unlock:
	unlock_page(page);
	page_cache_release(page);
failed:
	return err;
}

/*
 * nilfs_gccache_add_node() - add btree node data on pbn to cache
 * @inode - gc inode
 * @pbn - physical block number for the block
 * @vbn - virtual block number for the block
 *
 * Description: nilfs_gccache_add_node() registers the node buffer
 * specified by @vbn to the GC pagecache.  @pbn may be supplied by the
 * caller to avoid translation of the disk block addresses.
 *
 * Return Value: On success, 0 is returned. On Error, one of the following
 * negative error code is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 *
 * %-EEXIST - The block specified with @vbn already exist.
 *
 * Note: pages should be removed by nilfs_btnode_delete_all().
 */
int nilfs_gccache_add_node(struct inode *inode, sector_t pbn, __u64 vbn)
{
	struct nilfs_btnode_cache *bc = &NILFS_I(inode)->i_btnode_cache;
	struct buffer_head *bh;
	int ret;

	ret = nilfs_btnode_get_pb(bc, vbn ? vbn : pbn, pbn, &bh);
	if (ret < 0)
		return ret;	/* -ENOMEM or -EIO */
	ret = -EEXIST;
	if (!buffer_dirty(bh)) {
		nilfs_btnode_mark_dirty(bh);
		ret = 0;
	}
	brelse(bh);
	return ret;
}

/*
 * nilfs_init_gcinode() - allocate and initialize gc_inode hash table
 * @nilfs - the_nilfs
 *
 * Return Value: On success, 0.
 * On error, a negative error code is returned.
 */
int nilfs_init_gcinode(struct the_nilfs *nilfs)
{
	int loop;

	BUG_ON(nilfs->ns_gc_inodes_h);

	spin_lock_init(&nilfs->ns_gc_inode_lock);
	INIT_LIST_HEAD(&nilfs->ns_gc_inodes);

	nilfs->ns_gc_inodes_h =
		kmalloc(sizeof(struct hlist_head) * NILFS_GCINODE_HASH_SIZE,
			GFP_NOFS);
	if (nilfs->ns_gc_inodes_h == NULL)
		return -ENOMEM;

	for (loop = 0; loop < NILFS_GCINODE_HASH_SIZE; loop++)
		INIT_HLIST_HEAD(&nilfs->ns_gc_inodes_h[loop]);
	return 0;
}

/*
 * nilfs_destroy_gcinode() - free gc_inode hash table
 * @nilfs - the nilfs
 */
void nilfs_destroy_gcinode(struct the_nilfs *nilfs)
{
	if (nilfs->ns_gc_inodes_h) {
		nilfs_remove_all_gcinode(nilfs);
		kfree(nilfs->ns_gc_inodes_h);
		nilfs->ns_gc_inodes_h = NULL;
	}
}

static struct inode *alloc_gcinode(struct the_nilfs *nilfs, ino_t ino,
				   __u64 cno, unsigned long hv)
{
	struct inode *inode = nilfs_mdt_new_common(nilfs, NULL, ino, GFP_NOFS);
	struct nilfs_inode_info *ii;

	if (!inode)
		return NULL;

	inode->i_op = NULL;
	inode->i_fop = NULL;
	inode->i_mapping->a_ops = &def_gcinode_aops;

	ii = NILFS_I(inode);
	ii->i_cno = cno;
	ii->i_flags = 0;
	ii->i_state = 1 << NILFS_I_GCINODE;
	ii->i_bh = NULL;
	ii->i_dtime = 0;
	/* buffer_head ? */
	/* bmap ? */
	nilfs_bmap_init_gc(ii->i_bmap);
	/* other initialize needed ?? */

	return inode;
}

static unsigned long ihash(ino_t ino, __u64 cno)
{
	return hash_long((unsigned long)((ino << 2) + cno),
			 NILFS_GCINODE_HASH_BITS);
}

/*
 * nilfs_gc_iget() - find inode with ino/cno. if not exist, newly create.
 * @sb - super_block
 * @ino - inode number
 * @cno - check point number
 *
 * Return Value: On success, inode pointer
 * On error, NULL
 */
struct inode *nilfs_gc_iget(struct the_nilfs *nilfs, ino_t ino, __u64 cno)
{
	struct hlist_head *head;
	struct hlist_node *node;
	struct inode *inode = NULL;
	struct nilfs_inode_info *ii;
	unsigned long hv = ihash(ino, cno);

	spin_lock(&nilfs->ns_gc_inode_lock);
	head = nilfs->ns_gc_inodes_h + hv;
	hlist_for_each_entry(inode, node, head, i_hash) {
		ii = NILFS_I(inode);
		if (inode->i_ino == ino && ii->i_cno == cno)
			break;
	}
	spin_unlock(&nilfs->ns_gc_inode_lock);

	if (node)
		return inode;

	inode = alloc_gcinode(nilfs, ino, cno, hv);
	if (!inode)
		return NULL;

	spin_lock(&nilfs->ns_gc_inode_lock);
	head = nilfs->ns_gc_inodes_h + hv;
	hlist_add_head(&inode->i_hash, head);
	list_add(&NILFS_I(inode)->i_dirty, &nilfs->ns_gc_inodes);
	spin_unlock(&nilfs->ns_gc_inode_lock);

	return inode;
}

/*
 * nilfs_clear_gcinode() - clear and free a gc inode
 * @inode - inode
 */
void nilfs_clear_gcinode(struct inode *inode)
{
	/* other finalize needed ?? */
	nilfs_mdt_clear(inode);
	inode->i_state = I_CLEAR;
	nilfs_mdt_destroy(inode);
}

/*
 * nilfs_remove_all_gcinode() - remove all inodes from the_nilfs
 * @nilfs - the_nilfs
 */
void nilfs_remove_all_gcinode(struct the_nilfs *nilfs)
{
	struct hlist_head *head = nilfs->ns_gc_inodes_h;
	struct hlist_node *node, *n;
	struct inode *inode;
	int loop;

	spin_lock(&nilfs->ns_gc_inode_lock);
	for (loop = 0; loop < NILFS_GCINODE_HASH_SIZE; loop++, head++) {
		hlist_for_each_entry_safe(inode, node, n, head, i_hash) {
			hlist_del_init(&inode->i_hash);
			list_del_init(&NILFS_I(inode)->i_dirty);
			spin_unlock(&nilfs->ns_gc_inode_lock);
			nilfs_clear_gcinode(inode); /* might sleep */
			spin_lock(&nilfs->ns_gc_inode_lock);
		}
	}
	spin_unlock(&nilfs->ns_gc_inode_lock);
}
