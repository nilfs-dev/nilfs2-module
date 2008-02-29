/*
 * bmap.c - NILFS block mapping.
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
 * Written by Koji Sato <koji@osrg.net>.
 */

#include <linux/fs.h>
#include <linux/string.h>
#include <linux/errno.h>
#include "nilfs.h"
#include "sb.h"
#include "btnode.h"
#include "mdt.h"
#include "dat.h"
#include "bmap.h"

int nilfs_bmap_lookup_at_level(struct nilfs_bmap *bmap,
			       nilfs_bmap_key_t key,
			       int level,
			       nilfs_bmap_ptr_t *ptrp)
{
	nilfs_bmap_ptr_t ptr;
	int ret;

	down_read(&bmap->b_sem);
	ret = (*bmap->b_ops->bop_lookup)(bmap, key, level, ptrp);
	if (ret < 0)
		goto out;
	if (bmap->b_pops->bpop_translate != NULL) {
		ret = (*bmap->b_pops->bpop_translate)(bmap, *ptrp, &ptr);
		if (ret < 0)
			goto out;
		*ptrp = ptr;
	}

 out:
	up_read(&bmap->b_sem);
	return ret;
}


/**
 * nilfs_bmap_lookup - find a record
 * @bmap: bmap
 * @key: key
 * @recp: pointer to record
 *
 * Description: nilfs_bmap_lookup() finds a record whose key matches @key in
 * @bmap.
 *
 * Return Value: On success, 0 is returned and the record associated with @key
 * is stored in the place pointed by @recp. On error, one of the following
 * negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 *
 * %-ENOENT - A record associated with @key does not exist.
 */
int nilfs_bmap_lookup(struct nilfs_bmap *bmap,
		      unsigned long key,
		      unsigned long *recp)
{
	nilfs_bmap_ptr_t ptr;
	int ret;

	/* XXX: use macro for level 1 */
	ret = nilfs_bmap_lookup_at_level(bmap, key, 1, &ptr);
	if (recp != NULL)
		*recp = ptr;
	return ret;
}

static int nilfs_bmap_do_insert(struct nilfs_bmap *bmap,
				nilfs_bmap_key_t key,
				nilfs_bmap_ptr_t ptr)
{
	nilfs_bmap_key_t keys[NILFS_BMAP_SMALL_HIGH + 1];
	nilfs_bmap_ptr_t ptrs[NILFS_BMAP_SMALL_HIGH + 1];
	int ret, n;

	if (bmap->b_ops->bop_check_insert != NULL) {
		ret = (*bmap->b_ops->bop_check_insert)(bmap, key);
		if (ret > 0) {
			n = (*bmap->b_ops->bop_gather_data)(
				bmap, keys, ptrs, NILFS_BMAP_SMALL_HIGH + 1);
			if (n < 0)
				return n;
			ret = (*nilfs_bmap_large_convert_and_insert)(
				bmap, key, ptr, keys, ptrs, n,
				NILFS_BMAP_LARGE_LOW, NILFS_BMAP_LARGE_HIGH);
			if (ret == 0)
				bmap->b_u.u_flags |= NILFS_BMAP_LARGE;

			return ret;
		} else if (ret < 0)
			return ret;
	}

	return (*bmap->b_ops->bop_insert)(bmap, key, ptr);
}

/**
 * nilfs_bmap_insert - insert a new key-record pair into a bmap
 * @bmap: bmap
 * @key: key
 * @rec: record
 *
 * Description: nilfs_bmap_insert() inserts the new key-record pair specified
 * by @key and @rec into @bmap.
 *
 * Return Value: On success, 0 is returned. On error, one of the following
 * negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 *
 * %-EEXIST - A record associated with @key already exist.
 */
int nilfs_bmap_insert(struct nilfs_bmap *bmap,
		      unsigned long key,
		      unsigned long rec)
{
	int ret;

	down_write(&bmap->b_sem);
	ret = nilfs_bmap_do_insert(bmap, key, rec);
#ifdef CONFIG_NILFS_BMAP_DEBUG
	if ((*bmap->b_ops->bop_verify)(bmap) < 0) {
		printk(KERN_ERR
		       "%s: insertion of key %lu and rec %lu made bmap %p "
		       "corrupted\n",
		       __func__, key, rec, bmap);
		(*bmap->b_ops->bop_print)(bmap);
		BUG();
	}
#endif	/* CONFIG_NILFS_BMAP_DEBUG */
	up_write(&bmap->b_sem);
	return ret;
}

static int nilfs_bmap_do_delete(struct nilfs_bmap *bmap, nilfs_bmap_key_t key)
{
	nilfs_bmap_key_t keys[NILFS_BMAP_LARGE_LOW + 1];
	nilfs_bmap_ptr_t ptrs[NILFS_BMAP_LARGE_LOW + 1];
	int ret, n;

	if (bmap->b_ops->bop_check_delete != NULL) {
		ret = (*bmap->b_ops->bop_check_delete)(bmap, key);
		if (ret > 0) {
			n = (*bmap->b_ops->bop_gather_data)(
				bmap, keys, ptrs, NILFS_BMAP_LARGE_LOW + 1);
			if (n < 0)
				return n;
			ret = (*nilfs_bmap_small_delete_and_convert)(
				bmap, key, keys, ptrs, n,
				NILFS_BMAP_SMALL_LOW, NILFS_BMAP_SMALL_HIGH);
			if (ret == 0)
				bmap->b_u.u_flags &= ~NILFS_BMAP_LARGE;

			return ret;
		} else if (ret < 0)
			return ret;
	}

	return (*bmap->b_ops->bop_delete)(bmap, key);
}

/**
 * nilfs_bmap_delete - delete a key-record pair from a bmap
 * @bmap: bmap
 * @key: key
 *
 * Description: nilfs_bmap_delete() deletes the key-record pair specified by
 * @key from @bmap.
 *
 * Return Value: On success, 0 is returned. On error, one of the following
 * negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 *
 * %-ENOENT - A record associated with @key does not exist.
 */
int nilfs_bmap_delete(struct nilfs_bmap *bmap, unsigned long key)
{
	int ret;

	down_write(&bmap->b_sem);
	ret = nilfs_bmap_do_delete(bmap, key);
#ifdef CONFIG_NILFS_BMAP_DEBUG
	if ((*bmap->b_ops->bop_verify)(bmap) < 0) {
		printk(KERN_ERR
		       "%s: deletion of key %lu made bmap %p corrupted\n",
		       __func__, key, bmap);
		(*bmap->b_ops->bop_print)(bmap);
		BUG();
	}
#endif	/* CONFIG_NILFS_BMAP_DEBUG */
	up_write(&bmap->b_sem);
	return ret;
}

static int nilfs_bmap_do_truncate(struct nilfs_bmap *bmap, unsigned long key)
{
	nilfs_bmap_key_t lastkey;
	int ret;

	ret = (*bmap->b_ops->bop_last_key)(bmap, &lastkey);
	if (ret < 0) {
		if (ret == -ENOENT)
			ret = 0;
		return ret;
	}

	while (key <= lastkey) {
		ret = nilfs_bmap_do_delete(bmap, lastkey);
		if (ret < 0)
			return ret;
		ret = (*bmap->b_ops->bop_last_key)(bmap, &lastkey);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			return ret;
		}
	}
	return 0;
}

/**
 * nilfs_bmap_truncate - truncate a bmap to a specified key
 * @bmap: bmap
 * @key: key
 *
 * Description: nilfs_bmap_truncate() removes key-record pairs whose keys are
 * greater than or equal to @key from @bmap.
 *
 * Return Value: On success, 0 is returned. On error, one of the following
 * negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 */
int nilfs_bmap_truncate(struct nilfs_bmap *bmap, unsigned long key)
{
	int ret;

	down_write(&bmap->b_sem);
	ret = nilfs_bmap_do_truncate(bmap, key);
#ifdef CONFIG_NILFS_BMAP_DEBUG
	if ((*bmap->b_ops->bop_verify)(bmap) < 0) {
		printk(KERN_ERR
		       "%s: truncation to key %lu made bmap %p corrupted\n",
		       __func__, key, bmap);
		(*bmap->b_ops->bop_print)(bmap);
		BUG();
	}
#endif	/* CONFIG_NILFS_BMAP_DEBUG */
	up_write(&bmap->b_sem);
	return ret;
}

static void nilfs_bmap_do_clear(struct nilfs_bmap *bmap)
{
	nilfs_bmap_delete_all_blocks(bmap);
	if (bmap->b_ops->bop_clear != NULL)
		(*bmap->b_ops->bop_clear)(bmap);
}

/**
 * nilfs_bmap_clear - free resources a bmap holds
 * @bmap: bmap
 *
 * Description: nilfs_bmap_clear() frees resources associated with @bmap.
 */
void nilfs_bmap_clear(struct nilfs_bmap *bmap)
{
	down_write(&bmap->b_sem);
	nilfs_bmap_do_clear(bmap);
	up_write(&bmap->b_sem);
}

/**
 * nilfs_bmap_terminate - terminate a bmap
 * @bmap: bmap
 *
 * Description: nilfs_bmap_terminate() terminates @bmap, freeing the resources
 * it holds.
 *
 * Return Value: On success, 0 is returned. On error, one of the following
 * negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 */
int nilfs_bmap_terminate(struct nilfs_bmap *bmap)
{
	int ret;

	down_write(&bmap->b_sem);
	ret = nilfs_bmap_do_truncate(bmap, 0);
	if (ret < 0)
		goto out;
	/* nilfs_bmap_do_clear(bmap); */

 out:
	up_write(&bmap->b_sem);
	return ret;
}

/**
 * nilfs_bmap_propagate - propagate dirty state
 * @bmap: bmap
 * @bh: buffer head
 *
 * Description: nilfs_bmap_propagate() marks the buffers that directly or
 * indirectly refer to the block specified by @bh dirty.
 *
 * Return Value: On success, 0 is returned. On error, one of the following
 * negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 */
int nilfs_bmap_propagate(struct nilfs_bmap *bmap, struct buffer_head *bh)
{
	int ret;

	down_write(&bmap->b_sem);
	ret = (*bmap->b_ops->bop_propagate)(bmap, bh);
	up_write(&bmap->b_sem);
	return ret;
}

/**
 * nilfs_bmap_lookup_dirty_buffers -
 * @bmap: bmap
 * @listp: pointer to buffer head list
 */
void nilfs_bmap_lookup_dirty_buffers(struct nilfs_bmap *bmap,
				     struct list_head *listp)
{
	if (bmap->b_ops->bop_lookup_dirty_buffers != NULL)
		(*bmap->b_ops->bop_lookup_dirty_buffers)(bmap, listp);
}

/**
 * nilfs_bmap_assign - assign a new block number to a block
 * @bmap: bmap
 * @bhp: pointer to buffer head
 * @blocknr: block number
 * @binfo: block information
 *
 * Description: nilfs_bmap_assign() assigns the block number @blocknr to the
 * buffer specified by @bh.
 *
 * Return Value: On success, 0 is returned and the buffer head of a newly
 * create buffer and the block information associated with the buffer are
 * stored in the place pointed by @bh and @binfo, respectively. On error, one
 * of the following negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 */
int nilfs_bmap_assign(struct nilfs_bmap *bmap,
		      struct buffer_head **bh,
		      unsigned long blocknr,
		      union nilfs_binfo *binfo)
{
	int ret;

	down_write(&bmap->b_sem);
	ret = (*bmap->b_ops->bop_assign)(bmap, bh, blocknr, binfo);
	up_write(&bmap->b_sem);
	return ret;
}

/**
 * nilfs_bmap_mark - mark block dirty
 * @bmap: bmap
 * @key: key
 * @level: level
 *
 * Description: nilfs_bmap_mark() marks the block specified by @key and @level
 * as dirty.
 *
 * Return Value: On success, 0 is returned. On error, one of the following
 * negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 */
int nilfs_bmap_mark(struct nilfs_bmap *bmap, nilfs_bmap_key_t key, int level)
{
	int ret;

	if (bmap->b_ops->bop_mark == NULL)
		return 0;

	down_write(&bmap->b_sem);
	ret = (*bmap->b_ops->bop_mark)(bmap, key, level);
	up_write(&bmap->b_sem);
	return ret;
}

/**
 * nilfs_bmap_test_and_clear_dirty - test and clear a bmap dirty state
 * @bmap: bmap
 *
 * Description: nilfs_test_and_clear() is the atomic operation to test and
 * clear the dirty state of @bmap.
 *
 * Return Value: 1 is returned if @bmap is dirty, or 0 if clear.
 */
int nilfs_bmap_test_and_clear_dirty(struct nilfs_bmap *bmap)
{
	int ret;

	down_write(&bmap->b_sem);
	ret = nilfs_bmap_dirty(bmap);
	nilfs_bmap_clear_dirty(bmap);
	up_write(&bmap->b_sem);
	return ret;
}


/*
 * Internal use only
 */

void nilfs_bmap_add_blocks(const struct nilfs_bmap *bmap, int n)
{
	inode_add_bytes(bmap->b_inode, (1 << bmap->b_inode->i_blkbits) * n);
	if (NILFS_MDT(bmap->b_inode))
		nilfs_mdt_mark_dirty(bmap->b_inode);
	else
		mark_inode_dirty(bmap->b_inode);
}

void nilfs_bmap_sub_blocks(const struct nilfs_bmap *bmap, int n)
{
	inode_sub_bytes(bmap->b_inode, (1 << bmap->b_inode->i_blkbits) * n);
	if (NILFS_MDT(bmap->b_inode))
		nilfs_mdt_mark_dirty(bmap->b_inode);
	else
		mark_inode_dirty(bmap->b_inode);
}

int nilfs_bmap_get_block(const struct nilfs_bmap *bmap,
			 nilfs_bmap_ptr_t ptr,
			 struct buffer_head **bhp)
{
	return nilfs_btnode_get(&NILFS_BMAP_I(bmap)->i_btnode_cache, ptr, bhp);
}

void nilfs_bmap_put_block(const struct nilfs_bmap *bmap,
			  struct buffer_head *bh)
{
	brelse(bh);
}

int nilfs_bmap_get_new_block(const struct nilfs_bmap *bmap,
			     nilfs_bmap_ptr_t ptr,
			     struct buffer_head **bhp)
{
	int ret;

	ret = nilfs_btnode_get_new(&NILFS_BMAP_I(bmap)->i_btnode_cache,
				   ptr, bhp);
	if (ret < 0)
		return ret;
	set_buffer_nilfs_volatile(*bhp);
	return 0;
}

void nilfs_bmap_delete_block(const struct nilfs_bmap *bmap,
			     struct buffer_head *bh)
{
	nilfs_btnode_delete(bh);
}

void nilfs_bmap_delete_all_blocks(const struct nilfs_bmap *bmap)
{
	/* ??? */
}


nilfs_bmap_key_t nilfs_bmap_data_get_key(const struct nilfs_bmap *bmap,
					 const struct buffer_head *bh)
{
	struct buffer_head *pbh;
	nilfs_bmap_key_t key;

	key = page_index(bh->b_page) << (PAGE_CACHE_SHIFT -
					 bmap->b_inode->i_blkbits);
	for (pbh = page_buffers(bh->b_page); pbh != bh;
	     pbh = pbh->b_this_page, key++);

	return key;
}

nilfs_bmap_ptr_t nilfs_bmap_find_target_seq(const struct nilfs_bmap *bmap,
					    nilfs_bmap_key_t key)
{
	__s64 diff;

	diff = key - bmap->b_last_allocated_key;
	if ((nilfs_bmap_keydiff_abs(diff) < NILFS_INODE_BMAP_SIZE) &&
	    (bmap->b_last_allocated_ptr != NILFS_BMAP_INVALID_PTR) &&
	    (bmap->b_last_allocated_ptr + diff > 0))
		return bmap->b_last_allocated_ptr + diff;
	else
		return NILFS_BMAP_INVALID_PTR;
}

#define NILFS_BMAP_GROUP_DIV	8
nilfs_bmap_ptr_t nilfs_bmap_find_target_in_group(const struct nilfs_bmap *bmap)
{
	struct the_nilfs *nilfs;
	struct inode *dat;
	unsigned long entries_per_group, group;

	nilfs = (*bmap->b_pops->bpop_get_nilfs)(bmap);
	dat = nilfs_dat_inode(nilfs);
	entries_per_group = nilfs_dat_entries_per_group(dat);
	group = bmap->b_inode->i_ino / entries_per_group;

	return group * entries_per_group +
		(bmap->b_inode->i_ino % NILFS_BMAP_GROUP_DIV) *
		(entries_per_group / NILFS_BMAP_GROUP_DIV);
	/* XXX: for user-land test */
	/* return 0; */
}

static int nilfs_bmap_prepare_alloc_v(struct nilfs_bmap *bmap,
				      union nilfs_bmap_ptr_req *req)
{
	struct the_nilfs *nilfs;
	struct inode *dat;

	nilfs = (*bmap->b_pops->bpop_get_nilfs)(bmap);
	dat = nilfs_dat_inode(nilfs);
	return nilfs_dat_prepare_alloc(dat, &req->bpr_req);
}

static void nilfs_bmap_commit_alloc_v(struct nilfs_bmap *bmap,
				      union nilfs_bmap_ptr_req *req)
{
	struct the_nilfs *nilfs;
	struct inode *dat;

	nilfs = (*bmap->b_pops->bpop_get_nilfs)(bmap);
	dat = nilfs_dat_inode(nilfs);
	nilfs_dat_commit_alloc(dat, &req->bpr_req);
}

static void nilfs_bmap_abort_alloc_v(struct nilfs_bmap *bmap,
				     union nilfs_bmap_ptr_req *req)
{
	struct the_nilfs *nilfs;
	struct inode *dat;

	nilfs = (*bmap->b_pops->bpop_get_nilfs)(bmap);
	dat = nilfs_dat_inode(nilfs);
	nilfs_dat_abort_alloc(dat, &req->bpr_req);
}

static int nilfs_bmap_prepare_start_v(struct nilfs_bmap *bmap,
				      union nilfs_bmap_ptr_req *req)
{
	struct the_nilfs *nilfs;
	struct inode *dat;

	nilfs = (*bmap->b_pops->bpop_get_nilfs)(bmap);
	dat = nilfs_dat_inode(nilfs);
	return nilfs_dat_prepare_start(dat, &req->bpr_req);
}

static void nilfs_bmap_commit_start_v(struct nilfs_bmap *bmap,
				      union nilfs_bmap_ptr_req *req,
				      sector_t blocknr)
{
	struct the_nilfs *nilfs;
	struct inode *dat;

	nilfs = (*bmap->b_pops->bpop_get_nilfs)(bmap);
	dat = nilfs_dat_inode(nilfs);
	nilfs_dat_commit_start(dat, &req->bpr_req, blocknr);
}

static void nilfs_bmap_abort_start_v(struct nilfs_bmap *bmap,
				     union nilfs_bmap_ptr_req *req)
{
	struct the_nilfs *nilfs;
	struct inode *dat;

	nilfs = (*bmap->b_pops->bpop_get_nilfs)(bmap);
	dat = nilfs_dat_inode(nilfs);
	nilfs_dat_abort_start(dat, &req->bpr_req);
}

static int nilfs_bmap_prepare_end_v(struct nilfs_bmap *bmap,
				    union nilfs_bmap_ptr_req *req)
{
	struct the_nilfs *nilfs;
	struct inode *dat;

	nilfs = (*bmap->b_pops->bpop_get_nilfs)(bmap);
	dat = nilfs_dat_inode(nilfs);
	return nilfs_dat_prepare_end(dat, &req->bpr_req);
}

static void nilfs_bmap_commit_end_v(struct nilfs_bmap *bmap,
				    union nilfs_bmap_ptr_req *req)
{
	struct the_nilfs *nilfs;
	struct inode *dat;

	nilfs = (*bmap->b_pops->bpop_get_nilfs)(bmap);
	dat = nilfs_dat_inode(nilfs);
	nilfs_dat_commit_end(dat, &req->bpr_req);
}

static void nilfs_bmap_commit_end_vmdt(struct nilfs_bmap *bmap,
				       union nilfs_bmap_ptr_req *req)
{
	struct the_nilfs *nilfs;
	struct inode *dat;

	nilfs = (*bmap->b_pops->bpop_get_nilfs)(bmap);
	dat = nilfs_dat_inode(nilfs);
	nilfs_dat_commit_end_dead(dat, &req->bpr_req);
}

static void nilfs_bmap_abort_end_v(struct nilfs_bmap *bmap,
				   union nilfs_bmap_ptr_req *req)
{
	struct the_nilfs *nilfs;
	struct inode *dat;

	nilfs = (*bmap->b_pops->bpop_get_nilfs)(bmap);
	dat = nilfs_dat_inode(nilfs);
	nilfs_dat_abort_end(dat, &req->bpr_req);
}

int nilfs_bmap_move_v(const struct nilfs_bmap *bmap,
		      nilfs_sector_t vblocknr,
		      sector_t blocknr)
{
	struct the_nilfs *nilfs;
	struct inode *dat;

	nilfs = (*bmap->b_pops->bpop_get_nilfs)(bmap);
	dat = nilfs_dat_inode(nilfs);
	return nilfs_dat_move(dat, vblocknr, blocknr);
}

int nilfs_bmap_mark_dirty(const struct nilfs_bmap *bmap,
			  nilfs_sector_t vblocknr)
{
	struct the_nilfs *nilfs;
	struct inode *dat;

	nilfs = (*bmap->b_pops->bpop_get_nilfs)(bmap);
	dat = nilfs_dat_inode(nilfs);
	return nilfs_dat_mark_dirty(dat, vblocknr);
}

int nilfs_bmap_prepare_update(struct nilfs_bmap *bmap,
			      union nilfs_bmap_ptr_req *oldreq,
			      union nilfs_bmap_ptr_req *newreq)
{
	int ret;

	ret = (*bmap->b_pops->bpop_prepare_end_ptr)(bmap, oldreq);
	if (ret < 0)
		return ret;
	ret = (*bmap->b_pops->bpop_prepare_alloc_ptr)(bmap, newreq);
	if (ret < 0)
		(*bmap->b_pops->bpop_abort_end_ptr)(bmap, oldreq);

	return ret;
}

void nilfs_bmap_commit_update(struct nilfs_bmap *bmap,
			      union nilfs_bmap_ptr_req *oldreq,
			      union nilfs_bmap_ptr_req *newreq)
{
	(*bmap->b_pops->bpop_commit_end_ptr)(bmap, oldreq);
	(*bmap->b_pops->bpop_commit_alloc_ptr)(bmap, newreq);
}

void nilfs_bmap_abort_update(struct nilfs_bmap *bmap,
			     union nilfs_bmap_ptr_req *oldreq,
			     union nilfs_bmap_ptr_req *newreq)
{
	(*bmap->b_pops->bpop_abort_end_ptr)(bmap, oldreq);
	(*bmap->b_pops->bpop_abort_alloc_ptr)(bmap, newreq);
}

static struct the_nilfs *nilfs_bmap_get_nilfs_v(const struct nilfs_bmap *bmap)
{
	return NILFS_SB(bmap->b_inode->i_sb)->s_nilfs;
}

static struct the_nilfs *
nilfs_bmap_get_nilfs_vmdt(const struct nilfs_bmap *bmap)
{
	return NILFS_MDT(bmap->b_inode)->mi_nilfs;
}

static struct the_nilfs *nilfs_bmap_get_nilfs_gc(const struct nilfs_bmap *bmap)
{
	return NILFS_MDT(bmap->b_inode)->mi_nilfs;
}

static int nilfs_bmap_translate_v(const struct nilfs_bmap *bmap,
				  nilfs_bmap_ptr_t ptr,
				  nilfs_bmap_ptr_t *ptrp)
{
	struct the_nilfs *nilfs;
	struct inode *dat;
	sector_t blocknr;
	int ret;

	nilfs = (*bmap->b_pops->bpop_get_nilfs)(bmap);
	dat = nilfs_dat_inode(nilfs);
	ret = nilfs_dat_translate(dat, ptr, &blocknr);
	if (ret < 0)
		return ret;
	if (ptrp != NULL)
		*ptrp = blocknr;
	return 0;
}

static int nilfs_bmap_prepare_alloc_p(struct nilfs_bmap *bmap,
				      union nilfs_bmap_ptr_req *req)
{
	/* ignore target ptr */
	req->bpr_ptr = bmap->b_last_allocated_ptr++;
	return 0;
}

static void nilfs_bmap_commit_alloc_p(struct nilfs_bmap *bmap,
				      union nilfs_bmap_ptr_req *req)
{
	/* do nothing */
}

static void nilfs_bmap_abort_alloc_p(struct nilfs_bmap *bmap,
				     union nilfs_bmap_ptr_req *req)
{
	bmap->b_last_allocated_ptr--;
}

static const struct nilfs_bmap_ptr_operations nilfs_bmap_ptr_ops_v = {
	.bpop_prepare_alloc_ptr	=	nilfs_bmap_prepare_alloc_v,
	.bpop_commit_alloc_ptr	=	nilfs_bmap_commit_alloc_v,
	.bpop_abort_alloc_ptr	=	nilfs_bmap_abort_alloc_v,
	.bpop_prepare_start_ptr	=	nilfs_bmap_prepare_start_v,
	.bpop_commit_start_ptr	=	nilfs_bmap_commit_start_v,
	.bpop_abort_start_ptr	=	nilfs_bmap_abort_start_v,
	.bpop_prepare_end_ptr	=	nilfs_bmap_prepare_end_v,
	.bpop_commit_end_ptr	=	nilfs_bmap_commit_end_v,
	.bpop_abort_end_ptr	=	nilfs_bmap_abort_end_v,

	.bpop_get_nilfs		=	nilfs_bmap_get_nilfs_v,
	.bpop_translate		=	nilfs_bmap_translate_v,
};

static const struct nilfs_bmap_ptr_operations nilfs_bmap_ptr_ops_vmdt = {
	.bpop_prepare_alloc_ptr	=	nilfs_bmap_prepare_alloc_v,
	.bpop_commit_alloc_ptr	=	nilfs_bmap_commit_alloc_v,
	.bpop_abort_alloc_ptr	=	nilfs_bmap_abort_alloc_v,
	.bpop_prepare_start_ptr	=	nilfs_bmap_prepare_start_v,
	.bpop_commit_start_ptr	=	nilfs_bmap_commit_start_v,
	.bpop_abort_start_ptr	=	nilfs_bmap_abort_start_v,
	.bpop_prepare_end_ptr	=	nilfs_bmap_prepare_end_v,
	.bpop_commit_end_ptr	=	nilfs_bmap_commit_end_vmdt,
	.bpop_abort_end_ptr	=	nilfs_bmap_abort_end_v,

	.bpop_get_nilfs		=	nilfs_bmap_get_nilfs_vmdt,
	.bpop_translate		=	nilfs_bmap_translate_v,
};

static const struct nilfs_bmap_ptr_operations nilfs_bmap_ptr_ops_p = {
	.bpop_prepare_alloc_ptr	=	nilfs_bmap_prepare_alloc_p,
	.bpop_commit_alloc_ptr	=	nilfs_bmap_commit_alloc_p,
	.bpop_abort_alloc_ptr	=	nilfs_bmap_abort_alloc_p,
	.bpop_prepare_start_ptr	=	NULL,
	.bpop_commit_start_ptr	=	NULL,
	.bpop_abort_start_ptr	=	NULL,
	.bpop_prepare_end_ptr	=	NULL,
	.bpop_commit_end_ptr	=	NULL,
	.bpop_abort_end_ptr	=	NULL,

	.bpop_get_nilfs		=	NULL,
	.bpop_translate		=	NULL,
};

static const struct nilfs_bmap_ptr_operations nilfs_bmap_ptr_ops_gc = {
	.bpop_prepare_alloc_ptr	=	NULL,
	.bpop_commit_alloc_ptr	=	NULL,
	.bpop_abort_alloc_ptr	=	NULL,
	.bpop_prepare_start_ptr	=	NULL,
	.bpop_commit_start_ptr	=	NULL,
	.bpop_abort_start_ptr	=	NULL,
	.bpop_prepare_end_ptr	=	NULL,
	.bpop_commit_end_ptr	=	NULL,
	.bpop_abort_end_ptr	=	NULL,

	.bpop_get_nilfs		=	nilfs_bmap_get_nilfs_gc,
	.bpop_translate		=	NULL,
};

/**
 * nilfs_bmap_read - read a bmap from an inode
 * @bmap: bmap
 * @raw_inode: on-disk inode
 *
 * Description: nilfs_bmap_read() initializes the bmap @bmap.
 *
 * Return Value: On success, 0 is returned. On error, the following negative
 * error code is returned.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 */
int nilfs_bmap_read(struct nilfs_bmap *bmap, struct nilfs_inode *raw_inode)
{
	if (raw_inode == NULL)
		memset(bmap->b_u.u_data, 0, NILFS_BMAP_SIZE);
	else
		memcpy(bmap->b_u.u_data, raw_inode->i_bmap, NILFS_BMAP_SIZE);

	init_rwsem(&bmap->b_sem);
	bmap->b_state = 0;
	bmap->b_inode = &NILFS_BMAP_I(bmap)->vfs_inode;
	switch (bmap->b_inode->i_ino) {
	case NILFS_DAT_INO:
		bmap->b_pops = &nilfs_bmap_ptr_ops_p;
		bmap->b_last_allocated_key = 0;	/* XXX: use macro */
		bmap->b_last_allocated_ptr = NILFS_BMAP_NEW_PTR_INIT;
		break;
	case NILFS_CPFILE_INO:
	case NILFS_SUFILE_INO:
		bmap->b_pops = &nilfs_bmap_ptr_ops_vmdt;
		bmap->b_last_allocated_key = 0;	/* XXX: use macro */
		bmap->b_last_allocated_ptr = NILFS_BMAP_INVALID_PTR;
		break;
	default:
		bmap->b_pops = &nilfs_bmap_ptr_ops_v;
		bmap->b_last_allocated_key = 0;	/* XXX: use macro */
		bmap->b_last_allocated_ptr = NILFS_BMAP_INVALID_PTR;
		break;
	}

	return (bmap->b_u.u_flags & NILFS_BMAP_LARGE) ?
		nilfs_bmap_large_init(bmap,
				      NILFS_BMAP_LARGE_LOW,
				      NILFS_BMAP_LARGE_HIGH) :
		nilfs_bmap_small_init(bmap,
				      NILFS_BMAP_SMALL_LOW,
				      NILFS_BMAP_SMALL_HIGH);
}

/**
 * nilfs_bmap_write - write back a bmap to an inode
 * @bmap: bmap
 * @raw_inode: on-disk inode
 *
 * Description: nilfs_bmap_write() stores @bmap in @raw_inode.
 */
void nilfs_bmap_write(struct nilfs_bmap *bmap, struct nilfs_inode *raw_inode)
{
	down_write(&bmap->b_sem);
	memcpy(raw_inode->i_bmap, bmap->b_u.u_data,
	       NILFS_INODE_BMAP_SIZE * sizeof(__le64));
	if (bmap->b_inode->i_ino == NILFS_DAT_INO)
		bmap->b_last_allocated_ptr = NILFS_BMAP_NEW_PTR_INIT;

	up_write(&bmap->b_sem);
}

void nilfs_bmap_init_gc(struct nilfs_bmap *bmap)
{
	memset(&bmap->b_u, 0, NILFS_BMAP_SIZE);
	init_rwsem(&bmap->b_sem);
	bmap->b_inode = &NILFS_BMAP_I(bmap)->vfs_inode;
	bmap->b_pops = &nilfs_bmap_ptr_ops_gc;
	bmap->b_last_allocated_key = 0;
	bmap->b_last_allocated_ptr = NILFS_BMAP_INVALID_PTR;
	bmap->b_state = 0;
	nilfs_btree_init_gc(bmap);
}

void nilfs_bmap_init_gcdat(struct nilfs_bmap *gcbmap, struct nilfs_bmap *bmap)
{
	memcpy(gcbmap, bmap, sizeof(union nilfs_bmap_union));
	init_rwsem(&gcbmap->b_sem);
	gcbmap->b_inode = &NILFS_BMAP_I(gcbmap)->vfs_inode;
}

void nilfs_bmap_commit_gcdat(struct nilfs_bmap *gcbmap, struct nilfs_bmap *bmap)
{
	memcpy(bmap, gcbmap, sizeof(union nilfs_bmap_union));
	init_rwsem(&bmap->b_sem);
	bmap->b_inode = &NILFS_BMAP_I(bmap)->vfs_inode;
}
