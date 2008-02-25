/*
 * btree.c - NILFS B-tree.
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
 * Written by Koji Sato <koji@osrg.net>.
 */

#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include "nilfs.h"
#include "btnode.h"
#include "btree.h"


/*
 * B-tree path operations
 */

static struct kmem_cache *nilfs_btree_path_cache;

int __init nilfs_btree_path_cache_init(void)
{
	nilfs_btree_path_cache =
		kmem_cache_create("nilfs2_btree_path_cache",
				  sizeof(struct nilfs_btree_path) *
				  NILFS_BTREE_LEVEL_MAX,
#if NEED_SLAB_DESTRUCTOR_ARG
				  0, 0, NULL, NULL);
#else
				  0, 0, NULL);
#endif
	return (nilfs_btree_path_cache != NULL) ? 0 : -ENOMEM;
}

void nilfs_btree_path_cache_destroy(void)
{
	kmem_cache_destroy(nilfs_btree_path_cache);
}

static inline struct nilfs_btree_path *
nilfs_btree_alloc_path(const struct nilfs_btree *btree)
{
	return (struct nilfs_btree_path *)
		kmem_cache_alloc(nilfs_btree_path_cache, GFP_NOFS);
}

static inline void nilfs_btree_free_path(const struct nilfs_btree *btree,
					 struct nilfs_btree_path *path)
{
	kmem_cache_free(nilfs_btree_path_cache, path);
}

static void nilfs_btree_init_path(const struct nilfs_btree *btree,
				  struct nilfs_btree_path *path)
{
	int level;

	for (level = NILFS_BTREE_LEVEL_DATA;
	     level < NILFS_BTREE_LEVEL_MAX;
	     level++) {
		path[level].bp_bh = NULL;
		path[level].bp_sib_bh = NULL;
		path[level].bp_index = 0;
		path[level].bp_oldreq.bpr_ptr = NILFS_BMAP_INVALID_PTR;
		path[level].bp_newreq.bpr_ptr = NILFS_BMAP_INVALID_PTR;
		path[level].bp_op = NULL;
	}
}

static void nilfs_btree_clear_path(const struct nilfs_btree *btree,
				   struct nilfs_btree_path *path)
{
	int level;

	for (level = NILFS_BTREE_LEVEL_DATA;
	     level < NILFS_BTREE_LEVEL_MAX;
	     level++) {
		if (path[level].bp_bh != NULL) {
			nilfs_bmap_put_block(&btree->bt_bmap,
					     path[level].bp_bh);
			path[level].bp_bh = NULL;
		}
		/* sib_bh is released or deleted by prepare or commit
		 * operations. */
		path[level].bp_sib_bh = NULL;
		path[level].bp_index = 0;
		path[level].bp_oldreq.bpr_ptr = NILFS_BMAP_INVALID_PTR;
		path[level].bp_newreq.bpr_ptr = NILFS_BMAP_INVALID_PTR;
		path[level].bp_op = NULL;
	}
}


/*
 * B-tree node operations
 */

static inline int
nilfs_btree_node_get_flags(const struct nilfs_btree *btree,
			   const struct nilfs_btree_node *node)
{
	return node->bn_flags;
}

static inline void
nilfs_btree_node_set_flags(struct nilfs_btree *btree,
			   struct nilfs_btree_node *node,
			   int flags)
{
	node->bn_flags = flags;
}

static inline int nilfs_btree_node_root(const struct nilfs_btree *btree,
					const struct nilfs_btree_node *node)
{
	return nilfs_btree_node_get_flags(btree, node) & NILFS_BTREE_NODE_ROOT;
}

static inline int
nilfs_btree_node_get_level(const struct nilfs_btree *btree,
			   const struct nilfs_btree_node *node)
{
	return node->bn_level;
}

static inline void
nilfs_btree_node_set_level(struct nilfs_btree *btree,
			   struct nilfs_btree_node *node,
			   int level)
{
	node->bn_level = level;
}

static inline int
nilfs_btree_node_get_nchildren(const struct nilfs_btree *btree,
			       const struct nilfs_btree_node *node)
{
	return le16_to_cpu(node->bn_nchildren);
}

static inline void
nilfs_btree_node_set_nchildren(struct nilfs_btree *btree,
			       struct nilfs_btree_node *node,
			       int nchildren)
{
	node->bn_nchildren = cpu_to_le16(nchildren);
}

static inline int
nilfs_btree_node_size(const struct nilfs_btree *btree)
{
	return 1 << btree->bt_bmap.b_inode->i_blkbits;
}

static inline int
nilfs_btree_node_nchildren_min(const struct nilfs_btree *btree,
			       const struct nilfs_btree_node *node)
{
	return nilfs_btree_node_root(btree, node) ?
		NILFS_BTREE_ROOT_NCHILDREN_MIN :
		NILFS_BTREE_NODE_NCHILDREN_MIN(nilfs_btree_node_size(btree));
}

static inline int
nilfs_btree_node_nchildren_max(const struct nilfs_btree *btree,
			       const struct nilfs_btree_node *node)
{
	return nilfs_btree_node_root(btree, node) ?
		NILFS_BTREE_ROOT_NCHILDREN_MAX :
		NILFS_BTREE_NODE_NCHILDREN_MAX(nilfs_btree_node_size(btree));
}

static inline nilfs_bmap_dkey_t *
nilfs_btree_node_dkeys(const struct nilfs_btree *btree,
		       const struct nilfs_btree_node *node)
{
	return (nilfs_bmap_dkey_t *)((char *)(node + 1) +
				     (nilfs_btree_node_root(btree, node) ?
				      0 : NILFS_BTREE_NODE_EXTRA_PAD_SIZE));
}

static inline nilfs_bmap_dptr_t *
nilfs_btree_node_dptrs(const struct nilfs_btree *btree,
		       const struct nilfs_btree_node *node)
{
	return (nilfs_bmap_dptr_t *)(nilfs_btree_node_dkeys(btree, node) +
				     nilfs_btree_node_nchildren_max(btree,
								    node));
}

static inline nilfs_bmap_key_t
nilfs_btree_node_get_key(const struct nilfs_btree *btree,
			 const struct nilfs_btree_node *node,
			 int index)
{
	return nilfs_bmap_dkey_to_key(*(nilfs_btree_node_dkeys(btree, node) +
					index));
}

static inline void
nilfs_btree_node_set_key(struct nilfs_btree *btree,
			 struct nilfs_btree_node *node,
			 int index,
			 nilfs_bmap_key_t key)
{
	*(nilfs_btree_node_dkeys(btree, node) + index) =
		nilfs_bmap_key_to_dkey(key);
}

static inline nilfs_bmap_ptr_t
nilfs_btree_node_get_ptr(const struct nilfs_btree *btree,
			 const struct nilfs_btree_node *node,
			 int index)
{
	return nilfs_bmap_dptr_to_ptr(*(nilfs_btree_node_dptrs(btree, node) +
					index));
}

static inline void
nilfs_btree_node_set_ptr(struct nilfs_btree *btree,
			 struct nilfs_btree_node *node,
			 int index,
			 nilfs_bmap_ptr_t ptr)
{
	*(nilfs_btree_node_dptrs(btree, node) + index) =
		nilfs_bmap_ptr_to_dptr(ptr);
}

static void
nilfs_btree_node_init(struct nilfs_btree *btree,
		      struct nilfs_btree_node *node,
		      int flags,
		      int level,
		      int nchildren,
		      const nilfs_bmap_key_t *keys,
		      const nilfs_bmap_ptr_t *ptrs)
{
	nilfs_bmap_dkey_t *dkeys;
	nilfs_bmap_dptr_t *dptrs;
	int i;

	nilfs_btree_node_set_flags(btree, node, flags);
	nilfs_btree_node_set_level(btree, node, level);
	nilfs_btree_node_set_nchildren(btree, node, nchildren);

	dkeys = nilfs_btree_node_dkeys(btree, node);
	dptrs = nilfs_btree_node_dptrs(btree, node);
	for (i = 0; i < nchildren; i++) {
		dkeys[i] = nilfs_bmap_key_to_dkey(keys[i]);
		dptrs[i] = nilfs_bmap_ptr_to_dptr(ptrs[i]);
	}
}

/* Assume the buffer heads corresponding to left and right are locked. */
static void nilfs_btree_node_move_left(struct nilfs_btree *btree,
				       struct nilfs_btree_node *left,
				       struct nilfs_btree_node *right,
				       int n)
{
	nilfs_bmap_dkey_t *ldkeys, *rdkeys;
	nilfs_bmap_dptr_t *ldptrs, *rdptrs;
	int lnchildren, rnchildren;

	ldkeys = nilfs_btree_node_dkeys(btree, left);
	ldptrs = nilfs_btree_node_dptrs(btree, left);
	lnchildren = nilfs_btree_node_get_nchildren(btree, left);

	rdkeys = nilfs_btree_node_dkeys(btree, right);
	rdptrs = nilfs_btree_node_dptrs(btree, right);
	rnchildren = nilfs_btree_node_get_nchildren(btree, right);

	memcpy(ldkeys + lnchildren,
	       rdkeys, n * sizeof(nilfs_bmap_dkey_t));
	memcpy(ldptrs + lnchildren,
	       rdptrs, n * sizeof(nilfs_bmap_dptr_t));
	memmove(rdkeys, rdkeys + n,
		(rnchildren - n) * sizeof(nilfs_bmap_dkey_t));
	memmove(rdptrs, rdptrs + n,
		(rnchildren - n) * sizeof(nilfs_bmap_dptr_t));

	lnchildren += n;
	rnchildren -= n;
	nilfs_btree_node_set_nchildren(btree, left, lnchildren);
	nilfs_btree_node_set_nchildren(btree, right, rnchildren);
}

/* Assume that the buffer heads corresponding to left and right are locked. */
static void nilfs_btree_node_move_right(struct nilfs_btree *btree,
					struct nilfs_btree_node *left,
					struct nilfs_btree_node *right,
					int n)
{
	nilfs_bmap_dkey_t *ldkeys, *rdkeys;
	nilfs_bmap_dptr_t *ldptrs, *rdptrs;
	int lnchildren, rnchildren;

	ldkeys = nilfs_btree_node_dkeys(btree, left);
	ldptrs = nilfs_btree_node_dptrs(btree, left);
	lnchildren = nilfs_btree_node_get_nchildren(btree, left);

	rdkeys = nilfs_btree_node_dkeys(btree, right);
	rdptrs = nilfs_btree_node_dptrs(btree, right);
	rnchildren = nilfs_btree_node_get_nchildren(btree, right);

	memmove(rdkeys + n, rdkeys,
		rnchildren * sizeof(nilfs_bmap_dkey_t));
	memmove(rdptrs + n, rdptrs,
		rnchildren * sizeof(nilfs_bmap_dptr_t));
	memcpy(rdkeys, ldkeys + lnchildren - n,
	       n * sizeof(nilfs_bmap_dkey_t));
	memcpy(rdptrs, ldptrs + lnchildren - n,
	       n * sizeof(nilfs_bmap_dptr_t));

	lnchildren -= n;
	rnchildren += n;
	nilfs_btree_node_set_nchildren(btree, left, lnchildren);
	nilfs_btree_node_set_nchildren(btree, right, rnchildren);
}

/* Assume that the buffer head corresponding to node is locked. */
static void nilfs_btree_node_insert(struct nilfs_btree *btree,
				    struct nilfs_btree_node *node,
				    nilfs_bmap_key_t key,
				    nilfs_bmap_ptr_t ptr,
				    int index)
{
	nilfs_bmap_dkey_t *dkeys;
	nilfs_bmap_dptr_t *dptrs;
	int nchildren;

	dkeys = nilfs_btree_node_dkeys(btree, node);
	dptrs = nilfs_btree_node_dptrs(btree, node);
	nchildren = nilfs_btree_node_get_nchildren(btree, node);
	if (index < nchildren) {
		memmove(dkeys + index + 1, dkeys + index,
			(nchildren - index) * sizeof(nilfs_bmap_dkey_t));
		memmove(dptrs + index + 1, dptrs + index,
			(nchildren - index) * sizeof(nilfs_bmap_dptr_t));
	}
	dkeys[index] = nilfs_bmap_key_to_dkey(key);
	dptrs[index] = nilfs_bmap_ptr_to_dptr(ptr);
	nchildren++;
	nilfs_btree_node_set_nchildren(btree, node, nchildren);
}

/* Assume that the buffer head corresponding to node is locked. */
static void nilfs_btree_node_delete(struct nilfs_btree *btree,
				    struct nilfs_btree_node *node,
				    nilfs_bmap_key_t *keyp,
				    nilfs_bmap_ptr_t *ptrp,
				    int index)
{
	nilfs_bmap_key_t key;
	nilfs_bmap_ptr_t ptr;
	nilfs_bmap_dkey_t *dkeys;
	nilfs_bmap_dptr_t *dptrs;
	int nchildren;

	dkeys = nilfs_btree_node_dkeys(btree, node);
	dptrs = nilfs_btree_node_dptrs(btree, node);
	key = nilfs_bmap_dkey_to_key(dkeys[index]);
	ptr = nilfs_bmap_dptr_to_ptr(dptrs[index]);
	nchildren = nilfs_btree_node_get_nchildren(btree, node);
	if (keyp != NULL)
		*keyp = key;
	if (ptrp != NULL)
		*ptrp = ptr;

	if (index < nchildren - 1) {
		memmove(dkeys + index, dkeys + index + 1,
			(nchildren - index - 1) * sizeof(nilfs_bmap_dkey_t));
		memmove(dptrs + index, dptrs + index + 1,
			(nchildren - index - 1) * sizeof(nilfs_bmap_dptr_t));
	}
	nchildren--;
	nilfs_btree_node_set_nchildren(btree, node, nchildren);
}

static int nilfs_btree_node_lookup(const struct nilfs_btree *btree,
				   const struct nilfs_btree_node *node,
				   nilfs_bmap_key_t key,
				   int *indexp)
{
	nilfs_bmap_key_t nkey;
	int index, low, high, s;

	/* binary search */
	low = 0;
	high = nilfs_btree_node_get_nchildren(btree, node) - 1;
	index = 0;
	s = 0;
	while (low <= high) {
		index = (low + high) / 2;
		nkey = nilfs_btree_node_get_key(btree, node, index);
		if (nkey == key) {
			s = 0;
			goto out;
		} else if (nkey < key) {
			low = index + 1;
			s = -1;
		} else {
			high = index - 1;
			s = 1;
		}
	}

	/* adjust index */
	if (nilfs_btree_node_get_level(btree, node) >
	    NILFS_BTREE_LEVEL_NODE_MIN) {
		if ((s > 0) && (index > 0))
			index--;
	} else if (s < 0)
		index++;

 out:
	BUG_ON(indexp == NULL);
	*indexp = index;

	return (s == 0);
}

static inline struct nilfs_btree_node *
nilfs_btree_get_root(const struct nilfs_btree *btree)
{
	return (struct nilfs_btree_node *)btree->bt_bmap.b_u.u_data;
}

static inline struct nilfs_btree_node *
nilfs_btree_get_nonroot_node(const struct nilfs_btree *btree,
			     const struct nilfs_btree_path *path,
			     int level)
{
	return (struct nilfs_btree_node *)path[level].bp_bh->b_data;
}

static inline struct nilfs_btree_node *
nilfs_btree_get_sib_node(const struct nilfs_btree *btree,
			 const struct nilfs_btree_path *path,
			 int level)
{
	return (struct nilfs_btree_node *)path[level].bp_sib_bh->b_data;
}

static inline int nilfs_btree_height(const struct nilfs_btree *btree)
{
	return nilfs_btree_node_get_level(btree, nilfs_btree_get_root(btree))
		+ 1;
}

static inline struct nilfs_btree_node *
nilfs_btree_get_node(const struct nilfs_btree *btree,
		     const struct nilfs_btree_path *path,
		     int level)
{
	return (level == nilfs_btree_height(btree) - 1) ?
		nilfs_btree_get_root(btree) :
		nilfs_btree_get_nonroot_node(btree, path, level);
}

static int nilfs_btree_do_lookup(const struct nilfs_btree *btree,
				 struct nilfs_btree_path *path,
				 nilfs_bmap_key_t key,
				 nilfs_bmap_ptr_t *ptrp,
				 int minlevel)
{
	struct nilfs_btree_node *node;
	nilfs_bmap_ptr_t ptr;
	int level, index, found, ret;

	BUG_ON(minlevel <= NILFS_BTREE_LEVEL_DATA);

	node = nilfs_btree_get_root(btree);
	level = nilfs_btree_node_get_level(btree, node);
	if ((level < minlevel) ||
	    (nilfs_btree_node_get_nchildren(btree, node) <= 0))
		return -ENOENT;

	found = nilfs_btree_node_lookup(btree, node, key, &index);
	ptr = nilfs_btree_node_get_ptr(btree, node, index);
	path[level].bp_bh = NULL;
	path[level].bp_index = index;

	for (level--; level >= minlevel; level--) {
		ret = nilfs_bmap_get_block(&btree->bt_bmap, ptr,
					   &path[level].bp_bh);
		if (ret < 0)
			return ret;
		node = nilfs_btree_get_nonroot_node(btree, path, level);
		BUG_ON(level != nilfs_btree_node_get_level(btree, node));
		if (!found)
			found = nilfs_btree_node_lookup(btree, node, key,
							&index);
		else
			index = 0;
		if (index < nilfs_btree_node_nchildren_max(btree, node))
			ptr = nilfs_btree_node_get_ptr(btree, node, index);
		else {
			BUG_ON(found || level != NILFS_BTREE_LEVEL_NODE_MIN);
			/* insert */
			ptr = NILFS_BMAP_INVALID_PTR;
		}
		path[level].bp_index = index;
	}
	if (!found)
		return -ENOENT;

	if (ptrp != NULL)
		*ptrp = ptr;

	return 0;
}

static int nilfs_btree_do_lookup_last(const struct nilfs_btree *btree,
				      struct nilfs_btree_path *path,
				      nilfs_bmap_key_t *keyp,
				      nilfs_bmap_ptr_t *ptrp)
{
	struct nilfs_btree_node *node;
	nilfs_bmap_ptr_t ptr;
	int index, level, ret;

	node = nilfs_btree_get_root(btree);
	index = nilfs_btree_node_get_nchildren(btree, node) - 1;
	if (index < 0)
		return -ENOENT;
	level = nilfs_btree_node_get_level(btree, node);
	ptr = nilfs_btree_node_get_ptr(btree, node, index);
	path[level].bp_bh = NULL;
	path[level].bp_index = index;

	for (level--; level > 0; level--) {
		ret = nilfs_bmap_get_block(&btree->bt_bmap, ptr,
					   &path[level].bp_bh);
		if (ret < 0)
			return ret;
		node = nilfs_btree_get_nonroot_node(btree, path, level);
		BUG_ON(level != nilfs_btree_node_get_level(btree, node));
		index = nilfs_btree_node_get_nchildren(btree, node) - 1;
		ptr = nilfs_btree_node_get_ptr(btree, node, index);
		path[level].bp_index = index;
	}

	if (keyp != NULL)
		*keyp = nilfs_btree_node_get_key(btree, node, index);
	if (ptrp != NULL)
		*ptrp = ptr;

	return 0;
}

static int nilfs_btree_lookup(const struct nilfs_bmap *bmap,
			      nilfs_bmap_key_t key,
			      int level,
			      nilfs_bmap_ptr_t *ptrp)
{
	struct nilfs_btree *btree;
	struct nilfs_btree_path *path;
	nilfs_bmap_ptr_t ptr;
	int ret;

	btree = (struct nilfs_btree *)bmap;
	path = nilfs_btree_alloc_path(btree);
	if (path == NULL)
		return -ENOMEM;
	nilfs_btree_init_path(btree, path);

	ret = nilfs_btree_do_lookup(btree, path, key, &ptr, level);

	if (ptrp != NULL)
		*ptrp = ptr;

	nilfs_btree_clear_path(btree, path);
	nilfs_btree_free_path(btree, path);

	return ret;
}

static void nilfs_btree_promote_key(struct nilfs_btree *btree,
				    struct nilfs_btree_path *path,
				    int level,
				    nilfs_bmap_key_t key)
{
	if (level < nilfs_btree_height(btree) - 1) {
		do {
			lock_buffer(path[level].bp_bh);
			nilfs_btree_node_set_key(
				btree,
				nilfs_btree_get_nonroot_node(
					btree, path, level),
				path[level].bp_index, key);
			if (!buffer_dirty(path[level].bp_bh))
				nilfs_btnode_mark_dirty(path[level].bp_bh);
			unlock_buffer(path[level].bp_bh);
		} while ((path[level].bp_index == 0) &&
			 (++level < nilfs_btree_height(btree) - 1));
	}

	/* root */
	if (level == nilfs_btree_height(btree) - 1) {
		nilfs_btree_node_set_key(btree,
					 nilfs_btree_get_root(btree),
					 path[level].bp_index, key);
	}
}

static void nilfs_btree_do_insert(struct nilfs_btree *btree,
				  struct nilfs_btree_path *path,
				  int level,
				  nilfs_bmap_key_t *keyp,
				  nilfs_bmap_ptr_t *ptrp)
{
	struct nilfs_btree_node *node;

	if (level < nilfs_btree_height(btree) - 1) {
		lock_buffer(path[level].bp_bh);
		node = nilfs_btree_get_nonroot_node(btree, path, level);
		nilfs_btree_node_insert(btree, node, *keyp, *ptrp,
					path[level].bp_index);
		if (!buffer_dirty(path[level].bp_bh))
			nilfs_btnode_mark_dirty(path[level].bp_bh);
		unlock_buffer(path[level].bp_bh);

		if (path[level].bp_index == 0)
			nilfs_btree_promote_key(btree, path, level + 1,
						nilfs_btree_node_get_key(
							btree, node, 0));
	} else {
		node = nilfs_btree_get_root(btree);
		nilfs_btree_node_insert(btree, node, *keyp, *ptrp,
					path[level].bp_index);
	}
}

static void nilfs_btree_carry_left(struct nilfs_btree *btree,
				   struct nilfs_btree_path *path,
				   int level,
				   nilfs_bmap_key_t *keyp,
				   nilfs_bmap_ptr_t *ptrp)
{
	struct nilfs_btree_node *node, *left;
	int nchildren, lnchildren, n, move;

	lock_buffer(path[level].bp_bh);
	lock_buffer(path[level].bp_sib_bh);

	node = nilfs_btree_get_nonroot_node(btree, path, level);
	left = nilfs_btree_get_sib_node(btree, path, level);
	nchildren = nilfs_btree_node_get_nchildren(btree, node);
	lnchildren = nilfs_btree_node_get_nchildren(btree, left);
	move = 0;

	n = (nchildren + lnchildren + 1) / 2 - lnchildren;
	if (n > path[level].bp_index) {
		/* move insert point */
		n--;
		move = 1;
	}

	nilfs_btree_node_move_left(btree, left, node, n);

	if (!buffer_dirty(path[level].bp_bh))
		nilfs_btnode_mark_dirty(path[level].bp_bh);
	if (!buffer_dirty(path[level].bp_sib_bh))
		nilfs_btnode_mark_dirty(path[level].bp_sib_bh);

	unlock_buffer(path[level].bp_bh);
	unlock_buffer(path[level].bp_sib_bh);

	nilfs_btree_promote_key(btree, path, level + 1,
				nilfs_btree_node_get_key(btree, node, 0));

	if (move) {
		nilfs_bmap_put_block(&btree->bt_bmap, path[level].bp_bh);
		path[level].bp_bh = path[level].bp_sib_bh;
		path[level].bp_sib_bh = NULL;
		path[level].bp_index += lnchildren;
		path[level + 1].bp_index--;
	} else {
		nilfs_bmap_put_block(&btree->bt_bmap, path[level].bp_sib_bh);
		path[level].bp_sib_bh = NULL;
		path[level].bp_index -= n;
	}

	nilfs_btree_do_insert(btree, path, level, keyp, ptrp);
}

static void nilfs_btree_carry_right(struct nilfs_btree *btree,
				    struct nilfs_btree_path *path,
				    int level,
				    nilfs_bmap_key_t *keyp,
				    nilfs_bmap_ptr_t *ptrp)
{
	struct nilfs_btree_node *node, *right;
	int nchildren, rnchildren, n, move;

	lock_buffer(path[level].bp_bh);
	lock_buffer(path[level].bp_sib_bh);

	node = nilfs_btree_get_nonroot_node(btree, path, level);
	right = nilfs_btree_get_sib_node(btree, path, level);
	nchildren = nilfs_btree_node_get_nchildren(btree, node);
	rnchildren = nilfs_btree_node_get_nchildren(btree, right);
	move = 0;

	n = (nchildren + rnchildren + 1) / 2 - rnchildren;
	if (n > nchildren - path[level].bp_index) {
		/* move insert point */
		n--;
		move = 1;
	}

	nilfs_btree_node_move_right(btree, node, right, n);

	if (!buffer_dirty(path[level].bp_bh))
		nilfs_btnode_mark_dirty(path[level].bp_bh);
	if (!buffer_dirty(path[level].bp_sib_bh))
		nilfs_btnode_mark_dirty(path[level].bp_sib_bh);

	unlock_buffer(path[level].bp_bh);
	unlock_buffer(path[level].bp_sib_bh);

	path[level + 1].bp_index++;
	nilfs_btree_promote_key(btree, path, level + 1,
				nilfs_btree_node_get_key(btree, right, 0));
	path[level + 1].bp_index--;

	if (move) {
		nilfs_bmap_put_block(&btree->bt_bmap, path[level].bp_bh);
		path[level].bp_bh = path[level].bp_sib_bh;
		path[level].bp_sib_bh = NULL;
		path[level].bp_index -=
			nilfs_btree_node_get_nchildren(btree, node);
		path[level + 1].bp_index++;
	} else {
		nilfs_bmap_put_block(&btree->bt_bmap, path[level].bp_sib_bh);
		path[level].bp_sib_bh = NULL;
	}

	nilfs_btree_do_insert(btree, path, level, keyp, ptrp);
}

static void nilfs_btree_split(struct nilfs_btree *btree,
			      struct nilfs_btree_path *path,
			      int level,
			      nilfs_bmap_key_t *keyp,
			      nilfs_bmap_ptr_t *ptrp)
{
	struct nilfs_btree_node *node, *right;
	nilfs_bmap_key_t newkey;
	nilfs_bmap_ptr_t newptr;
	int nchildren, n, move;

	lock_buffer(path[level].bp_bh);
	lock_buffer(path[level].bp_sib_bh);

	node = nilfs_btree_get_nonroot_node(btree, path, level);
	right = nilfs_btree_get_sib_node(btree, path, level);
	nchildren = nilfs_btree_node_get_nchildren(btree, node);
	move = 0;

	n = (nchildren + 1) / 2;
	if (n > nchildren - path[level].bp_index) {
		n--;
		move = 1;
	}

	nilfs_btree_node_move_right(btree, node, right, n);

	if (!buffer_dirty(path[level].bp_bh))
		nilfs_btnode_mark_dirty(path[level].bp_bh);
	if (!buffer_dirty(path[level].bp_sib_bh))
		nilfs_btnode_mark_dirty(path[level].bp_sib_bh);

	unlock_buffer(path[level].bp_bh);
	unlock_buffer(path[level].bp_sib_bh);

	newkey = nilfs_btree_node_get_key(btree, right, 0);
	newptr = path[level].bp_newreq.bpr_ptr;

	if (move) {
		path[level].bp_index -=
			nilfs_btree_node_get_nchildren(btree, node);
		nilfs_btree_node_insert(btree, right, *keyp, *ptrp,
					path[level].bp_index);

		*keyp = nilfs_btree_node_get_key(btree, right, 0);
		*ptrp = path[level].bp_newreq.bpr_ptr;

		nilfs_bmap_put_block(&btree->bt_bmap, path[level].bp_bh);
		path[level].bp_bh = path[level].bp_sib_bh;
		path[level].bp_sib_bh = NULL;
	} else {
		nilfs_btree_do_insert(btree, path, level, keyp, ptrp);

		*keyp = nilfs_btree_node_get_key(btree, right, 0);
		*ptrp = path[level].bp_newreq.bpr_ptr;

		nilfs_bmap_put_block(&btree->bt_bmap, path[level].bp_sib_bh);
		path[level].bp_sib_bh = NULL;
	}

	path[level + 1].bp_index++;
}

static void nilfs_btree_grow(struct nilfs_btree *btree,
			     struct nilfs_btree_path *path,
			     int level,
			     nilfs_bmap_key_t *keyp,
			     nilfs_bmap_ptr_t *ptrp)
{
	struct nilfs_btree_node *root, *child;
	int n;

	lock_buffer(path[level].bp_sib_bh);

	root = nilfs_btree_get_root(btree);
	child = nilfs_btree_get_sib_node(btree, path, level);

	n = nilfs_btree_node_get_nchildren(btree, root);

	nilfs_btree_node_move_right(btree, root, child, n);
	nilfs_btree_node_set_level(btree, root, level + 1);

	if (!buffer_dirty(path[level].bp_sib_bh))
		nilfs_btnode_mark_dirty(path[level].bp_sib_bh);

	unlock_buffer(path[level].bp_sib_bh);

	path[level].bp_bh = path[level].bp_sib_bh;
	path[level].bp_sib_bh = NULL;

	nilfs_btree_do_insert(btree, path, level, keyp, ptrp);

	*keyp = nilfs_btree_node_get_key(btree, child, 0);
	*ptrp = path[level].bp_newreq.bpr_ptr;
}

static nilfs_bmap_ptr_t
nilfs_btree_find_near(const struct nilfs_btree *btree,
		      const struct nilfs_btree_path *path)
{
	struct nilfs_btree_node *node;
	int level;

	if (path == NULL)
		return NILFS_BMAP_INVALID_PTR;

	/* left sibling */
	level = NILFS_BTREE_LEVEL_NODE_MIN;
	if (path[level].bp_index > 0) {
		node = nilfs_btree_get_node(btree, path, level);
		return nilfs_btree_node_get_ptr(btree, node,
						path[level].bp_index - 1);
	}

	/* parent */
	level = NILFS_BTREE_LEVEL_NODE_MIN + 1;
	if (level <= nilfs_btree_height(btree) - 1) {
		node = nilfs_btree_get_node(btree, path, level);
		return nilfs_btree_node_get_ptr(btree, node,
						path[level].bp_index);
	}

	return NILFS_BMAP_INVALID_PTR;
}

static nilfs_bmap_ptr_t
nilfs_btree_find_target_v(const struct nilfs_btree *btree,
			  const struct nilfs_btree_path *path,
			  nilfs_bmap_key_t key)
{
	nilfs_bmap_ptr_t ptr;

	ptr = nilfs_bmap_find_target_seq(&btree->bt_bmap, key);
	if (ptr != NILFS_BMAP_INVALID_PTR)
		/* sequential access */
		return ptr;
	else {
		ptr = nilfs_btree_find_near(btree, path);
		if (ptr != NILFS_BMAP_INVALID_PTR)
			/* near */
			return ptr;
	}
	/* block group */
	return nilfs_bmap_find_target_in_group(&btree->bt_bmap);
}

static void nilfs_btree_set_target_v(struct nilfs_btree *btree,
				     nilfs_bmap_key_t key,
				     nilfs_bmap_ptr_t ptr)
{
	btree->bt_bmap.b_last_allocated_key = key;
	btree->bt_bmap.b_last_allocated_ptr = ptr;
}

static int nilfs_btree_prepare_insert(struct nilfs_btree *btree,
				      struct nilfs_btree_path *path,
				      int *levelp,
				      nilfs_bmap_key_t key,
				      nilfs_bmap_ptr_t ptr,
				      struct nilfs_bmap_stats *stats)
{
	struct buffer_head *bh;
	struct nilfs_btree_node *node, *parent, *sib;
	nilfs_bmap_ptr_t sibptr;
	int pindex, level, ret;

	stats->bs_nblocks = 0;
	level = NILFS_BTREE_LEVEL_DATA;

	/* allocate a new ptr for data block */
	if (btree->bt_ops->btop_find_target != NULL)
		path[level].bp_newreq.bpr_ptr =
			(*btree->bt_ops->btop_find_target)(btree, path, key);

	ret = (*btree->bt_bmap.b_pops->bpop_prepare_alloc_ptr)(
		&btree->bt_bmap, &path[level].bp_newreq);
	if (ret < 0)
		goto err_out_data;

	for (level = NILFS_BTREE_LEVEL_NODE_MIN;
	     level < nilfs_btree_height(btree) - 1;
	     level++) {
		node = nilfs_btree_get_nonroot_node(btree, path, level);
		if (nilfs_btree_node_get_nchildren(btree, node) <
		    nilfs_btree_node_nchildren_max(btree, node)) {
			path[level].bp_op = nilfs_btree_do_insert;
			stats->bs_nblocks++;
			goto out;
		}

		parent = nilfs_btree_get_node(btree, path, level + 1);
		pindex = path[level + 1].bp_index;

		/* left sibling */
		if (pindex > 0) {
			sibptr = nilfs_btree_node_get_ptr(btree, parent,
							  pindex - 1);
			ret = nilfs_bmap_get_block(&btree->bt_bmap, sibptr,
						   &bh);
			if (ret < 0)
				goto err_out_child_node;
			sib = (struct nilfs_btree_node *)bh->b_data;
			if (nilfs_btree_node_get_nchildren(btree, sib) <
			    nilfs_btree_node_nchildren_max(btree, sib)) {
				path[level].bp_sib_bh = bh;
				path[level].bp_op = nilfs_btree_carry_left;
				stats->bs_nblocks++;
				goto out;
			} else
				nilfs_bmap_put_block(&btree->bt_bmap, bh);
		}

		/* right sibling */
		if (pindex <
		    nilfs_btree_node_get_nchildren(btree, parent) - 1) {
			sibptr = nilfs_btree_node_get_ptr(btree, parent,
							  pindex + 1);
			ret = nilfs_bmap_get_block(&btree->bt_bmap, sibptr,
						   &bh);
			if (ret < 0)
				goto err_out_child_node;
			sib = (struct nilfs_btree_node *)bh->b_data;
			if (nilfs_btree_node_get_nchildren(btree, sib) <
			    nilfs_btree_node_nchildren_max(btree, sib)) {
				path[level].bp_sib_bh = bh;
				path[level].bp_op = nilfs_btree_carry_right;
				stats->bs_nblocks++;
				goto out;
			} else
				nilfs_bmap_put_block(&btree->bt_bmap, bh);
		}

		/* split */
		path[level].bp_newreq.bpr_ptr =
			path[level - 1].bp_newreq.bpr_ptr + 1;
		ret = (*btree->bt_bmap.b_pops->bpop_prepare_alloc_ptr)(
			&btree->bt_bmap, &path[level].bp_newreq);
		if (ret < 0)
			goto err_out_child_node;
		ret = nilfs_bmap_get_new_block(&btree->bt_bmap,
					       path[level].bp_newreq.bpr_ptr,
					       &bh);
		if (ret < 0)
			goto err_out_curr_node;

		stats->bs_nblocks++;

		lock_buffer(bh);
		nilfs_btree_node_init(btree,
				      (struct nilfs_btree_node *)bh->b_data,
				      0, level, 0, NULL, NULL);
		unlock_buffer(bh);
		path[level].bp_sib_bh = bh;
		path[level].bp_op = nilfs_btree_split;
	}

	/* root */
	node = nilfs_btree_get_root(btree);
	if (nilfs_btree_node_get_nchildren(btree, node) <
	    nilfs_btree_node_nchildren_max(btree, node)) {
		path[level].bp_op = nilfs_btree_do_insert;
		stats->bs_nblocks++;
		goto out;
	}

	/* grow */
	path[level].bp_newreq.bpr_ptr = path[level - 1].bp_newreq.bpr_ptr + 1;
	ret = (*btree->bt_bmap.b_pops->bpop_prepare_alloc_ptr)(
		&btree->bt_bmap, &path[level].bp_newreq);
	if (ret < 0)
		goto err_out_child_node;
	ret = nilfs_bmap_get_new_block(&btree->bt_bmap,
				       path[level].bp_newreq.bpr_ptr, &bh);
	if (ret < 0)
		goto err_out_curr_node;

	lock_buffer(bh);
	nilfs_btree_node_init(btree, (struct nilfs_btree_node *)bh->b_data,
			      0, level, 0, NULL, NULL);
	unlock_buffer(bh);
	path[level].bp_sib_bh = bh;
	path[level].bp_op = nilfs_btree_grow;

	level++;
	path[level].bp_op = nilfs_btree_do_insert;

	/* a newly-created node block and a data block are added */
	stats->bs_nblocks += 2;

	/* success */
 out:
	*levelp = level;
	return ret;

	/* error */
 err_out_curr_node:
	(*btree->bt_bmap.b_pops->bpop_abort_alloc_ptr)(&btree->bt_bmap,
						       &path[level].bp_newreq);
 err_out_child_node:
	for (level--; level > NILFS_BTREE_LEVEL_DATA; level--) {
		nilfs_bmap_delete_block(&btree->bt_bmap, path[level].bp_sib_bh);
		(*btree->bt_bmap.b_pops->bpop_abort_alloc_ptr)(
			&btree->bt_bmap, &path[level].bp_newreq);

	}

	(*btree->bt_bmap.b_pops->bpop_abort_alloc_ptr)(&btree->bt_bmap,
						       &path[level].bp_newreq);
 err_out_data:
	*levelp = level;
	stats->bs_nblocks = 0;
	return ret;
}

static void nilfs_btree_commit_insert(struct nilfs_btree *btree,
				      struct nilfs_btree_path *path,
				      int maxlevel,
				      nilfs_bmap_key_t key,
				      nilfs_bmap_ptr_t ptr)
{
	int level;

	set_buffer_nilfs_volatile((struct buffer_head *)((unsigned long)ptr));
	ptr = path[NILFS_BTREE_LEVEL_DATA].bp_newreq.bpr_ptr;
	if (btree->bt_ops->btop_set_target != NULL)
		(*btree->bt_ops->btop_set_target)(btree, key, ptr);

	for (level = NILFS_BTREE_LEVEL_NODE_MIN; level <= maxlevel; level++) {
		if (btree->bt_bmap.b_pops->bpop_commit_alloc_ptr != NULL) {
			(*btree->bt_bmap.b_pops->bpop_commit_alloc_ptr)(
				&btree->bt_bmap, &path[level - 1].bp_newreq);
		}
		(*path[level].bp_op)(btree, path, level, &key, &ptr);
	}

	if (!nilfs_bmap_dirty(&btree->bt_bmap))
		nilfs_bmap_set_dirty(&btree->bt_bmap);
}

static int nilfs_btree_insert(struct nilfs_bmap *bmap,
			      nilfs_bmap_key_t key,
			      nilfs_bmap_ptr_t ptr)
{
	struct nilfs_btree *btree;
	struct nilfs_btree_path *path;
	struct nilfs_bmap_stats stats;
	int level, ret;

	btree = (struct nilfs_btree *)bmap;
	path = nilfs_btree_alloc_path(btree);
	if (path == NULL)
		return -ENOMEM;
	nilfs_btree_init_path(btree, path);

	ret = nilfs_btree_do_lookup(btree, path, key, NULL,
				    NILFS_BTREE_LEVEL_NODE_MIN);
	if (ret != -ENOENT) {
		if (ret == 0)
			ret = -EEXIST;
		goto out;
	}

	ret = nilfs_btree_prepare_insert(btree, path, &level, key, ptr, &stats);
	if (ret < 0)
		goto out;
	nilfs_btree_commit_insert(btree, path, level, key, ptr);
	nilfs_bmap_add_blocks(bmap, stats.bs_nblocks);

 out:
	nilfs_btree_clear_path(btree, path);
	nilfs_btree_free_path(btree, path);
	return ret;
}

static void nilfs_btree_do_delete(struct nilfs_btree *btree,
				  struct nilfs_btree_path *path,
				  int level,
				  nilfs_bmap_key_t *keyp,
				  nilfs_bmap_ptr_t *ptrp)
{
	struct nilfs_btree_node *node;

	if (level < nilfs_btree_height(btree) - 1) {
		lock_buffer(path[level].bp_bh);
		node = nilfs_btree_get_nonroot_node(btree, path, level);
		nilfs_btree_node_delete(btree, node, keyp, ptrp,
					path[level].bp_index);
		if (!buffer_dirty(path[level].bp_bh))
			nilfs_btnode_mark_dirty(path[level].bp_bh);
		unlock_buffer(path[level].bp_bh);
		if (path[level].bp_index == 0)
			nilfs_btree_promote_key(btree, path, level + 1,
				nilfs_btree_node_get_key(btree, node, 0));
	} else {
		node = nilfs_btree_get_root(btree);
		nilfs_btree_node_delete(btree, node, keyp, ptrp,
					path[level].bp_index);
	}
}

static void nilfs_btree_borrow_left(struct nilfs_btree *btree,
				    struct nilfs_btree_path *path,
				    int level,
				    nilfs_bmap_key_t *keyp,
				    nilfs_bmap_ptr_t *ptrp)
{
	struct nilfs_btree_node *node, *left;
	int nchildren, lnchildren, n;

	nilfs_btree_do_delete(btree, path, level, keyp, ptrp);

	lock_buffer(path[level].bp_bh);
	lock_buffer(path[level].bp_sib_bh);

	node = nilfs_btree_get_nonroot_node(btree, path, level);
	left = nilfs_btree_get_sib_node(btree, path, level);
	nchildren = nilfs_btree_node_get_nchildren(btree, node);
	lnchildren = nilfs_btree_node_get_nchildren(btree, left);

	n = (nchildren + lnchildren) / 2 - nchildren;

	nilfs_btree_node_move_right(btree, left, node, n);

	if (!buffer_dirty(path[level].bp_bh))
		nilfs_btnode_mark_dirty(path[level].bp_bh);
	if (!buffer_dirty(path[level].bp_sib_bh))
		nilfs_btnode_mark_dirty(path[level].bp_sib_bh);

	unlock_buffer(path[level].bp_bh);
	unlock_buffer(path[level].bp_sib_bh);

	nilfs_btree_promote_key(btree, path, level + 1,
				nilfs_btree_node_get_key(btree, node, 0));

	nilfs_bmap_put_block(&btree->bt_bmap, path[level].bp_sib_bh);
	path[level].bp_sib_bh = NULL;
	path[level].bp_index += n;
}

static void nilfs_btree_borrow_right(struct nilfs_btree *btree,
				     struct nilfs_btree_path *path,
				     int level,
				     nilfs_bmap_key_t *keyp,
				     nilfs_bmap_ptr_t *ptrp)
{
	struct nilfs_btree_node *node, *right;
	int nchildren, rnchildren, n;

	nilfs_btree_do_delete(btree, path, level, keyp, ptrp);

	lock_buffer(path[level].bp_bh);
	lock_buffer(path[level].bp_sib_bh);

	node = nilfs_btree_get_nonroot_node(btree, path, level);
	right = nilfs_btree_get_sib_node(btree, path, level);
	nchildren = nilfs_btree_node_get_nchildren(btree, node);
	rnchildren = nilfs_btree_node_get_nchildren(btree, right);

	n = (nchildren + rnchildren) / 2 - nchildren;

	nilfs_btree_node_move_left(btree, node, right, n);

	if (!buffer_dirty(path[level].bp_bh))
		nilfs_btnode_mark_dirty(path[level].bp_bh);
	if (!buffer_dirty(path[level].bp_sib_bh))
		nilfs_btnode_mark_dirty(path[level].bp_sib_bh);

	unlock_buffer(path[level].bp_bh);
	unlock_buffer(path[level].bp_sib_bh);

	path[level + 1].bp_index++;
	nilfs_btree_promote_key(btree, path, level + 1,
				nilfs_btree_node_get_key(btree, right, 0));
	path[level + 1].bp_index--;

	nilfs_bmap_put_block(&btree->bt_bmap, path[level].bp_sib_bh);
	path[level].bp_sib_bh = NULL;
}

static void nilfs_btree_concat_left(struct nilfs_btree *btree,
				    struct nilfs_btree_path *path,
				    int level,
				    nilfs_bmap_key_t *keyp,
				    nilfs_bmap_ptr_t *ptrp)
{
	struct nilfs_btree_node *node, *left;
	int n;

	nilfs_btree_do_delete(btree, path, level, keyp, ptrp);

	lock_buffer(path[level].bp_bh);
	lock_buffer(path[level].bp_sib_bh);

	node = nilfs_btree_get_nonroot_node(btree, path, level);
	left = nilfs_btree_get_sib_node(btree, path, level);

	n = nilfs_btree_node_get_nchildren(btree, node);

	nilfs_btree_node_move_left(btree, left, node, n);

	if (!buffer_dirty(path[level].bp_sib_bh))
		nilfs_btnode_mark_dirty(path[level].bp_sib_bh);

	unlock_buffer(path[level].bp_bh);
	unlock_buffer(path[level].bp_sib_bh);

	nilfs_bmap_delete_block(&btree->bt_bmap, path[level].bp_bh);
	path[level].bp_bh = path[level].bp_sib_bh;
	path[level].bp_sib_bh = NULL;
	path[level].bp_index += nilfs_btree_node_get_nchildren(btree, left);
}

static void nilfs_btree_concat_right(struct nilfs_btree *btree,
				     struct nilfs_btree_path *path,
				     int level,
				     nilfs_bmap_key_t *keyp,
				     nilfs_bmap_ptr_t *ptrp)
{
	struct nilfs_btree_node *node, *right;
	int n;

	nilfs_btree_do_delete(btree, path, level, keyp, ptrp);

	lock_buffer(path[level].bp_bh);
	lock_buffer(path[level].bp_sib_bh);

	node = nilfs_btree_get_nonroot_node(btree, path, level);
	right = nilfs_btree_get_sib_node(btree, path, level);

	n = nilfs_btree_node_get_nchildren(btree, right);

	nilfs_btree_node_move_left(btree, node, right, n);

	if (!buffer_dirty(path[level].bp_bh))
		nilfs_btnode_mark_dirty(path[level].bp_bh);

	unlock_buffer(path[level].bp_bh);
	unlock_buffer(path[level].bp_sib_bh);

	nilfs_bmap_delete_block(&btree->bt_bmap, path[level].bp_sib_bh);
	path[level].bp_sib_bh = NULL;
	path[level + 1].bp_index++;
}

static void nilfs_btree_shrink(struct nilfs_btree *btree,
			       struct nilfs_btree_path *path,
			       int level,
			       nilfs_bmap_key_t *keyp,
			       nilfs_bmap_ptr_t *ptrp)
{
	struct nilfs_btree_node *root, *child;
	int n;

	nilfs_btree_do_delete(btree, path, level, keyp, ptrp);

	lock_buffer(path[level].bp_bh);
	root = nilfs_btree_get_root(btree);
	child = nilfs_btree_get_nonroot_node(btree, path, level);

	nilfs_btree_node_delete(btree, root, NULL, NULL, 0);
	nilfs_btree_node_set_level(btree, root, level);
	n = nilfs_btree_node_get_nchildren(btree, child);
	nilfs_btree_node_move_left(btree, root, child, n);
	unlock_buffer(path[level].bp_bh);

	nilfs_bmap_delete_block(&btree->bt_bmap, path[level].bp_bh);
	path[level].bp_bh = NULL;
}


static int nilfs_btree_prepare_delete(struct nilfs_btree *btree,
				      struct nilfs_btree_path *path,
				      int *levelp,
				      struct nilfs_bmap_stats *stats)
{
	struct buffer_head *bh;
	struct nilfs_btree_node *node, *parent, *sib;
	nilfs_bmap_ptr_t sibptr;
	int pindex, level, ret;

	ret = 0;
	stats->bs_nblocks = 0;
	for (level = NILFS_BTREE_LEVEL_NODE_MIN;
	     level < nilfs_btree_height(btree) - 1;
	     level++) {
		node = nilfs_btree_get_nonroot_node(btree, path, level);
		path[level].bp_oldreq.bpr_ptr =
			nilfs_btree_node_get_ptr(btree, node,
						 path[level].bp_index);
		if (btree->bt_bmap.b_pops->bpop_prepare_end_ptr != NULL) {
			ret = (*btree->bt_bmap.b_pops->bpop_prepare_end_ptr)(
				&btree->bt_bmap, &path[level].bp_oldreq);
			if (ret < 0)
				goto err_out_child_node;
		}

		if (nilfs_btree_node_get_nchildren(btree, node) >
		    nilfs_btree_node_nchildren_min(btree, node)) {
			path[level].bp_op = nilfs_btree_do_delete;
			stats->bs_nblocks++;
			goto out;
		}

		parent = nilfs_btree_get_node(btree, path, level + 1);
		pindex = path[level + 1].bp_index;

		if (pindex > 0) {
			/* left sibling */
			sibptr = nilfs_btree_node_get_ptr(btree, parent,
							  pindex - 1);
			ret = nilfs_bmap_get_block(&btree->bt_bmap, sibptr,
						   &bh);
			if (ret < 0)
				goto err_out_curr_node;
			sib = (struct nilfs_btree_node *)bh->b_data;
			if (nilfs_btree_node_get_nchildren(btree, sib) >
			    nilfs_btree_node_nchildren_min(btree, sib)) {
				path[level].bp_sib_bh = bh;
				path[level].bp_op = nilfs_btree_borrow_left;
				stats->bs_nblocks++;
				goto out;
			} else {
				path[level].bp_sib_bh = bh;
				path[level].bp_op = nilfs_btree_concat_left;
				stats->bs_nblocks++;
				/* continue; */
			}
		} else if (pindex <
			   nilfs_btree_node_get_nchildren(btree, parent) - 1) {
			/* right sibling */
			sibptr = nilfs_btree_node_get_ptr(btree, parent,
							  pindex + 1);
			ret = nilfs_bmap_get_block(&btree->bt_bmap, sibptr,
						   &bh);
			if (ret < 0)
				goto err_out_curr_node;
			sib = (struct nilfs_btree_node *)bh->b_data;
			if (nilfs_btree_node_get_nchildren(btree, sib) >
			    nilfs_btree_node_nchildren_min(btree, sib)) {
				path[level].bp_sib_bh = bh;
				path[level].bp_op = nilfs_btree_borrow_right;
				stats->bs_nblocks++;
				goto out;
			} else {
				path[level].bp_sib_bh = bh;
				path[level].bp_op = nilfs_btree_concat_right;
				stats->bs_nblocks++;
				/* continue; */
			}
		} else {
			/* no siblings */
			/* the only child of the root node */
			BUG_ON(level != nilfs_btree_height(btree) - 2);
			if (nilfs_btree_node_get_nchildren(btree, node) - 1 <=
			    NILFS_BTREE_ROOT_NCHILDREN_MAX) {
				path[level].bp_op = nilfs_btree_shrink;
				stats->bs_nblocks += 2;
			} else {
				path[level].bp_op = nilfs_btree_do_delete;
				stats->bs_nblocks++;
			}

			goto out;

		}
	}

	node = nilfs_btree_get_root(btree);
	path[level].bp_oldreq.bpr_ptr =
		nilfs_btree_node_get_ptr(btree, node, path[level].bp_index);
	if (btree->bt_bmap.b_pops->bpop_prepare_end_ptr != NULL) {
		ret = (*btree->bt_bmap.b_pops->bpop_prepare_end_ptr)(
			&btree->bt_bmap, &path[level].bp_oldreq);
		if (ret < 0)
			goto err_out_child_node;
	}
	/* child of the root node is deleted */
	path[level].bp_op = nilfs_btree_do_delete;
	stats->bs_nblocks++;

	/* success */
 out:
	*levelp = level;
	return ret;

	/* error */
 err_out_curr_node:
	if (btree->bt_bmap.b_pops->bpop_abort_end_ptr != NULL)
		(*btree->bt_bmap.b_pops->bpop_abort_end_ptr)(
			&btree->bt_bmap, &path[level].bp_oldreq);
 err_out_child_node:
	for (level--; level >= NILFS_BTREE_LEVEL_NODE_MIN; level--) {
		nilfs_bmap_put_block(&btree->bt_bmap, path[level].bp_sib_bh);
		if (btree->bt_bmap.b_pops->bpop_abort_end_ptr != NULL)
			(*btree->bt_bmap.b_pops->bpop_abort_end_ptr)(
				&btree->bt_bmap, &path[level].bp_oldreq);
	}
	*levelp = level;
	stats->bs_nblocks = 0;
	return ret;
}

static void nilfs_btree_commit_delete(struct nilfs_btree *btree,
				      struct nilfs_btree_path *path,
				      int maxlevel)
{
	int level;

	for (level = NILFS_BTREE_LEVEL_NODE_MIN; level <= maxlevel; level++) {
		if (btree->bt_bmap.b_pops->bpop_commit_end_ptr != NULL)
			(*btree->bt_bmap.b_pops->bpop_commit_end_ptr)(
				&btree->bt_bmap, &path[level].bp_oldreq);
		(*path[level].bp_op)(btree, path, level, NULL, NULL);
	}

	if (!nilfs_bmap_dirty(&btree->bt_bmap))
		nilfs_bmap_set_dirty(&btree->bt_bmap);
}

static int nilfs_btree_delete(struct nilfs_bmap *bmap,
			      nilfs_bmap_key_t key)

{
	struct nilfs_btree *btree;
	struct nilfs_btree_path *path;
	struct nilfs_bmap_stats stats;
	int level, ret;

	btree = (struct nilfs_btree *)bmap;
	path = nilfs_btree_alloc_path(btree);
	if (path == NULL)
		return -ENOMEM;
	nilfs_btree_init_path(btree, path);
	ret = nilfs_btree_do_lookup(btree, path, key, NULL,
				    NILFS_BTREE_LEVEL_NODE_MIN);
	if (ret < 0)
		goto out;

	ret = nilfs_btree_prepare_delete(btree, path, &level, &stats);
	if (ret < 0)
		goto out;
	nilfs_btree_commit_delete(btree, path, level);
	nilfs_bmap_sub_blocks(bmap, stats.bs_nblocks);

out:
	nilfs_btree_clear_path(btree, path);
	nilfs_btree_free_path(btree, path);
	return ret;
}

static int nilfs_btree_last_key(const struct nilfs_bmap *bmap,
				nilfs_bmap_key_t *keyp)
{
	struct nilfs_btree *btree;
	struct nilfs_btree_path *path;
	int ret;

	btree = (struct nilfs_btree *)bmap;
	path = nilfs_btree_alloc_path(btree);
	if (path == NULL)
		return -ENOMEM;
	nilfs_btree_init_path(btree, path);

	ret = nilfs_btree_do_lookup_last(btree, path, keyp, NULL);

	nilfs_btree_clear_path(btree, path);
	nilfs_btree_free_path(btree, path);

	return ret;
}

static int nilfs_btree_check_delete(struct nilfs_bmap *bmap,
				    nilfs_bmap_key_t key)
{
	struct buffer_head *bh;
	struct nilfs_btree *btree;
	struct nilfs_btree_node *root, *node;
	nilfs_bmap_key_t maxkey, nextmaxkey;
	nilfs_bmap_ptr_t ptr;
	int nchildren, ret;

	btree = (struct nilfs_btree *)bmap;
	root = nilfs_btree_get_root(btree);
	switch (nilfs_btree_height(btree)) {
	case 2:
		bh = NULL;
		node = root;
		break;
	case 3:
		nchildren = nilfs_btree_node_get_nchildren(btree, root);
		if (nchildren > 1)
			return 0;
		ptr = nilfs_btree_node_get_ptr(btree, root, nchildren - 1);
		ret = nilfs_bmap_get_block(bmap, ptr, &bh);
		if (ret < 0)
			return ret;
		node = (struct nilfs_btree_node *)bh->b_data;
		break;
	default:
		return 0;
	}

	nchildren = nilfs_btree_node_get_nchildren(btree, node);
	maxkey = nilfs_btree_node_get_key(btree, node, nchildren - 1);
	nextmaxkey = (nchildren > 1) ?
		nilfs_btree_node_get_key(btree, node, nchildren - 2) : 0;
	if (bh != NULL)
		nilfs_bmap_put_block(bmap, bh);

	return (maxkey == key) && (nextmaxkey < bmap->b_low);
}

static int nilfs_btree_gather_data(struct nilfs_bmap *bmap,
				   nilfs_bmap_key_t *keys,
				   nilfs_bmap_ptr_t *ptrs,
				   int nitems)
{
	struct buffer_head *bh;
	struct nilfs_btree *btree;
	struct nilfs_btree_node *node, *root;
	nilfs_bmap_dkey_t *dkeys;
	nilfs_bmap_dptr_t *dptrs;
	nilfs_bmap_ptr_t ptr;
	int nchildren, i, ret;

	btree = (struct nilfs_btree *)bmap;
	root = nilfs_btree_get_root(btree);
	switch (nilfs_btree_height(btree)) {
	case 2:
		bh = NULL;
		node = root;
		break;
	case 3:
		nchildren = nilfs_btree_node_get_nchildren(btree, root);
		BUG_ON(nchildren > 1);
		ptr = nilfs_btree_node_get_ptr(btree, root, nchildren - 1);
		ret = nilfs_bmap_get_block(bmap, ptr, &bh);
		if (ret < 0)
			return ret;
		node = (struct nilfs_btree_node *)bh->b_data;
		break;
	default:
		node = NULL;
		BUG();
	}

	nchildren = nilfs_btree_node_get_nchildren(btree, node);
	if (nchildren < nitems)
		nitems = nchildren;
	dkeys = nilfs_btree_node_dkeys(btree, node);
	dptrs = nilfs_btree_node_dptrs(btree, node);
	for (i = 0; i < nitems; i++) {
		keys[i] = nilfs_bmap_dkey_to_key(dkeys[i]);
		ptrs[i] = nilfs_bmap_dptr_to_ptr(dptrs[i]);
	}

	if (bh != NULL)
		nilfs_bmap_put_block(bmap, bh);

	return nitems;
}

static int
nilfs_btree_prepare_convert_and_insert(struct nilfs_bmap *bmap,
				       nilfs_bmap_key_t key,
				       union nilfs_bmap_ptr_req *dreq,
				       union nilfs_bmap_ptr_req *nreq,
				       struct buffer_head **bhp,
				       struct nilfs_bmap_stats *stats)
{
	struct buffer_head *bh;
	struct nilfs_btree *btree;
	int ret;

	btree = (struct nilfs_btree *)bmap;
	stats->bs_nblocks = 0;

	/* for data */
	/* cannot find near ptr */
	if (btree->bt_ops->btop_find_target != NULL)
		dreq->bpr_ptr
			= (*btree->bt_ops->btop_find_target)(btree, NULL, key);
	ret = (*bmap->b_pops->bpop_prepare_alloc_ptr)(bmap, dreq);
	if (ret < 0)
		return ret;

	*bhp = NULL;
	stats->bs_nblocks++;
	if (nreq != NULL) {
		nreq->bpr_ptr = dreq->bpr_ptr + 1;
		ret = (*bmap->b_pops->bpop_prepare_alloc_ptr)(bmap, nreq);
		if (ret < 0)
			goto err_out_dreq;

		ret = nilfs_bmap_get_new_block(bmap, nreq->bpr_ptr, &bh);
		if (ret < 0)
			goto err_out_nreq;

		*bhp = bh;
		stats->bs_nblocks++;
	}

	/* success */
	return 0;

	/* error */
 err_out_nreq:
	(*bmap->b_pops->bpop_abort_alloc_ptr)(bmap, nreq);
 err_out_dreq:
	(*bmap->b_pops->bpop_abort_alloc_ptr)(bmap, dreq);
	stats->bs_nblocks = 0;
	return ret;

}

static void
nilfs_btree_commit_convert_and_insert(struct nilfs_bmap *bmap,
				      nilfs_bmap_key_t key,
				      nilfs_bmap_ptr_t ptr,
				      const nilfs_bmap_key_t *keys,
				      const nilfs_bmap_ptr_t *ptrs,
				      int n,
				      nilfs_bmap_key_t low,
				      nilfs_bmap_key_t high,
				      union nilfs_bmap_ptr_req *dreq,
				      union nilfs_bmap_ptr_req *nreq,
				      struct buffer_head *bh)
{
	struct nilfs_btree *btree;
	struct nilfs_btree_node *node;
	nilfs_bmap_ptr_t tmpptr;

	/* free resources */
	if (bmap->b_ops->bop_clear != NULL)
		(*bmap->b_ops->bop_clear)(bmap);

	/* ptr must be a pointer to a buffer head. */
	set_buffer_nilfs_volatile((struct buffer_head *)((unsigned long)ptr));

	/* convert and insert */
	btree = (struct nilfs_btree *)bmap;
	nilfs_btree_init(bmap, low, high);
	if (nreq != NULL) {
		if (bmap->b_pops->bpop_commit_alloc_ptr != NULL) {
			(*bmap->b_pops->bpop_commit_alloc_ptr)(bmap, dreq);
			(*bmap->b_pops->bpop_commit_alloc_ptr)(bmap, nreq);
		}

		/* create child node at level 1 */
		lock_buffer(bh);
		node = (struct nilfs_btree_node *)bh->b_data;
		nilfs_btree_node_init(btree, node, 0, 1, n, keys, ptrs);
		nilfs_btree_node_insert(btree, node,
					key, dreq->bpr_ptr, n);
		if (!buffer_dirty(bh))
			nilfs_btnode_mark_dirty(bh);
		if (!nilfs_bmap_dirty(bmap))
			nilfs_bmap_set_dirty(bmap);

		unlock_buffer(bh);
		nilfs_bmap_put_block(bmap, bh);

		/* create root node at level 2 */
		node = nilfs_btree_get_root(btree);
		tmpptr = nreq->bpr_ptr;
		nilfs_btree_node_init(btree, node, NILFS_BTREE_NODE_ROOT,
				      2, 1, &keys[0], &tmpptr);
	} else {
		if (bmap->b_pops->bpop_commit_alloc_ptr != NULL)
			(*bmap->b_pops->bpop_commit_alloc_ptr)(bmap, dreq);

		/* create root node at level 1 */
		node = nilfs_btree_get_root(btree);
		nilfs_btree_node_init(btree, node, NILFS_BTREE_NODE_ROOT,
				      1, n, keys, ptrs);
		nilfs_btree_node_insert(btree, node,
					key, dreq->bpr_ptr, n);
		if (!nilfs_bmap_dirty(bmap))
			nilfs_bmap_set_dirty(bmap);
	}

	if (btree->bt_ops->btop_set_target != NULL)
		(*btree->bt_ops->btop_set_target)(btree, key, dreq->bpr_ptr);
}

/**
 * nilfs_btree_convert_and_insert -
 * @bmap:
 * @key:
 * @ptr:
 * @keys:
 * @ptrs:
 * @n:
 * @low:
 * @high:
 */
int nilfs_btree_convert_and_insert(struct nilfs_bmap *bmap,
				   nilfs_bmap_key_t key,
				   nilfs_bmap_ptr_t ptr,
				   const nilfs_bmap_key_t *keys,
				   const nilfs_bmap_ptr_t *ptrs,
				   int n,
				   nilfs_bmap_key_t low,
				   nilfs_bmap_key_t high)
{
	struct buffer_head *bh;
	union nilfs_bmap_ptr_req dreq, nreq, *di, *ni;
	struct nilfs_bmap_stats stats;
	int ret;

	if (n + 1 <= NILFS_BTREE_ROOT_NCHILDREN_MAX) {
		di = &dreq;
		ni = NULL;
	} else if ((n + 1) <= NILFS_BTREE_NODE_NCHILDREN_MAX(
			   1 << bmap->b_inode->i_blkbits)) {
		di = &dreq;
		ni = &nreq;
	} else {
		di = NULL;
		ni = NULL;
		BUG();
	}

	ret = nilfs_btree_prepare_convert_and_insert(bmap, key, di, ni, &bh,
						     &stats);
	if (ret < 0)
		return ret;
	nilfs_btree_commit_convert_and_insert(bmap, key, ptr, keys, ptrs, n,
					      low, high, di, ni, bh);
	nilfs_bmap_add_blocks(bmap, stats.bs_nblocks);
	return 0;
}

static int nilfs_btree_propagate_p(struct nilfs_btree *btree,
				   struct nilfs_btree_path *path,
				   int level,
				   struct buffer_head *bh)
{
	while ((++level < nilfs_btree_height(btree) - 1) &&
	       !buffer_dirty(path[level].bp_bh) &&
	       !buffer_prepare_dirty(path[level].bp_bh))
		nilfs_btnode_mark_prepare_dirty(path[level].bp_bh);

	return 0;
}

static int nilfs_btree_prepare_update_v(struct nilfs_btree *btree,
					struct nilfs_btree_path *path,
					int level)
{
	struct nilfs_btree_node *parent;
	int ret;

	parent = nilfs_btree_get_node(btree, path, level + 1);
	path[level].bp_oldreq.bpr_ptr =
		nilfs_btree_node_get_ptr(btree, parent,
					 path[level + 1].bp_index);
	path[level].bp_newreq.bpr_ptr = path[level].bp_oldreq.bpr_ptr + 1;
	ret = nilfs_bmap_prepare_update(&btree->bt_bmap,
					&path[level].bp_oldreq,
					&path[level].bp_newreq);
	if (ret < 0)
		return ret;

	if (buffer_nilfs_node(path[level].bp_bh)) {
		path[level].bp_ctxt.oldkey = path[level].bp_oldreq.bpr_ptr;
		path[level].bp_ctxt.newkey = path[level].bp_newreq.bpr_ptr;
		path[level].bp_ctxt.bh = path[level].bp_bh;
		ret = nilfs_btnode_prepare_change_key(
			&NILFS_BMAP_I(&btree->bt_bmap)->i_btnode_cache,
			&path[level].bp_ctxt);
		if (ret < 0) {
			nilfs_bmap_abort_update(&btree->bt_bmap,
						&path[level].bp_oldreq,
						&path[level].bp_newreq);
			return ret;
		}
	}

	return 0;
}

static void nilfs_btree_commit_update_v(struct nilfs_btree *btree,
					struct nilfs_btree_path *path,
					int level)
{
	struct nilfs_btree_node *parent;

	nilfs_bmap_commit_update(&btree->bt_bmap,
				 &path[level].bp_oldreq,
				 &path[level].bp_newreq);

	if (buffer_nilfs_node(path[level].bp_bh)) {
		nilfs_btnode_commit_change_key(
			&NILFS_BMAP_I(&btree->bt_bmap)->i_btnode_cache,
			&path[level].bp_ctxt);
		path[level].bp_bh = path[level].bp_ctxt.bh;
	}
	set_buffer_nilfs_volatile(path[level].bp_bh);

	parent = nilfs_btree_get_node(btree, path, level + 1);
	nilfs_btree_node_set_ptr(btree, parent, path[level + 1].bp_index,
				 path[level].bp_newreq.bpr_ptr);
}

static void nilfs_btree_abort_update_v(struct nilfs_btree *btree,
				       struct nilfs_btree_path *path,
				       int level)
{
	nilfs_bmap_abort_update(&btree->bt_bmap,
				&path[level].bp_oldreq,
				&path[level].bp_newreq);
	if (buffer_nilfs_node(path[level].bp_bh))
		nilfs_btnode_abort_change_key(
			&NILFS_BMAP_I(&btree->bt_bmap)->i_btnode_cache,
			&path[level].bp_ctxt);
}

static int nilfs_btree_prepare_propagate_v(struct nilfs_btree *btree,
					   struct nilfs_btree_path *path,
					   int minlevel,
					   int *maxlevelp)
{
	int level, ret;

	level = minlevel;
	if (!buffer_nilfs_volatile(path[level].bp_bh)) {
		ret = nilfs_btree_prepare_update_v(btree, path, level);
		if (ret < 0)
			return ret;
	}
	while ((++level < nilfs_btree_height(btree) - 1) &&
	       !buffer_dirty(path[level].bp_bh) &&
	       !buffer_prepare_dirty(path[level].bp_bh)) {

		BUG_ON(buffer_nilfs_volatile(path[level].bp_bh));
		ret = nilfs_btree_prepare_update_v(btree, path, level);
		if (ret < 0)
			goto out;
	}

	/* success */
	BUG_ON(maxlevelp == NULL);
	*maxlevelp = level - 1;
	return 0;

	/* error */
 out:
	while (--level > minlevel)
		nilfs_btree_abort_update_v(btree, path, level);
	if (!buffer_nilfs_volatile(path[level].bp_bh))
		nilfs_btree_abort_update_v(btree, path, level);
	return ret;
}

static void nilfs_btree_commit_propagate_v(struct nilfs_btree *btree,
					   struct nilfs_btree_path *path,
					   int minlevel,
					   int maxlevel,
					   struct buffer_head *bh)
{
	int level;

	if (!buffer_nilfs_volatile(path[minlevel].bp_bh))
		nilfs_btree_commit_update_v(btree, path, minlevel);

	for (level = minlevel + 1; level <= maxlevel; level++)
		nilfs_btree_commit_update_v(btree, path, level);
}

static int nilfs_btree_propagate_v(struct nilfs_btree *btree,
				   struct nilfs_btree_path *path,
				   int level,
				   struct buffer_head *bh)
{
	int maxlevel, ret;

	get_bh(bh);
	path[level].bp_bh = bh;
	ret = nilfs_btree_prepare_propagate_v(btree, path, level, &maxlevel);
	if (ret < 0)
		goto out;
	nilfs_btree_commit_propagate_v(btree, path, level, maxlevel, bh);

 out:
	brelse(path[level].bp_bh);
	path[level].bp_bh = NULL;
	return ret;
}

static int nilfs_btree_propagate(const struct nilfs_bmap *bmap,
				 struct buffer_head *bh)
{
	struct nilfs_btree *btree;
	struct nilfs_btree_path *path;
	struct nilfs_btree_node *node;
	nilfs_bmap_key_t key;
	int level, ret;

	BUG_ON(!buffer_dirty(bh));

	btree = (struct nilfs_btree *)bmap;
	path = nilfs_btree_alloc_path(btree);
	if (path == NULL)
		return -ENOMEM;
	nilfs_btree_init_path(btree, path);

	if (buffer_nilfs_node(bh)) {
		node = (struct nilfs_btree_node *)bh->b_data;
		key = nilfs_btree_node_get_key(btree, node, 0);
		level = nilfs_btree_node_get_level(btree, node);
	} else {
		key = nilfs_bmap_data_get_key(bmap, bh);
		level = NILFS_BTREE_LEVEL_DATA;
	}

	ret = nilfs_btree_do_lookup(btree, path, key, NULL, level + 1);
	if (ret < 0) {
		/* BUG_ON(ret == -ENOENT); */
		if (ret == -ENOENT) {
			printk(KERN_CRIT "%s: key = %llu, level == %d\n",
			       __func__, (unsigned long long)key, level);
			BUG();
		}
		goto out;
	}

	ret = (*btree->bt_ops->btop_propagate)(btree, path, level, bh);

 out:
	nilfs_btree_clear_path(btree, path);
	nilfs_btree_free_path(btree, path);

	return ret;
}

static int nilfs_btree_propagate_gc(const struct nilfs_bmap *bmap,
				    struct buffer_head *bh)
{
	return nilfs_bmap_mark_dirty(bmap, bh->b_blocknr);
}

static void nilfs_btree_add_dirty_buffer(struct nilfs_btree *btree,
					 struct list_head *lists,
					 struct buffer_head *bh)
{
	struct list_head *head;
	struct buffer_head *cbh;
	struct nilfs_btree_node *node, *cnode;
	nilfs_bmap_key_t key, ckey;
	int level;

	get_bh(bh);
	node = (struct nilfs_btree_node *)bh->b_data;
	key = nilfs_btree_node_get_key(btree, node, 0);
	level = nilfs_btree_node_get_level(btree, node);
	list_for_each(head, &lists[level]) {
		cbh = list_entry(head, struct buffer_head, b_assoc_buffers);
		cnode = (struct nilfs_btree_node *)cbh->b_data;
		ckey = nilfs_btree_node_get_key(btree, cnode, 0);
		if (key < ckey)
			break;
	}
	list_add_tail(&bh->b_assoc_buffers, head);
}

static void nilfs_btree_lookup_dirty_page_buffers(struct nilfs_btree *btree,
						  struct page *page,
						  struct list_head *lists)
{
	struct buffer_head *bh;

	bh = page_buffers(page);
	do {
		if (buffer_dirty(bh))
			nilfs_btree_add_dirty_buffer(btree, lists, bh);
		bh = bh->b_this_page;
	} while (bh != page_buffers(page));
}

#define NILFS_BTREE_GANG_LOOKUP_SIZE 16
static void
nilfs_btree_lookup_dirty_buffers_tag(struct nilfs_btree *btree,
				     struct nilfs_btnode_cache *btcache,
				     struct list_head *lists,
				     int tag)
{
	struct page *pages[NILFS_BTREE_GANG_LOOKUP_SIZE];
	nilfs_bmap_key_t index;
	int i, n;

	index = 0;
	n = nilfs_btnode_gang_lookup_tag_nolock(btcache, pages, index,
						NILFS_BTREE_GANG_LOOKUP_SIZE,
						tag);
	while (n > 0) {
		index = page_index(pages[n - 1]) + 1;
		for (i = 0; i < n; i++) {
			nilfs_btree_lookup_dirty_page_buffers(
				btree, pages[i], lists);
		}
		n = nilfs_btnode_gang_lookup_tag_nolock(
			btcache, pages, index,
			NILFS_BTREE_GANG_LOOKUP_SIZE, tag);
	}
}

static void nilfs_btree_lookup_dirty_buffers(struct nilfs_bmap *bmap,
					     struct list_head *listp)
{
	struct nilfs_btree *btree;
	struct nilfs_btnode_cache *btcache;
	struct list_head lists[NILFS_BTREE_LEVEL_MAX];
	int level;

	btree = (struct nilfs_btree *)bmap;
	for (level = NILFS_BTREE_LEVEL_NODE_MIN;
	     level < NILFS_BTREE_LEVEL_MAX;
	     level++)
		INIT_LIST_HEAD(&lists[level]);

	btcache = &NILFS_BMAP_I(bmap)->i_btnode_cache;
	nilfs_btnode_read_lock(btcache);
	nilfs_btree_lookup_dirty_buffers_tag(btree, btcache, lists,
					     PAGECACHE_TAG_DIRTY);
	nilfs_btree_lookup_dirty_buffers_tag(btree, btcache, lists,
					     NILFS_PAGECACHE_TAG_PDIRTY);
	nilfs_btnode_read_unlock(btcache);

	for (level = NILFS_BTREE_LEVEL_NODE_MIN;
	     level < NILFS_BTREE_LEVEL_MAX;
	     level++)
		list_splice(&lists[level], listp->prev);
}

static int nilfs_btree_assign_p(struct nilfs_btree *btree,
				struct nilfs_btree_path *path,
				int level,
				struct buffer_head **bh,
				sector_t blocknr,
				union nilfs_binfo *binfo)
{
	struct nilfs_btree_node *parent;
	nilfs_bmap_key_t key;
	nilfs_bmap_ptr_t ptr;
	int ret;

	parent = nilfs_btree_get_node(btree, path, level + 1);
	ptr = nilfs_btree_node_get_ptr(btree, parent,
				       path[level + 1].bp_index);
	if (buffer_nilfs_node(*bh)) {
		path[level].bp_ctxt.oldkey = ptr;
		path[level].bp_ctxt.newkey = blocknr;
		path[level].bp_ctxt.bh = *bh;
		ret = nilfs_btnode_prepare_change_key(
			&NILFS_BMAP_I(&btree->bt_bmap)->i_btnode_cache,
			&path[level].bp_ctxt);
		if (ret < 0)
			return ret;
		nilfs_btnode_commit_change_key(
			&NILFS_BMAP_I(&btree->bt_bmap)->i_btnode_cache,
			&path[level].bp_ctxt);
		*bh = path[level].bp_ctxt.bh;
	}

	nilfs_btree_node_set_ptr(btree, parent,
				 path[level + 1].bp_index, blocknr);

	key = nilfs_btree_node_get_key(btree, parent,
				       path[level + 1].bp_index);
	/* on-disk format */
	binfo->bi_dat.bi_blkoff = nilfs_bmap_key_to_dkey(key);
	binfo->bi_dat.bi_level = level;

	return 0;
}

static int nilfs_btree_assign_v(struct nilfs_btree *btree,
				struct nilfs_btree_path *path,
				int level,
				struct buffer_head **bh,
				sector_t blocknr,
				union nilfs_binfo *binfo)
{
	struct nilfs_btree_node *parent;
	nilfs_bmap_key_t key;
	nilfs_bmap_ptr_t ptr;
	union nilfs_bmap_ptr_req req;
	int ret;

	parent = nilfs_btree_get_node(btree, path, level + 1);
	ptr = nilfs_btree_node_get_ptr(btree, parent,
				       path[level + 1].bp_index);
	req.bpr_ptr = ptr;
	ret = (*btree->bt_bmap.b_pops->bpop_prepare_start_ptr)(&btree->bt_bmap,
							       &req);
	if (ret < 0)
		return ret;
	(*btree->bt_bmap.b_pops->bpop_commit_start_ptr)(&btree->bt_bmap,
							&req, blocknr);

	key = nilfs_btree_node_get_key(btree, parent,
				       path[level + 1].bp_index);
	/* on-disk format */
	binfo->bi_v.bi_vblocknr = nilfs_bmap_ptr_to_dptr(ptr);
	binfo->bi_v.bi_blkoff = nilfs_bmap_key_to_dkey(key);

	return 0;
}

static int nilfs_btree_assign(struct nilfs_bmap *bmap,
			      struct buffer_head **bh,
			      sector_t blocknr,
			      union nilfs_binfo *binfo)
{
	struct nilfs_btree *btree;
	struct nilfs_btree_path *path;
	struct nilfs_btree_node *node;
	nilfs_bmap_key_t key;
	int level, ret;

	btree = (struct nilfs_btree *)bmap;
	path = nilfs_btree_alloc_path(btree);
	if (path == NULL)
		return -ENOMEM;
	nilfs_btree_init_path(btree, path);

	if (buffer_nilfs_node(*bh)) {
		node = (struct nilfs_btree_node *)(*bh)->b_data;
		key = nilfs_btree_node_get_key(btree, node, 0);
		level = nilfs_btree_node_get_level(btree, node);
	} else {
		key = nilfs_bmap_data_get_key(bmap, *bh);
		level = NILFS_BTREE_LEVEL_DATA;
	}

	ret = nilfs_btree_do_lookup(btree, path, key, NULL, level + 1);
	if (ret < 0) {
		BUG_ON(ret == -ENOENT);
		goto out;
	}

	ret = (*btree->bt_ops->btop_assign)(btree, path, level, bh,
					    blocknr, binfo);

 out:
	nilfs_btree_clear_path(btree, path);
	nilfs_btree_free_path(btree, path);

	return ret;
}

static int nilfs_btree_assign_gc(struct nilfs_bmap *bmap,
				 struct buffer_head **bh,
				 sector_t blocknr,
				 union nilfs_binfo *binfo)
{
	struct nilfs_btree *btree;
	struct nilfs_btree_node *node;
	nilfs_bmap_key_t key;
	int ret;

	btree = (struct nilfs_btree *)bmap;
	ret = nilfs_bmap_move_v(bmap, (*bh)->b_blocknr, blocknr);
	if (ret < 0)
		return ret;

	if (buffer_nilfs_node(*bh)) {
		node = (struct nilfs_btree_node *)(*bh)->b_data;
		key = nilfs_btree_node_get_key(btree, node, 0);
	} else
		key = nilfs_bmap_data_get_key(bmap, *bh);

	/* on-disk format */
	binfo->bi_v.bi_vblocknr = cpu_to_le64((*bh)->b_blocknr);
	binfo->bi_v.bi_blkoff = nilfs_bmap_key_to_dkey(key);

	return 0;
}

static int nilfs_btree_mark(struct nilfs_bmap *bmap,
			    nilfs_bmap_key_t key,
			    int level)
{
	struct buffer_head *bh;
	struct nilfs_btree *btree;
	struct nilfs_btree_path *path;
	nilfs_bmap_ptr_t ptr;
	int ret;

	btree = (struct nilfs_btree *)bmap;
	path = nilfs_btree_alloc_path(btree);
	if (path == NULL)
		return -ENOMEM;
	nilfs_btree_init_path(btree, path);

	ret = nilfs_btree_do_lookup(btree, path, key, &ptr, level + 1);
	if (ret < 0) {
		BUG_ON(ret == -ENOENT);
		goto out;
	}
	ret = nilfs_bmap_get_block(&btree->bt_bmap, ptr, &bh);
	if (ret < 0) {
		BUG_ON(ret == -ENOENT);
		goto out;
	}

	if (!buffer_dirty(bh))
		nilfs_btnode_mark_dirty(bh);
	nilfs_bmap_put_block(&btree->bt_bmap, bh);
	if (!nilfs_bmap_dirty(&btree->bt_bmap))
		nilfs_bmap_set_dirty(&btree->bt_bmap);

 out:
	nilfs_btree_clear_path(btree, path);
	nilfs_btree_free_path(btree, path);
	return ret;
}


#ifdef CONFIG_NILFS_BMAP_DEBUG
/* preorder/postorder tree traverse */
static int nilfs_btree_traverse(const struct nilfs_btree *btree,
				int (*precb)(const struct nilfs_btree *,
					     const struct nilfs_btree_path *,
					     int),
				int (*postcb)(const struct nilfs_btree *,
					      const struct nilfs_btree_path *,
					      int))
{
	struct buffer_head *bh;
	struct nilfs_btree_path *path;
	struct nilfs_btree_node *node;
	nilfs_bmap_ptr_t ptr;
	int level, ret;

	if ((precb == NULL) && (postcb == NULL))
		/* do nothing */
		return 0;

	path = nilfs_btree_alloc_path(btree);
	if (path == NULL)
		return -ENOMEM;
	nilfs_btree_init_path(btree, path);

	ret = 0;
	node = NULL;
	level = nilfs_btree_height(btree) - 1;
	do {
		/* down */
		do {
			if (level < nilfs_btree_height(btree) - 1) {
				ptr = nilfs_btree_node_get_ptr(
					btree, node, path[level + 1].bp_index);
				ret = nilfs_bmap_get_block(&btree->bt_bmap,
							   ptr, &bh);
				if (ret < 0)
					goto out;
				node = (struct nilfs_btree_node *)bh->b_data;
			} else {
				bh = NULL;
				node = nilfs_btree_get_root(btree);
			}
			path[level].bp_bh = bh;
			path[level].bp_index = 0;
			/* preorder callback */
			if (precb != NULL) {
				ret = (*precb)(btree, path, level);
				if (ret < 0)
					goto out;
			}
		} while (level-- > NILFS_BTREE_LEVEL_NODE_MIN);

		/* up */
		level = NILFS_BTREE_LEVEL_NODE_MIN;
		do {
			node = nilfs_btree_get_node(btree, path, level);
			if ((level > NILFS_BTREE_LEVEL_NODE_MIN) &&
			    (++path[level].bp_index <
			     nilfs_btree_node_get_nchildren(btree, node))) {
				level--;
				break;
			}
			/* postorder callback */
			if (postcb != NULL) {
				ret = (*postcb)(btree, path, level);
				if (ret < 0)
					goto out;
			}
			if (level < nilfs_btree_height(btree) - 1) {
				nilfs_bmap_put_block(
					&btree->bt_bmap, path[level].bp_bh);
				path[level].bp_bh = NULL;
			}
		} while (++level <= nilfs_btree_height(btree) - 1);
	} while (level <= nilfs_btree_height(btree) - 1);

 out:
	nilfs_btree_clear_path(btree, path);
	nilfs_btree_free_path(btree, path);

	return ret;
}

static int nilfs_btree_verify_node(const struct nilfs_btree *btree,
				   const struct nilfs_btree_path *path,
				   int level)
{
	struct nilfs_btree_node *node, *parent, *root;
	nilfs_bmap_key_t pkey, nkey;
	int nchildren, i;

	node = nilfs_btree_get_node(btree, path, level);

	/* check level */
	if (level != nilfs_btree_node_get_level(btree, node)) {
		printk(KERN_ERR "%s: level %d must be %d\n",
		       __func__,
		       nilfs_btree_node_get_level(btree, node),
		       level);
		return -EINVAL;
	}

	/* check the number of children */
	nchildren = nilfs_btree_node_get_nchildren(btree, node);
	if ((level == nilfs_btree_height(btree) - 1) &&
	    (nchildren == 0))
		/* empty B-tree is valid */
		return 0;
	root = nilfs_btree_get_root(btree);
	if ((nchildren < nilfs_btree_node_nchildren_min(btree, node)) ||
	    (nchildren > nilfs_btree_node_nchildren_max(btree, node)))
		if (!((nilfs_btree_node_get_nchildren(btree, root) == 1) &&
		      (level == nilfs_btree_height(btree) - 2))) {
			printk(KERN_ERR
			       "%s: the number of children %d is invalid\n",
			       __func__, nchildren);
			return -EINVAL;
		}

	/* check the order of keys */
	pkey = nilfs_btree_node_get_key(btree, node, 0);
	for (i = 1; i < nchildren; i++) {
		nkey = nilfs_btree_node_get_key(btree, node, i);
		if (pkey >= nkey) {
			printk(KERN_ERR "%s: key order is invalid\n",
			       __func__);
			return -EINVAL;
		}
		pkey = nkey;
	}

	/* check the parent key */
	if (level < nilfs_btree_height(btree) - 1) {
		parent = nilfs_btree_get_node(btree, path, level + 1);
		if (nilfs_btree_node_get_key(btree, node, 0) !=
		    nilfs_btree_node_get_key(
			    btree, parent, path[level + 1].bp_index)) {
			printk(KERN_ERR
			       "%s: the first key of the node %llu must be "
			       "the same as the key of the parent %llu\n",
			       __func__,
			       (unsigned long long)nilfs_btree_node_get_key(
				       btree, node, 0),
			       (unsigned long long)nilfs_btree_node_get_key(
				       btree, parent,
				       path[level + 1].bp_index));
			return -EINVAL;
		}
	}

	/* check buffer state */
	if ((level < nilfs_btree_height(btree) - 1) &&
	    !buffer_dirty(path[level].bp_bh) &&
	    buffer_nilfs_volatile(path[level].bp_bh)) {
		/* volatile buffer must be dirty */
		printk(KERN_ERR
		       "%s: buffer head %p is volatile but not dirty\n",
		       __func__, path[level].bp_bh);
		return -EINVAL;
	}

	return 0;
}

static int nilfs_btree_verify(const struct nilfs_bmap *bmap)
{
	return nilfs_btree_traverse((const struct nilfs_btree *)bmap,
				    nilfs_btree_verify_node,
				    NULL);
}

#define NILFS_BTREE_PRINT_INDENT_FACTOR	2
static int nilfs_btree_print_node(const struct nilfs_btree *btree,
				  const struct nilfs_btree_path *path,
				  int level)
{
	struct nilfs_btree_node *node;
	int nchildren, indent, i;

	node = nilfs_btree_get_node(btree, path, level);
	nchildren = nilfs_btree_node_get_nchildren(btree, node);
	indent = (nilfs_btree_height(btree) - level - 1) *
		NILFS_BTREE_PRINT_INDENT_FACTOR;
	printk(KERN_DEBUG "%*slevel = %d nchildren = %d\n",
	       indent, "", level, nchildren);
	for (i = 0; i < nchildren; i++)
		printk(KERN_DEBUG "%*skey = %llu ptr = %llu\n", indent, "",
		       (unsigned long long)nilfs_btree_node_get_key(btree,
								    node, i),
		       (unsigned long long)nilfs_btree_node_get_ptr(btree,
								    node, i));
	return 0;
}

static int nilfs_btree_print(const struct nilfs_bmap *bmap)
{
	return nilfs_btree_traverse((const struct nilfs_btree *)bmap,
				    nilfs_btree_print_node,
				    NULL);
}
#endif	/* CONFIG_NILFS_BMAP_DEBUG */

static const struct nilfs_bmap_operations nilfs_btree_ops = {
	.bop_lookup		=	nilfs_btree_lookup,
	.bop_insert		=	nilfs_btree_insert,
	.bop_delete		=	nilfs_btree_delete,
	.bop_clear		=	NULL,

	.bop_propagate		=	nilfs_btree_propagate,

	.bop_lookup_dirty_buffers =	nilfs_btree_lookup_dirty_buffers,

	.bop_assign		=	nilfs_btree_assign,
	.bop_mark		=	nilfs_btree_mark,

	.bop_last_key		=	nilfs_btree_last_key,
	.bop_check_insert	=	NULL,
	.bop_check_delete	=	nilfs_btree_check_delete,
	.bop_gather_data	=	nilfs_btree_gather_data,

#ifdef CONFIG_NILFS_BMAP_DEBUG
	.bop_verify		=	nilfs_btree_verify,
	.bop_print		=	nilfs_btree_print,
#endif	/* CONFIG_NILFS_BMAP_DEBUG */
};

static const struct nilfs_bmap_operations nilfs_btree_ops_gc = {
	.bop_lookup		=	NULL,
	.bop_insert		=	NULL,
	.bop_delete		=	NULL,
	.bop_clear		=	NULL,

	.bop_propagate		=	nilfs_btree_propagate_gc,

	.bop_lookup_dirty_buffers =	nilfs_btree_lookup_dirty_buffers,

	.bop_assign		=	nilfs_btree_assign_gc,
	.bop_mark		=	NULL,

	.bop_last_key		=	NULL,
	.bop_check_insert	=	NULL,
	.bop_check_delete	=	NULL,
	.bop_gather_data	=	NULL,

#ifdef CONFIG_NILFS_BMAP_DEBUG
	.bop_verify		=	NULL,
	.bop_print		=	NULL,
#endif	/* CONFIG_NILFS_BMAP_DEBUG */
};

static const struct nilfs_btree_operations nilfs_btree_ops_v = {
	.btop_find_target	=	nilfs_btree_find_target_v,
	.btop_set_target	=	nilfs_btree_set_target_v,
	.btop_propagate		=	nilfs_btree_propagate_v,
	.btop_assign		=	nilfs_btree_assign_v,
};

static const struct nilfs_btree_operations nilfs_btree_ops_p = {
	.btop_find_target	=	NULL,
	.btop_set_target	=	NULL,
	.btop_propagate		=	nilfs_btree_propagate_p,
	.btop_assign		=	nilfs_btree_assign_p,
};

int nilfs_btree_init(struct nilfs_bmap *bmap,
		     nilfs_bmap_key_t low,
		     nilfs_bmap_key_t high)
{
	struct nilfs_btree *btree;

	btree = (struct nilfs_btree *)bmap;
	bmap->b_ops = &nilfs_btree_ops;
	bmap->b_low = low;
	bmap->b_high = high;
	switch (bmap->b_inode->i_ino) {
	case NILFS_DAT_INO:
		btree->bt_ops = &nilfs_btree_ops_p;
		break;
	default:
		btree->bt_ops = &nilfs_btree_ops_v;
		break;
	}

	return 0;
}

void nilfs_btree_init_gc(struct nilfs_bmap *bmap)
{
	bmap->b_low = NILFS_BMAP_LARGE_LOW;
	bmap->b_high = NILFS_BMAP_LARGE_HIGH;
	bmap->b_ops = &nilfs_btree_ops_gc;
}
