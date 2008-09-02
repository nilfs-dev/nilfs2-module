/*
 * btnode.h - NILFS BT-Node prototypes and definitions
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
 * Written by Seiji Kihara <kihara@osrg.net>
 */

#ifndef _NILFS_BTNODE_H
#define _NILFS_BTNODE_H

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <linux/spinlock.h>
#include <linux/radix-tree.h>

#include "kern_feature.h"
#include "debug.h"

struct nilfs_btnode_cache {
	struct radix_tree_root page_tree;
	rwlock_t tree_lock;
};

struct nilfs_btnode_chkey_ctxt {
	__u64 oldkey;
	__u64 newkey;
	struct buffer_head *bh;
	struct buffer_head *newbh;
};

static inline void
nilfs_btnode_cache_init_once(struct nilfs_btnode_cache *btnc)
{
	INIT_RADIX_TREE(&btnc->page_tree, GFP_ATOMIC);
	rwlock_init(&btnc->tree_lock);
}

void nilfs_btnode_cache_clear(struct nilfs_btnode_cache *);

int nilfs_btnode_submit_block(struct nilfs_btnode_cache *, __u64, sector_t,
			      struct buffer_head **, int);
int nilfs_btnode_get(struct nilfs_btnode_cache *, __u64, sector_t,
		     struct buffer_head **, int);
void nilfs_btnode_delete(struct buffer_head *);

#define nilfs_btnode_read_lock(btnc)	read_lock(&(btnc)->tree_lock)
#define nilfs_btnode_read_unlock(btnc)	read_unlock(&(btnc)->tree_lock)
#define nilfs_btnode_write_lock(btnc)	write_lock(&(btnc)->tree_lock)
#define nilfs_btnode_write_unlock(btnc)	write_unlock(&(btnc)->tree_lock)

static inline int nilfs_btnode_page_referenced(struct page *p, int ref)
{
	return page_count(p) - ref >
		!!p->mapping + page_has_buffers(p) + !list_empty(&p->lru);
}

static inline unsigned
nilfs_btnode_gang_lookup_nolock(struct nilfs_btnode_cache *btnc,
				struct page **pages, unsigned long index,
				int size)
{
	return radix_tree_gang_lookup(&btnc->page_tree, (void **)pages, index,
				      size);
}

static inline unsigned
nilfs_btnode_gang_lookup_tag_nolock(struct nilfs_btnode_cache *btnc,
				    struct page **pages, unsigned long index,
				    int size, int tag)
{
	return radix_tree_gang_lookup_tag(&btnc->page_tree, (void **)pages,
					  index, size, tag);
}

unsigned nilfs_btnode_find_get_pages(struct nilfs_btnode_cache *,
				     struct page **, pgoff_t *, unsigned int);
unsigned nilfs_btnode_find_get_pages_tag(struct nilfs_btnode_cache *,
					 struct page **, pgoff_t *,
					 unsigned int, int);
void nilfs_btnode_mark_dirty(struct buffer_head *);
void nilfs_btnode_set_page_dirty(struct page *);
void nilfs_btnode_page_clear_dirty(struct page *);
int nilfs_btnode_invalidate_page(struct page *, int);
int nilfs_btnode_prepare_change_key(struct nilfs_btnode_cache *,
				    struct nilfs_btnode_chkey_ctxt *);
void nilfs_btnode_commit_change_key(struct nilfs_btnode_cache *,
				    struct nilfs_btnode_chkey_ctxt *);
void nilfs_btnode_abort_change_key(struct nilfs_btnode_cache *,
				   struct nilfs_btnode_chkey_ctxt *);
int nilfs_btnode_copy_dirty_pages(struct nilfs_btnode_cache *,
				  struct nilfs_btnode_cache *);
void nilfs_btnode_clear_dirty_pages(struct nilfs_btnode_cache *);
void nilfs_btnode_copy_cache(struct nilfs_btnode_cache *,
			     struct nilfs_btnode_cache *);

#endif	/* _NILFS_BTNODE_H */
