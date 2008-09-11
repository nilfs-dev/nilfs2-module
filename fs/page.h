/*
 * page.h - buffer/page management specific to NILFS
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
 * Written by Ryusuke Konishi <ryusuke@osrg.net>,
 *            Seiji Kihara <kihara@osrg.net>.
 */

#ifndef _NILFS_PAGE_H
#define _NILFS_PAGE_H

#include <linux/buffer_head.h>
#include "nilfs.h"
#include "kern_feature.h"

/*
 * Extended buffer state bits
 */
enum {
	BH_NILFS_Allocated = BH_PrivateStart,
	BH_NILFS_Node,
	BH_NILFS_Volatile,
};

BUFFER_FNS(NILFS_Allocated, nilfs_allocated)	/* nilfs private buffers */
BUFFER_FNS(NILFS_Node, nilfs_node)		/* nilfs node buffers */
BUFFER_FNS(NILFS_Volatile, nilfs_volatile)


#if NEED_OLD_MARK_BUFFER_DIRTY
void nilfs_mark_buffer_dirty(struct buffer_head *bh);
#else
#define nilfs_mark_buffer_dirty(bh)	mark_buffer_dirty(bh)
#endif

#if HAVE_CLEAR_PAGE_DIRTY
#define __nilfs_clear_page_dirty(page)  test_clear_page_dirty(page)
#else
extern int __nilfs_clear_page_dirty(struct page *);
#endif

struct buffer_head *nilfs_grab_buffer(struct inode *, struct address_space *,
				      unsigned long, unsigned long);
void nilfs_forget_buffer(struct buffer_head *);
void nilfs_copy_buffer(struct buffer_head *, struct buffer_head *);
int nilfs_page_buffers_clean(struct page *);
void nilfs_page_bug(struct page *);
struct page *nilfs_alloc_private_page(struct block_device *, int,
				      unsigned long);
void nilfs_free_private_page(struct page *);

int nilfs_copy_dirty_pages(struct address_space *, struct address_space *);
void nilfs_copy_back_pages(struct address_space *, struct address_space *);
void nilfs_clear_dirty_pages(struct address_space *);
unsigned nilfs_page_count_clean_buffers(struct page *, unsigned, unsigned);

static inline struct buffer_head *
nilfs_page_get_nth_block(struct page *page, unsigned int count)
{
	struct buffer_head *head = page_buffers(page), *bh = head;

	while (count > 0) {
		bh = bh->b_this_page;  --count;
#ifdef CONFIG_NILFS_DEBUG
		BUG_ON(bh == head);
#endif
	}
	get_bh(bh);
	return bh;
}

#endif /* _NILFS_PAGE_H */
