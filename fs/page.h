/*
 * page.h - buffer/page managemen for NILFS
 *
 * Copyright (C) 2005-2008 Nippon Telegraph and Telephone Corporation.
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
 *                       Ryusuke Konishi <ryusuke@osrg.net>,
 *			 Seiji Kihara <kihara@osrg.net>
 */

#ifndef _NILFS_PAGE_H
#define _NILFS_PAGE_H

#include "nilfs.h"
#include "kern_feature.h"

extern struct buffer_head *nilfs_bread_slow(struct buffer_head *);
extern struct buffer_head *nilfs_get_page_block(struct page *, unsigned long,
						pgoff_t, int);

extern void nilfs_pages_init(void);
extern void nilfs_pages_destroy(void);
extern void nilfs_pages_read_counters(unsigned long *);
extern void nilfs_pages_disable_shrinker(void);
extern void nilfs_pages_enable_shrinker(void);

#ifdef NILFS_SHRINKER_ENABLE
extern int nilfs_pages_shrink(int, GFP_T);
#endif
extern void nilfs_page_add_to_lru(struct page *, int);
extern void nilfs_page_delete_from_lru(struct page *);
extern void nilfs_page_mark_accessed(struct page *);
extern struct page *nilfs_alloc_buffer_page(struct block_device *, int,
					    unsigned long);
extern void nilfs_free_buffer_page(struct page *);
extern void nilfs_copy_buffer_page(struct page *, struct page *, int);
extern void nilfs_copy_buffer(struct buffer_head *, struct buffer_head *);

extern int nilfs_page_buffers_clean(struct page *);
extern unsigned nilfs_page_count_clean_buffers(struct page *, unsigned,
					       unsigned);
#if HAVE_CLEAR_PAGE_DIRTY
#define __nilfs_clear_page_dirty(page)  test_clear_page_dirty(page)
#else
extern int __nilfs_clear_page_dirty(struct page *);
#endif

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

static inline int nilfs_page_to_be_frozen(struct page *page)
{
	return buffer_nilfs_freeze(page_buffers(page));
}

static inline void nilfs_set_page_to_be_frozen(struct page *page)
{
	set_buffer_nilfs_freeze(page_buffers(page));
}

static inline void nilfs_clear_page_to_be_frozen(struct page *page)
{
	clear_buffer_nilfs_freeze(page_buffers(page));
}

static inline void nilfs_set_page_writeback(struct page *page)
{
	if (buffer_nilfs_allocated(page_buffers(page))) {
#if HAVE_SET_CLEAR_PAGE_WRITEBACK
		SetPageWriteback(page);
#else
		if (!TestSetPageWriteback(page))
			inc_zone_page_state(page, NR_WRITEBACK);
#endif
	} else
		set_page_writeback(page);
}

static inline void nilfs_end_page_writeback(struct page *page)
{
	if (buffer_nilfs_allocated(page_buffers(page))) {
#if HAVE_SET_CLEAR_PAGE_WRITEBACK
		ClearPageWriteback(page);
#else
		if (TestClearPageWriteback(page))
			dec_zone_page_state(page, NR_WRITEBACK);
#endif
	} else
		end_page_writeback(page);
}

/**
 * nilfs_clear_page_dirty - clear dirty bits on page and tag on radix-tree
 * @page: page to be cleared
 * @bits: integer to specify which dirty flag should be cleared:
 *	1 << PAGECACHE_TAG_DIRTY: dirty
 *	1 << NILFS_PAGECACHE_TAG_PDIRTY: prepare dirty
 */
static inline void nilfs_clear_page_dirty(struct page *page, int bits)
{
	/*
	 * Page index must be fixed before calling this function.
	 */
	if (buffer_nilfs_node(page_buffers(page)))
		nilfs_btnode_page_clear_dirty(page, bits);
	else
		__nilfs_clear_page_dirty(page);
}

/* buffer_busy copied from fs/buffer.c */
static inline int nilfs_buffer_busy(struct buffer_head *bh)
{
	return atomic_read(&bh->b_count) |
		(bh->b_state & ((1 << BH_Dirty) | (1 << BH_Lock)));
}

static inline int nilfs_page_buffers_busy(struct page *page)
{
	struct buffer_head *head, *bh;

	head = bh = page_buffers(page);
	do {
		if (nilfs_buffer_busy(bh))
			return 1;
		bh = bh->b_this_page;
	} while (bh != head);
	return 0;
}

#define nilfs_copy_buffer_state(dbh, sbh, mask)  \
	do { (dbh)->b_state = ((sbh)->b_state & (mask)); } while (0)


#endif /* _NILFS_PAGE_H */
