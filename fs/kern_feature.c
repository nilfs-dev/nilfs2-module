/*
 * kern_feature.c - kernel features to support past versions
 *                  (would be removed in a future release)
 *
 * Copyright (C) 2007, 2008 Nippon Telegraph and Telephone Corporation.
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
 * Modified by Ryusuke Konishi <ryusuke@osrg.net>
 */
#include <linux/pagemap.h>
#include <linux/buffer_head.h>
#include "kern_feature.h"

/*
 * The following functions come from mm/filemap.c and mm/swap.c
 */
#if !HAVE_EXPORTED_PAGEVEC_LOOKUP
unsigned __nilfs_find_get_pages(struct address_space *mapping, pgoff_t start,
				unsigned int nr_pages, struct page **pages)
{
	unsigned int i;
	unsigned int ret;

	READ_LOCK_IRQ(&mapping->tree_lock);
	ret = radix_tree_gang_lookup(&mapping->page_tree, (void **)pages,
				     start, nr_pages);
	for (i = 0; i < ret; i++)
		page_cache_get(pages[i]);
	READ_UNLOCK_IRQ(&mapping->tree_lock);
	return ret;
}

unsigned
__nilfs_pagevec_lookup(struct pagevec *pvec, struct address_space *mapping,
		       pgoff_t start, unsigned nr_pages)
{
	pvec->nr = __nilfs_find_get_pages(mapping, start, nr_pages,
					  pvec->pages);
	return pagevec_count(pvec);
}
#endif

#if !HAVE_EXPORTED_PAGEVEC_LOOKUP_TAG
unsigned
__nilfs_find_get_pages_tag(struct address_space *mapping, pgoff_t *index,
			   int tag, unsigned int nr_pages,
			   struct page **pages)
{
	unsigned int i;
	unsigned int ret;

	READ_LOCK_IRQ(&mapping->tree_lock);
	ret = radix_tree_gang_lookup_tag(&mapping->page_tree, (void **)pages,
					 *index, nr_pages, tag);
	for (i = 0; i < ret; i++)
		page_cache_get(pages[i]);
	if (ret)
		*index = pages[ret - 1]->index + 1;
	READ_UNLOCK_IRQ(&mapping->tree_lock);
	return ret;
}

unsigned
__nilfs_pagevec_lookup_tag(struct pagevec *pvec, struct address_space *mapping,
			   pgoff_t *index, int tag, unsigned nr_pages)
{
	pvec->nr = __nilfs_find_get_pages_tag(mapping, index, tag, nr_pages,
					      pvec->pages);
	return pagevec_count(pvec);
}

void __nilfs_pagevec_release(struct pagevec *pvec)
{
	int i;

	for (i = 0; i < pagevec_count(pvec); i++)
		page_cache_release(pvec->pages[i]);

	pagevec_reinit(pvec);
}
#endif
