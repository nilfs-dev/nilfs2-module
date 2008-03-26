/*
 * gcdat.c - NILFS shadow DAT inode for GC
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
#include "nilfs.h"
#include "page.h"
#include "mdt.h"

#define	GCDAT_N_PAGEVEC	16


static int nilfs_gcdat_copy_dirty_data(struct address_space *src,
				       struct address_space *dst)
{
	struct page *pages[GCDAT_N_PAGEVEC];
	unsigned int i, n;
	pgoff_t index = 0;
	int err;

repeat:
	n = find_get_pages_tag(src, &index, PAGECACHE_TAG_DIRTY,
			       GCDAT_N_PAGEVEC, pages);
	if (!n)
		return 0;

	for (i = 0; i < n; i++) {
		struct page *page = pages[i], *dpage;

		lock_page(page);
		if (unlikely(!PageDirty(page)))
			PAGE_BUG(page, "inconsistent dirty state");

		dpage = grab_cache_page(dst, page->index);
		if (unlikely(!dpage)) {
			/* No empty page is added to the page cache */
			err = -ENOMEM;
			unlock_page(page);
			goto failed;
		}
		if (unlikely(!page_has_buffers(page)))
			PAGE_BUG(page, "found empty page in dat page cache");

		nilfs_copy_buffer_page(page, dpage, 1);
		__set_page_dirty_nobuffers(dpage);

		unlock_page(dpage);
		page_cache_release(dpage);
		unlock_page(page);
		page_cache_release(page);
	}
	goto repeat;
 failed:
	while (i < n)
		page_cache_release(pages[i++]);
	return err;
}

static void nilfs_gcdat_clear_dirty_data(struct address_space *mapping)
{
	struct page *pages[GCDAT_N_PAGEVEC];
	unsigned int i, n;
	pgoff_t index = 0;

repeat:
	n = find_get_pages_tag(mapping, &index, PAGECACHE_TAG_DIRTY,
			       GCDAT_N_PAGEVEC, pages);
	if (!n)
		return;

	for (i = 0; i < n; i++) {
		struct page *page = pages[i];
		struct buffer_head *bh, *head;

		lock_page(page);
		ClearPageUptodate(page);
		bh = head = page_buffers(page);
		do {
			lock_buffer(bh);
			clear_buffer_dirty(bh);
			clear_buffer_nilfs_volatile(bh);
			clear_buffer_uptodate(bh);
			clear_buffer_mapped(bh);
			unlock_buffer(bh);
			bh = bh->b_this_page;
		} while (bh != head);
		__nilfs_clear_page_dirty(page);
		unlock_page(page);
		page_cache_release(page);
	}
	goto repeat;
}

static void nilfs_gcdat_copy_mapping(struct address_space *gmapping,
				     struct address_space *mapping)
{
	struct page *pages[GCDAT_N_PAGEVEC];
	unsigned int i, n;
	pgoff_t index = 0;

repeat:
	n = find_get_pages(gmapping, index, GCDAT_N_PAGEVEC, pages);
	if (!n)
		return;
	index = pages[n - 1]->index + 1;
	/* note: mdt dirty flags should be cleared by segctor. */

	for (i = 0; i < n; i++) {
		struct page *page = pages[i], *dpage;
		pgoff_t offset = page->index;

		lock_page(page);
		dpage = find_lock_page(mapping, offset);
		if (dpage) {
			/* XXX skip if identical */
			BUG_ON(PageDirty(dpage));
			nilfs_copy_buffer_page(page, dpage, 0);
			unlock_page(dpage);
			page_cache_release(dpage);
#if 1 /* 0 for debug, withdrawn pages only in gcdat cache */
		} else {
			int err;

			/* move page from gcdat to dat cache */
			WRITE_LOCK_IRQ(&gmapping->tree_lock);
			radix_tree_delete(&gmapping->page_tree, offset);
			gmapping->nrpages--;
			WRITE_UNLOCK_IRQ(&gmapping->tree_lock);
			WRITE_LOCK_IRQ(&mapping->tree_lock);
			err = radix_tree_insert(&mapping->page_tree, offset,
						page);
			if (unlikely(err < 0)) {
				/* No pages must no be added to the cache
				   during commiting gcdat.  This is ensured by
				   the dat mi_sem and nilfs->ns_segctor_sem */
				BUG_ON(err == -EEXIST);
				 /* XXX: -ENOMEM */
				PAGE_DEBUG(page, "failed to move page");
				page->mapping = NULL;
				page_cache_release(page); /* for cache */
				goto skip_unlock;
			}
			page->mapping = mapping;
			mapping->nrpages++;
			if (PageDirty(page))
				radix_tree_tag_set(&mapping->page_tree, offset,
						   PAGECACHE_TAG_DIRTY);
skip_unlock:
			WRITE_UNLOCK_IRQ(&mapping->tree_lock);
#endif
		}
		unlock_page(page);
		page_cache_release(page);
	}
	goto repeat;
}

int nilfs_init_gcdat_inode(struct the_nilfs *nilfs)
{
	struct inode *dat = nilfs->ns_dat, *gcdat = nilfs->ns_gc_dat;
	struct nilfs_inode_info *dii = NILFS_I(dat), *gii = NILFS_I(gcdat);
	int err;

	gcdat->i_state = 0;
	gii->i_flags = dii->i_flags;
	gii->i_state = dii->i_state | (1 << NILFS_I_GCDAT);
	gii->i_cno = 0;
	nilfs_bmap_init_gcdat(gii->i_bmap, dii->i_bmap);
	err = nilfs_gcdat_copy_dirty_data(dat->i_mapping, gcdat->i_mapping);
	if (unlikely(err))
		return err;
	NILFS_CHECK_BTNODE_CACHE(&gii->i_btnode_cache, -1);
	err = nilfs_btnode_copy_dirty_pages(&dii->i_btnode_cache,
					    &gii->i_btnode_cache);
	return err;
}

void nilfs_commit_gcdat_inode(struct the_nilfs *nilfs)
{
	struct inode *dat = nilfs->ns_dat, *gcdat = nilfs->ns_gc_dat;
	struct nilfs_inode_info *dii = NILFS_I(dat), *gii = NILFS_I(gcdat);
	struct address_space *mapping = dat->i_mapping;
	struct address_space *gmapping = gcdat->i_mapping;

	down_write(&NILFS_MDT(dat)->mi_sem);
	dii->i_flags = gii->i_flags;
	dii->i_state = gii->i_state & ~(1 << NILFS_I_GCDAT);

	nilfs_bmap_commit_gcdat(gii->i_bmap, dii->i_bmap);

	nilfs_gcdat_clear_dirty_data(mapping);
	nilfs_gcdat_copy_mapping(gmapping, mapping);

	nilfs_btnode_clear_dirty_pages(&dii->i_btnode_cache);
	nilfs_btnode_copy_cache(&gii->i_btnode_cache, &dii->i_btnode_cache);
	up_write(&NILFS_MDT(dat)->mi_sem);
}

void nilfs_clear_gcdat_inode(struct the_nilfs *nilfs)
{
	struct inode *gcdat = nilfs->ns_gc_dat;
	struct nilfs_inode_info *gii = NILFS_I(gcdat);

	gcdat->i_state = I_CLEAR;
	gii->i_flags = 0;
	truncate_inode_pages(gcdat->i_mapping, 0);
	NILFS_CHECK_PAGE_CACHE(gcdat->i_mapping, -1);
	nilfs_btnode_cache_clear(&gii->i_btnode_cache);
}
