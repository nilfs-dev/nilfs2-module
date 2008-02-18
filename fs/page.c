/*
 * page.c - buffer/page management for NILFS
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
 * page.c,v 1.133 2008-02-06 13:50:47 ryusuke Exp
 *
 * Modified for NILFS by Amagai Yoshiji <amagai@osrg.net>,
 *                       Ryusuke Konishi <ryusuke@osrg.net>,
 *			 Seiji Kihara <kihara@osrg.net>.
 */
/*
 *  linux/fs/buffer.c
 *
 *  Copyright (C) 1991, 1992, 2002  Linus Torvalds
 */

#include <linux/pagemap.h>
#include <linux/writeback.h>
#include <linux/swap.h>
#include <linux/bitops.h>
#include <linux/page-flags.h>
#include <linux/list.h>
#include "nilfs.h"
#include "page.h"
#include "btnode.h"

struct buffer_head *nilfs_bread_slow(struct buffer_head *bh)
{
	lock_buffer(bh);
	if (buffer_uptodate(bh)) {
		unlock_buffer(bh);
		return bh;
	} else {
#ifdef CONFIG_NILFS_DEBUG
		char b[BDEVNAME_SIZE];
#endif

		get_bh(bh);
		page_debug(3, "try to read block (dev=%s, blocknr=%llu)\n",
			   bdevname(bh->b_bdev, b),
			   (unsigned long long)bh->b_blocknr);
		bh->b_end_io = end_buffer_read_sync;
		submit_bh(READ, bh);
		wait_on_buffer(bh);
		if (buffer_uptodate(bh))
			return bh;
	}
	brelse(bh);
	return NULL;
	/*
	 * __bread_slow() releases buffer count when it fails to read.
	 * The caller must not release buffer_head if NULL is returned.
	 * Note that an increment by get_bh() in __bread_slow() is consumed by
	 * the BIO submission.
	 */
}

/* end copied functions from fs/buffer.c */

struct buffer_head *
nilfs_get_page_block(struct page *page, nilfs_blkoff_t block, pgoff_t index,
		     int blkbits)

{
	nilfs_blkoff_t first_block;
	struct buffer_head *bh;

	BUG_ON(!PageLocked(page));

	if (!page_has_buffers(page)) {
		struct buffer_head *head;

		page_debug(3, "page has no buffer heads. allocating.. (page=%p)\n", page);
		head = alloc_page_buffers(page, 1 << blkbits, 1);
		if (!head)
			return NULL;
		nilfs_link_buffers(page, head);
	}

	first_block = (nilfs_blkoff_t)index << (PAGE_CACHE_SHIFT - blkbits);
	bh = nilfs_page_get_nth_block(page, block - first_block);

	touch_buffer(bh);
	wait_on_buffer(bh);
	return bh;
}

/*
 * low-level nilfs pages, page functions
 */
static struct nilfs_pages {
	spinlock_t		lru_lock;
	struct list_head	active;
	struct list_head	inactive;
	unsigned long		nr_active;
	unsigned long		nr_inactive;
	struct rw_semaphore	shrink_sem;
} nilfs_pages;

/*
 * XXX per-cpu pagevecs may be able to reduce the overhead of list handlings
 *
 * static DEFINE_PER_CPU(struct pagevec, nilfs_lru_active) = { 0, };
 * static DEFINE_PER_CPU(struct pagevec, nilfs_lru_inactive) = { 0, };
 */

void nilfs_pages_init(void)
{
	INIT_LIST_HEAD(&nilfs_pages.active);
	INIT_LIST_HEAD(&nilfs_pages.inactive);
	spin_lock_init(&nilfs_pages.lru_lock);
	init_rwsem(&nilfs_pages.shrink_sem);
	nilfs_pages.nr_active = 0;
	nilfs_pages.nr_inactive = 0;
}

void nilfs_pages_read_counters(unsigned long *counters)
{
	spin_lock(&nilfs_pages.lru_lock);
	counters[0] = nilfs_pages.nr_active;
	counters[1] = nilfs_pages.nr_inactive;
	spin_unlock(&nilfs_pages.lru_lock);
}

void nilfs_pages_disable_shrinker(void)
{
	down_read(&nilfs_pages.shrink_sem);
}

void nilfs_pages_enable_shrinker(void)
{
	up_read(&nilfs_pages.shrink_sem);
}

static void nilfs_free_page(struct page *page)
{
#ifdef CONFIG_NILFS_DEBUG
	/* Checks helpful for debugging purpose. */
	if (unlikely(!list_empty(&page->lru))) {
		PAGE_DEBUG(page, "page not isolated");
		BUG();
	}
	if (unlikely(page_count(page) != 1)) {
		PAGE_DEBUG(page, "wrong page count");
		BUG();
	}
	if (unlikely(PageDirty(page)))
		PAGE_DEBUG(page, "dirty page");
#endif
	unlock_page(page);
	__free_page(page);
}

static int nilfs_try_to_release_page(struct page *page)
{
	/* Since the page is allocated through nilfs_alloc_buffer_page(),
	   it always has buffer heads.  If not so, BUG. */
	if (buffer_nilfs_node(page_buffers(page)))
		return nilfs_btnode_invalidate_page(page, 0);
	return nilfs_page_buffers_busy(page);
}
	
static int nilfs_pages_free_lru(int active, int nr, int *nf)
{
	struct list_head *lru_list;
	spinlock_t *lock = &nilfs_pages.lru_lock;
	int n_freed = 0, n_scanned = 0;
	unsigned long *nr_lru;
	struct page *page, *next;
	LIST_HEAD(l_victim);

	lru_list = active ? &nilfs_pages.active : &nilfs_pages.inactive;
	nr_lru = active ? &nilfs_pages.nr_active : &nilfs_pages.nr_inactive;
	spin_lock(lock);
	if ((*nr_lru < nr) || (nr == 0))
		nr = *nr_lru;
	list_for_each_entry_safe(page, next, lru_list, lru) {
		if (nr == 0)
			break;
		nr--;
		n_scanned++;
		page_cache_get(page);
		if (TestSetPageLocked(page)) {
			page_debug(2, "Skipped(Locked) %p\n", page);
			goto keep_in_list;
		}
		if (PageWriteback(page) || PageDirty(page) ||
		    nilfs_btnode_page_referenced(page, 1)) {
			page_debug(2, "Skipped(Busy) %p\n", page);
			unlock_page(page);
			goto keep_in_list;
		}
		list_move_tail(&page->lru, &l_victim);
		continue;
	keep_in_list:
		page_cache_release(page);
	}
	spin_unlock(lock);
	list_for_each_entry_safe(page, next, &l_victim, lru) {
		if (nilfs_try_to_release_page(page)) {
			page_debug(2, "Skipped(BufsBusy) %p\n", page);
			continue;
		}
		list_del_init(&page->lru);
		n_freed++;
		if (unlikely(page_count(page) < 3))
			PAGE_DEBUG(page, "wrong page count");
		page_cache_release(page);
		__ClearPageActive(page); /* no need for atomic operation */
		ClearPageReferenced(page);
		page_debug(3, "freeing page %p\n", page);
		nilfs_free_buffer_page(page);
	}
	list_for_each_entry_safe(page, next, &l_victim, lru) {
		/*
		 * Although l_victim is a local list, each page in the list
		 * may be deleted by other task once it is unlocked and
		 * released.  Therefore we must separate these from the prior
		 * jobs and must use a safe version of loop macro.
		 */
		unlock_page(page);
		page_cache_release(page);
		/*
		 * next->lru.prev might be rewritten by the removal of the
		 * released page.  But we can barely continue the loop because
		 * next and next->lru.next is still safe.
		 */
	}
	spin_lock(lock);
	list_splice(&l_victim, lru_list);
	*nr_lru -= n_freed;
	spin_unlock(lock);
	if (nf)
		*nf = n_freed;
	return n_scanned;
}

void nilfs_pages_destroy(void)
{
	page_debug(3, "freeing inactive lru\n");
	nilfs_pages_free_lru(0 /* inactive */, 0, NULL);
	if (unlikely(nilfs_pages.nr_inactive)) {
		printk(KERN_WARNING
		       "NILFS warning: %ld pages remain on inactive list\n",
		       nilfs_pages.nr_inactive);
		nilfs_dump_page_lru(&nilfs_pages.inactive,
				    "leaking (inactive)");
	}
	page_debug(3, "freeing active lru\n");
	nilfs_pages_free_lru(1 /* active */, 0, NULL);
	if (unlikely(nilfs_pages.nr_active)) {
		printk(KERN_WARNING
		       "NILFS warning: %ld pages remain on active list\n",
		       nilfs_pages.nr_active);
		nilfs_dump_page_lru(&nilfs_pages.active, "leaking (active)");
	}
	/* BUG_ON(nilfs_pages.nr_active || nilfs_pages.nr_inactive); */
	page_debug(3, "finished.\n");
}

#ifdef NILFS_SHRINKER_ENABLE
int nilfs_pages_shrink(int nr, GFP_T gfp_mask)
{
	int ns, nfi = 0, nfa = 0;
	unsigned long nr_pages[2];

	nilfs_pages_read_counters(nr_pages);
	if (nr) {
		page_debug(2, "called with %d, a:i=%lu:%lu.\n",
			   nr, nr_pages[0], nr_pages[1]);

		if (down_write_trylock(&nilfs_pages.shrink_sem)) {
			ns = nilfs_pages_free_lru(0 /* inactive */, nr, &nfi);
			nr -= ns;
			if (nr > 0)
				ns += nilfs_pages_free_lru(1 /* active */, nr,
							   &nfa);
			up_write(&nilfs_pages.shrink_sem);
			/*
			 * XXX: must move pages from active to inactive for right PFRA.
			 */
			/* nilfs_pages_refill_inactive(nr + ns); */
			nilfs_pages_read_counters(nr_pages);
			page_debug(2, "%d scanned, %d+%d freed, "
				   "return %d(%lu+%lu).\n",
				   ns, nfa, nfi,
				   (int)(nr_pages[0] + nr_pages[1]),
				   nr_pages[0], nr_pages[1]);
		} else
			page_debug(2, "skipped by contention\n");
	}
	return nr_pages[0] + nr_pages[1];
}
#endif

void nilfs_page_add_to_lru(struct page *page, int active)
{
#ifdef CONFIG_NILFS_DEBUG
	BUG_ON(!list_empty(&page->lru));
#endif
	spin_lock(&nilfs_pages.lru_lock);
	page_cache_get(page);	/* LRU */
	if (active) {
		list_add_tail(&page->lru, &nilfs_pages.active);
		nilfs_pages.nr_active++;
		SetPageActive(page);
	} else {
		list_add_tail(&page->lru, &nilfs_pages.inactive);
		nilfs_pages.nr_inactive++;
	}
	spin_unlock(&nilfs_pages.lru_lock);
}

void nilfs_page_delete_from_lru(struct page *page)
{
#ifdef CONFIG_NILFS_DEBUG
	BUG_ON(list_empty(&page->lru));
	BUG_ON((page->lru.next == LIST_POISON1) ||
	       (page->lru.prev == LIST_POISON2));
#endif
	spin_lock(&nilfs_pages.lru_lock);
	list_del_init(&page->lru);
	if (PageActive(page)) {
		__ClearPageActive(page); /* Callers must ensure that no one
					    refers to this page. Otherwise,
					    page flags would be destroyed. */
		nilfs_pages.nr_active--;
	} else
		nilfs_pages.nr_inactive--;
	page_cache_release(page); /* LRU */
	spin_unlock(&nilfs_pages.lru_lock);
}

/* borrow from mm/swap.c::mark_page_accessed() and activate_page() */
void nilfs_page_mark_accessed(struct page *page)
{
	if (PageActive(page) && PageReferenced(page))
		return;
	lock_page(page);
	if (list_empty(&page->lru))
		goto out_unlock;
	if (!PageReferenced(page)) {
		SetPageReferenced(page);
		goto out_unlock;
	}
	spin_lock(&nilfs_pages.lru_lock);
	if (!PageActive(page)) {
		list_move_tail(&page->lru, &nilfs_pages.active);
		nilfs_pages.nr_inactive--;
		nilfs_pages.nr_active++;
		/* inc_page_state(pgactivate); */
		SetPageActive(page);
	}
	spin_unlock(&nilfs_pages.lru_lock);
	ClearPageReferenced(page);
out_unlock:
	unlock_page(page);
}

/**
 * nilfs_alloc_buffer_page - allocate a private page with buffer heads
 *
 * Return Value: On success, a pointer to the allocated page is returned.
 * On error, NULL is returned.
 */
struct page *nilfs_alloc_buffer_page(struct block_device *bdev, int size,
				     unsigned long state)
{
	struct buffer_head *bufs, *bh;
	struct page *page;

	page = alloc_page(GFP_NOFS); /* page_count of the returned page is 1 */
	if (unlikely(!page))
		return NULL;

#ifdef CONFIG_NILFS_DEBUG
	BUG_ON(PageLRU(page));
	BUG_ON(!list_empty(&page->lru) && (page->lru.next != LIST_POISON1) &&
	       (page->lru.prev != LIST_POISON2));
	BUG_ON(page->mapping);
#endif
	INIT_LIST_HEAD(&page->lru);

	lock_page(page);
	bufs = alloc_page_buffers(page, size, 0);
	if (unlikely(!bufs)) {
		nilfs_free_page(page);
		return NULL;
	}
	nilfs_link_buffers(page, bufs);
	bh = bufs;
	do {
		bh->b_state = (1UL << BH_NILFS_Allocated) | state;
		bh->b_bdev = bdev;	/* for a compatibility reason */
		bh = bh->b_this_page;
	} while (bh != bufs);

	return page;
}

/**
 * nilfs_try_to_free_buffer_page - try to free a private buffer page.
 * @page: page to be freed
 *
 * The page is freed only when it has no active buffers.
 * In that case, buffer heads attached to the page will be destroyed.
 */
void nilfs_free_buffer_page(struct page *page)
{
	BUG_ON(!PageLocked(page));
	if (page->mapping) {
		PAGE_DEBUG(page, "freeing page with mapping");
		BUG();
	}
	if (unlikely(!page_has_buffers(page)))
		PAGE_DEBUG(page, "freeing page without buffers");
	else if (!try_to_free_buffers(page)) {
		PAGE_DEBUG(page, "failed to free page");
		BUG();
	}
	nilfs_free_page(page);
}

/**
 * nilfs_copy_page -- copy page flags and data
 * @src: source page
 * @dst: destination page
 *
 * nilfs_copy_page() copies page contents and some page flags.
 * The uptodate flag and the mappedtodisk flag are copied to the @dst page.
 * The dirty flag must be copied separately by the caller, and the writeback
 * flag must be cleared.  The caller must lock both pages.
 */
static void nilfs_copy_page(struct page *src, struct page *dst)
{
	void *kaddr0, *kaddr1;

	kaddr0 = kmap_atomic(src, KM_USER0);
	kaddr1 = kmap_atomic(dst, KM_USER1);
	memcpy(kaddr1, kaddr0, PAGE_SIZE);
	kunmap_atomic(kaddr1, KM_USER1);
	kunmap_atomic(kaddr0, KM_USER0);

	BUG_ON(PageWriteback(dst));
	if (PageUptodate(src) && !PageUptodate(dst))
		SetPageUptodate(dst);
	else if (!PageUptodate(src) && PageUptodate(dst))
		ClearPageUptodate(dst);
	if (PageMappedToDisk(src) && !PageMappedToDisk(dst))
		SetPageMappedToDisk(dst);
	else if (!PageMappedToDisk(src) && PageMappedToDisk(dst))
		ClearPageMappedToDisk(dst);
}

/**
 * nilfs_copy_buffer -- copy buffer data and flags
 * @sbh: source buffer
 * @dbh: destination buffer
 */
void nilfs_copy_buffer(struct buffer_head *sbh, struct buffer_head *dbh)
{
	void *kaddr0, *kaddr1;
	unsigned long bits;
	struct page *spage = sbh->b_page, *dpage = dbh->b_page;
	struct buffer_head *bh;

	kaddr0 = kmap_atomic(spage, KM_USER0);
	kaddr1 = kmap_atomic(dpage, KM_USER1);
	memcpy(kaddr1 + bh_offset(dbh), kaddr0 + bh_offset(sbh), sbh->b_size);
	kunmap_atomic(kaddr1, KM_USER1);
	kunmap_atomic(kaddr0, KM_USER0);

	nilfs_copy_buffer_state(dbh, sbh, NILFS_BUFFER_INHERENT_BITS);

	dbh->b_blocknr = sbh->b_blocknr;
	dbh->b_bdev = sbh->b_bdev;

	bh = dbh;
	bits = sbh->b_state & ((1UL << BH_Uptodate) | (1UL << BH_Mapped));
	while ((bh = bh->b_this_page) != dbh) {
		lock_buffer(bh);
		bits &= bh->b_state;
		unlock_buffer(bh);
	}
	if (bits & (1UL << BH_Uptodate))
		SetPageUptodate(dpage);
	else
		ClearPageUptodate(dpage);
	if (bits & (1UL << BH_Mapped))
		SetPageMappedToDisk(dpage);
	else
		ClearPageMappedToDisk(dpage);
}

/**
 * nilfs_copy_buffer_page -- copy the page with buffers
 * @src: source page
 * @dst: destination page
 * @copy_dirty: flag whether to copy dirty states on the page's buffer heads.
 *
 * This fuction is for both data pages and btnode pages.  The dirty flag
 * should be treated by caller.  The page must not be under i/o.
 * Both src and dst page must be locked
 */
void nilfs_copy_buffer_page(struct page *src, struct page *dst, int copy_dirty)
{
	struct buffer_head *dbh, *dbufs, *sbh, *sbufs;
	unsigned long mask = NILFS_BUFFER_INHERENT_BITS;

	sbh = sbufs = page_buffers(src);
	if (!page_has_buffers(dst)) {
		dbufs = alloc_page_buffers(dst, sbh->b_size, 1);
		BUG_ON(!dbufs);
		nilfs_link_buffers(dst, dbufs);
	}

	if (copy_dirty)
		mask |= (1UL << BH_Dirty) | (1UL << BH_Prepare_Dirty);

	dbh = dbufs = page_buffers(dst);
	do {
		lock_buffer(sbh);
		lock_buffer(dbh);
		nilfs_copy_buffer_state(dbh, sbh, mask);
		dbh->b_blocknr = sbh->b_blocknr;
		/* dbh->b_size = sbh->b_size; */
		dbh->b_bdev = sbh->b_bdev;
		sbh = sbh->b_this_page;
		dbh = dbh->b_this_page;
	} while (dbh != dbufs);

	nilfs_copy_page(src, dst);

	do {
		unlock_buffer(sbh);
		unlock_buffer(dbh);
		sbh = sbh->b_this_page;
		dbh = dbh->b_this_page;
	} while (dbh != dbufs);
}

/**
 * nilfs_page_buffers_clean - check if a page has dirty buffers or not.
 * @page: page to be checked
 *
 * nilfs_page_buffers_clean() returns zero if the page has dirty buffers.
 * Otherwise, it returns non-zero value.
 * For the btnode page, the prepare-dirty state flag for written buffers
 * cleared here, and return values are:
 *	00(b): page state unchanged (remains dirty or prepare-dirty)
 *	01(b): page state will be changed from dirty to clean
 *	10(b): page state will be changed from prepare-dirty to dirty
 *	11(b): page state will be changed from prepare-dirty to clean
 */
int nilfs_page_buffers_clean(struct page *page)
{
	struct buffer_head *bh, *head;
	int d = 0, pd = 0, pc = 0;

	bh = head = page_buffers(page);
	do {
		int _d = buffer_dirty(bh), _p = buffer_prepare_dirty(bh);
		d |= _d;
		pd |= _p & _d;
		if (_p & !_d) {
			/* Note: buffer's prepare_dirty bit is cleared here */
			clear_buffer_prepare_dirty(bh);
			pc = 1;
		}
		bh = bh->b_this_page;
	} while (bh != head);
	return (!pd & pc) << NILFS_PAGECACHE_TAG_PDIRTY |
		!d << PAGECACHE_TAG_DIRTY;
}

unsigned nilfs_page_count_clean_buffers(struct page *page,
					unsigned from, unsigned to)
{
	unsigned block_start, block_end;
	struct buffer_head *bh, *head;
	unsigned nc = 0;

	for (bh = head = page_buffers(page), block_start = 0;
	     bh != head || !block_start;
	     block_start = block_end, bh = bh->b_this_page) {
		block_end = block_start + bh->b_size;
		if (block_end > from && block_start < to && !buffer_dirty(bh))
			nc++;
	}
	return nc;
}

#if !HAVE_CLEAR_PAGE_DIRTY
int __nilfs_clear_page_dirty(struct page *page)
{
	struct address_space *mapping = page->mapping;

	if (mapping) {
		WRITE_LOCK_IRQ(&mapping->tree_lock);
		if (test_bit(PG_dirty, &page->flags)) {
			radix_tree_tag_clear(&mapping->page_tree,
					     page_index(page),
					     PAGECACHE_TAG_DIRTY);
			WRITE_UNLOCK_IRQ(&mapping->tree_lock);
			return clear_page_dirty_for_io(page);
		}
		WRITE_UNLOCK_IRQ(&mapping->tree_lock);
		return 0;
	}
	return TestClearPageDirty(page);
}
#endif

/* Local Variables:		*/
/* eval: (c-set-style "linux")	*/
/* End:				*/
