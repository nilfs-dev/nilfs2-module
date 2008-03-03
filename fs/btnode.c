/*
 * btnode.c - NILFS B-tree node block
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
 * Written by Seiji Kihara <kihara@osrg.net>
 * Revised by Ryusuke Konishi <ryusuke@osrg.net>
 */

#include <linux/types.h>
#include <linux/list.h>
#include "nilfs.h"
#include "mdt.h"
#include "page.h"
#include "btnode.h"


#define NILFS_BTNODE_GANG_SIZE	16	/* Array size for gang lookups */
#define NILFS_BTNODE_CLEAN_BH_STATE \
	((1 << BH_NILFS_Node) | (1 << BH_NILFS_Allocated))

/*
 * Expediential macros
 *
 * - B2P: block to page_index
 * - B2O: block to offset in the page
 */
#define B2P(blocknr, inode) \
	(unsigned long)((blocknr) >> (PAGE_CACHE_SHIFT - (inode)->i_blkbits))
#define B2O(blocknr, inode) \
	((unsigned int)((blocknr) & \
			((1UL << (PAGE_CACHE_SHIFT - (inode)->i_blkbits)) - 1)))

static inline struct nilfs_btnode_cache *PAGE_BTNC(struct page *page)
{
	struct inode *inode =
		container_of(page->mapping, struct inode, i_data);
	return &NILFS_I(inode)->i_btnode_cache;
}

static inline struct inode *BTNC_I(struct nilfs_btnode_cache *btnc)
{
	struct nilfs_inode_info *ii =
		container_of(btnc, struct nilfs_inode_info, i_btnode_cache);
	return &ii->vfs_inode;
}

unsigned nilfs_btnode_find_get_pages(struct nilfs_btnode_cache *btnc,
				     struct page **pages, pgoff_t *index,
				     unsigned int nr_pages)
{
	unsigned int i, res;

	nilfs_btnode_read_lock(btnc);
	res = nilfs_btnode_gang_lookup_nolock(btnc, pages, *index, nr_pages);
	for (i = 0; i < res; i++)
		page_cache_get(pages[i]);
	if (res)
		*index = pages[res - 1]->index + 1;
	nilfs_btnode_read_unlock(btnc);
	return res;
}

unsigned nilfs_btnode_find_get_pages_tag(struct nilfs_btnode_cache *btnc,
					 struct page **pages, pgoff_t *index,
					 unsigned int nr_pages, int tag)
{
	unsigned int i, res;

	nilfs_btnode_read_lock(btnc);
	res = nilfs_btnode_gang_lookup_tag_nolock(btnc, pages, *index,
						  nr_pages, tag);
	for (i = 0; i < res; i++)
		page_cache_get(pages[i]);
	if (res)
		*index = pages[res - 1]->index + 1;
	nilfs_btnode_read_unlock(btnc);
	return res;
}

/* borrowed from mm/filemap.c::find_get_page */
static struct page *nilfs_btnode_find_get_page(struct nilfs_btnode_cache *btnc,
					       unsigned long index)
{
	struct page *page;

	/* btnode_debug(3, "btnc=%p idx=%lu\n", btnc, index); */
	nilfs_btnode_read_lock(btnc);
	page = radix_tree_lookup(&btnc->page_tree, index);
	if (page)
		page_cache_get(page);
	BUG_ON(page && !page_has_buffers(page));
	nilfs_btnode_read_unlock(btnc);
	return page;
}

static inline struct page *
nilfs_btnode_alloc_page(struct nilfs_btnode_cache *btnc)
{
	struct inode *inode = BTNC_I(btnc);
	return nilfs_alloc_buffer_page(NILFS_I_NILFS(inode)->ns_bdev,
				       1UL << inode->i_blkbits,
				       1UL << BH_NILFS_Node);
}

static int
nilfs_btnode_page_add_cache(struct page *page, struct nilfs_btnode_cache *btnc,
			    unsigned long index)
{
	int err;

#if HAVE_EXPORTED_RADIX_TREE_PRELOAD
	/*
	 * We cannot call radix_tree_preload for the kernels older than 2.6.23,
	 * because it is not exported for modules.
	 */
	err = radix_tree_preload(GFP_NOFS & ~__GFP_HIGHMEM);
	if (unlikely(err))
		return err;
#endif
	nilfs_btnode_write_lock(btnc);
	err = radix_tree_insert(&btnc->page_tree, index, page);
	if (likely(!err)) {
		page_cache_get(page);	/* for radix-tree */
		page->index = index;
		page->mapping = BTNC_I(btnc)->i_mapping;
	}
	nilfs_btnode_write_unlock(btnc);
#if HAVE_EXPORTED_RADIX_TREE_PRELOAD
	radix_tree_preload_end();
#endif
	return err;
}

static struct nilfs_btnode_cache *
nilfs_btnode_altbc(struct nilfs_btnode_cache *btnc)
{
	struct inode *orig_inode = NILFS_ORIG_I(BTNC_I(btnc));

	return orig_inode ? &NILFS_I(orig_inode)->i_btnode_cache : NULL;
}

/* some codes borrowed from mm/filemap.c::read_cache_page() */
static int nilfs_btnode_get_page(struct nilfs_btnode_cache *btnc,
				 unsigned long index,
				 struct page **res, int try_altbc)
{
	struct page *page, *cached_page = NULL;
	struct nilfs_btnode_cache *altbc;
	int err = 0;

repeat:
	page = nilfs_btnode_find_get_page(btnc, index);
	if (!page) {
		if (!cached_page) {
			cached_page = nilfs_btnode_alloc_page(btnc);
			if (unlikely(!cached_page)) {
				btnode_debug(2,
					     "failed to alloc btnode page\n");
				return -ENOMEM;
			}
		}
		err = nilfs_btnode_page_add_cache(cached_page, btnc, index);
		if (unlikely(err)) {
			if (err == -EEXIST)
				goto repeat;
			btnode_debug(2, "nilfs_btnode_page_add_cache() failed "
				     "(err=%d, index=%llu)\n", err,
				     (unsigned long long)index);
			goto out_free;
		}
		page = cached_page;
		cached_page = NULL;
		nilfs_page_add_to_lru(page, 0);

		if (try_altbc) {
			altbc = nilfs_btnode_altbc(btnc);
			if (altbc != NULL) {
				struct page *opage =
					nilfs_btnode_find_get_page(altbc,
								   index);
				if (opage) {
					btnode_debug(3, "got orig dat page %p "
						     "for index %lu\n",
						     opage, index);
					lock_page(opage);
					/*
					 * dirty or pdirty pages do not appear
					 * here.
					 */
					BUG_ON(PageDirty(opage));
					nilfs_copy_buffer_page(opage, page, 0);
					unlock_page(opage);
					page_cache_release(opage);
				}
			}
		}
		/* pass page_count from btnode_alloc_page to caller */
		unlock_page(page);
	}
out_free:
	/*
	 * maybe -ENOMEM occured at radix_tree_insert() if cached_page remains.
	 * it is not in the inactive list in this case.
	 */
	if (cached_page)
		nilfs_free_buffer_page(cached_page);

	if (likely(page)) {
		nilfs_page_mark_accessed(page);
		*res = page;
		err = 0;
		if (unlikely(!nilfs_btnode_page_referenced(page, 0))) {
			PAGE_DEBUG(page, "page not referred");
			BUG();
		}
	}
	return err;
}

/* page must be locked by caller */
int __nilfs_btnode_get(struct nilfs_btnode_cache *btnc, __u64 blocknr,
		       sector_t pblocknr, struct buffer_head **result,
		       int newblk)
{
	struct page *page = NULL;
	struct buffer_head *bh = NULL;
	struct inode *inode = BTNC_I(btnc);
	int err;

	err = nilfs_btnode_get_page(btnc, B2P(blocknr, inode), &page, 1);
	if (unlikely(err)) {	/* -ENOMEM */
		btnode_debug(2, "return %d (get_page).\n", err);
		goto out_nopage;
	}
	lock_page(page);

	bh = nilfs_page_get_nth_block(page, B2O(blocknr, inode));

	if (newblk) {
		if (unlikely(buffer_mapped(bh) || buffer_uptodate(bh) ||
			     buffer_dirty(bh))) {
			BH_DEBUG(bh, "invalid new bh");
			brelse(bh);
			BUG();
		}
		bh->b_blocknr = blocknr;
		set_buffer_mapped(bh);
		set_buffer_uptodate(bh);
		/* btnode_debug(3, "return 0 for new bh.\n"); */
		goto found;
	}

	if (buffer_uptodate(bh) || buffer_dirty(bh)) {
		/* btnode_debug(3, "return 0 for valid bh.\n"); */
		goto found;
	}

	if (pblocknr == 0) {
		pblocknr = blocknr;
		if (inode->i_ino != NILFS_DAT_INO) {
			struct inode *dat =
				nilfs_dat_inode(NILFS_I_NILFS(inode));

			/* blocknr is a Virtual BN */
			err = nilfs_dat_translate(dat, blocknr, &pblocknr);
			if (unlikely(err)) {
				brelse(bh);
				btnode_debug(1, "return %d (xlate).\n", err);
				goto out_locked;
			}
		}
	}
	bh->b_blocknr = pblocknr; /* set block address for read */
	set_buffer_mapped(bh);
	bh = nilfs_bread_slow(bh);

	if (unlikely(bh == NULL)) {
		btnode_debug(1, "return -EIO.\n");
		err = -EIO;
		goto out_locked;
	}
	bh->b_blocknr = blocknr; /* set back to the given block address */
	btnode_debug(3, "return 0.\n");
found:
	*result = bh;
	err = 0;
out_locked:
	unlock_page(page);
	page_cache_release(page);	/* from nilfs_btnode_get_page() */
out_nopage:
	return err;
}

static void __nilfs_btnode_set_page_dirty(struct nilfs_btnode_cache *btnc,
					  struct page *page, int tag,
					  int upgrade_tag)
{
	if (!TestSetPageDirty(page)) {
		/* set page-dirty or page-pdirty for a clean page */
		nilfs_btnode_write_lock(btnc);
		radix_tree_tag_set(&btnc->page_tree, page->index, tag);
		nilfs_btnode_write_unlock(btnc);
	} else if (upgrade_tag) {
		/* upgrade page dirty state from page-dirty to page-pdirty */
		nilfs_btnode_write_lock(btnc);
		radix_tree_tag_clear(&btnc->page_tree, page->index,
				     NILFS_PAGECACHE_TAG_PDIRTY);
		radix_tree_tag_set(&btnc->page_tree, page->index,
				   PAGECACHE_TAG_DIRTY);
		nilfs_btnode_write_unlock(btnc);
	}
}

/**
 * __nilfs_btnode_mark_dirty() - mark buffer dirty and set page state
 * @bh: buffer head
 * @tag: dirty state to be set
 *
 * The caller must check state of buffer head @bh previously.  Although
 * the page dirty state is automatically upgraded from pdirty to dirty,
 * the transition from buffer-pdirty to buffer-dirty is *not* supported.
 *
 * To set buffer-dirty, the caller must confirm @bh is not dirty.
 * To set buffer-pdirty, @bh must not be dirty nor pdirty.
 */
void __nilfs_btnode_mark_dirty(struct buffer_head *bh, int tag)
{
	struct buffer_head *b;
	struct page *page = bh->b_page;
	struct nilfs_btnode_cache *btnc;
	int upgrade_tag = 0;

	lock_page(page);
	if (test_set_buffer_dirty(bh))
		goto out_unlock;
	btnode_debug(3, "marked dirty on bh %p (tag=%d)\n", bh, tag);
	if (tag == NILFS_PAGECACHE_TAG_PDIRTY &&
	    test_set_buffer_prepare_dirty(bh))
		goto out_unlock;

	if (tag == PAGECACHE_TAG_DIRTY && PageDirty(page)) {
		/* check whether the rest of the buffers are not dirty */
		b = bh;
		while ((b = b->b_this_page) != bh)
			if (nilfs_btnode_buffer_dirty(b))
				goto found_dirty_buffer;
		upgrade_tag = 1;
	}

 found_dirty_buffer:
	btnc = PAGE_BTNC(page);
	__nilfs_btnode_set_page_dirty(btnc, page, tag, upgrade_tag);

 out_unlock:
	unlock_page(page);
}

/**
 * nilfs_btnode_page_clear_dirty - clear dirty bits on page and tag on radix-tree
 * @page: page to be cleared
 * @bits: bitmap to specify which dirty flag should be cleared:
 *	00(b): page state unchanged (remains dirty or prepare-dirty)
 *	01(b): page state will be changed from dirty to clean
 *	10(b): page state will be changed from prepare-dirty to dirty
 *	11(b): page state will be changed from prepare-dirty to clean
 */
void nilfs_btnode_page_clear_dirty(struct page *page, int bits)
{
	struct nilfs_btnode_cache *btnc;
	pgoff_t index;

	BUG_ON(!bits);
	if (!page->mapping && (bits & 1 << PAGECACHE_TAG_DIRTY)) {
		ClearPageDirty(page);
		return;
	}
	btnc = PAGE_BTNC(page);

	nilfs_btnode_write_lock(btnc);
	index = page_index(page);
	if (bits & 1 << PAGECACHE_TAG_DIRTY) {
		/* may be called twice for the same page with DIRTY bit */
		if (TestClearPageDirty(page))
			radix_tree_tag_clear(&btnc->page_tree, index,
					     PAGECACHE_TAG_DIRTY);
	} else /* the PDIRTY bit must be set here */
		radix_tree_tag_set(&btnc->page_tree, index,
				   PAGECACHE_TAG_DIRTY);
	if (bits & 1 << NILFS_PAGECACHE_TAG_PDIRTY)
		radix_tree_tag_clear(&btnc->page_tree, index,
				     NILFS_PAGECACHE_TAG_PDIRTY);
	nilfs_btnode_write_unlock(btnc);
}

/**
 * nilfs_btnode_invalidate_page - invalidate a page and remove it from cache
 * @page: page to be removed from cache
 * @force: force flag
 *
 * The caller must lock @page and must hold the reference count.
 */
int nilfs_btnode_invalidate_page(struct page *page, int force)
{
	struct nilfs_btnode_cache *btnc = PAGE_BTNC(page);
	struct buffer_head *head, *bh;
	struct page *page2;
	int busy = 0;

	nilfs_btnode_write_lock(btnc);
	/* check refs in critical section, page count 1 for caller */
	if (nilfs_btnode_page_referenced(page, 1) ||
	    nilfs_page_buffers_busy(page)) {
		busy++;
		if (!force) {
			btnode_debug(2, "skip busy page %p cnt %d\n",
				     page, page_count(page));
			goto out_locked;
		}
		PAGE_DEBUG(page, "invalidate busy page forcibly");
	}

	/* Ths following cleanup is omissible if no one will see buffers
	   on the invalidated page */
	head = bh = page_buffers(page);
	do {
		if (unlikely(atomic_read(&bh->b_count)))
			PAGE_DEBUG(page, "referred buffer");
		bh->b_state = (1 << BH_NILFS_Allocated);
		if (unlikely(!list_empty(&bh->b_assoc_buffers))) {
			PAGE_DEBUG(page, "chained buffer");
			list_del_init(&bh->b_assoc_buffers);
		}
		bh = bh->b_this_page;
	} while (bh != head);

	/* remove page and associated tags from cache */
	page2 = radix_tree_delete(&btnc->page_tree, page->index);
	if (unlikely(page != page2)) {
		PAGE_DEBUG(page, "radix_tree_delete failed (page2=%p)", page2);
		BUG();
	}
	page->mapping = NULL;
	page->index = 0;
	page_cache_release(page);	/* ref for radix-tree */

out_locked:
	nilfs_btnode_write_unlock(btnc);
	btnode_debug(3, "busy=%d for page %p force %d\n", busy, page, force);
	return busy;
}

/**
 * nilfs_btnode_delete_page - remove a page from cache and free it
 * @page: page to be deleted
 * @force: force flag
 *
 * nilfs_btnode_delete_page() removes @page from btnode cache.
 * If the page is used by someone and @force is zero, the removal is not
 * performed. If @force is not zero, the page is always removed.
 * For both cases, the value whether the page is busy or not is returned.
 * If the page was not busy or @force is not zero, it is removed from lru,
 * and is freed with its buffers.
 * The caller must lock @page and must hold a refcnt.
 * The caller must not refer to the page when removing forcibly or
 * after this function returned zero.
 */
static int nilfs_btnode_delete_page(struct page *page, int force)
{
	int busy = nilfs_btnode_invalidate_page(page, force);
	/* The shrinker may be using the page because it gets pages before
	   locking them. */
	if (!busy | force) {
		nilfs_page_delete_from_lru(page);
		    /* If page is not in any LRU list, it is a BUG. */
		nilfs_free_buffer_page(page);
		    /* nilfs_btnode_invalidate_page performs busy check
		       for buffers;  if this call failed it's a BUG */
	}
	return busy;
}

/**
 * nilfs_btnode_delete_bh - invalidate a buffer entry from a page
 * @bh: pointer of a btnode buffer
 *
 * The caller must lock the page.
 */
static void nilfs_btnode_delete_bh(struct buffer_head *bh)
{
	struct page *page = bh->b_page;
	int bits;

	clear_buffer_dirty(bh);
	clear_buffer_nilfs_volatile(bh);
	bits = nilfs_page_buffers_clean(page);
	if (bits != 0)
		nilfs_btnode_page_clear_dirty(page, bits);

	clear_buffer_uptodate(bh);
	clear_buffer_mapped(bh);
	bh->b_blocknr = 0;
	brelse(bh);	/* hold by caller */
}

/**
 * nilfs_btnode_delete - delete btnode buffer
 * @bh: buffer to be deleted
 *
 * nilfs_btnode_delete() invalidates the specified buffer and delete the page
 * including the buffer if the page gets unbusy.
 */
void nilfs_btnode_delete(struct buffer_head *bh)
{
	struct page *page = bh->b_page;
	struct buffer_head *b;

	btnode_debug(3, "deleting buffer %p\n", bh);
	page_cache_get(page);	/* for dealloc */
	lock_page(page);
	if (unlikely(!nilfs_doing_construction() && PageWriteback(page))) {
		PAGE_DEBUG(page, "page is on writeback");
		BUG();
	}
	if (unlikely(!buffer_mapped(bh)))
		BH_DEBUG(bh, "deleting unused btnode buffer");
	nilfs_btnode_delete_bh(bh);	/* bh ref freed */

	b = bh;
	do {
		if (nilfs_buffer_busy(b) || buffer_mapped(b))
			goto out_unlock; /* valid bh remains in page */
		b = b->b_this_page;
	} while (b != bh);
	if (!nilfs_btnode_delete_page(page, 0))
		return; /* successfully freed */
	/* if someone looking, shrinker will remove later. */
out_unlock:
	btnode_debug(2, "removal of page delayed (bh=%p, page=%p, bcnt=%d)\n",
		     bh, page, atomic_read(&bh->b_count));
	unlock_page(page);
	page_cache_release(page);
}

/**
 * nilfs_btnode_prepare_change_key
 *  prepare to move contents of the block for old key to one of new key.
 *  the old buffer will not be removed, but might be reused for new buffer.
 *  it might return -ENOMEM because of memory allocation errors,
 *  and might return -EIO because of disk read errors.
 */
int nilfs_btnode_prepare_change_key(struct nilfs_btnode_cache *btnc,
				    struct nilfs_btnode_chkey_ctxt *ctxt)
{
	int err;
	struct buffer_head *obh, *nbh;
	struct inode *inode = BTNC_I(btnc);
	__u64 oldkey = ctxt->oldkey, newkey = ctxt->newkey;

	if (oldkey == newkey) {
		btnode_debug(3, "oldkey==newkey(%llu).\n",
			     (unsigned long long)oldkey);
		return 0;
	}
	btnode_debug(3, "oldkey %llu newkey %llu\n",
		     (unsigned long long)oldkey, (unsigned long long)newkey);
	obh = ctxt->bh;
	if (inode->i_blkbits == PAGE_CACHE_SHIFT) {
#if HAVE_EXPORTED_RADIX_TREE_PRELOAD
		/*
		 * We cannot call radix_tree_preload for the kernels older
		 * than 2.6.23, because it is not exported for modules.
		 */
		err = radix_tree_preload(GFP_NOFS & ~__GFP_HIGHMEM);
		if (err)
			goto out;
#endif
		/* BUG_ON(oldkey != obh->b_page->index); */
		if (unlikely(oldkey != obh->b_page->index)) {
			PAGE_DEBUG(obh->b_page,
				   "invalid oldkey %lld (newkey=%lld)",
				   (unsigned long long)oldkey,
				   (unsigned long long)newkey);
			BUG();
		}
 retry:
		nilfs_btnode_write_lock(btnc);
		err = radix_tree_insert(&btnc->page_tree, newkey, obh->b_page);
		nilfs_btnode_write_unlock(btnc);
		/*
		 * Note: page->index will not change to newkey until
		 * nilfs_btnode_commit_change_key() will be called.
		 * When using page->index (or page_index(page)), we need care
		 * for independent tasks like the shrinker.  At present,
		 * it doesn't matter because the shrinker sees page->index
		 * only when no one refer to the page.
		 */
#if HAVE_EXPORTED_RADIX_TREE_PRELOAD
		radix_tree_preload_end();
#endif
		if (likely(!err))
			ctxt->newbh = NULL;
		else if (err == -EEXIST) {
			struct page *page;

			if (unlikely(inode->i_ino != NILFS_DAT_INO)) {
				btnode_debug(1, "insert failed, "
					     "ino %lu key %lld\n",
					     inode->i_ino,
					     (unsigned long long)newkey);
				BUG();
			}
			page = nilfs_btnode_find_get_page(btnc, newkey);
			if (page) {
				nilfs_pages_disable_shrinker();
				/* needed to avoid the possibility that
				   the shrinker disturbs busy check and drives
				   nilfs_btnode_delete_page() into failure */
				btnode_debug(3, "page %p exist for key %lld\n",
					     page, (unsigned long long)newkey);
				lock_page(page);
				if (nilfs_btnode_delete_page(page, 0)) {
					PAGE_DEBUG(page,
						   "busy page for key %lld",
						   (unsigned long long)newkey);
					BUG();
				}
				nilfs_pages_enable_shrinker();
			}
			goto retry;
		} /* Other errors (eg -ENOMEM) are just returned */
	} else {
		err = nilfs_btnode_get_new(btnc, newkey, &nbh);
		if (unlikely(err)) {	/* -ENOMEM or -EIO */
			btnode_debug(1, "cannot btnode_get_new for key %lld "
				     "err %d\n",
				     (long long)newkey, err);
			goto out;
		}
		BUG_ON(nbh == obh);
		ctxt->newbh = nbh;
	}
out:
	return err;
}

/**
 * nilfs_btnode_commit_change_key
 *  commit the change_key operation prepared by prepare_change_key().
 */
void nilfs_btnode_commit_change_key(struct nilfs_btnode_cache *btnc,
				    struct nilfs_btnode_chkey_ctxt *ctxt)
{
	struct buffer_head *obh, *nbh;
	__u64 oldkey = ctxt->oldkey, newkey = ctxt->newkey;
	struct page *opage;

	if (oldkey == newkey) {
		btnode_debug(3, "oldkey==newkey(%llu).\n",
			     (unsigned long long)oldkey);
		return;
	}
	btnode_debug(3, "ino %lu oldkey %llu newkey %llu\n",
		     BTNC_I(btnc)->i_ino,
		     (unsigned long long)oldkey, (unsigned long long)newkey);
	obh = ctxt->bh;
	nbh = ctxt->newbh;
	if (nbh == NULL) {	/* blocksize == pagesize */
		opage = obh->b_page;
		/* BUG_ON(oldkey != opage->index); */
		if (unlikely(oldkey != opage->index)) {
			PAGE_DEBUG(opage, "invalid oldkey %lld (newkey=%lld)",
				   (unsigned long long)oldkey,
				   (unsigned long long)newkey);
			BUG();
		}
		lock_page(opage);
		if (!test_set_buffer_dirty(obh)) {
			/* virtual block, will be prepare-dirty */
			if (unlikely(test_set_buffer_prepare_dirty(obh)))
				BUG();
			if (unlikely(TestSetPageDirty(opage)))
				BUG();
		}
		nilfs_btnode_write_lock(btnc);
		radix_tree_delete(&btnc->page_tree, oldkey);
		radix_tree_tag_set(&btnc->page_tree, newkey,
				   buffer_prepare_dirty(obh) ?
				   NILFS_PAGECACHE_TAG_PDIRTY :
				   PAGECACHE_TAG_DIRTY);
		nilfs_btnode_write_unlock(btnc);
		unlock_page(opage);
		opage->index = obh->b_blocknr = newkey;
	} else {
		memcpy(nbh->b_data, obh->b_data, obh->b_size);
		nilfs_copy_buffer_state(nbh, obh, NILFS_BUFFER_INHERENT_BITS);
		/*
		 * This copy of buffer state doesn't use atomic operations and
		 * needs care;  the page having nbh has already been added
		 * to an active or inactive list, and NILFS shrinker may refer
		 * to the state.  However, it's barely safe because the
		 * shrinker checks a reference counter of the buffer
		 * together with the state.
		 */
		if (nilfs_btnode_buffer_dirty(obh))
			nilfs_btnode_mark_dirty(nbh);	/* before copy */
		else
			nilfs_btnode_mark_prepare_dirty(nbh);

		nbh->b_blocknr = newkey;
		ctxt->bh = nbh;
		nilfs_btnode_delete(obh); /* will decrement bh->b_count */
	}
}

/**
 * nilfs_btnode_abort_change_key
 *  abort the change_key operation prepared by prepare_change_key().
 */
void nilfs_btnode_abort_change_key(struct nilfs_btnode_cache *btnc,
				   struct nilfs_btnode_chkey_ctxt *ctxt)
{
	struct buffer_head *nbh;
	__u64 oldkey = ctxt->oldkey, newkey = ctxt->newkey;

	if (oldkey == newkey) {
		btnode_debug(3, "oldkey==newkey(%llu).\n",
			     (unsigned long long)oldkey);
		return;
	}
	btnode_debug(3, "oldkey %llu newkey %llu\n",
		     (unsigned long long)oldkey, (unsigned long long)newkey);
	nbh = ctxt->newbh;
	if (nbh == NULL) {	/* blocksize == pagesize */
		nilfs_btnode_write_lock(btnc);
		radix_tree_delete(&btnc->page_tree, newkey);
		nilfs_btnode_write_unlock(btnc);
	} else {
		brelse(nbh);
		/* should be reclaimed by shrinker, or reuse by others */
	}
}

void nilfs_btnode_do_clear_dirty_pages(struct nilfs_btnode_cache *btnc,
				       int tag)
{
	struct page *pages[NILFS_BTNODE_GANG_SIZE], *page;
	pgoff_t offset;
	pgoff_t index = 0;
	unsigned int i, n;
	int ncleaned = 0, ndeleted = 0;
	struct buffer_head *bh, *head;

	btnode_debug(3, "btnc %p tag %d\n", btnc, tag);
 repeat:
	n = nilfs_btnode_find_get_pages_tag(btnc, pages, &index,
					    NILFS_BTNODE_GANG_SIZE, tag);
	if (!n) {
		btnode_debug(3, "cleared %d dirty pages and deleted %d pages "
			     "for tag=%d\n",
			     ncleaned, ndeleted, tag);
		return;
	}

	for (i = 0; i < n; i++) {
		/* The pdirty-tag and dirty-tag are designed exclusive.
		   So, the following process will not be called twice
		   for a same btnode page */
		page = pages[i];
		lock_page(page);
		offset = page_index(page);
		BUG_ON(PageWriteback(page));

		bh = head = page_buffers(page);
		do {
			/* invalidate buffer */
			bh->b_state = NILFS_BTNODE_CLEAN_BH_STATE;
			bh = bh->b_this_page;
		} while (bh != head);

		nilfs_btnode_write_lock(btnc);
		if (TestClearPageDirty(page))
			radix_tree_tag_clear(&btnc->page_tree, offset, tag);
		nilfs_btnode_write_unlock(btnc);

		ncleaned++;
		if (nilfs_btnode_invalidate_page(page, 0)) {
			btnode_debug(2, "Skipped(BufBusy) %p\n", page);
			ndeleted++;
		}
		unlock_page(page);
		page_cache_release(page);
	}
	goto repeat;
}

int nilfs_btnode_do_copy_dirty_pages(struct nilfs_btnode_cache *src,
				     struct nilfs_btnode_cache *dst,
				     int tag)
{
	struct page *pages[NILFS_BTNODE_GANG_SIZE];
	pgoff_t index = 0;
	unsigned int i, n;
	int err;

	btnode_debug(3, "src %p dst %p\n", src, dst);
repeat:
	n = nilfs_btnode_find_get_pages_tag(src, pages, &index,
					    NILFS_BTNODE_GANG_SIZE, tag);
	if (!n)
		return 0;

	for (i = 0; i < n; i++) {
		struct page *page = pages[i], *dpage;

		/* The pdirty-tag and dirty-tag are designed exclusive.
		   So, the following process will not be called twice
		   for a same btnode page */
		lock_page(page);
		/* do not search original dat cache */
		err = nilfs_btnode_get_page(dst, page->index, &dpage, 0);
		if (unlikely(err)) {
			unlock_page(page);
			goto failed;
		}
		lock_page(dpage);

		if (PageDirty(page))
			__nilfs_btnode_set_page_dirty(dst, dpage, tag, 0);
		btnode_debug(3, "cp: orig: page %p idx %lu, "
			     "gc: page %p idx %lu.\n",
			     page, page->index, dpage, dpage->index);
		nilfs_copy_buffer_page(page, dpage, 1);

		unlock_page(dpage);
		page_cache_release(dpage);
		unlock_page(page);
		page_cache_release(page);
	}
	goto repeat;
 failed:
	while (i < n)
		page_cache_release(pages[i++]);
	btnode_debug(1, "failed (err=%d)\n", err);
	return err;
}

void nilfs_btnode_copy_cache(struct nilfs_btnode_cache *src,
			     struct nilfs_btnode_cache *dst)
{
	struct page *pages[NILFS_BTNODE_GANG_SIZE];
	unsigned int i, n;
	pgoff_t index = 0;
	int err;

	btnode_debug(3, "src %p dst %p\n", src, dst);
repeat:
	n = nilfs_btnode_find_get_pages(src, pages, &index,
					NILFS_BTNODE_GANG_SIZE);
	if (!n)
		return;
	/* note: mdt dirty flags should be cleared by segctor. */
	for (i = 0; i < n; i++) {
		struct page *page = pages[i], *dpage;
		pgoff_t offset = page->index;

		lock_page(page);
		dpage = nilfs_btnode_find_get_page(dst, offset);
		if (dpage) {
			/* override existing page on the destination cache */
			/* XXX skip if identical */
			lock_page(dpage);
			btnode_debug(3, "orig: page %p idx %lu, "
				     "gc: page %p idx %lu.\n",
				     dpage, dpage->index, page, page->index);
			/* dirty or pdirty pages do not appear in src cache */
			BUG_ON(PageDirty(dpage));
			nilfs_copy_buffer_page(page, dpage, 0);
			unlock_page(dpage);
			page_cache_release(dpage);
		} else {
			struct page *page2;

			/* move the page to the destination cache */
			nilfs_btnode_write_lock(src);
			page2 = radix_tree_delete(&src->page_tree, offset);
			if (unlikely(page2 != page)) {
				PAGE_DEBUG(page, "page removal failed "
					   "(offset=%lu, page2=%p)",
					   offset, page2);
				BUG();
			}
			page->mapping = NULL;
			page_cache_release(page);
			nilfs_btnode_write_unlock(src);

			btnode_debug(3, "adding page %p idx %lu as off %lu\n",
				     page, page->index, offset);
			err = nilfs_btnode_page_add_cache(page, dst, offset);
			if (unlikely(err))
				PAGE_DEBUG(page, "failed to move page "
					   "(err=%d, offset=%lu)",
					   err, offset);
		}
		unlock_page(page);
		page_cache_release(page);
	}
	goto repeat;
}

void nilfs_btnode_cache_clear(struct nilfs_btnode_cache *btnc)
{
	struct page *pages[NILFS_BTNODE_GANG_SIZE], *page;
	pgoff_t index = 0;
	unsigned int i, n;

	btnode_debug(3, "btnode %p (ino=%lu)\n", btnc, BTNC_I(btnc)->i_ino);
 repeat:
	n = nilfs_btnode_find_get_pages(btnc, pages, &index,
					NILFS_BTNODE_GANG_SIZE);
	if (!n)
		return;

	nilfs_pages_disable_shrinker(); /* needed to avoid possible refcount
					   errors on the shrinker */
	for (i = 0; i < n; i++) {
		page = pages[i];
		lock_page(page);
		if (unlikely(!nilfs_doing_construction() &&
			     PageWriteback(page))) {
			PAGE_DEBUG(page, "page is on writeback");
			BUG();
		}
		nilfs_btnode_delete_page(page, 1);
	}
	nilfs_pages_enable_shrinker();
	goto repeat;
}
