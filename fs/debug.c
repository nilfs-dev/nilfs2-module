/*
 * debug.c - NILFS debug code and Proc-fs handling code.
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
 * Written by Amagai Yoshiji <amagai@osrg.net>,
 *            Ryusuke Konishi <ryusuke@osrg.net>
 */

#include <linux/buffer_head.h>
#include <linux/mpage.h>
#include <linux/writeback.h>
#include <linux/blkdev.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/parser.h>
#include "kern_feature.h"
#include "nilfs.h"
#include "sufile.h"
#include "page.h"
#include "segbuf.h"

static int proc_calc_metrics(char *page, char **start, off_t off,
			     int count, int *eof, int len);

/*
 * debug info
 */
struct nilfs_debug_info nilfs_debug_info;

DEFINE_SPINLOCK(debug_print_lock);
DEFINE_SPINLOCK(debug_info_lock);

enum {
	Opt_quiet, Opt_verbose, Opt_verbose2, Opt_verbose3,
	/* Opt_quiet ~ Opt_verbose3 must be successive. */
	Opt_err
};

#define MAX_VLEVEL  3   /* Maximum level of Opt_verbose */

static match_table_t opt_tokens = {
	{Opt_verbose, "v"},
	{Opt_verbose2, "vv"},
	{Opt_verbose3, "vvv"},
	{Opt_quiet, "n"},
	{Opt_err, NULL}
};


static match_table_t class_tokens = {
	{NILFS_VERBOSE_FS, "fs"},
	{NILFS_VERBOSE_SEGMENT, "segment"},
	{NILFS_VERBOSE_SEGINFO, "seginfo"},
	{NILFS_VERBOSE_RECOVERY, "recovery"},
	{NILFS_VERBOSE_INODE, "inode"},
	{NILFS_VERBOSE_MDT, "mdt"},
	{NILFS_VERBOSE_BMAP, "bmap"},
	{NILFS_VERBOSE_DAT, "dat"},
	{NILFS_VERBOSE_BTNODE, "btnode"},
	{NILFS_VERBOSE_PAGE, "page"},
	{NILFS_VERBOSE_TRANSACTION, "trans"},
	{-1, NULL},
};

static const char *find_token(int token, match_table_t tokens)
{
	const struct match_token *pt;

	for (pt = tokens; pt->pattern != NULL; pt++)
		if (pt->token == token)
			return pt->pattern;
	return NULL;
}

void nilfs_fill_debug_info(int level)
{
	int i;

	for (i = 0; i < NILFS_VERBOSE_LIMIT; i++)
		nilfs_debug_info.verbose[i] = level;
}

static int nilfs_read_debug_option(char *page, char **start, off_t off,
				   int count, int *eof, void *data)
{
	int len = 0;
	int flag;

	spin_lock(&debug_info_lock);

	for (flag = 0; flag < NILFS_VERBOSE_LIMIT; flag++) {
		const char *vopt, *p;
		int level = min(MAX_VLEVEL,
				(int)nilfs_debug_info.verbose[flag]);

		if (level >= 0) {
			vopt = find_token(Opt_quiet + level, opt_tokens);
			BUG_ON(vopt == NULL);

			p = find_token(flag, class_tokens);
			if (!p)
				break;

			if (len > 0)
				page[len++] = ' ';
			len += sprintf(page + len, "-%s %s", vopt, p);
		}
	}

	spin_unlock(&debug_info_lock);
	page[len++] = '\n';

	return proc_calc_metrics(page, start, off, count, eof, len);
}

static int
nilfs_parse_verbose_option(char **dp, char *vopt, substring_t args[],
			   int level)
{
	char *p = "";
	int flag;

	while ((p = strsep(dp, " \t\n")) != NULL) {
		if (!*p)
			continue;

		if (strcmp(p, "all") == 0) {
			nilfs_fill_debug_info(level);
			return 0;
		}
		flag = match_token(p, class_tokens, args);
		if (flag < 0)
			break;

		nilfs_debug_info.verbose[flag] = (char)level;
		return 0;
	}
	printk(KERN_ERR
	       "NILFS: Unrecognized verbose option \"-%s %s\"\n",
	       vopt, p);
	return -EINVAL;
}

static int nilfs_parse_debug_option(char *data)
{
	char *p;
	substring_t args[MAX_OPT_ARGS];
	int err;

	while ((p = strsep(&data, " \t\n")) != NULL) {
		int token, level = -1;

		if (!*p)
			continue;
		else if (*p != '-')
			goto bad_option;

		token = match_token(++p, opt_tokens, args);
		switch (token) {
		case Opt_verbose:
			level = 1;
			break;
		case Opt_verbose2:
			level = 2;
			break;
		case Opt_verbose3:
			level = 3;
			break;
		case Opt_quiet:
			level = 0;
			break;
		default:
			goto bad_option;
		}
		if (level >= 0) {
			err = nilfs_parse_verbose_option(&data, p, args, level);
			if (err < 0)
				return err;
		}
	}
	return 0;

 bad_option:
	printk(KERN_ERR "NILFS: Unrecognized debug option \"%s\"\n", p);
	return -EINVAL;
}

static int
nilfs_write_debug_option(struct file *file, const char __user *buffer,
			 unsigned long count, void *data)
{
	char *tmp;
	int ret = -EFAULT;

	tmp = kmalloc(count + 1, GFP_KERNEL);
	if (unlikely(!tmp))
		return -ENOMEM;

	if (copy_from_user(tmp, buffer, count))
		goto out;

	tmp[count] = '\0';

	spin_lock(&debug_info_lock);

	ret = nilfs_parse_debug_option(tmp);
	if (!ret)
		ret = count;

	spin_unlock(&debug_info_lock);
 out:
	kfree(tmp);
	return ret;
}


#define nbar(n) ((n)++ ? "|" : "")
#define MSIZ 512
#define snprint_flag(b, sz, c, f, n, l) \
	do {							\
		if (c)						\
			(l) += snprintf((b) + (l), (sz) - (l),	\
					"%s" #f, nbar(n));	\
	} while (0)

/*
 * VINODE
 */
#define TEST_INODE_STATE(inode, f, b, sz, n, l) \
	snprint_flag(b, sz, (inode)->i_state & I_##f, f, n, l)
#define TEST_NILFS_INODE_STATE(ni, f, b, sz, n, l) \
	snprint_flag(b, sz, test_bit(NILFS_I_##f, &(ni)->i_state), f, n, l)

void nilfs_vinode_debug(const char *fname, int line, struct inode *inode,
			const char *m, ...)
{
	struct nilfs_inode_info *ii;
	int n = 0, len;
	char b[MSIZ];
	va_list args;

	len = snprintf(b, MSIZ, "VINODE %p ", inode);
	va_start(args, m);
	len += vsnprintf(b + len, MSIZ - len, m, args);
	va_end(args);

	if (inode == NULL) {
		printk(KERN_DEBUG "%s: inode=NULL %s at %d\n", m, fname, line);
		return;
	}
	ii = NILFS_I(inode);
	len += snprintf(b + len, MSIZ - len, ": current %p ino=%lu nlink=%u "
			"count=%u mode=0%o mapping=%p i_bh=%p",
			current, inode->i_ino, inode->i_nlink,
			atomic_read(&inode->i_count), inode->i_mode,
			inode->i_mapping, ii->i_bh);

	len += snprintf(b + len, MSIZ - len, " %s(%d) i_state=", fname, line);
	TEST_INODE_STATE(inode, DIRTY_SYNC, b, MSIZ, n, len);
	TEST_INODE_STATE(inode, DIRTY_DATASYNC, b, MSIZ, n, len);
	TEST_INODE_STATE(inode, DIRTY_PAGES, b, MSIZ, n, len);
	TEST_INODE_STATE(inode, LOCK, b, MSIZ, n, len);
	TEST_INODE_STATE(inode, FREEING, b, MSIZ, n, len);
	TEST_INODE_STATE(inode, CLEAR, b, MSIZ, n, len);
	TEST_INODE_STATE(inode, NEW, b, MSIZ, n, len);
#ifdef I_WILL_FREE
	TEST_INODE_STATE(inode, WILL_FREE, b, MSIZ, n, len);
#endif

	if (ii->i_state) {
		n = 0;
		len += snprintf(b + len, MSIZ - len, " vi_state=");
		TEST_NILFS_INODE_STATE(ii, NEW, b, MSIZ, n, len);
		TEST_NILFS_INODE_STATE(ii, DIRTY, b, MSIZ, n, len);
		TEST_NILFS_INODE_STATE(ii, QUEUED, b, MSIZ, n, len);
		TEST_NILFS_INODE_STATE(ii, BUSY, b, MSIZ, n, len);
		TEST_NILFS_INODE_STATE(ii, COLLECTED, b, MSIZ, n, len);
		TEST_NILFS_INODE_STATE(ii, UPDATED, b, MSIZ, n, len);
		TEST_NILFS_INODE_STATE(ii, INODE_DIRTY, b, MSIZ, n, len);
		TEST_NILFS_INODE_STATE(ii, BMAP, b, MSIZ, n, len);
		TEST_NILFS_INODE_STATE(ii, GCINODE, b, MSIZ, n, len);
		TEST_NILFS_INODE_STATE(ii, GCDAT, b, MSIZ, n, len);
	}

	printk(KERN_DEBUG "%s\n", b);
	if (ii->i_bh)
		BH_DEBUG(ii->i_bh, "ibh");
}

/*
 * BH_DEBUG
 */
#define TEST_BH_STATE(bh, f, fn, b, sz, n, l) \
	snprint_flag(b, sz, buffer_##f(bh), fn, n, l)

static int snprint_bh_state(char *b, int size, struct buffer_head *bh)
{
	int len = 0, n = 0;

	TEST_BH_STATE(bh, uptodate, Uptodate, b, size, n, len);
	TEST_BH_STATE(bh, dirty, Dirty, b, size, n, len);
	TEST_BH_STATE(bh, locked, Locked, b, size, n, len);
	TEST_BH_STATE(bh, req, Req, b, size, n, len);
	TEST_BH_STATE(bh, mapped, Mapped, b, size, n, len);
	TEST_BH_STATE(bh, new, New, b, size, n, len);
	TEST_BH_STATE(bh, async_read, ARead, b, size, n, len);
	TEST_BH_STATE(bh, async_write, AWrite, b, size, n, len);
	TEST_BH_STATE(bh, delay, Delay, b, size, n, len);
	TEST_BH_STATE(bh, boundary, Boundary, b, size, n, len);
	TEST_BH_STATE(bh, write_io_error, WriteIOErr, b, size, n, len);
	TEST_BH_STATE(bh, ordered, Ordered, b, size, n, len);
	TEST_BH_STATE(bh, eopnotsupp, ENOTSUPP, b, size, n, len);

	/* nilfs private */
	TEST_BH_STATE(bh, nilfs_allocated, Allocated, b, size, n, len);
	TEST_BH_STATE(bh, nilfs_node, Node, b, size, n, len);
	TEST_BH_STATE(bh, nilfs_volatile, Volatile, b, size, n, len);

	snprint_flag(b, size, nilfs_doing_gc(), DoingGC, n, len);

	return len;
}

void nilfs_bh_debug(const char *fname, int line, struct buffer_head *bh,
		    const char *m, ...)
{
	struct page *page = bh->b_page;
	int len;
	char b[MSIZ];
	va_list args;

	len = snprintf(b, MSIZ, "BH %p ", bh);
	va_start(args, m);
	len += vsnprintf(b + len, MSIZ - len, m, args);
	va_end(args);

	if (bh == NULL) {
		printk(KERN_DEBUG "%s: bh=NULL %s at %d\n", b, fname, line);
		return;
	}
	len += snprintf(b + len, MSIZ - len,
			": page=%p cnt=%d blk#=%llu lst=%d",
			page, atomic_read(&bh->b_count),
			(unsigned long long)bh->b_blocknr,
			!list_empty(&bh->b_assoc_buffers));
	if (page)
		len += snprintf(b + len, MSIZ - len,
				" pagecnt=%d pageindex=%lu",
				page_count(page), page_index(page));
	len += snprintf(b + len, MSIZ - len, " %s(%d) state=", fname, line);
	len += snprint_bh_state(b + len, MSIZ - len, bh);

	printk(KERN_DEBUG "%s\n", b);
}

/*
 * PAGE_DEBUG
 */
#define TEST_PAGE_FLAG(page, f, b, sz, n, l) \
	snprint_flag(b, sz, Page##f(page), f, n, l)

static int snprint_page_flags(char *b, int size, struct page *page)
{
	int len = 0, n = 0;

	TEST_PAGE_FLAG(page, Locked, b, size, n, len);
	TEST_PAGE_FLAG(page, Error, b, size, n, len);
	TEST_PAGE_FLAG(page, Referenced, b, size, n, len);
	TEST_PAGE_FLAG(page, Uptodate, b, size, n, len);
	TEST_PAGE_FLAG(page, Dirty, b, size, n, len);
	TEST_PAGE_FLAG(page, LRU, b, size, n, len);
	TEST_PAGE_FLAG(page, Active, b, size, n, len);
	TEST_PAGE_FLAG(page, Slab, b, size, n, len);
	TEST_PAGE_FLAG(page, HighMem, b, size, n, len);
	TEST_PAGE_FLAG(page, Checked, b, size, n, len);
	TEST_PAGE_FLAG(page, Reserved, b, size, n, len);
	TEST_PAGE_FLAG(page, Private, b, size, n, len);
	TEST_PAGE_FLAG(page, Writeback, b, size, n, len);
	TEST_PAGE_FLAG(page, Compound, b, size, n, len);
	TEST_PAGE_FLAG(page, MappedToDisk, b, size, n, len);
	TEST_PAGE_FLAG(page, Reclaim, b, size, n, len);
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 11)) && (BITS_PER_LONG > 32)
	TEST_PAGE_FLAG(page, Uncached, b, size, n, len);
#endif
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 16))
	TEST_PAGE_FLAG(page, Buddy, b, size, n, len);
#endif
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 21))
	TEST_PAGE_FLAG(page, Tail, b, size, n, len);
	TEST_PAGE_FLAG(page, Head, b, size, n, len);
#endif
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 22))
	TEST_PAGE_FLAG(page, Pinned, b, size, n, len);
	TEST_PAGE_FLAG(page, Readahead, b, size, n, len);
#endif
	return len;
}

void nilfs_page_debug(const char *fname, int line, struct page *page,
		      const char *m, ...)
{
	struct address_space *mapping;
	struct inode *inode;
	va_list args;
	int len;
	char b[MSIZ];

	/* The page should be locked */
	len = snprintf(b, MSIZ, "PAGE %p ", page);
	va_start(args, m);
	len += vsnprintf(b + len, MSIZ - len, m, args);
	va_end(args);

	if (page == NULL) {
		printk(KERN_DEBUG "%s: page=NULL %s at %d\n", b, fname, line);
		return;
	}
	mapping = page->mapping;
	len += snprintf(b + len, MSIZ - len,
			": cnt=%d index#=%llu mapping=%d lru=%d",
			atomic_read(&page->_count),
			(unsigned long long)page->index, !!mapping,
			!list_empty(&page->lru));
	len += snprintf(b + len, MSIZ - len, " %s(%d) flags=", fname, line);
	len += snprint_page_flags(b + len, MSIZ - len, page);
	if (mapping) {
		if (buffer_nilfs_node(page_buffers(page)))
			inode = NILFS_BTNC_I(mapping);
		else
			inode = NILFS_AS_I(mapping);
		if (inode != NULL)
			len += snprintf(b + len, MSIZ - len, " ino=%lu",
					inode->i_ino);
	}
	printk(KERN_DEBUG "%s\n", b);

	if (page_has_buffers(page)) {
		struct buffer_head *bh, *head;
		int i = 0;

		bh = head = page_buffers(page);
		if (!bh) {
			printk(KERN_DEBUG "PAGE %p: invalid page buffers\n",
			       page);
			return;
		}
		do {
			len = snprintf(b, MSIZ,
				       "  BH[%d] %p: cnt=%d blk#=%llu state=",
				       i, bh, atomic_read(&bh->b_count),
				       (unsigned long long)bh->b_blocknr);
			len += snprint_bh_state(b + len, MSIZ - len, bh);
			printk(KERN_DEBUG "%s\n", b);
			bh = bh->b_this_page;  i++;
			if (unlikely(!bh)) {
				printk(KERN_DEBUG
				       "PAGE %p: unexpected buffers end\n",
				       page);
				break;
			}
		} while (bh != head);
	}
}

/*
 * Segment information
 */
#define TEST_SEGSUM_FLAG(flags, f, b, sz, n, l) \
	snprint_flag(b, sz, flags & NILFS_SS_##f, f, n, l)

void nilfs_print_seginfo(struct nilfs_segment_buffer *segbuf)
{
	int n = 0, len = 0;
	char b[MSIZ];
	unsigned int flags;

	if (nilfs_debug_info.verbose[NILFS_VERBOSE_SEGINFO] <= 1)
		return;

	b[0] = '\0';
	flags = segbuf->sb_sum.flags;
	if (flags) {
		TEST_SEGSUM_FLAG(flags, LOGBGN, b, MSIZ, n, len);
		TEST_SEGSUM_FLAG(flags, LOGEND, b, MSIZ, n, len);
		TEST_SEGSUM_FLAG(flags, SR, b, MSIZ, n, len);
		TEST_SEGSUM_FLAG(flags, SYNDT, b, MSIZ, n, len);
		TEST_SEGSUM_FLAG(flags, GC, b, MSIZ, n, len);
	} else {
		len += snprintf(b + len, MSIZ - len, "<none>");
	}
	printk(KERN_DEBUG "========= NILFS SEGMENT INFORMATION ========\n");
	printk(KERN_DEBUG "full segment: segnum=%llu, start=%llu, end=%llu\n",
	       (unsigned long long)segbuf->sb_segnum,
	       (unsigned long long)segbuf->sb_fseg_start,
	       (unsigned long long)segbuf->sb_fseg_end);
	printk(KERN_DEBUG "partial segment: start=%llu, rest=%u\n",
	       (unsigned long long)segbuf->sb_pseg_start,
	       segbuf->sb_rest_blocks);
	printk(KERN_DEBUG "------------------ SUMMARY -----------------\n");
	printk(KERN_DEBUG "nfinfo     = %lu (number of files)\n",
	       segbuf->sb_sum.nfinfo);
	printk(KERN_DEBUG "nblocks    = %lu (number of blocks)\n",
	       segbuf->sb_sum.nblocks);
	printk(KERN_DEBUG "sumbytes   = %lu (size of summary in bytes)\n",
	       segbuf->sb_sum.sumbytes);
	printk(KERN_DEBUG "nsumblk    = %lu (number of summary blocks)\n",
	       segbuf->sb_sum.nsumblk);
	printk(KERN_DEBUG "flags      = %s\n", b);
	printk(KERN_DEBUG "============================================\n");
}

void nilfs_print_finfo(sector_t blocknr, ino_t ino,
		       unsigned long nblocks, unsigned long ndatablk)
{
	unsigned long nnodeblk = nblocks - ndatablk;
	sector_t node_start = blocknr + ndatablk;
	char b[MSIZ];
	int len;

	if (nilfs_debug_info.verbose[NILFS_VERBOSE_SEGINFO] < 3)
		return;

	len = 0;
	b[0] = '\0';

	if (ndatablk)
		len += snprintf(b + len, MSIZ - len, " data[%llu,%llu]",
				(unsigned long long)blocknr,
				(unsigned long long)node_start - 1);
	else
		len += snprintf(b + len, MSIZ - len, " data[<none>]");

	if (nnodeblk)
		len += snprintf(b + len, MSIZ - len, " node[%llu,%llu]",
				(unsigned long long)node_start,
				(unsigned long long)(node_start + nnodeblk));
	else
		len += snprintf(b + len, MSIZ - len, " node[<none>]");

	printk(KERN_DEBUG "FINFO(ino=%lu)%s\n", ino, b);
}

void nilfs_print_binfo(sector_t blocknr, union nilfs_binfo *binfo,
		       int (*print)(char *, int, union nilfs_binfo *))
{
	char b[MSIZ];

	if (nilfs_debug_info.verbose[NILFS_VERBOSE_SEGINFO] < 3)
		return;

	if (print) {
		print(b, MSIZ, binfo);
		printk(KERN_DEBUG "BINFO(blocknr=%llu): %s\n",
		       (unsigned long long)blocknr, b);
	}
}
#undef MSIZ
#undef nbar

/*
 * Proc-fs entries
 */
struct proc_dir_entry *nilfs_proc_root;

static int proc_calc_metrics(char *page, char **start, off_t off,
			     int count, int *eof, int len)
{
	if (len <= off+count)
		*eof = 1;
	*start = page + off;
	len -= off;
	if (len > count)
		len = count;
	if (len < 0)
		len = 0;
	return len;
}

int nilfs_init_proc_entries(void)
{
	struct proc_dir_entry *entry;

	nilfs_proc_root = proc_mkdir("fs/nilfs2", NULL);
	if (!nilfs_proc_root) {
		printk(KERN_WARNING "NILFS: cannot create proc root\n");
		return 0; /* We don't abort when failed to make proc entries */
	}
	nilfs_proc_root->owner = THIS_MODULE;

	/* /proc entries */
	entry = create_proc_entry("debug_option", S_IFREG | S_IRUGO | S_IWUSR,
				  nilfs_proc_root);
	if (entry) {
		entry->read_proc = nilfs_read_debug_option;
		entry->write_proc = nilfs_write_debug_option;
	}

	return 0;
}

void nilfs_remove_proc_entries(void)
{
	remove_proc_entry("debug_option", nilfs_proc_root);
	remove_proc_entry("fs/nilfs2", NULL);
}

/*
 * For inode and page debug
 */
int nilfs_releasepage(struct page *page, gfp_t gfp_mask)
{
	struct address_space *mapping = page->mapping;
	struct inode *inode;
	int verbose = (nilfs_debug_info.verbose[NILFS_VERBOSE_PAGE] > 1);
	int ret;

	if (!verbose && mapping) {
		inode = NILFS_AS_I(mapping);
		if (inode->i_sb && !(inode->i_sb->s_flags & MS_ACTIVE))
			verbose = 1;
	}
	if (unlikely(!PagePrivate(page)))
		NILFS_PAGE_BUG(page, "no buffers");

	if (buffer_nilfs_allocated(page_buffers(page)))
		NILFS_PAGE_BUG(page, "nilfs allocated page");

	/*
	 * Note that non-busy buffer heads may be discarded though the
	 * try_to_free_buffers() call.  This may happen when the page is not
	 * dirty, not in writeback, not locked, and belongs to a mapping.
	 * Before changing the state of buffer heads to busy, the page lock
	 * must be held to protect them.
	 */
	ret = try_to_free_buffers(page);
	if (verbose && ret && mapping && mapping->host) {
		if (page_count(page) > 2 + !PageLRU(page))
			/*
			 * This may happen when the other task just happen to
			 * find and get the page during this invalidation.
			 */
			PAGE_DEBUG(page, "too many page count");
	}
	return ret;
}

void nilfs_sync_page(struct page *page)
{
	page_debug(3, "called (page=%p)\n", page);
}

void nilfs_invalidatepage(struct page *page, unsigned long offset)
{
	struct buffer_head *bh = NULL;

	if (PagePrivate(page)) {
		bh = page_buffers(page);
		BUG_ON(buffer_nilfs_allocated(bh));
	}
	block_invalidatepage(page, offset);
}

/*
 * Radix-tree checker
 */
void nilfs_check_radix_tree(const char *fname, int line,
			    struct address_space *mapping, int tag)
{
	struct pagevec pvec;
	unsigned int i, n;
	pgoff_t index = 0;
	char *page_type;
	int nr_found = 0;

	if (tag == PAGECACHE_TAG_DIRTY)
		page_type = "dirty";
	else if (tag == PAGECACHE_TAG_WRITEBACK)
		page_type = "writeback";
	else
		page_type = "leaking";

	pagevec_init(&pvec, 0);
 repeat:
	if (tag < 0) {
		n = pagevec_lookup(&pvec, mapping, index, PAGEVEC_SIZE);
		if (n)
			index = pvec.pages[n - 1]->index + 1;
	} else
		n = pagevec_lookup_tag(&pvec, mapping, &index, tag,
				       PAGEVEC_SIZE);
	if (!n) {
		if (nr_found)
			printk(KERN_WARNING "%s: found %d %s pages\n",
			       fname, nr_found, page_type);
		return;
	}

	for (i = 0; i < n; i++) {
		nilfs_page_debug(fname, line, pvec.pages[i], "%s page",
				 page_type);
		nr_found++;
	}
	pagevec_release(&pvec);
	cond_resched();
	goto repeat;
}
