/*
 * debug.h - NILFS debug primitives
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

#ifndef _NILFS_DEBUG_H
#define _NILFS_DEBUG_H

/*
 * Macros to printks
 */
#ifdef CONFIG_NILFS_DEBUG
#define nilfs_debug(l, f, a...)  \
	do {  \
		if ((l) <= (int)nilfs_debug_info.verbose[0])  \
			printk(KERN_DEBUG "NILFS %s: " f, __func__, ## a);  \
	} while (0)

#define nilfs_debug_verbose(v, l, c, f, a...)  \
	do {  \
		if ((l) <= (int)nilfs_debug_info.verbose[v])  \
			printk(KERN_DEBUG "NILFS(" c ") %s: " f,  \
			       __func__, ## a);              \
	} while (0)

#define seg_debug(l, f, a...)  \
	nilfs_debug_verbose(NILFS_VERBOSE_SEGMENT, l, "segment", f, ## a)
#define recovery_debug(l, f, a...)  \
	nilfs_debug_verbose(NILFS_VERBOSE_RECOVERY, l, "recovery", f, ## a)
#define inode_debug(l, f, a...)  \
	nilfs_debug_verbose(NILFS_VERBOSE_INODE, l, "inode", f, ## a)
#define mdt_debug(l, f, a...)  \
	nilfs_debug_verbose(NILFS_VERBOSE_MDT, l, "mdt", f, ## a)
#define bmap_debug(l, f, a...)  \
	nilfs_debug_verbose(NILFS_VERBOSE_BMAP, l, "bmap", f, ## a)
#define dat_debug(l, f, a...)  \
	nilfs_debug_verbose(NILFS_VERBOSE_DAT, l, "dat", f, ## a)
#define btnode_debug(l, f, a...)  \
	nilfs_debug_verbose(NILFS_VERBOSE_BTNODE, l, "btnode", f, ## a)
#define page_debug(l, f, a...)  \
	nilfs_debug_verbose(NILFS_VERBOSE_PAGE, l, "page", f, ## a)
#define trans_debug(l, f, a...)  \
	nilfs_debug_verbose(NILFS_VERBOSE_TRANSACTION, l, "trans", f, ## a)

#else /* CONFIG_NILFS_DEBUG */
#define nilfs_debug(l, f, a...)  do {} while (0)
#define nilfs_debug_verbose(v, l, c, f, a...)  do {} while (0)

#define seg_debug(l, f, a...)  do {} while (0)
#define recovery_debug(l, f, a...)   do {} while (0)
#define inode_debug(l, f, a...)   do {} while (0)
#define mdt_debug(l, f, a...)  do {} while (0)
#define bmap_debug(l, f, a...)  do {} while (0)
#define dat_debug(l, f, a...)  do {} while (0)
#define btnode_debug(l, f, a...)  do {} while (0)
#define page_debug(l, f, a...)  do {} while (0)
#define trans_debug(l, f, a...)  do {} while (0)
#endif /* CONFIG_NILFS_DEBUG */


/*
 * VINODE_DEBUG(), BH_DEBUG(), PAGE_DEBUG()
 */
#ifdef CONFIG_NILFS_DEBUG
extern void nilfs_bh_debug(const char *, int, struct buffer_head *,
			   const char *, ...)
	__attribute__ ((format (printf, 4, 5)));
extern void nilfs_page_debug(const char *, int, struct page *,
			     const char *, ...)
	__attribute__ ((format (printf, 4, 5)));
extern void nilfs_vinode_debug(const char *, int, struct inode *,
			       const char *, ...)
	__attribute__ ((format (printf, 4, 5)));

#define BH_DEBUG(bh, m, a...)  \
	nilfs_bh_debug(__func__, __LINE__, (bh), (m), ## a)
#define PAGE_DEBUG(page, m, a...)  \
	nilfs_page_debug(__func__, __LINE__, (page), (m), ## a)
#define VINODE_DEBUG(inode, m, a...)  \
	nilfs_vinode_debug(__func__, __LINE__, (inode), (m), ## a)
#define NILFS_PAGE_BUG(page, m, a...)  \
	do { PAGE_DEBUG((page), (m), ## a); BUG(); } while (0)

#define nilfs_dump_page_lru(lru_list, msg)  \
	do {  \
		struct page *page;  \
		list_for_each_entry(page, (lru_list), lru)  \
			PAGE_DEBUG(page, (msg));  \
	} while (0)

#define nilfs_dump_chained_buffers(head, msg)  \
	do {  \
		struct buffer_head *bh;  \
		list_for_each_entry(bh, (head), b_assoc_buffers)  \
			BH_DEBUG(bh, (msg));  \
	} while (0)

#else /* CONFIG_NILFS_DEBUG */
#define BH_DEBUG(bh, m, a...)  do {} while (0)
#define PAGE_DEBUG(page, m, a...)  do {} while (0)
#define VINODE_DEBUG(inode, m, a...)  do {} while (0)
#define NILFS_PAGE_BUG(page, m, a...)  \
	do { nilfs_page_bug(page); BUG(); } while (0)

#define nilfs_dump_page_lru(list, msg)  do {} while (0)
#define nilfs_dump_chained_buffers(head, msg)  do {} while (0)
#endif /* CONFIG_NILFS_DEBUG */


#ifdef CONFIG_NILFS_DEBUG

/*
 * debug switches
 */
enum {
	NILFS_VERBOSE_FS = 0,	 /* Generic switches */
	NILFS_VERBOSE_SEGMENT,	 /* Segment construction */
	NILFS_VERBOSE_SEGINFO,	 /* Segment summary information */
	NILFS_VERBOSE_RECOVERY,	 /* Recovery logic */
	NILFS_VERBOSE_INODE,	 /* Inode operations */
	NILFS_VERBOSE_MDT,	 /* Meta data file operations */
	NILFS_VERBOSE_BMAP,	 /* BMAP operations */
	NILFS_VERBOSE_DAT,	 /* DAT file operations */
	NILFS_VERBOSE_BTNODE,	 /* B-tree node operations */
	NILFS_VERBOSE_PAGE,	 /* Page operations */
	NILFS_VERBOSE_TRANSACTION, /* Transaction */
	NILFS_VERBOSE_LIMIT
};

struct nilfs_debug_info {
	signed char  verbose[NILFS_VERBOSE_LIMIT];  /* message switches */
};

extern struct nilfs_debug_info nilfs_debug_info;

#endif /* CONFIG_NILFS_DEBUG */

/* debug.c */
#ifdef CONFIG_NILFS_DEBUG
extern int nilfs_init_proc_entries(void);
extern void nilfs_remove_proc_entries(void);
extern void nilfs_fill_debug_info(int);
#define nilfs_init_debug_info()  do { nilfs_fill_debug_info(1); } while (0)

struct nilfs_segment_buffer;
extern void nilfs_print_seginfo(struct nilfs_segment_buffer *);
extern void nilfs_print_finfo(sector_t, ino_t, unsigned long, unsigned long);
extern void nilfs_print_binfo(sector_t, union nilfs_binfo *,
			      int (*print)(char *, int, union nilfs_binfo *));

extern int nilfs_releasepage(struct page *, gfp_t);
extern void nilfs_sync_page(struct page *);
extern void nilfs_invalidatepage(struct page *, unsigned long);
extern void nilfs_check_radix_tree(const char *, int, struct address_space *,
				   int);

#define NILFS_CHECK_PAGE_CACHE(mapping, tag)  \
	nilfs_check_radix_tree(__func__, __LINE__, (mapping), (tag))

#else /* CONFIG_NILFS_DEBUG */
#define nilfs_init_proc_entries()  (0)
#define nilfs_remove_proc_entries()  do {} while (0)
#define nilfs_init_debug_info()  do {} while (0)
#define nilfs_print_seginfo(segbuf)  do {} while (0)
#define nilfs_print_finfo(blocknr, ino, nblocks, ndatablk)  do {} while (0)
#define nilfs_print_binfo(blocknr, binfo, print)  do {} while (0)
#define nilfs_releasepage	NULL
#define nilfs_sync_page		NULL
#define nilfs_invalidatepage	block_invalidatepage

#define NILFS_CHECK_PAGE_CACHE(mapping, tag)  do {} while (0)

#endif /* CONFIG_NILFS_DEBUG*/
#define nilfs_release_inode_page  NULL

#endif /* _NILFS_DEBUG_H */
