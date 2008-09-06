/*
 * alloc.h - persistent object (dat entry/disk inode) allocator/deallocator
 *
 * Copyright (C) 2006-2008 Nippon Telegraph and Telephone Corporation.
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
 *            Ryusuke Konishi <ryusuke@osrg.net>.
 */

#ifndef _NILFS_ALLOC_H
#define _NILFS_ALLOC_H

#include <linux/types.h>
#include <linux/buffer_head.h>
#include <linux/fs.h>
#include <linux/bitops.h>


static inline unsigned long nilfs_palloc_groups_count(struct inode *inode)
{
	return 1UL << (BITS_PER_LONG - (inode->i_blkbits + 3 /* log2(8) */));
}

static inline unsigned long
nilfs_palloc_entries_per_group(struct inode *inode)
{
	return (1UL << inode->i_blkbits) * 8 /* CHAR_BIT */;
}

static inline int nilfs_palloc_group_descs_per_block(struct inode *inode)
{
	return (1UL << inode->i_blkbits) /
		sizeof(struct nilfs_palloc_group_desc);
}

static inline unsigned long
nilfs_palloc_group_desc_blkoff(struct inode *inode, unsigned long group)
{
	unsigned long g =
		group / nilfs_palloc_group_descs_per_block(inode);
	return g * (nilfs_palloc_group_descs_per_block(inode) *
		 (nilfs_palloc_entries_per_group(inode) /
		  NILFS_MDT(inode)->mi_entries_per_block + 1) + 1);
}

static inline unsigned long
nilfs_palloc_group_bitmap_blkoff(struct inode *inode, unsigned long group)
{
	unsigned long group_offset =
		group % nilfs_palloc_group_descs_per_block(inode);

	return nilfs_palloc_group_desc_blkoff(inode, group) + 1 +
		group_offset * (nilfs_palloc_entries_per_group(inode) /
				NILFS_MDT(inode)->mi_entries_per_block + 1);
}

/**
 * nilfs_palloc_req - request and reply
 * @nr: vblocknr or inode number
 * @pr_desc_bh: buffer head of the buffer containing block group descriptors
 * @pr_bitmap_bh: buffer head of the buffer containing a block group bitmap
 * @pr_entry_bh: buffer head of the buffer containing translation entries
 */
struct nilfs_palloc_req {
	struct buffer_head *pr_desc_bh;
	struct buffer_head *pr_bitmap_bh;
	struct buffer_head *pr_entry_bh;
	union {
		__u64	pr_vblocknr;
		ino_t	pr_ino;
		__u64	pr_nslot;	/* for clear both vblocknr and ino */
	} nr;
};

#define pr_vblocknr nr.vblocknr
#define pr_ino nr.pr_ino
#define pr_nslot nr.pr_nslot

static inline void
nilfs_palloc_put_group_bitmap_block(const struct inode *inode,
				    struct buffer_head *bitmap_bh)
{
	brelse(bitmap_bh);
}


static inline void nilfs_palloc_put_entry_block(const struct inode *inode,
						struct buffer_head *bh)
{
	brelse(bh);
}

int nilfs_palloc_init_blockgroup(struct inode *, unsigned);
int nilfs_palloc_prepare_alloc_entry(struct inode *, struct nilfs_palloc_req *,
				     unsigned long *, int *);
void nilfs_palloc_abort_alloc_entry(struct inode *, struct nilfs_palloc_req *,
				    unsigned long, int);
void nilfs_palloc_commit_alloc_entry(struct inode *,
				     struct nilfs_palloc_req *);
int nilfs_palloc_prepare_free_entry(struct inode *, struct nilfs_palloc_req *,
				    unsigned long);
void nilfs_palloc_abort_free_entry(struct inode *, struct nilfs_palloc_req *);
char *nilfs_palloc_get_group_bitmap_buffer(struct inode *,
					   const struct buffer_head *);

struct nilfs_palloc_group_desc *
nilfs_palloc_get_group_desc(struct inode *, unsigned long,
			    const struct buffer_head *);
void nilfs_palloc_put_group_bitmap_buffer(struct inode *,
					  const struct buffer_head *);

static inline void
nilfs_palloc_put_group_desc(struct inode *inode,
			    const struct buffer_head *desc_bh)
{
	kunmap(desc_bh->b_page);
}

static inline void
nilfs_palloc_put_group_desc_block(const struct inode *inode,
				  struct buffer_head *desc_bh)
{
	brelse(desc_bh);
}


#endif	/* _NILFS_ALLOC_H */
