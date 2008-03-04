/*
 * alloc.h - persistent object (dat entry/disk inode) allocator/deallocator
 *
 * Copyright (C) 2006, 2007 Nippon Telegraph and Telephone Corporation.
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
 * Written by Amagai Yoshiji <amagai@osrg.net>
 */

#ifndef _NILFS_ALLOC_H
#define _NILFS_ALLOC_H

#include <linux/types.h>
#include <linux/buffer_head.h>
#include <linux/fs.h>
#include <linux/bitops.h>


struct nilfs_persistent_group_desc {
	__le32 pg_nfrees;
};

#define NILFS_PERSISTENT_CHAR_BIT	8

#define nilfs_persistent_set_bit_atomic		ext2_set_bit_atomic
#define nilfs_persistent_clear_bit_atomic	ext2_clear_bit_atomic
#define nilfs_persistent_test_bit		ext2_test_bit
#define nilfs_persistent_find_next_zero_bit	ext2_find_next_zero_bit

static inline int nilfs_persistent_entries_per_group(struct inode *inode)
{
	return (1UL << inode->i_blkbits) * NILFS_PERSISTENT_CHAR_BIT;
}

static inline int nilfs_persistent_group_descs_per_block(struct inode *inode)
{
	return (1UL << inode->i_blkbits) /
		sizeof(struct nilfs_persistent_group_desc);
}

static inline int
nilfs_persistent_blocks_per_groups(struct inode *inode)
{
	/* including block descriptor block */
	return NILFS_MDT(inode)->mi_blocks_per_group
		* nilfs_persistent_group_descs_per_block(inode) + 1;
}

static inline unsigned long
nilfs_persistent_group_desc_blkoff(struct inode *inode, unsigned long group)
{
	unsigned long g =
		group % nilfs_persistent_group_descs_per_block(inode);
	return g * (nilfs_persistent_group_descs_per_block(inode) *
		 (nilfs_persistent_entries_per_group(inode) /
		  NILFS_MDT(inode)->mi_entries_per_block + 1) + 1);
}

static inline unsigned long
nilfs_persistent_group_bitmap_blkoff(struct inode *inode, unsigned long group)
{
	unsigned long long group_offset =
		group / nilfs_persistent_group_descs_per_block(inode);

	return nilfs_persistent_group_desc_blkoff(inode, group) + 1 +
		group_offset * (nilfs_persistent_entries_per_group(inode) /
				NILFS_MDT(inode)->mi_entries_per_block + 1);
}

/**
 * nilfs_persistent_req - request and reply
 * @nr: vblocknr or inode number
 * @pr_desc_bh: buffer head of the buffer containing block group descriptors
 * @pr_bitmap_bh: buffer head of the buffer containing a block group bitmap
 * @pr_entry_bh: buffer head of the buffer containing translation entries
 */
struct nilfs_persistent_req {
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
nilfs_persistent_put_group_bitmap_block(const struct inode *inode,
					struct buffer_head *bitmap_bh)
{
	brelse(bitmap_bh);
}


static inline void
nilfs_persistent_put_entry_block(const struct inode *inode,
				 struct buffer_head *bh)
{
	brelse(bh);
}

extern int nilfs_persistent_prepare_alloc_entry(struct inode *,
						struct nilfs_persistent_req *,
						unsigned long *, int *);
extern void nilfs_persistent_abort_alloc_entry(struct inode *,
					       struct nilfs_persistent_req *,
					       unsigned long, int);
extern void nilfs_persistent_commit_alloc_entry(struct inode *,
						struct nilfs_persistent_req *);
extern int nilfs_persistent_prepare_free_entry(struct inode *,
					       struct nilfs_persistent_req *,
					       unsigned long);
extern void nilfs_persistent_abort_free_entry(struct inode *,
					      struct nilfs_persistent_req *);
extern char *
nilfs_persistent_get_group_bitmap_buffer(struct inode *,
					 const struct buffer_head *);

extern struct nilfs_persistent_group_desc *
nilfs_persistent_get_group_desc(struct inode *, unsigned long,
				const struct buffer_head *);
extern void
nilfs_persistent_put_group_bitmap_buffer(struct inode *,
					 const struct buffer_head *);

static inline void
nilfs_persistent_put_group_desc(struct inode *inode,
				const struct buffer_head *desc_bh)
{
	kunmap(desc_bh->b_page);
}

static inline void
nilfs_persistent_put_group_desc_block(const struct inode *inode,
				      struct buffer_head *desc_bh)
{
	brelse(desc_bh);
}


#endif	/* _NILFS_ALLOC_H */
