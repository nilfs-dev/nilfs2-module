/*
 * dat.h - NILFS disk address translation.
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
 * Written by Koji Sato <koji@osrg.net>.
 */

#ifndef _NILFS_DAT_H
#define _NILFS_DAT_H

#include <linux/types.h>
#include <linux/buffer_head.h>
#include <linux/fs.h>
#include <linux/bitops.h>
#include "nilfs_fs.h"


#define NILFS_DAT_GFP	NILFS_MDT_GFP

/**
 * nilfs_dat_req - request to DAT
 * @dr_vblocknr: virtual block number
 * @dr_desc_bh: buffer head of the buffer containing block group descriptors
 * @dr_bitmap_bh: buffer head of the buffer containing a block group bitmap
 * @dr_entry_bh: buffer head of the buffer containing translation entries
 */
struct nilfs_dat_req {
	__u64 dr_vblocknr;
	struct buffer_head *dr_desc_bh;
	struct buffer_head *dr_bitmap_bh;
	struct buffer_head *dr_entry_bh;
};

static inline unsigned long
nilfs_dat_entries_per_group(const struct inode *dat)
{
	return (1UL << dat->i_blkbits) * 8 /* CHAR_BIT */;
}

int nilfs_dat_translate(struct inode *, __u64, sector_t *);

int nilfs_dat_prepare_alloc(struct inode *, struct nilfs_dat_req *);
void nilfs_dat_commit_alloc(struct inode *, struct nilfs_dat_req *);
void nilfs_dat_abort_alloc(struct inode *, struct nilfs_dat_req *);
int nilfs_dat_prepare_start(struct inode *, struct nilfs_dat_req *);
void nilfs_dat_commit_start(struct inode *, struct nilfs_dat_req *, sector_t);
void nilfs_dat_abort_start(struct inode *, struct nilfs_dat_req *);
int nilfs_dat_prepare_end(struct inode *, struct nilfs_dat_req *);
void nilfs_dat_commit_end(struct inode *, struct nilfs_dat_req *, int);
void nilfs_dat_abort_end(struct inode *, struct nilfs_dat_req *);

int nilfs_dat_mark_dirty(struct inode *, __u64);
int nilfs_dat_freev(struct inode *, __u64 *, size_t);
int nilfs_dat_move(struct inode *, __u64, sector_t);
ssize_t nilfs_dat_get_vinfo(struct inode *, struct nilfs_vinfo *, size_t);

#endif	/* _NILFS_DAT_H */
