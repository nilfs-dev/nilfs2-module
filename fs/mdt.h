/*
 * mdt.h - NILFS meta data file (provisional) prototype and definitions
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
 * Written by Ryusuke Konishi <ryusuke@osrg.net>
 */

#ifndef _NILFS_MDT_H
#define _NILFS_MDT_H

#include <linux/buffer_head.h>
#include <linux/blockgroup_lock.h>
#include "nilfs.h"
#include "nilfs_types.h"
#include "kern_feature.h"

/**
 * struct nilfs_mdt_info - on-memory private data of an meta data file
 * @mi_nilfs: back pointer to the_nilfs struct
 * @mi_sem: reader/writer semaphore for contents
 * @mi_bgl: per-blockgroup locking
 * @mi_orig_inode: original inode (only valid for shadow)
 * @mi_entry_size: size of an entry
 * @mi_entries_per_block: number of entries in a block
 * @mi_blocks_per_group: number of blocks in a group
 * @mi_groups_count: number of groups
 */
struct nilfs_mdt_info {
	struct the_nilfs       *mi_nilfs;
	struct rw_semaphore	mi_sem;
	struct blockgroup_lock *mi_bgl;
	struct inode	       *mi_orig_inode;
	unsigned		mi_entry_size;
	unsigned long		mi_entries_per_block;
	unsigned long		mi_blocks_per_group;
	unsigned long		mi_groups_count;
};

static inline struct nilfs_mdt_info *NILFS_MDT(struct inode *inode)
{
#if NEED_INODE_GENERIC_IP
	return inode->u.generic_ip;
#else
	return inode->i_private;
#endif
}

static inline struct the_nilfs *NILFS_I_NILFS(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;

	return sb ? NILFS_SB(sb)->s_nilfs : NILFS_MDT(inode)->mi_nilfs;
}

static inline struct inode *NILFS_ORIG_I(struct inode *inode)
{
	struct nilfs_mdt_info *mdi = NILFS_MDT(inode);

	return (mdi && mdi->mi_orig_inode) ? mdi->mi_orig_inode : NULL;
}

typedef void (nilfs_mdt_init_block_t)(struct inode *, struct buffer_head *,
				      void *);


/* Default GFP flags using highmem */
#define NILFS_MDT_GFP      (__GFP_WAIT | __GFP_IO | __GFP_HIGHMEM)

int nilfs_mdt_create_block(struct inode *, nilfs_blkoff_t,
			   struct buffer_head **, nilfs_mdt_init_block_t *);
int nilfs_mdt_read_block(struct inode *, nilfs_blkoff_t,
			 struct buffer_head **);
int nilfs_mdt_get_block(struct inode *, nilfs_blkoff_t, int,
			nilfs_mdt_init_block_t *, struct buffer_head **);
int nilfs_mdt_delete_block(struct inode *, nilfs_blkoff_t);
int nilfs_mdt_forget_block(struct inode *, nilfs_blkoff_t);
int nilfs_mdt_truncate_blocks(struct inode *, nilfs_blkoff_t);
int nilfs_mdt_mark_block_dirty(struct inode *, nilfs_blkoff_t);

struct inode *nilfs_mdt_new(struct the_nilfs *, struct super_block *, ino_t,
			    gfp_t);
struct inode *nilfs_mdt_new_common(struct the_nilfs *, struct super_block *,
				   ino_t, gfp_t);
void nilfs_mdt_clear(struct inode *);
struct inode *nilfs_mdt_new_with_blockgroup(struct the_nilfs *,
					    struct super_block *, ino_t, gfp_t,
					    unsigned, unsigned long);

#if NEED_OLD_MARK_BUFFER_DIRTY
void nilfs_mdt_mark_buffer_dirty(struct buffer_head *bh);
#else
#define nilfs_mdt_mark_buffer_dirty(bh)		mark_buffer_dirty(bh)
#endif

static inline void nilfs_mdt_mark_dirty(struct inode *inode)
{
	mdt_debug(3, "called (ino=%lu)\n", inode->i_ino);
	set_bit(NILFS_I_DIRTY, &NILFS_I(inode)->i_state);
}

static inline void nilfs_mdt_clear_dirty(struct inode *inode)
{
	clear_bit(NILFS_I_DIRTY, &NILFS_I(inode)->i_state);
}

static inline int nilfs_mdt_fetch_dirty(struct inode *inode)
{
	struct nilfs_inode_info *ii = NILFS_I(inode);

	if (nilfs_bmap_test_and_clear_dirty(ii->i_bmap)) {
		set_bit(NILFS_I_DIRTY, &ii->i_state);
		return 1;
	}
	return test_bit(NILFS_I_DIRTY, &ii->i_state);
}

static inline void nilfs_mdt_destroy(struct inode *inode)
{
	extern void nilfs_destroy_inode(struct inode *);
	struct nilfs_mdt_info *mdi = NILFS_MDT(inode);

	mdt_debug(2, "called (ino=%lu)\n", inode->i_ino);
	if (mdi->mi_bgl)
		kfree(mdi->mi_bgl);
	kfree(mdi);
	nilfs_destroy_inode(inode);
	mdt_debug(2, "done\n");
}

static inline void
nilfs_mdt_set_shadow(struct inode *orig, struct inode *shadow)
{
	NILFS_MDT(shadow)->mi_orig_inode = orig;
}

static inline void
nilfs_mdt_set_entry_size(struct inode *inode, unsigned entry_size)
{
	NILFS_MDT(inode)->mi_entry_size = entry_size;
}

static inline nilfs_cno_t nilfs_mdt_cno(struct inode *inode)
{
	return NILFS_MDT(inode)->mi_nilfs->ns_cno;
}

#define nilfs_mdt_bgl_lock(inode, bg) \
	(&NILFS_MDT(inode)->mi_bgl->locks[(bg) & (NR_BG_LOCKS-1)].lock)


static inline int
nilfs_mdt_read_inode_direct(struct inode *inode, struct buffer_head *bh,
			    unsigned n)
{
	return nilfs_read_inode_common(
		inode, (struct nilfs_inode *)(bh->b_data + n));
}

static inline void
nilfs_mdt_write_inode_direct(struct inode *inode, struct buffer_head *bh,
			     unsigned n)
{
	nilfs_write_inode_common(
		inode, (struct nilfs_inode *)(bh->b_data + n), 1);
}

#endif /* _NILFS_MDT_H */
