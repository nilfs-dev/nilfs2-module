/*
 * the_nilfs.h - the_nilfs shared structure.
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
 * Written by Ryusuke Konishi <ryusuke@osrg.net>
 *
 */

#ifndef _THE_NILFS_H
#define _THE_NILFS_H

#include <linux/types.h>
#include <linux/buffer_head.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/backing-dev.h>
#include "sb.h"

/* the_nilfs struct */
enum {
	THE_NILFS_INIT = 0,     /* Information from super_block is set */
	THE_NILFS_LOADED,       /* Roll-back/roll-forward has done and
				   the latest checkpoint was loaded */
	THE_NILFS_DISCONTINUED,	/* 'next' pointer chain has broken */
	THE_NILFS_COND_NONGC_WRITE,	/* Condition to wake up cleanerd */
};

/**
 * struct the_nilfs - struct to supervise multiple nilfs mount points
 * @ns_flags: flags
 * @ns_count: reference count
 * @ns_bdev: block device
 * @ns_bdi: backing dev info
 * @ns_writer: back pointer to writable nilfs_sb_info
 * @ns_sem: semaphore for shared states
 * @ns_writer_mutex: mutex protecting ns_writer attach/detach
 * @ns_writer_refcount: number of referrers on ns_writer
 * @ns_sbh: buffer head of the on-disk super block
 * @ns_sbp: pointer to the super block data
 * @ns_used_segments: list of full segments in volatile active state
 * @ns_supers: list of nilfs super block structs
 * @ns_seg_seq: segment sequence counter
 * @ns_segnum: index number of the latest full segment.
 * @ns_nextnum: index number of the full segment index to be used next
 * @ns_pseg_offset: offset of next partial segment in the current full segment
 * @ns_cno: next checkpoint number
 * @ns_ctime: write time of the last segment
 * @ns_nongc_ctime: write time of the last segment not for cleaner operation
 * @ns_ndirtyblks: Number of dirty data blocks
 * @ns_last_segment_lock: lock protecting fields for the latest segment
 * @ns_last_pseg: start block number of the latest segment
 * @ns_last_seq: sequence value of the latest segment
 * @ns_last_cno: checkpoint number of the latest segment
 * @ns_free_segments_count: counter of free segments
 * @ns_segctor_sem: segment constructor semaphore
 * @ns_dat: DAT file inode
 * @ns_cpfile: checkpoint file inode
 * @ns_sufile: segusage file inode
 * @ns_gc_dat: shadow inode of the DAT file inode for GC
 * @ns_gc_inodes: dummy inodes to keep live blocks
 * @ns_gc_inodes_h: hash list to keep dummy inode holding live blocks
 * @ns_cleanerd_wq: wait queue for cleanerd
 * @ns_blocksize_bits: bit length of block size
 * @ns_nsegments: number of segments in filesystem
 * @ns_blocks_per_segment: number of blocks per segment
 * @ns_r_segments_percentage: reserved segments percentage
 * @ns_nrsvsegs: number of reserved segments
 * @ns_first_data_block: block number of first data block
 * @ns_inode_size: size of on-disk inode
 * @ns_first_ino: first not-special inode number
 * @ns_crc_seed: seed value of CRC32 calculation
 */
struct the_nilfs {
	unsigned long		ns_flags;
	atomic_t		ns_count;

	struct block_device    *ns_bdev;
	struct backing_dev_info *ns_bdi;
	struct nilfs_sb_info   *ns_writer;
	struct rw_semaphore	ns_sem;
#if HAVE_PURE_MUTEX
	struct mutex		ns_writer_mutex;
#else
	struct semaphore	ns_writer_mutex;
#endif
	atomic_t		ns_writer_refcount;

	/*
	 * used for
	 * - loading the latest checkpoint exclusively.
	 * - allocating a new full segment.
	 * - protecting s_dirt in the super_block struct
	 *   (see nilfs_write_super) and the following fields.
	 */
	struct buffer_head     *ns_sbh;
	struct nilfs_super_block *ns_sbp;
	struct list_head	ns_used_segments;
	unsigned		ns_mount_state;
	struct list_head	ns_supers;

	/*
	 * Following fields are dedicated to a writable FS-instance.
	 * Except for the period seeking checkpoint, code outside the segment
	 * constructor must lock a segment semaphore with transaction_begin()
	 * and transaction_end(), when accessing these fields.
	 * The writable FS-instance is sole during a lifetime of the_nilfs.
	 */
	u64			ns_seg_seq;
	__u64			ns_segnum;
	__u64			ns_nextnum;
	unsigned long		ns_pseg_offset;
	__u64			ns_cno;
	time_t			ns_ctime;
	time_t			ns_nongc_ctime;
	atomic_t		ns_ndirtyblks;

	/*
	 * The following fields hold information on the latest partial segment
	 * written to disk with a super root.  These fields are protected by
	 * ns_last_segment_lock.
	 */
	spinlock_t		ns_last_segment_lock;
	sector_t		ns_last_pseg;
	u64			ns_last_seq;
	__u64			ns_last_cno;
	unsigned long		ns_free_segments_count;

	struct rw_semaphore	ns_segctor_sem;

	/*
	 * Following fields are lock free except for the period before
	 * the_nilfs is initialized.
	 */
	struct inode	       *ns_dat;
	struct inode	       *ns_cpfile;
	struct inode	       *ns_sufile;
	struct inode	       *ns_gc_dat;

	/* GC inode list and hash table head */
	struct list_head	ns_gc_inodes;
	struct hlist_head      *ns_gc_inodes_h;

	/* cleanerd */
	wait_queue_head_t	ns_cleanerd_wq;

	/* Disk layout information (static) */
	unsigned int		ns_blocksize_bits;
	unsigned long		ns_nsegments;
	unsigned long		ns_blocks_per_segment;
	unsigned long		ns_r_segments_percentage;
	unsigned long		ns_nrsvsegs;
	unsigned long		ns_first_data_block;
	int			ns_inode_size;
	int			ns_first_ino;
	u32			ns_crc_seed;
};

#define NILFS_GCINODE_HASH_BITS		8
#define NILFS_GCINODE_HASH_SIZE		(1<<NILFS_GCINODE_HASH_BITS)

#define THE_NILFS_FNS(bit, name)					\
static inline void set_nilfs_##name(struct the_nilfs *nilfs)		\
{									\
	set_bit(THE_NILFS_##bit, &(nilfs)->ns_flags);			\
}									\
static inline void clear_nilfs_##name(struct the_nilfs *nilfs)		\
{									\
	clear_bit(THE_NILFS_##bit, &(nilfs)->ns_flags);			\
}									\
static inline int nilfs_##name(struct the_nilfs *nilfs)			\
{									\
	return test_bit(THE_NILFS_##bit, &(nilfs)->ns_flags);		\
}

THE_NILFS_FNS(INIT, init)
THE_NILFS_FNS(LOADED, loaded)
THE_NILFS_FNS(DISCONTINUED, discontinued)
THE_NILFS_FNS(COND_NONGC_WRITE, cond_nongc_write)

void nilfs_set_last_segment(struct the_nilfs *, sector_t, u64, __u64);
struct the_nilfs *alloc_nilfs(struct block_device *);
void put_nilfs(struct the_nilfs *);
int init_nilfs(struct the_nilfs *, struct nilfs_sb_info *, char *);
int load_nilfs(struct the_nilfs *, struct nilfs_sb_info *);
int nilfs_count_free_blocks(struct the_nilfs *, sector_t *);
void nilfs_dispose_used_segments(struct the_nilfs *);
int nilfs_checkpoint_is_mounted(struct the_nilfs *, __u64, int);
int nilfs_near_disk_full(struct the_nilfs *);


static inline void get_nilfs(struct the_nilfs *nilfs)
{
	/* Caller must have at least one reference of the_nilfs. */
	atomic_inc(&nilfs->ns_count);
}

static inline struct nilfs_sb_info *nilfs_get_writer(struct the_nilfs *nilfs)
{
	if (atomic_inc_and_test(&nilfs->ns_writer_refcount))
		mutex_lock(&nilfs->ns_writer_mutex);
	return nilfs->ns_writer;
}

static inline void nilfs_put_writer(struct the_nilfs *nilfs)
{
	if (atomic_add_negative(-1, &nilfs->ns_writer_refcount))
		mutex_unlock(&nilfs->ns_writer_mutex);
}

static inline void
nilfs_attach_writer(struct the_nilfs *nilfs, struct nilfs_sb_info *sbi)
{
	mutex_lock(&nilfs->ns_writer_mutex);
	nilfs->ns_writer = sbi;
	mutex_unlock(&nilfs->ns_writer_mutex);
}

static inline void
nilfs_detach_writer(struct the_nilfs *nilfs, struct nilfs_sb_info *sbi)
{
	mutex_lock(&nilfs->ns_writer_mutex);
	if (sbi == nilfs->ns_writer)
		nilfs->ns_writer = NULL;
	mutex_unlock(&nilfs->ns_writer_mutex);
}

static inline void
nilfs_get_segment_range(struct the_nilfs *nilfs, __u64 segnum,
			sector_t *seg_start, sector_t *seg_end)
{
	*seg_start = (sector_t)nilfs->ns_blocks_per_segment * segnum;
	*seg_end = *seg_start + nilfs->ns_blocks_per_segment - 1;
	if (segnum == 0)
		*seg_start = nilfs->ns_first_data_block;
}

static inline sector_t
nilfs_get_segment_start_blocknr(struct the_nilfs *nilfs, __u64 segnum)
{
	return (segnum == 0) ? nilfs->ns_first_data_block :
		(sector_t)nilfs->ns_blocks_per_segment * segnum;
}

static inline __u64
nilfs_get_segnum_of_block(struct the_nilfs *nilfs, sector_t blocknr)
{
	sector_t segnum = blocknr;

	sector_div(segnum, nilfs->ns_blocks_per_segment);
	return segnum;
}

static inline void
nilfs_terminate_segment(struct the_nilfs *nilfs, sector_t seg_start,
			sector_t seg_end)
{
	/* terminate the current full segment (used in case of I/O-error) */
	nilfs->ns_pseg_offset = seg_end - seg_start + 1;
}

static inline void nilfs_shift_to_next_segment(struct the_nilfs *nilfs)
{
	/* move forward with a full segment */
	nilfs->ns_segnum = nilfs->ns_nextnum;
	nilfs->ns_pseg_offset = 0;
	nilfs->ns_seg_seq++;
}

static inline __u64 nilfs_last_cno(struct the_nilfs *nilfs)
{
	__u64 cno;

	spin_lock(&nilfs->ns_last_segment_lock);
	cno = nilfs->ns_last_cno;
	spin_unlock(&nilfs->ns_last_segment_lock);
	return cno;
}

#endif /* _THE_NILFS_H */
