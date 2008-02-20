/*
 * segment.h - NILFS Segment constructor prototypes and definitions
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
 * segment.h,v 1.58 2008-01-28 07:13:12 ryusuke Exp
 *
 * Written by Ryusuke Konishi <ryusuke@osrg.net>
 *
 */
#ifndef _NILFS_SEGMENT_H
#define _NILFS_SEGMENT_H

#include <linux/fs.h>
#include <linux/buffer_head.h>
#include "nilfs_fs.h"
#include "sb.h"
#include "segbuf.h"

/**
 * struct nilfs_recovery_info - Recovery infomation
 * @ri_need_recovery: Recovery status
 * @ri_super_root: Block number of the last super root
 * @ri_ri_cno: Number of the last checkpoint
 * @ri_lsegs_start: Region for roll-forwarding (start block number)
 * @ri_lsegs_end: Region for roll-forwarding (end block number)
 * @ri_lseg_start_seq: Sequence value of the segment at ri_lsegs_start
 * @ri_used_segments: List of segments to be mark active
 * @ri_pseg_start: Block number of the last partial segment
 * @ri_seq: Sequence number on the last partial segment
 * @ri_segnum: Segment number on the last partial segment
 * @ri_nextnum: Next segment number on the last partial segment
 */
struct nilfs_recovery_info {
	int			ri_need_recovery;
	sector_t		ri_super_root;
	nilfs_cno_t		ri_cno;

	sector_t		ri_lsegs_start;
	sector_t		ri_lsegs_end;
	u64			ri_lsegs_start_seq;
	struct list_head	ri_used_segments;
	sector_t		ri_pseg_start;
	u64			ri_seq;
	nilfs_segnum_t		ri_segnum;
	nilfs_segnum_t		ri_nextnum;
};

/* ri_need_recovery */
#define NILFS_RECOVERY_SR_UPDATED	 1  /* The super root was updated */
#define NILFS_RECOVERY_ROLLFORWARD_DONE	 2  /* Rollforward was carried out */

/**
 * struct nilfs_transaction_info: Transaction information
 * @ti_magic: Magic number
 * @ti_save: Backup of journal_info field of task_struct
 * @ti_flags: Flags
 * @ti_count: Nest level
 * @ti_garbage:	List of inode to be put when releasing semaphore
 * @ti_ndirtied: Number of dirtied blocks
 */
struct nilfs_transaction_info {
	u32			ti_magic;
	void		       *ti_save;
				/* This should never used. If this happens,
				   one of other filesystems has a bug. */
	unsigned short		ti_flags;
	unsigned short		ti_count;
	struct list_head	ti_garbage;
};
/* ti_magic */
#define NILFS_TI_MAGIC		0xd9e392fb

/* ti_flags */
#define NILFS_TI_DYNAMIC_ALLOC	0x0001
#define NILFS_TI_SYNC		0x0002	/* Force to construct segment at the
					   end of transaction. */
#define NILFS_TI_GC		0x0004	/* GC context */
#define NILFS_TI_COMMIT		0x0008	/* Change happened or not */
#define NILFS_TI_WRITER		0x0010	/* Constructor context */

/**
 * struct nilfs_collection_stage - Context of collection stage
 * @main: Collection stage
 * @sub: Sub-stage in a file
 * @done: Flags to store completion status of each stage.
 * @started: Flags to store start status of each stage.
 * @dirty_file_ptr: Pointer on dirty_files list, or inode of a target file
 * @gc_inode_ptr: Pointer on the list of gc-inodes
 */
struct nilfs_collection_stage {
	char			main;
	char			sub;
	unsigned short		done;
	unsigned short		started;
	struct nilfs_inode_info *dirty_file_ptr;
	struct nilfs_inode_info *gc_inode_ptr;
};

/**
 * struct nilfs_sc_info - Segment constructor information
 * @sc_super: Back pointer to super_block struct
 * @sc_sbi: Back pointer to nilfs_sb_info struct
 * @sc_nblk_inc: Block count of current generation
 * @sc_dirty_files: List of files to be written
 * @sc_gc_inodes: List of GC inodes having blocks to be written
 * @sc_active_segments: List of active segments that were already written out
 * @sc_cleaning_segments: List of segments to be freed through construction
 * @sc_copied_buffers: List of copied buffers (buffer heads) to freeze data
 * @sc_segbufs: List of segment buffers
 * @sc_curseg: Current segment buffer
 * @sc_super_root: Pointer to the super root buffer
 * @sc_stage: Collection stage
 * @sc_finfo_ptr: pointer to the current finfo struct in the segment summary
 * @sc_binfo_ptr: pointer to the current binfo struct in the segment summary
 * @sc_blk_cnt:	Block count of a file
 * @sc_datablk_cnt: Data block count of a file
 * @sc_nblk_this_inc: Number of blocks included in the current logical segment
 * @sc_seg_ctime: Creation time
 * @sc_flags: Internal flags
 * @sc_sketch_inode: Inode of the sketch file
 * @sc_state_lock: spinlock for sc_state and so on
 * @sc_state: Segctord state flags
 * @sc_wait_request: Client request queue
 * @sc_wait_daemon: Daemon wait queue
 * @sc_wait_task: Start/end wait queue to control segctord task
 * @sc_seq_request: Request counter
 * @sc_seq_done: Completion counter
 * @sc_sync: Request of explicit sync operation
 * @sc_interval: Timeout value of background construction
 * @sc_mjcp_freq: Frequency of creating checkpoints
 * @sc_lseg_stime: Start time of the latest logical segment
 * @sc_watermark: Watermark for the number of dirty buffers
 * @sc_timer: Timer for segctord
 * @sc_task: current thread of segctord
 */
struct nilfs_sc_info {
	struct super_block     *sc_super;
	struct nilfs_sb_info   *sc_sbi;

	unsigned long		sc_nblk_inc;

	struct list_head	sc_dirty_files;
	struct list_head	sc_gc_inodes;
	struct list_head	sc_active_segments;
	struct list_head	sc_cleaning_segments;
	struct list_head	sc_copied_buffers;

	/* Segment buffers */
	struct list_head	sc_segbufs;
	struct nilfs_segment_buffer *sc_curseg;
	struct buffer_head     *sc_super_root;

	struct nilfs_collection_stage sc_stage;

	struct nilfs_segsum_pointer sc_finfo_ptr;
	struct nilfs_segsum_pointer sc_binfo_ptr;
	unsigned long		sc_blk_cnt;
	unsigned long		sc_datablk_cnt;
	unsigned long		sc_nblk_this_inc;
	time_t			sc_seg_ctime;

	unsigned long		sc_flags;

	/*
	 * Pointer to an inode of the sketch.
	 * This pointer is kept only while it contains data.
	 * We protect it with a semaphore of the segment constructor.
	 */
	struct inode	       *sc_sketch_inode;

	spinlock_t		sc_state_lock;
	unsigned long		sc_state;

	wait_queue_head_t	sc_wait_request;
	wait_queue_head_t	sc_wait_daemon;
	wait_queue_head_t	sc_wait_task;

	__u32			sc_seq_request;
	__u32			sc_seq_done;

	int			sc_sync;
	unsigned long		sc_interval;
	unsigned long		sc_mjcp_freq;
	unsigned long		sc_lseg_stime;	/* in 1/HZ seconds */
	unsigned long		sc_watermark;

	struct timer_list      *sc_timer;
	struct task_struct     *sc_task;
};

/* sc_flags */
enum {
	NILFS_SC_DIRTY,		/* One or more dirty meta-data blocks exist */
	NILFS_SC_UNCLOSED,	/* Logical segment is not closed */
	NILFS_SC_SUPER_ROOT,	/* The latest segment has a super root */
	NILFS_SC_GC_COPY,	/* Copying GC blocks */
};

/* sc_state */
#define NILFS_SEGCTOR_QUIT	    0x0001  /* segctord is being destroyed */
#define NILFS_SEGCTOR_INIT	    0x0002  /* segctord is being started */
#define NILFS_SEGCTOR_COMMIT	    0x0004  /* committed transaction exists */
#define NILFS_SEGCTOR_FLUSH_DATA    0x0010
#define NILFS_SEGCTOR_FLUSH_IFILE   0x0020
#define NILFS_SEGCTOR_FLUSH	    (NILFS_SEGCTOR_FLUSH_DATA | \
				     NILFS_SEGCTOR_FLUSH_IFILE)

/*
 * Constant parameters
 */
#define NILFS_SC_CLEANUP_RETRY	    3  /* Retry count of construction when
					  destroying segctord */

/*
 * Default values of timeout, in seconds.
 */
#define NILFS_SC_DEFAULT_TIMEOUT    5   /* Timeout value of dirty blocks.
					   It triggers construction of a
					   logical segment with a super root */
#define NILFS_SC_DEFAULT_SR_FREQ    30  /* Maximum frequency of super root
					   creation */
#define NILFS_SC_DEFAULT_SB_FREQ    30  /* Minimum interval of periodical
					   update of superblock (reserved) */

/*
 * The default threshold amount of data, in block counts.
 */
#define NILFS_SC_DEFAULT_WATERMARK  3600


/* segment.c */
extern int nilfs_init_transaction_cache(void);
extern void nilfs_destroy_transaction_cache(void);
extern int nilfs_transaction_begin(struct super_block *,
				   struct nilfs_transaction_info *, int);
extern int nilfs_transaction_end(struct super_block *, int);

extern int nilfs_set_file_dirty(struct nilfs_sb_info *, struct inode *,
				unsigned);
extern int nilfs_commit_dirty_file(struct inode *, unsigned);
extern void nilfs_dirty_inode(struct inode *);

extern int nilfs_construct_segment(struct super_block *);
extern int nilfs_construct_dsync_segment(struct super_block *,
					 struct inode *);
extern void nilfs_flush_segment(struct nilfs_sb_info *, ino_t);
extern int nilfs_clean_segments(struct super_block *, unsigned long);

extern int nilfs_segctor_add_segments_to_be_freed(struct nilfs_sc_info *,
						  nilfs_segnum_t *, size_t);
extern void nilfs_segctor_clear_segments_to_be_freed(struct nilfs_sc_info *);

extern int nilfs_attach_segment_constructor(struct nilfs_sb_info *,
					    struct nilfs_recovery_info *);
extern void nilfs_detach_segment_constructor(struct nilfs_sb_info *);

/* recovery.c */
extern int nilfs_read_super_root_block(struct super_block *, sector_t,
				       struct buffer_head **, int);
extern int nilfs_search_super_root(struct the_nilfs *, struct nilfs_sb_info *,
				   struct nilfs_recovery_info *);
extern int nilfs_recover_logical_segments(struct the_nilfs *,
					  struct nilfs_sb_info *,
					  struct nilfs_recovery_info *);


static inline struct nilfs_sc_info *NILFS_SC(struct nilfs_sb_info *sbi)
{
	return sbi->s_sc_info;
}

static inline void nilfs_set_transaction_flag(unsigned int flag)
{
	struct nilfs_transaction_info *ti = current->journal_info;

	BUG_ON(!ti);
	ti->ti_flags |= flag;
}

#if 0
static inline void nilfs_clear_transaction_flag(unsigned int flag)
{
	struct nilfs_transaction_info *ti = current->journal_info;

	BUG_ON(!ti);
	ti->ti_flags &= ~flag;
}
#endif

static inline int nilfs_test_transaction_flag(unsigned int flag)
{
	struct nilfs_transaction_info *ti = current->journal_info;

	if (ti == NULL || ti->ti_magic != NILFS_TI_MAGIC)
		return 0;
	return !!(ti->ti_flags & flag);
}

#endif /* _NILFS_SEGMENT_H */
