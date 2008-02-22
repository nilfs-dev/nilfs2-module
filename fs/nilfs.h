/*
 * nilfs.h - NILFS local header file.
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
 * Written by Koji Sato <koji@osrg.net>
 *            Ryusuke Konishi <ryusuke@osrg.net>
 */

#ifndef _NILFS_H
#define _NILFS_H

#include <linux/kernel.h>
#include <linux/buffer_head.h>
#include <linux/spinlock.h>
#include <linux/blkdev.h>
#include <linux/crc32.h>
#include "nilfs_fs.h"
#include "the_nilfs.h"
#include "sb.h"
#include "btnode.h"
#include "bmap.h"
#include "bmap_union.h"
#include "segment.h"
#include "kern_feature.h"

/*
 * NILFS filesystem version
 */
#define NILFS_VERSION		"2.0.0"

/*
 * nilfs inode data in memory
 */
struct nilfs_inode_info {
	__u32 i_flags;
	unsigned long  i_state;		/* Dynamic state flags */
	struct nilfs_bmap *i_bmap;
	union nilfs_bmap_union i_bmap_union;
	__u64 i_xattr;	/* sector_t ??? */
	__u32 i_dtime;
	__u32 i_dir_start_lookup;
	nilfs_cno_t	i_cno;		/* check point number for GC inode */
	struct nilfs_btnode_cache i_btnode_cache;
	struct list_head i_dirty;	/* List for connecting dirty files */

#ifdef CONFIG_NILFS_XATTR
	/*
	 * Extended attributes can be read independently of the main file
	 * data. Taking i_sem even when reading would cause contention
	 * between readers of EAs and writers of regular file data, so
	 * instead we synchronize on xattr_sem when reading or changing
	 * EAs.
	 */
	struct rw_semaphore xattr_sem;
#endif
#ifdef CONFIG_NILFS_POSIX_ACL
	struct posix_acl *i_acl;
	struct posix_acl *i_default_acl;
#endif
	struct buffer_head *i_bh;	/* i_bh contains a new or dirty
					   disk inode */
	struct inode vfs_inode;
};

static inline struct nilfs_inode_info *NILFS_I(const struct inode *inode)
{
	return container_of(inode, struct nilfs_inode_info, vfs_inode);
}

static inline struct nilfs_inode_info *
NILFS_BMAP_I(const struct nilfs_bmap *bmap)
{
	return container_of((union nilfs_bmap_union *)bmap,
			    struct nilfs_inode_info,
			    i_bmap_union);
}

static inline struct inode *NILFS_AS_I(struct address_space *mapping)
{
	return (mapping->host) ? :
		container_of(mapping, struct inode, i_data);
}

/*
 * Dynamic state flags of NILFS on-memory inode (i_state)
 */
enum {
	NILFS_I_NEW = 0,		/* Inode is newly created */
	NILFS_I_DIRTY,			/* The file is dirty */
	NILFS_I_QUEUED,			/* inode is in dirty_files list */
	NILFS_I_BUSY,			/* inode is grabbed by a segment
					   constructor */
	NILFS_I_COLLECTED,		/* All dirty blocks are collected */
	NILFS_I_UPDATED,		/* The file has been written back */
	NILFS_I_INODE_DIRTY,		/* write_inode is requested */
	NILFS_I_BMAP,			/* has bmap and btnode_cache */
	NILFS_I_GCINODE,		/* inode for GC, on memory only */
	NILFS_I_GCDAT,			/* shadow DAT, on memory only */
};

/*
 * Macros to check inode numbers
 */
#define NILFS_SYS_INO_BITS   \
  (unsigned int)(1 << NILFS_ROOT_INO | 1 << NILFS_DAT_INO |		\
		1 << NILFS_CPFILE_INO | 1 << NILFS_SUFILE_INO |		\
		1 << NILFS_IFILE_INO | 1 << NILFS_ATIME_INO |		\
		1 << NILFS_SKETCH_INO)

#define NILFS_VALID_INODE(sb, ino) \
  ((ino) >= NILFS_FIRST_INO(sb) || (NILFS_SYS_INO_BITS & (1 << (ino))))

/*
 * Extended buffer state bits
 */
enum {
	BH_Prepare_Dirty = BH_PrivateStart,
	BH_NILFS_Freeze,
	BH_NILFS_Allocated,
	BH_NILFS_Node,
	BH_NILFS_Volatile,
};

BUFFER_FNS(Prepare_Dirty, prepare_dirty)	/* prepare-dirty flag */
TAS_BUFFER_FNS(Prepare_Dirty, prepare_dirty)	/* prepare-dirty flag */
BUFFER_FNS(NILFS_Freeze, nilfs_freeze)		/* must freeze during
						   writeback */
BUFFER_FNS(NILFS_Allocated, nilfs_allocated)	/* nilfs private buffers */
BUFFER_FNS(NILFS_Node, nilfs_node)		/* nilfs node buffers */
BUFFER_FNS(NILFS_Volatile, nilfs_volatile)

#define NILFS_BUFFER_INHERENT_BITS  \
	((1UL << BH_Uptodate) | (1UL << BH_Mapped) | (1UL << BH_NILFS_Node) | \
	 (1UL << BH_NILFS_Volatile) | (1UL << BH_NILFS_Allocated))

/*
 * State of btnode buffers and pages:
 *    Buffer-dirty:    BH-dirty & !BH-pdirty
 *    Buffer-pdirty:   BH-dirty & BH-pdirty
 *    Page-dirty:      PageFlag-dirty & TAG-dirty
 *    Page-pdirty:     PageFlag-dirty & TAG-pdirty
 *
 *  - The pdirty-page has pdirty-buffers or clean-buffers, and has no
 *    dirty-buffers.
 *  - The dirty-page has at least one dirty buffer.  It can include
 *    pdirty-buffers or clean-buffers.
 */
static inline int nilfs_btnode_buffer_dirty(struct buffer_head *bh)
{
	return buffer_dirty(bh) && !buffer_prepare_dirty(bh);
}

static inline int nilfs_btnode_buffer_prepare_dirty(struct buffer_head *bh)
{
	return buffer_dirty(bh) && buffer_prepare_dirty(bh);
}

/*
 * debug primitives
 */
#include "debug.h"

/*
 * function prototype
 */
#ifdef CONFIG_NILFS_POSIX_ACL
#error "NILFS: not yet supported POSIX ACL"
extern int nilfs_permission(struct inode *, int, struct nameidata *);
extern int nilfs_acl_chmod(struct inode *);
extern int nilfs_init_acl(struct inode *, struct inode *);
#else
#define nilfs_permission   NULL

static inline int nilfs_acl_chmod(struct inode *inode)
{
	return 0;
}

static inline int nilfs_init_acl(struct inode *inode, struct inode *dir)
{
	inode->i_mode &= ~current->fs->umask;
	return 0;
}
#endif

/*
 * Macro of checksum calculation
 */
#define nilfs_crc32(seed, data, length)  crc32_le(seed, data, length)


/* dir.c */
extern int nilfs_add_link(struct dentry *, struct inode *);
extern ino_t nilfs_inode_by_name(struct inode *, struct dentry *);
extern int nilfs_make_empty(struct inode *, struct inode *);
extern struct nilfs_dir_entry *
nilfs_find_entry(struct inode *, struct dentry *, struct page **);
extern int nilfs_delete_entry(struct nilfs_dir_entry *, struct page *);
extern int nilfs_empty_dir(struct inode *);
extern struct nilfs_dir_entry *nilfs_dotdot(struct inode *, struct page **);
extern void nilfs_set_link(struct inode *, struct nilfs_dir_entry *,
			   struct page *, struct inode *);

/* file.c */
#define nilfs_release_file   NULL
extern int nilfs_sync_file(struct file *, struct dentry *, int);

/* ioctl.c */
int nilfs_ioctl(struct inode *, struct file *, unsigned int, unsigned long);
long nilfs_compat_ioctl(struct file *, unsigned int, unsigned long);
int nilfs_ioctl_prepare_clean_segments(struct the_nilfs *, unsigned long);

/* inode.c */
extern struct inode *nilfs_new_inode(struct inode *, int);
extern void nilfs_free_inode(struct inode *);
extern int nilfs_get_block(struct inode *, sector_t, struct buffer_head *, int);
extern void nilfs_set_inode_flags(struct inode *);
extern int nilfs_read_inode_common(struct inode *, struct nilfs_inode *);
extern void nilfs_write_inode_common(struct inode *, struct nilfs_inode *, int);
#if NEED_READ_INODE
extern void nilfs_read_inode(struct inode *);
#else
extern struct inode *nilfs_iget(struct super_block *, unsigned long);
#endif
extern void nilfs_update_inode(struct inode *, struct buffer_head *);
extern void nilfs_truncate(struct inode *);
extern void nilfs_delete_inode(struct inode *);
extern int nilfs_setattr(struct dentry *, struct iattr *);
extern int
nilfs_load_inode_block_nolock(struct nilfs_sb_info *, struct inode *,
			      struct buffer_head **);

/* super.c */
extern struct inode *nilfs_alloc_inode(struct super_block *);
extern void nilfs_destroy_inode(struct inode *);
extern void nilfs_error(struct super_block *, const char *, const char *, ...)
	__attribute__ ((format (printf, 3, 4)));
extern void nilfs_warning(struct super_block *, const char *, const char *, ...)
       __attribute__ ((format (printf, 3, 4)));
extern struct nilfs_super_block *
nilfs_load_super_block(struct super_block *, struct buffer_head **);
extern struct nilfs_super_block *
nilfs_reload_super_block(struct super_block *, struct buffer_head **, int);
extern int nilfs_store_magic_and_option(struct super_block *,
					struct nilfs_super_block *, char *);
extern void nilfs_update_last_segment(struct nilfs_sb_info *, int);
extern int nilfs_sync_super(struct nilfs_sb_info *);
extern int nilfs_commit_super(struct nilfs_sb_info *, int);
extern int nilfs_attach_checkpoint(struct nilfs_sb_info *, nilfs_cno_t);
extern void nilfs_detach_checkpoint(struct nilfs_sb_info *);

/* gcinode.c */
int nilfs_gccache_add_data(struct inode *, sector_t, sector_t, nilfs_sector_t);
int nilfs_gccache_add_node(struct inode *, sector_t, nilfs_sector_t);
int nilfs_init_gcinode(struct the_nilfs *);
void nilfs_destroy_gcinode(struct the_nilfs *);
void nilfs_clear_gcinode(struct inode *);
struct inode *nilfs_gc_iget(struct the_nilfs *, ino_t, nilfs_cno_t);
void nilfs_remove_all_gcinode(struct the_nilfs *);

/* gcdat.c */
int nilfs_init_gcdat_inode(struct the_nilfs *);
void nilfs_commit_gcdat_inode(struct the_nilfs *);
void nilfs_clear_gcdat_inode(struct the_nilfs *);

/* inode.c */
static inline int
nilfs_handle_bmap_error(int err, const char *fname, struct inode *inode,
			struct super_block *sb)
{
	if (err == -EINVAL)
		nilfs_error(sb, fname, "broken bmap (inode=%lu)\n",
			    inode->i_ino);
	return err;
}

static inline int
nilfs_load_inode_block(struct nilfs_sb_info *sbi, struct inode *inode,
		       struct buffer_head **pbh)
{
	int err;

	spin_lock(&sbi->s_inode_lock);
	err = nilfs_load_inode_block_nolock(sbi, inode, pbh);
	spin_unlock(&sbi->s_inode_lock);
	return err;
}

static inline int nilfs_file_dirty(struct inode *inode)
{
	struct nilfs_inode_info *ii = NILFS_I(inode);
	struct nilfs_sb_info *sbi = NILFS_SB(inode->i_sb);
	int ret = 0;

	if (!list_empty(&ii->i_dirty)) {
		spin_lock(&sbi->s_inode_lock);
		ret = test_bit(NILFS_I_DIRTY, &ii->i_state) ||
			test_bit(NILFS_I_BUSY, &ii->i_state);
		spin_unlock(&sbi->s_inode_lock);
	}
	return ret;
}

static inline int nilfs_prepare_file_dirty(struct inode *inode)
{
	if (is_bad_inode(inode)) {
		inode_debug(1, "tried to register bad_inode. ignored.\n");
		nilfs_dump_stack(NILFS_VERBOSE_INODE, 2);
		return -EIO;
	}
	return nilfs_transaction_begin(inode->i_sb, NULL, 1);
}

static inline void nilfs_cancel_file_dirty(struct inode *inode)
{
	nilfs_transaction_end(inode->i_sb, 0);
}


/*
 * Temporal definitions required for compiling
 */
static inline loff_t nilfs_btree_max_bits(void)  /* interim definition */
{
	return sizeof(nilfs_sector_t) * 8 /* CHAR_BIT */;
}

/* super.c */
static inline loff_t nilfs_max_file_blkbits(void)
{
	return sizeof(nilfs_blkoff_t) * 8 /* CHAR_BIT */;
}

static inline int nilfs_doing_gc(void)
{
	return nilfs_test_transaction_flag(NILFS_TI_GC);
}

static inline int nilfs_doing_construction(void)
{
	return nilfs_test_transaction_flag(NILFS_TI_WRITER);
}

static inline struct inode *nilfs_dat_inode(const struct the_nilfs *nilfs)
{
	return nilfs_doing_gc() ? nilfs->ns_gc_dat : nilfs->ns_dat;
}

static inline nilfs_cno_t
nilfs_get_checkpoint_number(struct nilfs_sb_info *sbi)
{
	return sbi->s_snapshot_cno ? : nilfs_last_cno(sbi->s_nilfs);
}

static inline int nilfs_writeback_super(struct nilfs_sb_info *sbi)
{
	return (sbi->s_super->s_dirt) ?
		nilfs_commit_super(sbi, 1) : nilfs_sync_super(sbi);
}

/*
 * Inodes and files operations
 */

/* dir.c */
extern struct file_operations nilfs_dir_operations;

/* file.c */
extern struct inode_operations nilfs_file_inode_operations;
extern struct file_operations nilfs_file_operations;

/* inode.c */
extern struct address_space_operations nilfs_aops;

/* namei.c */
extern struct inode_operations nilfs_dir_inode_operations;
extern struct inode_operations nilfs_special_inode_operations;
extern struct inode_operations nilfs_symlink_inode_operations;

/*
 * proc entry
 */
extern struct proc_dir_entry *nilfs_proc_root;


/*
 * filesystem type
 */
extern struct file_system_type nilfs_fs_type;


#endif	/* _NILFS_H */
