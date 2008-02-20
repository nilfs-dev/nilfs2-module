/*
 * ioctl.c - NILFS ioctl operations.
 *
 * Copyright (C) 2007-2008 Nippon Telegraph and Telephone Corporation.
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
 * Written by Koji Sato <koji@osrg.net>.
 */

#include <linux/fs.h>
#include <linux/wait.h>
#include <linux/smp_lock.h>	/* lock_kernel(), unlock_kernel() */
#include <linux/capability.h>	/* capable() */
#include <asm/uaccess.h>	/* copy_from_user(), copy_to_user() */
#include "nilfs.h"
#include "nilfs_fs.h"
#include "sb.h"
#include "bmap.h"
#include "cpfile.h"
#include "sufile.h"
#include "dat.h"


#define KMALLOC_SIZE_MIN	4096	/* 4KB */
#define KMALLOC_SIZE_MAX	131072	/* 128 KB */
static int nilfs_ioctl_wrap_copy(struct the_nilfs *nilfs,
				 struct nilfs_argv *argv, int dir,
				 ssize_t (*dofunc)(struct the_nilfs *,
						   int, int,
						   void *, size_t, size_t))
{
	void *buf;
	size_t ksize, maxmembs, total, n;
	ssize_t nr;
	int ret, i;

	if (argv->v_nmembs == 0)
		return 0;

	for (ksize = KMALLOC_SIZE_MAX; ksize >= KMALLOC_SIZE_MIN; ksize /= 2)
		if ((buf = kmalloc(ksize, GFP_NOFS)) != NULL)
			break;
	if (ksize < KMALLOC_SIZE_MIN)
		return -ENOMEM;
	maxmembs = ksize / argv->v_size;

	ret = 0;
	total = 0;
	for (i = 0; i < argv->v_nmembs; i += n) {
		n = (argv->v_nmembs - i < maxmembs) ?
			argv->v_nmembs - i : maxmembs;
		if ((dir & _IOC_WRITE) &&
		    copy_from_user(buf,
			    (void __user *)argv->v_base + argv->v_size * i,
			    argv->v_size * n)) {
			ret = -EFAULT;
			break;
		}
		if ((nr = (*dofunc)(nilfs, argv->v_index + i, argv->v_flags,
				    buf, argv->v_size, n)) < 0) {
			ret = nr;
			break;
		}
		if ((dir & _IOC_READ) &&
		    copy_to_user(
			    (void __user *)argv->v_base + argv->v_size * i,
			    buf, argv->v_size * nr)) {
			ret = -EFAULT;
			break;
		}
		total += nr;
	}
	argv->v_nmembs = total;

	kfree(buf);
	return ret;
}

static int
nilfs_ioctl_change_cpmode(struct inode *inode, struct file *filp,
			  unsigned int cmd, unsigned long arg)
{
	struct inode *cpfile;
	struct nilfs_transaction_info ti;
	struct nilfs_cpmode cpmode;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (copy_from_user(&cpmode, (struct nilfs_cpmode __user *)arg,
			   sizeof(struct nilfs_cpmode)))
		return -EFAULT;
	cpfile = NILFS_SB(inode->i_sb)->s_nilfs->ns_cpfile;
	if (nilfs_transaction_begin(inode->i_sb, &ti, 0))
		BUG();
	ret = nilfs_cpfile_change_cpmode(
		cpfile, cpmode.cm_cno, cpmode.cm_mode);
	if (nilfs_transaction_end(inode->i_sb, !ret))
		BUG();
	return ret;
}

static int
nilfs_ioctl_delete_checkpoint(struct inode *inode, struct file *filp,
			      unsigned int cmd, unsigned long arg)
{
	struct inode *cpfile;
	struct nilfs_transaction_info ti;
	nilfs_cno_t cno;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (copy_from_user(&cno, (nilfs_cno_t __user *)arg,
			   sizeof(nilfs_cno_t)))
		return -EFAULT;

	cpfile = NILFS_SB(inode->i_sb)->s_nilfs->ns_cpfile;
	if (nilfs_transaction_begin(inode->i_sb, &ti, 0))
		BUG();
	ret = nilfs_cpfile_delete_checkpoint(cpfile, cno);
	if (nilfs_transaction_end(inode->i_sb, !ret))
		BUG();
	return ret;
}

static ssize_t
nilfs_ioctl_do_get_cpinfo(struct the_nilfs *nilfs, int index, int flags,
			  void *buf, size_t size, size_t nmembs)
{
	struct inode *cpfile;
	struct nilfs_cpinfo *cpinfo;

	cpfile = nilfs->ns_cpfile;
	cpinfo = (struct nilfs_cpinfo *)buf;

	return nilfs_cpfile_get_cpinfo(cpfile, index, flags, cpinfo, nmembs);
}

static int nilfs_ioctl_get_cpinfo(struct inode *inode, struct file *filp,
				  unsigned int cmd, unsigned long arg)
{
	struct the_nilfs *nilfs;
	struct nilfs_argv argv;
	struct nilfs_transaction_info ti;
	int ret;

	nilfs = NILFS_SB(inode->i_sb)->s_nilfs;
	if (copy_from_user(&argv, (struct nilfs_argv __user *)arg,
			   sizeof(struct nilfs_argv)))
		return -EFAULT;

	if (nilfs_transaction_begin(inode->i_sb, &ti, 0))
		BUG();
	ret = nilfs_ioctl_wrap_copy(nilfs, &argv, _IOC_DIR(cmd),
				    nilfs_ioctl_do_get_cpinfo);
	if (nilfs_transaction_end(inode->i_sb, 0))
		BUG();

	if (copy_to_user((struct nilfs_argv __user *)arg,
			 &argv, sizeof(struct nilfs_argv)))
		ret = -EFAULT;

	return ret;
}

static int nilfs_ioctl_get_cpstat(struct inode *inode, struct file *filp,
				  unsigned int cmd, unsigned long arg)
{
	struct inode *cpfile;
	struct nilfs_cpstat cpstat;
	struct nilfs_transaction_info ti;
	int ret;

	cpfile = NILFS_SB(inode->i_sb)->s_nilfs->ns_cpfile;
	if (nilfs_transaction_begin(inode->i_sb, &ti, 0))
		BUG();
	ret = nilfs_cpfile_get_stat(cpfile, &cpstat);
	if (nilfs_transaction_end(inode->i_sb, 0))
		BUG();
	if (ret < 0)
		return ret;

	if (copy_to_user((struct nilfs_cpstat __user *)arg,
			 &cpstat, sizeof(struct nilfs_cpstat)))
		return -EFAULT;
	return 0;
}

static ssize_t
nilfs_ioctl_do_get_suinfo(struct the_nilfs *nilfs, int index, int flags,
			  void *buf, size_t size, size_t nmembs)
{
	struct inode *sufile;
	struct nilfs_suinfo *suinfo;

	sufile = nilfs->ns_sufile;
	suinfo = (struct nilfs_suinfo *)buf;

	return nilfs_sufile_get_suinfo(sufile, index, suinfo, nmembs);
}

static int nilfs_ioctl_get_suinfo(struct inode *inode, struct file *filp,
				  unsigned int cmd, unsigned long arg)
{
	struct the_nilfs *nilfs;
	struct nilfs_argv argv;
	struct nilfs_transaction_info ti;
	int ret;

	nilfs = NILFS_SB(inode->i_sb)->s_nilfs;
	if (copy_from_user(&argv, (struct nilfs_argv __user *)arg,
			   sizeof(struct nilfs_argv)))
		return -EFAULT;
	if (nilfs_transaction_begin(inode->i_sb, &ti, 0))
		BUG();
	ret = nilfs_ioctl_wrap_copy(nilfs, &argv, _IOC_DIR(cmd),
				    nilfs_ioctl_do_get_suinfo);
	if (nilfs_transaction_end(inode->i_sb, 0))
		BUG();

	if (copy_to_user((struct nilfs_argv __user *)arg,
			 &argv, sizeof(struct nilfs_argv)))
		ret = -EFAULT;
	return ret;
}

static int nilfs_ioctl_get_sustat(struct inode *inode, struct file *filp,
				  unsigned int cmd, unsigned long arg)
{
	struct inode *sufile;
	struct nilfs_sustat sustat;
	struct nilfs_transaction_info ti;
	int ret;

	sufile = NILFS_SB(inode->i_sb)->s_nilfs->ns_sufile;
	if (nilfs_transaction_begin(inode->i_sb, &ti, 0))
		BUG();
	ret = nilfs_sufile_get_stat(sufile, &sustat);
	if (nilfs_transaction_end(inode->i_sb, 0))
		BUG();
	if (ret < 0)
		return ret;

	if (copy_to_user((struct nilfs_sustat __user *)arg,
			 &sustat, sizeof(struct nilfs_sustat)))
		return -EFAULT;
	return 0;
}

static ssize_t
nilfs_ioctl_do_get_vinfo(struct the_nilfs *nilfs, int index, int flags,
			 void *buf, size_t size, size_t nmembs)
{
	struct inode *dat;
	struct nilfs_vinfo *vinfo;

	dat = nilfs_dat_inode(nilfs);
	vinfo = (struct nilfs_vinfo *)buf;

	return nilfs_dat_get_vinfo(dat, vinfo, nmembs);
}

static int nilfs_ioctl_get_vinfo(struct inode *inode, struct file *filp,
				 unsigned int cmd, unsigned long arg)
{
	struct the_nilfs *nilfs;
	struct nilfs_argv argv;
	struct nilfs_transaction_info ti;
	int ret;

	nilfs = NILFS_SB(inode->i_sb)->s_nilfs;
	if (copy_from_user(&argv, (struct nilfs_argv __user *)arg,
			   sizeof(struct nilfs_argv)))
		return -EFAULT;

	if (nilfs_transaction_begin(inode->i_sb, &ti, 0))
		BUG();
	ret = nilfs_ioctl_wrap_copy(nilfs, &argv, _IOC_DIR(cmd),
				    nilfs_ioctl_do_get_vinfo);
	if (nilfs_transaction_end(inode->i_sb, 0))
		BUG();

	if (copy_to_user((struct nilfs_argv __user *)arg,
			 &argv, sizeof(struct nilfs_argv)))
		ret = -EFAULT;
	return ret;
}

static ssize_t
nilfs_ioctl_do_get_bdescs(struct the_nilfs *nilfs, int index, int flags,
			  void *buf, size_t size, size_t nmembs)
{
	struct inode *dat;
	struct nilfs_bmap *bmap;
	struct nilfs_bdesc *bdescs;
	int ret, i;

	bdescs = (struct nilfs_bdesc *)buf;

	dat = nilfs_dat_inode(nilfs);
	bmap = NILFS_I(dat)->i_bmap;
	for (i = 0; i < nmembs; i++) {
		if ((ret = nilfs_bmap_lookup_at_level(bmap,
			     bdescs[i].bd_offset,
			     bdescs[i].bd_level + 1,
			     &bdescs[i].bd_blocknr)) < 0) {
			if (ret != -ENOENT)
				return ret;
			ret = 0;
			bdescs[i].bd_blocknr = 0;
		}
	}
	return nmembs;
}

static int nilfs_ioctl_get_bdescs(struct inode *inode, struct file *filp,
				  unsigned int cmd, unsigned long arg)
{
	struct the_nilfs *nilfs;
	struct nilfs_argv argv;
	struct nilfs_transaction_info ti;
	int ret;

	nilfs = NILFS_SB(inode->i_sb)->s_nilfs;
	if (copy_from_user(&argv, (struct nilfs_argv __user *)arg,
			   sizeof(struct nilfs_argv)))
		return -EFAULT;

	if (nilfs_transaction_begin(inode->i_sb, &ti, 0))
		BUG();
	ret = nilfs_ioctl_wrap_copy(nilfs, &argv, _IOC_DIR(cmd),
				    nilfs_ioctl_do_get_bdescs);
	if (nilfs_transaction_end(inode->i_sb, 0))
		BUG();

	if (copy_to_user((struct nilfs_argv __user *)arg,
			 &argv, sizeof(struct nilfs_argv)))
		ret = -EFAULT;
	return ret;
}

static int nilfs_ioctl_move_inode_block(struct inode *inode,
					struct nilfs_vdesc *vdesc)
{
	int ret;

	if (vdesc->vd_flags == 0) {
		if ((ret = nilfs_gccache_add_data(
			     inode,
			     vdesc->vd_offset,
			     vdesc->vd_blocknr,
			     vdesc->vd_vblocknr)) < 0) {
			if ((ret == -ENOENT) || (ret == -EEXIST)) {
				printk("%s: ino = %llu, cno = %llu, offset = %llu, blocknr = %llu, vblocknr = %llu\n",
				       __FUNCTION__,
				       (unsigned long long)vdesc->vd_ino,
				       (unsigned long long)vdesc->vd_cno,
				       (unsigned long long)vdesc->vd_offset,
				       (unsigned long long)vdesc->vd_blocknr,
				       (unsigned long long)vdesc->vd_vblocknr);
				BUG();
			}
			return ret;
		}
	} else {
		if ((ret = nilfs_gccache_add_node(
			     inode,
			     vdesc->vd_blocknr,
			     vdesc->vd_vblocknr)) < 0) {
			if (ret == -EEXIST) {
				printk("%s: ino = %llu, cno = %llu, blocknr = %llu, vblocknr = %llu\n",
				       __FUNCTION__,
				       (unsigned long long)vdesc->vd_ino,
				       (unsigned long long)vdesc->vd_cno,
				       (unsigned long long)vdesc->vd_blocknr,
				       (unsigned long long)vdesc->vd_vblocknr);
				BUG();
			}
			return ret;
		}
	}

	return 0;
}

static ssize_t
nilfs_ioctl_do_move_blocks(struct the_nilfs *nilfs, int index, int flags,
			   void *buf, size_t size, size_t nmembs)
{
	struct inode *inode;
	struct nilfs_vdesc *vdescs;
	ino_t ino;
	nilfs_cno_t cno;
	int i, j, n, ret;

	vdescs = (struct nilfs_vdesc *)buf;

	for (i = 0; i < nmembs; i += n) {
		ino = vdescs[i].vd_ino;
		cno = vdescs[i].vd_cno;
		if ((inode = nilfs_gc_iget(nilfs, ino, cno)) == NULL)
			return -ENOMEM;
		for (j = i, n = 0;
		     (j < nmembs) && (vdescs[j].vd_ino == ino) && (vdescs[j].vd_cno == cno);
		     j++, n++) {
			if ((ret = nilfs_ioctl_move_inode_block(
				     inode, &vdescs[j])) < 0)
				return ret;
		}
		/* XXX: nilfs_gc_iput() ??? */
	}

	return nmembs;
}

inline static int nilfs_ioctl_move_blocks(struct the_nilfs *nilfs,
					  struct nilfs_argv *argv,
					  int dir)
{
	return nilfs_ioctl_wrap_copy(nilfs, argv, dir,
				     nilfs_ioctl_do_move_blocks);
}

static ssize_t
nilfs_ioctl_do_delete_checkpoints(struct the_nilfs *nilfs, int index, int flags,
				  void *buf, size_t size, size_t nmembs)
{
	struct inode *cpfile;
	struct nilfs_period *periods;
	int ret, i;

	cpfile = nilfs->ns_cpfile;
	periods = (struct nilfs_period *)buf;

	for (i = 0; i < nmembs; i++)
		if ((ret = nilfs_cpfile_delete_checkpoints(cpfile,
			     periods[i].p_start, periods[i].p_end)) < 0)
			return ret;
	return nmembs;
}

inline static int nilfs_ioctl_delete_checkpoints(struct the_nilfs *nilfs,
						 struct nilfs_argv *argv,
						 int dir)
{
	return nilfs_ioctl_wrap_copy(nilfs, argv, dir,
				     nilfs_ioctl_do_delete_checkpoints);
}

static ssize_t
nilfs_ioctl_do_free_vblocknrs(struct the_nilfs *nilfs, int index, int flags,
			      void *buf, size_t size, size_t nmembs)
{
	struct inode *dat;
	nilfs_sector_t *vbns;
	int ret;

	dat = nilfs_dat_inode(nilfs);
	vbns = (nilfs_sector_t *)buf;

	if ((ret = nilfs_dat_freev(dat, vbns, nmembs)) < 0)
		return ret;
	return nmembs;
}

inline static int nilfs_ioctl_free_vblocknrs(struct the_nilfs *nilfs,
					     struct nilfs_argv *argv,
					     int dir)
{
	return nilfs_ioctl_wrap_copy(nilfs, argv, dir,
				     nilfs_ioctl_do_free_vblocknrs);
}

static ssize_t
nilfs_ioctl_do_mark_blocks_dirty(struct the_nilfs *nilfs, int index, int flags,
				 void *buf, size_t size, size_t nmembs)
{
	struct inode *dat;
	struct nilfs_bmap *bmap;
	struct nilfs_bdesc *bdescs;
	int ret, i;

	bdescs = (struct nilfs_bdesc *)buf;

	dat = nilfs_dat_inode(nilfs);
	bmap = NILFS_I(dat)->i_bmap;
	for (i = 0; i < nmembs; i++) {
		/* XXX: use macro or inline func to check liveness */
		if ((ret = nilfs_bmap_lookup_at_level(bmap,
			     bdescs[i].bd_offset,
			     bdescs[i].bd_level + 1,
			     &bdescs[i].bd_blocknr)) < 0) {
			if (ret != -ENOENT)
				return ret;
			ret = 0;
			bdescs[i].bd_blocknr = 0;
		}
		if (bdescs[i].bd_blocknr != bdescs[i].bd_oblocknr)
			/* skip dead block */
			continue;
		if (bdescs[i].bd_level == 0) {
			if ((ret = nilfs_mdt_mark_block_dirty(dat,
				     bdescs[i].bd_offset)) < 0) {
				BUG_ON(ret == -ENOENT);
				return ret;
			}
		} else {
			if ((ret = nilfs_bmap_mark(bmap,
				     bdescs[i].bd_offset,
				     bdescs[i].bd_level)) < 0) {
				BUG_ON(ret == -ENOENT);
				return ret;
			}
		}
	}

	return nmembs;
}

inline static int nilfs_ioctl_mark_blocks_dirty(struct the_nilfs *nilfs,
						struct nilfs_argv *argv,
						int dir)
{
	return nilfs_ioctl_wrap_copy(nilfs, argv, dir,
				     nilfs_ioctl_do_mark_blocks_dirty);
}

static ssize_t
nilfs_ioctl_do_free_segments(struct the_nilfs *nilfs, int index, int flags,
			     void *buf, size_t size, size_t nmembs)
{
	struct nilfs_sb_info *sbi;
	nilfs_segnum_t *segnums;
	int ret;

	segnums = (nilfs_segnum_t *)buf;

	sbi = nilfs_get_writer(nilfs);
	ret = nilfs_segctor_add_segments_to_be_freed(
		NILFS_SC(sbi), segnums, nmembs);
	nilfs_put_writer(nilfs);

	if (ret < 0)
		return ret;
	return nmembs;
}

inline static int nilfs_ioctl_free_segments(struct the_nilfs *nilfs,
					     struct nilfs_argv *argv,
					     int dir)
{
	return nilfs_ioctl_wrap_copy(nilfs, argv, dir,
				     nilfs_ioctl_do_free_segments);
}

int nilfs_ioctl_prepare_clean_segments(struct the_nilfs *nilfs,
				       unsigned long arg)
{
	struct nilfs_argv argv[5];
	int dir, ret;

	if (copy_from_user(argv, (struct nilfs_argv __user *)arg,
			   sizeof(struct nilfs_argv) * 5))
		return -EFAULT;

	dir = _IOC_WRITE;
	if ((ret = nilfs_ioctl_move_blocks(nilfs, &argv[0], dir)) < 0)
		goto out_move_blks;
	if ((ret = nilfs_ioctl_delete_checkpoints(nilfs, &argv[1], dir)) < 0)
		goto out_del_cps;
	if ((ret = nilfs_ioctl_free_vblocknrs(nilfs, &argv[2], dir)) < 0)
		goto out_free_vbns;
	if ((ret = nilfs_ioctl_mark_blocks_dirty(nilfs, &argv[3], dir)) < 0)
		goto out_free_vbns;
	if ((ret = nilfs_ioctl_free_segments(nilfs, &argv[4], dir)) < 0)
		goto out_free_segs;

	/* success */
	return 0;

	/* error */
 out_free_segs:
	/* XXX: not implemented yet */
	BUG();
 out_free_vbns:
	/* XXX: not implemented yet */
	BUG();
 out_del_cps:
	/* XXX: not implemented yet */
	BUG();
 out_move_blks:
	nilfs_remove_all_gcinode(nilfs);
	return ret;
}

static int nilfs_ioctl_clean_segments(struct inode *inode, struct file *filp,
				      unsigned int cmd, unsigned long arg)
{
	struct the_nilfs *nilfs;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	ret = nilfs_clean_segments(inode->i_sb, arg);
	nilfs = NILFS_SB(inode->i_sb)->s_nilfs;
	clear_nilfs_cond_nongc_write(nilfs);
	return ret;
}

static int nilfs_ioctl_test_cond(struct the_nilfs *nilfs, int cond)
{
	return ((cond & NILFS_TIMEDWAIT_SEG_WRITE) &&
		nilfs_cond_nongc_write(nilfs));
}

static void nilfs_ioctl_clear_cond(struct the_nilfs *nilfs, int cond)
{
	if (cond & NILFS_TIMEDWAIT_SEG_WRITE)
		clear_nilfs_cond_nongc_write(nilfs);
}

static int nilfs_ioctl_timedwait(struct inode *inode, struct file *filp,
				 unsigned int cmd, unsigned long arg)
{
	struct the_nilfs *nilfs;
	struct nilfs_wait_cond wc;
	long ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	nilfs = NILFS_SB(inode->i_sb)->s_nilfs;
	if (copy_from_user(&wc, (struct nilfs_wait_cond __user *)arg,
			   sizeof(struct nilfs_wait_cond)))
		return -EFAULT;

	unlock_kernel();
	ret = wc.wc_flags ?
		wait_event_interruptible_timeout(
			nilfs->ns_cleanerd_wq,
			nilfs_ioctl_test_cond(nilfs, wc.wc_cond),
			timespec_to_jiffies(&wc.wc_timeout)) :
		wait_event_interruptible(
			nilfs->ns_cleanerd_wq,
			nilfs_ioctl_test_cond(nilfs, wc.wc_cond));
	lock_kernel();
	nilfs_ioctl_clear_cond(nilfs, wc.wc_cond);

	if (ret > 0) {
		jiffies_to_timespec(ret, &wc.wc_timeout);
		if (copy_to_user((struct nilfs_wait_cond __user *)arg,
				 &wc, sizeof(struct nilfs_wait_cond)))
			return -EFAULT;
		return 0;
	} else if (ret == 0) {
		return wc.wc_flags ? -ETIME : 0;
	} else {
		return -EINTR;
	}
}

static int nilfs_ioctl_sync(struct inode *inode, struct file *filp,
			    unsigned int cmd, unsigned long arg)
{
	nilfs_cno_t cno;
	int ret;

	if ((ret = nilfs_construct_segment(inode->i_sb)) < 0)
		return ret;

	if ((nilfs_cno_t __user *)arg == NULL)
		return 0;
	cno = NILFS_SB(inode->i_sb)->s_nilfs->ns_cno - 1;
	if (copy_to_user((nilfs_cno_t __user *)arg, &cno, sizeof(nilfs_cno_t)))
		return -EFAULT;
	return 0;
}

#if 0
static int nilfs_ioctl_sync(struct inode *inode, struct file *filp,
			    unsigned int cmd, unsigned long arg)
{
	nilfs_cno_t cno;
	int ret;

	unlock_kernel();
	if ((ret = nilfs_construct_segment(inode->i_sb)) < 0)
		goto out;
	if ((nilfs_cno_t __user *)arg == NULL)
		goto out;
	cno = NILFS_SB(inode->i_sb)->s_nilfs->ns_cno - 1;
	if (copy_to_user((nilfs_cno_t __user *)arg, &cno, sizeof(nilfs_cno_t)))
		ret = -EFAULT;
 out:
	lock_kernel();
	return ret;
}
#endif

int nilfs_ioctl(struct inode *inode, struct file *filp,
		unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case NILFS_IOCTL_CHANGE_CPMODE:
		return nilfs_ioctl_change_cpmode(inode, filp, cmd, arg);
	case NILFS_IOCTL_DELETE_CHECKPOINT:
		return nilfs_ioctl_delete_checkpoint(inode, filp, cmd, arg);
	case NILFS_IOCTL_GET_CPINFO:
		return nilfs_ioctl_get_cpinfo(inode, filp, cmd, arg);
	case NILFS_IOCTL_GET_CPSTAT:
		return nilfs_ioctl_get_cpstat(inode, filp, cmd, arg);
	case NILFS_IOCTL_GET_SUINFO:
		return nilfs_ioctl_get_suinfo(inode, filp, cmd, arg);
	case NILFS_IOCTL_GET_SUSTAT:
		return nilfs_ioctl_get_sustat(inode, filp, cmd, arg);
	case NILFS_IOCTL_GET_VINFO:
		/* XXX: rename to ??? */
		return nilfs_ioctl_get_vinfo(inode, filp, cmd, arg);
	case NILFS_IOCTL_GET_BDESCS:
		return nilfs_ioctl_get_bdescs(inode, filp, cmd, arg);
	case NILFS_IOCTL_CLEAN_SEGMENTS:
		return nilfs_ioctl_clean_segments(inode, filp, cmd, arg);
	case NILFS_IOCTL_TIMEDWAIT:
		return nilfs_ioctl_timedwait(inode, filp, cmd, arg);
	case NILFS_IOCTL_SYNC:
		return nilfs_ioctl_sync(inode, filp, cmd, arg);
	default:
		return -ENOTTY;
	}
}

/* compat_ioctl */
#ifdef CONFIG_COMPAT
#include <linux/compat.h>

static int nilfs_compat_locked_ioctl(struct inode *inode, struct file *filp,
				     unsigned int cmd, unsigned long arg)
{
	int ret;

	lock_kernel();
	ret = nilfs_ioctl(inode, filp, cmd, arg);
	unlock_kernel();
	return ret;
}

static int
nilfs_compat_ioctl_uargv32_to_uargv(struct nilfs_argv32 __user *uargv32,
				    struct nilfs_argv __user *uargv)
{
	compat_uptr_t base;
	compat_size_t nmembs, size;
	compat_int_t index, flags;

	if (get_user(base, &uargv32->v_base) ||
	    put_user(compat_ptr(base), &uargv->v_base) ||
	    get_user(nmembs, &uargv32->v_nmembs) ||
	    put_user(nmembs, &uargv->v_nmembs) ||
	    get_user(size, &uargv32->v_size) ||
	    put_user(size, &uargv->v_size) ||
	    get_user(index, &uargv32->v_index) ||
	    put_user(index, &uargv->v_index) ||
	    get_user(flags, &uargv32->v_flags) ||
	    put_user(flags, &uargv->v_flags))
		return -EFAULT;
	return 0;
}

static int
nilfs_compat_ioctl_uargv_to_uargv32(struct nilfs_argv __user *uargv,
				    struct nilfs_argv32 __user *uargv32)
{
	size_t nmembs;

	if (get_user(nmembs, &uargv->v_nmembs) ||
	    put_user(nmembs, &uargv32->v_nmembs))
		return -EFAULT;
	return 0;
}

static int
nilfs_compat_ioctl_get_by_argv(struct inode *inode, struct file *filp,
			       unsigned int cmd, unsigned long arg)
{
	struct nilfs_argv __user *uargv;
	struct nilfs_argv32 __user *uargv32;
	int ret;

	uargv = compat_alloc_user_space(sizeof(struct nilfs_argv));
	uargv32 = compat_ptr(arg);
	if ((ret = nilfs_compat_ioctl_uargv32_to_uargv(uargv32, uargv)) < 0)
		return ret;

	if ((ret = nilfs_compat_locked_ioctl(inode, filp, cmd,
					     (unsigned long)uargv)) < 0)
		return ret;

	return nilfs_compat_ioctl_uargv_to_uargv32(uargv, uargv32);
}

static int
nilfs_compat_ioctl_change_cpmode(struct inode *inode, struct file *filp,
				 unsigned int cmd, unsigned long arg)
{
	struct nilfs_cpmode __user *ucpmode;
	struct nilfs_cpmode32 __user *ucpmode32;
	int mode;

	ucpmode = compat_alloc_user_space(sizeof(struct nilfs_cpmode));
	ucpmode32 = compat_ptr(arg);
	if (copy_in_user(&ucpmode->cm_cno, &ucpmode32->cm_cno,
			 sizeof(nilfs_cno_t)) ||
	    get_user(mode, &ucpmode32->cm_mode) ||
	    put_user(mode, &ucpmode->cm_mode))
		return -EFAULT;

	return nilfs_compat_locked_ioctl(
		inode, filp, cmd, (unsigned long)ucpmode);
}


inline static int
nilfs_compat_ioctl_delete_checkpoint(struct inode *inode, struct file *filp,
				     unsigned int cmd, unsigned long arg)
{
	return nilfs_compat_locked_ioctl(inode, filp, cmd, arg);
}

inline static int
nilfs_compat_ioctl_get_cpinfo(struct inode *inode, struct file *filp,
			      unsigned int cmd, unsigned long arg)
{
	return nilfs_compat_ioctl_get_by_argv(inode, filp, cmd, arg);
}

inline static int
nilfs_compat_ioctl_get_cpstat(struct inode *inode, struct file *filp,
			      unsigned int cmd, unsigned long arg)
{
	return nilfs_compat_locked_ioctl(inode, filp, cmd, arg);
}

inline static int
nilfs_compat_ioctl_get_suinfo(struct inode *inode, struct file *filp,
			      unsigned int cmd, unsigned long arg)
{
	return nilfs_compat_ioctl_get_by_argv(inode, filp, cmd, arg);
}

static int
nilfs_compat_ioctl_get_sustat(struct inode *inode, struct file *filp,
			      unsigned int cmd, unsigned long arg)
{
	struct nilfs_sustat __user *usustat;
	struct nilfs_sustat32 __user *usustat32;
	time_t ctime, nongc_ctime;
	int ret;

	usustat = compat_alloc_user_space(sizeof(struct nilfs_sustat));
	if ((ret = nilfs_compat_locked_ioctl(inode, filp, cmd,
					     (unsigned long)usustat)) < 0)
		return ret;

	usustat32 = compat_ptr(arg);
	if (copy_in_user(&usustat32->ss_nsegs, &usustat->ss_nsegs,
			 sizeof(__u64)) ||
	    copy_in_user(&usustat32->ss_ncleansegs, &usustat->ss_ncleansegs,
			 sizeof(__u64)) ||
	    copy_in_user(&usustat32->ss_ndirtysegs, &usustat->ss_ndirtysegs,
			 sizeof(__u64)) ||
	    get_user(ctime, &usustat->ss_ctime) ||
	    put_user(ctime, &usustat32->ss_ctime) ||
	    get_user(nongc_ctime, &usustat->ss_nongc_ctime) ||
	    put_user(nongc_ctime, &usustat32->ss_nongc_ctime))
		return -EFAULT;
	return 0;
}

inline static int
nilfs_compat_ioctl_get_vinfo(struct inode *inode, struct file *filp,
			      unsigned int cmd, unsigned long arg)
{
	return nilfs_compat_ioctl_get_by_argv(inode, filp, cmd, arg);
}

inline static int
nilfs_compat_ioctl_get_bdescs(struct inode *inode, struct file *filp,
			     unsigned int cmd, unsigned long arg)
{
	return nilfs_compat_ioctl_get_by_argv(inode, filp, cmd, arg);
}

static int
nilfs_compat_ioctl_clean_segments(struct inode *inode, struct file *filp,
				  unsigned int cmd, unsigned long arg)
{
	struct nilfs_argv __user *uargv;
	struct nilfs_argv32 __user *uargv32;
	int i, ret;

	uargv = compat_alloc_user_space(sizeof(struct nilfs_argv) * 5);
	uargv32 = compat_ptr(arg);
	for (i = 0; i < 5; i++)
		if ((ret = nilfs_compat_ioctl_uargv32_to_uargv(
			     &uargv32[i], &uargv[i])) < 0)
			return ret;

	return nilfs_compat_locked_ioctl(
		inode, filp, cmd, (unsigned long)uargv);
}

static int
nilfs_compat_ioctl_timedwait(struct inode *inode, struct file *filp,
			     unsigned int cmd, unsigned long arg)
{
	struct nilfs_wait_cond __user *uwcond;
	struct nilfs_wait_cond32 __user *uwcond32;
	struct timespec ts;
	int cond, flags, ret;

	uwcond = compat_alloc_user_space(sizeof(struct nilfs_wait_cond));
	uwcond32 = compat_ptr(arg);
	if (get_user(cond, &uwcond32->wc_cond) ||
	    put_user(cond, &uwcond->wc_cond) ||
	    get_user(flags, &uwcond32->wc_flags) ||
	    put_user(flags, &uwcond->wc_flags) ||
	    get_user(ts.tv_sec, &uwcond32->wc_timeout.tv_sec) ||
	    get_user(ts.tv_nsec, &uwcond32->wc_timeout.tv_nsec) ||
	    put_user(ts.tv_sec, &uwcond->wc_timeout.tv_sec) ||
	    put_user(ts.tv_nsec, &uwcond->wc_timeout.tv_nsec))
		return -EFAULT;

	if ((ret = nilfs_compat_locked_ioctl(
		     inode, filp, cmd, (unsigned long)uwcond)) < 0)
		return ret;

	if (get_user(ts.tv_sec, &uwcond->wc_timeout.tv_sec) ||
	    get_user(ts.tv_nsec, &uwcond->wc_timeout.tv_nsec) ||
	    put_user(ts.tv_sec, &uwcond32->wc_timeout.tv_sec) ||
	    put_user(ts.tv_nsec, &uwcond32->wc_timeout.tv_nsec))
		return -EFAULT;

	return 0;
}

static int nilfs_compat_ioctl_sync(struct inode *inode, struct file *filp,
				   unsigned int cmd, unsigned long arg)
{
	return nilfs_compat_locked_ioctl(inode, filp, cmd, arg);
}

long nilfs_compat_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct inode *inode;

	/* inode = filp->f_path.dentry->d_inode; */
	inode = filp->f_dentry->d_inode;

	switch (cmd) {
	case NILFS_IOCTL32_CHANGE_CPMODE:
		return nilfs_compat_ioctl_change_cpmode(
			inode, filp, NILFS_IOCTL_CHANGE_CPMODE, arg);
	case NILFS_IOCTL_DELETE_CHECKPOINT:
		return nilfs_compat_ioctl_delete_checkpoint(
			inode, filp, cmd, arg);
	case NILFS_IOCTL32_GET_CPINFO:
		return nilfs_compat_ioctl_get_cpinfo(
			inode, filp, NILFS_IOCTL_GET_CPINFO, arg);
	case NILFS_IOCTL_GET_CPSTAT:
		return nilfs_compat_ioctl_get_cpstat(inode, filp, cmd, arg);
	case NILFS_IOCTL32_GET_SUINFO:
		return nilfs_compat_ioctl_get_suinfo(
			inode, filp, NILFS_IOCTL_GET_SUINFO, arg);
	case NILFS_IOCTL32_GET_SUSTAT:
		return nilfs_compat_ioctl_get_sustat(
			inode, filp, NILFS_IOCTL_GET_SUSTAT, arg);
	case NILFS_IOCTL32_GET_VINFO:
		return nilfs_compat_ioctl_get_vinfo(
			inode, filp, NILFS_IOCTL_GET_VINFO, arg);
	case NILFS_IOCTL32_GET_BDESCS:
		return nilfs_compat_ioctl_get_bdescs(
			inode, filp, NILFS_IOCTL_GET_BDESCS, arg);
	case NILFS_IOCTL32_CLEAN_SEGMENTS:
		return nilfs_compat_ioctl_clean_segments(
			inode, filp, NILFS_IOCTL_CLEAN_SEGMENTS, arg);
	case NILFS_IOCTL32_TIMEDWAIT:
		return nilfs_compat_ioctl_timedwait(
			inode, filp, NILFS_IOCTL_TIMEDWAIT, arg);
	case NILFS_IOCTL_SYNC:
		return nilfs_compat_ioctl_sync(inode, filp, cmd, arg);
	default:
		return -ENOIOCTLCMD;
	}
}
#endif
