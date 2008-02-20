/*
 * cpfile.c - NILFS checkpoint file.
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
 * cpfile.c,v 1.33 2007-10-19 01:19:51 koji Exp
 *
 * Written by Koji Sato <koji@osrg.net>.
 */

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/buffer_head.h>
#include <linux/errno.h>
#include "nilfs_fs.h"
#include "nilfs_types.h"
#include "mdt.h"
#include "cpfile.h"


inline static unsigned long
nilfs_cpfile_checkpoints_per_block(const struct inode *cpfile)
{
	return (1UL << cpfile->i_blkbits) / sizeof(struct nilfs_checkpoint);
}

/* block number from the beginning of the file */
inline static nilfs_blkoff_t
nilfs_cpfile_get_blkoff(const struct inode *cpfile, nilfs_cno_t cno)
{
	nilfs_cno_t tcno;

	/* checkpoint number 0 is invalid */
	BUG_ON(cno == 0);
	tcno = cno + NILFS_CPFILE_FIRST_CHECKPOINT_OFFSET - 1;
	do_div(tcno, nilfs_cpfile_checkpoints_per_block(cpfile));
	return (nilfs_blkoff_t)tcno;
}

/* offset in block */
inline static unsigned long
nilfs_cpfile_get_offset(const struct inode *cpfile, nilfs_cno_t cno)
{
	nilfs_cno_t tcno;

	tcno = cno + NILFS_CPFILE_FIRST_CHECKPOINT_OFFSET - 1;
	return do_div(tcno, nilfs_cpfile_checkpoints_per_block(cpfile));
}

inline static unsigned long
nilfs_cpfile_checkpoints_in_block(const struct inode *cpfile,
				  nilfs_cno_t curr,
				  nilfs_cno_t max)
{
	return min_t(nilfs_cno_t,
		     nilfs_cpfile_checkpoints_per_block(cpfile) -
		     nilfs_cpfile_get_offset(cpfile, curr),
		     max - curr);
}

inline static int nilfs_cpfile_is_in_first(const struct inode *cpfile,
					   nilfs_cno_t cno)
{
	return nilfs_cpfile_get_blkoff(cpfile, cno) == 0;
}

static unsigned int
nilfs_cpfile_block_add_valid_checkpoints(const struct inode *cpfile,
					 struct buffer_head *bh,
					 void *kaddr,
					 unsigned int n)
{
	struct nilfs_checkpoint *cp;
	unsigned int count;

	cp = (struct nilfs_checkpoint *)(kaddr + bh_offset(bh));
	count = le32_to_cpu(cp->cp_checkpoints_count) + n;
	cp->cp_checkpoints_count = cpu_to_le32(count);
	return count;
}

static unsigned int
nilfs_cpfile_block_sub_valid_checkpoints(const struct inode *cpfile,
					 struct buffer_head *bh,
					 void *kaddr,
					 unsigned int n)
{
	struct nilfs_checkpoint *cp;
	unsigned int count;

	cp = (struct nilfs_checkpoint *)(kaddr + bh_offset(bh));
	BUG_ON(le32_to_cpu(cp->cp_checkpoints_count) < n);
	count = le32_to_cpu(cp->cp_checkpoints_count) - n;
	cp->cp_checkpoints_count = cpu_to_le32(count);
	return count;
}

inline static struct nilfs_cpfile_header *
nilfs_cpfile_block_get_header(const struct inode *cpfile,
			      struct buffer_head *bh,
			      void *kaddr)
{
	return (struct nilfs_cpfile_header *)(kaddr + bh_offset(bh));
}

inline static struct nilfs_checkpoint *
nilfs_cpfile_block_get_checkpoint(const struct inode *cpfile,
				  nilfs_cno_t cno,
				  struct buffer_head *bh,
				  void *kaddr)
{
	return (struct nilfs_checkpoint *)(kaddr + bh_offset(bh)) +
		nilfs_cpfile_get_offset(cpfile, cno);
}

static void nilfs_cpfile_block_init(struct inode *cpfile,
				    struct buffer_head *bh,
				    void *kaddr)
{
	struct nilfs_checkpoint *cp;
	int i;

	memset(kaddr + bh_offset(bh), 0, 1UL << cpfile->i_blkbits);
	for (i = 0, cp = (struct nilfs_checkpoint *)(kaddr + bh_offset(bh));
	     i < nilfs_cpfile_checkpoints_per_block(cpfile);
	     i++, cp++)
		nilfs_checkpoint_set_invalid(cp);
}

static int nilfs_cpfile_get_block(struct inode *cpfile,
				  nilfs_blkoff_t blkoff,
				  int create,
				  struct buffer_head **bhp)
{
	struct buffer_head *bh;
	int ret;

	if ((ret = nilfs_mdt_read_block(cpfile, blkoff, &bh)) < 0) {
		if ((ret != -ENOENT) || !create)
			return ret;
		/* first block must be allocated by mkfs.nilfs */
		BUG_ON(blkoff == 0);
		if ((ret = nilfs_mdt_create_block(cpfile, blkoff, &bh,
						  nilfs_cpfile_block_init)) < 0)
			return ret;
	}

	BUG_ON(bhp == NULL);
	*bhp = bh;
	return ret;
}

inline static int nilfs_cpfile_get_header_block(struct inode *cpfile,
						struct buffer_head **bhp)
{
	return nilfs_cpfile_get_block(cpfile, 0, 0, bhp);
}

inline static int nilfs_cpfile_get_checkpoint_block(struct inode *cpfile,
						    nilfs_cno_t cno,
						    int create,
						    struct buffer_head **bhp)
{
	return nilfs_cpfile_get_block(cpfile,
				      nilfs_cpfile_get_blkoff(cpfile, cno),
				      create,
				      bhp);
}

inline static int nilfs_cpfile_delete_checkpoint_block(struct inode *cpfile,
						       nilfs_cno_t cno)
{
	return nilfs_mdt_delete_block(cpfile,
				      nilfs_cpfile_get_blkoff(cpfile, cno));
}

inline static unsigned long
nilfs_cpfile_header_add_checkpoints(const struct inode *cpfile,
				    struct nilfs_cpfile_header *header,
				    unsigned long n)
{
	unsigned long ns;

	ns = le64_to_cpu(header->ch_ncheckpoints) + n;
	header->ch_ncheckpoints = cpu_to_le64(ns);
	return ns;
}

inline static unsigned long
nilfs_cpfile_header_sub_checkpoints(const struct inode *cpfile,
				    struct nilfs_cpfile_header *header,
				    unsigned long n)
{
	unsigned long ns;

	BUG_ON(le64_to_cpu(header->ch_ncheckpoints) < n);
	ns = le64_to_cpu(header->ch_ncheckpoints) - n;
	header->ch_ncheckpoints = cpu_to_le64(ns);
	return ns;
}

inline static unsigned long
nilfs_cpfile_header_add_snapshots(const struct inode *cpfile,
				  struct nilfs_cpfile_header *header,
				  unsigned long n)
{
	unsigned long ns;

	ns = le64_to_cpu(header->ch_nsnapshots) + n;
	header->ch_nsnapshots = cpu_to_le64(ns);
	return ns;
}

inline static unsigned long
nilfs_cpfile_header_sub_snapshots(const struct inode *cpfile,
				  struct nilfs_cpfile_header *header,
				  unsigned long n)
{
	unsigned long ns;

	BUG_ON(le64_to_cpu(header->ch_nsnapshots) < n);
	ns = le64_to_cpu(header->ch_nsnapshots) - n;
	header->ch_nsnapshots = cpu_to_le64(ns);
	return ns;
}

/**
 * nilfs_cpfile_get_checkpoint - get a checkpoint
 * @cpfile: inode of checkpoint file
 * @cno: checkpoint number
 * @create: create flag
 * @cpp: pointer to a checkpoint
 * @bhp: pointer to a buffer head
 *
 * Description: nilfs_cpfile_get_checkpoint() acquires the checkpoint
 * specified by @cno. A new checkpoint will be created if @cno is the current
 * checkpoint number and @create is nonzero.
 *
 * Return Value: On success, 0 is returned, and the checkpoint and the
 * buffer head of the buffer on which the checkpoint is located are stored in
 * the place pointed by @cpp and @bhp, respectively. On error, one of the
 * following negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 *
 * %-ENOENT - No such checkpoint.
 */
int nilfs_cpfile_get_checkpoint(struct inode *cpfile,
				nilfs_cno_t cno,
				int create,
				struct nilfs_checkpoint **cpp,
				struct buffer_head **bhp)
{
	struct buffer_head *header_bh, *cp_bh;
	struct nilfs_cpfile_header *header;
	struct nilfs_checkpoint *cp;
	void *kaddr;
	int ret;

	BUG_ON((cno < 1) ||
	       (cno > nilfs_mdt_cno(cpfile)) ||
	       ((cno < nilfs_mdt_cno(cpfile)) && create));

	down_write(&NILFS_MDT(cpfile)->mi_sem);

	if ((ret = nilfs_cpfile_get_header_block(cpfile, &header_bh)) < 0)
		goto out_sem;

	if ((ret = nilfs_cpfile_get_checkpoint_block(cpfile, cno, create, &cp_bh)) < 0)
		goto out_header;
	kaddr = kmap(cp_bh->b_page);
	cp = nilfs_cpfile_block_get_checkpoint(cpfile, cno, cp_bh, kaddr);
	if (nilfs_checkpoint_invalid(cp)) {
		if (!create) {
			kunmap(cp_bh->b_page);
			brelse(cp_bh);
			ret = -ENOENT;
			goto out_header;
		}
		/* a newly-created checkpoint */
		nilfs_checkpoint_clear_invalid(cp);
		if (!nilfs_cpfile_is_in_first(cpfile, cno))
			nilfs_cpfile_block_add_valid_checkpoints(cpfile, cp_bh, kaddr, 1);
		nilfs_mdt_mark_buffer_dirty(cp_bh);

		kaddr = kmap_atomic(header_bh->b_page, KM_USER0);
		header = nilfs_cpfile_block_get_header(cpfile, header_bh, kaddr);
		nilfs_cpfile_header_add_checkpoints(cpfile, header, 1);
		kunmap_atomic(kaddr, KM_USER0);
		nilfs_mdt_mark_buffer_dirty(header_bh);

		nilfs_mdt_mark_dirty(cpfile);
	}

	if (cpp != NULL)
		*cpp = cp;
	BUG_ON(bhp == NULL);
	*bhp = cp_bh;

 out_header:
	brelse(header_bh);
	
 out_sem:
	up_write(&NILFS_MDT(cpfile)->mi_sem);
	return ret;
}

/**
 * nilfs_cpfile_put_checkpoint - put a checkpoint
 * @cpfile: inode of checkpoint file
 * @cno: checkpoint number
 * @bh: buffer head
 *
 * Description: nilfs_cpfile_put_checkpoint() releases the checkpoint
 * specified by @cno. @bh must be the buffer head which has been returned by
 * a previous call to nilfs_cpfile_get_checkpoint() with @cno.
 */
void nilfs_cpfile_put_checkpoint(struct inode *cpfile,
				 nilfs_cno_t cno,
				 struct buffer_head *bh)
{
	/* XXX: must check cno */
	kunmap(bh->b_page);
	brelse(bh);
}

/**
 * nilfs_cpfile_delete_checkpoints - delete checkpoints
 * @cpfile: inode of checkpoint file
 * @start: start checkpoint number
 * @end: end checkpoint numer
 *
 * Description: nilfs_cpfile_delete_checkpoints() deletes the checkpoints in
 * the period from @start to @end, excluding @end itself. The checkpoints
 * which have been already deleted are ignored.
 *
 * Return Value: On success, 0 is returned. On error, one of the following
 * negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 *
 * %-EINVAL - invalid checkpoints.
 */
int nilfs_cpfile_delete_checkpoints(struct inode *cpfile,
				    nilfs_cno_t start,
				    nilfs_cno_t end)
{
	struct buffer_head *header_bh, *cp_bh;
	struct nilfs_cpfile_header *header;
	struct nilfs_checkpoint *cp;
	nilfs_cno_t cno;
	void *kaddr;
	unsigned long tnicps;
	int ret, ncps, nicps, count, i;

	if ((start == 0) || (start > end)) {
		printk("%s: start = %llu, end = %llu\n",
		       __FUNCTION__,
		       (unsigned long long)start,
		       (unsigned long long)end);
		BUG();
	}

	/* cannot delete the latest checkpoint */
	if (start == nilfs_mdt_cno(cpfile) - 1)
		return -EPERM;

	down_write(&NILFS_MDT(cpfile)->mi_sem);

	if ((ret = nilfs_cpfile_get_header_block(cpfile, &header_bh)) < 0)
		goto out_sem;
	tnicps = 0;

	for (cno = start; cno < end; cno += ncps) {
		ncps = nilfs_cpfile_checkpoints_in_block(cpfile, cno, end);
		if ((ret = nilfs_cpfile_get_checkpoint_block(
			     cpfile, cno, 0, &cp_bh)) < 0) {
			if (ret != -ENOENT)
				goto out_sem;
			/* skip hole */
			ret = 0;
			continue;
		}

		kaddr = kmap_atomic(cp_bh->b_page, KM_USER0);
		cp = nilfs_cpfile_block_get_checkpoint(
			cpfile, cno, cp_bh, kaddr);
		nicps = 0;
		for (i = 0; i < ncps; i++, cp++) {
			BUG_ON(nilfs_checkpoint_snapshot(cp));
			if (!nilfs_checkpoint_invalid(cp)) {
				nilfs_checkpoint_set_invalid(cp);
				nicps++;
			}
		}
		if (nicps > 0) {
			tnicps += nicps;
			nilfs_mdt_mark_buffer_dirty(cp_bh);
			nilfs_mdt_mark_dirty(cpfile);
			if (!nilfs_cpfile_is_in_first(cpfile, cno) &&
			    ((count = nilfs_cpfile_block_sub_valid_checkpoints(
				      cpfile, cp_bh, kaddr, nicps)) == 0)) {
				/* make hole */
				kunmap_atomic(kaddr, KM_USER0);
				brelse(cp_bh);
				if ((ret = nilfs_cpfile_delete_checkpoint_block(
					     cpfile, cno)) < 0) {
					printk("%s: cannot delete block\n",
					       __FUNCTION__);
					goto out_sem;
				}
				continue;
			}
		}

		kunmap_atomic(kaddr, KM_USER0);
		brelse(cp_bh);
	}

	if (tnicps > 0) {
		kaddr = kmap_atomic(header_bh->b_page, KM_USER0);
		header = nilfs_cpfile_block_get_header(cpfile, header_bh, kaddr);
		nilfs_cpfile_header_sub_checkpoints(cpfile, header, tnicps);
		nilfs_mdt_mark_buffer_dirty(header_bh);
		nilfs_mdt_mark_dirty(cpfile);
		kunmap_atomic(kaddr, KM_USER0);
	}
	brelse(header_bh);

 out_sem:
	up_write(&NILFS_MDT(cpfile)->mi_sem);
	return ret;
}

/**
 * nilfs_cpfile_get_checkpoints -
 * @cpfile: inode of checkpoint file
 * @cno: checkpoint number to start looking
 * @cps: array of checkpoint
 * @size: size of checkpoint array
 *
 * Description:
 *
 * Return Value: On success, 0 is returned and .... On error, one of the
 * following negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 */
int nilfs_cpfile_get_checkpoints(struct inode *cpfile,
				 nilfs_cno_t cno,
				 struct nilfs_checkpoint *cps,
				 unsigned long *size)
{
	struct nilfs_checkpoint *cp;
	struct buffer_head *bh;
	void *kaddr;
	unsigned long n;
	int ncps, ret, i;

	down_read(&NILFS_MDT(cpfile)->mi_sem);

	ret = 0;
	for (n = 0; (cno < nilfs_mdt_cno(cpfile)) && (n < *size); cno += ncps) {
		ncps = nilfs_cpfile_checkpoints_in_block(cpfile, cno, nilfs_mdt_cno(cpfile));
		if ((ret = nilfs_cpfile_get_checkpoint_block(cpfile, cno, 0, &bh)) < 0) {
			if (ret != -ENOENT)
				goto out;
			/* skip hole */
			continue;
		}

		kaddr = kmap_atomic(bh->b_page, KM_USER0);
		cp = nilfs_cpfile_block_get_checkpoint(cpfile, cno, bh, kaddr);
		for (i = 0; (i < ncps) && (n < *size); i++, cp++) {
			if (!nilfs_checkpoint_invalid(cp))
				cps[n++] = *cp;	/* copy structure */
		}
		kunmap_atomic(kaddr, KM_USER0);
		brelse(bh);
	}

 out:
	*size = n;

	up_read(&NILFS_MDT(cpfile)->mi_sem);
	return ret;
}

static void nilfs_cpfile_checkpoint_to_cpinfo(struct inode *cpfile,
					      struct nilfs_checkpoint *cp,
					      struct nilfs_cpinfo *ci)
{
	ci->ci_flags = le32_to_cpu(cp->cp_flags);
	ci->ci_cno = le64_to_cpu(cp->cp_cno);
	ci->ci_create = le64_to_cpu(cp->cp_create);
	ci->ci_nblk_inc = le64_to_cpu(cp->cp_nblk_inc);
	ci->ci_inodes_count = le64_to_cpu(cp->cp_inodes_count);
	ci->ci_blocks_count = le64_to_cpu(cp->cp_blocks_count);
	ci->ci_next = le64_to_cpu(cp->cp_snapshot_list.ssl_next);
}

static ssize_t
nilfs_cpfile_do_get_cpinfo(struct inode *cpfile, nilfs_cno_t cno,
			   struct nilfs_cpinfo *ci, size_t nci)
{
	struct nilfs_checkpoint *cp;
	struct buffer_head *bh;
	void *kaddr;
	int n, ret;
	int ncps, i;

	down_read(&NILFS_MDT(cpfile)->mi_sem);

	for (n = 0; (cno < nilfs_mdt_cno(cpfile)) && (n < nci); cno += ncps) {
		ncps = nilfs_cpfile_checkpoints_in_block(
			cpfile, cno, nilfs_mdt_cno(cpfile));
		if ((ret = nilfs_cpfile_get_checkpoint_block(
			     cpfile, cno, 0, &bh)) < 0) {
			if (ret != -ENOENT)
				goto out;
			/* skip hole */
			continue;
		}

		kaddr = kmap_atomic(bh->b_page, KM_USER0);
		cp = nilfs_cpfile_block_get_checkpoint(cpfile, cno, bh, kaddr);
		for (i = 0; (i < ncps) && (n < nci); i++, cp++) {
			if (!nilfs_checkpoint_invalid(cp))
				nilfs_cpfile_checkpoint_to_cpinfo(
					cpfile, cp, &ci[n++]);
		}
		kunmap_atomic(kaddr, KM_USER0);
		brelse(bh);
	}

	ret = n;

 out:
	up_read(&NILFS_MDT(cpfile)->mi_sem);
	return ret;
}

static ssize_t
nilfs_cpfile_do_get_ssinfo(struct inode *cpfile, nilfs_cno_t cno,
			   struct nilfs_cpinfo *ci, size_t nci)
{
	struct buffer_head *bh;
	struct nilfs_cpfile_header *header;
	struct nilfs_checkpoint *cp;
	nilfs_cno_t curr, next;
	nilfs_blkoff_t curr_blkoff, next_blkoff;
	void *kaddr;
	int n, ret;

	down_read(&NILFS_MDT(cpfile)->mi_sem);

	if (cno == 0) {
		if ((ret = nilfs_cpfile_get_header_block(cpfile, &bh)) < 0)
			goto out;
		kaddr = kmap_atomic(bh->b_page, KM_USER0);
		header = nilfs_cpfile_block_get_header(cpfile, bh, kaddr);
		curr = le64_to_cpu(header->ch_snapshot_list.ssl_next);
		kunmap_atomic(kaddr, KM_USER0);
		brelse(bh);
		if (curr == 0) {
			ret = 0;
			goto out;
		}
	} else
		curr = cno;
	curr_blkoff = nilfs_cpfile_get_blkoff(cpfile, curr);
	if ((ret = nilfs_cpfile_get_checkpoint_block(cpfile, curr, 0, &bh)) < 0)
		goto out;
	kaddr = kmap_atomic(bh->b_page, KM_USER0);
	for (n = 0; n < nci; n++) {
		cp = nilfs_cpfile_block_get_checkpoint(
			cpfile, curr, bh, kaddr);
		nilfs_cpfile_checkpoint_to_cpinfo(cpfile, cp, &ci[n]);
		if ((next = le64_to_cpu(cp->cp_snapshot_list.ssl_next)) == 0) {
			curr = next;
			n++;
			break;
		}
		next_blkoff = nilfs_cpfile_get_blkoff(cpfile, next);
		if (curr_blkoff != next_blkoff) {
			kunmap_atomic(kaddr, KM_USER0);
			brelse(bh);
			if ((ret = nilfs_cpfile_get_checkpoint_block(
				     cpfile, next, 0, &bh)) < 0)
				goto out;
			kaddr = kmap_atomic(bh->b_page, KM_USER0);
		}
		curr = next;
		curr_blkoff = next_blkoff;
	}
	kunmap_atomic(kaddr, KM_USER0);
	brelse(bh);
	ret = n;

 out:
	up_read(&NILFS_MDT(cpfile)->mi_sem);
	return ret;
}

/**
 * nilfs_cpfile_get_cpinfo -
 * @cpfile:
 * @cno:
 * @ci:
 * @nci:
 */
ssize_t nilfs_cpfile_get_cpinfo(struct inode *cpfile,
				nilfs_cno_t cno, int mode,
				struct nilfs_cpinfo *ci, size_t nci)
{
	switch (mode) {
	case NILFS_CHECKPOINT:
		return nilfs_cpfile_do_get_cpinfo(cpfile, cno, ci, nci);
	case NILFS_SNAPSHOT:
		return nilfs_cpfile_do_get_ssinfo(cpfile, cno, ci, nci);
	default:
		return -EINVAL;
	}
}

/**
 * nilfs_cpfile_delete_checkpoint -
 * @cpfile:
 * @cno:
 */
int nilfs_cpfile_delete_checkpoint(struct inode *cpfile, nilfs_cno_t cno)
{
	struct nilfs_cpinfo ci;
	ssize_t nci;
	int ret;

	/* checkpoint number 0 is invalid */
	if (cno == 0)
		return -ENOENT;
	if ((nci = nilfs_cpfile_do_get_cpinfo(cpfile, cno, &ci, 1)) < 0)
		return nci;
	else if ((nci == 0) || (ci.ci_cno != cno))
		return -ENOENT;

	/* cannot delete the latest checkpoint nor snapshots */
	if ((ret = nilfs_cpinfo_snapshot(&ci)) < 0)
		return ret;
	else if ((ret > 0) || (cno == nilfs_mdt_cno(cpfile) - 1))
		return -EPERM;

	return nilfs_cpfile_delete_checkpoints(cpfile, cno, cno + 1);
}

static struct nilfs_snapshot_list *
nilfs_cpfile_block_get_snapshot_list(const struct inode *cpfile,
				     nilfs_cno_t cno,
				     struct buffer_head *bh,
				     void *kaddr)
{
	struct nilfs_cpfile_header *header;
	struct nilfs_checkpoint *cp;
	struct nilfs_snapshot_list *list;

	if (cno != 0) {
		cp = nilfs_cpfile_block_get_checkpoint(cpfile, cno, bh, kaddr);
		list = &cp->cp_snapshot_list;
	} else {
		header = nilfs_cpfile_block_get_header(cpfile, bh, kaddr);
		list = &header->ch_snapshot_list;
	}
	return list;
}

static int nilfs_cpfile_set_snapshot(struct inode *cpfile, nilfs_cno_t cno)
{
	struct buffer_head *header_bh, *curr_bh, *prev_bh, *cp_bh;
	struct nilfs_cpfile_header *header;
	struct nilfs_checkpoint *cp;
	struct nilfs_snapshot_list *list;
	nilfs_cno_t curr, prev;
	nilfs_blkoff_t curr_blkoff, prev_blkoff;
	void *kaddr;
	int ret;

	down_write(&NILFS_MDT(cpfile)->mi_sem);

	if ((ret = nilfs_cpfile_get_checkpoint_block(
		     cpfile, cno, 0, &cp_bh)) < 0)
		goto out_sem;
	kaddr = kmap_atomic(cp_bh->b_page, KM_USER0);
	cp = nilfs_cpfile_block_get_checkpoint(cpfile, cno, cp_bh, kaddr);
	if (nilfs_checkpoint_invalid(cp)) {
		ret = -ENOENT;
		kunmap_atomic(kaddr, KM_USER0);
		goto out_cp;
	}
	if (nilfs_checkpoint_snapshot(cp)) {
		ret = 0;
		kunmap_atomic(kaddr, KM_USER0);
		goto out_cp;
	}
	kunmap_atomic(kaddr, KM_USER0);

	if ((ret = nilfs_cpfile_get_header_block(cpfile, &header_bh)) < 0)
		goto out_cp;
	kaddr = kmap_atomic(header_bh->b_page, KM_USER0);
	header = nilfs_cpfile_block_get_header(cpfile, header_bh, kaddr);
	list = &header->ch_snapshot_list;
	curr_bh = header_bh;
	get_bh(curr_bh);
	curr = 0;
	curr_blkoff = 0;
	prev = le64_to_cpu(list->ssl_prev);
	while (prev > cno) {
		prev_blkoff = nilfs_cpfile_get_blkoff(cpfile, prev);
		curr = prev;
		if (curr_blkoff != prev_blkoff) {
			kunmap_atomic(kaddr, KM_USER0);
			brelse(curr_bh);
			if ((ret = nilfs_cpfile_get_checkpoint_block(
				     cpfile, curr, 0, &curr_bh)) < 0)
				goto out_header;
			kaddr = kmap_atomic(curr_bh->b_page, KM_USER0);
		}
		curr_blkoff = prev_blkoff;
		cp = nilfs_cpfile_block_get_checkpoint(
			cpfile, curr, curr_bh, kaddr);
		list = &cp->cp_snapshot_list;
		prev = le64_to_cpu(list->ssl_prev);
	}
	kunmap_atomic(kaddr, KM_USER0);

	if (prev != 0) {
		if ((ret = nilfs_cpfile_get_checkpoint_block(
			     cpfile, prev, 0, &prev_bh)) < 0)
			goto out_curr;
	} else {
		prev_bh = header_bh;
		get_bh(prev_bh);
	}

	kaddr = kmap_atomic(curr_bh->b_page, KM_USER0);
	list = nilfs_cpfile_block_get_snapshot_list(
		cpfile, curr, curr_bh, kaddr);
	list->ssl_prev = cpu_to_le64(cno);
	kunmap_atomic(kaddr, KM_USER0);

	kaddr = kmap_atomic(cp_bh->b_page, KM_USER0);
	cp = nilfs_cpfile_block_get_checkpoint(cpfile, cno, cp_bh, kaddr);
	cp->cp_snapshot_list.ssl_next = cpu_to_le64(curr);
	cp->cp_snapshot_list.ssl_prev = cpu_to_le64(prev);
	nilfs_checkpoint_set_snapshot(cp);
	kunmap_atomic(kaddr, KM_USER0);

	kaddr = kmap_atomic(prev_bh->b_page, KM_USER0);
	list = nilfs_cpfile_block_get_snapshot_list(
		cpfile, prev, prev_bh, kaddr);
	list->ssl_next = cpu_to_le64(cno);
	kunmap_atomic(kaddr, KM_USER0);

	kaddr = kmap_atomic(header_bh->b_page, KM_USER0);
	header = nilfs_cpfile_block_get_header(cpfile, header_bh, kaddr);
	nilfs_cpfile_header_add_snapshots(cpfile, header, 1);
	kunmap_atomic(kaddr, KM_USER0);

	nilfs_mdt_mark_buffer_dirty(prev_bh);
	nilfs_mdt_mark_buffer_dirty(curr_bh);
	nilfs_mdt_mark_buffer_dirty(cp_bh);
	nilfs_mdt_mark_buffer_dirty(header_bh);
	nilfs_mdt_mark_dirty(cpfile);
	
	brelse(prev_bh);

 out_curr:
	brelse(curr_bh);

 out_header:
	brelse(header_bh);

 out_cp:
	brelse(cp_bh);

 out_sem:
	up_write(&NILFS_MDT(cpfile)->mi_sem);
	return ret;
}

static int nilfs_cpfile_clear_snapshot(struct inode *cpfile, nilfs_cno_t cno)
{
	struct buffer_head *header_bh, *next_bh, *prev_bh, *cp_bh;
	struct nilfs_cpfile_header *header;
	struct nilfs_checkpoint *cp;
	struct nilfs_snapshot_list *list;
	nilfs_cno_t next, prev;
	void *kaddr;
	int ret;

	down_write(&NILFS_MDT(cpfile)->mi_sem);

	if ((ret = nilfs_cpfile_get_checkpoint_block(
		     cpfile, cno, 0, &cp_bh)) < 0)
		goto out_sem;
	kaddr = kmap_atomic(cp_bh->b_page, KM_USER0);
	cp = nilfs_cpfile_block_get_checkpoint(cpfile, cno, cp_bh, kaddr);
	if (nilfs_checkpoint_invalid(cp)) {
		ret = -ENOENT;
		kunmap_atomic(kaddr, KM_USER0);
		goto out_cp;
	}
	if (!nilfs_checkpoint_snapshot(cp)) {
		ret = 0;
		kunmap_atomic(kaddr, KM_USER0);
		goto out_cp;
	}

	list = &cp->cp_snapshot_list;
	next = le64_to_cpu(list->ssl_next);
	prev = le64_to_cpu(list->ssl_prev);
	kunmap_atomic(kaddr, KM_USER0);

	if ((ret = nilfs_cpfile_get_header_block(cpfile, &header_bh)) < 0)
		goto out_cp;
	if (next != 0) {
		if ((ret = nilfs_cpfile_get_checkpoint_block(
			     cpfile, next, 0, &next_bh)) < 0)
			goto out_header;
	} else {
		next_bh = header_bh;
		get_bh(next_bh);
	}
	if (prev != 0) {
		if ((ret = nilfs_cpfile_get_checkpoint_block(
			     cpfile, prev, 0, &prev_bh)) < 0)
			goto out_next;
	} else {
		prev_bh = header_bh;
		get_bh(prev_bh);
	}

	kaddr = kmap_atomic(next_bh->b_page, KM_USER0);
	list = nilfs_cpfile_block_get_snapshot_list(
		cpfile, next, next_bh, kaddr);
	list->ssl_prev = cpu_to_le64(prev);
	kunmap_atomic(kaddr, KM_USER0);

	kaddr = kmap_atomic(prev_bh->b_page, KM_USER0);
	list = nilfs_cpfile_block_get_snapshot_list(
		cpfile, prev, prev_bh, kaddr);
	list->ssl_next = cpu_to_le64(next);
	kunmap_atomic(kaddr, KM_USER0);

	kaddr = kmap_atomic(cp_bh->b_page, KM_USER0);
	cp = nilfs_cpfile_block_get_checkpoint(cpfile, cno, cp_bh, kaddr);
	cp->cp_snapshot_list.ssl_next = cpu_to_le64(0);
	cp->cp_snapshot_list.ssl_prev = cpu_to_le64(0);
	nilfs_checkpoint_clear_snapshot(cp);
	kunmap_atomic(kaddr, KM_USER0);

	kaddr = kmap_atomic(header_bh->b_page, KM_USER0);
	header = nilfs_cpfile_block_get_header(cpfile, header_bh, kaddr);
	nilfs_cpfile_header_sub_snapshots(cpfile, header, 1);
	kunmap_atomic(kaddr, KM_USER0);

	nilfs_mdt_mark_buffer_dirty(next_bh);
	nilfs_mdt_mark_buffer_dirty(prev_bh);
	nilfs_mdt_mark_buffer_dirty(cp_bh);
	nilfs_mdt_mark_buffer_dirty(header_bh);
	nilfs_mdt_mark_dirty(cpfile);

	brelse(prev_bh);

 out_next:
	brelse(next_bh);

 out_header:
	brelse(header_bh);

 out_cp:
	brelse(cp_bh);

 out_sem:
	up_write(&NILFS_MDT(cpfile)->mi_sem);
	return ret;
}

/**
 * nilfs_cpfile_is_snapshot -
 * @cpfile: inode of checkpoint file
 * @cno: checkpoint number
 *
 * Description:
 *
 * Return Value: On success, 1 is returned if the checkpoint specified by
 * @cno is a snapshot, or 0 if not. On error, one of the following negative
 * error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 *
 * %-ENOENT - No such checkpoint.
 */
int nilfs_cpfile_is_snapshot(struct inode *cpfile, nilfs_cno_t cno)
{
	struct buffer_head *bh;
	struct nilfs_checkpoint *cp;
	void *kaddr;
	int ret;

	down_read(&NILFS_MDT(cpfile)->mi_sem);

	if ((ret = nilfs_cpfile_get_checkpoint_block(cpfile, cno, 0, &bh)) < 0)
		goto out;
	kaddr = kmap_atomic(bh->b_page, KM_USER0);
	cp = nilfs_cpfile_block_get_checkpoint(cpfile, cno, bh, kaddr);
	ret = nilfs_checkpoint_snapshot(cp);
	kunmap_atomic(kaddr, KM_USER0);
	brelse(bh);

 out:
	up_read(&NILFS_MDT(cpfile)->mi_sem);
	return ret;
}

/**
 * nilfs_cpfile_change_cpmode - change checkpoint mode
 * @cpfile: inode of checkpoint file
 * @cno: checkpoint number
 * @status: mode of checkpoint
 *
 * Description: nilfs_change_cpmode() changes the mode of the checkpoint
 * specified by @cno. The mode @mode is NILFS_CHECKPOINT or NILFS_SNAPSHOT.
 *
 * Return Value: On success, 0 is returned. On error, one of the following
 * negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 *
 * %-ENOENT - No such checkpoint.
 */
int nilfs_cpfile_change_cpmode(struct inode *cpfile, nilfs_cno_t cno, int mode)
{
	struct the_nilfs *nilfs;
	int ret;

	nilfs = NILFS_MDT(cpfile)->mi_nilfs;

	switch (mode) {
	case NILFS_CHECKPOINT:
		/*
		 * Check for protecting existing snapshot mounts:
		 * bd_mount_sem is used to make this operation atomic and
		 * exclusive with a new mount job.  Though it doesn't cover
		 * umount, it's enough for the purpose.
		 */
		nilfs_lock_bdev(nilfs->ns_bdev);
		if (nilfs_checkpoint_is_mounted(nilfs, cno, 1)) {
			/* Current implementation does not have to protect
			   plain read-only mounts since they are exclusive
			   with a read/write mount and are protected from the
			   cleaner. */
			ret = -EBUSY;
		} else
			ret = nilfs_cpfile_clear_snapshot(cpfile, cno);
		nilfs_unlock_bdev(nilfs->ns_bdev);
		return ret;
	case NILFS_SNAPSHOT:
		return nilfs_cpfile_set_snapshot(cpfile, cno);
	default:
		return -EINVAL;
	}
}

/**
 * nilfs_cpfile_get_stat - get checkpoint statistics
 * @cpfile: inode of checkpoint file
 * @stat: pointer to a structure of checkpoint statistics
 *
 * Description: nilfs_cpfile_get_stat() returns information about checkpoints.
 *
 * Return Value: On success, 0 is returned, and checkpoints information is
 * stored in the place pointed by @stat. On error, one of the following
 * negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 */
int nilfs_cpfile_get_stat(struct inode *cpfile, struct nilfs_cpstat *cpstat)
{
	struct buffer_head *bh;
	struct nilfs_cpfile_header *header;
	void *kaddr;
	int ret;

	down_read(&NILFS_MDT(cpfile)->mi_sem);

	if ((ret = nilfs_cpfile_get_header_block(cpfile, &bh)) < 0)
		goto out_sem;
	kaddr = kmap_atomic(bh->b_page, KM_USER0);
	header = nilfs_cpfile_block_get_header(cpfile, bh, kaddr);
	cpstat->cs_cno = nilfs_mdt_cno(cpfile);
	cpstat->cs_ncps = le64_to_cpu(header->ch_ncheckpoints);
	cpstat->cs_nsss = le64_to_cpu(header->ch_nsnapshots);
	kunmap_atomic(kaddr, KM_USER0);
	brelse(bh);

 out_sem:
	up_read(&NILFS_MDT(cpfile)->mi_sem);
	return ret;
}

/**
 * nilfs_cpfile_get_snapshots -
 * @cpfile: inode of checkpoint file
 * @snapshots: array of checkpoint number
 * @size: size of snapshots array
 * @next: checkpoint number of next snapshot
 *
 * Description:
 *
 * Return Value: On success, 0 is returned and .... On error, one of the
 * following negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 */
int nilfs_cpfile_get_snapshots(struct inode *cpfile,
			       nilfs_cno_t *snapshots,
			       unsigned long *size,
			       nilfs_cno_t *cno)
{
	struct buffer_head *bh;
	struct nilfs_cpfile_header *header;
	struct nilfs_checkpoint *cp;
	nilfs_cno_t curr, next;
	nilfs_blkoff_t curr_blkoff, next_blkoff;
	void *kaddr;
	unsigned long n;
	int ret;

	BUG_ON((size == NULL) || (cno == NULL));

	down_write(&NILFS_MDT(cpfile)->mi_sem);

	if (*cno == 0) {
		if ((ret = nilfs_cpfile_get_header_block(cpfile, &bh)) < 0)
			goto out_sem;
		kaddr = kmap_atomic(bh->b_page, KM_USER0);
		header = nilfs_cpfile_block_get_header(cpfile, bh, kaddr);
		curr = le64_to_cpu(header->ch_snapshot_list.ssl_next);
		kunmap_atomic(kaddr, KM_USER0);
		brelse(bh);
		if (curr == 0) {
			n = 0;
			goto out_assign;
		}
	} else
		curr = *cno;
	curr_blkoff = nilfs_cpfile_get_blkoff(cpfile, curr);
	if ((ret = nilfs_cpfile_get_checkpoint_block(cpfile, curr, 0, &bh)) < 0)
		goto out_sem;
	kaddr = kmap_atomic(bh->b_page, KM_USER0);
	for (n = 0; n < *size; n++) {
		snapshots[n] = curr;

		cp = nilfs_cpfile_block_get_checkpoint(cpfile, curr, bh, kaddr);
		if ((next = le64_to_cpu(cp->cp_snapshot_list.ssl_next)) == 0) {
			curr = next;
			n++;
			break;
		}
		next_blkoff = nilfs_cpfile_get_blkoff(cpfile, next);
		if (curr_blkoff != next_blkoff) {
			kunmap_atomic(kaddr, KM_USER0);
			brelse(bh);
			if ((ret = nilfs_cpfile_get_checkpoint_block(cpfile, next, 0, &bh)) < 0)
				goto out_sem;
			kaddr = kmap_atomic(bh->b_page, KM_USER0);
		}
		curr = next;
		curr_blkoff = next_blkoff;
	}
	kunmap_atomic(kaddr, KM_USER0);
	brelse(bh);

 out_assign:
	*size = n;
	*cno = curr;

 out_sem:
	up_write(&NILFS_MDT(cpfile)->mi_sem);
	return ret;
}
