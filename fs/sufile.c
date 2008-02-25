/*
 * sufile.c - NILFS segment usage file.
 *
 * Copyright (C) 2006-2008 Nippon Telegraph and Telephone Corporation.
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

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/buffer_head.h>
#include <linux/errno.h>
#include "nilfs_fs.h"
#include "nilfs_types.h"
#include "mdt.h"
#include "sufile.h"


static inline unsigned long
nilfs_sufile_segment_usages_per_block(const struct inode *sufile)
{
	return (1UL << sufile->i_blkbits) / sizeof(struct nilfs_segment_usage);
}

static inline nilfs_blkoff_t
nilfs_sufile_get_blkoff(const struct inode *sufile, nilfs_segnum_t segnum)
{
	nilfs_segnum_t t;

	t = segnum + NILFS_SUFILE_FIRST_SEGMENT_USAGE_OFFSET;
	do_div(t, nilfs_sufile_segment_usages_per_block(sufile));
	return (nilfs_blkoff_t)t;
}

static inline unsigned long
nilfs_sufile_get_offset(const struct inode *sufile, nilfs_segnum_t segnum)
{
	nilfs_segnum_t t;

	t = segnum + NILFS_SUFILE_FIRST_SEGMENT_USAGE_OFFSET;
	return do_div(t, nilfs_sufile_segment_usages_per_block(sufile));
}

static inline unsigned long
nilfs_sufile_segment_usages_in_block(const struct inode *sufile,
				     nilfs_segnum_t curr,
				     nilfs_segnum_t max)
{
	return min_t(unsigned long,
		     nilfs_sufile_segment_usages_per_block(sufile) -
		     nilfs_sufile_get_offset(sufile, curr),
		     max - curr + 1);
}

static inline struct nilfs_sufile_header *
nilfs_sufile_block_get_header(const struct inode *sufile,
			      struct buffer_head *bh,
			      void *kaddr)
{
	return (struct nilfs_sufile_header *)(kaddr + bh_offset(bh));
}

static inline struct nilfs_segment_usage *
nilfs_sufile_block_get_segment_usage(const struct inode *sufile,
				     nilfs_segnum_t segnum,
				     struct buffer_head *bh,
				     void *kaddr)
{
	return (struct nilfs_segment_usage *)(kaddr + bh_offset(bh)) +
		nilfs_sufile_get_offset(sufile, segnum);
}

static int nilfs_sufile_get_block(struct inode *sufile,
				  nilfs_blkoff_t blkoff,
				  int create,
				  struct buffer_head **bhp)
{
	struct buffer_head *bh;
	int ret;

	ret = nilfs_mdt_read_block(sufile, blkoff, &bh);
	if (ret < 0) {
		if ((ret != -ENOENT) || !create)
			return ret;
		/* first block must be allocated by mkfs.nilfs */
		BUG_ON(blkoff == 0);
		ret = nilfs_mdt_create_block(sufile, blkoff, &bh, NULL);
		if (ret < 0)
			return ret;
	}

	BUG_ON(bhp == NULL);
	*bhp = bh;
	return ret;
}

static inline int nilfs_sufile_get_header_block(struct inode *sufile,
						struct buffer_head **bhp)
{
	return nilfs_sufile_get_block(sufile, 0, 0, bhp);
}

static inline int
nilfs_sufile_get_segment_usage_block(struct inode *sufile,
				     nilfs_segnum_t segnum,
				     int create,
				     struct buffer_head **bhp)
{
	return nilfs_sufile_get_block(sufile,
				      nilfs_sufile_get_blkoff(sufile, segnum),
				      create,
				      bhp);
}

/**
 * nilfs_sufile_alloc - allocate a segment
 * @sufile: inode of segment usage file
 * @segnump: pointer to segment number
 *
 * Description: nilfs_sufile_alloc() allocates a clean segment.
 *
 * Return Value: On success, 0 is returned and the segment number of the
 * allocated segment is stored in the place pointed by @segnump. On error, one
 * of the following negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 *
 * %-ENOSPC - No clean segment left.
 */
int nilfs_sufile_alloc(struct inode *sufile, nilfs_segnum_t *segnump)
{
	struct buffer_head *header_bh, *su_bh;
	struct the_nilfs *nilfs;
	struct nilfs_sufile_header *header;
	struct nilfs_segment_usage *su;
	nilfs_segnum_t segnum, maxsegnum, last_alloc;
	void *kaddr;
	unsigned long nsegments, ncleansegs, nsus;
	int ret, i, j;

	down_write(&NILFS_MDT(sufile)->mi_sem);

	nilfs = NILFS_MDT(sufile)->mi_nilfs;

	ret = nilfs_sufile_get_header_block(sufile, &header_bh);
	if (ret < 0)
		goto out_sem;
	kaddr = kmap_atomic(header_bh->b_page, KM_USER0);
	header = nilfs_sufile_block_get_header(sufile, header_bh, kaddr);
	ncleansegs = le64_to_cpu(header->sh_ncleansegs);
	last_alloc = le64_to_cpu(header->sh_last_alloc);
	kunmap_atomic(kaddr, KM_USER0);

	nsegments = nilfs_sufile_get_nsegments(sufile);
	segnum = last_alloc + 1;
	maxsegnum = nsegments - 1;
	for (i = 0; i < nsegments; i += nsus) {
		if (segnum >= nsegments) {
			/* wrap around */
			segnum = 0;
			maxsegnum = last_alloc;
		}
		ret = nilfs_sufile_get_segment_usage_block(sufile, segnum, 1,
							   &su_bh);
		if (ret < 0)
			goto out_header;
		kaddr = kmap_atomic(su_bh->b_page, KM_USER0);
		su = nilfs_sufile_block_get_segment_usage(
			sufile, segnum, su_bh, kaddr);

		nsus = nilfs_sufile_segment_usages_in_block(
			sufile, segnum, maxsegnum);
		for (j = 0; j < nsus; j++, su++, segnum++) {
			if (nilfs_segment_usage_clean(su)) {
				/* found a clean segment */
				nilfs_segment_usage_set_active(su);
				nilfs_segment_usage_set_dirty(su);
				kunmap_atomic(kaddr, KM_USER0);

				kaddr = kmap_atomic(header_bh->b_page,
						    KM_USER0);
				header = nilfs_sufile_block_get_header(
					sufile, header_bh, kaddr);
				header->sh_ncleansegs = cpu_to_le64(
					le64_to_cpu(header->sh_ncleansegs) - 1);
				header->sh_ndirtysegs =	cpu_to_le64(
					le64_to_cpu(header->sh_ndirtysegs) + 1);
				header->sh_last_alloc = cpu_to_le64(segnum);
				kunmap_atomic(kaddr, KM_USER0);

				nilfs_mdt_mark_buffer_dirty(header_bh);
				nilfs_mdt_mark_buffer_dirty(su_bh);
				nilfs_mdt_mark_dirty(sufile);
				brelse(su_bh);
				BUG_ON(segnump == NULL);
				*segnump = segnum;
				goto out_header;
			}
		}

		kunmap_atomic(kaddr, KM_USER0);
		brelse(su_bh);
	}

	/* no segments left */
	ret = -ENOSPC;

 out_header:
	brelse(header_bh);

 out_sem:
	up_write(&NILFS_MDT(sufile)->mi_sem);
	return ret;
}

/**
 * nilfs_sufile_cancel_free -
 * @sufile: inode of segment usage file
 * @segnum: segment number
 *
 * Description:
 *
 * Return Value: On success, 0 is returned. On error, one of the following
 * negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 */
int nilfs_sufile_cancel_free(struct inode *sufile, nilfs_segnum_t segnum)
{
	struct buffer_head *header_bh, *su_bh;
	struct the_nilfs *nilfs;
	struct nilfs_sufile_header *header;
	struct nilfs_segment_usage *su;
	void *kaddr;
	unsigned long ncleansegs, ndirtysegs;
	int ret;

	down_write(&NILFS_MDT(sufile)->mi_sem);

	nilfs = NILFS_MDT(sufile)->mi_nilfs;

	ret = nilfs_sufile_get_header_block(sufile, &header_bh);
	if (ret < 0)
		goto out_sem;

	ret = nilfs_sufile_get_segment_usage_block(sufile, segnum, 0, &su_bh);
	if (ret < 0)
		goto out_header;

	kaddr = kmap_atomic(su_bh->b_page, KM_USER0);
	su = nilfs_sufile_block_get_segment_usage(
		sufile, segnum, su_bh, kaddr);
	if (!nilfs_segment_usage_clean(su)) {
		printk(KERN_CRIT "%s: segment %llu must be clean\n",
		       __FUNCTION__, (unsigned long long)segnum);
		BUG();
	}
	nilfs_segment_usage_set_dirty(su);
	kunmap_atomic(kaddr, KM_USER0);

	kaddr = kmap_atomic(header_bh->b_page, KM_USER0);
	header = nilfs_sufile_block_get_header(sufile, header_bh, kaddr);
	ncleansegs = le64_to_cpu(header->sh_ncleansegs) - 1;
	ndirtysegs = le64_to_cpu(header->sh_ndirtysegs) + 1;
	header->sh_ncleansegs =	cpu_to_le64(ncleansegs);
	header->sh_ndirtysegs =	cpu_to_le64(ndirtysegs);
	kunmap_atomic(kaddr, KM_USER0);

	nilfs_mdt_mark_buffer_dirty(header_bh);
	nilfs_mdt_mark_buffer_dirty(su_bh);
	nilfs_mdt_mark_dirty(sufile);

	brelse(su_bh);

 out_header:
	brelse(header_bh);

 out_sem:
	up_write(&NILFS_MDT(sufile)->mi_sem);
	return ret;
}

/**
 * nilfs_sufile_freev - free segments
 * @sufile: inode of segment usage file
 * @segnum: array of segment numbers
 * @nsegs: number of segments
 *
 * Description: nilfs_sufile_freev() frees segments specified by @segnum and
 * @nsegs, which must have been returned by a previous call to
 * nilfs_sufile_alloc().
 *
 * Return Value: On success, 0 is returned. On error, one of the following
 * negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 */
#define NILFS_SUFILE_FREEV_PREALLOC	16
int nilfs_sufile_freev(struct inode *sufile,
		       nilfs_segnum_t *segnum, size_t nsegs)
{
	struct buffer_head *header_bh, **su_bh,
		*su_bh_prealloc[NILFS_SUFILE_FREEV_PREALLOC];
	struct the_nilfs *nilfs;
	struct nilfs_sufile_header *header;
	struct nilfs_segment_usage *su;
	void *kaddr;
	unsigned long ncleansegs, ndirtysegs;
	int ret, i;

	down_write(&NILFS_MDT(sufile)->mi_sem);

	nilfs = NILFS_MDT(sufile)->mi_nilfs;

	/* prepare resources */
	if (nsegs <= NILFS_SUFILE_FREEV_PREALLOC)
		su_bh = su_bh_prealloc;
	else {
		su_bh = kmalloc(sizeof(*su_bh) * nsegs, GFP_NOFS);
		if (su_bh == NULL) {
			ret = -ENOMEM;
			goto out_sem;
		}
	}

	ret = nilfs_sufile_get_header_block(sufile, &header_bh);
	if (ret < 0)
		goto out_su_bh;
	for (i = 0; i < nsegs; i++) {
		ret = nilfs_sufile_get_segment_usage_block(sufile, segnum[i],
							   0, &su_bh[i]);
		if (ret < 0)
			goto out_bh;
	}

	/* free segments */
	for (i = 0; i < nsegs; i++) {
		kaddr = kmap_atomic(su_bh[i]->b_page, KM_USER0);
		su = nilfs_sufile_block_get_segment_usage(
			sufile, segnum[i], su_bh[i], kaddr);
		BUG_ON(nilfs_segment_usage_error(su));
#ifdef CONFIG_NILFS_DEBUG
		/* XXX: sh_ncleansegs will be destroyed if true */
		BUG_ON(nilfs_segment_usage_clean(su));
		/* XXX: sh_ndirtysegs will be destroyed if true */
		BUG_ON(!nilfs_segment_usage_dirty(su));
#endif
		nilfs_segment_usage_set_clean(su);
		kunmap_atomic(kaddr, KM_USER0);
		nilfs_mdt_mark_buffer_dirty(su_bh[i]);
	}
	kaddr = kmap_atomic(header_bh->b_page, KM_USER0);
	header = nilfs_sufile_block_get_header(sufile, header_bh, kaddr);
	ncleansegs = le64_to_cpu(header->sh_ncleansegs) + nsegs;
	ndirtysegs = le64_to_cpu(header->sh_ndirtysegs) - nsegs;
	header->sh_ncleansegs = cpu_to_le64(ncleansegs);
	header->sh_ndirtysegs = cpu_to_le64(ndirtysegs);
	kunmap_atomic(kaddr, KM_USER0);
	nilfs_mdt_mark_buffer_dirty(header_bh);
	nilfs_mdt_mark_dirty(sufile);

 out_bh:
	for (i--; i >= 0; i--)
		brelse(su_bh[i]);
	brelse(header_bh);

 out_su_bh:
	if (su_bh != su_bh_prealloc)
		kfree(su_bh);

 out_sem:
	up_write(&NILFS_MDT(sufile)->mi_sem);
	return ret;
}

/**
 * nilfs_sufile_free -
 * @sufile:
 * @segnum:
 */
int nilfs_sufile_free(struct inode *sufile, nilfs_segnum_t segnum)
{
	return nilfs_sufile_freev(sufile, &segnum, 1);
}

/**
 * nilfs_sufile_get_segment_usage - get a segment usage
 * @sufile: inode of segment usage file
 * @segnum: segment number
 * @sup: pointer to segment usage
 * @bhp: pointer to buffer head
 *
 * Description: nilfs_sufile_get_segment_usage() acquires the segment usage
 * specified by @segnum.
 *
 * Return Value: On success, 0 is returned, and the segment usage and the
 * buffer head of the buffer on which the segment usage is located are stored
 * in the place pointed by @sup and @bhp, respectively. On error, one of the
 * following negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 *
 * %-EINVAL - Invalid segment usage number.
 */
int nilfs_sufile_get_segment_usage(struct inode *sufile,
				   nilfs_segnum_t segnum,
				   struct nilfs_segment_usage **sup,
				   struct buffer_head **bhp)
{
	struct buffer_head *bh;
	struct nilfs_segment_usage *su;
	void *kaddr;
	int ret;

	/* segnum is 0 origin */
	BUG_ON(segnum >= nilfs_sufile_get_nsegments(sufile));

	down_write(&NILFS_MDT(sufile)->mi_sem);
	ret = nilfs_sufile_get_segment_usage_block(sufile, segnum, 1, &bh);
	if (ret < 0)
		goto out_sem;
	kaddr = kmap(bh->b_page);
	su = nilfs_sufile_block_get_segment_usage(sufile, segnum, bh, kaddr);
	if (nilfs_segment_usage_error(su)) {
		kunmap(bh->b_page);
		brelse(bh);
		ret = -EINVAL;
		goto out_sem;
	}

	if (sup != NULL)
		*sup = su;
	BUG_ON(bhp == NULL);
	*bhp = bh;

 out_sem:
	up_write(&NILFS_MDT(sufile)->mi_sem);
	return ret;
}

/**
 * nilfs_sufile_put_segment_usage - put a segment usage
 * @sufile: inode of segment usage file
 * @segnum: segment number
 * @bh: buffer head
 *
 * Description: nilfs_sufile_put_segment_usage() releases the segment usage
 * specified by @segnum. @bh must be the buffer head which have been returned
 * by a previous call to nilfs_sufile_get_segment_usage() with @segnum.
 */
void nilfs_sufile_put_segment_usage(struct inode *sufile,
				    nilfs_segnum_t segnum,
				    struct buffer_head *bh)
{
	/* XXX: must check segnum */
	kunmap(bh->b_page);
	brelse(bh);
}

/**
 * nilfs_sufile_get_stat - get segment usage statistics
 * @sufile: inode of segment usage file
 * @stat: pointer to a structure of segment usage statistics
 *
 * Description: nilfs_sufile_get_stat() returns information about segment
 * usage.
 *
 * Return Value: On success, 0 is returned, and segment usage information is
 * stored in the place pointed by @stat. On error, one of the following
 * negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 */
int nilfs_sufile_get_stat(struct inode *sufile, struct nilfs_sustat *sustat)
{
	struct buffer_head *header_bh;
	struct nilfs_sufile_header *header;
	void *kaddr;
	int ret;

	down_read(&NILFS_MDT(sufile)->mi_sem);

	ret = nilfs_sufile_get_header_block(sufile, &header_bh);
	if (ret < 0)
		goto out_sem;

	kaddr = kmap_atomic(header_bh->b_page, KM_USER0);
	header = nilfs_sufile_block_get_header(sufile, header_bh, kaddr);
	sustat->ss_nsegs = nilfs_sufile_get_nsegments(sufile);
	sustat->ss_ncleansegs = le64_to_cpu(header->sh_ncleansegs);
	sustat->ss_ndirtysegs = le64_to_cpu(header->sh_ndirtysegs);
	sustat->ss_ctime = NILFS_MDT(sufile)->mi_nilfs->ns_ctime;
	sustat->ss_nongc_ctime = NILFS_MDT(sufile)->mi_nilfs->ns_nongc_ctime;
	kunmap_atomic(kaddr, KM_USER0);
	brelse(header_bh);

 out_sem:
	up_read(&NILFS_MDT(sufile)->mi_sem);
	return ret;
}

/**
 * nilfs_sufile_get_ncleansegs - get the number of clean segments
 * @sufile: inode of segment usage file
 * @nsegsp: pointer to the number of clean segments
 *
 * Description: nilfs_sufile_get_ncleansegs() acquires the number of clean
 * segments.
 *
 * Return Value: On success, 0 is returned and the number of clean segments is
 * stored in the place pointed by @nsegsp. On error, one of the following
 * negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 */
int nilfs_sufile_get_ncleansegs(struct inode *sufile, unsigned long *nsegsp)
{
	struct nilfs_sustat sustat;
	int ret;

	ret = nilfs_sufile_get_stat(sufile, &sustat);
	if (ret < 0)
		return ret;
	BUG_ON(nsegsp == NULL);
	*nsegsp = sustat.ss_ncleansegs;
	return 0;
}

/**
 * nilfs_sufile_get_ndirtysegs - get the number of dirty segments
 * @sufile: inode of segment usage file
 * @nsegsp: pointer to the number of dirty segments
 *
 * Description: nilfs_sufile_get_ndirtysegs() acquires the number of dirty
 * segments.
 *
 * Return Value: On success, 0 is returned and the number of dirty segments is
 * stored in the place pointed by @nsegsp. On error, one of the following
 * negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 */
int nilfs_sufile_get_ndirtysegs(struct inode *sufile, unsigned long *nsegsp)
{
	struct nilfs_sustat sustat;
	int ret;

	ret = nilfs_sufile_get_stat(sufile, &sustat);
	if (ret < 0)
		return ret;
	BUG_ON(nsegsp == NULL);
	*nsegsp = sustat.ss_ndirtysegs;
	return 0;
}

/**
 * nilfs_sufile_set_error - mark a segment as erroneous
 * @sufile: inode of segment usage file
 * @segnum: segment number
 *
 * Description: nilfs_sufile_set_error() marks the segment specified by
 * @segnum as erroneous. The error segment will never be used again.
 *
 * Return Value: On success, 0 is returned. On error, one of the following
 * negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 */
int nilfs_sufile_set_error(struct inode *sufile, nilfs_segnum_t segnum)
{
	struct buffer_head *header_bh, *su_bh;
	struct nilfs_segment_usage *su;
	struct nilfs_sufile_header *header;
	void *kaddr;
	int ret;

	BUG_ON(segnum >= nilfs_sufile_get_nsegments(sufile));

	down_write(&NILFS_MDT(sufile)->mi_sem);

	ret = nilfs_sufile_get_header_block(sufile, &header_bh);
	if (ret < 0)
		goto out_sem;
	ret = nilfs_sufile_get_segment_usage_block(sufile, segnum, 0, &su_bh);
	if (ret < 0)
		goto out_header;

	kaddr = kmap_atomic(su_bh->b_page, KM_USER0);
	su = nilfs_sufile_block_get_segment_usage(sufile, segnum, su_bh, kaddr);
	if (nilfs_segment_usage_error(su)) {
		kunmap_atomic(kaddr, KM_USER0);
		brelse(su_bh);
		goto out_header;
	}

	nilfs_segment_usage_set_error(su);
	kunmap_atomic(kaddr, KM_USER0);
	brelse(su_bh);

	kaddr = kmap_atomic(header_bh->b_page, KM_USER0);
	header = nilfs_sufile_block_get_header(sufile, header_bh, kaddr);
	header->sh_ndirtysegs =
		cpu_to_le64(le64_to_cpu(header->sh_ndirtysegs) - 1);
	kunmap_atomic(kaddr, KM_USER0);
	nilfs_mdt_mark_buffer_dirty(header_bh);
	nilfs_mdt_mark_buffer_dirty(su_bh);
	nilfs_mdt_mark_dirty(sufile);
	brelse(su_bh);

 out_header:
	brelse(header_bh);

 out_sem:
	up_write(&NILFS_MDT(sufile)->mi_sem);
	return ret;
}

/**
 * nilfs_sufile_get_segment_usages -
 * @sufile: inode of segment usage file
 * @segnum: segment number to start looking
 * @sus: array of segment usage
 * @size: size of segment usage array
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
ssize_t nilfs_sufile_get_segment_usages(struct inode *sufile,
					nilfs_segnum_t segnum,
					struct nilfs_segment_usage *sus,
					size_t size)
{
	struct buffer_head *su_bh;
	struct nilfs_segment_usage *su;
	void *kaddr;
	unsigned long nsegs, segusages_per_block;
	ssize_t n;
	int ret, i;

	down_read(&NILFS_MDT(sufile)->mi_sem);

	segusages_per_block = nilfs_sufile_segment_usages_per_block(sufile);
	nsegs = min_t(unsigned long,
		      nilfs_sufile_get_nsegments(sufile) - segnum,
		      size);
	for (i = 0; i < nsegs; i += n, segnum += n) {
		n = min_t(unsigned long,
			  segusages_per_block -
				  nilfs_sufile_get_offset(sufile, segnum),
			  nsegs - i);
		ret = nilfs_sufile_get_segment_usage_block(sufile, segnum, 0,
							   &su_bh);
		if (ret < 0) {
			if (ret != -ENOENT)
				goto out;
			/* hole */
			memset(&sus[i], 0,
			       sizeof(struct nilfs_segment_usage) * n);
			continue;
		}

		kaddr = kmap_atomic(su_bh->b_page, KM_USER0);
		su = nilfs_sufile_block_get_segment_usage(
			sufile, segnum, su_bh, kaddr);
		memcpy(&sus[i], su, sizeof(struct nilfs_segment_usage) * n);
		kunmap_atomic(kaddr, KM_USER0);
		brelse(su_bh);
	}
	ret = nsegs;

 out:
	up_read(&NILFS_MDT(sufile)->mi_sem);
	return ret;
}

/**
 * nilfs_sufile_get_suinfo -
 * @sufile: inode of segment usage file
 * @segnum: segment number to start looking
 * @si: array of suinfo
 * @nsi: size of suinfo array
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
ssize_t nilfs_sufile_get_suinfo(struct inode *sufile, nilfs_segnum_t segnum,
				struct nilfs_suinfo *si, size_t nsi)
{
	struct buffer_head *su_bh;
	struct nilfs_segment_usage *su;
	void *kaddr;
	unsigned long nsegs, segusages_per_block;
	ssize_t n;
	int ret, i, j;

	down_read(&NILFS_MDT(sufile)->mi_sem);

	segusages_per_block = nilfs_sufile_segment_usages_per_block(sufile);
	nsegs = min_t(unsigned long,
		      nilfs_sufile_get_nsegments(sufile) - segnum,
		      nsi);
	for (i = 0; i < nsegs; i += n, segnum += n) {
		n = min_t(unsigned long,
			  segusages_per_block -
				  nilfs_sufile_get_offset(sufile, segnum),
			  nsegs - i);
		ret = nilfs_sufile_get_segment_usage_block(sufile, segnum, 0,
							   &su_bh);
		if (ret < 0) {
			if (ret != -ENOENT)
				goto out;
			/* hole */
			memset(&si[i], 0, sizeof(struct nilfs_suinfo) * n);
			continue;
		}

		kaddr = kmap_atomic(su_bh->b_page, KM_USER0);
		su = nilfs_sufile_block_get_segment_usage(
			sufile, segnum, su_bh, kaddr);
		for (j = 0; j < n; j++, su++) {
			si[i + j].si_lastmod = le64_to_cpu(su->su_lastmod);
			si[i + j].si_nblocks = le32_to_cpu(su->su_nblocks);
			si[i + j].si_flags = le32_to_cpu(su->su_flags);
		}
		kunmap_atomic(kaddr, KM_USER0);
		brelse(su_bh);
	}
	ret = nsegs;

 out:
	up_read(&NILFS_MDT(sufile)->mi_sem);
	return ret;
}
