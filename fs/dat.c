/*
 * dat.c - NILFS disk address translation.
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
 * Written by Koji Sato <koji@osrg.net>.
 */

#include <linux/types.h>
#include <linux/buffer_head.h>
#include <linux/string.h>
#include <linux/errno.h>
#include "nilfs.h"	/* XXX: nilfs_error() */
#include "sb.h"
#include "mdt.h"
#include "dat.h"


#define NILFS_CNO_MIN	((__u64)1)
#define NILFS_CNO_MAX	(~(__u64)0)

static inline unsigned long
nilfs_dat_groups_per_desc_block(const struct inode *dat)
{
	return (1UL << dat->i_blkbits) / sizeof(struct nilfs_dat_group_desc);
}

static inline unsigned long
nilfs_dat_blocks_per_group(const struct inode *dat)
{
	/* including a bitmap block */
	return (nilfs_dat_entries_per_group(dat) - 1) /
		nilfs_dat_entries_per_block(dat) + 1 +
		1;
}

static inline unsigned long
nilfs_dat_blocks_per_desc_block(const struct inode *dat)
{
	/* including a group descriptor block and group bitmap blocks */
	return nilfs_dat_groups_per_desc_block(dat) *
		nilfs_dat_blocks_per_group(dat) + 1;
}

static inline unsigned long
nilfs_dat_group(const struct inode *dat, __u64 vblocknr)
{
	__u64 group = vblocknr;

	do_div(group, nilfs_dat_entries_per_group(dat));
	return group;
}

static inline unsigned long
nilfs_dat_group_offset(const struct inode *dat, __u64 vblocknr)
{
	return do_div(vblocknr, nilfs_dat_entries_per_group(dat));
}

static inline unsigned long
nilfs_dat_desc_block(const struct inode *dat, unsigned long group)
{
	return group % nilfs_dat_groups_per_desc_block(dat);
}

static inline unsigned long
nilfs_dat_desc_offset(const struct inode *dat, unsigned long group)
{
	return group / nilfs_dat_groups_per_desc_block(dat);
}

static inline unsigned long
nilfs_dat_entry_block(const struct inode *dat, unsigned long group_offset)
{
	return group_offset / nilfs_dat_entries_per_block(dat);
}

static inline unsigned long
nilfs_dat_entry_offset(const struct inode *dat, __u64 vblocknr)
{
	return nilfs_dat_group_offset(dat, vblocknr) %
		nilfs_dat_entries_per_block(dat);
}

static inline unsigned long
nilfs_dat_rest_groups_in_desc_block(const struct inode *dat,
				    unsigned long curr, unsigned long max)
{
	return min_t(unsigned long,
		     nilfs_dat_groups_per_desc_block(dat) -
		     nilfs_dat_desc_offset(dat, curr),
		     max - curr + 1);
}

static inline unsigned long
nilfs_dat_desc_blkoff(const struct inode *dat, unsigned long group)
{
	return nilfs_dat_desc_block(dat, group) *
		nilfs_dat_blocks_per_desc_block(dat);
}

static inline unsigned long
nilfs_dat_bitmap_blkoff(const struct inode *dat, unsigned long group)
{
	return nilfs_dat_desc_blkoff(dat, group) + 1 +
		nilfs_dat_desc_offset(dat, group) *
		nilfs_dat_blocks_per_group(dat);
}

static inline unsigned long
nilfs_dat_entry_blkoff(const struct inode *dat, __u64 vblocknr)
{
	return nilfs_dat_bitmap_blkoff(dat, nilfs_dat_group(dat, vblocknr)) +
		1 +
		nilfs_dat_entry_block(dat,
				      nilfs_dat_group_offset(dat, vblocknr));
}

static inline unsigned long
nilfs_dat_group_desc_get_nfrees(struct inode *dat,
				unsigned long group,
				const struct nilfs_dat_group_desc *desc)
{
	unsigned long nfree;

	spin_lock(nilfs_mdt_bgl_lock(dat, group));
	nfree = le32_to_cpu(desc->dg_nfrees);
	spin_unlock(nilfs_mdt_bgl_lock(dat, group));

	return nfree;
}

static inline void
nilfs_dat_group_desc_set_nfrees(const struct inode *dat,
				struct nilfs_dat_group_desc *desc,
				unsigned long nfrees)
{
	desc->dg_nfrees = cpu_to_le32(nfrees);
}

static inline unsigned long
nilfs_dat_group_desc_add_entries(struct inode *dat,
				 unsigned long group,
				 struct nilfs_dat_group_desc *desc,
				 unsigned long n)
{
	unsigned long nfrees;

	spin_lock(nilfs_mdt_bgl_lock(dat, group));
	nfrees = le32_to_cpu(desc->dg_nfrees) + n;
	desc->dg_nfrees = cpu_to_le32(nfrees);
	spin_unlock(nilfs_mdt_bgl_lock(dat, group));

	return nfrees;
}

static inline unsigned long
nilfs_dat_group_desc_sub_entries(struct inode *dat,
				 unsigned long group,
				 struct nilfs_dat_group_desc *desc,
				 unsigned long n)
{
	unsigned long nfrees;

	spin_lock(nilfs_mdt_bgl_lock(dat, group));
	nfrees = le32_to_cpu(desc->dg_nfrees) - n;
	desc->dg_nfrees = cpu_to_le32(nfrees);
	spin_unlock(nilfs_mdt_bgl_lock(dat, group));

	return nfrees;
}

static inline __u64
nilfs_dat_entry_get_start(const struct inode *dat,
			  const struct nilfs_dat_entry *entry)
{
	return le64_to_cpu(entry->de_start);
}

static inline void nilfs_dat_entry_set_start(const struct inode *dat,
					     struct nilfs_dat_entry *entry,
					     __u64 start)
{
	entry->de_start = cpu_to_le64(start);
}

static inline __u64
nilfs_dat_entry_get_end(const struct inode *dat,
			const struct nilfs_dat_entry *entry)
{
	return le64_to_cpu(entry->de_end);
}

static inline void nilfs_dat_entry_set_end(const struct inode *dat,
					   struct nilfs_dat_entry *entry,
					   __u64 end)
{
	entry->de_end = cpu_to_le64(end);
}

static inline sector_t
nilfs_dat_entry_get_blocknr(const struct inode *dat,
			    const struct nilfs_dat_entry *entry)
{
	return le64_to_cpu(entry->de_blocknr);
}

static inline void nilfs_dat_entry_set_blocknr(const struct inode *dat,
					       struct nilfs_dat_entry *entry,
					       sector_t blocknr)
{
	entry->de_blocknr = cpu_to_le64(blocknr);
}

static void nilfs_dat_desc_block_init(struct inode *dat,
				      struct buffer_head *bh,
				      void *kaddr)
{
	struct nilfs_dat_group_desc *desc;
	unsigned long i;

	for (i = 0, desc = (struct nilfs_dat_group_desc *)
		     (kaddr + bh_offset(bh));
	     i < nilfs_dat_groups_per_desc_block(dat);
	     i++, desc++)
		nilfs_dat_group_desc_set_nfrees(
			dat, desc, nilfs_dat_entries_per_group(dat));
}

#define nilfs_dat_bitmap_block_init	NULL

static void nilfs_dat_entry_block_init(struct inode *dat,
				       struct buffer_head *bh,
				       void *kaddr)
{
	struct nilfs_dat_entry *entry;
	unsigned long i;

	for (i = 0, entry = (struct nilfs_dat_entry *)(kaddr + bh_offset(bh));
	     i < nilfs_dat_entries_per_block(dat);
	     i++, entry++) {
		/* XXX: use macro */
		nilfs_dat_entry_set_blocknr(dat, entry, 0);
		nilfs_dat_entry_set_start(dat, entry, 0);
		nilfs_dat_entry_set_end(dat, entry, 0);
	}
}

static inline int nilfs_dat_get_desc_block(struct inode *dat,
					   unsigned long group,
					   int create,
					   struct buffer_head **bhp)
{
	return nilfs_mdt_get_block(dat, nilfs_dat_desc_blkoff(dat, group),
				   create, nilfs_dat_desc_block_init, bhp);
}

static inline int nilfs_dat_get_bitmap_block(struct inode *dat,
					     unsigned long group,
					     int create,
					     struct buffer_head **bhp)
{
	return nilfs_mdt_get_block(dat, nilfs_dat_bitmap_blkoff(dat, group),
				   create, nilfs_dat_bitmap_block_init, bhp);
}

static inline int
nilfs_dat_get_entry_block(struct inode *dat, __u64 vblocknr, int create,
			  struct buffer_head **bhp)
{
	return nilfs_mdt_get_block(dat, nilfs_dat_entry_blkoff(dat, vblocknr),
				   create, nilfs_dat_entry_block_init, bhp);
}

static inline struct nilfs_dat_group_desc *
nilfs_dat_block_get_group_desc(const struct inode *dat,
			       unsigned long group,
			       const struct buffer_head *bh,
			       void *kaddr)
{
	return (struct nilfs_dat_group_desc *)(kaddr + bh_offset(bh)) +
		nilfs_dat_desc_offset(dat, group);
}

static inline unsigned char *
nilfs_dat_block_get_bitmap(const struct inode *dat,
			   const struct buffer_head *bh,
			   void *kaddr)
{
	return (unsigned char *)(kaddr + bh_offset(bh));
}

static inline struct nilfs_dat_entry *
nilfs_dat_block_get_entry(const struct inode *dat,
			  __u64 vblocknr,
			  const struct buffer_head *bh,
			  void *kaddr)
{
	return (struct nilfs_dat_entry *)(kaddr + bh_offset(bh)) +
		nilfs_dat_entry_offset(dat, vblocknr);
}


static int
nilfs_dat_group_find_available_vblocknr(struct inode *dat,
					unsigned long group,
					unsigned long target,
					unsigned char *bitmap,
					int size)	/* size in bits */
{
	int curr, end, result, i;

	if (target > 0) {
		end = (target + BITS_PER_LONG - 1) & ~(BITS_PER_LONG - 1);
		if (end > size)
			end = size;
		result = nilfs_dat_find_next_zero_bit(bitmap, end, target);
		if ((result < end) &&
		    !nilfs_dat_set_bit_atomic(nilfs_mdt_bgl_lock(dat, group),
					      result, bitmap))
			return result;
	} else
		end = 0;

	for (i = 0, curr = end;
	     i < size;
	     i += BITS_PER_LONG, curr += BITS_PER_LONG) {
		/* wrap around */
		if (curr >= size)
			curr = 0;
		while (*((unsigned long *)bitmap + curr / BITS_PER_LONG)
		       != ~0UL) {
			end = curr + BITS_PER_LONG;
			if (end > size)
				end = size;
			result = nilfs_dat_find_next_zero_bit(
				bitmap, end, curr);
			if ((result < end) &&
			    !nilfs_dat_set_bit_atomic(
				    nilfs_mdt_bgl_lock(dat, group),
				    result, bitmap))
				return result;
		}
	}

	return -ENOSPC;
}

static int nilfs_dat_prepare_alloc_vblocknr(struct inode *dat,
					    struct nilfs_dat_req *req)
{
	struct buffer_head *desc_bh, *bitmap_bh;
	struct nilfs_dat_group_desc *desc;
	unsigned char *bitmap;
	void *desc_kaddr, *bitmap_kaddr;
	unsigned long group, maxgroup, ngroups;
	unsigned long  group_offset;
	unsigned long n, entries_per_group, groups_per_desc_block;
	unsigned long i, j;
	int res, ret;

	ngroups = NILFS_MDT(dat)->mi_groups_count;
	maxgroup = ngroups - 1;
	group = nilfs_dat_group(dat, req->dr_vblocknr);
	group_offset = nilfs_dat_group_offset(dat, req->dr_vblocknr);
	entries_per_group = nilfs_dat_entries_per_group(dat);
	groups_per_desc_block = nilfs_dat_groups_per_desc_block(dat);
	for (i = 0; i < ngroups; i += n) {
		if (group >= ngroups) {
			/* wrap around */
			group = 0;
			maxgroup = nilfs_dat_group(dat, req->dr_vblocknr) - 1;
		}
		ret = nilfs_dat_get_desc_block(dat, group, 1, &desc_bh);
		if (ret < 0)
			return ret;
		desc_kaddr = kmap(desc_bh->b_page);
		desc = nilfs_dat_block_get_group_desc(
			dat, group, desc_bh, desc_kaddr);
		n = nilfs_dat_rest_groups_in_desc_block(dat, group, maxgroup);
		for (j = 0; j < n; j++, desc++, group++) {
			if (nilfs_dat_group_desc_get_nfrees(
				    dat, group, desc) > 0) {
				ret = nilfs_dat_get_bitmap_block(dat, group, 1,
								 &bitmap_bh);
				if (ret < 0)
					goto out_desc;
				bitmap_kaddr = kmap(bitmap_bh->b_page);
				bitmap = nilfs_dat_block_get_bitmap(
					dat, bitmap_bh, bitmap_kaddr);
				res = nilfs_dat_group_find_available_vblocknr(
					dat, group, group_offset, bitmap,
					entries_per_group);
				if (res >= 0) {
					nilfs_dat_group_desc_sub_entries(
						dat, group, desc, 1);
					req->dr_vblocknr =
						entries_per_group * group + res;
					kunmap(desc_bh->b_page);
					kunmap(bitmap_bh->b_page);

					req->dr_desc_bh = desc_bh;
					req->dr_bitmap_bh = bitmap_bh;
					return 0;
				}
				kunmap(bitmap_bh->b_page);
				brelse(bitmap_bh);
			}

			group_offset = 0;
		}

		kunmap(desc_bh->b_page);
		brelse(desc_bh);
	}

	/* no virtual block numbers left */
	return -ENOSPC;

 out_desc:
	kunmap(desc_bh->b_page);
	brelse(desc_bh);
	return ret;
}

static void nilfs_dat_commit_alloc_vblocknr(struct inode *dat,
					    struct nilfs_dat_req *req)
{
	nilfs_mdt_mark_buffer_dirty(req->dr_bitmap_bh);
	nilfs_mdt_mark_buffer_dirty(req->dr_desc_bh);
	nilfs_mdt_mark_dirty(dat);

	brelse(req->dr_bitmap_bh);
	brelse(req->dr_desc_bh);
}

static void nilfs_dat_abort_alloc_vblocknr(struct inode *dat,
					   struct nilfs_dat_req *req)
{
	struct nilfs_dat_group_desc *desc;
	void *desc_kaddr, *bitmap_kaddr;
	unsigned char *bitmap;
	unsigned long group;
	unsigned long group_offset;

	group = nilfs_dat_group(dat, req->dr_vblocknr);
	group_offset = nilfs_dat_group_offset(dat, req->dr_vblocknr);
	desc_kaddr = kmap(req->dr_desc_bh->b_page);
	desc = nilfs_dat_block_get_group_desc(dat, group, req->dr_desc_bh,
					      desc_kaddr);
	bitmap_kaddr = kmap(req->dr_bitmap_bh->b_page);
	bitmap = nilfs_dat_block_get_bitmap(dat, req->dr_bitmap_bh,
					    bitmap_kaddr);

	if (!nilfs_dat_clear_bit_atomic(nilfs_mdt_bgl_lock(dat, group),
					group_offset, bitmap)) {
		/*
		nilfs_error(dat->i_sb, __func__,
			    "virtual block number %llu already freed",
			    (unsigned long long)req->dr_vblocknr);
		*/
		printk(KERN_CRIT
		       "%s: virtual block number %llu already freed\n",
		       __func__, (unsigned long long)req->dr_vblocknr);
		BUG();
	}

	nilfs_dat_group_desc_add_entries(dat, group, desc, 1);

	kunmap(req->dr_bitmap_bh->b_page);
	kunmap(req->dr_desc_bh->b_page);

	brelse(req->dr_bitmap_bh);
	brelse(req->dr_desc_bh);

	req->dr_vblocknr = 0;
	req->dr_bitmap_bh = NULL;
	req->dr_desc_bh = NULL;
}

static int nilfs_dat_prepare_free_vblocknr(struct inode *dat,
					   struct nilfs_dat_req *req)
{
	struct buffer_head *desc_bh, *bitmap_bh;
	unsigned long group;
	int ret;

	group = nilfs_dat_group(dat, req->dr_vblocknr);
	ret = nilfs_dat_get_desc_block(dat, group, 0, &desc_bh);
	if (ret < 0)
		return ret;
	ret = nilfs_dat_get_bitmap_block(dat, group, 0, &bitmap_bh);
	if (ret < 0) {
		brelse(desc_bh);
		return ret;
	}

	req->dr_desc_bh = desc_bh;
	req->dr_bitmap_bh = bitmap_bh;
	return 0;
}

static void nilfs_dat_commit_free_vblocknr(struct inode *dat,
					   struct nilfs_dat_req *req)
{
	struct nilfs_dat_group_desc *desc;
	void *desc_kaddr, *bitmap_kaddr;
	unsigned char *bitmap;
	unsigned long group;
	unsigned long group_offset;

	group = nilfs_dat_group(dat, req->dr_vblocknr);
	group_offset = nilfs_dat_group_offset(dat, req->dr_vblocknr);
	desc_kaddr = kmap(req->dr_desc_bh->b_page);
	desc = nilfs_dat_block_get_group_desc(
		dat, group, req->dr_desc_bh, desc_kaddr);
	bitmap_kaddr = kmap(req->dr_bitmap_bh->b_page);
	bitmap = nilfs_dat_block_get_bitmap(
		dat, req->dr_bitmap_bh, bitmap_kaddr);

	if (!nilfs_dat_clear_bit_atomic(nilfs_mdt_bgl_lock(dat, group),
					group_offset, bitmap)) {
		/*
		nilfs_error(dat->i_sb, __func__,
			    "virtual block number %llu already freed",
			    (unsigned long long)req->dr_vblocknr);
		*/
		printk(KERN_CRIT
		       "%s: virtual block number %llu already freed\n",
		       __func__, (unsigned long long)req->dr_vblocknr);
		BUG();
	}

	nilfs_dat_group_desc_add_entries(dat, group, desc, 1);

	kunmap(req->dr_bitmap_bh->b_page);
	kunmap(req->dr_desc_bh->b_page);

	nilfs_mdt_mark_buffer_dirty(req->dr_bitmap_bh);
	nilfs_mdt_mark_buffer_dirty(req->dr_desc_bh);
	nilfs_mdt_mark_dirty(dat);

	brelse(req->dr_bitmap_bh);
	brelse(req->dr_desc_bh);
}

static void nilfs_dat_abort_free_vblocknr(struct inode *dat,
					  struct nilfs_dat_req *req)
{
	brelse(req->dr_bitmap_bh);
	brelse(req->dr_desc_bh);

	req->dr_vblocknr = 0;
	req->dr_bitmap_bh = NULL;
	req->dr_desc_bh = NULL;
}

static int nilfs_dat_prepare_entry(struct inode *dat,
				   struct nilfs_dat_req *req,
				   int create)
{
	return nilfs_dat_get_entry_block(dat, req->dr_vblocknr,
					 create, &req->dr_entry_bh);
}

static void nilfs_dat_commit_entry(struct inode *dat,
				   struct nilfs_dat_req *req)
{
	nilfs_mdt_mark_buffer_dirty(req->dr_entry_bh);
	nilfs_mdt_mark_dirty(dat);
	brelse(req->dr_entry_bh);
}

static void nilfs_dat_abort_entry(struct inode *dat,
				  struct nilfs_dat_req *req)
{
	brelse(req->dr_entry_bh);
}

/**
 * nilfs_dat_prepare_alloc -
 * @dat:
 * @req:
 */
int nilfs_dat_prepare_alloc(struct inode *dat, struct nilfs_dat_req *req)
{
	int ret;

	ret = nilfs_dat_prepare_alloc_vblocknr(dat, req);
	if (ret < 0)
		return ret;
	ret = nilfs_dat_prepare_entry(dat, req, 1);
	if (ret < 0) {
		nilfs_dat_abort_alloc_vblocknr(dat, req);
		return ret;
	}

	dat_debug(3, "done (vblocknr=%llu, ret=%d)\n",
		  (unsigned long long)req->dr_vblocknr, ret);

	return ret;
}

/**
 * nilfs_dat_commit_alloc -
 * @dat:
 * @req:
 */
void nilfs_dat_commit_alloc(struct inode *dat, struct nilfs_dat_req *req)
{
	struct nilfs_dat_entry *entry;
	void *entry_kaddr;

	dat_debug(3, "called (vblocknr=%llu)\n",
		  (unsigned long long)req->dr_vblocknr);
	entry_kaddr = kmap_atomic(req->dr_entry_bh->b_page, KM_USER0);
	entry = nilfs_dat_block_get_entry(dat, req->dr_vblocknr,
					  req->dr_entry_bh, entry_kaddr);
	nilfs_dat_entry_set_start(dat, entry, NILFS_CNO_MIN);
	nilfs_dat_entry_set_end(dat, entry, NILFS_CNO_MAX);
	nilfs_dat_entry_set_blocknr(dat, entry, 0);

	kunmap_atomic(entry_kaddr, KM_USER0);

	nilfs_dat_commit_alloc_vblocknr(dat, req);
	nilfs_dat_commit_entry(dat, req);
}

/**
 * nilfs_dat_abort_alloc -
 * @dat:
 * @req:
 */
void nilfs_dat_abort_alloc(struct inode *dat, struct nilfs_dat_req *req)
{
	nilfs_dat_abort_entry(dat, req);
	nilfs_dat_abort_alloc_vblocknr(dat, req);
}

/**
 * nilfs_dat_prepare_free -
 * @dat:
 * @req:
 */
int nilfs_dat_prepare_free(struct inode *dat, struct nilfs_dat_req *req)
{
	int ret;

	ret = nilfs_dat_prepare_free_vblocknr(dat, req);
	if (ret < 0)
		return ret;
	ret = nilfs_dat_prepare_entry(dat, req, 0);
	if (ret < 0) {
		nilfs_dat_abort_free_vblocknr(dat, req);
		return ret;
	}

	return 0;
}

/**
 * nilfs_dat_commit_free -
 * @dat:
 * @req:
 */
void nilfs_dat_commit_free(struct inode *dat, struct nilfs_dat_req *req)
{
	struct nilfs_dat_entry *entry;
	void *entry_kaddr;

	entry_kaddr = kmap_atomic(req->dr_entry_bh->b_page, KM_USER0);
	entry = nilfs_dat_block_get_entry(dat, req->dr_vblocknr,
					  req->dr_entry_bh, entry_kaddr);

	nilfs_dat_entry_set_start(dat, entry, NILFS_CNO_MIN);
	nilfs_dat_entry_set_end(dat, entry, NILFS_CNO_MIN);
	nilfs_dat_entry_set_blocknr(dat, entry, 0);
	kunmap_atomic(entry_kaddr, KM_USER0);

	nilfs_dat_commit_entry(dat, req);
	nilfs_dat_commit_free_vblocknr(dat, req);
}

/**
 * nilfs_dat_abort_free -
 * @dat:
 * @req:
 */
void nilfs_dat_abort_free(struct inode *dat, struct nilfs_dat_req *req)
{
	nilfs_dat_abort_entry(dat, req);
	nilfs_dat_abort_free_vblocknr(dat, req);
}

/**
 * nilfs_dat_prepare_start -
 * @dat:
 * @req:
 */
int nilfs_dat_prepare_start(struct inode *dat, struct nilfs_dat_req *req)
{
	int ret;

	ret = nilfs_dat_prepare_entry(dat, req, 0);
	BUG_ON(ret == -ENOENT);
	return ret;
}

/**
 * nilfs_dat_commit_start -
 * @dat:
 * @req:
 * @blocknr:
 */
void nilfs_dat_commit_start(struct inode *dat,
			    struct nilfs_dat_req *req,
			    sector_t blocknr)
{
	struct nilfs_dat_entry *entry;
	void *entry_kaddr;

	entry_kaddr = kmap_atomic(req->dr_entry_bh->b_page, KM_USER0);
	entry = nilfs_dat_block_get_entry(dat, req->dr_vblocknr,
					  req->dr_entry_bh, entry_kaddr);
	nilfs_dat_entry_set_start(dat, entry, nilfs_mdt_cno(dat));
	if ((nilfs_dat_entry_get_blocknr(dat, entry) != 0) ||
	    (nilfs_dat_entry_get_end(dat, entry) != NILFS_CNO_MAX)) {
		printk(KERN_CRIT
		       "%s: vbn = %llu, start = %llu, end = %llu, pbn = %llu\n",
		       __func__, (unsigned long long)req->dr_vblocknr,
		       (unsigned long long)nilfs_dat_entry_get_start(dat,
								     entry),
		       (unsigned long long)nilfs_dat_entry_get_end(dat, entry),
		       (unsigned long long)nilfs_dat_entry_get_blocknr(dat,
								       entry));
		BUG();
	}
	nilfs_dat_entry_set_blocknr(dat, entry, blocknr);
	kunmap_atomic(entry_kaddr, KM_USER0);

	nilfs_dat_commit_entry(dat, req);
}

/**
 * nilfs_dat_abort_start -
 * @dat:
 * @req:
 */
void nilfs_dat_abort_start(struct inode *dat, struct nilfs_dat_req *req)
{
	nilfs_dat_abort_entry(dat, req);
}

/**
 * nilfs_dat_prepare_end -
 * @dat:
 * @req:
 */
int nilfs_dat_prepare_end(struct inode *dat, struct nilfs_dat_req *req)
{
	struct nilfs_dat_entry *entry;
	__u64 start;
	sector_t blocknr;
	void *entry_kaddr;
	int ret;

	ret = nilfs_dat_prepare_entry(dat, req, 0);
	if (ret < 0) {
		BUG_ON(ret == -ENOENT);
		return ret;
	}

	entry_kaddr = kmap_atomic(req->dr_entry_bh->b_page, KM_USER0);
	entry = nilfs_dat_block_get_entry(dat, req->dr_vblocknr,
					  req->dr_entry_bh, entry_kaddr);
	start = nilfs_dat_entry_get_start(dat, entry);
	blocknr = nilfs_dat_entry_get_blocknr(dat, entry);
	kunmap_atomic(entry_kaddr, KM_USER0);

	if (blocknr == 0) {
		ret = nilfs_dat_prepare_free_vblocknr(dat, req);
		if (ret < 0) {
			nilfs_dat_abort_entry(dat, req);
			return ret;
		}
	}

	return 0;
}

/**
 * nilfs_dat_commit_end -
 * @dat:
 * @req:
 */
void nilfs_dat_commit_end(struct inode *dat, struct nilfs_dat_req *req)
{
	struct nilfs_dat_entry *entry;
	__u64 start, end;
	sector_t blocknr;
	void *entry_kaddr;

	entry_kaddr = kmap_atomic(req->dr_entry_bh->b_page, KM_USER0);
	entry = nilfs_dat_block_get_entry(dat, req->dr_vblocknr,
					  req->dr_entry_bh, entry_kaddr);
	start = nilfs_dat_entry_get_start(dat, entry);
	end = nilfs_mdt_cno(dat);
	blocknr = nilfs_dat_entry_get_blocknr(dat, entry);
	BUG_ON(start > end);

	nilfs_dat_entry_set_end(dat, entry, end);
	kunmap_atomic(entry_kaddr, KM_USER0);

	if (blocknr == 0)
		nilfs_dat_commit_free(dat, req);
	else
		nilfs_dat_commit_entry(dat, req);
}

/**
 * nilfs_dat_commit_end_dead -
 * @dat:
 * @req:
 */
void nilfs_dat_commit_end_dead(struct inode *dat, struct nilfs_dat_req *req)
{
	struct nilfs_dat_entry *entry;
	__u64 start;
	sector_t blocknr;
	void *entry_kaddr;

	entry_kaddr = kmap_atomic(req->dr_entry_bh->b_page, KM_USER0);
	entry = nilfs_dat_block_get_entry(dat, req->dr_vblocknr,
					  req->dr_entry_bh, entry_kaddr);
	start = nilfs_dat_entry_get_start(dat, entry);
	nilfs_dat_entry_set_end(dat, entry, start);
	blocknr = nilfs_dat_entry_get_blocknr(dat, entry);
	kunmap_atomic(entry_kaddr, KM_USER0);

	if (blocknr == 0)
		nilfs_dat_commit_free(dat, req);
	else
		nilfs_dat_commit_entry(dat, req);
}

/**
 * nilfs_dat_abort_end -
 * @dat:
 * @req:
 */
void nilfs_dat_abort_end(struct inode *dat, struct nilfs_dat_req *req)
{
	struct nilfs_dat_entry *entry;
	__u64 start;
	sector_t blocknr;
	void *entry_kaddr;

	entry_kaddr = kmap_atomic(req->dr_entry_bh->b_page, KM_USER0);
	entry = nilfs_dat_block_get_entry(dat, req->dr_vblocknr,
					  req->dr_entry_bh, entry_kaddr);
	start = nilfs_dat_entry_get_start(dat, entry);
	blocknr = nilfs_dat_entry_get_blocknr(dat, entry);
	kunmap_atomic(entry_kaddr, KM_USER0);

	if ((start == nilfs_mdt_cno(dat)) && (blocknr == 0))
		nilfs_dat_abort_free_vblocknr(dat, req);
	nilfs_dat_abort_entry(dat, req);
}

/**
 * nilfs_dat_mark_dirty -
 * @dat: DAT file inode
 * @vblocknr: virtual block number
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
int nilfs_dat_mark_dirty(struct inode *dat, __u64 vblocknr)
{
	struct nilfs_dat_req req;
	int ret;

	req.dr_vblocknr = vblocknr;
	ret = nilfs_dat_prepare_entry(dat, &req, 0);
	if (ret == 0)
		nilfs_dat_commit_entry(dat, &req);
	return ret;
}

/**
 * nilfs_dat_alloc - allocate a virtual block number
 * @dat: DAT file inode
 * @vblocknr: virtual block number
 *
 * Description: nilfs_dat_alloc() allocates a new virtual block number,
 * preferably @vblocknr.
 *
 * Return Value: On success, 0 is returned and the newly allocated virtual
 * block number is stored in the place pointed by @vblocknr. On error, one of
 * the following negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 *
 * %-ENOSPC - No virtual block number left.
 */
int nilfs_dat_alloc(struct inode *dat, __u64 *vblocknr)
{
	struct nilfs_dat_req req;
	int ret;

	req.dr_vblocknr = *vblocknr;
	ret = nilfs_dat_prepare_alloc(dat, &req);
	if (ret < 0)
		return ret;
	nilfs_dat_commit_alloc(dat, &req);
	*vblocknr = req.dr_vblocknr;
	return 0;
}

static inline int
nilfs_dat_group_is_in(struct inode *dat, unsigned long group, __u64 vblocknr)
{
	__u64 first, last;

	first = group * nilfs_dat_entries_per_group(dat);
	last = first + nilfs_dat_entries_per_group(dat) - 1;
	return (vblocknr >= first) && (vblocknr <= last);
}

/**
 * nilfs_dat_freev - free virtual block numbers
 * @dat: DAT file inode
 * @vblocknrs: array of virtual block numbers
 * @nitems: number of virtual block numbers
 *
 * Description: nilfs_dat_freev() frees the virtual block numbers specified by
 * @vblocknrs and @nitems.
 *
 * Return Value: On success, 0 is returned. On error, one of the following
 * nagative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 *
 * %-ENOENT - The virtual block number have not been allocated.
 */
int nilfs_dat_freev(struct inode *dat, __u64 *vblocknrs, size_t nitems)
{
	struct buffer_head *desc_bh, *bitmap_bh;
	struct nilfs_dat_group_desc *desc;
	unsigned char *bitmap;
	void *desc_kaddr, *bitmap_kaddr;
	unsigned long group;
	unsigned long group_offset;
	int i, j, n, ret;

	for (i = 0; i < nitems; i += n) {
		group = nilfs_dat_group(dat, vblocknrs[i]);
		ret = nilfs_dat_get_desc_block(dat, group, 0, &desc_bh);
		if (ret < 0)
			return ret;
		ret = nilfs_dat_get_bitmap_block(dat, group, 0, &bitmap_bh);
		if (ret < 0) {
			brelse(desc_bh);
			return ret;
		}
		desc_kaddr = kmap(desc_bh->b_page);
		desc = nilfs_dat_block_get_group_desc(
			dat, group, desc_bh, desc_kaddr);
		bitmap_kaddr = kmap(bitmap_bh->b_page);
		bitmap = nilfs_dat_block_get_bitmap(
			dat, bitmap_bh, bitmap_kaddr);
		for (j = i, n = 0;
		     (j < nitems) && nilfs_dat_group_is_in(dat, group,
							   vblocknrs[j]);
		     j++, n++) {
			group_offset = nilfs_dat_group_offset(
				dat, vblocknrs[j]);
			if (!nilfs_dat_clear_bit_atomic(
				    nilfs_mdt_bgl_lock(dat, group),
				    group_offset, bitmap)) {
				printk(KERN_CRIT
				       "%s: virtual block number %llu already "
				       "freed\n",
				       __func__,
				       (unsigned long long)vblocknrs[j]);
				BUG();
			}
		}
		nilfs_dat_group_desc_add_entries(dat, group, desc, n);

		kunmap(bitmap_bh->b_page);
		kunmap(desc_bh->b_page);

		nilfs_mdt_mark_buffer_dirty(desc_bh);
		nilfs_mdt_mark_buffer_dirty(bitmap_bh);
		nilfs_mdt_mark_dirty(dat);

		brelse(bitmap_bh);
		brelse(desc_bh);
	}

	return 0;
}

/**
 * nilfs_dat_move - change a block number
 * @dat: DAT file inode
 * @vblocknr: virtual block number
 * @blocknr: block number
 *
 * Description: nilfs_dat_move() changes the block number associated with
 * @vblocknr to @blocknr.
 *
 * Return Value: On success, 0 is returned. On error, one of the following
 * negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 */
int nilfs_dat_move(struct inode *dat, __u64 vblocknr, sector_t blocknr)
{
	struct buffer_head *entry_bh;
	struct nilfs_dat_entry *entry;
	void *entry_kaddr;
	int ret;

	ret = nilfs_dat_get_entry_block(dat, vblocknr, 0, &entry_bh);
	if (ret < 0)
		return ret;
	entry_kaddr = kmap_atomic(entry_bh->b_page, KM_USER0);
	entry = nilfs_dat_block_get_entry(
		dat, vblocknr, entry_bh, entry_kaddr);
	if (nilfs_dat_entry_get_blocknr(dat, entry) == 0) {
		printk(KERN_CRIT "%s: vbn = %llu, [%llu, %llu)\n",
		       __func__,
		       (unsigned long long)vblocknr,
		       (unsigned long long)nilfs_dat_entry_get_start(dat,
								     entry),
		       (unsigned long long)nilfs_dat_entry_get_end(dat, entry));
		BUG();
	}
	BUG_ON(blocknr == 0);
	nilfs_dat_entry_set_blocknr(dat, entry, blocknr);
	kunmap_atomic(entry_kaddr, KM_USER0);

	nilfs_mdt_mark_buffer_dirty(entry_bh);
	nilfs_mdt_mark_dirty(dat);

	brelse(entry_bh);

	return 0;
}

/**
 * nilfs_dat_translate - translate a virtual block number to a block number
 * @dat: DAT file inode
 * @vblocknr: virtual block number
 * @blocknrp: pointer to a block number
 *
 * Description: nilfs_dat_translate() maps the virtual block number @vblocknr
 * to the corresponding block number.
 *
 * Return Value: On success, 0 is returned and the block number associated
 * with @vblocknr is stored in the place pointed by @blocknrp. On error, one
 * of the following negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 *
 * %-ENOENT - A block number associated with @vblocknr does not exist.
 */
int nilfs_dat_translate(struct inode *dat, __u64 vblocknr, sector_t *blocknrp)
{
	struct buffer_head *entry_bh;
	struct nilfs_dat_entry *entry;
	sector_t blocknr;
	void *entry_kaddr;
	int ret;

#if 0
#ifdef CONFIG_NILFS_DEBUG
	struct buffer_head *bitmap_bh;
	void *bitmap_kaddr;
	unsigned char *bitmap;

	ret = nilfs_dat_get_bitmap_block(dat, nilfs_dat_group(dat, vblocknr),
					 0, &bitmap_bh);
	if (ret < 0)
		return ret;
	bitmap_kaddr = kmap_atomic(bitmap_bh->b_page, KM_USER0);
	bitmap = nilfs_dat_block_get_bitmap(dat, bitmap_bh, bitmap_kaddr);
	if (!nilfs_dat_test_bit(nilfs_dat_group_offset(dat, vblocknr),
				bitmap)) {
		printk(KERN_CRIT
		       "%s: virtual block number %llu not allocated\n",
		       __func__, (unsigned long long)vblocknr);
		BUG();
	}
	kunmap_atomic(bitmap_kaddr, KM_USER0);
	brelse(bitmap_bh);
#endif	/* CONFIG_NILFS_DEBUG */
#endif
	dat_debug(2, "called (vblocknr=%llu)\n", (unsigned long long)vblocknr);
	ret = nilfs_dat_get_entry_block(dat, vblocknr, 0, &entry_bh);
	if (ret < 0) {
		dat_debug(1, "failed (ret=%d)\n", ret);
		return ret;
	}
	entry_kaddr = kmap_atomic(entry_bh->b_page, KM_USER0);
	entry = nilfs_dat_block_get_entry(dat, vblocknr, entry_bh, entry_kaddr);
	blocknr = nilfs_dat_entry_get_blocknr(dat, entry);
	if (blocknr == 0) {
#ifdef CONFIG_NILFS_DEBUG
		printk(KERN_DEBUG "%s: invalid virtual block number: %llu\n",
		       __func__, (unsigned long long)vblocknr);
		BUG();
#endif
		ret = -ENOENT;
		goto out;
	}
	if (blocknrp != NULL)
		*blocknrp = blocknr;

 out:
	dat_debug(2, "done: vblocknr=%llu -> blocknr=%llu (ret=%d)\n",
		  (unsigned long long)vblocknr,
		  (unsigned long long)blocknr,
		  ret);
	kunmap_atomic(entry_kaddr, KM_USER0);
	brelse(entry_bh);
	return ret;
}

/**
 * nilfs_dat_get_vinfo -
 * @vinfo:
 * @nvinfo:
 */
ssize_t nilfs_dat_get_vinfo(struct inode *dat,
			    struct nilfs_vinfo *vinfo,
			    size_t nvi)
{
	struct buffer_head *entry_bh;
	struct nilfs_dat_entry *entry;
	__u64 first, last;
	void *kaddr;
	unsigned long entries_per_block;
	int i, j, n, ret;

	entries_per_block = nilfs_dat_entries_per_block(dat);
	for (i = 0; i < nvi; i += n) {
		ret = nilfs_dat_get_entry_block(dat, vinfo[i].vi_vblocknr, 0,
						&entry_bh);
		if (ret < 0)
			return ret;
		kaddr = kmap_atomic(entry_bh->b_page, KM_USER0);
		/* last virtual block number in this block */
		first = vinfo[i].vi_vblocknr;
		do_div(first, entries_per_block);
		first *= entries_per_block;
		last = first + entries_per_block - 1;
		for (j = i, n = 0;
		     (j < nvi) && (vinfo[j].vi_vblocknr >= first) &&
			     (vinfo[j].vi_vblocknr <= last);
		     j++, n++) {
			entry = nilfs_dat_block_get_entry(
				dat, vinfo[j].vi_vblocknr, entry_bh, kaddr);
			vinfo[j].vi_start =
				nilfs_dat_entry_get_start(dat, entry);
			vinfo[j].vi_end = nilfs_dat_entry_get_end(dat, entry);
			vinfo[j].vi_blocknr =
				nilfs_dat_entry_get_blocknr(dat, entry);
		}
		kunmap_atomic(kaddr, KM_USER0);
		brelse(entry_bh);
	}

	return nvi;
}
