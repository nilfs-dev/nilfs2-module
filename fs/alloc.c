/*
 * alloc.c - NILFS dat/inode allocator
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
 */

#include "mdt.h"
#include "alloc.h"

static inline unsigned long
nilfs_persistent_desc_offset(struct inode *inode, nilfs_bgno_t group)
{
	return sector_div(group,
			  nilfs_persistent_group_descs_per_block(inode));
}


struct nilfs_persistent_group_desc *
nilfs_persistent_get_group_desc(struct inode *inode,
			 nilfs_bgno_t group,
			 const struct buffer_head *desc_bh)
{
	void *kaddr = kmap(desc_bh->b_page);

	return (struct nilfs_persistent_group_desc *)
		(kaddr + bh_offset(desc_bh)) +
		nilfs_persistent_desc_offset(inode, group);
}

static void
nilfs_persistent_desc_block_init(struct inode *inode, struct buffer_head *bh,
				 void *kaddr)
{
	struct nilfs_persistent_group_desc *desc = kaddr + bh_offset(bh);
	int i;

	for (i = 0; i < nilfs_persistent_group_descs_per_block(inode); i++) {
		desc->pg_nfrees =
			cpu_to_le32(nilfs_persistent_entries_per_group(inode));
		desc++;
	}
}

char *
nilfs_persistent_get_group_bitmap_buffer(struct inode *inode,
					 const struct buffer_head *bitmap_bh)
{
	void *kaddr = kmap(bitmap_bh->b_page);

	return (char *)(kaddr + bh_offset(bitmap_bh));
}

void
nilfs_persistent_put_group_bitmap_buffer(struct inode *inode,
					 const struct buffer_head *bitmap_bh)
{
	kunmap(bitmap_bh->b_page);
}

int
nilfs_persistent_get_group_desc_block(struct inode *inode, nilfs_bgno_t group,
				      struct buffer_head **desc_bhp)
{
	nilfs_blkoff_t blkoff =
		nilfs_persistent_group_desc_blkoff(inode, group);

	return nilfs_mdt_get_block(inode, blkoff, 1,
				   nilfs_persistent_desc_block_init, desc_bhp);
}

static int
nilfs_persistent_get_group_bitmap_block(struct inode *inode,
					nilfs_bgno_t group,
					struct buffer_head **bitmap_bhp)
{
	nilfs_blkoff_t blkoff =
		nilfs_persistent_group_bitmap_blkoff(inode, group);

	return nilfs_mdt_get_block(inode, blkoff, 1, NULL, bitmap_bhp);
}

static int
nilfs_persistent_group_find_available_slot(struct inode *inode,
					   nilfs_bgno_t group,
					   unsigned long target,
					   unsigned char *bitmap,
					   int bsize)
{
	int curr, pos, end;
	int i;

	if (target > 0) {
		end = (target + BITS_PER_LONG - 1) & ~(BITS_PER_LONG - 1);
		if (end > bsize)
			end = bsize;
		pos = nilfs_persistent_find_next_zero_bit(bitmap, end, target);
		if ((pos < end) &&
		    !nilfs_persistent_set_bit_atomic(
			    nilfs_mdt_bgl_lock(inode, group), pos, bitmap))
			return pos;
	} else
		end = 0;

	for (i = 0, curr = end;
	     i < bsize;
	     i += BITS_PER_LONG, curr += BITS_PER_LONG) {
		/* wrap around */
		if (curr >= bsize)
			curr = 0;
		while (*((unsigned long *)bitmap + curr / BITS_PER_LONG)
		       != ~0UL) {
			end = curr + BITS_PER_LONG;
			if (end > bsize)
				end = bsize;
			pos = nilfs_persistent_find_next_zero_bit(bitmap, end,
								  curr);
			if ((pos < end) &&
			    !nilfs_persistent_set_bit_atomic(
				    nilfs_mdt_bgl_lock(inode, group), pos,
				    bitmap))
				return pos;
		}
	}

	return -ENOSPC;
}

int nilfs_persistent_prepare_alloc_entry(struct inode *inode,
					 struct nilfs_persistent_req *req,
					 nilfs_bgno_t *group_p, int *target_p)
{
	struct buffer_head *desc_bh, *bitmap_bh;
	struct nilfs_persistent_group_desc *desc;
	nilfs_bgno_t group;
	unsigned long ngroups;
	char *start;
	int pos, target, ret, bsize;
	unsigned long i;

	bsize = nilfs_persistent_entries_per_group(inode);

	group = *group_p;
	target = *target_p;

	ngroups = NILFS_MDT(inode)->mi_groups_count;

	for (i = 0; i < ngroups; i++, group++) {
		if (group >= ngroups)
			group = 0;
		if ((ret = nilfs_persistent_get_group_desc_block(
			     inode, group, &desc_bh)) < 0)
			return ret;
		desc = nilfs_persistent_get_group_desc(inode, group, desc_bh);
		if (le32_to_cpu(desc->pg_nfrees) > 0) {
			if ((ret = nilfs_persistent_get_group_bitmap_block(
				     inode, group, &bitmap_bh)) < 0) {
				nilfs_persistent_put_group_desc(
					inode, desc_bh);
				nilfs_persistent_put_group_desc_block(
					inode, desc_bh);
				return ret;
			}
			start = nilfs_persistent_get_group_bitmap_buffer(
				inode, bitmap_bh);
			pos = nilfs_persistent_group_find_available_slot(
				inode, group, target, start, bsize);
			if (pos >= 0) {
				/* found a free inode number */
				spin_lock(nilfs_mdt_bgl_lock(inode, group));
				desc->pg_nfrees = cpu_to_le32(
					le32_to_cpu(desc->pg_nfrees) - 1);
				spin_unlock(nilfs_mdt_bgl_lock(inode, group));

				*group_p = group;
				*target_p = pos;
				req->pr_desc_bh = desc_bh;
				req->pr_bitmap_bh = bitmap_bh;
				return 0;
			}
			nilfs_persistent_put_group_bitmap_buffer(inode,
								 bitmap_bh);
			nilfs_persistent_put_group_bitmap_block(inode,
								bitmap_bh);
		}
		nilfs_persistent_put_group_desc(inode, desc_bh);
		nilfs_persistent_put_group_desc_block(inode, desc_bh);
		target = 0;
	}

	return -ENOSPC;
}

void nilfs_persistent_commit_alloc_entry(struct inode *inode,
					 struct nilfs_persistent_req *req)
{
	nilfs_mdt_mark_buffer_dirty(req->pr_bitmap_bh);
	nilfs_mdt_mark_buffer_dirty(req->pr_desc_bh);

	nilfs_persistent_put_group_bitmap_buffer(inode, req->pr_bitmap_bh);
	nilfs_persistent_put_group_bitmap_block(inode, req->pr_bitmap_bh);
	nilfs_persistent_put_group_desc(inode, req->pr_desc_bh);
	nilfs_persistent_put_group_desc_block(inode, req->pr_desc_bh);
}

void nilfs_persistent_abort_alloc_entry(struct inode *inode,
					struct nilfs_persistent_req *req,
					nilfs_bgno_t group, int grpoff)
{
	struct nilfs_persistent_group_desc *desc;
	char *bitmap_buffer;

	desc = nilfs_persistent_get_group_desc(inode, group, req->pr_desc_bh);
	bitmap_buffer = nilfs_persistent_get_group_bitmap_buffer(
		inode, req->pr_bitmap_bh);

	if (!nilfs_persistent_clear_bit_atomic(
		    nilfs_mdt_bgl_lock(inode, group), grpoff, bitmap_buffer))
		printk(KERN_WARNING
		       "persistent entry numer %lu already freed\n",
		       req->pr_ino);

	spin_lock(nilfs_mdt_bgl_lock(inode, group));
	desc->pg_nfrees = cpu_to_le32(le32_to_cpu(desc->pg_nfrees) + 1);
	spin_unlock(nilfs_mdt_bgl_lock(inode, group));

	nilfs_persistent_put_group_bitmap_buffer(inode, req->pr_bitmap_bh);
	nilfs_persistent_put_group_bitmap_block(inode, req->pr_bitmap_bh);
	nilfs_persistent_put_group_desc(inode, req->pr_desc_bh);
	nilfs_persistent_put_group_desc_block(inode, req->pr_desc_bh);

	req->pr_nslot = 0;
	req->pr_bitmap_bh = NULL;
	req->pr_desc_bh = NULL;
}

int nilfs_persistent_prepare_free_entry(struct inode *inode,
					struct nilfs_persistent_req *req,
					nilfs_bgno_t group)
{
	struct buffer_head *desc_bh, *bitmap_bh;
	int ret;


	if ((ret = nilfs_persistent_get_group_desc_block(
		     inode, group, &desc_bh)) < 0)
		return ret;
	if ((ret = nilfs_persistent_get_group_bitmap_block(
		     inode, group, &bitmap_bh)) < 0) {
		nilfs_persistent_put_group_desc_block(inode, desc_bh);
		return ret;
	}

	req->pr_desc_bh = desc_bh;
	req->pr_bitmap_bh = bitmap_bh;

	return 0;
}

void nilfs_persistent_abort_free_entry(struct inode *inode,
				       struct nilfs_persistent_req *req)
{
	nilfs_persistent_put_group_bitmap_buffer(inode, req->pr_bitmap_bh);
	nilfs_persistent_put_group_bitmap_block(inode, req->pr_bitmap_bh);
	nilfs_persistent_put_group_desc(inode, req->pr_desc_bh);
	nilfs_persistent_put_group_desc_block(inode, req->pr_desc_bh);

	req->pr_nslot = 0;
	req->pr_bitmap_bh = NULL;
	req->pr_desc_bh = NULL;
}
