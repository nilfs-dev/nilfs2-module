/*
 * segbuf.c - NILFS segment buffer
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
 *
 */

#include <linux/buffer_head.h>
#include <linux/writeback.h>
#include "page.h"
#include "segbuf.h"
#include "seglist.h"


static struct kmem_cache *nilfs_segbuf_cachep;

#if NEED_OLD_INIT_ONCE_ARGS
static void nilfs_segbuf_init_once(void *obj, struct kmem_cache *cachep,
				   unsigned long flags)
#else
static void nilfs_segbuf_init_once(struct kmem_cache *cachep, void *obj)
#endif
{
	struct nilfs_segment_buffer *segbuf = obj;
#if NEED_SLAB_CTOR_CONSTRUCTOR
	if ((flags & (SLAB_CTOR_VERIFY | SLAB_CTOR_CONSTRUCTOR)) ==
	   SLAB_CTOR_CONSTRUCTOR) {
#endif
		memset(segbuf, 0, sizeof(*segbuf));
#if NEED_SLAB_CTOR_CONSTRUCTOR
	}
#endif
}

int __init nilfs_init_segbuf_cache(void)
{
	nilfs_segbuf_cachep =
		kmem_cache_create("nilfs2_segbuf_cache",
				  sizeof(struct nilfs_segment_buffer),
				  0, SLAB_RECLAIM_ACCOUNT,
#if NEED_SLAB_DESTRUCTOR_ARG
				  nilfs_segbuf_init_once, NULL);
#else
				  nilfs_segbuf_init_once);
#endif
	return ((nilfs_segbuf_cachep == NULL) ? -ENOMEM : 0);
}

void nilfs_destroy_segbuf_cache(void)
{
	kmem_cache_destroy(nilfs_segbuf_cachep);
}

struct nilfs_segment_buffer *nilfs_segbuf_new(struct super_block *sb)
{
	struct nilfs_segment_buffer *segbuf;

	segbuf = kmem_cache_alloc(nilfs_segbuf_cachep, GFP_NOFS);
	if (unlikely(!segbuf))
		return NULL;

	segbuf->sb_super = sb;
	INIT_LIST_HEAD(&segbuf->sb_list);
	INIT_LIST_HEAD(&segbuf->sb_segsum_buffers);
	INIT_LIST_HEAD(&segbuf->sb_payload_buffers);
	segbuf->sb_segent = NULL;
	return segbuf;
}

void nilfs_segbuf_free(struct nilfs_segment_buffer *segbuf)
{
	struct nilfs_segment_entry *ent = segbuf->sb_segent;

	if (ent != NULL && list_empty(&ent->list)) {
		/* free isolated segment list head */
		nilfs_free_segment_entry(segbuf->sb_segent);
		segbuf->sb_segent = NULL;
	}
	kmem_cache_free(nilfs_segbuf_cachep, segbuf);
}

int nilfs_segbuf_map(struct nilfs_segment_buffer *segbuf, __u64 segnum,
		     unsigned long offset, struct the_nilfs *nilfs)
{
	struct nilfs_segment_entry *ent;

	segbuf->sb_segnum = segnum;
	nilfs_get_segment_range(nilfs, segnum, &segbuf->sb_fseg_start,
				&segbuf->sb_fseg_end);

	segbuf->sb_pseg_start = segbuf->sb_fseg_start + offset;
	segbuf->sb_rest_blocks =
		segbuf->sb_fseg_end - segbuf->sb_pseg_start + 1;

	/* Attach a segment list head */
	ent = segbuf->sb_segent;
	if (ent == NULL) {
		segbuf->sb_segent = nilfs_alloc_segment_entry(segnum);
		if (unlikely(!segbuf->sb_segent))
			return -ENOMEM;
	} else {
		BUG_ON(ent->bh_su || !list_empty(&ent->list));
		ent->segnum = segnum;
	}
	return 0;
}

void nilfs_segbuf_set_next_segnum(struct nilfs_segment_buffer *segbuf,
				  __u64 nextnum, struct the_nilfs *nilfs)
{
	segbuf->sb_nextnum = nextnum;
	segbuf->sb_sum.next = nilfs_get_segment_start_blocknr(nilfs, nextnum);
}

int nilfs_segbuf_extend_segsum(struct nilfs_segment_buffer *segbuf)
{
	struct buffer_head *bh;

	bh = sb_getblk(segbuf->sb_super,
		       segbuf->sb_pseg_start + segbuf->sb_sum.nsumblk);
	if (unlikely(!bh))
		return -ENOMEM;

	nilfs_segbuf_add_segsum_buffer(segbuf, bh);
	return 0;
}

int nilfs_segbuf_extend_payload(struct nilfs_segment_buffer *segbuf,
				struct buffer_head **bhp)
{
	struct buffer_head *bh;

	bh = sb_getblk(segbuf->sb_super,
		       segbuf->sb_pseg_start + segbuf->sb_sum.nblocks);
	if (unlikely(!bh))
		return -ENOMEM;

	nilfs_segbuf_add_payload_buffer(segbuf, bh);
	*bhp = bh;
	return 0;
}

int nilfs_segbuf_reset(struct nilfs_segment_buffer *segbuf, unsigned flags,
		       time_t ctime)
{
	int err;

	segbuf->sb_sum.nblocks = segbuf->sb_sum.nsumblk = 0;
	err = nilfs_segbuf_extend_segsum(segbuf);
	if (unlikely(err))
		return err;

	segbuf->sb_sum.flags = flags;
	segbuf->sb_sum.sumbytes = sizeof(struct nilfs_segment_summary);
	segbuf->sb_sum.nfinfo = segbuf->sb_sum.nfileblk = 0;
	segbuf->sb_sum.ctime = ctime;

	segbuf->sb_io_error = 0;
	return 0;
}

/*
 * Setup segument summary
 */
void nilfs_segbuf_fill_in_segsum(struct nilfs_segment_buffer *segbuf)
{
	struct nilfs_segment_summary *raw_sum;
	struct buffer_head *bh_sum;

	bh_sum = list_entry(segbuf->sb_segsum_buffers.next,
			    struct buffer_head, b_assoc_buffers);
	raw_sum = (struct nilfs_segment_summary *)bh_sum->b_data;

	raw_sum->ss_magic    = cpu_to_le32(NILFS_SEGSUM_MAGIC);
	raw_sum->ss_bytes    = cpu_to_le16(sizeof(*raw_sum));
	raw_sum->ss_flags    = cpu_to_le16(segbuf->sb_sum.flags);
	raw_sum->ss_seq      = cpu_to_le64(segbuf->sb_sum.seg_seq);
	raw_sum->ss_create   = cpu_to_le64(segbuf->sb_sum.ctime);
	raw_sum->ss_next     = cpu_to_le64(segbuf->sb_sum.next);
	raw_sum->ss_nblocks  = cpu_to_le32(segbuf->sb_sum.nblocks);
	raw_sum->ss_nfinfo   = cpu_to_le32(segbuf->sb_sum.nfinfo);
	raw_sum->ss_sumbytes = cpu_to_le32(segbuf->sb_sum.sumbytes);
	raw_sum->ss_pad      = 0;
}

/*
 * CRC calculation routines
 */
void nilfs_segbuf_fill_in_segsum_crc(struct nilfs_segment_buffer *segbuf,
				     u32 seed)
{
	struct buffer_head *bh;
	struct nilfs_segment_summary *raw_sum;
	unsigned long size, bytes = segbuf->sb_sum.sumbytes;
	u32 crc;

	bh = list_entry(segbuf->sb_segsum_buffers.next, struct buffer_head,
			b_assoc_buffers);

	raw_sum = (struct nilfs_segment_summary *)bh->b_data;
	size = min_t(unsigned long, bytes, bh->b_size);
	crc = nilfs_crc32(seed,
			  (unsigned char *)raw_sum +
			  sizeof(raw_sum->ss_datasum) +
			  sizeof(raw_sum->ss_sumsum),
			  size - (sizeof(raw_sum->ss_datasum) +
				  sizeof(raw_sum->ss_sumsum)));

	list_for_each_entry_continue(bh, &segbuf->sb_segsum_buffers,
				     b_assoc_buffers) {
		bytes -= size;
		size = min_t(unsigned long, bytes, bh->b_size);
		crc = nilfs_crc32(crc, bh->b_data, size);
	}
	raw_sum->ss_sumsum = cpu_to_le32(crc);
}

void nilfs_segbuf_fill_in_data_crc(struct nilfs_segment_buffer *segbuf,
				   u32 seed)
{
	struct buffer_head *bh;
	struct nilfs_segment_summary *raw_sum;
	void *kaddr;
	u32 crc;

	bh = list_entry(segbuf->sb_segsum_buffers.next, struct buffer_head,
			b_assoc_buffers);
	raw_sum = (struct nilfs_segment_summary *)bh->b_data;
	crc = nilfs_crc32(seed,
			  (unsigned char *)raw_sum +
			  sizeof(raw_sum->ss_datasum),
			  bh->b_size - sizeof(raw_sum->ss_datasum));

	list_for_each_entry_continue(bh, &segbuf->sb_segsum_buffers,
				     b_assoc_buffers) {
		crc = nilfs_crc32(crc, bh->b_data, bh->b_size);
	}
	list_for_each_entry(bh, &segbuf->sb_payload_buffers, b_assoc_buffers) {
		kaddr = kmap_atomic(bh->b_page, KM_USER0);
		crc = nilfs_crc32(crc, kaddr + bh_offset(bh), bh->b_size);
		kunmap_atomic(kaddr, KM_USER0);
	}
	raw_sum->ss_datasum = cpu_to_le32(crc);
}


/*
 * BIO operations
 */
#if NEED_OLD_BIO_END_IO
static int
nilfs_end_bio_write(struct bio *bio, unsigned int bytes_done, int err)
#else
static void nilfs_end_bio_write(struct bio *bio, int err)
#endif
{
	const int uptodate = test_bit(BIO_UPTODATE, &bio->bi_flags);
	struct nilfs_write_info *wi;

#if NEED_OLD_BIO_END_IO
	if (bio->bi_size)
		return 1;
#endif

	wi = bio->bi_private;

	if (err == -EOPNOTSUPP) {
		set_bit(BIO_EOPNOTSUPP, &bio->bi_flags);
		bio_put(bio);
#if NEED_OLD_BIO_END_IO
		return 0;
#endif
		/* to be detected by submit_seg_bio() */
	}

	if (!uptodate)
		atomic_inc(&wi->err);

	bio_put(bio);
	complete(&wi->bio_event);
#if NEED_OLD_BIO_END_IO
	return 0;
#endif
}

static int nilfs_submit_seg_bio(struct nilfs_write_info *wi, int mode)
{
	struct bio *bio = wi->bio;
	int err;

	if (wi->nbio > 0 && bdi_write_congested(wi->bdi)) {
		seg_debug(3, "waiting for a segment\n");
		wait_for_completion(&wi->bio_event);
		wi->nbio--;
		if (unlikely(atomic_read(&wi->err))) {
			seg_debug(2, "detected io-error\n");
			bio_put(bio);
			err = -EIO;
			goto failed;
		}
	}

	bio->bi_end_io = nilfs_end_bio_write;
	bio->bi_private = wi;
	seg_debug(3, "submitting bio (start_sector=%llu, size=%u, "
		  "vcnt=%hu, barrier=%d)\n",
		  (unsigned long long)bio->bi_sector,
		  bio->bi_size, bio->bi_vcnt,
		  (mode & (1 << BIO_RW_BARRIER)) != 0);

	bio_get(bio);
	submit_bio(mode, bio);
	if (bio_flagged(bio, BIO_EOPNOTSUPP)) {
		seg_debug(2, "aborted bio submission\n");
		bio_put(bio);
		err = -EOPNOTSUPP;
		goto failed;
	}
	wi->nbio++;
	bio_put(bio);

	wi->bio = NULL;
	wi->rest_blocks -= wi->end - wi->start;
	wi->nr_vecs = min(wi->max_pages, wi->rest_blocks);
	wi->start = wi->end;
	return 0;

 failed:
	wi->bio = NULL;
	return err;
}

/**
 * nilfs_alloc_seg_bio - allocate a bio for writing segment.
 * @sb: super block
 * @start: beginning disk block number of this BIO.
 * @nr_vecs: request size of page vector.
 *
 * alloc_seg_bio() allocates a new BIO structure and initialize it.
 *
 * Return Value: On success, pointer to the struct bio is returned.
 * On error, NULL is returned.
 */
static struct bio *nilfs_alloc_seg_bio(struct super_block *sb, sector_t start,
				       int nr_vecs)
{
	struct bio *bio;

	bio = bio_alloc(GFP_NOWAIT, nr_vecs);
	if (bio == NULL) {
		seg_debug(1, "bio_alloc() failed. retrying (nr_vecs=%d)\n",
			  nr_vecs);
		while (!bio && (nr_vecs >>= 1))
			bio = bio_alloc(GFP_NOWAIT, nr_vecs);
		seg_debug(1, "done retry (nr_vecs=%d, bio=%p)\n",
			  nr_vecs, bio);
	}
	if (likely(bio)) {
		bio->bi_bdev = sb->s_bdev;
		bio->bi_sector = (sector_t)start << (sb->s_blocksize_bits - 9);
		seg_debug(3, "allocated bio (max_vecs=%d)\n",
			  bio->bi_max_vecs);
	}
	return bio;
}

void nilfs_segbuf_prepare_write(struct nilfs_segment_buffer *segbuf,
				struct nilfs_write_info *wi)
{
	wi->bio = NULL;
	wi->rest_blocks = segbuf->sb_sum.nblocks;
	wi->max_pages = bio_get_nr_vecs(wi->sb->s_bdev);
	wi->nr_vecs = min(wi->max_pages, wi->rest_blocks);
	wi->start = wi->end = 0;
	wi->nbio = 0;
	wi->blocknr = segbuf->sb_pseg_start;

	atomic_set(&wi->err, 0);
	init_completion(&wi->bio_event);
}

static int nilfs_submit_bh(struct nilfs_write_info *wi, struct buffer_head *bh,
			   int mode)
{
	int len, err;

	BUG_ON(wi->nr_vecs <= 0);
 repeat:
	if (!wi->bio) {
		wi->bio = nilfs_alloc_seg_bio(wi->sb, wi->blocknr + wi->end,
					      wi->nr_vecs);
		if (unlikely(!wi->bio)) {
			seg_debug(2, "failed to allocate bio\n");
			return -ENOMEM;
		}
	}

	len = bio_add_page(wi->bio, bh->b_page, bh->b_size, bh_offset(bh));
	if (len == bh->b_size) {
		wi->end++;
		return 0;
	}
	/* bio is FULL */
	err = nilfs_submit_seg_bio(wi, mode);
	/* never submit current bh */
	if (likely(!err))
		goto repeat;
	return err;
}

int nilfs_segbuf_write(struct nilfs_segment_buffer *segbuf,
		       struct nilfs_write_info *wi)
{
	struct buffer_head *bh;
	int res, rw = WRITE;

	seg_debug(3, "submitting summary blocks\n");
	list_for_each_entry(bh, &segbuf->sb_segsum_buffers, b_assoc_buffers) {
		res = nilfs_submit_bh(wi, bh, rw);
		if (unlikely(res))
			goto failed_bio;
	}

	seg_debug(3, "submitting normal blocks (index=%d)\n", wi->end);
	list_for_each_entry(bh, &segbuf->sb_payload_buffers, b_assoc_buffers) {
		res = nilfs_submit_bh(wi, bh, rw);
		if (unlikely(res))
			goto failed_bio;
	}

	if (wi->bio) {
		/*
		 * Last BIO is always sent through the following
		 * submission.
		 */
		rw |= (1 << BIO_RW_SYNC);
		res = nilfs_submit_seg_bio(wi, rw);
		if (unlikely(res))
			goto failed_bio;
	}

	res = 0;
 out:
	seg_debug(1 + !res, "submitted a segment "
		  "(err=%d, pseg_start=%llu, #requested-blocks=%u)\n",
		  res, (unsigned long long)segbuf->sb_pseg_start, wi->end);
	return res;

 failed_bio:
	atomic_inc(&wi->err);
	goto out;
}

/**
 * nilfs_segbuf_wait - wait for completion of requested BIOs
 * @wi: nilfs_write_info
 *
 * Return Value: On Success, 0 is returned. On Error, one of the following
 * negative error code is returned.
 *
 * %-EIO - I/O error
 */
int nilfs_segbuf_wait(struct nilfs_segment_buffer *segbuf,
		      struct nilfs_write_info *wi)
{
	int err = 0;

	seg_debug(3, "called nbio=%d\n", wi->nbio);
	if (!wi->nbio)
		return 0;

	do {
		wait_for_completion(&wi->bio_event);
	} while (--wi->nbio > 0);

	seg_debug(3, "wait completed\n");
	if (unlikely(atomic_read(&wi->err) > 0)) {
		printk(KERN_ERR "NILFS: IO error writing segment\n");
		err = -EIO;
		segbuf->sb_io_error = 1;
	}
	return err;
}
