/*
 * sufile.h - NILFS segment usage file.
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
 * sufile.h,v 1.21 2008-02-04 08:12:26 koji Exp
 *
 * Written by Koji Sato <koji@osrg.net>.
 */

#ifndef _NILFS_SUFILE_H
#define _NILFS_SUFILE_H

#include <linux/fs.h>
#include <linux/buffer_head.h>
#include "nilfs_fs.h"
#include "nilfs_types.h"
#include "mdt.h"

#define NILFS_SUFILE_GFP	NILFS_MDT_GFP

inline static unsigned long nilfs_sufile_get_nsegments(struct inode *sufile)
{
	return NILFS_MDT(sufile)->mi_nilfs->ns_nsegments;
}

inline static unsigned long nilfs_sufile_get_nrsvsegs(struct inode *sufile)
{
	unsigned long nsegments, rsvpercent, nrsvsegs;

	nsegments = NILFS_MDT(sufile)->mi_nilfs->ns_nsegments;
	rsvpercent = NILFS_MDT(sufile)->mi_nilfs->ns_r_segments_percentage;
	nrsvsegs = (nsegments * rsvpercent - 1) / 100 + 1;
	return max_t(unsigned long, nrsvsegs, NILFS_MIN_NRSVSEGS);
}

int nilfs_sufile_alloc(struct inode *, nilfs_segnum_t *);
int nilfs_sufile_cancel_free(struct inode *, nilfs_segnum_t);
int nilfs_sufile_freev(struct inode *, nilfs_segnum_t *, size_t);
int nilfs_sufile_free(struct inode *, nilfs_segnum_t);
int nilfs_sufile_get_segment_usage(struct inode *, nilfs_segnum_t,
				   struct nilfs_segment_usage **,
				   struct buffer_head **);
void nilfs_sufile_put_segment_usage(struct inode *, nilfs_segnum_t,
				    struct buffer_head *);
int nilfs_sufile_get_stat(struct inode *, struct nilfs_sustat *);
int nilfs_sufile_get_ncleansegs(struct inode *, unsigned long *);
int nilfs_sufile_get_ndirtysegs(struct inode *, unsigned long *);
int nilfs_sufile_set_error(struct inode *, nilfs_segnum_t);
ssize_t nilfs_sufile_get_segment_usages(struct inode *, nilfs_segnum_t,
					struct nilfs_segment_usage *, size_t);
ssize_t nilfs_sufile_get_suinfo(struct inode *, nilfs_segnum_t,
				struct nilfs_suinfo *, size_t);


#endif	/* _NILFS_SUFILE_H */

/* Local Variables:		*/
/* eval: (c-set-style "linux")	*/
/* End:				*/
