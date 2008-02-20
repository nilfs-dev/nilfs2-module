/*
 * cpfile.h - NILFS checkpoint file.
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
 * cpfile.h,v 1.15 2007-06-12 03:52:54 koji Exp
 *
 * Written by Koji Sato <koji@osrg.net>.
 */

#ifndef _NILFS_CPFILE_H
#define _NILFS_CPFILE_H

#include <linux/fs.h>
#include <linux/buffer_head.h>
#include "nilfs_fs.h"
#include "nilfs_types.h"

#define NILFS_CPFILE_GFP	NILFS_MDT_GFP


int nilfs_cpfile_get_checkpoint(struct inode *, nilfs_cno_t, int,
				struct nilfs_checkpoint **,
				struct buffer_head **);
void nilfs_cpfile_put_checkpoint(struct inode *, nilfs_cno_t,
				 struct buffer_head *);
int nilfs_cpfile_delete_checkpoints(struct inode *, nilfs_cno_t, nilfs_cno_t);
int nilfs_cpfile_delete_checkpoint(struct inode *, nilfs_cno_t);
int nilfs_cpfile_get_checkpoints(struct inode *, nilfs_cno_t,
				 struct nilfs_checkpoint *, unsigned long *);
int nilfs_cpfile_change_cpmode(struct inode *, nilfs_cno_t, int);
int nilfs_cpfile_is_snapshot(struct inode *, nilfs_cno_t);
int nilfs_cpfile_get_stat(struct inode *, struct nilfs_cpstat *);
int nilfs_cpfile_get_snapshots(struct inode *, nilfs_cno_t *,
			       unsigned long *, nilfs_cno_t *);
ssize_t nilfs_cpfile_get_cpinfo(struct inode *, nilfs_cno_t, int,
				struct nilfs_cpinfo *, size_t);


#endif	/* _NILFS_CPFILE_H */
