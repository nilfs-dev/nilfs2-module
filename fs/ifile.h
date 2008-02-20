/*
 * ifile.h - NILFS inode file
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
 * ifile.h,v 1.16 2007-04-20 13:15:55 ryusuke Exp
 *
 * Written by Amagai Yoshiji <amagai@osrg.net>,
 *            Ryusuke Konishi <ryusuke@osrg.net>
 */

#ifndef _NILFS_IFILE_H
#define _NILFS_IFILE_H

#include <linux/fs.h>
#include <linux/buffer_head.h>
#include "nilfs_fs.h"
#include "nilfs_types.h"
#include "mdt.h"
#include "alloc.h"

/* disk inode specific functions */
extern int nilfs_inode_alloc(struct inode *, ino_t *, struct buffer_head **);
extern int nilfs_inode_free(struct inode *, ino_t, struct buffer_head **);
extern struct nilfs_inode *nilfs_ifile_map_inode(struct inode *, ino_t, 
						 struct buffer_head *);
extern void nilfs_ifile_unmap_inode(struct inode *, ino_t,
				    struct buffer_head *);

int nilfs_ifile_create_inode(struct inode *, ino_t *, struct buffer_head **);
int nilfs_ifile_delete_inode(struct inode *, ino_t);
int nilfs_ifile_get_inode_block(struct inode *, ino_t, struct buffer_head **);

#define NILFS_IFILE_GFP  NILFS_MDT_GFP
#define NILFS_IFILE_GROUPS_COUNT(blkbits) \
	(1UL << (BITS_PER_LONG - ((blkbits) + 3 /* log2(8) */)))

#endif	/* _NILFS_IFILE_H */

/* Local Variables:		*/
/* eval: (c-set-style "linux")	*/
/* End:				*/
