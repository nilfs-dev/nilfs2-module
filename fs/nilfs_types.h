/*
 * nilfs_types.h -- common types definitions for nilfs
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

#ifndef _NILFS_TYPES_H
#define _NILFS_TYPES_H

#include <linux/types.h>

typedef sector_t nilfs_blkoff_t;       /* file block offset (interim type)
					  As a similar type, linux-2.6.17 added
					  blkcnt_t for inode's block count */

typedef sector_t nilfs_bgno_t;	/* block group number */

#endif	/* _NILFS_TYPES_H */
