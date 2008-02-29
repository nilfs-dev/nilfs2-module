/*
 * direct.h - NILFS direct block pointer.
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

#ifndef _NILFS_DIRECT_H
#define _NILFS_DIRECT_H

#include <linux/types.h>
#include <linux/buffer_head.h>
#include "bmap.h"


struct nilfs_direct;

/**
 * struct nilfs_direct_operations - direct mapping operation table
 */
struct nilfs_direct_operations {
	__u64 (*dop_find_target)(const struct nilfs_direct *, __u64);
	void (*dop_set_target)(struct nilfs_direct *, __u64, __u64);
	int (*dop_propagate)(struct nilfs_direct *, struct buffer_head *);
	int (*dop_assign)(struct nilfs_direct *, __u64, __u64,
			  struct buffer_head **, sector_t,
			  union nilfs_binfo *);
};

/**
 * struct nilfs_direct_node - direct node
 * @dn_flags: flags
 * @dn_pad: padding
 */
struct nilfs_direct_node {
	__u8 dn_flags;
	__u8 pad[7];
};

/**
 * struct nilfs_direct - direct mapping
 * @d_bmap: bmap structure
 * @d_ops: direct mapping operation table
 */
struct nilfs_direct {
	struct nilfs_bmap d_bmap;

	/* direct-mapping-specific members */
	const struct nilfs_direct_operations *d_ops;
};


#define NILFS_DIRECT_NBLOCKS	(NILFS_BMAP_SIZE / sizeof(__le64) - 1)
#define NILFS_DIRECT_KEY_MIN	0
#define NILFS_DIRECT_KEY_MAX	(NILFS_DIRECT_NBLOCKS - 1)


int nilfs_direct_init(struct nilfs_bmap *, __u64, __u64);
int nilfs_direct_delete_and_convert(struct nilfs_bmap *, __u64, __u64 *,
				    __u64 *, int, __u64, __u64);


#endif	/* _NILFS_DIRECT_H */
