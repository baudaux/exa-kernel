/*
 * Copyright (C) 2026 Benoit Baudaux
 *
 * This file is part of EXA.
 *
 * EXA is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundationt, either version 3 of the License, or (at your option) any later version.
 *
 * EXA is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with EXA. If not, sees <https://www.gnu.org/licenses/>.
 */

#ifndef _EXAFS_META_H
#define _EXAFS_META_H

#include <sys/types.h>

#include "exafs.h"

enum meta_op {
  
  EXAFS_OP_CREATE_INODE,
  EXAFS_OP_DELETE_INODE,
  EXAFS_OP_LINK,
  EXAFS_OP_UNLINK,
  EXAFS_OP_INODE_SET_NLINK,
  EXAFS_OP_INODE_SET_SIZE,
  EXAFS_OP_INODE_SET_MTIME,
  EXAFS_OP_INODE_SET_CTIME,
  EXAFS_OP_INODE_SET_ATIME,
  EXAFS_OP_WRITE_EXTENT,
  EXAFS_OP_TRUNCATE,
  EXAFS_OP_CHMOD,
  EXAFS_OP_CHOWN,
  EXAFS_OP_RENAME,
  EXAFS_OP_SNAPSHOT,
  EXAFS_OP_SNAPSHOT_END,
  EXAFS_OP_SNAPSHOT_ABORTED,
  EXAFS_OP_WRITE_OBJ,
  EXAFS_OP_DEL_OBJ,
};

struct meta_record {
  
  uint64_t seq;
  time_t timestamp;
  uint32_t  op;
  uint32_t len;
  //char  payload[];
  //uint32_t crc;
};

int exafs_record_header(struct exafs_ctx * ctx, enum meta_op op, time_t now, int len, struct meta_record * record);
int exafs_record_crc(struct meta_record * record);

int exafs_meta_store(struct exafs_ctx * ctx, void * obj, int len);

uint64_t exafs_meta_replay(struct exafs_ctx * ctx, void * obj, int len);

#endif
