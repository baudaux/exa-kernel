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

#ifndef _EXAFS_H
#define _EXAFS_H

#define EXAFS_NB_SUPERBLOCKS 4

#define METADATA_LOG_START EXAFS_NB_SUPERBLOCKS
#define METADATA_LOG_END 10000

struct exafs_ctx;

typedef int (*access_func)(struct exafs_ctx * ctx, int id, void * buffer, int len);

struct superblock {
  char magic[8];          // "EXAEQUO\0"
  uint64_t generation;
  uint32_t fs_uuid;
  uint32_t meta_log_head;
  uint32_t inode_table_head;
  uint32_t dir_index_head;
  uint32_t flags;
  uint32_t crc;
};

struct exafs_ctx {

  struct superblock superblocks[EXAFS_NB_SUPERBLOCKS];
  
  int active_superblock;

  access_func read;
  access_func write;
};

struct exafs_cfg {

  access_func read;
  access_func write;
};

enum meta_op {
  EXAFS_OP_CREATE_INODE,
  EXAFS_OP_DELETE_INODE,
  EXAFS_OP_LINK,
  EXAFS_OP_UNLINK,
  EXAFS_OP_WRITE_EXTENT,
  EXAFS_OP_TRUNCATE,
  EXAFS_OP_CHMOD,
  EXAFS_OP_CHOWN,
  EXAFS_OP_RENAME
};

struct meta_record {
  uint64_t seq;
  //uint64_t timestamp;
  uint32_t  op;
  uint32_t len;
  //char  payload[];
  //uint32_t crc;
};

struct inode {
  uint64_t ino;
  uint64_t size;
  uint64_t ctime, mtime;
  uint32_t type;
  uint32_t mode;
  uint32_t uid, gid;
  uint32_t extent_head;
};

struct extent {
  uint64_t offset;
  uint64_t length;
  //u64 object_id; ??
};

int exafs_init(struct exafs_ctx * ctx, struct exafs_cfg * cfg);

int exafs_mount(struct exafs_ctx * ctx, struct exafs_cfg * cfg);

int exafs_format(struct exafs_ctx * ctx, struct exafs_cfg * cfg);

int exfs_mkdir(struct exafs_ctx * ctx, const char * path);

#endif // _EXAFS_H
