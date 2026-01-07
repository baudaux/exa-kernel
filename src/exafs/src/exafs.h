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

#define META_LOG_SIZE 10000

struct exafs_ctx;

typedef int (*rw_func)(struct exafs_ctx * ctx, uint32_t id, void * buffer, int len);
typedef int (*r_range_func)(struct exafs_ctx * ctx, uint32_t id_min, uint32_t id_max, void * buffer, int len);
typedef int (*w_range_func)(struct exafs_ctx * ctx, void * buffer, int len);
typedef int (*del_func)(struct exafs_ctx * ctx, uint32_t id);
typedef int (*del_range_func)(struct exafs_ctx * ctx, uint32_t id_min, uint32_t id_max);

struct superblock {
  
  char magic[8];          // "EXAEQUO\0"
  uint64_t generation;
  uint32_t fs_uuid;
  uint32_t meta_log_size;
  uint32_t meta_log_head;
  uint32_t inode_table_head;
  uint32_t dir_index_head;
  uint32_t flags;
  uint32_t padding;
  uint32_t crc;
};

struct exafs_ctx {

  struct superblock superblocks[EXAFS_NB_SUPERBLOCKS];
  
  int active_superblock;

  uint32_t meta_log_size;
  uint32_t meta_log_head;
  uint64_t meta_log_seq;

  uint32_t last_ino;
  
  rw_func read;
  r_range_func read_range;
  rw_func write;
  w_range_func write_range;
  del_func delete;
  del_range_func delete_range;
};

struct exafs_cfg {

  rw_func read;
  r_range_func read_range;
  rw_func write;
  w_range_func write_range;
  del_func delete;
  del_range_func delete_range;

  uint32_t meta_log_size;
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
int exfs_mkdir_at(struct exafs_ctx * ctx, uint32_t ino, const char * path);

#endif // _EXAFS_H
