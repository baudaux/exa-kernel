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

#include <time.h>

#define EXAFS_NB_SUPERBLOCKS 4

#define META_LOG_SIZE 10000

#define GRP_SIZE 128
#define SNAPSHOT_SIZE 100000

struct exafs_ctx;

typedef int (*clean_func)(struct exafs_ctx * ctx, const char * repo_name);
typedef int (*r_func)(struct exafs_ctx * ctx, uint32_t id, void * buffer, int len, int offset);
typedef int (*w_func)(struct exafs_ctx * ctx, uint32_t id, void * buffer, int len);
typedef int (*r_range_func)(struct exafs_ctx * ctx, uint32_t id_min, uint32_t id_max, void * buffer, int len, uint32_t * last_obj);
typedef int (*w_range_func)(struct exafs_ctx * ctx, void * buffer, int len);
typedef int (*w_rand_func)(struct exafs_ctx * ctx, uint32_t max_reserved_id, void * buffer, uint32_t len, uint32_t * id);
typedef int (*del_func)(struct exafs_ctx * ctx, uint32_t id);
typedef int (*del_range_func)(struct exafs_ctx * ctx, uint32_t id_min, uint32_t id_max);
typedef int (*del_set_func)(struct exafs_ctx * ctx, uint32_t * buffer, int len);

struct superblock {
  
  char magic[8];          // "EXAEQUO\0"
  uint64_t generation;
  uint32_t fs_uuid;
  uint32_t meta_log_size;
  uint64_t meta_log_seq;
  uint32_t meta_log_head;
  uint32_t meta_log_tail;
  uint32_t snapshot_size;
  uint32_t grp_size;
  uint32_t next_ino;
  uint32_t flags;
  uint32_t crc;
};

struct exafs_ctx {

  struct superblock superblocks[EXAFS_NB_SUPERBLOCKS];
  
  int active_superblock;

  uint32_t meta_log_size;
  uint32_t meta_log_head;
  uint32_t meta_log_tail;
  uint64_t meta_log_seq;
  uint32_t snapshot_size;
  uint32_t grp_size;
  
  uint32_t next_ino;
  
  struct exafs_inode * inode_table;

  clean_func clean_repo;
  r_func read;
  r_range_func read_range;
  w_func write;
  w_range_func write_range;
  w_rand_func write_rand;
  del_func delete;
  del_range_func delete_range;
  del_set_func delete_set;

  int snapshot_aborted;

  int delete_obj;
  int delete_buf_size;
  char * delete_buf;
  int delete_offset;
};

struct exafs_cfg {

  clean_func clean_repo;
  r_func read;
  r_range_func read_range;
  w_func write;
  w_range_func write_range;
  w_rand_func write_rand;
  del_func delete;
  del_range_func delete_range;
  del_set_func delete_set;
  
  uint32_t meta_log_size;
  uint32_t grp_size;
  uint32_t snapshot_size;
};

struct extent {
  uint64_t offset;
  uint64_t length;
  //u64 object_id; ??
};

struct exafs_snap_end_meta {

  uint32_t erase_start;
  uint32_t erase_end;
  uint32_t obj;
};

int exafs_init(struct exafs_ctx * ctx, struct exafs_cfg * cfg);

int exafs_mount(struct exafs_ctx * ctx, struct exafs_cfg * cfg);
int exafs_unmount(struct exafs_ctx * ctx);

int exafs_format(struct exafs_ctx * ctx, struct exafs_cfg * cfg);

uint32_t exafs_mkdir(struct exafs_ctx * ctx, uint32_t mode, const char * path);
uint32_t exafs_mkdir_at(struct exafs_ctx * ctx, uint32_t parent_ino, uint32_t mode, const char * path);

uint32_t exafs_mknod(struct exafs_ctx * ctx, uint32_t mode, const char * path);
uint32_t exafs_mknod_at(struct exafs_ctx * ctx, uint32_t parent_ino, uint32_t mode, const char * path);
uint32_t exafs_mknod_at2(struct exafs_ctx * ctx, uint32_t parent_ino, uint32_t child_ino, uint32_t mode, const char * path);

int exafs_unlink(struct exafs_ctx * ctx, const char * path);
int exafs_rename(struct exafs_ctx * ctx, const char * oldpath, const char * newpath);
int exafs_rmdir(struct exafs_ctx * ctx, const char * path);

int exafs_ftruncate(struct exafs_ctx * ctx, uint32_t ino, uint64_t length);

int exafs_create_snapshot(struct exafs_ctx * ctx);

#endif // _EXAFS_H
