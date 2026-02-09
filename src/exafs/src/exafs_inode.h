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

#ifndef _EXAFS_INODE_H
#define _EXAFS_INODE_H

#include <sys/types.h>
#include <time.h>
#include <sys/stat.h>

#include "exafs.h"

#include "uthash.h"

#define EXAFS_ROOT_INO 2
#define EXAFS_START_INO 10

#define PATHNAME_LEN_MAX 1024

struct exafs_dir_entry_meta {

  uint32_t parent_ino;
  uint32_t ino;
  char path[PATHNAME_LEN_MAX];
};

struct exafs_dir_entry {

  char path[PATHNAME_LEN_MAX];
  uint32_t ino;
  
  UT_hash_handle hh;
};

struct exafs_chunk_entry {

  uint64_t offset;
  uint64_t size;
  uint32_t id;
  
  char * buf;
  
  struct exafs_chunk_entry * next;
};

struct exafs_inode_meta {

  uint32_t ino;
  uint64_t size;
  time_t atime;
  time_t btime;
  time_t ctime;
  time_t mtime;
  uint32_t mode;
  uint32_t uid;
  uint32_t gid;
  uint32_t nlink;
};

struct exafs_inode {

  uint32_t ino;
  uint64_t size;
  time_t atime;
  time_t btime;
  time_t ctime;
  time_t mtime;
  uint32_t mode;
  uint32_t uid;
  uint32_t gid;
  uint32_t nlink;
  
  //uint32_t extent_head;
  
  // No need to store in metadata log after here
  union {
    struct exafs_dir_entry * entry_table;
    struct exafs_chunk_entry * chunk_entry_list;
  } e;

  uint32_t obj;

  UT_hash_handle hh;
};

struct __dirent {
    ino_t d_ino;
    off_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[1];
  };

struct exafs_set_size_meta {

  uint32_t ino;
  uint64_t size;
};

struct exafs_set_nlink_meta {

  uint32_t ino;
  uint32_t nlink;
};

struct exafs_set_time_meta {

  uint32_t ino;
  uint64_t time;
};

struct exafs_dir_entry * exafs_inode_get_entry(struct exafs_ctx * ctx, uint32_t parent_ino, const char * path);

int exafs_inode_record(struct exafs_ctx * ctx, uint32_t ino, uint32_t mode, time_t now, char * ptr);
int exafs_inode_create(struct exafs_ctx * ctx, struct exafs_inode_meta * inode_meta);

int exafs_inode_link_record(struct exafs_ctx * ctx, uint32_t parent_ino, uint32_t child_ino, const char * path, time_t now, char * ptr);
int exafs_inode_link(struct exafs_ctx * ctx, struct exafs_dir_entry_meta * entry_meta);

int exafs_inode_unlink_record(struct exafs_ctx * ctx, uint32_t ino, const char * path, time_t now, char * ptr);
int exafs_inode_unlink(struct exafs_ctx * ctx, struct exafs_dir_entry_meta * entry_meta);

int exafs_inode_set_size_record(struct exafs_ctx * ctx, uint32_t ino, uint64_t size, time_t now, char * ptr);
int exafs_inode_set_size(struct exafs_ctx * ctx, struct exafs_set_size_meta * meta);

int exafs_inode_set_nlink_record(struct exafs_ctx * ctx, uint32_t ino, uint32_t nlink, time_t now, char * ptr);
int exafs_inode_set_nlink(struct exafs_ctx * ctx, struct exafs_set_nlink_meta * meta);

int exafs_inode_set_mtime_record(struct exafs_ctx * ctx, uint32_t ino, time_t now, char * ptr);
int exafs_inode_set_mtime(struct exafs_ctx * ctx, struct exafs_set_time_meta * meta);

int exafs_inode_set_ctime_record(struct exafs_ctx * ctx, uint32_t ino, time_t now, char * ptr);
int exafs_inode_set_ctime(struct exafs_ctx * ctx, struct exafs_set_time_meta * meta);

int exafs_inode_set_atime_record(struct exafs_ctx * ctx, uint32_t ino, time_t now, char * ptr);
int exafs_inode_set_atime(struct exafs_ctx * ctx, struct exafs_set_time_meta * meta);

struct exafs_inode * exafs_inode_find_by_id(struct exafs_ctx * ctx, uint32_t ino);
uint32_t exafs_inode_find(struct exafs_ctx * ctx, const char * path);
uint32_t exafs_inode_find_n(struct exafs_ctx * ctx, const char * path, int len);

int exafs_inode_stat(struct exafs_ctx * ctx, uint32_t ino, struct stat * stat);

uint32_t exafs_inode_get_nb_entries(struct exafs_ctx * ctx, uint32_t ino);

void exafs_inode_sort(struct exafs_ctx * ctx);

void exafs_inode_snap(struct exafs_ctx * ctx, uint64_t now);

int exafs_inode_read_entry(struct exafs_ctx * ctx, struct exafs_inode * inode);

#endif // _EXAFS_INODE_H
