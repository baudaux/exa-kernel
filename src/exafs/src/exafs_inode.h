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

#include "exafs.h"

#include "uthash.h"

#define EXAFS_ROOT_INO 2
#define EXAFS_START_INO 10

#define PATHNAME_LEN_MAX 1024

struct exafs_dir_entry {

  char path[PATHNAME_LEN_MAX];
  uint64_t ino;

  UT_hash_handle hh;
};

struct exafs_inode {
  
  uint64_t ino;
  
  uint64_t size;
  uint64_t atime;
  uint64_t btime;
  uint64_t ctime;
  uint64_t mtime;
  uint32_t mode;
  uint32_t uid;
  uint32_t gid;
  //uint32_t extent_head;
  
  // No need to store in metadata log after here
  uint32_t nlink;
  struct exafs_dir_entry * entry_table;

  UT_hash_handle hh;
};

int exafs_inode_create(struct exafs_ctx * ctx, uint32_t ino, uint32_t mode, void * ptr);

int exafs_inode_add(struct exafs_ctx * ctx, struct exafs_inode * inode);

int exafs_inode_delete(struct exafs_ctx * ctx, uint32_t ino);

int exafs_inode_link(struct exafs_ctx * ctx, uint32_t parent_ino, uint32_t child_ino, const char * path, void * ptr);

int exafs_inode_unlink(struct exafs_ctx * ctx, uint32_t parent_ino, const char * path);

#endif
