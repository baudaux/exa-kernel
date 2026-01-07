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

#define EXAFS_ROOT_INO 2
#define EXAFS_START_INO 10

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
  uint32_t extent_head;
};

int exafs_inode_create(struct exafs_ctx * ctx, uint32_t ino, uint32_t mode);

int exafs_inode_add(struct exafs_ctx * ctx, struct exafs_inode * inode);

#endif
