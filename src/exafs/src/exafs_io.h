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

#ifndef _EXAFS_IO_H
#define _EXAFS_IO_H

#include <sys/types.h>
#include <time.h>
#include <sys/stat.h>

#include "exafs.h"

struct exafs_extent_meta {

  uint32_t ino;
  uint64_t size;
  uint64_t offset;
  uint32_t id;
};

int exafs_dir_read(struct exafs_ctx * ctx, uint32_t ino, struct __dirent * dir_entry, uint64_t offset);

ssize_t exafs_write(struct exafs_ctx * ctx, uint32_t ino, void * buf, uint64_t size, uint64_t offset);
ssize_t exafs_read(struct exafs_ctx * ctx, uint32_t ino, void * buf, uint64_t size, uint64_t offset);

int exafs_extent_record(struct exafs_ctx * ctx, uint32_t ino, uint64_t size, uint64_t offset, uint32_t id, time_t now, char * ptr);

void exafs_inode_add_extent(struct exafs_inode * inode, uint64_t size, uint64_t offset, uint32_t id);
int exafs_inode_write_extent(struct exafs_ctx * ctx, struct exafs_extent_meta * meta);

int exafs_io_read_group(struct exafs_ctx * ctx, int group, char * buf, uint64_t now);
int exafs_io_write_group(struct exafs_ctx * ctx, int group, char * buf, int slot);

#endif // _EXAFS_IO_H
