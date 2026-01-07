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

#include "exafs_inode.h"
#include "exafs_meta.h"

#include <stdlib.h>

#ifndef DEBUG
#define DEBUG 0
#endif

#if DEBUG
#include <emscripten.h>
#else
#define emscripten_log(...)
#endif

int exafs_inode_create(struct exafs_ctx * ctx, uint32_t ino, uint32_t mode) {

  emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_inode_create ino=%d mode=%07o", ino, mode);

  struct exafs_inode * inode = malloc(sizeof(struct exafs_inode));

  inode->ino = ino;
  inode->size = 0;
  inode->mode = mode;

  // Store inode creation record

  int res = exafs_record_store(ctx, EXAFS_OP_CREATE_INODE, inode, sizeof(struct exafs_inode));

  emscripten_log(EM_LOG_CONSOLE, "exafs: exafs_record_store -> res=%d", res);

  if (res < 0) {

    return -1;
  }

  // Add inode in inode table

  res = exafs_inode_add(ctx, inode);
  
  return 0;
}

int exafs_inode_add(struct exafs_ctx * ctx, struct exafs_inode * inode) {

  return 0;
}
