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

#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stropts.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/sysmacros.h>
#include <dirent.h>

#include "exafs.h"

#include "exafs_util.h"

#ifndef DEBUG
#define DEBUG 0
#endif

#if DEBUG
#include <emscripten.h>
#else
#define emscripten_log(...)
#endif

int exafs_init(struct exafs_ctx * ctx, struct exafs_cfg * cfg) {

  ctx->active_superblock = -1;
  
  ctx->read = cfg->read;
  ctx->write = cfg->write;

  if ( (ctx->read == NULL) || (ctx->write == NULL) ) {
    return -1;
  }
  
  return 0;
}

int exafs_mount(struct exafs_ctx * ctx, struct exafs_cfg * cfg) {

  emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_mount");
  
  // Initialize ctx structure
  
  if (exafs_init(ctx, cfg) < 0) {

    return -1;
  }

  // Read superblocks

  for (int i=0; i < EXAFS_NB_SUPERBLOCKS; i++) {

    int len = ctx->read(ctx, i, &(ctx->superblocks[i]), sizeof(struct superblock));

    emscripten_log(EM_LOG_CONSOLE, "exafs: read block %d -> %d bytes", i, len);

    if (len < sizeof(struct superblock)) {

      ctx->superblocks[i].generation = 0;
    }
    else {

      uint32_t crc = exafs_crc(&(ctx->superblocks[i]), sizeof(struct superblock) - sizeof(uint32_t), 0);

      emscripten_log(EM_LOG_CONSOLE, "exafs: read block %d -> magic=%s generation=%lld crc=%x (computed crc=%x)", i, ctx->superblocks[i].magic, ctx->superblocks[i].generation, ctx->superblocks[i].crc, crc);

      if (crc != ctx->superblocks[i].crc) {
	
	ctx->superblocks[i].generation = 0;
      }
    }
  }

  int active_superblock_generation = 0;

  for (int i=0; i < EXAFS_NB_SUPERBLOCKS; i++) {

    if (ctx->superblocks[i].generation > active_superblock_generation) {

      active_superblock_generation = ctx->superblocks[i].generation;
      ctx->active_superblock = i;
    }
  }
  
  if (ctx->active_superblock < 0) {

    emscripten_log(EM_LOG_CONSOLE, "exafs: <-- exafs_mount: error (no active superblock)");
    
    return -1;
  }

  emscripten_log(EM_LOG_CONSOLE, "exafs: <-- exafs_mount: success (active superblock %d generation %lld)", ctx->active_superblock, ctx->superblocks[ctx->active_superblock].generation);
  
  return 0;
}

int exafs_format(struct exafs_ctx * ctx, struct exafs_cfg * cfg) {

  emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_format");
  
  // Initialize ctx structure
  
  if (exafs_init(ctx, cfg) < 0) {

    return -1;
  }
  
  int res = -1;

  // Write superblock in all the slots

  for (int i=0; i < EXAFS_NB_SUPERBLOCKS; i++) {

    memset(&(ctx->superblocks[i]), 0, sizeof(struct superblock));

    strcpy(ctx->superblocks[i].magic, "EXAEQUO");
    ctx->superblocks[i].generation = 1;
    ctx->superblocks[i].meta_log_head = METADATA_LOG_START;
    ctx->superblocks[i].crc = exafs_crc(&(ctx->superblocks[i]), sizeof(struct superblock) - sizeof(uint32_t), 0);
    
    int len = ctx->write(ctx, i, &(ctx->superblocks[i]), sizeof(struct superblock));

    if (len == sizeof(struct superblock)) {

      res = 0;

      if (ctx->active_superblock < 0) {
	
	ctx->active_superblock = i; // active superblock is the first with successful writing
      }
    }
  }

  emscripten_log(EM_LOG_CONSOLE, "exafs: <-- exafs_format: res=%d", res);

  return res;
}

int exfs_mkdir(struct exafs_ctx * ctx, const char * path) {

  emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_mkdir: path=%s", path);
  
  return -1;
}
