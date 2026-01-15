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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "exafs_meta.h"
#include "exafs_util.h"
#include "exafs_inode.h"

#ifndef DEBUG
#define DEBUG 0
#endif

#if DEBUG
#include <emscripten.h>
#else
#define emscripten_log(...)
#endif

int exafs_record_header(struct exafs_ctx * ctx, enum meta_op op, time_t now, int len, struct meta_record * record) {

  emscripten_log(EM_LOG_CONSOLE, "exafs: exafs_record_header: op=%d len=%d", op, len);
  
  record->seq = ctx->meta_log_seq;
  record->timestamp = now;
  record->op = op;
  record->len = len;
  
  return sizeof(struct meta_record);
}

int exafs_record_crc(struct meta_record * record) {

  int len = sizeof(struct meta_record)+record->len;
  
  // Compute CRC on header + data
  uint32_t crc = exafs_crc(record, len, 0);

  char * crc_p = ((char *)record)+len;
  
  *((uint32_t *)crc_p) = crc;
  
  return sizeof(crc);
}

int exafs_meta_store(struct exafs_ctx * ctx, void * obj, int len) {

  int res = ctx->write(ctx, ctx->meta_log_head, obj, len);

  emscripten_log(EM_LOG_CONSOLE, "exafs: exafs_meta_store at object %d (size=%d) -> res=%d", ctx->meta_log_head, len, res);

  if (res < len) {

    return -1;
  }

  ctx->meta_log_seq++;
  
  ctx->meta_log_head++;
  
  return 0;
}

int exafs_meta_replay_record(struct exafs_ctx * ctx, struct meta_record * record) {

  emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_meta_replay_record: seq=%d t=%lld op=%d len=%d", record->seq, record->timestamp, record->op, record->len);
  
  int len = sizeof(struct meta_record)+record->len;
  
  // Compute CRC on header + data
  uint32_t crc = exafs_crc(record, len, 0);

  char * crc_p = ((char *)record)+len;

  if (*((uint32_t *)crc_p) != crc) {

    emscripten_log(EM_LOG_CONSOLE, "exafs: exafs_meta_replay_record --> bad crc");
    
    return -1;
  }

  char * data = ((char *)record)+sizeof(struct meta_record);

  switch (record->op) {

    case EXAFS_OP_CREATE_INODE:

      exafs_inode_create(ctx, (struct exafs_inode_meta *)data);
      break;

    case EXAFS_OP_LINK:

      exafs_inode_link(ctx, (struct exafs_dir_entry_meta *)data);
      break;

    case EXAFS_OP_INODE_SET_SIZE:

      exafs_inode_set_size(ctx, (struct exafs_set_size_meta *)data);
      break;

    case EXAFS_OP_INODE_SET_MTIME:

      exafs_inode_set_mtime(ctx, (struct exafs_set_time_meta *)data);
      break;

    case EXAFS_OP_INODE_SET_NLINK:

      exafs_inode_set_nlink(ctx, (struct exafs_set_nlink_meta *)data);
      break;

    case EXAFS_OP_WRITE_EXTENT:

      // Do nothing
      break;

    default:

      break;
  }
  
  return 0;
}

int exafs_meta_replay(struct exafs_ctx * ctx, void * obj, int len) {

  char * data = (char *)obj;
  
  int offset = 0;

  while (offset < len) {

    struct meta_record * record = (struct meta_record *)(data+offset);

    //if (record->seq > ctx->)

    exafs_meta_replay_record(ctx, record);

    offset += sizeof(struct meta_record)+record->len+sizeof(uint32_t);
  }

  return 0;
}
