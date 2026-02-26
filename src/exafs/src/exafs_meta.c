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
#include "exafs_io.h"

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

  emscripten_log(EM_LOG_CONSOLE, "exafs: exafs_meta_store at object %d (len=%d) -> res=%d", ctx->meta_log_head, len, res);

  if (res < len) {

    return -1;
  }

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

    emscripten_log(EM_LOG_CONSOLE, "exafs: exafs_meta_replay_record --> bad crc (%x %x)", *((uint32_t *)crc_p), crc);
    
    return -1;
  }
  else {

    emscripten_log(EM_LOG_CONSOLE, "exafs: exafs_meta_replay_record --> crc=%x", crc);
  }

  char * data = ((char *)record)+sizeof(struct meta_record);

  switch (record->op) {

    case EXAFS_OP_CREATE_INODE:

      exafs_inode_create(ctx, (struct exafs_inode_meta *)data);
      break;

    case EXAFS_OP_LINK:

      exafs_inode_link(ctx, (struct exafs_dir_entry_meta *)data);
      break;

    case EXAFS_OP_UNLINK:

      exafs_inode_unlink(ctx, (struct exafs_dir_entry_meta *)data);
      break;

    case EXAFS_OP_INODE_SET_SIZE:

      exafs_inode_set_size(ctx, (struct exafs_set_size_meta *)data);
      break;

    case EXAFS_OP_INODE_SET_MTIME:

      exafs_inode_set_mtime(ctx, (struct exafs_set_time_meta *)data);
      break;

    case EXAFS_OP_INODE_SET_CTIME:

      exafs_inode_set_ctime(ctx, (struct exafs_set_time_meta *)data);
      break;

    case EXAFS_OP_INODE_SET_ATIME:

      exafs_inode_set_atime(ctx, (struct exafs_set_time_meta *)data);
      break;

    case EXAFS_OP_INODE_SET_NLINK:

      exafs_inode_set_nlink(ctx, (struct exafs_set_nlink_meta *)data);
      break;

    case EXAFS_OP_WRITE_EXTENT:

      exafs_inode_write_extent(ctx, (struct exafs_extent_meta *)data);
      break;

    case EXAFS_OP_SNAPSHOT:

      if (ctx->delete_obj) {

	ctx->delete_buf_size = 64*1024;
	ctx->delete_buf = (char *)malloc(ctx->delete_buf_size*sizeof(uint32_t));
	ctx->delete_offset = 0;
      }
      else {
	
	return -2;
      }

      break;

    case EXAFS_OP_SNAPSHOT_END:
      {

	struct exafs_snap_end_meta * snap_end_meta = (struct exafs_snap_end_meta *)data;

	if (ctx->delete_obj) {

	  if (ctx->delete_offset > 0) {

	    ctx->delete_set(ctx, ctx->delete_buf, ctx->delete_offset);

	    ctx->delete_offset = 0;
	  }
	  
	  ctx->delete_range(ctx, snap_end_meta->erase_start, snap_end_meta->erase_end);

	  free(ctx->delete_buf);

	  ctx->delete_obj = snap_end_meta->obj;
	  
	  //TODO: when to delete obj between EXAFS_OP_SNAPSHOT and EXAFS_OP_SNAPSHOT_END ?
	}

	return -3;

      }
      
    case EXAFS_OP_SNAPSHOT_ABORTED:

      return -4;
      
    case EXAFS_OP_WRITE_OBJ:

      break;
      
    case EXAFS_OP_DEL_OBJ:

      if (ctx->delete_obj) {

	if ((ctx->delete_buf_size - ctx->delete_offset) > (record->len - sizeof(uint32_t))) {

	  ctx->delete_set(ctx, ctx->delete_buf, ctx->delete_offset);

	  ctx->delete_offset = 0;
	}

	memcpy(ctx->delete_buf+ctx->delete_offset, data+sizeof(uint32_t), record->len - sizeof(uint32_t));
	  
	ctx->delete_offset += record->len - sizeof(uint32_t);
      }

      break;
      
    default:

      break;
  }
  
  return 0;
}

uint64_t exafs_meta_replay(struct exafs_ctx * ctx, void * obj, int len) {

  emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_meta_replay: len=%d", len);

  char * data = (char *)obj;
  
  int offset = 0;

  uint64_t last_seq = 0;

  while (offset < len) {

    struct meta_record * record = (struct meta_record *)(data+offset);

    if (record->seq >= ctx->meta_log_seq) {

      int ret = exafs_meta_replay_record(ctx, record);

      if (ret == -2) { // Snapshot has been aborted ?

	ctx->snapshot_aborted = 1;
      }
      else if (ret == -3) {
	
	ctx->snapshot_aborted = 0;

	if (ctx->delete_obj) {

	  return 0;
	}
      }

      last_seq = record->seq;
    }
    else {

      emscripten_log(EM_LOG_CONSOLE, "exafs: exafs_meta_replay -> record in the past  %lld < %lld", record->seq, ctx->meta_log_seq);
    }

    offset += sizeof(struct meta_record)+record->len+sizeof(uint32_t);
    
    emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_meta_replay: offset=%d", offset);
  }

  return last_seq;
}
