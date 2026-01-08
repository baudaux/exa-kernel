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

#include "exafs_meta.h"
#include "exafs_util.h"

#ifndef DEBUG
#define DEBUG 0
#endif

#if DEBUG
#include <emscripten.h>
#else
#define emscripten_log(...)
#endif

struct meta_record * exafs_record_create(struct exafs_ctx * ctx, enum meta_op op, void * buffer, int len, void * ptr) {

  emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_record_store: op=%d", op);

  int l = sizeof(struct meta_record)+len+sizeof(uint32_t);
  
  struct meta_record * record;

  if (ptr) {

    record = ptr;
  }
  else {

    record = malloc(l); // includes last crc

    if (!record) {

      return NULL;
    }
  }

  record->seq = ctx->meta_log_seq;
  record->op = op;
  record->len = len;

  char * data = (char *)record;

  memcpy(data+sizeof(struct meta_record), buffer, len);

  uint32_t crc = exafs_crc(data, l - sizeof(uint32_t), 0);

  uint32_t * crc_p = (data+(l-sizeof(uint32_t)));

  *crc_p = crc;

  return record;
}

int exafs_record_store(struct exafs_ctx * ctx, struct meta_record * record) {

  int l = sizeof(struct meta_record)+record->len+sizeof(uint32_t);
  
  return exafs_log_store(ctx, record, l);
}

int exafs_log_store(struct exafs_ctx * ctx, void * obj, int len) {

  int res = ctx->write(ctx, ctx->meta_log_head, obj, len);

  emscripten_log(EM_LOG_CONSOLE, "exafs: exafs_log_store at object %d (size=%d) -> res=%d", ctx->meta_log_head, len, res);

  if (res < len) {

    return -1;
  }

  ctx->meta_log_seq++;
  
  ctx->meta_log_head++;
  
  return 0;
}
