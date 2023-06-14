/*
 * Copyright (C) 2023 Benoit Baudaux
 *
 * This file is part of EXA.
 *
 * EXA is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * EXA is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with EXA. If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <string.h>

#include "circular_buffer.h"

#ifndef DEBUG
#define DEBUG 0
#endif

#if DEBUG
#include <emscripten.h>
#else
#define emscripten_log(...)
#endif

void init_circular_buffer(struct circular_buffer * buf, size_t size) {

  buf->start = 0;
  buf->end = 0;

  buf->size = size;
  buf->buf = malloc(size);

  if (!buf->buf) {
    emscripten_log(EM_LOG_CONSOLE, "circular_buffer: cannot allocate %d bytes", size);
  }
}

void free_circular_buffer(struct circular_buffer * buf) {

  if (buf->buf)
    free(buf->buf);

  buf->size = 0;
}

int count_circular_buffer_index(struct circular_buffer * buf, int index) {

  if (index >= buf->start)
    return index - buf->start;
  else
    return buf->size - buf->start + index;
}

int count_circular_buffer(struct circular_buffer * buf) {

  return count_circular_buffer_index(buf, buf->end);
}

int get_circular_buffer_head(struct circular_buffer * buf, char ** ptr) {

  if (count_circular_buffer(buf) > 0) {

    *ptr = (char *)&(buf->buf[buf->start]);

    if (buf->end >= buf->start)
      return buf->end-buf->start;

    return buf->size - buf->start;
  }

  return 0;
}

int get_circular_buffer_tail(struct circular_buffer * buf, char ** ptr) {

  if (buf->end >= buf->start)
    return 0;

  *ptr = (char *)&(buf->buf[0]);

  return buf->end;
}

void empty_circular_buffer(struct circular_buffer * buf) {

  buf->start = buf->end;
}

int find_eol_circular_buffer(struct circular_buffer * buf, int * index) {

  for (int i = buf->start; i != buf->end; i = (i+1)%buf->size) {

    if ( (buf->buf[i] == '\r') || (buf->buf[i] == '\n') ) {

      *index = i;
      return 1;
    }
  }
  
  return 0;
}

int enqueue_circular_buffer(struct circular_buffer * buf, char c) {

  if (count_circular_buffer(buf) < (buf->size-1)) {

    buf->buf[buf->end] = c;

    buf->end = (buf->end+1) % buf->size;

    return 1;
  }
      
  return 0;
}

char undo_enqueue_circular_buffer(struct circular_buffer * buf, char * c) {

  if (count_circular_buffer(buf) > 0) {

    *c = buf->buf[buf->end];

    if (buf->end > 0)
      --(buf->end);
    else
      buf->end = buf->size-1;

    return 1;
  }
      
  return 0;
}

int dequeue_circular_buffer(struct circular_buffer * buf, char * c) {

  if (count_circular_buffer(buf) > 0) {

    *c = buf->buf[buf->start];

    buf->start = (buf->start+1) % buf->size;

    return 1;
  }
  
  return 0;
}

int read_circular_buffer(struct circular_buffer * buf, int len, char * dest) {

  if (len == 0)
    return 0;

  int l = count_circular_buffer(buf);

  if (l == 0)
    return 0;

  if (l < len)
    len = l;
  
  int end_index = (buf->start+len) % buf->size;

  if (end_index > buf->start) {

    memcpy(dest, &(buf->buf[buf->start]), len);
  }
  else {

    memcpy(dest, &(buf->buf[buf->start]), buf->size - buf->start);

    if ((len - (buf->size - buf->start)) > 0)
      memcpy(dest+(buf->size - buf->start), &(buf->buf[0]), len - (buf->size - buf->start));
  }

  buf->start = end_index;
    
  return len;
}

int write_circular_buffer(struct circular_buffer * buf, int len, char * src) {

  int i = 0;
  
  while ( (i < len) && enqueue_circular_buffer(buf, *src++))
    ++i;

  return i;
}
