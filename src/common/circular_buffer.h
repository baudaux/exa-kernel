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

#ifndef _CIRCULAR_BUFFER_H
#define _CIRCULAR_BUFFER_H

#include <stdlib.h>

struct circular_buffer {

  unsigned char * buf;
  unsigned long start;
  unsigned long end;
  
  size_t size;
};

void init_circular_buffer(struct circular_buffer * buf, size_t size);
void free_circular_buffer(struct circular_buffer * buf);

int count_circular_buffer_index(struct circular_buffer * buf, int index);

int count_circular_buffer(struct circular_buffer * buf);

int get_circular_buffer_head(struct circular_buffer * buf, char ** ptr);

int get_circular_buffer_tail(struct circular_buffer * buf, char ** ptr);

void empty_circular_buffer(struct circular_buffer * buf);

int find_eol_circular_buffer(struct circular_buffer * buf, int * index);

int enqueue_circular_buffer(struct circular_buffer * buf, char c);

char undo_enqueue_circular_buffer(struct circular_buffer * buf, char * c);

int dequeue_circular_buffer(struct circular_buffer * buf, char * c);

int read_circular_buffer(struct circular_buffer * buf, int len, char * dest);
int write_circular_buffer(struct circular_buffer * buf, int len, char * src);

#endif // _CIRCULAR_BUFFER_H
