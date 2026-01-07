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

#ifndef _EXAFS_UTIL_H
#define _EXAFS_UTIL_H

#include <sys/types.h>

#ifdef HASH
struct hnode {
  uint64_t key;          // inode id for example
  void * value;   // pointer to data
  struct hnode * next;
};

struct htable {
    size_t bucket_count;
    struct hnode ** buckets;
};
#endif

uint32_t exafs_crc(const void * data, size_t length, uint32_t previousCrc32);

#endif // _EXAFS_UTIL_H
