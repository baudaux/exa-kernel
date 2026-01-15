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
#include "exafs_io.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <dirent.h>

#ifndef DEBUG
#define DEBUG 0
#endif

#if DEBUG
#include <emscripten.h>
#else
#define emscripten_log(...)
#endif

int exafs_dir_read(struct exafs_ctx * ctx, uint32_t ino, struct __dirent * dir_entry, uint64_t offset) {

  emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_dir_read: ino=%d, offset=%lld", ino, offset);

  if (!dir_entry) {

    return -1;
  }

  struct exafs_inode * inode = exafs_inode_find_by_id(ctx, ino);

  if (!inode) {

    return -2;
  }

  if (!(inode->mode & S_IFDIR)) { // inode is not a dir

    return -3;
  }

  struct exafs_dir_entry * e;
  
  int i = 0;

  for (e = inode->entry_table; e != NULL; e = e->hh.next, i++) {
    
    if (i >= offset) {

      struct exafs_inode * child_inode = exafs_inode_find_by_id(ctx, e->ino);

      if (child_inode) {
	
	strcpy(dir_entry->d_name, e->path);

	switch(child_inode->mode & S_IFMT) {
	  
	   case S_IFBLK:
	     dir_entry->d_type = DT_BLK;
	     break;
	   case S_IFCHR:
	     dir_entry->d_type = DT_CHR;
	     break;
           case S_IFDIR:
	     dir_entry->d_type = DT_DIR;
	     break;
           case S_IFIFO:
	     dir_entry->d_type = DT_FIFO;
	     break;
           case S_IFLNK:
	     dir_entry->d_type = DT_LNK;
	     break;
           case S_IFREG:
	     dir_entry->d_type = DT_REG;
	     break;
           case S_IFSOCK:
	     dir_entry->d_type = DT_SOCK;
	     break;
	   default:
	     dir_entry->d_type = DT_REG;
	     break;
	}
	
	return 0;
      }
    }
  }
  
  return -4;
}

int exafs_extent_record(struct exafs_ctx * ctx, uint32_t ino, uint64_t size, uint64_t offset, uint32_t id, time_t now, char * ptr) {

  emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_extent_record: ino=%d size=%lld, offset=%lld", ino, size, offset);
  
  int record_size = sizeof(struct exafs_extent_meta)+size;
  
  int header_len = exafs_record_header(ctx, EXAFS_OP_WRITE_EXTENT, now, record_size, (struct meta_record *)ptr);

  struct exafs_extent_meta * extent = (struct exafs_extent_meta *)(ptr+header_len);
  
  extent->ino = ino;
  extent->size = size;
  extent->offset = offset;
  extent->id = id;
  
  return header_len+record_size;
}

ssize_t exafs_write(struct exafs_ctx * ctx, uint32_t ino, void * buf, uint64_t size, uint64_t offset) {

  emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_write: ino=%d size=%lld, offset=%lld", ino, size, offset);

  uint32_t id = 0; //exafs_extent_write(buf, size);
  
  if (!id) {

    return -1;
  }
  
  time_t now = time(NULL);

  char * recordset = (char *)malloc(4096);

  int recordset_length = exafs_extent_record(ctx, ino, size, offset, id, now, recordset);

  struct exafs_inode * inode = exafs_inode_find_by_id(ctx, ino);
  
  if (!inode) {

    return -1;
  }

  if (inode->size < (offset+size)) { // File size has been increased
  
    recordset_length += exafs_inode_set_size_record(ctx, ino, offset+size, now, recordset+recordset_length);
  }

  recordset_length += exafs_inode_set_mtime_record(ctx, ino, now, recordset+recordset_length);
  
  int err = exafs_meta_store(ctx, recordset, recordset_length);

  emscripten_log(EM_LOG_CONSOLE, "exafs: <-- exafs_meta_store: err=%d", err);

  if (!err) {

    err = exafs_meta_replay(ctx, recordset, recordset_length);
  }
  
  free(recordset);
  
  return (err == 0)?size:err;
}
