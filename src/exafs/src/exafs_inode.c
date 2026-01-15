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

#include "xxhash.h"

// Fold a 64-bit hash to 32 bits (xor high/low)
static inline unsigned fold64_to_32(uint64_t h) {
    return (unsigned)(h ^ (h >> 32));
}

#define HASH_FUNCTION(keyptr, keylen, hashv)                          \
    do {                                                              \
        uint64_t h64 = XXH3_64bits((const void*)(keyptr), (size_t)(keylen)); \
        hashv = fold64_to_32(h64);                                  \
    } while (0)

int exafs_inode_entry_exists(struct exafs_ctx * ctx, uint32_t parent_ino, const char * path) {

  struct exafs_inode * parent_inode = exafs_inode_find_by_id(ctx, parent_ino); 

  if (!parent_inode) {

    return 0;
  }

  struct exafs_dir_entry * e = NULL;

  HASH_FIND_STR( parent_inode->entry_table, path, e);

  if (e) {
    
    return 0;
  }

  return 1;
}

int exafs_inode_record(struct exafs_ctx * ctx, uint32_t ino, uint32_t mode, time_t now, char * ptr) {

  emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_inode_record: ino=%d", ino);
  
  int record_size = sizeof(struct exafs_inode_meta);
  
  int header_len = exafs_record_header(ctx, EXAFS_OP_CREATE_INODE, now, record_size, (struct meta_record *)ptr);

  struct exafs_inode_meta * inode = (struct exafs_inode_meta *)(ptr+header_len);
  
  inode->ino = ino;
  inode->size = 0;
  inode->atime = now;
  inode->btime = now;
  inode->ctime = now;
  inode->mtime = now;
  inode->mode = mode;
  inode->uid = 1;
  inode->gid = 1;
  inode->nlink = 0;

  int crc_len = exafs_record_crc((struct meta_record *)ptr);
  
  return header_len+record_size+crc_len;
}

int exafs_inode_create(struct exafs_ctx * ctx, struct exafs_inode_meta * inode_meta) {

  emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_inode_create: ino=%d", inode_meta->ino);
  
  struct exafs_inode * inode = (struct exafs_inode *)malloc(sizeof(struct exafs_inode));

  if (!inode) {

    return -1;
  }
  
  inode->ino = inode_meta->ino;
  inode->size = inode_meta->size;
  inode->atime = inode_meta->atime;
  inode->btime = inode_meta->btime;
  inode->ctime = inode_meta->ctime;
  inode->mtime = inode_meta->mtime;
  inode->mode = inode_meta->mode;
  inode->uid = inode_meta->uid;
  inode->gid = inode_meta->gid;
  inode->nlink = inode_meta->nlink;
  
  inode->entry_table = NULL;
  
  HASH_ADD_INT( ctx->inode_table, ino, inode );
  
  return 0;
}

int exafs_inode_link_record(struct exafs_ctx * ctx, uint32_t parent_ino, uint32_t child_ino, const char * path, time_t now, char * ptr) {

  emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_inode_link_record: parent_ino=%d ino=%d path=%s", parent_ino, child_ino, path);
  
  int record_size = sizeof(struct exafs_dir_entry_meta);

  int header_len = exafs_record_header(ctx, EXAFS_OP_LINK, now, record_size, (struct meta_record *)ptr);

  struct exafs_dir_entry_meta * entry = (struct exafs_dir_entry_meta *)(ptr+header_len);

  entry->parent_ino = parent_ino;
  entry->ino = child_ino;
  
  strcpy(entry->path, path);
  
  int crc_len = exafs_record_crc((struct meta_record *)ptr);
  
  return header_len+record_size+crc_len;
}

int exafs_inode_link(struct exafs_ctx * ctx, struct exafs_dir_entry_meta * entry_meta) {

  emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_inode_link: parent_ino=%d ino=%d path=%s", entry_meta->parent_ino, entry_meta->ino, entry_meta->path);

  struct exafs_dir_entry * dir_entry = (struct exafs_dir_entry *)malloc(sizeof(struct exafs_dir_entry));

  if (!dir_entry) {

    return -1;
  }

  strcpy(dir_entry->path, entry_meta->path);
  dir_entry->ino = entry_meta->ino;
  
  struct exafs_inode * parent_inode = exafs_inode_find_by_id(ctx, entry_meta->parent_ino); 

  if (!parent_inode) {
    
    free(dir_entry);
    return -1;
  }

  struct exafs_inode * child_inode = exafs_inode_find_by_id(ctx, entry_meta->ino);

  if (!child_inode) {

    free(dir_entry);
    return -1;
  }

  HASH_ADD_STR( parent_inode->entry_table, path, dir_entry );
  
  return 0;
}

int exafs_inode_set_size_record(struct exafs_ctx * ctx, uint32_t ino, uint64_t size, time_t now, char * ptr) {

  int record_size = sizeof(struct exafs_set_size_meta);

  int header_len = exafs_record_header(ctx, EXAFS_OP_INODE_SET_SIZE, now, record_size, (struct meta_record *)ptr);

  struct exafs_set_size_meta * m = (struct exafs_set_size_meta *)(ptr+header_len);

  m->ino = ino;
  m->size = size;
  
  int crc_len = exafs_record_crc((struct meta_record *)ptr);
  
  return header_len+record_size+crc_len;
}

int exafs_inode_set_size(struct exafs_ctx * ctx, struct exafs_set_size_meta * meta) {

  struct exafs_inode * inode = exafs_inode_find_by_id(ctx, meta->ino); 

  if (!inode) {

    return -1;
  }

  inode->size = meta->size;
  
  return 0;
}

int exafs_inode_set_mtime_record(struct exafs_ctx * ctx, uint32_t ino, time_t now, char * ptr) {

  int record_size = sizeof(struct exafs_set_time_meta);

  int header_len = exafs_record_header(ctx, EXAFS_OP_INODE_SET_MTIME, now, record_size, (struct meta_record *)ptr);

  struct exafs_set_time_meta * m = (struct exafs_set_time_meta *)(ptr+header_len);

  m->ino = ino;
  m->time = now;
  
  int crc_len = exafs_record_crc((struct meta_record *)ptr);
  
  return header_len+record_size+crc_len;
}

int exafs_inode_set_mtime(struct exafs_ctx * ctx, struct exafs_set_time_meta * meta) {

  struct exafs_inode * inode = exafs_inode_find_by_id(ctx, meta->ino); 

  if (!inode) {

    return -1;
  }

  inode->mtime = meta->time;
  
  return 0;
}

int exafs_inode_set_nlink_record(struct exafs_ctx * ctx, uint32_t ino, uint32_t nlink, time_t now, char * ptr) {

  int record_size = sizeof(struct exafs_set_nlink_meta);

  int header_len = exafs_record_header(ctx, EXAFS_OP_INODE_SET_NLINK, now, record_size, (struct meta_record *)ptr);

  struct exafs_set_nlink_meta * m = (struct exafs_set_nlink_meta *)(ptr+header_len);

  m->ino = ino;
  m->nlink = nlink;
  
  int crc_len = exafs_record_crc((struct meta_record *)ptr);
  
  return header_len+record_size+crc_len;
}

int exafs_inode_set_nlink(struct exafs_ctx * ctx, struct exafs_set_nlink_meta * meta) {

  struct exafs_inode * inode = exafs_inode_find_by_id(ctx, meta->ino); 

  if (!inode) {

    return -1;
  }
  
  inode->nlink = meta->nlink;
  
  return 0;
}

struct exafs_inode * exafs_inode_find_by_id(struct exafs_ctx * ctx, uint32_t ino) {

  struct exafs_inode * inode = NULL;

  HASH_FIND_INT( ctx->inode_table, &ino, inode );

  return inode;
}

uint32_t exafs_inode_find_n(struct exafs_ctx * ctx, const char * path, int len) {

  char * p = (char *)path;

  char c = p[len];
  
  p[len]= 0; // Temporary trunc the string
  
  uint32_t ino = exafs_inode_find(ctx, p);

  p[len] = c; // Restore the string

  emscripten_log(EM_LOG_CONSOLE, "exafs: <-- exafs_inode_find_n: ino=%d", ino);
  
  return ino;
}

uint32_t exafs_inode_find(struct exafs_ctx * ctx, const char * path) {

  if (!path) {

    return 0;
  }
  
  emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_inode_find: path=%s", path);

  if (path[0] != '/') { // path shall start by '/'

    return 0;
  }

  if (strcmp(path, "/") == 0) {

    return EXAFS_ROOT_INO;
  }
  
  char * leaf = strrchr(path, '/');
  
  uint32_t ino = exafs_inode_find_n(ctx, path, (leaf == path)?1:leaf-path);

  emscripten_log(EM_LOG_CONSOLE, "exafs: exafs_inode_find_n -> ino=%d", ino);
  
  if (ino) {

    struct exafs_inode * inode = exafs_inode_find_by_id(ctx, ino);

    emscripten_log(EM_LOG_CONSOLE, "exafs: find inode -> inode=%x", inode);

    if (!inode) {

      return 0;
    }

    if (strlen(leaf+1) == 0) {

      if (inode->mode & S_IFDIR) {

	return ino;
      }
      else {
	
	return -1;
      }
    }
    
    struct exafs_dir_entry * e = NULL;
    
    HASH_FIND_STR( inode->entry_table, leaf+1, e);

    emscripten_log(EM_LOG_CONSOLE, "exafs: find entry -> e=%x", e);

    if (e) {
	
      return e->ino;
    }
  }
  
  return 0;
}

int exafs_inode_stat(struct exafs_ctx * ctx, uint32_t ino, struct stat * stat) {

  emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_inode_stat ino=%d", ino);

  if (!stat) {

    return -1;
  }
  
  struct exafs_inode * inode = exafs_inode_find_by_id(ctx, ino); 

  if (!inode) {

    return -1;
  }

  //stat->dev_t      st_dev;      /* ID of device containing file */
  stat->st_ino = ino;      /* Inode number */
  stat->st_mode = inode->mode;     /* File type and mode */
  stat->st_nlink = inode->nlink;    /* Number of hard links */
  stat->st_uid = inode->uid;      /* User ID of owner */
  stat->st_gid = inode->gid;      /* Group ID of owner */
  //dev_t      st_rdev;     /* Device ID (if special file) */
  stat->st_size = inode->size;     /* Total size, in bytes */
  stat->st_blksize = 0;  /* Block size for filesystem I/O */
  stat->st_blocks = 0;

  stat->st_atim.tv_sec = inode->atime;  /* Time of last access */
  stat->st_mtim.tv_sec = inode->mtime;  /* Time of last modification */
  stat->st_ctim.tv_sec = inode->ctime;
  
  return 0;
}

