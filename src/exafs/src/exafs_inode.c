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

#if OLD
int exafs_inode_create(struct exafs_ctx * ctx, uint32_t ino, uint32_t mode, void * ptr) {

  emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_inode_create ino=%d mode=%07o", ino, mode);

  struct exafs_inode * inode = malloc(sizeof(struct exafs_inode));

  inode->ino = ino;
  inode->size = 0;
  inode->mode = mode;
  inode->nlink = 0;
  
  // Add inode in inode table
  
  int res = exafs_inode_add(ctx, inode);

  if (res < 0) {

    return -1;
  }

  struct meta_record * record = exafs_record_create(ctx, EXAFS_OP_CREATE_INODE, inode, sizeof(struct exafs_inode), ptr);
  
  if (!record) {
    
    return -1;
  }

  if (!ptr && !record) { // if ptr is not null then record is set in it. So return is null
    
    return -1;
  }

  if (ptr) {

    // we will store the record later for having all records in a same object
    
    emscripten_log(EM_LOG_CONSOLE, "exafs: exafs_record_create -> res=%d", res);
    
    return sizeof(struct meta_record)+record->len+sizeof(uint32_t);
  }

  // Store inode creation record
  
  res = exafs_record_store(ctx, record);

  free(record);
  
  emscripten_log(EM_LOG_CONSOLE, "exafs: exafs_record_store -> res=%d", res);

  if (res < 0) {

    return -1;
  }
  
  return 0;
}

int exafs_inode_add(struct exafs_ctx * ctx, struct exafs_inode * inode) {

  uint32_t ino = inode->ino;
  
  struct exafs_inode * in = NULL;

  HASH_FIND_INT( ctx->inode_table, &ino, in );

  if (in) { // Not possible to have two inode with same id

    return -1;
  }
  
  HASH_ADD_INT( ctx->inode_table, ino, inode );

#if DEBUG

  unsigned int num_inodes;
  num_inodes = HASH_COUNT(ctx->inode_table);

  emscripten_log(EM_LOG_CONSOLE, "exafs: exafs_inode_add OK -> num=%d", num_inodes);
#endif // DEBUG
  
  return 0;
}

int exafs_inode_delete(struct exafs_ctx * ctx, uint32_t ino) {

  struct exafs_inode * inode = NULL;
  
  HASH_FIND_INT( ctx->inode_table, &ino, inode );

  if (inode) {
  
    HASH_DEL( ctx->inode_table, inode );

    free(inode);

#if DEBUG
    unsigned int num_inodes;
    num_inodes = HASH_COUNT(ctx->inode_table);
    
    emscripten_log(EM_LOG_CONSOLE, "exafs: exafs_inode_delete OK -> num=%d", num_inodes);
#endif // DEBUG

    return 0;
  }
  
  return -1;
}

int exafs_inode_link(struct exafs_ctx * ctx, uint32_t parent_ino, uint32_t child_ino, const char * path, void * ptr) {

  struct exafs_inode * parent_inode = NULL;
  struct exafs_inode * child_inode = NULL;
  
  HASH_FIND_INT( ctx->inode_table, &parent_ino, parent_inode );

  if (!parent_inode) {

    return -1;
  }

  HASH_FIND_INT( ctx->inode_table, &child_ino, child_inode );

  if (!child_inode) {

    return -1;
  }

  struct exafs_dir_entry * e;

  HASH_FIND_STR( parent_inode->entry_table, path, e);

  if (e) {

    return -1;
  }
  
  struct exafs_dir_entry * entry = malloc(sizeof(struct exafs_dir_entry));
  
  if (!entry) {

    return -1;
  }

  entry->ino = child_ino;
  strcpy(entry->path, path);
  
  HASH_ADD_STR( parent_inode->entry_table, path, entry );

  child_inode->nlink++;

  return 0;
}

int exafs_inode_unlink(struct exafs_ctx * ctx, uint32_t parent_ino, const char * path) {

  struct exafs_inode * parent_inode = NULL;
  struct exafs_inode * child_inode = NULL;
  
  HASH_FIND_INT( ctx->inode_table, &parent_ino, parent_inode );

  if (!parent_inode) {

    return -1;
  }

  struct exafs_dir_entry * e;

  HASH_FIND_STR( parent_inode->entry_table, path, e);

  if (e) {

    HASH_FIND_INT( ctx->inode_table, &(e->ino), child_inode );

    if (!child_inode) {

      return -1;
    }

    HASH_DEL( parent_inode->entry_table, e );
    
    free(e);

    child_inode->nlink--;

    return 0;
  }
  
  return -1;
}
#endif // OLD

int exafs_inode_entry_exists(struct exafs_ctx * ctx, uint32_t parent_ino, const char * path) {

  struct exafs_inode * parent_inode = NULL;
  
  HASH_FIND_INT( ctx->inode_table, &parent_ino, parent_inode );

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

int exafs_inode_create(struct exafs_ctx * ctx, struct exafs_inode_meta * inode_meta, time_t now) {

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

  inode->read_offset = 0;

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

int exafs_inode_link(struct exafs_ctx * ctx, struct exafs_dir_entry_meta * entry_meta, time_t now) {

  emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_inode_link: parent_ino=%d ino=%d path=%s", entry_meta->parent_ino, entry_meta->ino, entry_meta->path);

  struct exafs_dir_entry * dir_entry = (struct exafs_dir_entry *)malloc(sizeof(struct exafs_dir_entry));

  if (!dir_entry) {

    return -1;
  }

  strcpy(dir_entry->path, entry_meta->path);
  dir_entry->ino = entry_meta->ino;

  struct exafs_inode * parent_inode = NULL;
  
  HASH_FIND_INT( ctx->inode_table, &(entry_meta->parent_ino), parent_inode );

  if (!parent_inode) {

    free(dir_entry);
    return -1;
  }

  struct exafs_inode * child_inode = NULL;
  
  HASH_FIND_INT( ctx->inode_table, &(entry_meta->ino), child_inode );

  if (!child_inode) {

    free(dir_entry);
    return -1;
  }

  HASH_ADD_STR( parent_inode->entry_table, path, dir_entry );

  child_inode->nlink++;
  
  return 0;
}

uint32_t exafs_inode_find(struct exafs_ctx * ctx, const char * path) {

  emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_inode_find path=%s", path);

  uint32_t ino = EXAFS_ROOT_INO;
  struct exafs_inode * inode = NULL;
  struct exafs_dir_entry * e = NULL;

  char * tmp = (char *)malloc(PATHNAME_LEN_MAX);
  
  if (!path || (strchr(path, '/') != path) ) { // path shall start by '/'

    return 0;
  }

  char * ptr = path+1;

  while (1) {
    
    inode = NULL;

    HASH_FIND_INT( ctx->inode_table, &ino, inode );

    if (!inode) {

      return 0;
    }

    char * s = strchr(ptr, '/');

    if (!s) { // last node

      e = NULL;

      HASH_FIND_STR( inode->entry_table, ptr, e);

      free(tmp);
      
      if (e) {
	
	return e->ino;
      }
      else {

	return 0;
      }
    }
    else {

      strncpy(tmp, ptr, s-ptr);
      tmp[s-ptr] = 0;

      e = NULL;
      
      HASH_FIND_STR( inode->entry_table, tmp, e);

      if (!e) {

	free(tmp);

	return 0;
      }
      else {

	ino = e->ino;
	
	ptr = s+1;
      }
    }
  }
  
  return 0;
}

int exafs_inode_stat(struct exafs_ctx * ctx, uint32_t ino, struct stat * stat) {

  emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_inode_stat ino=%d", ino);

  if (!stat) {

    return -1;
  }
  
  struct exafs_inode * inode = NULL;

  HASH_FIND_INT( ctx->inode_table, &ino, inode );

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

int exafs_dir_read(struct exafs_ctx * ctx, uint32_t ino, struct __dirent * dir_entry) {

  struct exafs_inode * inode = NULL;

  if (!dir_entry) {

    return -1;
  }

  HASH_FIND_INT( ctx->inode_table, &ino, inode );

  if (!inode) {

    return -1;
  }

  if (!(inode->mode & S_IFDIR)) { // inode is not a dir

    return -1;
  }

  struct exafs_dir_entry * e;
  
  int i = 0;

  for (e = inode->entry_table; e != NULL; e = e->hh.next, i++) {
    
    if (i >= inode->read_offset) {

      struct exafs_inode * child_inode = NULL;

      HASH_FIND_INT( ctx->inode_table, &(e->ino), child_inode );

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
	
	inode->read_offset = i+1;

	return 0;
      }
    }
  }
  
  return -1;
}

int exafs_dir_seek(struct exafs_ctx * ctx, uint32_t ino, int64_t offset, int whence) {

  struct exafs_inode * inode = NULL;

  HASH_FIND_INT( ctx->inode_table, &ino, inode );

  if (!inode) {

    return -1;
  }

  if (!(inode->mode & S_IFDIR)) { // inode is not a dir

    return -1;
  }

  switch(whence) {

    case SEEK_SET:

      inode->read_offset = offset;
      break;

    case SEEK_CUR:

      inode->read_offset += offset;
      break;
      
    default:
      break;
  }
  
  return 0;
}
