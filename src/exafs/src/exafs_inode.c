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

struct exafs_dir_entry * exafs_inode_get_entry(struct exafs_ctx * ctx, uint32_t parent_ino, const char * path) {

  emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_inode_get_entry: ino=%d", parent_ino);
  
  struct exafs_inode * parent_inode = exafs_inode_find_by_id(ctx, parent_ino); 

  if (!parent_inode) {

    return 0;
  }

  if (!parent_inode->e.entry_table) {

    exafs_inode_read_entry(ctx, parent_inode);
  }

  struct exafs_dir_entry * e = NULL;

  HASH_FIND_STR( parent_inode->e.entry_table, path, e);

  return e;
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
  
  inode->obj = 0;

  if (inode->mode & S_IFDIR) {
    inode->e.entry_table = NULL;
  }
  else {
    inode->e.chunk_entry_list = NULL;
  }
  
  HASH_ADD_INT( ctx->inode_table, ino, inode );

  ctx->next_ino = inode->ino+1;
  
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
  
  struct exafs_inode * parent_inode = exafs_inode_find_by_id(ctx, entry_meta->parent_ino); 
  
  if (!parent_inode) {
    
    return -1;
  }

  if (!parent_inode->e.entry_table) {

    exafs_inode_read_entry(ctx, parent_inode);
  }

  struct exafs_dir_entry * dir_entry = NULL;

  HASH_FIND_STR( parent_inode->e.entry_table, entry_meta->path, dir_entry);

  if (dir_entry) {

    dir_entry->ino = entry_meta->ino;
  }
  else {

    dir_entry = (struct exafs_dir_entry *)malloc(sizeof(struct exafs_dir_entry));

    if (!dir_entry) {

      return -1;
    }
    
    strcpy(dir_entry->path, entry_meta->path);
    dir_entry->ino = entry_meta->ino;

    HASH_ADD_STR( parent_inode->e.entry_table, path, dir_entry );
  }
  
  return 0;
}

int exafs_inode_unlink_record(struct exafs_ctx * ctx, uint32_t ino, const char * path, time_t now, char * ptr) {

  emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_inode_unlink_record: ino=%d path=%s", ino, path);
  
  int record_size = sizeof(struct exafs_dir_entry_meta);

  int header_len = exafs_record_header(ctx, EXAFS_OP_UNLINK, now, record_size, (struct meta_record *)ptr);

  struct exafs_dir_entry_meta * entry = (struct exafs_dir_entry_meta *)(ptr+header_len);

  entry->parent_ino = ino;
  entry->ino = 0;
  
  strcpy(entry->path, path);
  
  int crc_len = exafs_record_crc((struct meta_record *)ptr);
  
  return header_len+record_size+crc_len;
}

int exafs_inode_unlink(struct exafs_ctx * ctx, struct exafs_dir_entry_meta * entry_meta) {

  emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_inode_unlink: ino=%d path=%s", entry_meta->parent_ino, entry_meta->path);
  
  struct exafs_inode * inode = exafs_inode_find_by_id(ctx, entry_meta->parent_ino); 

  if (!inode) {
    
    return -1;
  }

  if (!inode->e.entry_table) {

    exafs_inode_read_entry(ctx, inode);
  }

  struct exafs_dir_entry * e = NULL;
    
  HASH_FIND_STR( inode->e.entry_table, entry_meta->path, e);

  if (!e) {

    return -1;
  }

  emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_inode_unlink: entry found");

  HASH_DEL(inode->e.entry_table, e);
  
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


int exafs_inode_set_ctime_record(struct exafs_ctx * ctx, uint32_t ino, time_t now, char * ptr) {

  int record_size = sizeof(struct exafs_set_time_meta);

  int header_len = exafs_record_header(ctx, EXAFS_OP_INODE_SET_CTIME, now, record_size, (struct meta_record *)ptr);

  struct exafs_set_time_meta * m = (struct exafs_set_time_meta *)(ptr+header_len);

  m->ino = ino;
  m->time = now;
  
  int crc_len = exafs_record_crc((struct meta_record *)ptr);
  
  return header_len+record_size+crc_len;
}

int exafs_inode_set_ctime(struct exafs_ctx * ctx, struct exafs_set_time_meta * meta) {

  struct exafs_inode * inode = exafs_inode_find_by_id(ctx, meta->ino); 

  if (!inode) {

    return -1;
  }

  inode->ctime = meta->time;
  
  return 0;
}

int exafs_inode_set_atime_record(struct exafs_ctx * ctx, uint32_t ino, time_t now, char * ptr) {

  int record_size = sizeof(struct exafs_set_time_meta);

  int header_len = exafs_record_header(ctx, EXAFS_OP_INODE_SET_ATIME, now, record_size, (struct meta_record *)ptr);

  struct exafs_set_time_meta * m = (struct exafs_set_time_meta *)(ptr+header_len);

  m->ino = ino;
  m->time = now;
  
  int crc_len = exafs_record_crc((struct meta_record *)ptr);
  
  return header_len+record_size+crc_len;
}

int exafs_inode_set_atime(struct exafs_ctx * ctx, struct exafs_set_time_meta * meta) {

  struct exafs_inode * inode = exafs_inode_find_by_id(ctx, meta->ino); 

  if (!inode) {

    return -1;
  }

  inode->atime = meta->time;
  
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

  emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_inode_find_by_id: ino=%d", ino);

  uint32_t ino2 = ino;

  HASH_FIND_INT( ctx->inode_table, &ino2, inode );

  if (!inode) { // Search inode in inode table created by snapshot
    
    emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_inode_find_by_id: %d not found", ino);
    
    int group_size = sizeof(uint64_t) + ctx->grp_size * (sizeof(struct exafs_inode_meta) + sizeof(uint32_t));
  
    // buf stores one group A and B
    char * buf = (char *)malloc(2 * group_size);

    int group = ino / ctx->grp_size;

    int updating_slot = exafs_io_read_group(ctx, group, buf, 0);

    emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_inode_find_by_id: exafs_io_read_group %d -> %d", group, updating_slot);
    
    if (updating_slot < 0) {

      return NULL;
    }
    else {

      char * ptr = buf;

      if (updating_slot > 0) {

	ptr += group_size;
      }

      ptr += sizeof(uint64_t);
      
      for (int i=0; i < ctx->grp_size; i++) {

	struct exafs_inode_meta * inode_meta = (struct exafs_inode_meta *)ptr;

	int found = 0;

	if (inode_meta->ino) {

	  uint32_t ino2 = inode_meta->ino;
	  struct exafs_inode * inode2 = NULL;

	  HASH_FIND_INT( ctx->inode_table, &ino2, inode2 );

	  found = (inode2 != NULL);
	}

	if ((inode_meta->ino) && !found) {

	  emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_inode_find_by_id: load inode %d", inode_meta->ino);

	  struct exafs_inode * inode2 = (struct exafs_inode *)malloc(sizeof(struct exafs_inode));

	  if (!inode2) {

	    return NULL;
	  }
  
	  inode2->ino = inode_meta->ino;
	  inode2->size = inode_meta->size;
	  inode2->atime = inode_meta->atime;
	  inode2->btime = inode_meta->btime;
	  inode2->ctime = inode_meta->ctime;
	  inode2->mtime = inode_meta->mtime;
	  inode2->mode = inode_meta->mode;
	  inode2->uid = inode_meta->uid;
	  inode2->gid = inode_meta->gid;
	  inode2->nlink = inode_meta->nlink;

	  ptr += sizeof(struct exafs_inode_meta);

	  inode2->obj = *((uint32_t *)ptr);

	  ptr += sizeof(uint32_t);
	  
	  if (inode2->mode & S_IFDIR) {
	    inode2->e.entry_table = NULL;
	  }
	  else {
	    inode2->e.chunk_entry_list = NULL;
	  }
	  
	  HASH_ADD_INT( ctx->inode_table, ino, inode2 );

	  if (ino == inode_meta->ino) {

	    inode = inode2;
	  }
	}
	else {

	  ptr += sizeof(struct exafs_inode_meta)+sizeof(uint32_t);
	}
      }
    }
  }

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

    if (!inode->e.entry_table) {

      exafs_inode_read_entry(ctx, inode);
    }
    
    struct exafs_dir_entry * e = NULL;
    
    HASH_FIND_STR( inode->e.entry_table, leaf+1, e);

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
  stat->st_blksize = 4096;  /* Block size for filesystem I/O */
  stat->st_blocks = (inode->size / 4096)+1;

  stat->st_atim.tv_sec = inode->atime;  /* Time of last access */
  stat->st_mtim.tv_sec = inode->mtime;  /* Time of last modification */
  stat->st_ctim.tv_sec = inode->ctime;
  
  return 0;
}

uint32_t exafs_inode_get_nb_entries(struct exafs_ctx * ctx, uint32_t ino) {

  struct exafs_inode * inode = exafs_inode_find_by_id(ctx, ino);

  if (!inode) {

    return 0;
  }

  if (!(inode->mode & S_IFDIR)) {

    return 0;
  }

  return HASH_COUNT(inode->e.entry_table);
}

int by_ino(const struct exafs_inode  * a, const struct exafs_inode * b) {
  
  return (a->ino - b->ino);
}

void exafs_inode_sort(struct exafs_ctx * ctx) {
  
  HASH_SORT(ctx->inode_table, by_ino);
}

char * exafs_inode_snap_dir(struct exafs_ctx * ctx, struct exafs_inode * inode, uint32_t * size) {

  int nb_entries = HASH_COUNT(inode->e.entry_table);

  char * buf = (char*)malloc(nb_entries * (PATHNAME_LEN_MAX + 2 * sizeof(uint32_t)));

  struct exafs_dir_entry * current;
  struct exafs_dir_entry * tmp;

  char * ptr = buf;

  if (!inode->e.entry_table) {

    exafs_inode_read_entry(ctx, inode);
  }

  HASH_ITER(hh, inode->e.entry_table, current, tmp) {

    int len = strlen(current->path);

    *((uint32_t *)ptr) = current->ino;
    ptr += sizeof(uint32_t);
    *((uint32_t *)ptr) = len;
    ptr += sizeof(uint32_t);
    memcpy(ptr, current->path, len);
    ptr += len;
    
    /* useful ?

      int padding = (4 - (len%4))%4;

      ptr += padding;*/
  }
  
  *size = ptr-buf;

  return buf;
}

char * exafs_inode_snap_file(struct exafs_ctx * ctx, struct exafs_inode * inode, uint32_t * size) {

  int nb_entries = 0;

  if (!inode->e.chunk_entry_list) {

    exafs_inode_read_entry(ctx, inode);
  }

  struct exafs_chunk_entry * chunk_entry = inode->e.chunk_entry_list;

  while (chunk_entry) {

    nb_entries++;

    chunk_entry = chunk_entry->next;
  }

  char * buf = (char*)malloc(nb_entries * (2 * sizeof(uint64_t) + sizeof(uint32_t)));

  chunk_entry = inode->e.chunk_entry_list;

  char * ptr = buf;

  while (chunk_entry) {
    
    *((uint64_t *)ptr) = chunk_entry->offset;
    ptr += sizeof(uint64_t);
    *((uint64_t *)ptr) = chunk_entry->size;
    ptr += sizeof(uint64_t);
    *((uint64_t *)ptr) = chunk_entry->id;
    ptr += sizeof(uint32_t);

    chunk_entry = chunk_entry->next;
  }

  *size = ptr-buf;
  
  return buf;
}

void exafs_inode_snap_content(struct exafs_ctx * ctx, struct exafs_inode * inode) {
  
  char * buf;
  uint32_t size;
  uint32_t id;

  emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_inode_snap_content: ino=%d", inode->ino);

  if (inode->mode & S_IFDIR) {

    buf = exafs_inode_snap_dir(ctx, inode, &size);
  }
  else {

    buf = exafs_inode_snap_file(ctx, inode, &size);
  }

  if (!buf) {
    return;
  }

  ctx->write_rand(ctx, EXAFS_NB_SUPERBLOCKS+ctx->meta_log_size+ctx->snapshot_size, buf, size, &id);

  inode->obj = id;

  emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_inode_snap_content -> obj=%d", id);
  
  free(buf);
}

void exafs_inode_snap(struct exafs_ctx * ctx, uint64_t now) {

  struct exafs_inode * current_inode;
  struct exafs_inode * tmp;

  int updating_group = -1;
  int updating_slot = 0;

  int group_size = sizeof(uint64_t) + ctx->grp_size * (sizeof(struct exafs_inode_meta) + sizeof(uint32_t));
  
  // buf stores one group A and B
  char * buf = (char *)malloc(2 * group_size);

  HASH_ITER(hh, ctx->inode_table, current_inode, tmp) {

    if (current_inode->mtime > ctx->superblocks[ctx->active_superblock].generation) {

      exafs_inode_snap_content(ctx, current_inode);
    }

    if ( (current_inode->mtime > ctx->superblocks[ctx->active_superblock].generation) || (current_inode->ctime > ctx->superblocks[ctx->active_superblock].generation) ) {

      emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_inode_snap: store ino=%d", current_inode->ino);
      
      if ( (updating_group >= 0) && ((current_inode->ino / ctx->grp_size) != updating_group) ) {

	// Store updated group
	
	exafs_io_write_group(ctx, updating_group, buf, updating_slot);

	updating_group = -1;
      }

      if ((current_inode->ino / ctx->grp_size) != updating_group) {

	// Read new group (slots A and B)

	updating_group = current_inode->ino / ctx->grp_size;

	updating_slot = exafs_io_read_group(ctx, updating_group, buf, now);
      }

      int offset = (updating_slot == 0)?0:group_size;

      char * ptr = buf+offset;

      ptr += sizeof(uint64_t);

      ptr += (current_inode->ino % ctx->grp_size) * (sizeof(struct exafs_inode_meta) + sizeof(uint32_t));

      struct exafs_inode_meta * meta = (struct exafs_inode_meta *)ptr;

      meta->ino = current_inode->ino;
      meta->size = current_inode->size;
      meta->atime = current_inode->atime;
      meta->btime = current_inode->btime;
      meta->ctime = current_inode->ctime;
      meta->mtime = current_inode->mtime;
      meta->mode = current_inode->mode;
      meta->uid = current_inode->uid;
      meta->gid = current_inode->gid;
      meta->nlink = current_inode->nlink;

      ptr += sizeof(struct exafs_inode_meta);

      *((uint32_t *)ptr) = current_inode->obj;
    }
    else {

      emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_inode_snap: inode not updated mtime=%lld ctime=%lld", current_inode->mtime, current_inode->ctime);
    }
  }
  
  if (updating_group >= 0) {

    // Store updating group

    exafs_io_write_group(ctx, updating_group, buf, updating_slot);
  }  
}

int exafs_inode_read_entry(struct exafs_ctx * ctx, struct exafs_inode * inode) {

  emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_inode_read_entry: ino=%d", inode->ino);

  if (!inode->obj) {

    return -1;
  }

  int size = 128 * 1024;
  
  char * buf = (char *)malloc(size);

  int len = ctx->read(ctx, inode->obj, buf, size, 0);

  if (len < -1) {

    free(buf);

    buf = (char *)malloc(size);

    if (ctx->read(ctx, inode->obj, buf, len, 0) != len) {

      return -1;
    }
  }

  char * ptr = buf;

  if (inode->mode & S_IFDIR) {

    while ((ptr-buf) < len) {

      struct exafs_dir_entry * dir_entry = (struct exafs_dir_entry *)malloc(sizeof(struct exafs_dir_entry));

      if (!dir_entry) {
	
	return -1;
      }
      
      dir_entry->ino = *((uint32_t *)ptr);
      ptr += sizeof(uint32_t);
      uint32_t path_len = *((uint32_t *)ptr);
      ptr += sizeof(uint32_t);
      strncpy(dir_entry->path, ptr, path_len);
      dir_entry->path[path_len] = 0;
      ptr += path_len;

      HASH_ADD_STR( inode->e.entry_table, path, dir_entry );
    }
  }
  else {

    while ((ptr-buf) < len) {

      uint64_t offset = *((uint64_t *)ptr);
      ptr += sizeof(uint64_t);
      uint64_t size = *((uint64_t *)ptr);
      ptr += sizeof(uint64_t);
      uint32_t id = *((uint32_t *)ptr);
      ptr += sizeof(uint32_t);
      
      exafs_inode_add_extent(inode, size, offset, id);
    }
  }
  
  return 0;
}
