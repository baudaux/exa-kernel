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
