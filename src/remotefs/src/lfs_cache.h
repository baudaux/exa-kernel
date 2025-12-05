#ifndef _LFS_CACHE_H
#define _LFS_CACHE_H

#include "lfs_block.h"

#define LFS_BLK_PER_CLS 16

struct cache_entry {

  char * data;
  int dirty;
};

void lfs_cache_init();

int lfs_cache_block_read(int block, int off, void * buffer, int size);
int lfs_cache_block_write(int block, int off, void * buffer, int size);
int lfs_cache_block_erase(int block);
int lfs_cache_block_sync();

#endif
