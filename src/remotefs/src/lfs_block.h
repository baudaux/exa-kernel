#ifndef _LFS_BLOCK_H
#define _LFS_BLOCK_H

#define LFS_BLK_SIZE 4096
#define LFS_BLK_NB (256*1024)
#define LFS_CACHE_SIZE 4096

#include "lfs.h"
#include "lfs_cache.h"


struct blk_context {

  int view_index;
  struct blk_cache cache;
};

struct blk_context * alloc_blk_context(const char * view);

void free_blk_context(struct blk_context * blk_context);

int lfs_blk_read(const struct lfs_config *c, lfs_block_t block,
            lfs_off_t off, void *buffer, lfs_size_t size);

int lfs_blk_prog(const struct lfs_config *c, lfs_block_t block,
            lfs_off_t off, const void *buffer, lfs_size_t size);

int lfs_blk_erase(const struct lfs_config *c, lfs_block_t block);

int lfs_blk_sync(const struct lfs_config *c);

#endif //_LFS_BLOCK_H
