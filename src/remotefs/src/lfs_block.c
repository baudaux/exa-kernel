#include "lfs_block.h"
#include "lfs_cache.h"

#include <emscripten.h>

int lfs_blk_read(const struct lfs_config * c, lfs_block_t block, lfs_off_t off, void * buffer, lfs_size_t size) {

  return lfs_cache_block_read(c->context, block, off, buffer, size);
}

int lfs_blk_prog(const struct lfs_config * c, lfs_block_t block, lfs_off_t off, const void * buffer, lfs_size_t size) {

  return lfs_cache_block_write(c->context, block, off, buffer, size);
}

int lfs_blk_erase(const struct lfs_config * c, lfs_block_t block) {

    return lfs_cache_block_erase(c->context, block);
}

int lfs_blk_sync(const struct lfs_config * c) {
  
  return lfs_cache_block_sync(c->context);
}
