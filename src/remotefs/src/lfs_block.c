#include "lfs_block.h"
#include "lfs_cache.h"

#include <emscripten.h>

void lfs_blk_set(const char * view) {

  EM_ASM({

      window.view = UTF8ToString($0, $1);

      //console.log("lfs_block: view="+window.view);
	  
    }, view, strlen(view));

  lfs_cache_init();
}

int lfs_blk_read(const struct lfs_config * c, lfs_block_t block, lfs_off_t off, void * buffer, lfs_size_t size) {

  return lfs_cache_block_read(block, off, buffer, size);
}

int lfs_blk_prog(const struct lfs_config * c, lfs_block_t block, lfs_off_t off, const void * buffer, lfs_size_t size) {

  return lfs_cache_block_write(block, off, buffer, size);
}

int lfs_blk_erase(const struct lfs_config * c, lfs_block_t block) {

    return lfs_cache_block_erase(block);
}

int lfs_blk_sync(const struct lfs_config * c) {
  
  return lfs_cache_block_sync();
}
