/*
 * Copyright (C) 2025 Benoit Baudaux
 *
 * This file is part of EXA.
 *
 * EXA is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundationt, either version 3 of the License, or (at your option) any later version.
 *
 * EXA is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with EXA. If not, sees <https://www.gnu.org/licenses/>.
 */

#include <emscripten.h>

#include "lfs_block.h"
#include "lfs_cache.h"
#include "lfs_cluster.h"

#ifndef DEBUG
#define DEBUG 0
#endif

#if DEBUG

#else
#define emscripten_log(...)
#endif

int lfs_set_view(const char * view) {

  int i = EM_ASM_INT({

      if (typeof window.views === 'undefined') {

	window.views = new Array();
      }

      window.views.push(UTF8ToString($0, $1));

      //console.log("lfs_block: view="+window.view);

      return window.views.length-1;
	  
    }, view, strlen(view));

  return i;
}

struct blk_cache * alloc_cache(const char * view, const char * key, struct cluster_ops * ops) {

  struct blk_cache * cache = (struct blk_cache *)malloc(sizeof(struct blk_cache));

  cache->view_index = lfs_set_view(view);
  cache->key = key;
  cache->ops = ops;
  
  for (int i = 0; i < NB_CLUSTERS; ++i) {

    cache->cluster_cache[i].data = NULL;
    cache->cluster_cache[i].dirty = 0;
  }
  
  cache->dirty_index = 0;

  return cache;
}

void free_cache(struct blk_cache * cache) {

  for (int i = 0; i < NB_CLUSTERS; ++i) {

    if (cache->cluster_cache[i].data) {

      free(cache->cluster_cache[i].data);
    }
  }

  free(cache);
}

int add_dirty_cluster(struct blk_cache * cache, int cluster) {

  if (!cache->cluster_cache[cluster].dirty) {
    
    cache->cluster_cache[cluster].dirty = 1;
    cache->dirty_clusters[cache->dirty_index++] = cluster;
    
    if (cache->dirty_index >= NB_DIRTY_MAX) {

      lfs_cache_block_sync(cache);
    }
  }

  return 0;
}

int lfs_cache_block_read(struct blk_cache * cache, int block, int off, void * buffer, int size) {

  emscripten_log(EM_LOG_CONSOLE, "--> lfs_cache_block_read: block=%d off=%d buffer=%p size=%d", block, off, buffer, size);
  
  int cls = block / LFS_BLK_PER_CLS;

  if (!cache->cluster_cache[cls].data) {

    emscripten_log(EM_LOG_CONSOLE, "lfs_cache_block_read: alloc mem for cluster %d", cls);

    cache->cluster_cache[cls].data = (char *)malloc(CLUSTER_SIZE);

    int res = lfs_cluster_read(cache, cache->key, cls, cache->cluster_cache[cls].data, CLUSTER_SIZE);

    if (res < 0) {
      return res;
    }
  }
  
  int offset = LFS_HEADER_SIZE + (block % LFS_BLK_PER_CLS) * LFS_BLK_SIZE + off;

  memcpy(buffer, cache->cluster_cache[cls].data + offset, size);

  emscripten_log(EM_LOG_CONSOLE, "<-- lfs_cache_block_read: block=%d", block);
  
  return 0;
}

int lfs_cache_block_write(struct blk_cache * cache, int block, int off, void * buffer, int size) {

  emscripten_log(EM_LOG_CONSOLE, "lfs_cache_block_write: block=%d", block);
  
  int cls = block / LFS_BLK_PER_CLS;

  if (!cache->cluster_cache[cls].data) {

    cache->cluster_cache[cls].data = (char *)malloc(CLUSTER_SIZE);
    
    int res = lfs_cluster_read(cache, cache->key, cls, cache->cluster_cache[cls].data, CLUSTER_SIZE);
    
    if (res < 0) {
      return res;
    }
  }
  
  int offset = LFS_HEADER_SIZE + (block % LFS_BLK_PER_CLS) * LFS_BLK_SIZE + off;

  memcpy(cache->cluster_cache[cls].data + offset, buffer, size);

  add_dirty_cluster(cache, cls);
  
  return 0;
}

int lfs_cache_block_erase(struct blk_cache * cache, int block) {

  emscripten_log(EM_LOG_CONSOLE, "lfs_cache_block_erase: block=%d", block);
  
  int cls = block / LFS_BLK_PER_CLS;

  if (!cache->cluster_cache[cls].data) {

    cache->cluster_cache[cls].data = (char *)malloc(CLUSTER_SIZE);
    
    int res = lfs_cluster_read(cache, cache->key, cls, cache->cluster_cache[cls].data, CLUSTER_SIZE);

    if (res < 0) {
      return res;
    }
  }

  int offset = LFS_HEADER_SIZE + (block % LFS_BLK_PER_CLS) * LFS_BLK_SIZE;

  memset(cache->cluster_cache[cls].data + offset, 0xFF, LFS_BLK_SIZE);

  add_dirty_cluster(cache, cls);
  
  return 0;
}

int lfs_cache_block_sync(struct blk_cache * cache) {

  emscripten_log(EM_LOG_CONSOLE,"lfs_cache_block_sync (dirty index = %d)", cache->dirty_index);

  lfs_cluster_bulk_start(cache);

  for (int i=0; i < cache->dirty_index; i++) {

    int cls = cache->dirty_clusters[i];

    if (cache->cluster_cache[cls].dirty) {

      int res = lfs_cluster_write(cache, cache->key, cls, cache->cluster_cache[cls].data, CLUSTER_SIZE);

      if (res < 0) {
	return res;
      }
      
      cache->cluster_cache[cls].dirty = 0;
    }
  }
  
  lfs_cluster_bulk_end(cache);
  
  cache->dirty_index = 0;

  emscripten_log(EM_LOG_CONSOLE,"lfs_cache_block_sync: done");

  return 0;
}
