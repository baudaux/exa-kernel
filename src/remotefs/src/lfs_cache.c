#include "lfs_cache.h"
#include "lfs_cluster.h"

#include <emscripten.h>

#define NB_CLUSTERS (LFS_BLK_NB/LFS_BLK_PER_CLS)
#define CLUSTER_SIZE (LFS_BLK_PER_CLS * LFS_BLK_SIZE)

#define NB_DIRTY_MAX 20

static struct cache_entry cluster_cache[NB_CLUSTERS];

static int cache_init = 0;

static int dirty_clusters[NB_DIRTY_MAX];
static int dirty_index = 0;

void lfs_cache_init() {
  
  if (!cache_init) {

    for (int i = 0; i < NB_CLUSTERS; ++i) {

      cluster_cache[i].data = NULL;
      cluster_cache[i].dirty = 0;
    }

    dirty_index = 0;

    cache_init = 1;
  }
}

int add_dirty_cluster(int cluster) {

  cluster_cache[cluster].dirty = 1;
  dirty_clusters[dirty_index++] = cluster;
    
  if (dirty_index >= NB_DIRTY_MAX) {

    lfs_cache_block_sync();
  }

  return 0;
}

int lfs_cache_block_read(int block, int off, void * buffer, int size) {

  int cls = block / LFS_BLK_PER_CLS;

  if (!cluster_cache[cls].data) {

    cluster_cache[cls].data = (char *)malloc(LFS_BLK_PER_CLS * LFS_BLK_SIZE);

    lfs_cluster_read(cls, cluster_cache[cls].data, CLUSTER_SIZE);
  }
  
  int offset = (block % LFS_BLK_PER_CLS) * LFS_BLK_SIZE + off;

  memcpy(buffer, cluster_cache[cls].data + offset, size);
  
  return 0;
}

int lfs_cache_block_write(int block, int off, void * buffer, int size) {

  int cls = block / LFS_BLK_PER_CLS;

  if (!cluster_cache[cls].data) {

    cluster_cache[cls].data = (char *)malloc(LFS_BLK_PER_CLS * LFS_BLK_SIZE);
    
    lfs_cluster_read(cls, cluster_cache[cls].data, CLUSTER_SIZE);
  }
  
  int offset = (block % LFS_BLK_PER_CLS) * LFS_BLK_SIZE + off;

  memcpy(cluster_cache[cls].data + offset, buffer, size);

  add_dirty_cluster(cls);
  
  return 0;
}

int lfs_cache_block_erase(int block) {

  int cls = block / LFS_BLK_PER_CLS;

  if (!cluster_cache[cls].data) {

    cluster_cache[cls].data = (char *)malloc(LFS_BLK_PER_CLS * LFS_BLK_SIZE);

    lfs_cluster_read(cls, cluster_cache[cls].data, CLUSTER_SIZE);
  }

  int offset = (block % LFS_BLK_PER_CLS) * LFS_BLK_SIZE;

  memset(cluster_cache[cls].data + offset, 0xFF, LFS_BLK_SIZE);

  add_dirty_cluster(cls);
  
  return 0;
}

int lfs_cache_block_sync() {

  emscripten_log(EM_LOG_CONSOLE,"!!! lfs_cache_block_sync !!! (%d)", dirty_index);

  for (int i=0; i < dirty_index; i++) {

    int cls = dirty_clusters[i];

    if (cluster_cache[cls].dirty) {

      lfs_cluster_write(cls, cluster_cache[cls].data, CLUSTER_SIZE);
      cluster_cache[cls].dirty = 0;
    }
  }

  dirty_index = 0;

  return 0;
}
