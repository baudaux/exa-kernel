#ifndef _LFS_CACHE_H
#define _LFS_CACHE_H

#include <sodium/crypto_kdf.h>

#define LFS_BLK_PER_CLS 16

#define LFS_HEADER_SIZE 256

#define NB_CLUSTERS (LFS_BLK_NB/LFS_BLK_PER_CLS)
#define CLUSTER_SIZE (LFS_BLK_PER_CLS * LFS_BLK_SIZE + LFS_HEADER_SIZE)

#define NB_DIRTY_MAX 20

struct cache_entry {

  char * data;
  int dirty;
};

struct cluster_ops {

  int (*cls_read)(int view_id, int cluster, void * buffer, int size);
  int (*cls_write)(int view_id, int cluster, char * buffer, int size);
  int (*cls_bulk_start)(int view_id);
  int (*cls_bulk_end)(int view_id);
};

struct blk_cache {

  struct cache_entry cluster_cache[NB_CLUSTERS];

  int dirty_clusters[NB_DIRTY_MAX];
  int dirty_index;

  int view_index;
  char * key;

  struct cluster_ops * ops;
};

struct blk_cache * alloc_cache(const char * view, const char * key, struct cluster_ops * ops);
void free_cache(struct blk_cache * cache);

int lfs_cache_block_read(struct blk_cache * cache, int block, int off, void * buffer, int size);
int lfs_cache_block_write(struct blk_cache * cache, int block, int off, void * buffer, int size);
int lfs_cache_block_erase(struct blk_cache * cache, int block);
int lfs_cache_block_sync(struct blk_cache * cache);

#endif
