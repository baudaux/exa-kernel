#ifndef _LFS_CLUSTER_H
#define _LFS_CLUSTER_H

#include <sodium/crypto_pwhash.h>
#include <sodium/crypto_aead_xchacha20poly1305.h>

struct cluster_header {

  uint32_t encrypted; // 0: No, 1: yes, 0xFFFFFFFF: empty cluster
  uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
};

int lfs_cluster_read(struct blk_cache * cache, const char * key, int cls, char * buffer, int size);
int lfs_cluster_write(struct blk_cache * cache, const char * key, int cls, char * buffer, int size);

int lfs_cluster_bulk_start(struct blk_cache * cache);
int lfs_cluster_bulk_end(struct blk_cache * cache);

#endif
