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
#include "lfs_remote_dev.h"
#include "lfs_cache.h"
#include "lfs_cluster.h"

#include <sodium/core.h>
#include <sodium/randombytes.h>


#define CONTEXT "EXAFS"

int sodium_initialized = 0;

char tmp[CLUSTER_SIZE+crypto_aead_xchacha20poly1305_ietf_ABYTES];

int lfs_cluster_read(int view_id, const char * key, int cluster, char * buffer, int size) {

  emscripten_log(EM_LOG_CONSOLE,"lfs_cluster_read: cluster=%d", cluster);

  if (!sodium_initialized) {
    
    int res = sodium_init();

    if (res < 0) {

      return res;
    }
    
    sodium_initialized = 1;
  }

  if (key == NULL) {
    
    return lfs_remote_read(view_id, cluster, buffer, size);
  }
  else {

    int res = lfs_remote_read(view_id, cluster, tmp, size+crypto_aead_xchacha20poly1305_ietf_ABYTES);

    if (res < 0)
      return res;

    struct cluster_header * header = (struct cluster_header *) tmp;
    
    if (header->encrypted == 0xFFFFFFFF) { // Empty cluster

      memcpy(buffer, tmp, size);
    }
    else if (header->encrypted == 1) {
      
      char subkey[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];

      res = crypto_kdf_derive_from_key(subkey, sizeof subkey, cluster, CONTEXT, key);

      emscripten_log(EM_LOG_CONSOLE,"lfs_cluster_read: crypto_kdf_derive_from_key -> res=%d", res);
      
      if (res < 0)
	return res;

      int len;

      res = crypto_aead_xchacha20poly1305_ietf_decrypt(buffer+LFS_HEADER_SIZE, &len, NULL, tmp+LFS_HEADER_SIZE, size-LFS_HEADER_SIZE+crypto_aead_xchacha20poly1305_ietf_ABYTES, NULL, 0, header->nonce, subkey);

      emscripten_log(EM_LOG_CONSOLE,"lfs_cluster_read: crypto_aead_xchacha20poly1305_ietf_decrypt -> res=%d (len=%d)", res, len);

      if (res < 0)
	return res;

      if (len != (size-LFS_HEADER_SIZE)) {

	return -1;
      }

      memcpy(buffer, tmp, LFS_HEADER_SIZE);
      
    }
    else {

      return -1;
    }

    return res;
  }
}

int lfs_cluster_write(int view_id, const char * key, int cluster, char * buffer, int size) {

  emscripten_log(EM_LOG_CONSOLE,"lfs_cluster_write: cluster=%d", cluster);
  
  if (!sodium_initialized) {

    int res = sodium_init();

    if (res < 0) {
      return res;
    }
    
    sodium_initialized = 1;
  }

  struct cluster_header * header = (struct cluster_header *) buffer;
  
  if (key == NULL) {
    
    header->encrypted = 0;
    
    return lfs_remote_write(view_id, cluster, buffer, size);
  }
  else {

    header->encrypted = 1;

    char subkey[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];

    int res = crypto_kdf_derive_from_key(subkey, sizeof subkey, cluster, CONTEXT, key);

    emscripten_log(EM_LOG_CONSOLE,"lfs_cluster_write: crypto_kdf_derive_from_key -> res=%d", res);
      
    if (res < 0)
      return res;

    for (int i=0; i < crypto_aead_xchacha20poly1305_ietf_NPUBBYTES; i++) {

      header->nonce[i] = (char) randombytes_random(); // libsodium needs to be initialized first
    }

    int len;

    res = crypto_aead_xchacha20poly1305_ietf_encrypt(tmp+LFS_HEADER_SIZE, &len, buffer+LFS_HEADER_SIZE, size-LFS_HEADER_SIZE, NULL, 0, NULL, header->nonce, subkey);
    
    emscripten_log(EM_LOG_CONSOLE,"lfs_cluster_write: crypto_aead_xchacha20poly1305_ietf_encrypt -> res=%d (len=%d)", res, len);

    if (res < 0)
      return res;

    if (len != (size-LFS_HEADER_SIZE+crypto_aead_xchacha20poly1305_ietf_ABYTES)) {

      emscripten_log(EM_LOG_CONSOLE,"lfs_cluster_write: len=%d size=%d %d %d", len, size, LFS_HEADER_SIZE, crypto_aead_xchacha20poly1305_ietf_ABYTES);
      
      return -1;
    }

    if (res < 0) {
      return res;
    }

    memcpy(tmp, buffer, LFS_HEADER_SIZE);
    
    return lfs_remote_write(view_id, cluster, tmp, size+crypto_aead_xchacha20poly1305_ietf_ABYTES);
  }
}

int lfs_cluster_bulk_start(int view_id) {

  return lfs_remote_bulk_start(view_id);
}

int lfs_cluster_bulk_end(int view_id) {

  return lfs_remote_bulk_end(view_id);
}
