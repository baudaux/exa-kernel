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


#include "exafs_util.h"


uint32_t exafs_crc(const void * data, size_t length, uint32_t previousCrc32)
{
  uint32_t crc = ~previousCrc32; // same as previousCrc32 ^ 0xFFFFFFFF
  const unsigned char * current = (const unsigned char *) data;

  /// look-up table for half-byte, same as crc32Lookup[0][16*i]
  static const uint32_t Crc32Lookup16[16] =
  {
    0x00000000,0x1DB71064,0x3B6E20C8,0x26D930AC,0x76DC4190,0x6B6B51F4,0x4DB26158,0x5005713C,
    0xEDB88320,0xF00F9344,0xD6D6A3E8,0xCB61B38C,0x9B64C2B0,0x86D3D2D4,0xA00AE278,0xBDBDF21C
  };

  while (length-- != 0)
  {
    crc = Crc32Lookup16[(crc ^  *current      ) & 0x0F] ^ (crc >> 4);
    crc = Crc32Lookup16[(crc ^ (*current >> 4)) & 0x0F] ^ (crc >> 4);
    current++;
  }

  return ~crc; // same as crc ^ 0xFFFFFFFF
}

#ifdef HASH
static inline uint64_t hash_u64(uint64_t x) {
  
  x ^= x >> 33;
  x *= 0xff51afd7ed558ccdULL;
  x ^= x >> 33;
  x *= 0xc4ceb9fe1a85ec53ULL;
  x ^= x >> 33;
  
  return x;
}

// 1024 buckets ?

struct htable * htable_create(size_t buckets) {
  
  struct htable * ht = malloc(sizeof(*ht));
  
  ht->bucket_count = buckets;
  ht->buckets = calloc(buckets, sizeof(struct hnode *));
    
  return ht;
}

void * htable_get(struct htable * ht, uint64_t key) {
  
    size_t idx = hash_u64(key) & (ht->bucket_count - 1);
    struct hnode * n = ht->buckets[idx];
    
    while (n) {
      
        if (n->key == key)
            return n->value;
	
        n = n->next;
    }
    
    return NULL;
}

int htable_put(struct htable * ht, uint64_t key, struct inode *value) {
  
  size_t idx = hash_u64(key) & (ht->bucket_count - 1);

  struct hnode * n = ht->buckets[idx];
  
  while (n) {
    
    if (n->key == key)
      return -1; // already exists
    
    n = n->next;
  }

  n = malloc(sizeof(*n));
  
  n->key = key;
  n->value = value;
  n->next = ht->buckets[idx];
  ht->buckets[idx] = n;
  
  return 0;
}

void * htable_remove(struct htable * ht, uint64_t key) {
  
    size_t idx = hash_u64(key) & (ht->bucket_count - 1);

    struct hnode ** pp = &ht->buckets[idx];
    
    while (*pp) {
      
        if ((*pp)->key == key) {
	  
            struct hnode * victim = *pp;
            void * val = victim->value;
            *pp = victim->next;
            free(victim);
	    
            return val;
        }
	
        pp = &(*pp)->next;
    }
    
    return NULL;
}
#endif // HASH
