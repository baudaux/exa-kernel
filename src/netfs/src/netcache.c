/*
 * Copyright (C) 2023 Benoit Baudaux
 *
 * This file is part of EXA.
 *
 * EXA is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * EXA is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with EXA. If not, see <https://www.gnu.org/licenses/>.
 */

#include <string.h>
#include <stdlib.h>

#include "netcache.h"

#ifndef DEBUG
#define DEBUG 0
#endif

#if DEBUG
#include <emscripten.h>
#else
#define emscripten_log(...)
#endif

#define STAT_CACHE_SIZE 256
#define DENTS_CACHE_SIZE 256
#define DATA_CACHE_SIZE 256

struct stat_entry {

  unsigned long key;
  char path[1024];
  struct stat stat;
  int _errno;

  struct stat_entry * next;
};

struct dents_entry {

  unsigned long key;
  char path[1024];
  int buflen;
  char * buf;
  int _errno;
  
  struct dents_entry * next;
};

struct data_entry {

  unsigned long key;
  char path[1024];
  int buflen;
  char * buf;
  int _errno;
  
  struct data_entry * next;
};

struct stat_entry * stat_cache[STAT_CACHE_SIZE] = { 0 };

struct dents_entry * dents_cache[DENTS_CACHE_SIZE] = { 0 };

struct data_entry * data_cache[DATA_CACHE_SIZE] = { 0 };

void netcache_init() {

  
}

unsigned long netcache_get_key(const char * path) {

  unsigned long key = 0;

  char * c = path;
  
  for (unsigned long i = 0; *c ; ++c,++i) {

    key += 1000*(i+1)*(*c);
  }
  
  return key;
}

int netcache_get_stat(const char * path, struct stat * stat) {

  unsigned long key = netcache_get_key(path);

  int index = key % STAT_CACHE_SIZE;

  for (struct stat_entry * entry = stat_cache[index]; entry; entry = entry->next) {

    if (entry->key == key) {

      memmove(stat, &entry->stat, sizeof(*stat));
      return entry->_errno;
    }
  }
  
  return ENOTCACHED;
}

int netcache_set_stat(const char * path, struct stat * stat, int _errno) {

  unsigned long key = netcache_get_key(path);

  int index = key % STAT_CACHE_SIZE;

  for (struct stat_entry * entry = stat_cache[index]; entry; entry = entry->next) {

    if (entry->key == key) {

      return -1;
    }
  }

  struct stat_entry * new_entry = (struct stat_entry *)malloc(sizeof(struct stat_entry));

  new_entry->key = key;
  strcpy(new_entry->path, path);
  memmove(&new_entry->stat, stat, sizeof(*stat));
  new_entry->_errno = _errno;
  
  new_entry->next = stat_cache[index];
  
  stat_cache[index] = new_entry;

  return 0;
}

char * netcache_get_dents(const char * path, int * len, int * _errno) {

  unsigned long key = netcache_get_key(path);

  int index = key % DENTS_CACHE_SIZE;

  for (struct dents_entry * entry = dents_cache[index]; entry; entry = entry->next) {
    
    if (entry->key == key) {

      *len = entry->buflen;
      *_errno = entry->_errno;
      
      return entry->buf;
    }
  }

  *_errno = ENOTCACHED;
  
  return NULL;
}

int netcache_set_dents(const char * path, char * buf, int len, int _errno) {

  unsigned long key = netcache_get_key(path);

  int index = key % DENTS_CACHE_SIZE;

  for (struct dents_entry * entry = dents_cache[index]; entry; entry = entry->next) {

    if (entry->key == key) {
      
      return -1;
    }
  }

  struct dents_entry * new_entry = (struct dents_entry *)malloc(sizeof(struct dents_entry));

  new_entry->key = key;
  strcpy(new_entry->path, path);

  new_entry->buflen = len;
  new_entry->buf = buf;
  
  new_entry->_errno = _errno;
  
  new_entry->next = dents_cache[index];
  
  dents_cache[index] = new_entry;

  return len;
}

int netcache_read(const char * path, int offset, char * buf, int count) {

  unsigned long key = netcache_get_key(path);

  int index = key % DATA_CACHE_SIZE;

  for (struct data_entry * entry = data_cache[index]; entry; entry = entry->next) {
    
    if (entry->key == key) {

      int size = (count <= (entry->buflen-offset))?count:entry->buflen-offset;

      if (entry->buf && (size > 0) )
	memmove(buf, entry->buf+offset, size);
      
      return size;
    }
  }
  
  return -ENOTCACHED;
}

int netcache_write(const char * path, char * buf, int count) {

  unsigned long key = netcache_get_key(path);

  int index = key % DATA_CACHE_SIZE;

  for (struct data_entry * entry = data_cache[index]; entry; entry = entry->next) {

    if (entry->key == key) {
      
      return -1;
    }
  }

  struct data_entry * new_entry = (struct data_entry *)malloc(sizeof(struct data_entry));

  new_entry->key = key;
  strcpy(new_entry->path, path);

  new_entry->buflen = count;
  new_entry->buf = buf;
  
  new_entry->_errno = 0;
  
  new_entry->next = data_cache[index];
  
  data_cache[index] = new_entry;

  return count;
}
