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

#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stropts.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/sysmacros.h>
#include <dirent.h>

#include <time.h>

#include "exafs.h"
#include "exafs_inode.h"
#include "exafs_meta.h"
#include "exafs_util.h"

#ifndef DEBUG
#define DEBUG 0
#endif

#if DEBUG
#include <emscripten.h>
#else
#define emscripten_log(...)
#endif

int exafs_init(struct exafs_ctx * ctx, struct exafs_cfg * cfg) {

  ctx->active_superblock = -1;
  ctx->meta_log_head = EXAFS_NB_SUPERBLOCKS;
  ctx->meta_log_tail = EXAFS_NB_SUPERBLOCKS;
  ctx->meta_log_seq = 0;
  ctx->next_ino = 0;
  
  ctx->inode_table = NULL;

  ctx->clean_repo = cfg->clean_repo;
  ctx->read = cfg->read;
  ctx->read_range = cfg->read_range;
  ctx->write = cfg->write;
  ctx->write_range = cfg->write_range;
  ctx->write_rand = cfg->write_rand;
  ctx->delete = cfg->delete;
  ctx->delete_range = cfg->delete_range;
  ctx->delete_set = cfg->delete_set;

  if (cfg->meta_log_size > 0) {

    ctx->meta_log_size = cfg->meta_log_size;
  }
  else {
    ctx->meta_log_size = META_LOG_SIZE;
  }

  if (cfg->grp_size > 0) {
    ctx->grp_size = cfg->grp_size;
  }
  else {
    ctx->grp_size = GRP_SIZE;
  }

  if (cfg->snapshot_size > 0) {
    ctx->snapshot_size = cfg->snapshot_size;
  }
  else {
    ctx->snapshot_size = SNAPSHOT_SIZE;
  }

  if ( (ctx->clean_repo == NULL) || (ctx->read == NULL) || (ctx->read_range == NULL) || (ctx->write == NULL) || (ctx->write_range == NULL) || (ctx->write_rand == NULL) || (ctx->delete == NULL) || (ctx->delete_range == NULL) ) {
    return -1;
  }

  ctx->snapshot_aborted = 0;
  
  return 0;
}

int exafs_mount(struct exafs_ctx * ctx, struct exafs_cfg * cfg) {
  
  emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_mount");
  
  // Initialize ctx structure
  
  if (exafs_init(ctx, cfg) < 0) {

    return -1;
  }

  // Read superblocks

  //TODO use read_range

  for (int i=0; i < EXAFS_NB_SUPERBLOCKS; i++) {

    int len = ctx->read(ctx, i, &(ctx->superblocks[i]), sizeof(struct superblock), 0);

    emscripten_log(EM_LOG_CONSOLE, "exafs: read block %d -> %d bytes", i, len);

    if (len < sizeof(struct superblock)) {
      
      ctx->superblocks[i].generation = 0;
    }
    else {

      uint32_t crc = exafs_crc(&(ctx->superblocks[i]), sizeof(struct superblock) - sizeof(uint32_t), 0);
      
      emscripten_log(EM_LOG_CONSOLE, "exafs: read block %d -> magic=%s generation=%lld crc=%x (computed crc=%x)", i, ctx->superblocks[i].magic, ctx->superblocks[i].generation, ctx->superblocks[i].crc, crc);

      if (crc != ctx->superblocks[i].crc) {
	
	ctx->superblocks[i].generation = 0;
      }
    }
  }

  int active_superblock_generation = 0;

  for (int i=0; i < EXAFS_NB_SUPERBLOCKS; i++) {

    if (ctx->superblocks[i].generation > active_superblock_generation) {
      
      active_superblock_generation = ctx->superblocks[i].generation;
      ctx->active_superblock = i;
    }
  }
  
  if (ctx->active_superblock < 0) {

    emscripten_log(EM_LOG_CONSOLE, "exafs: <-- exafs_mount: error (no active superblock)");
    
    return -1;
  }

  ctx->meta_log_size = ctx->superblocks[ctx->active_superblock].meta_log_size;
  ctx->meta_log_head = ctx->superblocks[ctx->active_superblock].meta_log_head;
  ctx->meta_log_tail = ctx->superblocks[ctx->active_superblock].meta_log_tail;
  ctx->meta_log_seq = ctx->superblocks[ctx->active_superblock].meta_log_seq;
  ctx->snapshot_size = ctx->superblocks[ctx->active_superblock].snapshot_size;
  ctx->grp_size = ctx->superblocks[ctx->active_superblock].grp_size;
  ctx->next_ino = ctx->superblocks[ctx->active_superblock].next_ino;

  emscripten_log(EM_LOG_CONSOLE, "exafs: exafs_mount: active_superblock=%d generation %lld log_size=%d log_head=%d log_tail=%d log_seq=%lld snapshot_size=%d grp_size=%d next_ino=%d", ctx->active_superblock, ctx->superblocks[ctx->active_superblock].generation, ctx->meta_log_size, ctx->meta_log_head, ctx->meta_log_tail, ctx->meta_log_seq, ctx->snapshot_size, ctx->grp_size, ctx->next_ino);

  ctx->delete_obj = 0;

  if (ctx->meta_log_tail < ctx->meta_log_head) {

    // We need to erase objects between snapshot tail and head and all deleted obj
    
    ctx->delete_obj = 1;
  }
  
  // Read metadata logs by group of (ctx->meta_log_size/10)

  int buf_len = ctx->meta_log_size*10;
  char * buf = malloc(buf_len);

  for (int i=ctx->meta_log_head; i < EXAFS_NB_SUPERBLOCKS+ctx->meta_log_size; i+= (ctx->meta_log_size/10)) {

    uint32_t last_obj;

    // Read at maximum (ctx->meta_log_size/10) objects
  
    int size = ctx->read_range(ctx, i, i+(ctx->meta_log_size/10)-1, buf, buf_len, &last_obj);
    
    if (size <= 0) {
      break;
    }

    emscripten_log(EM_LOG_CONSOLE, "exafs: read_range: %d -> %d: size=%d", i, last_obj, size);

    // Replay them

    ctx->meta_log_seq = exafs_meta_replay(ctx, buf, size);

    if (ctx->delete_obj > 1) {

      // Snapshot has been finalized with object deletion
      // (ctx->delete_obj + 1) points to the new tail/head

      time_t now = time(NULL);

      ctx->meta_log_tail = ctx->delete_obj + 1;
      ctx->meta_log_head = ctx->meta_log_tail;

      int next = (ctx->active_superblock+1)%EXAFS_NB_SUPERBLOCKS;
      int next2 = (next+1)%EXAFS_NB_SUPERBLOCKS;
  
      // Write snapshot twice
      
      exafs_write_superblock(ctx, next, now);
      exafs_write_superblock(ctx, next2, now);

      // TODO: and then ?
    }
    
    ctx->meta_log_seq++;
    
    ctx->meta_log_head = last_obj+1;

    if (last_obj < (i+(ctx->meta_log_size/10)-1)) { // we read less objects so there is no more object to read
      break;
    }
  }
  
  free(buf);
  
  if (ctx->snapshot_aborted) { // Snapshot has been aborted, add a flag for continuing 

    // Objects written during aborted snapshot have to be deleted
  }
  
  emscripten_log(EM_LOG_CONSOLE, "exafs: <-- exafs_mount: success (active superblock %d generation %lld)", ctx->active_superblock, ctx->superblocks[ctx->active_superblock].generation);
  
  return 0;
}

int exafs_unmount(struct exafs_ctx * ctx) {

  emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_unmount");

  exafs_create_snapshot(ctx);
  
  return 0;
}

int exafs_write_superblock(struct exafs_ctx * ctx, int index, uint64_t now) {

  memset(&(ctx->superblocks[index]), 0, sizeof(struct superblock));
  
  strcpy(ctx->superblocks[index].magic, "EXAEQUO");
  ctx->superblocks[index].generation = now;
  ctx->superblocks[index].meta_log_size = ctx->meta_log_size;
  ctx->superblocks[index].meta_log_head = ctx->meta_log_head;
  ctx->superblocks[index].meta_log_tail = ctx->meta_log_tail;
  ctx->superblocks[index].meta_log_seq = ctx->meta_log_seq;
  ctx->superblocks[index].snapshot_size = ctx->snapshot_size;
  ctx->superblocks[index].grp_size = ctx->grp_size;
  ctx->superblocks[index].next_ino = ctx->next_ino;
  ctx->superblocks[index].crc = exafs_crc(&(ctx->superblocks[index]), sizeof(struct superblock) - sizeof(uint32_t), 0);
  
  int len = ctx->write(ctx, index, &(ctx->superblocks[index]), sizeof(struct superblock));
  
  return len;
}

int exafs_format(struct exafs_ctx * ctx, struct exafs_cfg * cfg) {

  emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_format");
  
  // Initialize ctx structure
  
  if (exafs_init(ctx, cfg) < 0) {

    return -1;
  }
  
  int res = -1;

  // Delete all objects of the repo
  
  ctx->clean_repo(ctx, "home"); // TODO: configure repo name

  time_t now = time(NULL);
  
  // Write superblock in all the slots
  
  for (int i=0; i < EXAFS_NB_SUPERBLOCKS; i++) {

    int len = exafs_write_superblock(ctx, i, 1); // time=1 for recording all newly created inodes 
    
    if (len == sizeof(struct superblock)) {

      res = 0; // at least one block is successfully written, so it is ok

      if (ctx->active_superblock < 0) {
	
	ctx->active_superblock = i; // active superblock is the first with successful writing
      }
    }
  }
  
  // Delete all objects belonging to metadata log
  //ctx->delete_range(ctx, EXAFS_NB_SUPERBLOCKS, EXAFS_NB_SUPERBLOCKS+ctx->meta_log_size);
  
  // Read first metadata log object to check if it has really been deleted
  
  uint32_t tmp;
  
  int len = ctx->read(ctx, EXAFS_NB_SUPERBLOCKS, &tmp, sizeof(tmp), 0);
  
  emscripten_log(EM_LOG_CONSOLE, "exafs: reading deleted object -> len=%d", len);

  if (len != -1) {

    return -1;
  }
  
  // Metadata log seq is reset
  ctx->meta_log_seq = 1;
  
  // Inode seq is reset
  ctx->next_ino = EXAFS_START_INO;

  exafs_mknod_at2(ctx, 0, EXAFS_ROOT_INO, S_IFDIR | S_IRWXU, "/");
  
  emscripten_log(EM_LOG_CONSOLE, "exafs: <-- exafs_format: res=%d", res);
  
  return res;
}

uint32_t exafs_mkdir(struct exafs_ctx * ctx, uint32_t mode, const char * path) {

  emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_mkdir: path=%s", path);

  return exafs_mknod(ctx, mode | S_IFDIR,  path);
}

uint32_t exafs_mknod_at2(struct exafs_ctx * ctx, uint32_t parent_ino, uint32_t child_ino, uint32_t mode, const char * path) {
  
  emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_mknod_at2: parent_ino=%d child_ino=%d path=%s", parent_ino, child_ino, path);
    
  if (exafs_inode_get_entry(ctx, parent_ino, path)) {

    emscripten_log(EM_LOG_CONSOLE, "exafs: <-- exafs_mknod_at2: error, path %s already exists", path);

    return 0;
  }

  time_t now = time(NULL);

  emscripten_log(EM_LOG_CONSOLE, "exafs: time=%lld (%d)", now, sizeof(time_t));
  
  char * recordset = (char *)malloc(4096);

  int recordset_length = exafs_inode_record(ctx, child_ino, mode, now, recordset); // inode for subdir

  if (parent_ino) { // root has no parent
    
    recordset_length += exafs_inode_link_record(ctx, parent_ino, child_ino, path, now, recordset+recordset_length);
  }

  if (parent_ino) {

    struct stat stat;
    uint32_t parent_nlink;
    
    exafs_inode_stat(ctx, parent_ino, &stat);

    if (mode & S_IFDIR) {

      parent_nlink = stat.st_nlink+1;
    
      recordset_length += exafs_inode_set_nlink_record(ctx, parent_ino, parent_nlink, now, recordset+recordset_length); // '..' points to parent
    }

    uint64_t parent_size = stat.st_size + PATHNAME_LEN_MAX+sizeof(uint32_t); // path + ino

    recordset_length += exafs_inode_set_size_record(ctx, parent_ino, parent_size, now, recordset+recordset_length);

    recordset_length += exafs_inode_set_mtime_record(ctx, parent_ino, now, recordset+recordset_length);
  }

  uint32_t child_nlink = 1;

  if (mode & S_IFDIR) {
    
    child_nlink++; // in case of dir, '.' also points to it
  }
  
  recordset_length += exafs_inode_set_nlink_record(ctx, child_ino, child_nlink, now, recordset+recordset_length);

  if (mode & S_IFDIR) {

    recordset_length += exafs_inode_link_record(ctx, child_ino, child_ino, ".", now, recordset+recordset_length);

    uint32_t top_ino = (parent_ino)?parent_ino:child_ino; // For handling case of root

    recordset_length += exafs_inode_link_record(ctx, child_ino, top_ino, "..", now, recordset+recordset_length);
  
    recordset_length += exafs_inode_set_size_record(ctx, child_ino, 2*(PATHNAME_LEN_MAX+sizeof(uint32_t)), now, recordset+recordset_length);
  }

  int err = exafs_meta_store(ctx, recordset, recordset_length);
  
  if (!err) {

    uint64_t seq = exafs_meta_replay(ctx, recordset, recordset_length);

    if (seq == 0) {

      err = -1;
    }
    else {
      ctx->meta_log_seq = seq+1;
    }
  }

  free(recordset);

  emscripten_log(EM_LOG_CONSOLE, "exafs: <-- exafs_mkdir_at2: err=%d", err);

  if (err < 0) {
    
    return 0;
  }
  
  return child_ino; 
}

uint32_t exafs_mknod_at(struct exafs_ctx * ctx, uint32_t parent_ino, uint32_t mode, const char * path) {
 
  emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_mknod_at: parent_ino=%d mode=%x path=%s", parent_ino, mode, path);

  uint32_t ino = exafs_mknod_at2(ctx, parent_ino, ctx->next_ino, mode, path);

  if (!ino) {

    return 0;
  }
  
  return ino;
}

uint32_t exafs_mknod(struct exafs_ctx * ctx,  uint32_t mode, const char * path) {

  emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_mknod: mode=%x path=%s", mode, path);

  char * leaf = strrchr(path, '/');

  if (!leaf) {

    return 0;
  }

  uint32_t ino = exafs_inode_find_n(ctx, path, leaf-path/*, flags & O_NOFOLLOW*/);

  if (!ino) {

    return 0;
  }

  return exafs_mknod_at(ctx, ino, mode, leaf+1);
}

uint32_t exafs_mkdir_at(struct exafs_ctx * ctx, uint32_t parent_ino, uint32_t mode, const char * path) {
  
  uint32_t ino = exafs_mknod_at(ctx, parent_ino, mode | S_IFDIR,  path);

  if (!ino) {

    return 0;
  }
  
  return ino;
}

int exafs_unlink(struct exafs_ctx * ctx, const char * path) {

  if (!path) {

    return ENOENT;
  }

  emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_inode_find: path=%s", path);

  if (path[0] != '/') { // path shall start by '/'

    return ENOENT;
  }

  if (strcmp(path, "/") == 0) {

    return ENOENT;
  }

  char * leaf = strrchr(path, '/');

  uint32_t ino = exafs_inode_find_n(ctx, path, (leaf == path)?1:leaf-path);

  if (!ino) {
    return ENOENT;
  }
  
  struct exafs_dir_entry * e = exafs_inode_get_entry(ctx, ino, leaf+1);

  if (!e) {
    return ENOENT;
  }

  struct stat stat, stat_child;
    
  exafs_inode_stat(ctx, ino, &stat);
  exafs_inode_stat(ctx, e->ino, &stat_child);

  if (stat_child.st_mode & S_IFDIR) {
    
    return EISDIR;
  }
  
  char * recordset = (char *)malloc(4096);

  time_t now = time(NULL);
  
  int recordset_length = exafs_inode_unlink_record(ctx, ino, leaf+1, now, recordset);
  
  recordset_length += exafs_inode_set_size_record(ctx, ino, stat.st_size-(PATHNAME_LEN_MAX+sizeof(uint32_t)), now, recordset+recordset_length);
  
  recordset_length += exafs_inode_set_mtime_record(ctx, ino, now, recordset+recordset_length);

  uint32_t nlink = stat_child.st_nlink-1;
  
  recordset_length += exafs_inode_set_nlink_record(ctx, stat_child.st_ino, nlink, now, recordset+recordset_length);
  
  recordset_length += exafs_inode_set_ctime_record(ctx, stat_child.st_ino, now, recordset+recordset_length);
  
  int err = exafs_meta_store(ctx, recordset, recordset_length);
  
  if (!err) {

    uint64_t seq = exafs_meta_replay(ctx, recordset, recordset_length);

    if (seq == 0) {

      err = ENOMEM;
    }
    else {
      ctx->meta_log_seq = seq+1;
    }
  }
  else {

    err = ENOMEM;
  }

  free(recordset);

  return err;
}

int exafs_rename(struct exafs_ctx * ctx, const char * oldpath, const char * newpath) {

  if (!oldpath || !newpath) {

    return EINVAL;
  }

  emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_rename: oldpath=%s newpath=%s", oldpath, newpath);

  char * old_leaf = strrchr(oldpath, '/');

  uint32_t old_ino = exafs_inode_find_n(ctx, oldpath, (old_leaf == oldpath)?1:old_leaf-oldpath);

  if (!old_ino) {
    return ENOENT;
  }

  emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_rename: old_ino=%d", old_ino);

  char * new_leaf = strrchr(newpath, '/');
  
  uint32_t new_ino = exafs_inode_find_n(ctx, newpath, (new_leaf == newpath)?1:new_leaf-newpath);

  if (!new_ino) {
    return ENOENT;
  }
  
  emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_rename: new_ino=%d", new_ino);

  struct exafs_dir_entry * old_e = exafs_inode_get_entry(ctx, old_ino, old_leaf+1);

  if (!old_e) {
    return ENOENT;
  }

  struct exafs_dir_entry * new_e = exafs_inode_get_entry(ctx, new_ino, new_leaf+1);

  struct stat old_stat;
    
  exafs_inode_stat(ctx, old_e->ino, &old_stat);

  if (new_e) {

    emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_rename: newpath exists");

    if (old_e->ino == new_e->ino) {

      // oldpath and newpath point to same file/directory -> do nothing
      return 0;
    }
    else {

      struct stat new_stat;
      
      exafs_inode_stat(ctx, new_e->ino, &new_stat);
      
      if (new_stat.st_mode & S_IFDIR) { // Destination is a directory

	if (old_stat.st_mode & S_IFREG) {

	  // Cannot transform a file into a dir
	
	  return EISDIR;
	}
	else {

	  uint32_t nb_entries = exafs_inode_get_nb_entries(ctx, new_e->ino);

	  if ( (nb_entries == 2) && (strcmp(new_leaf+1, ".")) && (strcmp(new_leaf+1, "..")) ) {

	    // new path is an empty dir so it can replace old path

	    char * recordset = (char *)malloc(4096);

	    time_t now = time(NULL);

	    int recordset_length = exafs_inode_unlink_record(ctx, new_ino, new_leaf+1, now, recordset);

	    // And . and .. ??
	    
	    recordset_length += exafs_inode_link_record(ctx, new_ino, old_e->ino, new_leaf+1, now, recordset+recordset_length);

	    if  (new_ino != old_ino) {
	      recordset_length += exafs_inode_link_record(ctx, old_e->ino, new_ino, "..", now, recordset+recordset_length);
	    }
	    
	    recordset_length += exafs_inode_unlink_record(ctx, old_ino, old_leaf+1, now, recordset+recordset_length);

	    recordset_length += exafs_inode_set_ctime_record(ctx, old_e->ino, now, recordset+recordset_length);

	    recordset_length += exafs_inode_set_mtime_record(ctx, old_ino, now, recordset+recordset_length);

	    //TODO: update size

	    if (new_ino != old_ino) {
	      recordset_length += exafs_inode_set_mtime_record(ctx, new_ino, now, recordset+recordset_length);
	    }
	    
	    int err = exafs_meta_store(ctx, recordset, recordset_length);
  
	    if (!err) {

	      uint64_t seq = exafs_meta_replay(ctx, recordset, recordset_length);

	      if (seq == 0) {

		err = -1;
	      }
	      else {
		ctx->meta_log_seq = seq+1;
	      }
	    }
	    
	    free(recordset);

	    return 0;
	    
	  }
	  else {

	    return ENOTEMPTY;
	  }
	}
      }
      else { // Destination is a file

	if (old_stat.st_mode & S_IFDIR) {

	  // Cannot transform a dir into a file
	
	  return ENOTDIR;
	}
	else {

	  char * recordset = (char *)malloc(4096);

	  time_t now = time(NULL);

	  int recordset_length = exafs_inode_unlink_record(ctx, new_ino, new_leaf+1, now, recordset);

	  recordset_length += exafs_inode_link_record(ctx, new_ino, old_e->ino, new_leaf+1, now, recordset+recordset_length);

	  recordset_length += exafs_inode_unlink_record(ctx, old_ino, old_leaf+1, now, recordset+recordset_length);

	  recordset_length += exafs_inode_set_ctime_record(ctx, old_e->ino, now, recordset+recordset_length);

	  recordset_length += exafs_inode_set_mtime_record(ctx, old_ino, now, recordset+recordset_length);

	  if (new_ino != old_ino) {
	    recordset_length += exafs_inode_set_mtime_record(ctx, new_ino, now, recordset+recordset_length);
	  }

	  //TODO: update size

	  int err = exafs_meta_store(ctx, recordset, recordset_length);
  
	  if (!err) {

	    uint64_t seq = exafs_meta_replay(ctx, recordset, recordset_length);

	    if (seq == 0) {

	      err = -1;
	    }
	    else {
	      ctx->meta_log_seq = seq+1;
	    }
	    
	  }
	    
	  free(recordset);

	  return 0;
	}
      }
    }
  }
  else {

    emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_rename: newpath does not existx");

    char * recordset = (char *)malloc(4096);

    time_t now = time(NULL);

    int recordset_length = exafs_inode_link_record(ctx, new_ino, old_e->ino, new_leaf+1, now, recordset);

    if ( (old_stat.st_mode & S_IFDIR) && (new_ino != old_ino) ) {

      recordset_length += exafs_inode_link_record(ctx, old_e->ino, new_ino, "..", now, recordset+recordset_length);
    }

    recordset_length += exafs_inode_unlink_record(ctx, old_ino, old_leaf+1, now, recordset+recordset_length);

    recordset_length += exafs_inode_set_ctime_record(ctx, old_e->ino, now, recordset+recordset_length);

    recordset_length += exafs_inode_set_mtime_record(ctx, old_ino, now, recordset+recordset_length);
    
    if (new_ino != old_ino) {
      recordset_length += exafs_inode_set_mtime_record(ctx, new_ino, now, recordset+recordset_length);
    }

    //TODO: update size
    
    int err = exafs_meta_store(ctx, recordset, recordset_length);
  
    if (!err) {

      uint64_t seq = exafs_meta_replay(ctx, recordset, recordset_length);

      if (seq == 0) {

	err = -1;
      }
      else {
	ctx->meta_log_seq = seq+1;
      }
    }
	    
    free(recordset);

    return 0;
  }
  
  return 0;
}

int exafs_rmdir(struct exafs_ctx * ctx, const char * path) {

  if (!path) {

    return EINVAL;
  }

  emscripten_log(EM_LOG_CONSOLE, "exafs: --> exafs_rmdir: path=%s", path);

  char * leaf = strrchr(path, '/');

  uint32_t ino = exafs_inode_find_n(ctx, path, (leaf == path)?1:leaf-path);
  
  if (!ino) {
    return ENOENT;
  }

  if ( (strcmp(leaf+1, ".") == 0) || (strcmp(leaf+1, "..") == 0) ) {

    return EINVAL;
  }

  struct exafs_dir_entry * e = exafs_inode_get_entry(ctx, ino, leaf+1);

  if (!e) {

    return ENOENT;
  }

  struct stat stat;
  
  exafs_inode_stat(ctx, e->ino, &stat);

  if (!(stat.st_mode & S_IFDIR)) {
    
    return ENOTDIR;
  }

  if (exafs_inode_get_nb_entries(ctx, e->ino) > 2) {

    return ENOTEMPTY;
  }

  struct stat parent_stat;
  
  exafs_inode_stat(ctx, ino, &parent_stat);

  char * recordset = (char *)malloc(4096);
  
  time_t now = time(NULL);
  
  int recordset_length = exafs_inode_unlink_record(ctx, ino, leaf+1, now, recordset);
  
  recordset_length += exafs_inode_set_size_record(ctx, ino, parent_stat.st_size-(PATHNAME_LEN_MAX+sizeof(uint32_t)), now, recordset+recordset_length);
  
  recordset_length += exafs_inode_set_mtime_record(ctx, ino, now, recordset+recordset_length);

  recordset_length += exafs_inode_set_nlink_record(ctx, e->ino, 0, now, recordset+recordset_length);

  recordset_length += exafs_inode_set_ctime_record(ctx, e->ino, now, recordset+recordset_length);
  
  int err = exafs_meta_store(ctx, recordset, recordset_length);
  
  if (!err) {

    uint64_t seq = exafs_meta_replay(ctx, recordset, recordset_length);
    
    if (seq == 0) {

      err = ENOMEM;
    }
    else {
      ctx->meta_log_seq = seq+1;
    }
  }
  else {

    err = ENOMEM;
  }

  free(recordset);

  return err;
}

int exafs_ftruncate(struct exafs_ctx * ctx, uint32_t ino, uint64_t length) {

  char * recordset = (char *)malloc(4096);
  
  time_t now = time(NULL);

  int recordset_length = exafs_inode_set_size_record(ctx, ino, length, now, recordset);
  
  recordset_length += exafs_inode_set_mtime_record(ctx, ino, now, recordset+recordset_length);
  recordset_length += exafs_inode_set_ctime_record(ctx, ino, now, recordset+recordset_length);

  int err = exafs_meta_store(ctx, recordset, recordset_length);
  
  if (!err) {

    uint64_t seq = exafs_meta_replay(ctx, recordset, recordset_length);
    
    if (seq == 0) {

      err = ENOMEM;
    }
    else {
      ctx->meta_log_seq = seq+1;
    }
  }
  else {

    err = ENOMEM;
  }

  free(recordset);

  return err;
}

int exafs_snapshot_record(struct exafs_ctx * ctx, time_t now, char * ptr) {

  int record_size = 0;

  int header_len = exafs_record_header(ctx, EXAFS_OP_SNAPSHOT, now, record_size, (struct meta_record *)ptr);
  
  int crc_len = exafs_record_crc((struct meta_record *)ptr);
  
  return header_len+record_size+crc_len;
}

int exafs_snapshot_end_record(struct exafs_ctx * ctx, uint32_t erase_start, uint32_t erase_end, uint32_t obj, time_t now, char * ptr) {

  int record_size = sizeof(struct exafs_snap_end_meta);

  int header_len = exafs_record_header(ctx, EXAFS_OP_SNAPSHOT_END, now, record_size, (struct meta_record *)ptr);

  struct exafs_snap_end_meta * snap_end = (struct exafs_snap_end_meta *)(ptr+header_len);

  snap_end->erase_start = erase_start;
  snap_end->erase_end = erase_end;
  snap_end->obj = obj;
  
  int crc_len = exafs_record_crc((struct meta_record *)ptr);
  
  return header_len+record_size+crc_len;
}

int exafs_create_snapshot(struct exafs_ctx * ctx) {

  time_t now = time(NULL);

  char * recordset = (char *)malloc(1024);
  
  // Objects between ctx->meta_log_tail and erase_end, included, need to be erased once snapshot is done
  
  uint32_t erase_end = ctx->meta_log_head - 1;
  
  int recordset_length = exafs_snapshot_record(ctx, now, recordset);
  
  int err = exafs_meta_store(ctx, recordset, recordset_length);

  if (err < 0) {

    free(recordset);
    
    return -1;
  }
  
  // Sort inodes by ino
  exafs_inode_sort(ctx);
  
  // Snap all inodes
  exafs_inode_snap(ctx, now);
  
  recordset_length = exafs_snapshot_end_record(ctx, ctx->meta_log_tail, erase_end, ctx->meta_log_head, now, recordset);
  
  err = exafs_meta_store(ctx, recordset, recordset_length);
  
  free(recordset);
  
  if (err < 0) {

    return -1;
  }

  ctx->meta_log_tail = erase_end + 1;

  // Records between meta_log_tail and (meta_log_head - 1) will be handled (objects erased) while doing next snapshot
  
  int next = (ctx->active_superblock+1)%EXAFS_NB_SUPERBLOCKS;
  int next2 = (next+1)%EXAFS_NB_SUPERBLOCKS;
  
  // Write snapshot twice
  
  exafs_write_superblock(ctx, next, now);
  exafs_write_superblock(ctx, next2, now);
}
