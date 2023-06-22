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

#ifndef _VFS_H
#define _VFS_H

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>

enum vnode_type {

  VDIR = 0,
  VFILE,
  VSYMLINK,
  VDEV,
  VMOUNT
};

struct vnode {
  
  struct vnode * parent;
  
  enum vnode_type type;
  char name[FILENAME_MAX];
  
  union {
    struct {
      struct vnode * vnode;
      unsigned char * symlink;
    } link;
    struct {
      unsigned char * buffer;
      size_t buffer_size;
      size_t file_size;
    } file;
    struct {
      struct vnode * vnode;  /* Used for memorizing children when a node switches from VDIR to VMOUNT (mount) and vice versa (umount) */
      unsigned char type;
      unsigned short major;
      unsigned short minor;
      char peer[108];
    } dev;
  } _u;
  
  struct vnode * next;
};

void vfs_set_debug(char enable);

int vfs_init();

struct vnode * vfs_add_node(struct vnode * parent, enum vnode_type type, const char * name);

struct vnode * vfs_add_file(struct vnode * parent, const char * name);
struct vnode * vfs_add_dir(struct vnode * parent, const char * name);
struct vnode * vfs_add_symlink(struct vnode * parent, const char * name, const char * symlink, struct vnode * link);
struct vnode * vfs_add_dev(struct vnode * parent, const char * name, unsigned char type, unsigned short major, unsigned short minor);

int vfs_del_node(struct vnode * node);
int vfs_del_tree(struct vnode * node);

int vfs_set_mount(struct vnode * node, unsigned char type, unsigned short major, unsigned short minor);

struct vnode * vfs_add_path(const char * pathname);

struct vnode * vfs_find_node(const char * pathname, char ** trail);

int vfs_get_path(struct vnode * vnode, char * new_dir); 

struct vnode * vfs_create_file(const char * pathname);

int vfs_open(const char * pathname, int flags, mode_t mode, pid_t pid, unsigned short minor);

struct vnode * vfs_get_vnode(int fd);
const char * vfs_get_pathname(int fd);

int vfs_close(int fd);
ssize_t vfs_write(int fd, const void * buf, size_t len);
ssize_t vfs_read(int fd, void * buf, size_t len);

ssize_t vfs_getdents(int fd, void * buf, size_t len);

int vfs_ioctl(int fd, int op);

int vfs_stat(const char * pathname, struct stat * buf, struct vnode ** vnode, char ** trail);
int vfs_lstat(const char * pathname, struct stat * buf, struct vnode ** vnode, char ** trail);
int vfs_fstat(int fd, struct stat * stat_buf);

int vfs_seek(int fd, int offset, int whence);

int vfs_unlink(struct vnode * vnode);

int vfs_set_fs_flags(int fd, int flags);

void vfs_dump();


#endif // _VFS_H
