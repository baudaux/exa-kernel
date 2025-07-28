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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

#include <sys/sysmacros.h>

#include <errno.h>

#ifndef DEBUG
#define DEBUG 0
#endif

#if DEBUG
#include <emscripten.h>
#else
#define emscripten_log(...)
#endif

#include "vfs.h"



#define NB_FD_MAX 128

static char vfs_debug = 0;
		
static struct vnode * vfs_root;

struct fd_entry {

  int fd;
  pid_t pid;
  unsigned short minor;
  char pathname[1024];
  int flags;
  unsigned short mode;
  unsigned int offset;
  struct vnode * vnode;
  int unlink_pending;
};

// keep 0 for latest open of dev type is dev or mount

static int last_fd = 0;

static struct fd_entry fds[NB_FD_MAX];

void vfs_set_debug(char enable) {

  vfs_debug = enable; 
}

int vfs_init() {

  vfs_root = NULL;

  vfs_root = vfs_add_dir(NULL, "/");

  for (int i = 0; i < NB_FD_MAX; ++i) {
    
    fds[i].fd = -1;
  }
    
  return 0;
}

struct vnode * vfs_add_node(struct vnode * parent, enum vnode_type type, const char * name) {

  emscripten_log(EM_LOG_CONSOLE, "vfs_add_node: parent=%p type=%d name=%s", parent, type, name);

  if (!parent && (type != VDIR))
    return NULL;

  if (parent)
    emscripten_log(EM_LOG_CONSOLE, "vfs_add_node: parent->name=%s parent->type=%d", parent->name, parent->type);

  if (parent && parent->type != VDIR)
    return NULL;
  
  struct vnode ** vnode_p = NULL;
  
  if (parent) {

    if (!parent->_u.link.vnode) {
      vnode_p = &parent->_u.link.vnode;
    }
    else {
      struct vnode * p = parent->_u.link.vnode;
      
      if ( (p->linked) && (strcmp(p->name, name) == 0) )
	return NULL;

      while (p->next) {
	
	p = p->next;

	if ( (p->linked) && (strcmp(p->name, name) == 0) )
	  return NULL;
      }

      vnode_p = &(p->next);
    }
  }

  struct vnode * n = (struct vnode *) malloc(sizeof(struct vnode));
  
  if (!n)
    return NULL;

  n->parent = parent;
  n->type = type;

  strcpy(n->name, name);
  
  if (name[0] == 0)
    n->linked = 0;
  else
    n->linked = 1;
  
  n->next = NULL;

  if (vnode_p)
    *vnode_p = n;
  
  return n;
}

struct vnode * vfs_add_file(struct vnode * parent, const char * name) {

  struct vnode * vn = vfs_add_node(parent, VFILE, name);

  if (!vn)
    return NULL;

  vn->_u.file.buffer = NULL;
  vn->_u.file.buffer_size = 0;
  vn->_u.file.file_size = 0;

  return vn;
}

struct vnode * vfs_add_dir(struct vnode * parent, const char * name) {

  struct vnode * vn = vfs_add_node(parent, VDIR, name);

  if (!vn)
    return NULL;

  vn->_u.link.vnode = NULL;
  vn->_u.link.symlink = NULL;

  struct vnode * curr = vfs_add_symlink(vn, ".", NULL, vn);

  struct vnode * n = (parent)?parent:vn;

  struct vnode * prev = vfs_add_symlink(vn, "..", NULL, n);

  return vn;
}

struct vnode * vfs_add_symlink(struct vnode * parent, const char * name, const char * symlink, struct vnode * link) {

  struct vnode * vn = vfs_add_node(parent, VSYMLINK, name);

  if (!vn)
    return NULL;

  if (symlink)
    vn->_u.link.symlink = (unsigned char *) strdup(symlink);
  else {
    vn->_u.link.symlink = NULL;
  }

  vn->_u.link.vnode = link;

  return vn;
}

struct vnode * vfs_add_dev(struct vnode * parent, const char * name, unsigned char type, unsigned short major, unsigned short minor) {

  struct vnode * vn = vfs_add_node(parent, VDEV, name);

  if (!vn)
    return NULL;

  vn->_u.dev.type = type;
  vn->_u.dev.major = major;
  vn->_u.dev.minor = minor;

  return vn;
}

int vfs_del_node(struct vnode * node) {

  if (!node)
    return -1;
  
  if ( (node->type == VDIR) && (node->_u.link.vnode) ) {

    return -1;
  }

  if (!node->parent)
    return -1;

  struct vnode * n = node->parent->_u.link.vnode;

  if (n == node) {

    node->parent->_u.link.vnode = node->next;
  }
  else {

    while (n->next != node) {

      n = n->next;
    }

    n->next = node->next;
  }

  switch(node->type) {

  case VDIR:
    break;
  case VFILE:
    if (node->_u.file.buffer)
      free(node->_u.file.buffer);
    break;
  case VSYMLINK:
    if (node->_u.link.symlink)
      free(node->_u.link.symlink);
    break;
  case VDEV:
    break;
  case VMOUNT:
    break;
  default:
    break;
  }

  free(node);

  return 0;
}

int vfs_del_tree(struct vnode * node) {

  if (!node)
    return -1;

  if (node->type == VDIR) {

    struct vnode * n = node->_u.link.vnode;

    while (n) {
      
      struct vnode * n2 = n->next;

      vfs_del_tree(n);

      n = n2;
    }

    n->next = node->next;
  }
  
  vfs_del_node(node);
  
  return 0;
}

int vfs_rm_dir(struct vnode * node) {

  if (!node || (node->type != VDIR))
    return -1;

  struct vnode * n = node->_u.link.vnode;

  int not_empty = 0;

  while (n) {

    if ( (n->type != VSYMLINK) || (strcmp(n->name, ".") && strcmp(n->name, "..")) ) {

      emscripten_log(EM_LOG_CONSOLE, "vfs_rm_dir: child node %d %s", n->type, n->name);
      
      not_empty = 1;
      break;
    }

    n = n->next;
  }

  emscripten_log(EM_LOG_CONSOLE, "vfs_rm_dir: not_empty=%d", not_empty);

  if (!not_empty) {

    struct vnode * n = node->_u.link.vnode;

    while (n) {

      struct vnode * next = n->next;

      vfs_del_node(n);

      n = next;
    }

    node->_u.link.vnode = NULL;

    return vfs_del_node(node);
  }
      
  return -1;
}

int vfs_set_mount(struct vnode * node, unsigned char type, unsigned short major, unsigned short minor) {

  node->type = VMOUNT;

  node->_u.dev.type = type;
  node->_u.dev.major = major;
  node->_u.dev.minor = minor;
    
  return 0;
}

struct vnode * vfs_add_path(const char * pathname) {

  //TODO
  return NULL;
}

struct vnode * vfs_find_node_in_subnodes(struct vnode * vnode, const char * pathname, char ** trail) {

  struct vnode * prev_node;
  const char * path = pathname;

  if (vfs_debug)
    emscripten_log(EM_LOG_CONSOLE, "*** vfs_find_node_in_subnodes: %s %s (%d)", vnode->name, pathname, strlen(pathname));

  while (vnode) {

    if (vfs_debug)
      emscripten_log(EM_LOG_CONSOLE, "vfs_find_node_in_subnodes: %s (%d) == %s ?", vnode->name, strlen(vnode->name), path);

    if (strncmp(vnode->name, path, strlen(vnode->name)) == 0) {

      if (vfs_debug)
	emscripten_log(EM_LOG_CONSOLE, "vfs_find_node_in_subnodes: same name %d %d",strlen(path),strlen(vnode->name));

      if (strlen(path) == strlen(vnode->name)) {

	if (vfs_debug)
	  emscripten_log(EM_LOG_CONSOLE, "vfs_find_node_in_subnodes: found");

	if (vnode->type == VSYMLINK) {

	  if (vfs_debug)
	    emscripten_log(EM_LOG_CONSOLE, "vfs_find_node_in_subnodes: VSYMLINK 2 : %s", path);
	  
	  if (vnode->_u.link.vnode)
	    vnode = vnode->_u.link.vnode;
	}
	
	return vnode;
      }

      if ( (path[strlen(vnode->name)] == '/') || (strcmp(vnode->name, "/") == 0) ) {

	if (vnode->type == VDIR) {

	  path += strlen(vnode->name);
      
	  if (strcmp(vnode->name, "/"))
	    ++path;

	  if (strlen(path) == 0)
	    return vnode;

	  struct vnode * vnode2 = vfs_find_node_in_subnodes(vnode->_u.link.vnode, path, trail);

	  if (vnode2) {

	    if (vfs_debug)
	      emscripten_log(EM_LOG_CONSOLE, "vfs_find_node_in_subnodes: found");
	    
	    return vnode2;
	  }
	}
	else if (vnode->type == VSYMLINK) {

	  if (vfs_debug)
	    emscripten_log(EM_LOG_CONSOLE, "vfs_find_node_in_subnodes: VSYMLINK %s", path);

	  if (vnode->_u.link.vnode) {

	    path += strlen(vnode->name);

	    if (strcmp(vnode->name, "/"))
	      ++path;

	    if (vfs_debug)
	      emscripten_log(EM_LOG_CONSOLE, "vfs_find_node_in_subnodes: VSYMLINK has vnode %s %s", vnode->_u.link.vnode->name, path);

	    if (strlen(path) == 0)
	      return vnode;

	    struct vnode * vnode2 = vfs_find_node_in_subnodes(vnode->_u.link.vnode->_u.link.vnode, path, trail);

	    if (vnode2) {

	      if (vfs_debug)
		emscripten_log(EM_LOG_CONSOLE, "vfs_find_node_in_subnodes: VSYMLINK found");
	    
	      return vnode2;
	    }
	    
	  }
	  else if (vnode->_u.link.symlink) {
	  
	    return vnode;
	  }
	}
	else if (vnode->type == VMOUNT) {

	  if (vfs_debug)
	    emscripten_log(EM_LOG_CONSOLE, "vfs_find_node_in_subnodes: found mount");

	  if (trail) {
	    *trail = path+strlen(vnode->name);

	    if (vfs_debug)
	      emscripten_log(EM_LOG_CONSOLE, "vfs_find_node_in_subnodes: trail=%s", *trail);
	  }

	  return vnode;
	}
      }
    }
    
    vnode = vnode->next;
  }

  return NULL;
}

struct vnode * vfs_find_node(const char * pathname, char ** trail) {

  return vfs_find_node_in_subnodes(vfs_root, pathname, trail);
}

int vfs_get_path(struct vnode * vnode, char * new_dir) {

  struct vnode * vnode_table[64];
  int nb_nodes = 0;

  while (vnode) {

    if (vnode->parent)
      vnode_table[nb_nodes++] = vnode;
    
    vnode = vnode->parent;
  }

  new_dir[0] = 0;

  for (int i = nb_nodes-1; i >= 0; --i) {
    
    strcat(new_dir, "/");
    strcat(new_dir, vnode_table[i]->name);
  }

  if (nb_nodes == 0)
    strcat(new_dir, "/");
  
  return 0;
}

struct vnode * vfs_create_file(const char * pathname) {

  //emscripten_log(EM_LOG_CONSOLE, "vfs_create_file: %s",pathname);
  
  // find path i.e last '/'
  char * p = strrchr(pathname,'/');

  if (!p)
    return NULL;

  //emscripten_log(EM_LOG_CONSOLE, "strrchr: %s",p);

  char * dir = (char *)malloc(p-pathname+1);

  if (!dir)
    return NULL;

  strncpy(dir,pathname,p-pathname);
  dir[p-pathname] = 0;

  //emscripten_log(EM_LOG_CONSOLE, "dir: %s",dir);

  // find path in vfs tree
  struct vnode * vnode = vfs_find_node(dir, NULL);

  //emscripten_log(EM_LOG_CONSOLE, "dir vnode: %p",vnode);
  
  if (!vnode || (vnode->type != VDIR)) {
    free(dir);
    return NULL;
  }

  //emscripten_log(EM_LOG_CONSOLE, "dir vnode: %s",vnode->name);

  // add file to path
  struct vnode * vfile = vfs_add_file(vnode,p+1);

  free(dir);
  
  return vfile;
}

void vfs_dump_node(struct vnode * vnode, int indent) {

  emscripten_log(EM_LOG_CONSOLE, "%*s * %s (%d)", (2*indent), "", vnode->name, vnode->type);

  if (vnode->type == VDIR) {
    struct vnode * link = vnode->_u.link.vnode;
  
    while (link) {

      vfs_dump_node(link,indent+1);

      link = link->next;
    }
  }
}

int get_fd_entry(int fd) {

  if (fd == 0)
    return 0;

  for (int i = 1; i < NB_FD_MAX; ++i) { // 0 is reserved

    if (fds[i].fd == fd)
      return i;
  }

  return -1;
}

int add_fd_entry(int fd, pid_t pid, unsigned short minor, const char * pathname, int flags, unsigned short mode, unsigned int size, struct vnode * vnode) {

  emscripten_log(EM_LOG_CONSOLE, "add_fd_entry: fd=%d pid=%d pathname=%s vnode=%x", fd, pid, pathname, vnode);

  int i = 1;
  
  for (; i < NB_FD_MAX; ++i) { // 0 is reserved

    if (fds[i].fd < 0)
      break;
  }

  if (i == NB_FD_MAX)
    return -1;

  fds[i].fd = fd;
  fds[i].pid = pid;
  fds[i].minor = minor;
  strcpy(fds[i].pathname, pathname);
  fds[i].flags = flags;
  fds[i].mode = mode;
  fds[i].offset = 0;
  fds[i].vnode = vnode;
  fds[i].unlink_pending = (vnode->linked == 0);
  
  return i;
}

int vfs_open(const char * pathname, int flags, mode_t mode, pid_t pid, unsigned short minor) {

  int remote_fd = -1;

  char * trail = NULL;
  
  struct vnode * vnode = vfs_find_node(pathname, &trail);

  emscripten_log(EM_LOG_CONSOLE, "vfs_open: %s flags=%x mode=%x", pathname, flags, mode);

  if (vnode && (vnode->type == VSYMLINK) ) {

    emscripten_log(EM_LOG_CONSOLE, "vfs_open: type of vnode %p is VSYMLINK !!", vnode);

    vnode = vnode->_u.link.symlink;
  }      

  if (vnode) {

    if ( (vnode->type == VDEV) || (vnode->type == VMOUNT) ) {

      emscripten_log(EM_LOG_CONSOLE, "vfs_open: type=%d trail=%x", vnode->type, trail);

      remote_fd = 0;
      fds[remote_fd].vnode = vnode;

      if (trail)
	strcpy(fds[remote_fd].pathname, trail);
      else
	fds[remote_fd].pathname[0] = 0;
    }
    else if (vnode->type != VDIR && (flags & O_DIRECTORY)) {

      remote_fd = -1;
    }
    else {

      if ( (vnode->type == VFILE) && (flags & (O_RDWR|O_WRONLY)) && (flags & O_TRUNC) ) {

	vnode->_u.file.file_size = 0;
      }
      else if ( (vnode->type == VDIR) && (flags & O_TMPFILE) ) { // We have to create a temporary file

	struct vnode * vfile = vfs_add_file(vnode, ""); // unlinked node as empty name

	vnode = vfile;
      }

      ++last_fd;

      add_fd_entry(last_fd, pid, minor, pathname, flags, mode, 0, vnode);
      
      remote_fd = last_fd;
    }
  }
  else if (flags & O_CREAT) {

    emscripten_log(EM_LOG_CONSOLE, "vfs_open: create file");

    struct vnode * vfile = vfs_create_file(pathname);
    
    if (vfile) {

      emscripten_log(EM_LOG_CONSOLE, "vfs_open: file created");

      ++last_fd;

      add_fd_entry(last_fd, pid, minor, pathname, flags, mode, 0, vfile);
      
      remote_fd = last_fd;
    }
  }
  
  return remote_fd;
}

struct vnode * vfs_get_vnode(int fd) {

  int i = get_fd_entry(fd);

  if (i < 0)
    return NULL;
  
  return fds[i].vnode;
}

const char * vfs_get_pathname(int fd) {

  int i = get_fd_entry(fd);

  if (i < 0)
    return NULL;
  
  return (const char *)&fds[i].pathname[0];
}

int vfs_close(int fd) {

  int i = get_fd_entry(fd);

  if (i < 0)
    return -1;
  
  fds[i].fd = -1;

  if (fds[i].pathname)
    free(fds[i].pathname);

  if (fds[i].unlink_pending) {

    vfs_unlink(fds[i].vnode);
  }
  
  fds[i].vnode = NULL;
  
  return i;
}

ssize_t vfs_read(int fd, void * buf, size_t len) {

  int i = get_fd_entry(fd);

  if (i < 0)
    return -ENOENT;
  
  struct vnode * vnode = fds[i].vnode;

  emscripten_log(EM_LOG_CONSOLE, "vfs_read: %d %d off=%d", fd, len, fds[i].offset);

  if (vnode && (vnode->type == VFILE)) {

    if (fds[i].offset >= vnode->_u.file.file_size)
      return 0;

    ssize_t bytes_read = ((fds[i].offset+len) <= vnode->_u.file.file_size)?len:vnode->_u.file.file_size-fds[i].offset;

    memcpy(buf, vnode->_u.file.buffer+fds[i].offset, bytes_read);
    
    fds[i].offset += bytes_read;

    /*if (DEBUG) {
      for (int i=0; i < bytes_read; ++i) {
	emscripten_log(EM_LOG_CONSOLE, "* %c", ((char *)buf)[i]);
      }
      }*/

    return bytes_read;
  }

  return -1;
}

ssize_t vfs_write(int fd, const void * buf, size_t len) {

  int i = get_fd_entry(fd);

  if (i < 0)
    return -ENOENT;
  
  struct vnode * vnode = fds[i].vnode;

  emscripten_log(EM_LOG_CONSOLE, "vfs_write: %d %d off=%d", fd, len, fds[i].offset);

  /*for (int i=0; i < len; ++i) {

    emscripten_log(EM_LOG_CONSOLE, "* %c", ((char *)buf)[i]);
    }*/

  emscripten_log(EM_LOG_CONSOLE, "vfs_write: vnode = %x", vnode);

  if (vnode && (vnode->type == VFILE)) {

    emscripten_log(EM_LOG_CONSOLE, "vfs_write: vnode is VFILE");

    int min_size = fds[i].offset+len;

    if (!vnode->_u.file.buffer) { // buffer does not exist

      vnode->_u.file.buffer_size = ((min_size+1024)/1024)*1024;

      vnode->_u.file.buffer = (unsigned char *)malloc(vnode->_u.file.buffer_size);
    }
    else if (vnode->_u.file.buffer_size < min_size) { // buffer_size is too small

      vnode->_u.file.buffer_size = ((min_size+1024)/1024)*1024;

      vnode->_u.file.buffer = (unsigned char *)realloc(vnode->_u.file.buffer, vnode->_u.file.buffer_size);

      if (fds[i].offset > vnode->_u.file.file_size) {

	memset(vnode->_u.file.buffer+vnode->_u.file.file_size, 0, fds[i].offset - vnode->_u.file.file_size);
      }
    }

    if (vnode->_u.file.buffer) {

      memcpy(vnode->_u.file.buffer+fds[i].offset, buf, len);

      fds[i].offset += len;

      // Update file size if offset is greater
      if (vnode->_u.file.file_size < fds[i].offset)
	vnode->_u.file.file_size = fds[i].offset;

      emscripten_log(EM_LOG_CONSOLE, "vfs_write: %d bytes written", len);

      return len;
    }
  }
  else if (vnode) {

    emscripten_log(EM_LOG_CONSOLE, "vfs_write: vnode %s is of type %d", vnode->name, vnode->type);
  }
  
  return -1;
}

ssize_t vfs_getdents(int fd, void * buf, size_t len) {

  //TODO remove unlinked nodes

  emscripten_log(EM_LOG_CONSOLE, "vfs_getdents: sizeof off_t=%d", sizeof(off_t));
  
  int i = get_fd_entry(fd);

  if (i < 0)
    return -ENOENT;
  
  struct vnode * vnode = fds[i].vnode;
  
  struct vnode * child = vnode->_u.link.vnode;

  struct __dirent {
    ino_t d_ino;
    off_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[1];
  };

  
  int off;
  
  for (off = 0; off < fds[i].offset; ++off) {
    
    child = child->next;
  }

  ssize_t count;
  struct __dirent * ptr;

  for (count = 0; count < len; ++fds[i].offset) {

    if (child && ((count+sizeof(struct __dirent)+strlen(child->name)) < len) ) {

      ptr = (struct __dirent *)(((char *)buf)+count);

      switch(child->type) {

      case VDIR:

	ptr->d_type = DT_DIR;
	break;
	
      case VFILE:

	ptr->d_type = DT_REG;
	break;
	
      case VSYMLINK:

	//TODO
	ptr->d_type = DT_DIR;
	break;
	
      case VDEV:

	//TODO
	ptr->d_type = DT_CHR;
	break;
	
      case VMOUNT:

	//TODO: correct ?
	ptr->d_type = DT_DIR;
	break;
	
      default:

	ptr->d_type = DT_REG;
	break;
      }

      ptr->d_ino = (ino_t)child;

      strcpy(ptr->d_name, child->name);
      
      ptr->d_reclen = sizeof(struct __dirent) + strlen(child->name);

      count += ptr->d_reclen;

      ptr->d_off = count;
    }
    else {

      return count;
    }

    child = child->next;
  }
  
  
  return count;
}

int vfs_ioctl(int fd, int op) {

  emscripten_log(EM_LOG_CONSOLE, "vfs_ioctl: %d %d", fd, op);

  struct vnode * vnode = vfs_get_vnode(fd);

  if (vnode) {
    
    emscripten_log(EM_LOG_CONSOLE, "vfs_ioctl: fd found");

    return EINVAL;
  }

  emscripten_log(EM_LOG_CONSOLE, "vfs_ioctl: fd not found");

  return EBADF;
}

int vfs_stat(const char * pathname, struct stat * buf, struct vnode ** p_vnode, char ** trail) {

  struct vnode * vnode = vfs_find_node(pathname, trail);

  *p_vnode = NULL;

  if (vnode) {

    if ( (vnode->type == VDEV) || (vnode->type == VMOUNT) ) {

      *p_vnode = vnode;
      return 0;
    }
    else {

      buf->st_dev = makedev(0, 0); // vfs major, minor
      buf->st_ino = (ino_t)vnode;
      
      buf->st_mode = 0;
      buf->st_size = 0;

      buf->st_nlink = 1;	
      buf->st_uid = 1;
      buf->st_gid = 1;

      switch(vnode->type) {

      case VDIR:

	buf->st_mode |= S_IFDIR;
	buf->st_mode |= S_IRWXU | S_IRWXG | S_IRWXO;
	break;
	
      case VFILE:

	buf->st_mode |= S_IFREG;
	buf->st_mode |= S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;

	buf->st_size = vnode->_u.file.file_size;
	
	break;
	
      case VSYMLINK:

	//TODO
        buf->st_mode |= S_IFDIR;
	buf->st_mode |= S_IRWXU | S_IRWXG | S_IRWXO;
	break;
	
      default:

	buf->st_mode |= S_IFREG;
	buf->st_mode |= S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
	break;
      }
      
      return 0;
    }
  }
  
  return -1;
}

int vfs_lstat(const char * pathname, struct stat * buf, struct vnode ** p_vnode, char ** trail) {

  struct vnode * vnode = vfs_find_node(pathname, trail);

  *p_vnode = NULL;

  if (vnode) {

    if ( (vnode->type == VDEV) || (vnode->type == VMOUNT) ) {

      *p_vnode = vnode;
      return 0;
    }
    else {

      buf->st_dev = makedev(0, 0); // vfs major, minor
      buf->st_ino = (ino_t)vnode;

      buf->st_mode = 0;
      buf->st_size = 0;

      buf->st_nlink = 1;	
      buf->st_uid = 1;
      buf->st_gid = 1;

      switch(vnode->type) {

      case VDIR:

	buf->st_mode |= S_IFDIR;
	buf->st_mode |= S_IRWXU | S_IRWXG | S_IRWXO;
	break;
	
      case VFILE:

	buf->st_mode |= S_IFREG;
	buf->st_mode |= S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;

	buf->st_size = vnode->_u.file.file_size;
	
	break;
	
      case VSYMLINK:

	//TODO
        buf->st_mode |= S_IFDIR;
	buf->st_mode |= S_IRWXU | S_IRWXG | S_IRWXO;
	break;
      }
      
      return 0;
    }
  }
  
  return -1;
}

int vfs_fstat(int fd, struct stat * buf) {

  struct vnode * vnode = vfs_get_vnode(fd);

  if (vnode) {

    buf->st_dev = makedev(0, 0); // vfs major, minor
    buf->st_ino = (ino_t)vnode;

    buf->st_mode = 0;
    buf->st_size = 0;

    buf->st_nlink = 1;	
    buf->st_uid = 1;
    buf->st_gid = 1;

    switch(vnode->type) {

    case VDIR:

      buf->st_mode |= S_IFDIR;
      buf->st_mode |= S_IRWXU | S_IRWXG | S_IRWXO;
      break;

    case VFILE:

      buf->st_mode |= S_IFREG;
      buf->st_mode |= S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
      
      buf->st_size = vnode->_u.file.file_size;
      
      break;
	
    default:

      buf->st_mode |= S_IFREG;
      buf->st_mode |= S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
	
      break;
    }
      
    return 0;
  }

  return -1;
}

int vfs_seek(int fd, int offset, int whence) {

  int i = get_fd_entry(fd);

  if (i < 0)
    return -ENOENT;
  
  struct vnode * vnode = fds[i].vnode;

  if (vnode && (vnode->type == VFILE)) {

    switch(whence) {

    case SEEK_SET:

      fds[i].offset = offset;

      break;

    case SEEK_CUR:

      fds[i].offset += offset;

      break;

    case SEEK_END:

      fds[i].offset = vnode->_u.file.file_size + offset;
      
      break;

    default:

      break;
    }

    emscripten_log(EM_LOG_CONSOLE, "vfs_seek: offset=%d", fds[i].offset);

    return fds[i].offset;
  }
  
  return -1;
}

int vfs_ftruncate(int fd, int length) {

  int i = get_fd_entry(fd);

  if (i < 0)
    return ENOENT;

  struct vnode * vnode = fds[i].vnode;

  if (!vnode)
    return EBADF;

  if (vnode->type != VFILE)
    return EISDIR;

  if (length > vnode->_u.file.file_size) {

    if (length > vnode->_u.file.buffer_size) {

      unsigned char * buf = (unsigned char *)malloc(length);

      if (vnode->_u.file.buffer_size > 0)
	memcpy(buf, vnode->_u.file.buffer, vnode->_u.file.buffer_size);

      if (vnode->_u.file.buffer)
	free(vnode->_u.file.buffer);

      vnode->_u.file.buffer = buf;
      vnode->_u.file.buffer_size = length;
    }

    memset(vnode->_u.file.buffer+vnode->_u.file.file_size, 0, vnode->_u.file.buffer_size-vnode->_u.file.file_size);
    
  }

  vnode->_u.file.file_size = length;
  
  return 0;
}

int vfs_unlink(struct vnode * vnode) {

  if (!vnode)
    return ENOENT;
  
  int i = 1;
  int unlink_pending_set = 0;
  
  for (; i < NB_FD_MAX; ++i) { // 0 is reserved

    if ( (fds[i].fd >= 0) && (fds[i].vnode == vnode) ) {

      emscripten_log(EM_LOG_CONSOLE, "vfs_unlink: %d is opened -> unlink_pending=1", fds[i].fd);
      
      fds[i].unlink_pending = 1;
      unlink_pending_set = 1;
    }
  }
  
  if (unlink_pending_set)
    return 0;

  vfs_del_node(vnode);

  return 0;
}

int vfs_rename(struct vnode * old_vnode, const char * newpath) {

  struct vnode * new_vnode = vfs_find_node(newpath, NULL);

  if (old_vnode == new_vnode) // Same node
    return 0;

  if (old_vnode->type == VDIR) {

    if ( (new_vnode == NULL) /*||
			       ((new_vnode->type == VDIR) && () )*/ ) {

      //TODO

    }
    else {

      return ENOTDIR;
    }
  }
  else if (old_vnode->type == VFILE) {

    if (!new_vnode) {

      char parent_dir[1024];

      char * last = strrchr(newpath, '/');

      if (!last || (last == newpath) )
	return EACCES;

      strncpy(parent_dir, newpath, last-newpath);
      parent_dir[last-newpath] = 0;

      struct vnode * parent_vnode = vfs_find_node(parent_dir, NULL);

      if (!parent_vnode || (parent_vnode->type != VDIR) )
	return EACCES;

      if (parent_vnode == old_vnode->parent) { // Same dir

	strcpy(old_vnode->name, last+1);
	
	return 0;
      }
      else {

	//TODO
	//parent_vnode
      }
	
    }
    else if (new_vnode->type == VFILE){

      //TODO
    }
    else if (new_vnode->type == VDIR) {

      return EISDIR;
    }
  }
  else {

    //TODO
  }

  return EACCES;
}

int vfs_set_fs_flags(int fd, int flags) {

  if (fd == 0)
    return -1;

  for (int i = 1; i < NB_FD_MAX; ++i) { // 0 is reserved

    if (fds[i].fd == fd) {

      fds[i].flags = flags;
      return i;
    }
  }

  return -1;
}

void vfs_dump() {

  emscripten_log(EM_LOG_CONSOLE, "VFS dump");
  
  vfs_dump_node(vfs_root,0);

  emscripten_log(EM_LOG_CONSOLE, "********");
}
