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

#include <emscripten.h>

#include "vfs.h"

#define NB_FD_MAX 64

static char vfs_debug = 0;
		
static struct vnode * vfs_root;

struct fd_entry {

  pid_t pid;
  unsigned short minor;
  char pathname[1024];
  int flags;
  unsigned short mode;
  unsigned int offset;
  struct vnode * vnode;
};

static int last_fd = 0; // keep 0 for latest open of dev type is dev or mount

static struct fd_entry fds[NB_FD_MAX];

void vfs_set_debug(char enable) {

  vfs_debug = enable; 
}

int vfs_init() {

  vfs_root = NULL;

  vfs_root = vfs_add_dir(NULL, "/");
    
  return 0;
}

struct vnode * vfs_add_node(struct vnode * parent, enum vnode_type type, const char * name) {

  if (!parent && (type != VDIR))
    return NULL;

  if (parent && parent->type != VDIR)
    return NULL;
  
  struct vnode ** vnode_p = NULL;
  
  if (parent) {

    if (!parent->_u.link.vnode) {
      vnode_p = &parent->_u.link.vnode;
    }
    else {
      struct vnode * p = parent->_u.link.vnode;

      if (strcmp(p->name, name) == 0)
	return NULL;

      while (p->next) {

	p = p->next;

	if (strcmp(p->name, name) == 0)
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

int add_fd_entry(int fd, pid_t pid, unsigned short minor, const char * pathname, int flags, unsigned short mode, unsigned int size, struct vnode * vnode) {

  emscripten_log(EM_LOG_CONSOLE, "add_fd_entry: fd=%d pid=%d pathname=%s vnode=%x", fd, pid, pathname, vnode);
  
  fds[fd].pid = pid;
  fds[fd].minor = minor;
  strcpy(fds[fd].pathname, pathname);
  fds[fd].flags = flags;
  fds[fd].mode = mode;
  fds[fd].offset = 0;
  fds[fd].vnode = vnode;
  
  return fd;
}

int vfs_open(const char * pathname, int flags, mode_t mode, pid_t pid, unsigned short minor) {

  int remote_fd = -1;

  char * trail;
  
  struct vnode * vnode = vfs_find_node(pathname, &trail);

  emscripten_log(EM_LOG_CONSOLE, "vfs_open: %s flags=%x mode=%x", pathname, flags, mode);

  if (vnode) {

    if ( (vnode->type == VDEV) || (vnode->type == VMOUNT) ) {

      remote_fd = 0;
      fds[remote_fd].vnode = vnode;
      strcpy(fds[remote_fd].pathname, trail);
    }
    else {

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

  return fds[fd].vnode;
}

const char * vfs_get_pathname(int fd) {

  return (const char *)&fds[fd].pathname[0];
}

int vfs_close(int fd) {

  return 0;
}

ssize_t vfs_read(int fd, void * buf, size_t len) {

  emscripten_log(EM_LOG_CONSOLE, "vfs_read: %d %d off=%d", fd, len, fds[fd].offset);

  struct vnode * vnode = vfs_get_vnode(fd);

  if (vnode && (vnode->type == VFILE)) {

    if (fds[fd].offset >= vnode->_u.file.file_size)
      return 0;

    ssize_t bytes_read = ((fds[fd].offset+len) <= vnode->_u.file.file_size)?len:vnode->_u.file.file_size-fds[fd].offset;

    memcpy(buf, vnode->_u.file.buffer+fds[fd].offset, bytes_read);

    fds[fd].offset += bytes_read;

    for (int i=0; i < bytes_read; ++i) {

      emscripten_log(EM_LOG_CONSOLE, "* %c", ((char *)buf)[i]);
    }

    return bytes_read;
  }

  return -1;
}

ssize_t vfs_write(int fd, const void * buf, size_t len) {

  emscripten_log(EM_LOG_CONSOLE, "vfs_write: %d %d off=%d", fd, len, fds[fd].offset);

  for (int i=0; i < len; ++i) {

    emscripten_log(EM_LOG_CONSOLE, "* %c", ((char *)buf)[i]);
  }

  struct vnode * vnode = vfs_get_vnode(fd);

  if (vnode && (vnode->type == VFILE)) {

    int min_size = fds[fd].offset+len;

    if (!vnode->_u.file.buffer) { // buffer does not exist

      vnode->_u.file.buffer_size = ((min_size+1024)/1024)*1024;

      vnode->_u.file.buffer = (unsigned char *)malloc(vnode->_u.file.buffer_size);
    }
    else if (vnode->_u.file.buffer_size < min_size) { // buffer_size is too small

      vnode->_u.file.buffer_size = ((min_size+1024)/1024)*1024;

      vnode->_u.file.buffer = (unsigned char *)realloc(vnode->_u.file.buffer, vnode->_u.file.buffer_size);

      if (fds[fd].offset > vnode->_u.file.file_size) {

	memset(vnode->_u.file.buffer+vnode->_u.file.file_size, 0, fds[fd].offset - vnode->_u.file.file_size);
      }
    }

    if (vnode->_u.file.buffer) {

      memcpy(vnode->_u.file.buffer+fds[fd].offset, buf, len);

      fds[fd].offset += len;

      // Update file size if offset is greater
      if (vnode->_u.file.file_size < fds[fd].offset)
	vnode->_u.file.file_size = fds[fd].offset;

      emscripten_log(EM_LOG_CONSOLE, "vfs_write: %d bytes written", len);

      return len;
    }
  }
  
  return -1;
}

ssize_t vfs_getdents(int fd, void * buf, size_t len) {

  emscripten_log(EM_LOG_CONSOLE, "vfs_getdents: sizeof off_t=%d", sizeof(off_t));
  
  struct vnode * vnode = vfs_get_vnode(fd);

  if (!vnode)
    return -1;
  
  struct vnode * child = vnode->_u.link.vnode;

  struct __dirent {
    ino_t d_ino;
    off_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[1];
  };

  
  int off;
  
  for (off = 0; off < fds[fd].offset; ++off) {

    child = child->next;
  }

  ssize_t count;
  struct __dirent * ptr;

  for (count = 0; count < len; ++fds[fd].offset) {

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

    return 0;
  }

  emscripten_log(EM_LOG_CONSOLE, "vfs_ioctl: fd not found");

  return -1;
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

      switch(vnode->type) {

      case VDIR:

	buf->st_mode |= S_IFDIR;
	break;
	
      case VFILE:

	buf->st_mode |= S_IFREG;
	buf->st_size = vnode->_u.file.file_size;
	break;
	
      case VSYMLINK:

	//TODO
        buf->st_mode |= S_IFDIR;
	break;
	
      default:

	buf->st_mode |= S_IFREG;
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

      switch(vnode->type) {

      case VDIR:

	buf->st_mode |= S_IFDIR;
	break;
	
      case VFILE:

	buf->st_mode |= S_IFREG;
	buf->st_size = vnode->_u.file.file_size;
	break;
	
      case VSYMLINK:

	//TODO
        buf->st_mode |= S_IFDIR;
	break;
	
      default:

	buf->st_mode |= S_IFREG;
	break;
      }
      
      return 0;
    }
  }
  
  return -1;
}

int vfs_seek(int fd, int offset, int whence) {

  struct vnode * vnode = vfs_get_vnode(fd);

  if (vnode && (vnode->type == VFILE)) {

    switch(whence) {

    case SEEK_SET:

      fds[fd].offset = offset;

      break;

    case SEEK_CUR:

      fds[fd].offset += offset;

      break;

    case SEEK_END:

      fds[fd].offset = vnode->_u.file.file_size + offset;
      
      break;

    default:

      break;
    }

    emscripten_log(EM_LOG_CONSOLE, "vfs_seek: offset=%d", fds[fd].offset);

    return fds[fd].offset;
  }
  
  return -1;
}

void vfs_dump() {

  emscripten_log(EM_LOG_CONSOLE, "VFS dump");
  
  vfs_dump_node(vfs_root,0);

  emscripten_log(EM_LOG_CONSOLE, "********");
}
