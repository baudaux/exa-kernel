/*
 * Copyright (C) 2023 Benoit Baudaux
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

#include "msg.h"

#include "lfs.h"
#include "lfs_block.h"

#ifndef DEBUG
#define DEBUG 0
#endif

#if DEBUG
#include <emscripten.h>
#else
#define emscripten_log(...)
#endif

#define LOCALFS_VERSION "localfs v0.1.0"

#define LOCALFS_PATH "/var/localfs.peer"
#define RESMGR_PATH "/var/resmgr.peer"

#define NB_LOCALFS_MAX  16
#define NB_FD_MAX     128

struct device_ops {

  int (*open)(const char *pathname, int flags, mode_t mode, pid_t pid, unsigned short minor);
  ssize_t (*read)(int fd, void * buf, size_t count);
  ssize_t (*write)(int fildes, const void * buf, size_t nbyte);
  int (*ioctl)(int fildes, int request, ... /* arg */);
  int (*close)(int fd);
  int (*stat)(const char * pathname, struct stat * stat);
  ssize_t (*getdents)(int fd, char * buf, ssize_t count);
  int (*seek)(int fd, int offset, int whence);
  int (*faccess)(const char * pathname, int amode, int flags);
  int (*unlink)(const char * path, int flags);
  int (*rename)(const char * oldpath, const char * newpath);
  int (*ftruncate)(int fd, int length);
  int (*mkdir)(const char * path, int mode);
};

struct fd_entry {

  int fd;
  pid_t pid;
  unsigned short minor;
  char pathname[1024];
  int flags;
  unsigned short mode;
  mode_t type;
  unsigned int size;
  unsigned int offset;
  char * data;
  unsigned int data_size;
  void * lfs_handle;
  int unlink_pending;
};

static unsigned short major;
static unsigned short minor = 0;

static lfs_t lfs;

static struct device_ops * devices[NB_LOCALFS_MAX];

static int last_fd = 0;

static struct fd_entry fds[NB_FD_MAX];

static struct lfs_config lfs_config = {

  .read = &lfs_blk_read,
  .prog = &lfs_blk_prog,
  .erase = &lfs_blk_erase,
  .sync = lfs_blk_sync,

#ifdef LFS_THREADSAFE
  .lock = NULL,
  .unlock = NULL,
#endif

  .read_size = LFS_READ_SIZE,
  .prog_size = LFS_READ_SIZE,
  .block_size = LFS_BLK_SIZE,
  .block_count = LFS_BLK_NB,
  .block_cycles = 1000,
  .cache_size = LFS_CACHE_SIZE,
  .lookahead_size = 8,
  .read_buffer = NULL,
  .prog_buffer = NULL,
  .lookahead_buffer = NULL,
  .name_max = 0,
  .file_max = 0,
  .attr_max = 0,
  .metadata_max = 0,
};

int add_fd_entry(pid_t pid, unsigned short minor, const char * pathname, int flags, unsigned short mode, mode_t type, unsigned int size, void * lfs_handle) {

  emscripten_log(EM_LOG_CONSOLE,"localfs:add_fd_entry -> %d %d %s", pid, minor, pathname);
  
  for (int i = 0; i < NB_FD_MAX; ++i) {

    if (fds[i].fd < 0) {

      ++last_fd;

      fds[i].fd = last_fd;
      fds[i].pid = pid;
      fds[i].minor = minor;
      strcpy(fds[i].pathname, pathname);
      fds[i].flags = flags;
      fds[i].mode = mode;
      fds[i].type = type;
      fds[i].size = size;
      fds[i].offset = 0;
      fds[i].lfs_handle = lfs_handle;
      fds[i].unlink_pending = 0;

      emscripten_log(EM_LOG_CONSOLE,"<-- localfs:add_fd_entry : remote_fd=%d", last_fd);

      return last_fd;
    }
  }

  return -ENOMEM;
}

int del_fd_entry(int index) {

  if (fds[index].fd >= 0) {

    fds[index].fd = -1;

    return 0;
  }

  return -1;
}

int find_fd_entry(int fd) {

  for (int i = 0; i < NB_FD_MAX; ++i) {

    if (fds[i].fd == fd) {

      return i;
    }
  }

  return -1;
}

static int localfs_errno(int lfs_errno) {

  switch(lfs_errno) {
    
  case LFS_ERR_OK:
    return 0;
  case LFS_ERR_IO:
    return EIO;
  case LFS_ERR_CORRUPT:
    return EFAULT;
  case LFS_ERR_NOENT:
    return ENOENT;
  case LFS_ERR_EXIST:
    return EEXIST;
  case LFS_ERR_NOTDIR:
    return ENOTDIR;
  case LFS_ERR_ISDIR:
    return EISDIR;
  case LFS_ERR_NOTEMPTY:
    return ENOTEMPTY;
  case LFS_ERR_BADF:
    return EBADF;
  case LFS_ERR_FBIG:
    return EFBIG;
  case LFS_ERR_INVAL:
    return EINVAL;
  case LFS_ERR_NOSPC:
    return ENOSPC;
  case LFS_ERR_NOMEM:
    return ENOMEM;
  case LFS_ERR_NOATTR:
    return ENODATA;
  case LFS_ERR_NAMETOOLONG:
    return ENAMETOOLONG;
  default:
    return EFAULT;
  }
}

static ssize_t localfs_read(int fd, void * buf, size_t count) {

  int i = find_fd_entry(fd);

  if (i < 0)
    return -1;

  ssize_t ret = lfs_file_read(&lfs, fds[i].lfs_handle, buf, count);

  if (ret < 0)
    ret = -localfs_errno(ret); // Negative value if error
  
  return ret;
}

static ssize_t localfs_write(int fd, const void * buf, size_t count) {

  int i = find_fd_entry(fd);

  if (i < 0)
    return -1;

  ssize_t ret = lfs_file_write(&lfs, fds[i].lfs_handle, buf, count);
  
  if (ret < 0)
    ret = -localfs_errno(ret); // Negative value if error

  return ret;
}

static int localfs_ioctl(int fildes, int request, ... /* arg */) {

  return EINVAL;
}

static int localfs_unlink(const char * path, int flags) {

  int unlink_pending_set = 0;
  
  for (int i = 0; i < NB_FD_MAX; ++i) {

    if ( (fds[i].fd >= 0) && (strcmp(path, fds[i].pathname) == 0) ) {

      fds[i].unlink_pending = 1;
      unlink_pending_set = 1;
    }
  }

  if (unlink_pending_set)
    return EBUSY;
  
  return localfs_errno(lfs_remove(&lfs, path));
}
static int localfs_close(int fd) {

  int i = find_fd_entry(fd);

  if (i < 0)
    return -1;

  int res;

  if (fds[i].type & S_IFDIR)
    res = lfs_dir_close(&lfs, fds[i].lfs_handle);
  else
    res = lfs_file_close(&lfs, fds[i].lfs_handle);

  if (fds[i].unlink_pending) {

    fds[i].fd = -1; // not to take this entry during unlink
    localfs_unlink(fds[i].pathname, 0);
    fds[i].fd = fd;
  }
  
  if (res == LFS_ERR_OK)
    del_fd_entry(i);
  
  return localfs_errno(res);
}

static int localfs_stat(const char * pathname, struct stat * stat) {

  emscripten_log(EM_LOG_CONSOLE,"localfs_stat: %s", pathname);
  
  struct lfs_info info;

  int res = lfs_stat(&lfs, pathname, &info);

  if (res == LFS_ERR_OK) {

    emscripten_log(EM_LOG_CONSOLE,"localfs_stat -> %d %d %s", info.type, info.size, info.name);
  }

  if ((res == LFS_ERR_OK) && stat) {

    stat->st_dev = makedev(major, 1);
    
    if (info.type == LFS_TYPE_REG) {
      stat->st_mode = S_IFREG;
      stat->st_size = info.size;
      stat->st_mode |= S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
    }
    else if (info.type == LFS_TYPE_DIR) {
      stat->st_mode = S_IFDIR;
      stat->st_size = 0;
      stat->st_mode |= S_IRWXU | S_IRWXG | S_IRWXO;
    }
    else {
      stat->st_mode = S_IFREG;
      stat->st_size = 0;
      stat->st_mode |= S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
    }

    int i = 0;
    
    for (char * c = pathname; *c; ++c)
      i += *c;

    stat->st_ino = i;
  }

  emscripten_log(EM_LOG_CONSOLE,"<-- localfs_stat: %d (mode=%d)", -res, stat->st_mode);
  
  return localfs_errno(res);
}

static int localfs_open(const char * pathname, int flags, mode_t mode, pid_t pid, unsigned short minor) {

  emscripten_log(EM_LOG_CONSOLE,"localfs_open: %d %d %s", flags, mode, pathname);

  int _errno;
  struct stat stat;

  _errno = localfs_stat(pathname, &stat);

  if ( (_errno == 0) || (flags & O_CREAT) ) {

    int lfs_flags = 0;
    void * lfs_handle = NULL;

    if (_errno != 0) {

      stat.st_mode = S_IFREG; // Create a regular file if it does not exist
    }

    if ((flags & 3) == 0)
      lfs_flags |= LFS_O_RDONLY;
    if (flags & O_WRONLY)
      lfs_flags |= LFS_O_WRONLY;
    if (flags & O_RDWR)
      lfs_flags |= LFS_O_RDWR;
    if (flags & O_CREAT)
      lfs_flags |= LFS_O_CREAT;
    if (flags & O_EXCL)
      lfs_flags |= LFS_O_EXCL;
    if (flags & O_TRUNC)
      lfs_flags |= LFS_O_TRUNC;
    if (flags & O_APPEND)
      lfs_flags |= LFS_O_APPEND;

    if (stat.st_mode & S_IFREG) {

      if (flags & O_DIRECTORY)   // Error pathname is not a directory
	return -ENOTDIR;

      emscripten_log(EM_LOG_CONSOLE,"localfs_open -> lfs_open_file: %x %x", flags, lfs_flags);

      lfs_handle = malloc(sizeof(lfs_file_t));
      
      _errno = localfs_errno(lfs_file_open(&lfs, (lfs_file_t *)lfs_handle, pathname, lfs_flags));
    }
    else if (stat.st_mode & S_IFDIR) {

      emscripten_log(EM_LOG_CONSOLE,"localfs_open -> lfs_open_dir");

      lfs_handle = malloc(sizeof(lfs_dir_t));

      _errno = localfs_errno(lfs_dir_open(&lfs, lfs_handle, pathname));
    }

    if (_errno == 0) {
      
      int fd = add_fd_entry(pid, minor, pathname, flags, mode, stat.st_mode, stat.st_size, lfs_handle);

      if (fd >= 0)
	return fd;
      
      _errno = ENOMEM;
    }
    else {

      if (lfs_handle)
	free(lfs_handle);
    }
  }

  emscripten_log(EM_LOG_CONSOLE,"<-- localfs_open : errno=%d", _errno);

  return -_errno; // Negative value if error
  
}

struct __dirent {
    ino_t d_ino;
    off_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[1];
  };

static ssize_t localfs_getdents(int fd, char * buf, ssize_t count) {

  int i = find_fd_entry(fd);

  if (i < 0)
    return -EBADF;
  
  int res = 1;
  int len = 0;

  struct lfs_info info;

  while (res > 0) {
    
    res = lfs_dir_read(&lfs, fds[i].lfs_handle, &info);

    if (res > 0) {
    
      struct __dirent * dirent_ptr = (struct __dirent *)(buf+len);

      if ((len+sizeof(struct __dirent)+strlen(info.name)) < count) {  // there is space for this entry

	strcpy(dirent_ptr->d_name, info.name);
	
	if (info.type == LFS_TYPE_DIR){
	  dirent_ptr->d_type = DT_DIR;
	}
	else {
	  dirent_ptr->d_type = DT_REG;
	}
	
	dirent_ptr->d_reclen = sizeof(struct __dirent) + strlen(dirent_ptr->d_name);
	  
	len += dirent_ptr->d_reclen;

	dirent_ptr->d_off = len;	  
      }
      else {

	// Unread

	lfs_soff_t off = lfs_dir_tell(&lfs, fds[i].lfs_handle);
	lfs_dir_seek(&lfs, fds[i].lfs_handle, off-1);
	
	res = 0;
      }
    }
  }
  
  return len;
}

static int localfs_seek(int fd, int offset, int whence) {

  int i = find_fd_entry(fd);

  if (i < 0)
    return EBADF;

  return lfs_file_seek(&lfs, fds[i].lfs_handle, offset, whence);
}

static int localfs_faccess(const char * pathname, int amode, int flags) {

  struct stat stat;
  
  return localfs_stat(pathname, &stat);
}

static int localfs_rename(const char * oldpath, const char * newpath) {

  return localfs_errno(lfs_rename(&lfs, oldpath, newpath));
}

static int localfs_ftruncate(int fd, int length) {

  int i = find_fd_entry(fd);

  if (i < 0)
    return EBADF;

  return localfs_errno(lfs_file_truncate(&lfs, fds[i].lfs_handle, length));
}

static int localfs_mkdir(const char * path, int mode) {

  return localfs_errno(lfs_mkdir(&lfs, path));
}

static int localfs_rmdir(const char * path) {

  return localfs_errno(lfs_remove(&lfs, path));
}

static struct device_ops localfs_ops = {

  .open = localfs_open,
  .read = localfs_read,
  .write = localfs_write,
  .ioctl = localfs_ioctl,
  .close = localfs_close,
  .stat = localfs_stat,
  .getdents = localfs_getdents,
  .seek = localfs_seek,
  .faccess = localfs_faccess,
  .unlink = localfs_unlink,
  .rename = localfs_rename,
  .ftruncate = localfs_ftruncate,
  .mkdir = localfs_mkdir,
};

int register_device(unsigned short minor, struct device_ops * dev_ops) {

  devices[minor] = dev_ops;

  return 0;
}

struct device_ops * get_device(unsigned short minor) {

  return devices[minor];
}

struct device_ops * get_device_from_fd(int fd) {

  int i = find_fd_entry(fd);

  if (i < 0)
    return NULL;
  
  return devices[fds[i].minor];
}

int main() {

  int sock;
  struct sockaddr_un local_addr, resmgr_addr, remote_addr;
  int bytes_rec;
  socklen_t len;
  char buf[1256];
  
  emscripten_log(EM_LOG_CONSOLE, "Starting " LOCALFS_VERSION "...");

  for (int i = 0; i < NB_FD_MAX; ++i) {
    
    fds[i].fd = -1;
    fds[i].data = NULL;
  }

  int fd = open("/dev/tty1", O_WRONLY | O_NOCTTY);
  
  if (fd >= 0)
    write(fd, "\n\r[" LOCALFS_VERSION "]", strlen("\n\r[" LOCALFS_VERSION "]")+1);

  close(fd);
  
  /* Create the server local socket */
  sock = socket (AF_UNIX, SOCK_DGRAM, 0);
  if (sock < 0) {
    return -1;
  }

  /* Bind server socket to LOCALFS_PATH */
  memset(&local_addr, 0, sizeof(local_addr));
  local_addr.sun_family = AF_UNIX;
  strcpy(local_addr.sun_path, LOCALFS_PATH);
  
  if (bind(sock, (struct sockaddr *) &local_addr, sizeof(struct sockaddr_un))) {
    
    return -1;
  }

  memset(&resmgr_addr, 0, sizeof(resmgr_addr));
  resmgr_addr.sun_family = AF_UNIX;
  strcpy(resmgr_addr.sun_path, RESMGR_PATH);

  struct message * msg = (struct message *)&buf[0];
  
  msg->msg_id = REGISTER_DRIVER;
  msg->_u.dev_msg.dev_type = FS_DEV;
  
  memset(msg->_u.dev_msg.dev_name, 0, sizeof(msg->_u.dev_msg.dev_name));
  
  strcpy((char *)&msg->_u.dev_msg.dev_name[0], "localfs");
  
  sendto(sock, buf, 1256, 0, (struct sockaddr *) &resmgr_addr, sizeof(resmgr_addr));

  while (1) {
    
    bytes_rec = recvfrom(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, &len);

    emscripten_log(EM_LOG_CONSOLE, "*** localfs: %d", msg->msg_id);
    
    if (msg->msg_id == (REGISTER_DRIVER|0x80)) {

      if (msg->_errno)
	continue;

      major = msg->_u.dev_msg.major;

      emscripten_log(EM_LOG_CONSOLE, "REGISTER_DRIVER successful: major=%d", major);

      int res = lfs_mount(&lfs, &lfs_config);

      emscripten_log(EM_LOG_CONSOLE, "lfs_mount: res=%d", res);

      if (res < 0) {

	res = lfs_format(&lfs, &lfs_config);

	emscripten_log(EM_LOG_CONSOLE, "lfs_format: res=%d", res);

	if (res == 0) {

	  res = lfs_mount(&lfs, &lfs_config);
	  
	  emscripten_log(EM_LOG_CONSOLE, "second lfs_mount: res=%d", res);
	}
      }

      if (res == 0) {

	minor += 1;
	
	register_device(minor, &localfs_ops);
      
	msg->msg_id = REGISTER_DEVICE;
	msg->_u.dev_msg.minor = minor;

	memset(msg->_u.dev_msg.dev_name, 0, sizeof(msg->_u.dev_msg.dev_name));
	sprintf((char *)&msg->_u.dev_msg.dev_name[0], "localfs%d", msg->_u.dev_msg.minor);
  
	sendto(sock, buf, 1256, 0, (struct sockaddr *) &resmgr_addr, sizeof(resmgr_addr));
      }
    }
    else if (msg->msg_id == (REGISTER_DEVICE|0x80)) {

      if (msg->_errno)
	continue;

      emscripten_log(EM_LOG_CONSOLE, "REGISTER_DEVICE successful: %d,%d,%d", msg->_u.dev_msg.dev_type, msg->_u.dev_msg.major, msg->_u.dev_msg.minor);

      unsigned short minor = msg->_u.dev_msg.minor;

      msg->msg_id = MOUNT;
      msg->_u.mount_msg.dev_type = FS_DEV;
      msg->_u.mount_msg.major = major;
      msg->_u.mount_msg.minor = minor;

      memset(msg->_u.mount_msg.pathname, 0, sizeof(msg->_u.mount_msg.pathname));

      if (minor == 1) {

	int res = lfs_mkdir(&lfs, "/home");

	emscripten_log(EM_LOG_CONSOLE, "mkdir /home: res=%d", res);

	if (res == LFS_ERR_EXIST) {
	  res = 0;
	}

	if (res == 0) {
	  strcpy((char *)&msg->_u.mount_msg.pathname[0], "/home");
	
	  sendto(sock, buf, 1256, 0, (struct sockaddr *) &resmgr_addr, sizeof(resmgr_addr));
	}
      }
      
    }
    else if (msg->msg_id == (MOUNT|0x80)) {

      if (msg->_errno)
	continue;

      emscripten_log(EM_LOG_CONSOLE, "localfs device mounted successfully: %d,%d,%d", msg->_u.mount_msg.dev_type, msg->_u.mount_msg.major, msg->_u.mount_msg.minor);
    }
    else if (msg->msg_id == OPEN) {
      
      emscripten_log(EM_LOG_CONSOLE, "localfs: OPEN from %d: minor=%d pathname=%s dirfd=%d", msg->pid, msg->_u.open_msg.minor, msg->_u.open_msg.pathname, msg->_u.open_msg.fd);

      int remote_fd = -ENOENT;

      if ( (msg->_u.open_msg.fd == 0) || ((msg->_u.open_msg.fd == AT_FDCWD)) ) { // open absolute

	remote_fd = get_device(msg->_u.open_msg.minor)->open((const char *)(msg->_u.open_msg.pathname), msg->_u.open_msg.flags, msg->_u.open_msg.mode, msg->pid, msg->_u.open_msg.minor);

      }
      else { // open at dir

	int i = find_fd_entry(msg->_u.open_msg.fd);

	if (i >= 0) {

	  char path[1024];
	
	  strcpy(path, fds[i].pathname);

	  int l = strlen(path);

	  if (path[l-1] != '/') {

	    if ( (l > 1) && (path[l-1] == '.') && (path[l-2] == '/') ) {

	      path[l-1] = 0;
	    }
	    else {
	      strcat(path, "/");
	    }
	  }

	  strcat(path, msg->_u.open_msg.pathname);

	  msg->_u.open_msg.minor = fds[i].minor;

	  remote_fd = get_device(msg->_u.open_msg.minor)->open((const char *)path, msg->_u.open_msg.flags, msg->_u.open_msg.mode, msg->pid, msg->_u.open_msg.minor);
	}
      }

      emscripten_log(EM_LOG_CONSOLE, "localfs: OPEN -> remote_fd=%d", remote_fd);

      if (remote_fd >= 0) {

	msg->_u.open_msg.remote_fd = remote_fd;
	msg->_errno = 0;
      }
      else {

	msg->_u.open_msg.remote_fd = -1;
	msg->_errno = -remote_fd; // to positive value
      }
      
      msg->msg_id |= 0x80;
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == READ) {

      emscripten_log(EM_LOG_CONSOLE, "localfs: READ from %d: %d bytes", msg->pid, msg->_u.io_msg.len);

      struct message * reply = (struct message *) malloc(12+sizeof(struct io_message)+msg->_u.io_msg.len);

      reply->msg_id = READ|0x80;
      reply->pid = msg->pid;
      reply->_u.io_msg.fd = msg->_u.io_msg.fd;

      struct device_ops * dev = NULL;

      int i = find_fd_entry(msg->_u.io_msg.fd);

      if (i >= 0) {
        
	dev = get_device(fds[i].minor);
      }
      
      if (dev) {
	
	reply->_u.io_msg.len = dev->read(msg->_u.io_msg.fd, reply->_u.io_msg.buf, msg->_u.io_msg.len);

	if (reply->_u.io_msg.len >= 0) {
	  reply->_errno = 0;
	}
	else {
	  reply->_errno = -reply->_u.io_msg.len; // to positive value;
	  reply->_u.io_msg.len = 0;
	}

	emscripten_log(EM_LOG_CONSOLE, "READ: errno=%d %d bytes", reply->_errno, reply->_u.io_msg.len);
      }
      else {

	emscripten_log(EM_LOG_CONSOLE, "READ error: %d %d", msg->_u.io_msg.fd, fds[msg->_u.io_msg.fd].minor);
	reply->_errno = ENXIO;
      }
      
      sendto(sock, reply, 12+sizeof(struct message)+reply->_u.io_msg.len, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

      free(reply);
    }
    else if (msg->msg_id == WRITE) {

      emscripten_log(EM_LOG_CONSOLE, "localfs: WRITE from %d: %d bytes", msg->pid, msg->_u.io_msg.len);

      char * buf2 = msg->_u.io_msg.buf;

      if (msg->_u.io_msg.len > (bytes_rec - 20)) {

	emscripten_log(EM_LOG_CONSOLE, "localfs: WRITE need to read %d remaining bytes (%d read)", msg->_u.io_msg.len - (bytes_rec - 20), bytes_rec - 20);

	buf2 = (char *)malloc(msg->_u.io_msg.len);

	memcpy(buf2, msg->_u.io_msg.buf, bytes_rec - 20);

	int bytes_rec2 = recvfrom(sock, buf2+bytes_rec - 20, msg->_u.io_msg.len - (bytes_rec - 20), 0, (struct sockaddr *) &remote_addr, &len);

	emscripten_log(EM_LOG_CONSOLE, "localfs: WRITE %d read", bytes_rec2);
      }
      
      struct device_ops * dev = NULL;

      int i = find_fd_entry(msg->_u.io_msg.fd);

      if (i >= 0) {
        
	dev = get_device(fds[i].minor);
      }
      
      if (dev) {
	
	msg->_u.io_msg.len = dev->write(msg->_u.io_msg.fd, buf2, msg->_u.io_msg.len);
	if (msg->_u.io_msg.len >= 0) {
	  msg->_errno = 0;
	}
	else {
	  msg->_errno = -msg->_u.io_msg.len; // to positive value;
	  msg->_u.io_msg.len = 0;
	}
      }
      else {

	msg->_errno = EBADF;
      }

      msg->msg_id |= 0x80;
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      if (buf2 != msg->_u.io_msg.buf) {

	free(buf2);
      }
    }
    else if (msg->msg_id == IOCTL) {

      struct device_ops * dev = NULL;

      int i = find_fd_entry(msg->_u.ioctl_msg.fd);

      if (i >= 0) {
        
	dev = get_device(fds[i].minor);
      }
      
      if (dev) {
	
	msg->_errno = dev->ioctl(msg->_u.ioctl_msg.fd, msg->_u.ioctl_msg.op, msg->_u.ioctl_msg.len, msg->_u.ioctl_msg.buf);
      }
      else {

	msg->_errno = EBADF;
      }

      msg->msg_id |= 0x80;
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == CLOSE) {

      emscripten_log(EM_LOG_CONSOLE, "localfs: CLOSE -> fd=%d", msg->_u.close_msg.fd);

      struct device_ops * dev = NULL;

      int i = find_fd_entry(msg->_u.close_msg.fd);

      if (i >= 0) {
        
	dev = get_device(fds[i].minor);

	msg->_errno = dev->close(msg->_u.close_msg.fd);
      }
      else {

	msg->_errno = EBADF;
      }
      
      msg->msg_id |= 0x80;
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if ( (msg->msg_id == STAT) || (msg->msg_id == LSTAT) )  {
      
      emscripten_log(EM_LOG_CONSOLE, "localfs: STAT from %d: %s", msg->pid, msg->_u.stat_msg.pathname_or_buf);

      struct stat stat_buf;

      stat_buf.st_dev = makedev(msg->_u.stat_msg.major, msg->_u.stat_msg.minor);
      stat_buf.st_ino = (ino_t)&devices[msg->_u.stat_msg.minor];
      stat_buf.st_nlink = 1;	
      stat_buf.st_uid = 1;
      stat_buf.st_gid = 1;

      int _errno = 0;

      if ((_errno=get_device(msg->_u.stat_msg.minor)->stat((const char *)(msg->_u.stat_msg.pathname_or_buf), &stat_buf)) == 0) {
	
	msg->_u.stat_msg.len = sizeof(struct stat);
	memcpy(msg->_u.stat_msg.pathname_or_buf, &stat_buf, sizeof(struct stat));
      }

      msg->_errno = _errno;

      msg->msg_id |= 0x80;
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == GETDENTS) {

      emscripten_log(EM_LOG_CONSOLE, "localfs: GETDENTS from %d: fd=%d len=%d", msg->pid, msg->_u.getdents_msg.fd, msg->_u.getdents_msg.len);

      struct device_ops * dev = NULL;
      
      int i = find_fd_entry(msg->_u.getdents_msg.fd);

      if (i >= 0) {
        
	dev = get_device(fds[i].minor);
	
      }
      
      if (dev) {

	ssize_t count = (msg->_u.getdents_msg.len < 1024)?msg->_u.getdents_msg.len:1024;

	count = dev->getdents(msg->_u.getdents_msg.fd, (char *)(msg->_u.getdents_msg.buf), count);

	emscripten_log(EM_LOG_CONSOLE, "GETDENTS from %d: --> count=%d", msg->pid, count);

	if (count >= 0) {
	  
	  msg->_u.getdents_msg.len = count;
	  msg->_errno = 0;
	}
	else {

	  msg->_u.getdents_msg.len = 0;
	  msg->_errno = -count; // To positive value
	}
      }
      else {
	
	msg->_u.getdents_msg.len = 0;
	msg->_errno = EBADF;
      }

      msg->msg_id |= 0x80;

      sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == CHDIR) {

      emscripten_log(EM_LOG_CONSOLE, "localfs: CHDIR from %d", msg->pid);

      struct stat stat_buf;

      msg->_errno = get_device(msg->_u.cwd2_msg.minor)->stat((const char *)(msg->_u.cwd2_msg.buf), &stat_buf);

      msg->msg_id |= 0x80;

      sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == SEEK) {

      struct device_ops * dev = NULL;
      
      int i = find_fd_entry(msg->_u.seek_msg.fd);
      
      if (i >= 0) {
        
	dev = get_device(fds[i].minor);
      }
      
      if (dev) {

	msg->_u.seek_msg.offset = dev->seek(msg->_u.seek_msg.fd, msg->_u.seek_msg.offset, msg->_u.seek_msg.whence);
	
	if (msg->_u.seek_msg.offset < 0)
	  msg->_errno = localfs_errno(msg->_u.seek_msg.offset);
	else
	  msg->_errno = 0;

      }
      else {

	msg->_errno = EBADF;
      }

      msg->msg_id |= 0x80;

      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == FACCESSAT) {

      msg->_errno = get_device(msg->_u.faccessat_msg.minor)->faccess((const char *)(msg->_u.faccessat_msg.pathname), msg->_u.faccessat_msg.amode, msg->_u.faccessat_msg.flags);

      msg->msg_id |= 0x80;
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == FSTAT) {
      
      emscripten_log(EM_LOG_CONSOLE, "localfs: FSTAT from %d: %d", msg->pid, msg->_u.fstat_msg.fd);

      struct stat stat_buf;

      int i = find_fd_entry(msg->_u.fstat_msg.fd);

      if (i >= 0) {

	int min = fds[i].minor;

	stat_buf.st_dev = makedev(major, min);
	stat_buf.st_ino = (ino_t)&devices[min];
	stat_buf.st_nlink = 1;	
	stat_buf.st_uid = 1;
	stat_buf.st_gid = 1;
	
	int _errno = 0;

	if ((_errno=get_device(min)->stat((const char *)fds[i].pathname, &stat_buf)) == 0) {
	
	  msg->_u.fstat_msg.len = sizeof(struct stat);
	  memcpy(msg->_u.fstat_msg.buf, &stat_buf, sizeof(struct stat)); 
	}
	
	msg->_errno = _errno;
      }
      else {

	msg->_errno = EBADF;
      }

      msg->msg_id |= 0x80;
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

    }
    else if (msg->msg_id == FSYNC) {
      
      emscripten_log(EM_LOG_CONSOLE, "localfs: FSYNC from %d: %d", msg->pid, msg->_u.fsync_msg.fd);
      
      msg->_errno = 0;
      msg->msg_id |= 0x80;
      
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

    }
    else if (msg->msg_id == UNLINKAT) {

      msg->_errno = get_device(msg->_u.unlinkat_msg.minor)->unlink((const char *)msg->_u.unlinkat_msg.path, msg->_u.unlinkat_msg.flags);

      msg->msg_id |= 0x80;
      
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == RENAMEAT) {

      // struct renameat_message is longer than 1256, read remaining bytes

      char * buf2 = malloc(12+sizeof(struct renameat_message));

      memmove(buf2, buf, bytes_rec);

      int rem_bytes_rec = recvfrom(sock, buf2+bytes_rec, 12+sizeof(struct renameat_message)-bytes_rec, 0, (struct sockaddr *) &remote_addr, &len);

      //emscripten_log(EM_LOG_CONSOLE, "localfs: RENAMEAT bytes_rec=%d rem=%d (%d)", bytes_rec, rem_bytes_rec, sizeof(struct renameat_message));

      struct message * msg2 = (struct message *)&buf2[0];

      //emscripten_log(EM_LOG_CONSOLE, "localfs: RENAMEAT from %d: (%d %d %d) %s %s", msg2->pid, msg2->_u.renameat_msg.type, msg2->_u.renameat_msg.major, msg2->_u.renameat_msg.minor, msg2->_u.renameat_msg.oldpath, msg2->_u.renameat_msg.newpath);

      char newpath[1024];

      sprintf(newpath, "/home%s", (const char *)msg2->_u.renameat_msg.newpath);

      //emscripten_log(EM_LOG_CONSOLE, "localfs: RENAMEAT: newpath=%s", newpath);
      
      msg2->_errno = get_device(msg2->_u.renameat_msg.minor)->rename((const char *)msg2->_u.renameat_msg.oldpath, (const char *)&newpath[0]);
      
      //emscripten_log(EM_LOG_CONSOLE, "localfs: RENAMEAT from %d: errno=%d", msg2->pid, msg2->_errno);

      msg2->msg_id |= 0x80;
      
      sendto(sock, buf2, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

      free(buf2);
    }
    else if (msg->msg_id == FTRUNCATE) {

      emscripten_log(EM_LOG_CONSOLE, "localfs: FTRUNCATE from %d: fd=%d length=%d", msg->pid, msg->_u.ftruncate_msg.fd, msg->_u.ftruncate_msg.length);

      struct device_ops * dev = NULL;

      int i = find_fd_entry(msg->_u.ftruncate_msg.fd);

      if (i >= 0) {
        
	dev = get_device(fds[i].minor);
      }
      
      if (dev) {
      
	msg->_errno = dev->ftruncate(msg->_u.ftruncate_msg.fd, msg->_u.ftruncate_msg.length);
      }
      else {

	msg->_errno = EBADF;
      }
      
      msg->msg_id |= 0x80;
      
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    
    }
    else if (msg->msg_id == MKDIRAT) {

      emscripten_log(EM_LOG_CONSOLE, "localfs: MKDIRAT from %d: path=%s", msg->pid, msg->_u.mkdirat_msg.path);
      
      struct device_ops * dev = NULL;

      dev = get_device(msg->_u.mkdirat_msg.minor);
      
      if (dev) {
      
	msg->_errno = dev->mkdir(msg->_u.mkdirat_msg.path, msg->_u.mkdirat_msg.mode);
      }
      else {

	msg->_errno = EBADF;
      }
      
      msg->msg_id |= 0x80;
      
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == RMDIR) {

      emscripten_log(EM_LOG_CONSOLE, "localfs: RMDIR from %d: path=%s", msg->pid, msg->_u.rmdir_msg.path);
      
      struct device_ops * dev = NULL;

      dev = get_device(msg->_u.rmdir_msg.minor);
      
      if (dev) {
      
	msg->_errno = dev->unlink(msg->_u.rmdir_msg.path, 0);
      }
      else {

	msg->_errno = EBADF;
      }
      
      msg->msg_id |= 0x80;
      
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == FSTATAT) {

      emscripten_log(EM_LOG_CONSOLE, "FSTATAT from pid=%d: dirfd=%d %s", msg->pid, msg->_u.fstatat_msg.dirfd, msg->_u.fstatat_msg.pathname_or_buf);

      int i = find_fd_entry(msg->_u.fstatat_msg.dirfd);

      int _errno = ENOENT;
      
      if (i >= 0) {

	char path[1024];
	
	strcpy(path, fds[i].pathname);

	int l = strlen(path);

	if (path[l-1] != '/') {

	  if ( (l > 1) && (path[l-1] == '.') && (path[l-2] == '/') ) {

	    path[l-1] = 0;
	  }
	  else {
	    strcat(path, "/");
	  }
	}

	strcat(path, msg->_u.fstatat_msg.pathname_or_buf);

	emscripten_log(EM_LOG_CONSOLE, "FSTATAT: %s %s", fds[i].pathname, path);

	struct stat stat_buf;

	stat_buf.st_dev = makedev(major, fds[i].minor);
	stat_buf.st_ino = (ino_t)&devices[fds[i].minor];
	stat_buf.st_nlink = 1;	
	stat_buf.st_uid = 1;
	stat_buf.st_gid = 1;

	if ((_errno=get_device(fds[i].minor)->stat((const char *)path, &stat_buf)) == 0) {
	
	  msg->_u.fstatat_msg.len = sizeof(struct stat);
	  memcpy(msg->_u.fstatat_msg.pathname_or_buf, &stat_buf, sizeof(struct stat));
	}
      }
      
      msg->_errno = _errno;

      msg->msg_id |= 0x80;
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      
    }
  }
  
  return 0;
}
