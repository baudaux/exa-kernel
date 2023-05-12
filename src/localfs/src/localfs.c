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

#include <emscripten.h>

#define DEBUG 0

#define LOCALFS_VERSION "localfs v0.1.0"

#define LOCALFS_PATH "/var/localfs.peer"
#define RESMGR_PATH "/var/resmgr.peer"

#define NB_LOCALFS_MAX  16
#define NB_FD_MAX     128

struct device_ops {

  int (*open)(const char *pathname, int flags, mode_t mode, pid_t pid, unsigned short minor);
  ssize_t (*read)(int fd, void *buf, size_t count);
  ssize_t (*write)(int fildes, const void *buf, size_t nbyte);
  int (*ioctl)(int fildes, int request, ... /* arg */);
  int (*close)(int fd);
  int (*stat)(const char *pathname, struct stat * stat);
  ssize_t (*getdents)(int fd, char * buf, ssize_t count);
  int (*seek)(int fd, int offset, int whence);
  int (*faccess)(const char *pathname, int amode, int flags);
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

      return last_fd;
    }
  }

  return -1;
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


static ssize_t localfs_read(int fd, void * buf, size_t count) {

  int i = find_fd_entry(fd);

  if (i < 0)
    return -1;

  return lfs_file_read(&lfs, fds[i].lfs_handle, buf, count);
}

static ssize_t localfs_write(int fd, const void * buf, size_t count) {

  int i = find_fd_entry(fd);

  if (i < 0)
    return -1;

  return lfs_file_write(&lfs, fds[i].lfs_handle, buf, count);
}

static int localfs_ioctl(int fildes, int request, ... /* arg */) {

  return 0;
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

  if (res == LFS_ERR_OK)
    del_fd_entry(i);
  
  return res;
}

static int localfs_stat(const char * pathname, struct stat * stat) {

  if (DEBUG)
    emscripten_log(EM_LOG_CONSOLE,"localfs_stat: %s", pathname);
  
  struct lfs_info info;

  int res = lfs_stat(&lfs, pathname, &info);

  if (res == LFS_ERR_OK) {

    if (DEBUG)
      emscripten_log(EM_LOG_CONSOLE,"localfs_stat -> %d %d %s", info.type, info.size, info.name);
  }

  if ((res == LFS_ERR_OK) && stat) {

    stat->st_dev = makedev(major, 1);
    
    if (info.type == LFS_TYPE_REG) {
      stat->st_mode = S_IFREG;
      stat->st_size = info.size;
    }
    else if (info.type == LFS_TYPE_DIR){
      stat->st_mode = S_IFDIR;
      stat->st_size = 0;
    }
    else {
      stat->st_mode = S_IFREG;
      stat->st_size = 0;
    }
  }

  if (DEBUG)
    emscripten_log(EM_LOG_CONSOLE,"<-- localfs_stat: %d (mode=%d)", res, stat->st_mode);
  
  return res;
}

static int localfs_open(const char * pathname, int flags, mode_t mode, pid_t pid, unsigned short minor) {

  if (DEBUG)
    emscripten_log(EM_LOG_CONSOLE,"localfs_open: %s", pathname);

  int _errno;
  struct stat stat;

  _errno = localfs_stat(pathname, &stat);

  if ( (_errno == LFS_ERR_OK) || (flags & O_CREAT) ) {

    int lfs_flags = 0;
    int res = -1;
    void * lfs_handle = NULL;

    if (_errno != LFS_ERR_OK) {

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

    if (stat.st_mode == S_IFREG) {

      if (flags & O_DIRECTORY)   // Error pathname is not a directory
	return -1;

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE,"localfs_open -> lfs_open_file: %x %x", flags, lfs_flags);

      lfs_handle = malloc(sizeof(lfs_file_t));
      
      res = lfs_file_open(&lfs, (lfs_file_t *)lfs_handle, pathname, lfs_flags);
    }
    else if (stat.st_mode == S_IFDIR) {

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE,"localfs_open -> lfs_open_dir");

      lfs_handle = malloc(sizeof(lfs_dir_t));

      res = lfs_dir_open(&lfs, lfs_handle, pathname);
    }

    if (res == LFS_ERR_OK) {
      return add_fd_entry(pid, minor, pathname, flags, mode, stat.st_mode, stat.st_size, lfs_handle);
    }
    else {

      if (lfs_handle)
	free(lfs_handle);
      
      _errno = res;
    }
  }

  if (DEBUG)
      emscripten_log(EM_LOG_CONSOLE,"<-- localfs_open : errno=%d", _errno);

  return _errno;
  
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
    return -1;
  
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
      }
    }
  }
  
  return len;
}

static int localfs_seek(int fd, int offset, int whence) {

  int i = find_fd_entry(fd);

  if (i < 0)
    return -1;

  return lfs_file_seek(&lfs, fds[i].lfs_handle, offset, whence);
}

static int localfs_faccess(const char * pathname, int amode, int flags) {

  return 0;
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

    if (DEBUG)
	  emscripten_log(EM_LOG_CONSOLE, "*** localfs: %d", msg->msg_id);
    
    if (msg->msg_id == (REGISTER_DRIVER|0x80)) {

      if (msg->_errno)
	continue;

      major = msg->_u.dev_msg.major;

      if (DEBUG)
	  emscripten_log(EM_LOG_CONSOLE, "REGISTER_DRIVER successful: major=%d", major);

      int res = lfs_mount(&lfs, &lfs_config);

      if (DEBUG)
	  emscripten_log(EM_LOG_CONSOLE, "lfs_mount: res=%d", res);

      if (res < 0) {

	res = lfs_format(&lfs, &lfs_config);

	if (DEBUG)
	  emscripten_log(EM_LOG_CONSOLE, "lfs_format: res=%d", res);

	if (res == 0) {

	  res = lfs_mount(&lfs, &lfs_config);
	  
	  if (DEBUG)
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

      if (DEBUG)
	  emscripten_log(EM_LOG_CONSOLE, "REGISTER_DEVICE successful: %d,%d,%d", msg->_u.dev_msg.dev_type, msg->_u.dev_msg.major, msg->_u.dev_msg.minor);

      unsigned short minor = msg->_u.dev_msg.minor;

      msg->msg_id = MOUNT;
      msg->_u.mount_msg.dev_type = FS_DEV;
      msg->_u.mount_msg.major = major;
      msg->_u.mount_msg.minor = minor;

      memset(msg->_u.mount_msg.pathname, 0, sizeof(msg->_u.mount_msg.pathname));

      if (minor == 1) {

	int res = lfs_mkdir(&lfs, "/home");

	if (DEBUG)
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

      int remote_fd = get_device(msg->_u.open_msg.minor)->open((const char *)(msg->_u.open_msg.pathname), msg->_u.open_msg.flags, msg->_u.open_msg.mode, msg->pid, msg->_u.open_msg.minor);

      if (remote_fd >= 0) {

	msg->_u.open_msg.remote_fd = remote_fd;
	msg->_errno = 0;
      }
      else {

	msg->_u.open_msg.remote_fd = -1;
	msg->_errno = ENOENT;
      }
      
      msg->msg_id |= 0x80;
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == READ) {

      struct message * reply = (struct message *) malloc(sizeof(struct message)+msg->_u.io_msg.len);

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
	reply->_errno = 0;

	emscripten_log(EM_LOG_CONSOLE, "READ successful: %d bytes", reply->_u.io_msg.len);
      }
      else {

	emscripten_log(EM_LOG_CONSOLE, "READ error: %d %d", msg->_u.io_msg.fd, fds[msg->_u.io_msg.fd].minor);
	reply->_errno = ENXIO;
      }
      
      sendto(sock, reply, sizeof(struct message)+reply->_u.io_msg.len, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

      free(reply);
    }
    else if (msg->msg_id == WRITE) {
      
      struct device_ops * dev = NULL;

      int i = find_fd_entry(msg->_u.io_msg.fd);

      if (i >= 0) {
        
	dev = get_device(fds[i].minor);
      }
      
      if (dev) {
	
	msg->_u.io_msg.len = dev->write(msg->_u.io_msg.fd, msg->_u.io_msg.buf, msg->_u.io_msg.len);
	msg->_errno = 0;
      }
      else {

	msg->_errno = EBADF;
      }

      msg->msg_id |= 0x80;
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
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
      stat_buf.st_ino = 1;

      int _errno = 0;

      if ((_errno=get_device(msg->_u.stat_msg.minor)->stat((const char *)(msg->_u.stat_msg.pathname_or_buf), &stat_buf)) == 0) {
	
	msg->_u.stat_msg.len = sizeof(struct stat);
	memcpy(msg->_u.stat_msg.pathname_or_buf, &stat_buf, sizeof(struct stat));

	msg->_errno = 0;
      }
      else {

	msg->_errno = -_errno;
      }

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
	  msg->_errno = EBADF;
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

      msg->_errno = get_device(1)->stat((const char *)(msg->_u.cwd_msg.buf), &stat_buf);

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
	  msg->_errno = EBADF;
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
    
  }
  
  return 0;
}