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

#include "netcache.h"

#ifndef DEBUG
#define DEBUG 0
#endif

#include <emscripten.h>

#if DEBUG
#else
#define emscripten_log(...)
#endif

#define NETFS_VERSION "netfs v0.1.0"

#define NETFS_PATH "/var/netfs.peer"
#define RESMGR_PATH "/var/resmgr.peer"

#define NB_NETFS_MAX  16
#define NB_FD_MAX     128

#define LOCALHOST_MINOR 5

struct device_ops {

  int (*open)(const char *pathname, int flags, mode_t mode, pid_t pid, unsigned short minor);
  ssize_t (*read)(int fd, void *buf, size_t count);
  ssize_t (*write)(int fildes, const void *buf, size_t nbyte);
  int (*ioctl)(int fildes, int request, ... /* arg */);
  int (*close)(int fd);
  int (*stat)(const char *pathname, struct stat * stat, unsigned short minor);
  ssize_t (*getdents)(int fd, char * buf, ssize_t count);
  int (*seek)(int fd, int offset, int whence);
  int (*faccess)(const char *pathname, int amode, int flags, unsigned short minor);

  char root[128];
};

struct fd_entry {

  int fd;
  pid_t pid;
  unsigned short minor;
  char pathname[1024];
  int flags;
  unsigned short mode;
  unsigned int size;
  unsigned int offset;
};

static unsigned short major;
static unsigned short minor = 0;

static struct device_ops * devices[NB_NETFS_MAX];

static int last_fd = 0;

static struct fd_entry fds[NB_FD_MAX];

int add_fd_entry(pid_t pid, unsigned short minor, const char * pathname, int flags, unsigned short mode, unsigned int size) {

  for (int i = 0; i < NB_FD_MAX; ++i) {

    if (fds[i].fd < 0) {

      ++last_fd;

      fds[i].fd = last_fd;
      fds[i].pid = pid;
      fds[i].minor = minor;
      strcpy(fds[i].pathname, pathname);
      fds[i].flags = flags;
      fds[i].mode = mode;
      fds[i].size = size;
      fds[i].offset = 0;

      return last_fd;
    }
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

EM_JS(int, do_fetch_head, (const char * root, const char * pathname), {
    
  return Asyncify.handleSleep(function (wakeUp) {

      var myHeaders = new Headers();

      var myInit = { method: 'HEAD',
	headers: myHeaders,
	mode: 'cors',
	cache: 'default' };

      let path = UTF8ToString(pathname);
      let sep = "/";

      if (path[0] == '/')
	sep = "";
      
	fetch(UTF8ToString(root) + sep + path, myInit).then(function (response) {

	    //console.log(response);
	    //console.log(response.headers);
	    //console.log(response.headers.get('Accept-Ranges'));
	    //console.log(response.headers.get('Content-Length'));

	    if (response.ok) {

	      let contentLength = 0;

	      if (typeof response.headers.get('Content-Length') == 'string') {
		contentLength = parseInt(response.headers.get('Content-Length'));
	      }
	    
	      wakeUp(contentLength);
	    }
	    else
	      wakeUp(-2); // NOENT
	  }).catch((error) => {

	      wakeUp(-2); // NOENT
	      
	    });
  });
});

EM_JS(int, do_fetch, (const char * root, const char * pathname, unsigned int offset, void * buf, unsigned int count), {
    
  return Asyncify.handleSleep(function (wakeUp) {

      let range = {};

      if (count > 0)
	range = {'Range': 'bytes='+offset+'-'+(offset+count-1)};

      var myHeaders = new Headers(range);

      var myInit = { method: 'GET',
	headers: myHeaders,
	mode: 'cors',
	cache: 'default' };

      let path = UTF8ToString(pathname);
      let sep = "/";

      if (path[0] == '/')
	sep = "";
      
	fetch(UTF8ToString(root) + sep + path, myInit).then(function (response) {
	  
	    /*console.log(response.headers.get('Accept-Ranges'));
	      console.log(response.headers.get('Content-Length'));
	      console.log(response.headers.get('Content-Size'));*/

	    //console.log(response);
	    //console.log(response.headers);

	    if (response.ok) {
	    
	      response.arrayBuffer().then(buffer => {

		  Module.HEAPU8.set(new Uint8Array(buffer), buf);
		
		  wakeUp(buffer.byteLength);
		});
	    
	    }
	    else
	      wakeUp(-2); // NOENT
	  }).catch((error) => {

	      wakeUp(-2); // NOENT
	      
	    });
  });
});

static void encode(char * buf, const char * pathname) {

  int offset = strlen(buf);

  int j = 0;
  
  for (; pathname[j]; ++j) { // starts after =
    
    if (pathname[j] == '+') {

      buf[offset+j] = '%';
      buf[offset+j+1] = '2';
      buf[offset+j+2] = 'B';
      
      offset+=2;
    }
    else if (pathname[j] == '&') {

      buf[offset+j] = '%';
      buf[offset+j+1] = '2';
      buf[offset+j+2] = '6';
      
      offset+=2;
    }
    else {
      buf[offset+j] = pathname[j];
    }
  }

  buf[offset+j] = 0;
}

static ssize_t netfs_read(int fd, void * buf, size_t count) {

  int i = find_fd_entry(fd);

  if (i < 0)
    return -EBADF;

  emscripten_log(EM_LOG_CONSOLE,"netfs_read: %d %d %d %d", fd, count, fds[i].offset, fds[i].size);
  
  if (fds[i].offset >= fds[i].size) {

    return 0;
  }

  int size = netcache_read(fds[i].pathname, fds[i].offset, buf, count);

  if (size < 0) {

    emscripten_log(EM_LOG_CONSOLE,"netfs_read: %s not cached", fds[i].pathname);

    char * data = (char *)malloc(fds[i].size);

    if (!data) {

      return -ENOMEM;
    }

    char buf2[1256];

    buf2[0] = 0;

    encode(buf2, fds[i].pathname);
    
    size = do_fetch(devices[fds[i].minor]->root, buf2/*fds[i].pathname*/, 0, data, 0); // count=0 means all file i.e no range

    emscripten_log(EM_LOG_CONSOLE,"netfs_read: %d bytes fetched (/%d)", size, fds[i].size);

    if (size != fds[i].size) {

      free(data);
      
      return -EIO;
    }

    if (size >= 0) {
      
      netcache_write(fds[i].pathname, data, size);

      int count2 = (count <= (size-fds[i].offset))?count:size-fds[i].offset;
      
      memmove(buf, data+fds[i].offset, count2);
    }

    if (size <= 0)
      free(data);

    size = (count <= (fds[i].size-fds[i].offset))?count:fds[i].size-fds[i].offset;    
  }

  emscripten_log(EM_LOG_CONSOLE, "netfs_read: %d bytes", size);

  if (size >= 0) {

    fds[i].offset += size;

    return size;
  }
  
  return -EIO;
}

static ssize_t netfs_write(int fd, const void * buf, size_t count) {

  
  return 0;
}

static int netfs_ioctl(int fildes, int request, ... /* arg */) {

  return EINVAL;
}

static int netfs_close(int fd) {

  int i = find_fd_entry(fd);

  if (i < 0)
    return EBADFD;

  fds[i].fd = -1;
  
  return 0;
}

static int netfs_stat(const char * pathname, struct stat * stat, unsigned short minor) {

  emscripten_log(EM_LOG_CONSOLE, "netfs_stat: %s", pathname);

  int _errno = ENOENT;

  _errno = netcache_get_stat(pathname, stat);

  if (_errno != ENOTCACHED) {

    emscripten_log(EM_LOG_CONSOLE, "netfs_stat: found in cache");
    return _errno;
  }

  emscripten_log(EM_LOG_CONSOLE, "netfs_stat: NOT found in cache");
  
  _errno = ENOENT;

  char buf[1256];

  emscripten_log(EM_LOG_CONSOLE, "netfs_stat: do_fetch minor=%d root=%s", minor, devices[minor]->root);
  
  //sprintf(buf, "../query?stat=%s", pathname);
  strcpy(buf, "../query?stat=");

  encode(buf, pathname);
  
  int size = do_fetch(devices[minor]->root, buf, 0, buf, 1256);
  
  if (size > 0) {

    buf[size] = 0;

    emscripten_log(EM_LOG_CONSOLE, "netfs_stat result\n%s", buf);

    char delim[] = "\n";

    char * ptr = strtok(buf, delim);

    while (ptr != NULL) {

      char * ptr2 = strchr(ptr, '=');

      if (!ptr2)
	continue;
      
      if (strncmp(ptr, "errno", 5) == 0) {

	_errno = -atoi(ptr2+1); // Return the positive value
      }
      else if (strncmp(ptr, "mode", 4) == 0) {

	stat->st_mode = atoi(ptr2+1);

	emscripten_log(EM_LOG_CONSOLE, "netfs_stat mode=%d %d %d", stat->st_mode, S_ISDIR(stat->st_mode), S_ISREG(stat->st_mode));
      }
      else if (strncmp(ptr, "size", 4) == 0) {

	stat->st_size = atoi(ptr2+1);
      }
      
      ptr = strtok(NULL, delim);
    }
  }

  int i = 0;
    
  for (char * c = pathname; *c; ++c)
    i += *c;

  stat->st_ino = i;
  
  netcache_set_stat(pathname, stat, _errno);

  emscripten_log(EM_LOG_CONSOLE, "<-- netfs_stat: errno=%d", _errno);

  return _errno;
}

static int netfs_open(const char * pathname, int flags, mode_t mode, pid_t pid, unsigned short minor) {

  emscripten_log(EM_LOG_CONSOLE,"netfs_open: %s", pathname);

  int _errno;
  struct stat stat;

  if ((_errno=netfs_stat(pathname, &stat, minor)) == 0) {

    if ( (flags & O_DIRECTORY) && (!S_ISDIR(stat.st_mode)) )    // Error pathname is not a directory
	return -ENOTDIR;
    
    int remote_fd =  add_fd_entry(pid, minor, pathname, flags, mode, stat.st_size);

    emscripten_log(EM_LOG_CONSOLE,"<-- netfs_open: remote_fd=%d", remote_fd);

    return remote_fd;
  }

  emscripten_log(EM_LOG_CONSOLE,"<-- netfs_open: errno=%d", _errno);

  return -_errno; // Return the negative value
}

struct __dirent {
    ino_t d_ino;
    off_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[1];
  };

static ssize_t netfs_getdents(int fd, char * data_buf, ssize_t count) {

  int i = find_fd_entry(fd);

  if (i < 0)
    return -1;

  int dents_size = 0;
  int _errno = 0;
  
  char * dents = netcache_get_dents(fds[i].pathname, &dents_size, &_errno);

  if (_errno == ENOTCACHED) {

    emscripten_log(EM_LOG_CONSOLE, "netfs_getdents: not cached");

    char buf2[2048];
    
    //sprintf(buf2, "../query?getdents=%s", fds[i].pathname);
    strcpy(buf2, "../query?getdents=");

    encode(buf2, fds[i].pathname);

    int tmp_size = 8192;
    char * tmp = (char *)malloc(tmp_size+1);
    tmp_size = do_fetch(devices[fds[i].minor]->root, buf2, 0, tmp, tmp_size);
      
    tmp[tmp_size] = 0;

    int buf_size = 8192;
    char * buf = (char *)malloc(8192);
    int buf_offset = 0;

    emscripten_log(EM_LOG_CONSOLE, "**** tmp_size=%d tmp: %s", tmp_size, tmp);
    
    char * ptr = tmp;
    
    _errno = 0;
  
    while (ptr != NULL) {
    
	char * ptr2 = strchr(ptr, '=');

	if (ptr2) {
      
	  if (strncmp(ptr, "errno", 5) == 0) {
	    
	    _errno = atoi(ptr2+1);
	  
	    if (_errno) {

	      netcache_set_dents(fds[i].pathname, NULL, 0, _errno);
	      break;
	    }
	  }
	}
	else {

	  struct __dirent * dirent_ptr = (struct __dirent *)(buf+buf_offset);

	  ptr2 = strchr(ptr, ';');

	  if (ptr2) {

	    if ((buf_offset+sizeof(struct __dirent)+ptr2-ptr+1) < buf_size) {  // there is space for this entry

	      strncpy(dirent_ptr->d_name, ptr, ptr2-ptr);
	      dirent_ptr->d_name[ptr2-ptr] = 0;
	      
	      emscripten_log(EM_LOG_CONSOLE, "*** %d: %s", buf_offset, dirent_ptr->d_name);
	  
	      ptr = ptr2+1;
	
	      ptr2 = strchr(ptr, ';');

	      char str_mode[8];

	      strncpy(str_mode, ptr, ptr2-ptr);
	      str_mode[ptr2-ptr] = 0;

	      int mode = atoi(str_mode);

	      emscripten_log(EM_LOG_CONSOLE, "*** %d: mode=%s %d", buf_offset, str_mode, mode);

	      if (S_ISDIR(mode)) {

		dirent_ptr->d_type = DT_DIR;
	      }
	      else if (S_ISREG(mode)) {

		dirent_ptr->d_type = DT_REG;
	      }
	      else {

		dirent_ptr->d_type = DT_REG;
	      }

	      ptr = ptr2+1;
	
	      ptr2 = strchr(ptr, '\n');

	      char str_size[16];

	      strncpy(str_size, ptr, ptr2-ptr);
	      str_size[ptr2-ptr] = 0;

	      int size = atoi(str_size);
	  
	      dirent_ptr->d_reclen = sizeof(struct __dirent) + strlen(dirent_ptr->d_name);
	  
	      buf_offset += dirent_ptr->d_reclen;

	      dirent_ptr->d_off = buf_offset;

	      // add stat in cache for each entry

	      struct stat stat_buf;
	      char pathname[1024];

	      strcpy(pathname, fds[i].pathname);

	      int str_len = strlen(pathname);

	      if ( (str_len > 1) && (pathname[str_len-1] == '.') && (pathname[str_len-2] == '/') ) {

		pathname[str_len-1] = 0;
	      }
	      else if ( (str_len > 2) && (pathname[str_len-1] == '/') && (pathname[str_len-2] == '.') && (pathname[str_len-3] == '/') ) {

		pathname[str_len-1] = 0;
		pathname[str_len-2] = 0;
	      }
	      else if ( (str_len > 0) && (pathname[str_len-1] != '/') ) {

		pathname[str_len] = '/';
		pathname[str_len+1] = 0;
	      }

	      strcat(pathname, dirent_ptr->d_name);

	      emscripten_log(EM_LOG_CONSOLE, "Add stat in cache for: %s", pathname);

	      stat_buf.st_dev = makedev(major, fds[i].minor);
	      stat_buf.st_ino = (ino_t)&devices[fds[i].minor];
	      stat_buf.st_mode = mode;
	      stat_buf.st_size = size;
	      stat_buf.st_nlink = 1;	
	      stat_buf.st_uid = 1;
	      stat_buf.st_gid = 1;

	      netcache_set_stat(pathname, &stat_buf, 0);
	    }
	  }
	  else {

	    break;
	  }
	}

	ptr = strchr(ptr, '\n');
    
	if (ptr)
	  ptr += 1;
    }

    if (_errno == 0) {
      
      netcache_set_dents(fds[i].pathname, buf, buf_offset, _errno);

      dents = buf;
      dents_size = buf_offset;
    }
    else {
      
      free(buf);
    }

    free(tmp);
  }

  emscripten_log(EM_LOG_CONSOLE, "*** _errno=%d dents_size=%d fds[i].offset=%d", _errno, dents_size, fds[i].offset);

  if (_errno)
    return -_errno;

  if (!dents || fds[i].offset >= dents_size)
    return 0;
  
  char * start = dents+fds[i].offset;
  int len = 0;

  while ((fds[i].offset+len) < dents_size) {

    struct __dirent * dirent_ptr = (struct __dirent *)(start+len);

    if ((len+dirent_ptr->d_reclen) > count)
      break;

    len += dirent_ptr->d_reclen;
  }

  if (len > 0) {
    memmove(data_buf, start, len);
    fds[i].offset += len;
  }
  
  emscripten_log(EM_LOG_CONSOLE, "*** start=%d len=%d", start, len);
    
  return len;
}

static int netfs_seek(int fd, int offset, int whence) {

  int i = find_fd_entry(fd);

  if (i < 0)
    return -EBADF;

  emscripten_log(EM_LOG_CONSOLE,"netfs_seek: %d %d %d %d", fd, offset, whence, fds[i].offset);

  switch(whence) {

    case SEEK_SET:

      fds[i].offset = offset;

      break;

    case SEEK_CUR:

      fds[i].offset += offset;

      break;

    case SEEK_END:

      fds[i].offset = fds[i].size + offset;
      
      break;

    default:

      break;
    }

  emscripten_log(EM_LOG_CONSOLE,"netfs_seek -> %d", fds[i].offset);

  return fds[i].offset;
}

static int netfs_faccess(const char * pathname, int amode, int flags, unsigned short minor) {

  if (amode & W_OK)
    return EACCES;

  char buf[1256];

  buf[0] = 0;

  encode(buf, pathname);

  if (do_fetch_head(devices[minor]->root, buf/*pathname*/) < 0)
    return EACCES;
      
  return 0;
}

static struct device_ops netfs_ops = {

  .open = netfs_open,
  .read = netfs_read,
  .write = netfs_write,
  .ioctl = netfs_ioctl,
  .close = netfs_close,
  .stat = netfs_stat,
  .getdents = netfs_getdents,
  .seek = netfs_seek,
  .faccess = netfs_faccess,
  .root = "/netfs",
};

static struct device_ops localhost_ops = {

  .open = netfs_open,
  .read = netfs_read,
  .write = netfs_write,
  .ioctl = netfs_ioctl,
  .close = netfs_close,
  .stat = netfs_stat,
  .getdents = netfs_getdents,
  .seek = netfs_seek,
  .faccess = netfs_faccess,
  .root = "http://localhost:7777",
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
  
  emscripten_log(EM_LOG_CONSOLE, "Starting " NETFS_VERSION "...");

  for (int i = 0; i < NB_FD_MAX; ++i) {
    
    fds[i].fd = -1;
  }

  int fd = open("/dev/tty1", O_WRONLY | O_NOCTTY);
  
  if (fd >= 0)
    write(fd, "\n\r[" NETFS_VERSION "]", strlen("\n\r[" NETFS_VERSION "]")+1);

  close(fd);
  
  /* Create the server local socket */
  sock = socket (AF_UNIX, SOCK_DGRAM, 0);
  if (sock < 0) {
    return -1;
  }

  /* Bind server socket to NETFS_PATH */
  memset(&local_addr, 0, sizeof(local_addr));
  local_addr.sun_family = AF_UNIX;
  strcpy(local_addr.sun_path, NETFS_PATH);
  
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
  
  strcpy((char *)&msg->_u.dev_msg.dev_name[0], "netfs");
  
  sendto(sock, buf, 1256, 0, (struct sockaddr *) &resmgr_addr, sizeof(resmgr_addr));

  netcache_init();

  while (1) {
    
    bytes_rec = recvfrom(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, &len);

    emscripten_log(EM_LOG_CONSOLE,"*** netfs: %d", msg->msg_id);

    if (msg->msg_id == (REGISTER_DRIVER|0x80)) {

      if (msg->_errno)
	continue;

      major = msg->_u.dev_msg.major;

      emscripten_log(EM_LOG_CONSOLE,"REGISTER_DRIVER successful: major=%d", major);

      minor += 1;
	
      register_device(minor, (minor < LOCALHOST_MINOR)?&netfs_ops:&localhost_ops);
      
      msg->msg_id = REGISTER_DEVICE;
      msg->_u.dev_msg.minor = minor;

      memset(msg->_u.dev_msg.dev_name, 0, sizeof(msg->_u.dev_msg.dev_name));
      sprintf((char *)&msg->_u.dev_msg.dev_name[0], "netfs%d", msg->_u.dev_msg.minor);
  
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &resmgr_addr, sizeof(resmgr_addr));
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

      switch(minor) {

      case 1:

	strcpy((char *)&msg->_u.mount_msg.pathname[0], "/bin");
	break;

      case 2:

	strcpy((char *)&msg->_u.mount_msg.pathname[0], "/usr");
	break;

      case 3:

	strcpy((char *)&msg->_u.mount_msg.pathname[0], "/etc");
	break;

      case 4:

	strcpy((char *)&msg->_u.mount_msg.pathname[0], "/lib64");
	break;

      case LOCALHOST_MINOR:

	strcpy((char *)&msg->_u.mount_msg.pathname[0], "/media/localhost");
	break;

      default:
	break;
      }
      
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &resmgr_addr, sizeof(resmgr_addr));
    }
    else if (msg->msg_id == (MOUNT|0x80)) {

      if (msg->_errno)
	continue;

      emscripten_log(EM_LOG_CONSOLE, "MOUNT successful: %d,%d,%d", msg->_u.mount_msg.dev_type, msg->_u.mount_msg.major, msg->_u.mount_msg.minor);

      if (msg->_u.mount_msg.minor < LOCALHOST_MINOR) {
	
	minor += 1;
	
	register_device(minor, (minor < LOCALHOST_MINOR)?&netfs_ops:&localhost_ops);
      
	msg->msg_id = REGISTER_DEVICE;
	msg->_u.dev_msg.dev_type = FS_DEV;	
	msg->_u.dev_msg.major = major;
	msg->_u.dev_msg.minor = minor;

	memset(msg->_u.dev_msg.dev_name, 0, sizeof(msg->_u.dev_msg.dev_name));
	sprintf((char *)&msg->_u.dev_msg.dev_name[0], "netfs%d", msg->_u.dev_msg.minor);
  
	sendto(sock, buf, 1256, 0, (struct sockaddr *) &resmgr_addr, sizeof(resmgr_addr));
      }
    }
    
    else if (msg->msg_id == OPEN) {

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

      if (remote_fd >= 0) {

	msg->_u.open_msg.remote_fd = remote_fd;
	msg->_errno = 0;
      }
      else {

	msg->_u.open_msg.remote_fd = -1;
	msg->_errno = -remote_fd;
      }
      
      msg->msg_id |= 0x80;
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == READ) {

      emscripten_log(EM_LOG_CONSOLE, "netfs: READ (%d) from %d", READ, msg->pid);

      //TODO: no malloc if buffer is large enough

      int reply_size = 12+sizeof(struct io_message)+msg->_u.io_msg.len;

      struct message * reply = (struct message *) malloc(reply_size);

      if (!reply) {

	msg->msg_id |= 0x80;
	msg->_errno = ENOMEM;
	sendto(sock, buf, 256, 0, (struct sockaddr *) &resmgr_addr, sizeof(resmgr_addr));
	continue;
      }

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

	  reply->_errno = -reply->_u.io_msg.len;
	  reply->_u.io_msg.len = 0;
	}

	emscripten_log(EM_LOG_CONSOLE, "READ successful: %d bytes", reply->_u.io_msg.len);
      }
      else {

	emscripten_log(EM_LOG_CONSOLE, "READ error: %d %d", msg->_u.io_msg.fd, fds[msg->_u.io_msg.fd].minor);
	
	reply->_errno = ENXIO;
      }
      
      sendto(sock, reply, reply_size, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

      free(reply);
    }
    else if (msg->msg_id == WRITE) {
      
      //TODO
    }
    else if (msg->msg_id == IOCTL) {

      msg->_errno = EPERM;
      
      msg->msg_id |= 0x80;
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == CLOSE) {

      emscripten_log(EM_LOG_CONSOLE, "netfs: CLOSE -> fd=%d", msg->_u.close_msg.fd);

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
      
      emscripten_log(EM_LOG_CONSOLE, "netfs: STAT from %d: %s", msg->pid, msg->_u.stat_msg.pathname_or_buf);

      struct stat stat_buf;

      stat_buf.st_dev = makedev(msg->_u.stat_msg.major, msg->_u.stat_msg.minor);
      stat_buf.st_ino = (ino_t)&devices[msg->_u.stat_msg.minor];
      stat_buf.st_nlink = 1;	
      stat_buf.st_uid = 1;
      stat_buf.st_gid = 1;

      int _errno = 0;

      if ((_errno=get_device(msg->_u.stat_msg.minor)->stat((const char *)(msg->_u.stat_msg.pathname_or_buf), &stat_buf, msg->_u.stat_msg.minor)) == 0) {
	
	msg->_u.stat_msg.len = sizeof(struct stat);
	memcpy(msg->_u.stat_msg.pathname_or_buf, &stat_buf, sizeof(struct stat));

	msg->_errno = 0;
      }
      else {

	msg->_errno = _errno;
      }

      msg->msg_id |= 0x80;
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == GETDENTS) {

      emscripten_log(EM_LOG_CONSOLE, "netfs: GETDENTS from %d: fd=%d len=%d", msg->pid, msg->_u.getdents_msg.fd, msg->_u.getdents_msg.len);

      struct device_ops * dev = NULL;
      
      int i = find_fd_entry(msg->_u.getdents_msg.fd);

      if (i >= 0) {
        
	dev = get_device(fds[i].minor);
      }

      char * buf2 = buf;
      struct message * msg2 = msg;
      
      if (dev) {

	ssize_t count = 0;
	
	if (msg->_u.getdents_msg.len < 1024) {
	  
	  count = dev->getdents(msg->_u.getdents_msg.fd, (char *)&(msg->_u.getdents_msg.buf[0]), msg->_u.getdents_msg.len);
	}
	else {

	  buf2 = malloc(12+sizeof(struct getdents_message)+msg->_u.getdents_msg.len);

	  if (!buf2) {

	    emscripten_log(EM_LOG_CONSOLE, "GETDENTS from %d: no mem", msg->pid);
	  }
	  else {
	  
	    msg2 = (struct message *)&buf2[0];

	    msg2->msg_id = msg->msg_id;
	    msg2->pid = msg->pid;
	    msg2->_u.getdents_msg.fd = msg->_u.getdents_msg.fd;
	    msg2->_u.getdents_msg.len = msg->_u.getdents_msg.len;

	    count = dev->getdents(msg2->_u.getdents_msg.fd, (char *)&(msg2->_u.getdents_msg.buf[0]), msg2->_u.getdents_msg.len);
	  }
	  
	}

	emscripten_log(EM_LOG_CONSOLE, "GETDENTS from %d: --> count=%d", msg->pid, count);

	if (count >= 0) {
	  
	  msg2->_u.getdents_msg.len = count;
	  msg2->_errno = 0;
	}
	else {

	  msg2->_u.getdents_msg.len = 0;
	  msg2->_errno = -count;
	}
      }
      else {
	
	msg2->_u.getdents_msg.len = 0;
	msg2->_errno = EBADF;
      }

      msg2->msg_id |= 0x80;

      sendto(sock, buf2, 12+sizeof(struct getdents_message)+msg2->_u.getdents_msg.len, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

      if (buf2 && (buf2 != buf))
	free(buf2);
    }
    else if (msg->msg_id == CHDIR) {

      emscripten_log(EM_LOG_CONSOLE, "netfs: CHDIR from %d", msg->pid);

      struct stat stat_buf;

      msg->_errno = get_device(msg->_u.cwd2_msg.minor)->stat((const char *)(msg->_u.cwd2_msg.buf), &stat_buf, msg->_u.cwd2_msg.minor);

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

      msg->_errno = get_device(msg->_u.faccessat_msg.minor)->faccess((const char *)(msg->_u.faccessat_msg.pathname), msg->_u.faccessat_msg.amode, msg->_u.faccessat_msg.flags, msg->_u.faccessat_msg.minor);

      msg->msg_id |= 0x80;
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == FSTAT) {
      
      emscripten_log(EM_LOG_CONSOLE, "netfs: FSTAT from %d: %d", msg->pid, msg->_u.fstat_msg.fd);

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

	if ((_errno=get_device(min)->stat((const char *)fds[i].pathname, &stat_buf, min)) == 0) {
	
	  msg->_u.fstat_msg.len = sizeof(struct stat);
	  memcpy(msg->_u.fstat_msg.buf, &stat_buf, sizeof(struct stat));

	  msg->_errno = 0;
	}
	else {

	  msg->_errno = _errno;
	}
      }
      else {

	msg->_errno = EBADF;
      }

      msg->msg_id |= 0x80;
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

    }
    else if (msg->msg_id == UNLINKAT) {

      msg->_errno = EPERM;

      msg->msg_id |= 0x80;
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == RENAMEAT) {

      msg->_errno = EPERM;

      msg->msg_id |= 0x80;
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == FSTATAT) {

      emscripten_log(EM_LOG_CONSOLE, "netfs FSTATAT from pid=%d: dirfd=%d %s", msg->pid, msg->_u.fstatat_msg.dirfd, msg->_u.fstatat_msg.pathname_or_buf);

      char path[1024];
      
      int i = find_fd_entry(msg->_u.fstatat_msg.dirfd);

      int _errno = ENOENT;
      
      if (i >= 0) {
	
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

	struct stat stat_buf;

	stat_buf.st_dev = makedev(major, fds[i].minor);
	stat_buf.st_ino = (ino_t)&devices[fds[i].minor];
	stat_buf.st_nlink = 1;	
	stat_buf.st_uid = 1;
	stat_buf.st_gid = 1;

	if ((_errno=get_device(fds[i].minor)->stat((const char *)path, &stat_buf, fds[i].minor)) == 0) {

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
