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

#include <emscripten.h>

#define DEBUG 0

#define NETFS_VERSION "netfs v0.1.0"

#define NETFS_PATH "/var/netfs.peer"
#define RESMGR_PATH "/var/resmgr.peer"

#define NB_NETFS_MAX  16
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
  char * data;
  unsigned int data_size;
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

EM_JS(int, do_fetch_head, (const char * pathname), {
    
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
      
      fetch("/netfs" + sep + path, myInit).then(function (response) {
	  
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
    });
  });
});

EM_JS(int, do_fetch, (const char * pathname, unsigned int offset, void * buf, unsigned int count), {
    
  return Asyncify.handleSleep(function (wakeUp) {

      var myHeaders = new Headers({'Range': 'bytes='+offset+'-'+(offset+count-1)});

      var myInit = { method: 'GET',
	headers: myHeaders,
	mode: 'cors',
	cache: 'default' };

      let path = UTF8ToString(pathname);
      let sep = "/";

      if (path[0] == '/')
	sep = "";
      
      fetch("/netfs" + sep + path, myInit).then(function (response) {
	  
	  //console.log(response.headers.get('Accept-Ranges'));
	  //console.log(response.headers.get('Content-Length'));

	  if (response.ok) {

	    let contentLength = 0;

	    if (typeof response.headers.get('Content-Size') == 'string') {
	      contentLength = parseInt(response.headers.get('Content-Size'));
	    }
	    else if (typeof response.headers.get('Content-Length') == 'string') {
	      contentLength = parseInt(response.headers.get('Content-Length'));
	    }

	    /*response.arrayBuffer().then(buffer => {
		
		Module.HEAPU8.set(buffer, buf);
		
		wakeUp(contentLength);
		});*/

	    response.text().then(text => {

		//console.log(text);
		stringToUTF8(text, buf, count);
		
		//Module.HEAPU8.set(buffer, buf);
		
		wakeUp(contentLength);
		})
	    
	  }
	  else
	    wakeUp(-2); // NOENT
	}).catch((error) => {
	    //console.error("Error:", error);
	  });
  });
});

static ssize_t netfs_read(int fd, void * buf, size_t count) {

  int i = find_fd_entry(fd);

  if (i < 0)
    return -1;

  if (DEBUG)
    emscripten_log(EM_LOG_CONSOLE,"netfs_read: %d %d %d %d", fd, count, fds[i].offset, fds[i].size);


  if (fds[i].offset >= fds[i].size) {

    return 0;
  }
  
  int size = do_fetch(fds[i].pathname, fds[i].offset, buf, count);

  if (DEBUG)
    emscripten_log(EM_LOG_CONSOLE,"netfs_read: %d bytes", size);

  if (size >= 0) {

    fds[i].offset += size;

    return size;
  }
  
  return -1;
}

static ssize_t netfs_write(int fd, const void * buf, size_t count) {

  
  return 0;
}

static int netfs_ioctl(int fildes, int request, ... /* arg */) {

  return 0;
}

static int netfs_close(int fd) {

  int i = find_fd_entry(fd);

  if (i < 0)
    return -1;

  fds[i].fd = -1;

  if (fds[i].data) {

    free(fds[i].data);
    fds[i].data = NULL;
  }
  
  return 0;
}

static int netfs_stat(const char * pathname, struct stat * stat) {

  if (DEBUG)
    emscripten_log(EM_LOG_CONSOLE, "netfs_stat: %s", pathname);

  char buf[1256];

  sprintf(buf, "../query?stat=%s", pathname);

  int size = do_fetch(buf, 0, buf, 1256);
  
  int _errno = -1;
  
  if (size > 0) {

    if (DEBUG)
      emscripten_log(EM_LOG_CONSOLE, "netfs_stat result\n%s", buf);

    char delim[] = "\n";

    char * ptr = strtok(buf, delim);

    while (ptr != NULL) {

      char * ptr2 = strchr(ptr, '=');

      if (!ptr2)
	continue;
      
      if (strncmp(ptr, "errno", 5) == 0) {

	_errno = atoi(ptr2+1);
      }
      else if (strncmp(ptr, "mode", 4) == 0) {

	stat->st_mode = atoi(ptr2+1);

	if (DEBUG)
	  emscripten_log(EM_LOG_CONSOLE, "netfs_stat mode=%d %d %d", stat->st_mode, S_ISDIR(stat->st_mode), S_ISREG(stat->st_mode));
      }
      else if (strncmp(ptr, "size", 4) == 0) {

	stat->st_size = atoi(ptr2+1);
      }
      
      ptr = strtok(NULL, delim);
    }
  
    return _errno;
  }

  return _errno;
}

static int netfs_open(const char * pathname, int flags, mode_t mode, pid_t pid, unsigned short minor) {

  if (DEBUG)
    emscripten_log(EM_LOG_CONSOLE,"netfs_open: %s", pathname);

  int _errno;
  struct stat stat;

  if ((_errno=netfs_stat(pathname, &stat)) == 0) {
    
    return add_fd_entry(pid, minor, pathname, flags, mode, stat.st_size);
  }

  return _errno;
}

struct __dirent {
    ino_t d_ino;
    off_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[1];
  };

static ssize_t netfs_getdents(int fd, char * buf, ssize_t count) {

  char buf2[2256];

  int i = find_fd_entry(fd);

  if (i < 0)
    return -1;

  if (!fds[i].data) {

    fds[i].data_size = 4096;
    fds[i].data = (char *)malloc(fds[i].data_size);
    
    sprintf(buf2, "../query?getdents=%s", fds[i].pathname);
  
    fds[i].data_size = do_fetch(buf2, 0, fds[i].data, 4096);

    fds[i].offset = 0;
  }

  if (fds[i].data_size < 0)
    return -1;

  if (fds[i].data_size == 0)
    return 0;
  
  if (DEBUG)
    emscripten_log(EM_LOG_CONSOLE, "netfs_getdents: fd=%d offset=%d\n", fd, fds[i].offset);

  char delim[] = "\n";

  int len = 0;

  char * ptr = strtok(fds[i].data+fds[i].offset, delim);

  while (ptr != NULL) {

    //emscripten_log(EM_LOG_CONSOLE, "**** ptr: %s", ptr);

    char * ptr2 = strchr(ptr, '=');

    if (ptr2) {
      
      if (strncmp(ptr, "errno", 5) == 0) {

	int _errno = atoi(ptr2+1);

	if (_errno)
	  return _errno;
      }
    }
    else {

      struct __dirent * dirent_ptr = (struct __dirent *)(buf+len);

      ptr2 = strchr(ptr, ';');

      if (ptr2) {

	strncpy(dirent_ptr->d_name, ptr, ptr2-ptr);

	if ((len+sizeof(struct __dirent)+strlen(dirent_ptr->d_name)) < count) {  // there is space for this entry

	  ///emscripten_log(EM_LOG_CONSOLE, "*** %d: %s", len, dirent_ptr->d_name);

	  ptr = ptr2+1;
	
	  ptr2 = strchr(ptr, ';');

	  char str_mode[8];

	  strncpy(str_mode, ptr, ptr2-ptr);

	  int mode = atoi(str_mode);

	  if (S_ISDIR(mode)) {

	    dirent_ptr->d_type = DT_DIR;
	  }
	  else if (S_ISREG(mode)) {

	    dirent_ptr->d_type = DT_REG;
	  }
	  else {

	    dirent_ptr->d_type = DT_REG;
	  }
	  
	  dirent_ptr->d_reclen = sizeof(struct __dirent) + strlen(dirent_ptr->d_name);
	  
	  len += dirent_ptr->d_reclen;

	  dirent_ptr->d_off = len;
	}
	else {

	  break;
	}
      }
    }

    ptr = strtok(NULL, delim);
  }

  if (ptr)
    fds[i].offset = ptr-fds[i].data;
  else
    fds[i].offset = strlen(fds[i].data);
    
  return len;
}

static int netfs_seek(int fd, int offset, int whence) {

  int i = find_fd_entry(fd);

  if (i < 0)
    return -1;

  switch(whence) {

    case SEEK_SET:

      fds[fd].offset = offset;

      break;

    case SEEK_CUR:

      fds[fd].offset += offset;

      break;

    case SEEK_END:

      fds[fd].offset = fds[fd].size + offset;
      
      break;

    default:

      break;
    }

  return fds[fd].offset;
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
  
  if (DEBUG)
    emscripten_log(EM_LOG_CONSOLE, "Starting " NETFS_VERSION "...");

  for (int i = 0; i < NB_FD_MAX; ++i) {
    
    fds[i].fd = -1;
    fds[i].data = NULL;
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

  while (1) {
    
    bytes_rec = recvfrom(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, &len);

    //emscripten_log(EM_LOG_CONSOLE,"*** netfs: %d", msg->msg_id);

    if (msg->msg_id == (REGISTER_DRIVER|0x80)) {

      if (msg->_errno)
	continue;

      major = msg->_u.dev_msg.major;

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE,"REGISTER_DRIVER successful: major=%d", major);

      minor += 1;
	
      register_device(minor, &netfs_ops);
      
      msg->msg_id = REGISTER_DEVICE;
      msg->_u.dev_msg.minor = minor;

      memset(msg->_u.dev_msg.dev_name, 0, sizeof(msg->_u.dev_msg.dev_name));
      sprintf((char *)&msg->_u.dev_msg.dev_name[0], "netfs%d", msg->_u.dev_msg.minor);
  
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &resmgr_addr, sizeof(resmgr_addr));
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

      if (minor == 1)
	strcpy((char *)&msg->_u.mount_msg.pathname[0], "/bin");
      else if (minor == 2)
	strcpy((char *)&msg->_u.mount_msg.pathname[0], "/usr");
      else if (minor == 3)
	strcpy((char *)&msg->_u.mount_msg.pathname[0], "/etc");
  
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &resmgr_addr, sizeof(resmgr_addr));
    }
    else if (msg->msg_id == (MOUNT|0x80)) {

      if (msg->_u.mount_msg.minor < 3) {
	
	minor += 1;
	
	register_device(minor, &netfs_ops);
      
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

	if (DEBUG)
	  emscripten_log(EM_LOG_CONSOLE, "READ successful: %d bytes", reply->_u.io_msg.len);
      }
      else {

	if (DEBUG)
	  emscripten_log(EM_LOG_CONSOLE, "READ error: %d %d", msg->_u.io_msg.fd, fds[msg->_u.io_msg.fd].minor);
	
	reply->_errno = ENXIO;
      }
      
      sendto(sock, reply, sizeof(struct message)+reply->_u.io_msg.len, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

      free(reply);
    }
    else if (msg->msg_id == WRITE) {
      
      
    }
    else if (msg->msg_id == IOCTL) {

      
    }
    else if (msg->msg_id == CLOSE) {

      if (DEBUG)
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
      
      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "netfs: STAT from %d: %s", msg->pid, msg->_u.stat_msg.pathname_or_buf);

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

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "netfs: GETDENTS from %d: fd=%d len=%d", msg->pid, msg->_u.getdents_msg.fd, msg->_u.getdents_msg.len);

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

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "netfs: CHDIR from %d", msg->pid);

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
    
  }
  
  return 0;
}
