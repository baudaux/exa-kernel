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
#include <stdlib.h>

#include <fcntl.h>
#include <errno.h>

#include <signal.h>

#include "vfs.h"
#include "process.h"
#include "device.h"

#include "jobs.h"

#include "msg.h"

#include <emscripten.h>

/* Be careful when changing this path as it may be also used in javascript */

#define RESMGR_ROOT "/var"
#define RESMGR_FILE "resmgr.peer"
#define RESMGR_PATH RESMGR_ROOT "/" RESMGR_FILE

#define PIPE_PATH "/var/pipe.peer"

#define NB_ITIMERS_MAX 64

#define NB_JOBS_MAX    16

#define DEBUG 1

struct itimer {

  pid_t pid;
  int fd;
};

enum {
  // NO_JOB=0
  EXIT_JOB = 1,
  EXEC_JOB,
};

static struct job jobs[NB_JOBS_MAX];

static unsigned short vfs_major;
static unsigned short vfs_minor;

int close_opened_fd(int job, int sock, char * buf);
int do_exit(int sock, struct message * msg);

int main() {

  int sock;
  struct sockaddr_un local_addr, remote_addr, tty_addr;
  int bytes_rec;
  socklen_t len;
  char buf[1256];
  struct message * msg = (struct message *)&buf[0];

  struct itimer itimers[NB_ITIMERS_MAX];

  // Use console.log as tty is not yet started

  if (DEBUG)
    emscripten_log(EM_LOG_CONSOLE, "Starting resmgr v0.1.0 ...");

  for (int i = 0; i < NB_ITIMERS_MAX; ++i) {
    itimers[i].pid = 0;
    itimers[i].fd = -1;
  }

  vfs_init();
  process_init();
  device_init();
  
  jobs_init(jobs, NB_JOBS_MAX);

  /* Create the server local socket */
  sock = socket(AF_UNIX, SOCK_DGRAM, 0);
  
  memset(&local_addr, 0, sizeof(local_addr));
  local_addr.sun_family = AF_UNIX;
  strcpy(local_addr.sun_path, RESMGR_PATH);

  /* Bind socket to RESMGR_PATH : path is not created as we are in resmgr ... */
  bind(sock, (struct sockaddr *) &local_addr, sizeof(local_addr));

  /* ... so we need to add it in vfs */
  struct vnode * vnode = vfs_find_node(RESMGR_ROOT, NULL);
  vfs_add_file(vnode, RESMGR_FILE);

  /* Register vfs driver */
  vfs_major = device_register_driver(FS_DEV, "vfs", RESMGR_PATH);
  vfs_minor = 1;

  device_register_device(FS_DEV, vfs_major, vfs_minor, "vfs1");

  // First, we create tty process
  
  create_tty_process();
  
  while (1) {

    fd_set rfds;
    int retval;

    FD_ZERO(&rfds);
    FD_SET(sock, &rfds);

    int fd_max = sock;

    for (int i = 0; i < NB_ITIMERS_MAX; ++i) {
      
      if (itimers[i].fd >= 0) {

	FD_SET(itimers[i].fd, &rfds);

	if (itimers[i].fd > fd_max)
	  fd_max = itimers[i].fd;
      }
    }

    retval = select(fd_max+1, &rfds, NULL, NULL, NULL);

    if (retval < 0)
      continue;

    if (!FD_ISSET(sock, &rfds)) {

      for (int i = 0; i < NB_ITIMERS_MAX; ++i) {
      
	if ( (itimers[i].fd >= 0) && (FD_ISSET(itimers[i].fd, &rfds)) ) {

	  uint64_t count = 0;

	  read(itimers[i].fd, &count, sizeof(count));

	  if (DEBUG)
	    emscripten_log(EM_LOG_CONSOLE, "resmgr: ITIMER count=%d", count);

	  msg->msg_id = KILL;
	  msg->pid = itimers[i].pid;
	  msg->_u.kill_msg.pid = itimers[i].pid;
	  msg->_u.kill_msg.sig = SIGALRM;

	  int action = process_kill(msg->_u.kill_msg.pid, msg->_u.kill_msg.sig, &msg->_u.kill_msg.act);

	  if (DEBUG)
	    emscripten_log(EM_LOG_CONSOLE, "resmgr: process_kill action=%d", action);

	  if (action == 2) {
	    sendto(sock, buf, 256, 0, (struct sockaddr *)process_get_peer_addr(msg->pid), sizeof(struct sockaddr_un));
	  }
	}
      }

      continue;
    }
    
    bytes_rec = recvfrom(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, &len);

    if (DEBUG)
      emscripten_log(EM_LOG_CONSOLE, "resmgr: msg %d received from %s (%d)", msg->msg_id, remote_addr.sun_path,bytes_rec);

    if (msg->msg_id == REGISTER_DRIVER) {
      
      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "REGISTER_DRIVER %s (%d)", msg->_u.dev_msg.dev_name, msg->_u.dev_msg.dev_type);

      // Add driver
      msg->_u.dev_msg.major = device_register_driver(msg->_u.dev_msg.dev_type, (const char *)msg->_u.dev_msg.dev_name, (const char *)remote_addr.sun_path);

      if (msg->_u.dev_msg.major == 1) { // tty

	// TTY driver: add /dev/tty with minor 0
	
	struct vnode * vnode = vfs_find_node("/dev", NULL);
	
	vfs_add_dev(vnode, "tty", CHR_DEV, 1, 0);
      }
      else if (strcmp(msg->_u.dev_msg.dev_name, "pipe") == 0) {

	create_init_process();
      }
      
      msg->msg_id |= 0x80;
      msg->_errno = 0;
      
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == REGISTER_DEVICE) {
      
      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "REGISTER_DEVICE %s (%d,%d,%d)", msg->_u.dev_msg.dev_name, msg->_u.dev_msg.dev_type, msg->_u.dev_msg.major, msg->_u.dev_msg.minor);

      device_register_device(msg->_u.dev_msg.dev_type, msg->_u.dev_msg.major, msg->_u.dev_msg.minor, (const char *)msg->_u.dev_msg.dev_name);

      char dev_name[DEV_NAME_LENGTH_MAX];
      strcpy(dev_name, (const char *)msg->_u.dev_msg.dev_name);
      unsigned char dev_type = msg->_u.dev_msg.dev_type;

      msg->msg_id |= 0x80;
      msg->_errno = 0;
      
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

      if ( (msg->_u.dev_msg.dev_type == CHR_DEV) && (msg->_u.dev_msg.major == 1) && (msg->_u.dev_msg.minor == 1) ) {  // First device is tty

	memcpy(&tty_addr, &remote_addr, sizeof(remote_addr));

	create_netfs_process();
      }

      // add char and block devices to /dev
      if ( (dev_type == CHR_DEV) || (dev_type == BLK_DEV) ) {

	  memset(buf, 0, 1256);
	  msg->msg_id = WRITE;
	  msg->_u.io_msg.fd = -1; // minor == 1

	  sprintf((char *)msg->_u.io_msg.buf,"\r\n/dev/%s added", dev_name);

	  msg->_u.io_msg.len = strlen((char *)(msg->_u.io_msg.buf))+1;

	  sendto(sock, buf, 1256, 0, (struct sockaddr *) &tty_addr, sizeof(tty_addr));

	  if (DEBUG)
	    emscripten_log(EM_LOG_CONSOLE, "Send msg to %s", tty_addr.sun_path);
	}
      
    }
    else if (msg->msg_id == MOUNT) {

      struct device * dev = NULL;
      char pathname[1024];

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "MOUNT %d %d %d %s", msg->_u.mount_msg.dev_type, msg->_u.mount_msg.major, msg->_u.mount_msg.minor, (const char *)&msg->_u.mount_msg.pathname[0]);

      struct vnode * vnode = vfs_find_node((const char *)&msg->_u.mount_msg.pathname[0], NULL);
  
      if (vnode && (vnode->type == VDIR)) {
	vfs_set_mount(vnode, msg->_u.mount_msg.dev_type, msg->_u.mount_msg.major, msg->_u.mount_msg.minor);
	msg->_errno = 0;

	dev = device_get_device(msg->_u.mount_msg.dev_type, msg->_u.mount_msg.major, msg->_u.mount_msg.minor);

	strcpy((char *)&(pathname[0]), (const char *)&(msg->_u.mount_msg.pathname[0]));
      }
      else {
	msg->_errno = ENOTDIR;

	if (DEBUG)
	  emscripten_log(EM_LOG_CONSOLE, "mount: %s not a directory", msg->_u.mount_msg.pathname);
      }

      msg->msg_id |= 0x80;
      
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

      if (msg->_errno == 0) {

	memset(buf, 0, 1256);
	msg->msg_id = WRITE;
	msg->_u.io_msg.fd = -1; // minor == 1

	sprintf((char *)msg->_u.io_msg.buf,"\r\ndevice %s mounted on %s", (const char *)&(dev->name[0]), (const char *)&(pathname[0]));

	msg->_u.io_msg.len = strlen((char *)(msg->_u.io_msg.buf))+1;

	sendto(sock, buf, 1256, 0, (struct sockaddr *) &tty_addr, sizeof(tty_addr));
	if (DEBUG)
	  emscripten_log(EM_LOG_CONSOLE, "Mount path: %s", pathname);

	if (strcmp((const char *)&(pathname[0]),"/etc") == 0) {

	  memset(buf, 0, 1256);
	  msg->msg_id = WRITE;
	  msg->_u.io_msg.fd = -1; // minor == 1

	  sprintf((char *)msg->_u.io_msg.buf,"\r\nstart sysvinit");

	  msg->_u.io_msg.len = strlen((char *)(msg->_u.io_msg.buf))+1;

	  sendto(sock, buf, 1256, 0, (struct sockaddr *) &tty_addr, sizeof(tty_addr));

	  create_pipe_process();

	  dump_processes();
	}
      }
    }
    else if (msg->msg_id == SOCKET) {

      msg->msg_id |= 0x80;
      msg->_errno = 0;

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "SOCKET %d %d %d %d", msg->pid, msg->_u.socket_msg.domain, msg->_u.socket_msg.type, msg->_u.socket_msg.protocol);

      msg->_u.socket_msg.fd = process_create_fd(msg->pid, -2, (unsigned char)(msg->_u.socket_msg.type & 0xff), (unsigned short)(msg->_u.socket_msg.domain & 0xffff), (unsigned short)(msg->_u.socket_msg.protocol & 0xffff), msg->_u.socket_msg.type); // type contains flags

      // Add /proc/<pid>/fd/<fd> entry
      process_add_proc_fd_entry(msg->pid, msg->_u.socket_msg.fd, "socket");

      if (msg->_u.socket_msg.type & SOCK_CLOEXEC) {

	// TODO
      }

      if (msg->_u.socket_msg.type & SOCK_NONBLOCK) {

	// TODO
      }

      if (DEBUG)
	    emscripten_log(EM_LOG_CONSOLE, "SOCKET created %d", msg->_u.socket_msg.fd);

      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == BIND) {

      msg->msg_id |= 0x80;
      msg->_errno = 0;

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "BIND %x %s", ((struct sockaddr_un *)&(msg->_u.bind_msg.addr))->sun_family, ((struct sockaddr_un *)&(msg->_u.bind_msg.addr))->sun_path);

      //TODO: bind in all possible fs, not only vfs
      
      struct vnode * vnode = vfs_find_node((const char *) ((struct sockaddr_un *)&(msg->_u.bind_msg.addr))->sun_path, NULL);

      if (vnode) {

	//emscripten_log(EM_LOG_CONSOLE, "vnode found");

	msg->_errno = EADDRINUSE;
      }
      else {

	vnode = vfs_create_file((const char *) ((struct sockaddr_un *)&(msg->_u.bind_msg.addr))->sun_path);

	if (vnode) {

	  //emscripten_log(EM_LOG_CONSOLE, "vnode created");
	}
	else {

	  //emscripten_log(EM_LOG_CONSOLE, "vnode creation error");

	  msg->_errno = EACCES;
	}
      }
      
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == OPEN) {

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "OPEN from %d: %x %x %s", msg->pid, msg->_u.open_msg.flags, msg->_u.open_msg.mode, msg->_u.open_msg.pathname);

      char * path;
      char new_path[1024];

      if (msg->_u.open_msg.pathname[0] == '/') {

	path = msg->_u.open_msg.pathname;
      }
      else {

	char * cwd = process_getcwd(msg->pid);

	if (cwd[strlen(cwd)-1] == '/')
	  sprintf(new_path, "%s%s", cwd, msg->_u.open_msg.pathname);
	else
	  sprintf(new_path, "%s/%s", cwd, msg->_u.open_msg.pathname);

	path = &new_path[0];
      }
      
      int remote_fd = vfs_open((const char *)path, msg->_u.open_msg.flags, msg->_u.open_msg.mode, msg->pid, vfs_minor);

      if (remote_fd >= 0) {

	char new_path[1024];
	
	vfs_get_path(vfs_get_vnode(remote_fd), new_path);

	if (DEBUG)
	  emscripten_log(EM_LOG_CONSOLE, "vfs_get_path: %s", new_path);
	
	if (remote_fd == 0) {

	  struct vnode * vnode = vfs_get_vnode(remote_fd);

	  if (DEBUG)
	    emscripten_log(EM_LOG_CONSOLE, "vnode is a device or mount point: %d %d %d %s",vnode->_u.dev.type, vnode->_u.dev.major, vnode->_u.dev.minor, device_get_driver(vnode->_u.dev.type, vnode->_u.dev.major)->peer);

	  char node_path[1024];
	
	  vfs_get_path(vnode, node_path);

	  if (DEBUG)
	    emscripten_log(EM_LOG_CONSOLE, "OPEN: VMOUNT %s trail=%s", node_path, vfs_get_pathname(remote_fd));

	  msg->_u.open_msg.sid = process_getsid(msg->pid);

	  // Forward msg to driver
	
	  msg->_u.open_msg.type = vnode->_u.dev.type;
	  msg->_u.open_msg.major = vnode->_u.dev.major;
	  msg->_u.open_msg.minor = vnode->_u.dev.minor;
	  strcpy((char *)msg->_u.open_msg.peer, device_get_driver(vnode->_u.dev.type, vnode->_u.dev.major)->peer);

	  strcpy(msg->_u.open_msg.pathname, node_path);

	  if (vnode->type == VMOUNT)
	    strcat(msg->_u.open_msg.pathname, vfs_get_pathname(remote_fd));
	  
	  struct sockaddr_un driver_addr;

	  driver_addr.sun_family = AF_UNIX;
	  strcpy(driver_addr.sun_path, device_get_driver(vnode->_u.dev.type, vnode->_u.dev.major)->peer);

	  sendto(sock, buf, 1256, 0, (struct sockaddr *) &driver_addr, sizeof(driver_addr));
	}
	else if (remote_fd > 0) {

	  msg->msg_id |= 0x80;
	  msg->_errno = 0;
	  
	  msg->_u.open_msg.remote_fd = remote_fd;
	  msg->_u.open_msg.type = FS_DEV;
	  msg->_u.open_msg.major = vfs_major;
	  msg->_u.open_msg.minor = vfs_minor;
	  strcpy((char *)msg->_u.open_msg.peer, RESMGR_PATH);
	  
	  msg->_u.open_msg.fd = process_create_fd(msg->pid, msg->_u.open_msg.remote_fd, msg->_u.open_msg.type, msg->_u.open_msg.major, msg->_u.open_msg.minor, msg->_u.open_msg.flags);

	  // Add /proc/<pid>/fd/<fd> entry
	  process_add_proc_fd_entry(msg->pid, msg->_u.open_msg.fd, new_path);

	  sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
	}
      }
      else {

	if (DEBUG)
	  emscripten_log(EM_LOG_CONSOLE, "vnode not found");

	msg->msg_id |= 0x80;
	msg->_errno = ENOENT;
	
	sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      }
    }
    else if (msg->msg_id == (OPEN|0x80)) {

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "Response from OPEN from %d: %d %x %x %s %d %d", msg->pid, msg->_errno, msg->_u.open_msg.flags, msg->_u.open_msg.mode, msg->_u.open_msg.pathname,msg->pid, msg->_u.open_msg.remote_fd);

      if (msg->_errno == 0) {

	msg->_u.open_msg.fd = process_create_fd(msg->pid, msg->_u.open_msg.remote_fd, msg->_u.open_msg.type, msg->_u.open_msg.major, msg->_u.open_msg.minor, msg->_u.open_msg.flags);

	// Add /proc/<pid>/fd/<fd> entry
	process_add_proc_fd_entry(msg->pid, msg->_u.open_msg.fd, (char *)msg->_u.open_msg.pathname);
      }

      // Forward response to process

      sendto(sock, buf, 1256, 0, (struct sockaddr *)process_get_peer_addr(msg->pid), sizeof(struct sockaddr_un));
      
    }
    else if (msg->msg_id == CLOSE) {

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "CLOSE from %d: %d", msg->pid, msg->_u.close_msg.fd);

      unsigned char type;
      unsigned short major;
      int remote_fd;

      // Get the fd of the process
      if (process_get_fd(msg->pid, msg->_u.close_msg.fd, &type, &major, &remote_fd) >= 0) {

	// Close the fd for this process
	process_close_fd(msg->pid, msg->_u.close_msg.fd);

	// Remove /proc/<pid>/fd/<fd> entry
	process_del_proc_fd_entry(msg->pid, msg->_u.close_msg.fd);

	// Find fd in other processes
	if (process_find_open_fd(type, major, remote_fd) < 0) {

	  // No more fd, close the fd in the driver

	  // Forward msg to driver

	  msg->_u.close_msg.fd = remote_fd;

	  if (major != vfs_major) {

	    struct sockaddr_un driver_addr;

	    driver_addr.sun_family = AF_UNIX;
	    strcpy(driver_addr.sun_path, device_get_driver(type, major)->peer);

	    if (DEBUG)
	      emscripten_log(EM_LOG_CONSOLE, "CLOSE send to: %s", driver_addr.sun_path);

	    sendto(sock, buf, 256, 0, (struct sockaddr *) &driver_addr, sizeof(driver_addr));
	  }
	  else {

	    msg->msg_id |= 0x80;

	    if (vfs_close(remote_fd) >= 0) {
	      
	      msg->_errno = 0;
	    }
	    else {

	      msg->_errno = EBADF;
	    }

	    sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
	  }
	}
	else {

	  if (DEBUG)
	    emscripten_log(EM_LOG_CONSOLE, "CLOSE: do not close");

	  // Other fd are there, do not close fd in the driver

	  msg->msg_id |= 0x80;
	  msg->_errno = 0;

	  sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
	}
      }
      else {

	if (DEBUG)
	  emscripten_log(EM_LOG_CONSOLE, "CLOSE: not found");

	msg->msg_id |= 0x80;
	msg->_errno = EBADF;

	sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      }
    }
    else if (msg->msg_id == (CLOSE|0x80)) {

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "Response from CLOSE from %d (%s)", msg->pid, process_get_peer_addr(msg->pid)->sun_path);

      unsigned long job;
      
      if (job=is_pending_job(jobs, msg->pid)) {

	if (close_opened_fd(job, sock, buf) > 0)
	    continue;

	if (job == EXEC_JOB) {
	  continue_pending_job(jobs, msg->pid, sock);
	}
	else if (job == EXIT_JOB) {

	  char * buf2;
	  int buf2_size;
	  struct sockaddr_un * addr2;

	  unsigned long job = get_pending_job(jobs, msg->pid, &buf2, &buf2_size, &addr2);

	  do_exit(sock, (struct message *)&buf2[0]);
	}
      }
      else {

	// Forward response to process

	sendto(sock, buf, 256, 0, (struct sockaddr *)process_get_peer_addr(msg->pid), sizeof(struct sockaddr_un));
      }
      
    }
    else if (msg->msg_id == READ) {

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "READ from %d: %d %d", msg->pid, msg->_u.io_msg.fd, msg->_u.io_msg.len);

      struct message * reply = (struct message *) malloc(sizeof(struct message)+msg->_u.io_msg.len);

      reply->msg_id = READ|0x80;
      reply->pid = msg->pid;
      reply->_u.io_msg.fd = msg->_u.io_msg.fd;

      int len = vfs_read(reply->_u.io_msg.fd, reply->_u.io_msg.buf, msg->_u.io_msg.len);

      if (len >= 0) {
	
	if (DEBUG)
	    emscripten_log(EM_LOG_CONSOLE, "READ done : %d bytes", len);

	reply->_u.io_msg.len = len;
	      
	reply->_errno = 0;
      }
      else {

	reply->_errno = EBADF;
      }
      
      sendto(sock, reply, sizeof(struct message)+reply->_u.io_msg.len, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

      free(reply);
    }
    else if (msg->msg_id == WRITE) {

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "WRITE from %d: %d %d", msg->pid, msg->_u.io_msg.fd, msg->_u.io_msg.len);

      //TODO : read remaining bytes if needed (beyond 1256)

      msg->msg_id |= 0x80;
      
      if (vfs_write(msg->_u.io_msg.fd, msg->_u.io_msg.buf, msg->_u.io_msg.len) >= 0)  {

	 if (DEBUG)
	    emscripten_log(EM_LOG_CONSOLE, "WRITE from %d: done");
	      
	msg->_errno = 0;
      }
      else {

	msg->_errno = EBADF;
      }
      
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

    }
    else if (msg->msg_id == IOCTL) {
      
      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "IOCTL from %d: %d %d", msg->pid, msg->_u.ioctl_msg.fd, msg->_u.ioctl_msg.op);

      msg->msg_id |= 0x80;

      if (vfs_ioctl(msg->_u.ioctl_msg.fd, msg->_u.ioctl_msg.op) >= 0) {
	      
	msg->_errno = 0; 
      }
      else {

	msg->_errno = EBADF;
      }

      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

    }
    else if (msg->msg_id == FCNTL) {
      
      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "FCNTL from %d: %d %d", msg->pid, msg->_u.fcntl_msg.fd, msg->_u.fcntl_msg.cmd);

      msg->_u.fcntl_msg.ret = 0;
      msg->_errno = 0;

      if (msg->_u.fcntl_msg.cmd == F_SETFD) {

	int flags;
	int flags2 = 0;

	memcpy(&flags, msg->_u.fcntl_msg.buf, sizeof(int));

	if (flags & FD_CLOEXEC) {
	  
	  flags2 |= O_CLOEXEC;  
	}
	
	msg->_errno = process_set_fd_flags(msg->pid, msg->_u.fcntl_msg.fd, flags2);
      }
      else if (msg->_u.fcntl_msg.cmd == F_GETFD) {

	msg->_u.fcntl_msg.ret = process_get_fd_flags(msg->pid, msg->_u.fcntl_msg.fd);
      }

      msg->msg_id |= 0x80;
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

    }
    else if (msg->msg_id == SETSID) {

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "SETSID from %d", msg->pid);

      msg->_u.setsid_msg.sid = process_setsid(msg->pid);
      
      msg->msg_id |= 0x80;
      msg->_errno = 0;

      if (msg->_u.setsid_msg.sid < 0)
	msg->_errno = EPERM;

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "SETSID --> %d", msg->_u.setsid_msg.sid);

      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      
    }
    else if (msg->msg_id == GETSID) {

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "GETSID from %d", msg->pid);

      if (msg->_u.getsid_msg.pid == 0) {
	msg->_u.getsid_msg.sid = process_getsid(msg->pid);
	msg->_u.getsid_msg.pgid = process_getpgid(msg->pid);
      }
      else {
	msg->_u.getsid_msg.sid = process_getsid(msg->_u.getsid_msg.pid);
	msg->_u.getsid_msg.pgid = process_getpgid(msg->_u.getsid_msg.pid);
      }

      //dump_processes();
      
      msg->msg_id |= 0x80;
      msg->_errno = 0;

      if (msg->_u.getsid_msg.sid < 0)
	msg->_errno = EPERM;

      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      
    }
    else if (msg->msg_id == FORK) {

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "FORK from %d", msg->pid);

      msg->_u.fork_msg.child = process_fork(-1, msg->pid, NULL);
      
      msg->msg_id |= 0x80;
      msg->_errno = 0;

      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      
    }
    else if (msg->msg_id == EXECVE) {

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "EXECVE from %d: %lu", msg->pid, msg->_u.execve_msg.args_size);

      if (msg->_u.execve_msg.args_size == 0xffffffff) {

	if (is_pending_job(jobs, msg->pid) == EXEC_JOB) {

	  // Close all opened fd with flag O_CLOEXEC

	  unsigned char type;
	  unsigned short major;
	  int remote_fd;

	  if (process_opened_fd(msg->pid, &type, &major, &remote_fd, O_CLOEXEC) >= 0) {
	    if (DEBUG)
	      emscripten_log(EM_LOG_CONSOLE, "EXECVE from %d: there are O_CLOEXEC opened fd", msg->pid);
	    
	    if (close_opened_fd(EXEC_JOB, sock, buf) > 0) {

	      continue; // Wait CLOSE response before closing the other opened fd
	    }
	  }
	  
	  continue_pending_job(jobs, msg->pid, sock);
	}
      }
      else {

        msg->msg_id |= 0x80;

	add_pending_job(jobs, EXEC_JOB, msg->pid, msg, bytes_rec, &remote_addr);
      }
    }
    else if (msg->msg_id == DUP) {

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "DUP from %d", msg->pid);

      msg->_u.dup_msg.new_fd = process_dup(msg->pid, msg->_u.dup_msg.fd, msg->_u.dup_msg.new_fd);
      
      msg->msg_id |= 0x80;
      msg->_errno = 0;

      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == GETPPID) {

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "GETPPID from %d", msg->pid);

      msg->_u.getppid_msg.ppid = process_getppid(msg->pid);
      
      //dump_processes();
      
      msg->msg_id |= 0x80;
      msg->_errno = 0;

      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr)); 
    }
    else if (msg->msg_id == GETPGID) {

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "GETPGID from %d", msg->pid);

      if (msg->_u.getpgid_msg.pid == 0)
	msg->_u.getpgid_msg.pgid = process_getpgid(msg->pid);
      else
	msg->_u.getpgid_msg.pgid = process_getpgid(msg->_u.getsid_msg.pid);
      
      //dump_processes();
      
      msg->msg_id |= 0x80;
      msg->_errno = 0;

      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr)); 
    }
    else if (msg->msg_id == SETPGID) {

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "SETPGID from %d", msg->pid);

      if (msg->_u.getpgid_msg.pid == 0)
        process_setpgid(msg->pid, msg->_u.getpgid_msg.pgid);
      else
        process_setpgid(msg->_u.getpgid_msg.pid, msg->_u.getpgid_msg.pgid);
      
      //dump_processes();
      
      msg->msg_id |= 0x80;
      msg->_errno = 0;

      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr)); 
    }
    else if (msg->msg_id == IS_OPEN) {

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "IS_OPEN from %d: %d", msg->pid, msg->_u.is_open_msg.fd);

      msg->_errno = ENOENT;

      if (process_get_fd(msg->pid, msg->_u.is_open_msg.fd, &msg->_u.is_open_msg.type, &msg->_u.is_open_msg.major, &msg->_u.is_open_msg.remote_fd) == 0) {

	struct driver * drv = device_get_driver(msg->_u.is_open_msg.type, msg->_u.is_open_msg.major);

	if (drv) {

	  strcpy(msg->_u.is_open_msg.peer, drv->peer);

	  if (DEBUG)
	    emscripten_log(EM_LOG_CONSOLE, "IS_OPEN found %d %d %d %s", msg->_u.is_open_msg.type, msg->_u.is_open_msg.major, msg->_u.is_open_msg.remote_fd, msg->_u.is_open_msg.peer);

	  msg->_errno = 0;
	}
      }
      msg->msg_id |= 0x80;

      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == READLINK) {
      
      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "READLINK from %d: %s", msg->pid, msg->_u.readlink_msg.pathname_or_buf);

      char * pathname;
      char str[1024];

      // TODO: other self conversion
      if (strncmp(msg->_u.readlink_msg.pathname_or_buf, "/proc/self/", 11) == 0) {

	sprintf(str, "/proc/%d/%s", msg->pid, msg->_u.readlink_msg.pathname_or_buf+11);

	pathname = &str[0];
      }
      else {

	pathname = msg->_u.readlink_msg.pathname_or_buf;
      }
      
      struct vnode * node = vfs_find_node(pathname, NULL);

      if (node->type == VSYMLINK) {

	if (DEBUG)
	  emscripten_log(EM_LOG_CONSOLE, "READLINK found: %s", node->_u.link.symlink);

	strcpy(msg->_u.readlink_msg.pathname_or_buf, (const char *)node->_u.link.symlink);

	msg->_u.readlink_msg.len = strlen(msg->_u.readlink_msg.pathname_or_buf)+1;

	msg->msg_id |= 0x80;
	msg->_errno = 0;
	
	sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      }
      else if (node->type == VDEV) {
	
	// TODO
      }

    }
    else if (msg->msg_id == STAT) {
      
      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "STAT from %d: %s", msg->pid, msg->_u.stat_msg.pathname_or_buf);

      char * path;
      char new_path[1024];

      if (msg->_u.stat_msg.pathname_or_buf[0] == '/') {

	path = msg->_u.stat_msg.pathname_or_buf;
      }
      else {

	char * cwd = process_getcwd(msg->pid);

	if (cwd[strlen(cwd)-1] == '/')
	  sprintf(new_path, "%s%s", cwd, msg->_u.stat_msg.pathname_or_buf);
	else
	  sprintf(new_path, "%s/%s", cwd, msg->_u.stat_msg.pathname_or_buf);

	path = &new_path[0];
      }

      struct stat stat_buf;
      struct vnode * vnode;
      char * trail;

      int res = vfs_stat((const char *)path, &stat_buf, &vnode, &trail);

      if (res == 0) {

	if (vnode == NULL) {

	 if (DEBUG)
	   emscripten_log(EM_LOG_CONSOLE, "STAT from %d: %s found", msg->pid, path);

	  msg->msg_id |= 0x80;
	  msg->_errno = 0;

	  msg->_u.stat_msg.len = sizeof(struct stat);
	  memcpy(msg->_u.stat_msg.pathname_or_buf, &stat_buf, sizeof(struct stat));
	  
	  sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
	}
	else {

	  struct sockaddr_un driver_addr;

	  char node_path[1024];
	
	  vfs_get_path(vnode, node_path);

	  if (vnode->type == VMOUNT)
	    strcat(node_path, trail);

	  strcpy(msg->_u.stat_msg.pathname_or_buf, node_path);

	  if (DEBUG)
	    emscripten_log(EM_LOG_CONSOLE, "STAT: VMOUNT %s %s %s", node_path, trail, msg->_u.stat_msg.pathname_or_buf);

	  driver_addr.sun_family = AF_UNIX;
	  strcpy(driver_addr.sun_path, device_get_driver(vnode->_u.dev.type, vnode->_u.dev.major)->peer);

	  msg->_u.stat_msg.type = vnode->_u.dev.type;
	  msg->_u.stat_msg.major = vnode->_u.dev.major;
	  msg->_u.stat_msg.minor = vnode->_u.dev.minor;

	  sendto(sock, buf, 1256, 0, (struct sockaddr *) &driver_addr, sizeof(driver_addr));
	}
      }
      else {

	msg->msg_id |= 0x80;
	msg->_errno = ENOENT;

	sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
	
      }
    }
    else if (msg->msg_id == (STAT|0x80)) {

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "Response from STAT from %d", msg->pid);

      // Forward response to process
      
      sendto(sock, buf, 1256, 0, (struct sockaddr *)process_get_peer_addr(msg->pid), sizeof(struct sockaddr_un));
      
    }
    else if (msg->msg_id == LSTAT) {
      
      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "LSTAT from %d: %s", msg->pid, msg->_u.stat_msg.pathname_or_buf);

      char * path;
      char new_path[1024];

      if (msg->_u.stat_msg.pathname_or_buf[0] == '/') {

	path = msg->_u.stat_msg.pathname_or_buf;
      }
      else {

	char * cwd = process_getcwd(msg->pid);

	if (cwd[strlen(cwd)-1] == '/')
	  sprintf(new_path, "%s%s", cwd, msg->_u.stat_msg.pathname_or_buf);
	else
	  sprintf(new_path, "%s/%s", cwd, msg->_u.stat_msg.pathname_or_buf);

	path = &new_path[0];
      }

      struct stat stat_buf;
      struct vnode * vnode;
      char * trail;

      int res = vfs_lstat((const char *)path, &stat_buf, &vnode, &trail);

      if (res == 0) {

	if (vnode == NULL) {

	  msg->msg_id |= 0x80;
	  msg->_errno = 0;

	  msg->_u.stat_msg.len = sizeof(struct stat);
	  memcpy(msg->_u.stat_msg.pathname_or_buf, &stat_buf, sizeof(struct stat));
	  
	  sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
	}
	else {

	  struct sockaddr_un driver_addr;

	  char node_path[1024];
	
	  vfs_get_path(vnode, node_path);

	  if (vnode->type == VMOUNT)
	    strcat(node_path, trail);

	  strcpy(msg->_u.stat_msg.pathname_or_buf, node_path);
	  
	  if (DEBUG)
	    emscripten_log(EM_LOG_CONSOLE, "LSTAT: VMOUNT %s", msg->_u.stat_msg.pathname_or_buf);

	  driver_addr.sun_family = AF_UNIX;
	  strcpy(driver_addr.sun_path, device_get_driver(vnode->_u.dev.type, vnode->_u.dev.major)->peer);

	  msg->_u.stat_msg.type = vnode->_u.dev.type;
	  msg->_u.stat_msg.major = vnode->_u.dev.major;
	  msg->_u.stat_msg.minor = vnode->_u.dev.minor;

	  sendto(sock, buf, 1256, 0, (struct sockaddr *) &driver_addr, sizeof(driver_addr));
	}
      }
      else {

	msg->msg_id |= 0x80;
	msg->_errno = ENOENT;

	sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
	
      }
    }
    else if (msg->msg_id == (LSTAT|0x80)) {

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "Response from LSTAT from %d", msg->pid);

      // Forward response to process
      
      sendto(sock, buf, 1256, 0, (struct sockaddr *)process_get_peer_addr(msg->pid), sizeof(struct sockaddr_un));
      
    }
    else if (msg->msg_id == TIMERFD_CREATE) {

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "TIMERFD_CREATE from %d (%d)", msg->pid, msg->_u.timerfd_create_msg.clockid);

      msg->_u.timerfd_create_msg.fd = process_create_fd(msg->pid, -3, 0, 0, msg->_u.timerfd_create_msg.clockid & 0xffff, msg->_u.timerfd_create_msg.flags);

      msg->msg_id |= 0x80;
      msg->_errno = 0;
      
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == GETCWD) {

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "GETCWD from %d", msg->pid);

      strcpy((char *)msg->_u.cwd_msg.buf, process_getcwd(msg->pid));
      msg->_u.cwd_msg.len = strlen((char *)msg->_u.cwd_msg.buf)+1;
      
      msg->msg_id |= 0x80;
      msg->_errno = 0;

      sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr)); 
    }
    else if (msg->msg_id == CHDIR) {

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "CHDIR from %d: %s", msg->pid, msg->_u.cwd_msg.buf);

      msg->_errno = 0;

      char * dir;
      char new_dir[1024];

      if (msg->_u.cwd_msg.buf[0] == '/') {

	dir = msg->_u.cwd_msg.buf;
      }
      else {

	char * cwd = process_getcwd(msg->pid);

	if (cwd[strlen(cwd)-1] == '/')
	  sprintf(new_dir, "%s%s", cwd, msg->_u.cwd_msg.buf);
	else
	  sprintf(new_dir, "%s/%s", cwd, msg->_u.cwd_msg.buf);

	dir = &new_dir[0];
      }

      char * trail= 0;

      struct vnode * vnode = vfs_find_node(dir, &trail);
  
      if (vnode) {

	if (DEBUG)
	  emscripten_log(EM_LOG_CONSOLE, "CHDIR resolved %s", dir);

	char new_dir[1024];
	
	vfs_get_path(vnode, new_dir);

	if (DEBUG)
	  emscripten_log(EM_LOG_CONSOLE, "CHDIR resolved -> %s %d", new_dir, vnode->type);

	if (vnode->type == VDIR) {
	  
	  msg->_errno = 0;

	  if (process_chdir(msg->pid, (char *)new_dir) < 0)
	    msg->_errno = ENOENT;
	  
	}
	else if (vnode->type == VMOUNT) {

	  struct sockaddr_un driver_addr;

	  if (trail)
	    strcat(new_dir, trail);
	  
	  strcpy(msg->_u.cwd_msg.buf, new_dir);

	  if (DEBUG)
	    emscripten_log(EM_LOG_CONSOLE, "CHDIR from %d: %s -> send to driver", msg->pid, msg->_u.cwd_msg.buf);

	  driver_addr.sun_family = AF_UNIX;
	  strcpy(driver_addr.sun_path, device_get_driver(vnode->_u.dev.type, vnode->_u.dev.major)->peer);

	  sendto(sock, buf, 1256, 0, (struct sockaddr *) &driver_addr, sizeof(driver_addr));

	  continue;
	}
	else {

	  msg->_errno = ENOENT;
	}
      }
      else {

	msg->_errno = ENOENT;
      }
      
      msg->msg_id |= 0x80;

      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr)); 
    }
    else if (msg->msg_id == (CHDIR|0x80)) {

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "Return from CHDIR from %d: %s", msg->pid, msg->_u.cwd_msg.buf);

      if (msg->_errno == 0) {

	if (process_chdir(msg->pid, (char *)msg->_u.cwd_msg.buf) < 0)
	    msg->_errno = ENOENT;
      }

      sendto(sock, buf, 1256, 0, (struct sockaddr *)process_get_peer_addr(msg->pid), sizeof(struct sockaddr_un));
    }
    else if (msg->msg_id == GETDENTS) {

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "GETDENTS from %d: count=%d", msg->pid, msg->_u.getdents_msg.len);

      ssize_t count = (msg->_u.getdents_msg.len < 1024)?msg->_u.getdents_msg.len:1024;
      
      count = vfs_getdents(msg->_u.getdents_msg.fd, msg->_u.getdents_msg.buf, count);

      msg->msg_id |= 0x80;

      if (count >= 0) {

	msg->_u.getdents_msg.len = count;
	msg->_errno = 0;
      }
      else {

	msg->_u.getdents_msg.len = 0;
	msg->_errno = EBADF;
      }

      sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == WAIT) {

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "WAIT from %d: pid=%d option=%d", msg->pid, msg->_u.wait_msg.pid, msg->_u.wait_msg.options);

      if (msg->_u.wait_msg.pid=process_wait(msg->pid, msg->_u.wait_msg.pid, msg->_u.wait_msg.options, &msg->_u.wait_msg.status)) {

	if (DEBUG)
	  emscripten_log(EM_LOG_CONSOLE, "WAIT -> %d status=%d", msg->_u.wait_msg.pid, msg->_u.wait_msg.status);

	msg->msg_id |= 0x80;
	msg->_errno = 0;
	
	sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      }
      
    }
    else if (msg->msg_id == EXIT) {

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "EXIT from %d: status=%d", msg->pid, msg->_u.exit_msg.status);
      
      // Close all opened fd

      // Find if there is already a timer for this pid

      for (int i = 0; i < NB_ITIMERS_MAX; ++i) {
      
	if (itimers[i].pid == msg->pid) {

	  itimers[i].fd = -1;
	  break;
	}
      }
      
      process_clearitimer(msg->pid);

      unsigned char type;
      unsigned short major;
      int remote_fd;
      
      if (process_opened_fd(msg->pid, &type, &major, &remote_fd, 0) >= 0) {

	if (DEBUG)
	  emscripten_log(EM_LOG_CONSOLE, "EXIT from %d: there are opened fd", msg->pid);

	if (close_opened_fd(EXIT_JOB, sock, buf) > 0) {

	  msg->msg_id |= 0x80;

	  add_pending_job(jobs, EXIT_JOB, msg->pid, msg, bytes_rec, &remote_addr);
	
	  continue; // Wait CLOSE response before closing the other opened fd
	}
      }

      do_exit(sock, msg);

    }
    else if (msg->msg_id == SEEK) {

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "SEEK from %d: fd=%d off=%d whence=%d", msg->pid, msg->_u.seek_msg.fd, msg->_u.seek_msg.offset, msg->_u.seek_msg.whence);

      msg->msg_id |= 0x80;
      
      msg->_u.seek_msg.offset = vfs_seek(msg->_u.seek_msg.fd, msg->_u.seek_msg.offset, msg->_u.seek_msg.whence);

      if (msg->_u.seek_msg.offset >= 0)  {

	if (DEBUG)
	    emscripten_log(EM_LOG_CONSOLE, "SEEK: done");
	
	msg->_errno = 0;
      }
      else {

	msg->_errno = EBADF;
      }
      
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == SIGACTION) {

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "SIGACTION from %d: signum=%d", msg->pid, msg->_u.sigaction_msg.signum);

      msg->_errno = process_sigaction(msg->pid, msg->_u.sigaction_msg.signum, &msg->_u.sigaction_msg.act);
      
      msg->msg_id |= 0x80;
      
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

    }
    else if (msg->msg_id == SIGPROCMASK) {

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "SIGPROGMASK from %d: how=%d", msg->pid, msg->_u.sigprocmask_msg.how);

      msg->_errno = process_sigprocmask(msg->pid, msg->_u.sigprocmask_msg.how, &msg->_u.sigprocmask_msg.sigset);
      
      msg->msg_id |= 0x80;
      
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

    }
    else if (msg->msg_id == KILL) {

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "KILL from %d: pid=%d sig=%d", msg->pid, msg->_u.kill_msg.pid, msg->_u.kill_msg.sig);

      int action = process_kill(msg->_u.kill_msg.pid, msg->_u.kill_msg.sig, &msg->_u.kill_msg.act);

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "KILL from %d: action=%d", msg->pid, action);

      if (action == 1) { // Default action

	
      }
      else if (action == 2) { // Custom action

	if (msg->pid == msg->_u.kill_msg.pid) {
	  
	  sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
	}
	else {

	  //TODO
	}
      }
    }
    else if (msg->msg_id == EXA_RELEASE_SIGNAL) {
      
      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "EXA_RELEASE_SIGNAL from %d: pid=%d sig=%d", msg->pid, msg->_u.exa_release_signal_msg.sig);
      
      process_signal_delivered(msg->pid, msg->_u.exa_release_signal_msg.sig);

      msg->msg_id |= 0x80;

      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == SETITIMER) {

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "SETITIMER from %d: %d %d %d %d", msg->pid, msg->_u.setitimer_msg.val_sec, msg->_u.setitimer_msg.val_usec, msg->_u.setitimer_msg.it_sec, msg->_u.setitimer_msg.it_usec);

      int fd = process_setitimer(msg->pid, msg->_u.setitimer_msg.which, msg->_u.setitimer_msg.val_sec, msg->_u.setitimer_msg.val_usec, msg->_u.setitimer_msg.it_sec, msg->_u.setitimer_msg.it_usec);

      int i;

      // Find if there is already a timer for this pid
      for (i = 0; i < NB_ITIMERS_MAX; ++i) {
      
	if (itimers[i].pid == msg->pid) {

	  itimers[i].fd = fd;
	  break;
	}
      }

      if (i == NB_ITIMERS_MAX) {

	// Timer not found so we add it at the first free slot

	for (i = 0; i < NB_ITIMERS_MAX; ++i) {
      
	  if (itimers[i].fd < 0) {

	    itimers[i].pid = msg->pid;
	    itimers[i].fd = fd;
	    break;
	  }
	}
      }

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "SETITIMER from %d: timerfd=%d", msg->pid, fd);

      msg->msg_id |= 0x80;
      
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == FACCESSAT) {
      
      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "FACCESSAT from %d: %s", msg->pid, msg->_u.faccessat_msg.pathname);

      char * path;
      char new_path[1024];

      if (msg->_u.faccessat_msg.pathname[0] == '/') {

	path = msg->_u.faccessat_msg.pathname;
      }
      else {

	char * cwd = process_getcwd(msg->pid);

	if (cwd[strlen(cwd)-1] == '/')
	  sprintf(new_path, "%s%s", cwd, msg->_u.faccessat_msg.pathname);
	else
	  sprintf(new_path, "%s/%s", cwd, msg->_u.faccessat_msg.pathname);

	path = &new_path[0];
      }

      struct stat stat_buf;
      char * trail;
      
      struct vnode * vnode = vfs_find_node((const char *)path, &trail);

      if (vnode == NULL) {

	if (DEBUG)
	  emscripten_log(EM_LOG_CONSOLE, "FACCESSAT from %d: %s not found", msg->pid, path);

	msg->msg_id |= 0x80;
	msg->_errno = ENOENT;

	sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      }
      else if (vnode->type == VMOUNT) {

	struct sockaddr_un driver_addr;

	msg->_u.faccessat_msg.type = vnode->_u.dev.type;
	msg->_u.faccessat_msg.major = vnode->_u.dev.major;
	msg->_u.faccessat_msg.minor = vnode->_u.dev.minor;

	char node_path[1024];
	
	vfs_get_path(vnode, node_path);

	strcat(node_path, trail);

	strcpy(msg->_u.faccessat_msg.pathname, node_path);

	if (DEBUG)
	  emscripten_log(EM_LOG_CONSOLE, "FACCESSAT: VMOUNT %s %s %s", node_path, trail, msg->_u.faccessat_msg.pathname);

	driver_addr.sun_family = AF_UNIX;
	strcpy(driver_addr.sun_path, device_get_driver(vnode->_u.dev.type, vnode->_u.dev.major)->peer);

	sendto(sock, buf, 1256, 0, (struct sockaddr *) &driver_addr, sizeof(driver_addr));
	}
      else {

	msg->msg_id |= 0x80;
	msg->_errno = 0;

	sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
	
      }
    }
    else if (msg->msg_id == (FACCESSAT|0x80)) {

      // Forward response to process

      sendto(sock, buf, 1256, 0, (struct sockaddr *)process_get_peer_addr(msg->pid), sizeof(struct sockaddr_un));
    }
    else if (msg->msg_id == FSTAT) {

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "resmgr: FSTAT from %d: %d", msg->pid, msg->_u.fstat_msg.fd);

      struct stat stat_buf;

      msg->_errno = vfs_fstat(msg->_u.fstat_msg.fd, &stat_buf);

      if (msg->_errno == 0) {
	msg->_u.fstat_msg.len = sizeof(struct stat);
	memcpy(msg->_u.fstat_msg.buf, &stat_buf, sizeof(struct stat));
      }
      else {
      
	msg->_u.fstat_msg.len = 0;
      }  

      msg->msg_id |= 0x80;
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

    }
     else if (msg->msg_id == PIPE) {

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "resmgr: PIPE from %d", msg->pid);

      struct sockaddr_un pipe_addr;

      memset(&pipe_addr, 0, sizeof(pipe_addr));
      pipe_addr.sun_family = AF_UNIX;
      strcpy(pipe_addr.sun_path, PIPE_PATH);
  
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &pipe_addr, sizeof(pipe_addr));
     }
     else if (msg->msg_id == (PIPE|0x80)) {

       if (msg->_errno == 0) {

	 msg->_u.pipe_msg.fd[0] = process_create_fd(msg->pid, msg->_u.pipe_msg.remote_fd[0], msg->_u.pipe_msg.type, msg->_u.pipe_msg.major, msg->_u.pipe_msg.minor, msg->_u.pipe_msg.flags);

	 // Add /proc/<pid>/fd/<fd> entry
	 process_add_proc_fd_entry(msg->pid, msg->_u.pipe_msg.fd[0], "pipe");

	 msg->_u.pipe_msg.fd[1] = process_create_fd(msg->pid, msg->_u.pipe_msg.remote_fd[1], msg->_u.pipe_msg.type, msg->_u.pipe_msg.major, msg->_u.pipe_msg.minor, msg->_u.pipe_msg.flags);

	 // Add /proc/<pid>/fd/<fd> entry
	 process_add_proc_fd_entry(msg->pid, msg->_u.pipe_msg.fd[1], "pipe");

	 emscripten_log(EM_LOG_CONSOLE, "resmgr: Return of PIPE: (%d,%d), (%d,%d)", msg->_u.pipe_msg.fd[0], msg->_u.pipe_msg.remote_fd[0], msg->_u.pipe_msg.fd[1], msg->_u.pipe_msg.remote_fd[1]);
       }

       // Forward response to process

       sendto(sock, buf, 256, 0, (struct sockaddr *)process_get_peer_addr(msg->pid), sizeof(struct sockaddr_un));
     }
  }
  
  return 0;
}

int close_opened_fd(int job, int sock, char * buf) {

  struct message * msg = (struct message *)&buf[0];
  
  int fd = -1;
  unsigned char type;
  unsigned short major;
  int remote_fd;

  while (1) {

    fd = process_opened_fd(msg->pid, &type, &major, &remote_fd, (job == EXEC_JOB)?O_CLOEXEC:0);

    if (fd < 0)
      break;

    // Get the fd of the process

    // Close the fd for this process
    process_close_fd(msg->pid, fd);

    // Remove /proc/<pid>/fd/<fd> entry
    process_del_proc_fd_entry(msg->pid, fd);

    // Find fd in other processes
    if (process_find_open_fd(type, major, remote_fd) < 0) {

      // No more fd, close the fd in the driver

      if (major != vfs_major) { // Send close  msg to driver

	msg->msg_id = CLOSE;
	
	msg->_u.close_msg.fd = remote_fd;

	struct sockaddr_un driver_addr;

	driver_addr.sun_family = AF_UNIX;
	strcpy(driver_addr.sun_path, device_get_driver(type, major)->peer);

	if (DEBUG)
	  emscripten_log(EM_LOG_CONSOLE, "CLOSE send to: %s", driver_addr.sun_path);

	sendto(sock, buf, 256, 0, (struct sockaddr *) &driver_addr, sizeof(driver_addr));

	return 1; // Need to wait CLOSE response before closing the other ones
      }
      else {
	
	vfs_close(remote_fd);
      }
    }
  }

  return 0;
}

int do_exit(int sock, struct message * msg) {
      
  int exit_status = msg->_u.exit_msg.status;
  int pid = msg->pid;
  int ppid;
      
  if (ppid=process_exit(pid, exit_status << 8)) {

    msg->msg_id = WAIT|0x80;
    msg->pid = ppid;
    msg->_errno = 0;

    msg->_u.wait_msg.pid = pid;
    msg->_u.wait_msg.status = exit_status << 8;

    if (DEBUG)
      emscripten_log(EM_LOG_CONSOLE, "EXIT: Send wait response to parent %d -> status=%d", msg->pid, msg->_u.wait_msg.status);
    // Forward response to process
	
    sendto(sock, (char *)msg, 256, 0, (struct sockaddr *)process_get_peer_addr(msg->pid), sizeof(struct sockaddr_un));

    return 1;
  }

  return 0;
}
