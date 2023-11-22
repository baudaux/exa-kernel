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

#ifndef DEBUG
#define DEBUG 0
#endif

#if DEBUG
#include <emscripten.h>
#else
#define emscripten_log(...)
#endif

#define UTS_SYSNAME    "EXA"
#define UTS_NODENAME   "exaequos"
#define UTS_RELEASE    "0.1.0"
#define UTS_VERSION    "#1"
#ifdef __wasm64__
#define UTS_MACHINE    "wasm64"
#else
#define UTS_MACHINE    "wasm32"
#endif
#define UTS_DOMAINNAME ""

/* Be careful when changing this path as it may be also used in javascript */

#define RESMGR_ROOT "/var"
#define RESMGR_FILE "resmgr.peer"
#define RESMGR_PATH RESMGR_ROOT "/" RESMGR_FILE

#define PIPE_PATH "/var/pipe.peer"
#define IP_PATH "/var/ip.peer"

#define NB_ITIMERS_MAX 64

#define NB_JOBS_MAX    16

struct itimer {

  pid_t pid;
  int fd;
  int once;
};

enum {
  // NO_JOB=0
  EXIT_JOB = 1,
  EXEC_JOB,
  DUP_JOB
};

static struct job jobs[NB_JOBS_MAX];

static unsigned short vfs_major;
static unsigned short vfs_minor;

int close_opened_fd(int job, int sock, char * buf);
int do_exit(int sock, struct itimer * itimers, struct message * msg, int len, struct sockaddr_un * remote_addr);
int finish_exit(int sock, struct message * msg);
void process_to_kill(int sock, struct itimer * itimers);

static pid_t processes_to_kill[128];
static int process_index = 0;
static int nb_processes_to_kill = 0;
static int process_sig;

int main() {

  int sock;
  struct sockaddr_un local_addr, remote_addr, tty_addr;
  int bytes_rec;
  socklen_t len;
  char buf[1256];
  struct message * msg = (struct message *)&buf[0];

  struct itimer itimers[NB_ITIMERS_MAX];

  // Use console.log as tty is not yet started

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

  emscripten_log(EM_LOG_CONSOLE, "vfs device registered: major=%d minor=%d", vfs_major, vfs_minor);

  // First, we create tty process
  
  create_tty_process();
  
  while (1) {

    fd_set rfds;

    FD_ZERO(&rfds);
    FD_SET(sock, &rfds);

    int fd_max = sock;

    int timer_is_set = 0;

    for (int i = 0; i < NB_ITIMERS_MAX; ++i) {
      
      if (itimers[i].fd >= 0) {

	FD_SET(itimers[i].fd, &rfds);

	//  emscripten_log(EM_LOG_CONSOLE, "resmgr: itimer fd=%d", itimers[i].fd);

	if (itimers[i].fd > fd_max)
	  fd_max = itimers[i].fd;

	timer_is_set = 1;
      }
    }

    //  emscripten_log(EM_LOG_CONSOLE, "resmgr: timer_is_set=%d fd_max=%d", timer_is_set, fd_max);

    int retval = 0;

    if (timer_is_set > 0) {

      retval = select(fd_max+1, &rfds, NULL, NULL, NULL);

      //emscripten_log(EM_LOG_CONSOLE, "resmgr: retval=%d", retval);

      if (retval < 0)
	continue;

      if (!FD_ISSET(sock, &rfds)) {

	//  emscripten_log(EM_LOG_CONSOLE, "resmgr: !! timer !!");

	for (int i = 0; i < NB_ITIMERS_MAX; ++i) {
      
	  if ( (itimers[i].fd >= 0) && (FD_ISSET(itimers[i].fd, &rfds)) ) {

	    uint64_t count = 0;

	    read(itimers[i].fd, &count, sizeof(count));

	    if (itimers[i].once)
	      itimers[i].fd = -1; // Do not automatically listen fd next time 

	    //  emscripten_log(EM_LOG_CONSOLE, "resmgr: ITIMER count=%d", count);

	    msg->msg_id = KILL;
	    msg->pid = itimers[i].pid;
	    msg->_u.kill_msg.pid = itimers[i].pid;
	    msg->_u.kill_msg.sig = SIGALRM;

	    int action = process_kill(msg->_u.kill_msg.pid, msg->_u.kill_msg.sig, &msg->_u.kill_msg.act, sock);

	    //  emscripten_log(EM_LOG_CONSOLE, "resmgr: process_kill action=%d", action);

	    if (action == 1) { // default

	      do_exit(sock, itimers, msg, 256, NULL);
	    }
	  }
	}

	continue;
      }
      
    }
    
    bytes_rec = recvfrom(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, &len);

    emscripten_log(EM_LOG_CONSOLE, "resmgr: msg %d received from %s (%d)", msg->msg_id, remote_addr.sun_path,bytes_rec);

    if (bytes_rec == 0)
      continue;

    if (msg->msg_id == REGISTER_DRIVER) {
      
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

	  emscripten_log(EM_LOG_CONSOLE, "Send msg to %s", tty_addr.sun_path);
	}
      
    }
    else if (msg->msg_id == MOUNT) {

      struct device * dev = NULL;
      char pathname[1024];

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
	emscripten_log(EM_LOG_CONSOLE, "Mount path: %s", pathname);

	if (strcmp((const char *)&(pathname[0]),"/media/localhost") == 0) {

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

      emscripten_log(EM_LOG_CONSOLE, "SOCKET %d %d %d %d", msg->pid, msg->_u.socket_msg.domain, msg->_u.socket_msg.type, msg->_u.socket_msg.protocol);

      if ( (msg->_u.socket_msg.domain == AF_INET) || (msg->_u.socket_msg.domain == AF_INET6) ) {
	
	struct sockaddr_un ip_addr;
	
	memset(&ip_addr, 0, sizeof(ip_addr));
	ip_addr.sun_family = AF_UNIX;
	strcpy(ip_addr.sun_path, IP_PATH);
	
	sendto(sock, buf, 256, 0, (struct sockaddr *) &ip_addr, sizeof(ip_addr));
      }
      else {

	msg->msg_id |= 0x80;
	msg->_errno = 0;

	msg->_u.socket_msg.fd = process_create_fd(msg->pid, -2, (unsigned char)(msg->_u.socket_msg.type & 0xff), (unsigned short)(msg->_u.socket_msg.domain & 0xffff), (unsigned short)(msg->_u.socket_msg.protocol & 0xffff), msg->_u.socket_msg.type); // type contains flags

	// Add /proc/<pid>/fd/<fd> entry
	process_add_proc_fd_entry(msg->pid, msg->_u.socket_msg.fd, "socket");

        emscripten_log(EM_LOG_CONSOLE, "SOCKET created %d", msg->_u.socket_msg.fd);

	sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      }
      
    }
    else if (msg->msg_id == (SOCKET|0x80)) {

      if (msg->_errno == 0) {

	msg->_u.socket_msg.fd = process_create_fd(msg->pid, msg->_u.socket_msg.remote_fd, (unsigned char)(msg->_u.socket_msg.type & 0xff), (unsigned short)(msg->_u.socket_msg.domain & 0xffff), (unsigned short)(msg->_u.socket_msg.protocol & 0xffff), msg->_u.socket_msg.type); // type contains flags

	// Add /proc/<pid>/fd/<fd> entry
	process_add_proc_fd_entry(msg->pid, msg->_u.socket_msg.fd, "socket");

	emscripten_log(EM_LOG_CONSOLE, "SOCKET created %d", msg->_u.socket_msg.fd);
      }
      
      // Forward response to process

      struct sockaddr_un addr;

      process_get_peer_addr(msg->pid, &addr);

      sendto(sock, buf, 256, 0, (struct sockaddr *)&addr, sizeof(struct sockaddr_un));
    }
    else if (msg->msg_id == BIND) {

      msg->msg_id |= 0x80;
      msg->_errno = 0;

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

	emscripten_log(EM_LOG_CONSOLE, "vfs_get_path: new_path=%s remote_fd=%d", new_path, remote_fd);
	
	if (remote_fd == 0) {

	  struct vnode * vnode = vfs_get_vnode(remote_fd);

	  emscripten_log(EM_LOG_CONSOLE, "vnode is a device or mount point: %d %d %d %s",vnode->_u.dev.type, vnode->_u.dev.major, vnode->_u.dev.minor, device_get_driver(vnode->_u.dev.type, vnode->_u.dev.major)->peer);

	  char node_path[1024];
	
	  vfs_get_path(vnode, node_path);

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

	emscripten_log(EM_LOG_CONSOLE, "vnode not found");

	msg->msg_id |= 0x80;
	msg->_errno = ENOENT;
	
	sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      }
    }
    else if (msg->msg_id == (OPEN|0x80)) {
      
      emscripten_log(EM_LOG_CONSOLE, "Response from OPEN from %d: errno=%d flags=%x mode=%x %s pid=%d remote_fd=%d", msg->pid, msg->_errno, msg->_u.open_msg.flags, msg->_u.open_msg.mode, msg->_u.open_msg.pathname, msg->pid, msg->_u.open_msg.remote_fd);

      if (msg->_errno == 0) {

	msg->_u.open_msg.fd = process_create_fd(msg->pid, msg->_u.open_msg.remote_fd, msg->_u.open_msg.type, msg->_u.open_msg.major, msg->_u.open_msg.minor, msg->_u.open_msg.flags);

	// Add /proc/<pid>/fd/<fd> entry
	process_add_proc_fd_entry(msg->pid, msg->_u.open_msg.fd, (char *)msg->_u.open_msg.pathname);
      }

      // Forward response to process

      struct sockaddr_un addr;

      process_get_peer_addr(msg->pid, &addr);
       
      sendto(sock, buf, 1256, 0, (struct sockaddr *)&addr, sizeof(struct sockaddr_un));
      
    }
    else if (msg->msg_id == CLOSE) {

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

	  if ( !( (type == FS_DEV) && (major == vfs_major) ) ) {

	    struct sockaddr_un driver_addr;

	    driver_addr.sun_family = AF_UNIX;
	    strcpy(driver_addr.sun_path, device_get_driver(type, major)->peer);

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

	  emscripten_log(EM_LOG_CONSOLE, "CLOSE: do not close");

	  // Other fd are there, do not close fd in the driver

	  msg->msg_id |= 0x80;
	  msg->_errno = 0;

	  sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
	}
      }
      else {

	emscripten_log(EM_LOG_CONSOLE, "CLOSE: not found");

	msg->msg_id |= 0x80;
	msg->_errno = EBADF;

	sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      }
    }
    else if (msg->msg_id == (CLOSE|0x80)) {

      emscripten_log(EM_LOG_CONSOLE, "Response from CLOSE from %d", msg->pid);

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

	  finish_exit(sock, (struct message *)&buf2[0]);
	  
	  del_pending_job(jobs, job, msg->pid);
	  
	  if (nb_processes_to_kill > 0) {
	    ++process_index;
	    process_to_kill(sock, itimers);
	  }
	}
	else if (job == DUP_JOB) {

	  char * buf2;
	  int buf2_size;
	  struct sockaddr_un * addr2;

	  unsigned long job = get_pending_job(jobs, msg->pid, &buf2, &buf2_size, &addr2);

	  struct message * msg2 = (struct message *)&buf2[0];

	  msg2->_u.dup_msg.new_fd = process_dup(msg->pid, msg2->_u.dup_msg.fd, msg2->_u.dup_msg.new_fd);

	  // Add /proc/<pid>/fd/<fd> entry
	  process_add_proc_fd_entry(msg->pid, msg2->_u.dup_msg.new_fd, "dup");
	  
	  msg2->msg_id |= 0x80;
	  msg2->_errno = 0;

	  continue_pending_job(jobs, msg->pid, sock);
	}
      }
      else {

	// Forward response to process

	struct sockaddr_un addr;

	process_get_peer_addr(msg->pid, &addr);

	sendto(sock, buf, 256, 0, (struct sockaddr *)&addr, sizeof(struct sockaddr_un));
      }
      
    }
    else if (msg->msg_id == READ) {

      emscripten_log(EM_LOG_CONSOLE, "READ from %d: %d %d", msg->pid, msg->_u.io_msg.fd, msg->_u.io_msg.len);

      struct message * reply = (struct message *) malloc(12+sizeof(struct io_message)+msg->_u.io_msg.len);

      reply->msg_id = READ|0x80;
      reply->pid = msg->pid;
      reply->_u.io_msg.fd = msg->_u.io_msg.fd;

      int len = vfs_read(reply->_u.io_msg.fd, reply->_u.io_msg.buf, msg->_u.io_msg.len);

      if (len >= 0) {
	
	emscripten_log(EM_LOG_CONSOLE, "READ done : %d bytes", len);

	reply->_u.io_msg.len = len;
	      
	reply->_errno = 0;
      }
      else {

	reply->_errno = EBADF;
      }
      
      sendto(sock, reply, 12+sizeof(struct io_message)+reply->_u.io_msg.len, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

      free(reply);
    }
    else if (msg->msg_id == WRITE) {

      emscripten_log(EM_LOG_CONSOLE, "WRITE from %d: %d %d", msg->pid, msg->_u.io_msg.fd, msg->_u.io_msg.len);

      char * buf2 = msg->_u.io_msg.buf;

      if (msg->_u.io_msg.len > (bytes_rec - 20)) {

	emscripten_log(EM_LOG_CONSOLE, "localfs: WRITE need to read %d remaining bytes (%d read)", msg->_u.io_msg.len - (bytes_rec - 20), bytes_rec - 20);

	buf2 =(char *)malloc(msg->_u.io_msg.len);

	memcpy(buf2, msg->_u.io_msg.buf, bytes_rec - 20);

	int bytes_rec2 = recvfrom(sock, buf2+bytes_rec - 20, msg->_u.io_msg.len - (bytes_rec - 20), 0, (struct sockaddr *) &remote_addr, &len);

	emscripten_log(EM_LOG_CONSOLE, "localfs: WRITE %d read", bytes_rec2);
      }

      msg->msg_id |= 0x80;
      
      if (vfs_write(msg->_u.io_msg.fd, buf2, msg->_u.io_msg.len) >= 0)  {

	emscripten_log(EM_LOG_CONSOLE, "WRITE done");
	      
	msg->_errno = 0;
      }
      else {

	emscripten_log(EM_LOG_CONSOLE, "WRITE  KO");

	msg->_errno = EBADF;
      }
      
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

      if (buf2 != msg->_u.io_msg.buf) {

	free(buf2);
      }
    }
    else if (msg->msg_id == IOCTL) {
      
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
      
      emscripten_log(EM_LOG_CONSOLE, "FCNTL from %d: %d %d", msg->pid, msg->_u.fcntl_msg.fd, msg->_u.fcntl_msg.cmd);

      msg->_u.fcntl_msg.ret = 0;
      msg->_errno = 0;

      if (msg->_u.fcntl_msg.cmd == F_SETFL) {

	emscripten_log(EM_LOG_CONSOLE, "FCNTL from %d: setting fs_flags of %d", msg->pid, msg->_u.fcntl_msg.fd);

	int flags;

	memcpy(&flags, msg->_u.fcntl_msg.buf, sizeof(int));
	
	msg->_errno = (process_set_fs_flags(msg->pid, msg->_u.fcntl_msg.fd, flags) < 0)?EBADFD:0;

	if (msg->_errno) {

	  msg->msg_id |= 0x80;
	  sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
	}
	else {

	  unsigned char type;
	  unsigned short major;
	  int remote_fd;

	  if (process_get_fd(msg->pid, msg->_u.fcntl_msg.fd, &type, &major, &remote_fd) == 0) {

	    emscripten_log(EM_LOG_CONSOLE, "FCNTL from %d: type=%d major=%d remote_fd=%d", msg->pid, type, major, remote_fd);
	    
	    if ( (type == FS_DEV) && (major == vfs_major) ) { // vfs

	      if (vfs_set_fs_flags(remote_fd, flags) < 0)
		msg->_errno = EBADFD;

	      msg->msg_id |= 0x80;
	      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
		
	    }
	    else { // Send message to driver

	      msg->_u.fcntl_msg.fd = remote_fd;

	      struct sockaddr_un driver_addr;

	      driver_addr.sun_family = AF_UNIX;
	      strcpy(driver_addr.sun_path, device_get_driver(type, major)->peer);

	      emscripten_log(EM_LOG_CONSOLE, "FCNTL from %d: send to %s", msg->pid, driver_addr.sun_path);

	      //TODO: receive in each driver
	      
	      sendto(sock, buf, 256, 0, (struct sockaddr *) &driver_addr, sizeof(driver_addr));
	    }
	  }
	  else {

	    msg->_errno = EBADFD;
	    
	    msg->msg_id |= 0x80;
	    sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
	  }
	}
      }
      else {

	if (msg->_u.fcntl_msg.cmd == F_GETFL) {

	  msg->_u.fcntl_msg.ret = process_get_fs_flags(msg->pid, msg->_u.fcntl_msg.fd);
	}
	else if (msg->_u.fcntl_msg.cmd == F_SETFD) {

	  int flags;

	  memcpy(&flags, msg->_u.fcntl_msg.buf, sizeof(int));
	
	  msg->_errno = process_set_fd_flags(msg->pid, msg->_u.fcntl_msg.fd, flags);
	}
	else if (msg->_u.fcntl_msg.cmd == F_GETFD) {

	  msg->_u.fcntl_msg.ret = process_get_fd_flags(msg->pid, msg->_u.fcntl_msg.fd);
	}
	else if (msg->_u.fcntl_msg.cmd == F_DUPFD) {

	  int fd;

	  memcpy(&fd, msg->_u.fcntl_msg.buf, sizeof(int));

	  msg->_u.fcntl_msg.ret = process_dup(msg->pid, fd, -1);

	  // Add /proc/<pid>/fd/<fd> entry
	  process_add_proc_fd_entry(msg->pid, msg->_u.fcntl_msg.ret, "dup");
	}
	else if (msg->_u.fcntl_msg.cmd == F_DUPFD_CLOEXEC) {

	  int fd;

	  memcpy(&fd, msg->_u.fcntl_msg.buf, sizeof(int));

	  msg->_u.fcntl_msg.ret = process_dup(msg->pid, fd, -1);

	  // Add /proc/<pid>/fd/<fd> entry
	  process_add_proc_fd_entry(msg->pid, msg->_u.fcntl_msg.ret, "dup");
	
	  int flags = process_get_fd_flags(msg->pid, msg->_u.fcntl_msg.ret);

	  process_set_fd_flags(msg->pid, msg->_u.fcntl_msg.ret, flags|FD_CLOEXEC);
	}
	else if (msg->_u.fcntl_msg.cmd == F_GETFL) {

	  msg->_u.fcntl_msg.ret = process_get_fs_flags(msg->pid, msg->_u.fcntl_msg.fd);
	}

	msg->msg_id |= 0x80;
	sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      }
    }
    else if (msg->msg_id == (FCNTL|0x80)) {

      struct sockaddr_un addr;

      process_get_peer_addr(msg->pid, &addr);

      sendto(sock, buf, 256, 0, (struct sockaddr *)&addr, sizeof(struct sockaddr_un));
    }
    else if (msg->msg_id == SETSID) {

      emscripten_log(EM_LOG_CONSOLE, "SETSID from %d", msg->pid);

      msg->_u.setsid_msg.sid = process_setsid(msg->pid);
      
      msg->msg_id |= 0x80;
      msg->_errno = 0;

      if (msg->_u.setsid_msg.sid < 0)
	msg->_errno = EPERM;

      emscripten_log(EM_LOG_CONSOLE, "SETSID --> %d", msg->_u.setsid_msg.sid);

      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      
    }
    else if (msg->msg_id == GETSID) {

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

      //TODO reset pending signals in child

      emscripten_log(EM_LOG_CONSOLE, "FORK from %d", msg->pid);

      msg->_u.fork_msg.child = process_fork(-1, msg->pid, NULL);
      
      msg->msg_id |= 0x80;
      msg->_errno = 0;

      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      
    }
    else if (msg->msg_id == EXECVE) {

      emscripten_log(EM_LOG_CONSOLE, "EXECVE from %d: %lu", msg->pid, msg->_u.execve_msg.args_size);

      if (msg->_u.execve_msg.args_size == 0xffffffff) { // 2nd time once new iframe is created

	if (is_pending_job(jobs, msg->pid) == EXEC_JOB) {

	  // Close all opened fd with fd_flag FD_CLOEXEC

	  unsigned char type;
	  unsigned short major;
	  int remote_fd;

	  if (process_opened_fd(msg->pid, &type, &major, &remote_fd, FD_CLOEXEC) >= 0) {
	    emscripten_log(EM_LOG_CONSOLE, "EXECVE from %d: there are O_CLOEXEC opened fd", msg->pid);
	    
	    if (close_opened_fd(EXEC_JOB, sock, buf) > 0) {

	      continue; // Wait CLOSE response before closing the other opened fd
	    }
	  }
	  
	  continue_pending_job(jobs, msg->pid, sock);
	}
      }
      else { // first time before creating new iframe
	
	process_reset_sigactions(msg->pid);

        msg->msg_id |= 0x80;

	add_pending_job(jobs, EXEC_JOB, msg->pid, msg, bytes_rec, &remote_addr);
      }
    }
    else if (msg->msg_id == DUP) {

      emscripten_log(EM_LOG_CONSOLE, "DUP from %d: fd=%d new_fd=%d", msg->pid, msg->_u.dup_msg.fd, msg->_u.dup_msg.new_fd);

      {

	unsigned char type;
	unsigned short major;
	int remote_fd;

	int res = process_get_fd(msg->pid, msg->_u.dup_msg.fd, &type, &major, &remote_fd);

	emscripten_log(EM_LOG_CONSOLE, "DUP -> fd %d is %d %d %d (%s)", msg->_u.dup_msg.fd, type, major, remote_fd, device_get_driver(type, major)->peer);
      }

      if (msg->_u.dup_msg.fd != msg->_u.dup_msg.new_fd) { // do nothing if values are equal

	if (msg->_u.dup_msg.new_fd >= 0) { // Check if new_fd already exists and close it
	  unsigned char type;
	  unsigned short major;
	  int remote_fd;

	  int res = process_get_fd(msg->pid, msg->_u.dup_msg.new_fd, &type, &major, &remote_fd);

	  if (res >= 0) { // new_fd exists

	    emscripten_log(EM_LOG_CONSOLE, "DUP -> new_fd %d exists %d %d %d", msg->_u.dup_msg.new_fd, type, major, remote_fd);

	    // Close the fd for this process
	    process_close_fd(msg->pid, msg->_u.dup_msg.new_fd);

	    // Remove /proc/<pid>/fd/<fd> entry
	    process_del_proc_fd_entry(msg->pid, msg->_u.dup_msg.new_fd);

	    // Find fd in other processes
	    if (process_find_open_fd(type, major, remote_fd) < 0) {

	      emscripten_log(EM_LOG_CONSOLE, "DUP -> new_fd has to be fully closed %d %d", major, vfs_major);

	      // No more fd, close the fd in the driver

	      if ((type == FS_DEV) && (major == vfs_major)) {

		vfs_close(remote_fd);
	      }
	      else { // Send close  msg to driver

		add_pending_job(jobs, DUP_JOB, msg->pid, msg, bytes_rec, &remote_addr);

		msg->msg_id = CLOSE;
	
		msg->_u.close_msg.fd = remote_fd;

		struct sockaddr_un driver_addr;

		driver_addr.sun_family = AF_UNIX;
		strcpy(driver_addr.sun_path, device_get_driver(type, major)->peer);

		emscripten_log(EM_LOG_CONSOLE, "CLOSE send to: %s", driver_addr.sun_path);

		sendto(sock, buf, 256, 0, (struct sockaddr *) &driver_addr, sizeof(driver_addr));

		continue; // Need to wait CLOSE response before closing the other ones
	      }
	    }
	  }
	}

	msg->_u.dup_msg.new_fd = process_dup(msg->pid, msg->_u.dup_msg.fd, msg->_u.dup_msg.new_fd);

	unsigned char type;
	unsigned short major;
	int remote_fd;

	int res = process_get_fd(msg->pid, msg->_u.dup_msg.new_fd, &type, &major, &remote_fd);

	emscripten_log(EM_LOG_CONSOLE, "DUP -> new_fd %d is now %d %d %d", msg->_u.dup_msg.new_fd, type, major, remote_fd);

	// Add /proc/<pid>/fd/<fd> entry
	process_add_proc_fd_entry(msg->pid, msg->_u.dup_msg.new_fd, "dup");
      }
      
      msg->msg_id |= 0x80;
      msg->_errno = 0;

      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == GETPPID) {

      emscripten_log(EM_LOG_CONSOLE, "GETPPID from %d", msg->pid);

      msg->_u.getppid_msg.ppid = process_getppid(msg->pid);
      
      //dump_processes();
      
      msg->msg_id |= 0x80;
      msg->_errno = 0;

      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr)); 
    }
    else if (msg->msg_id == GETPGID) {

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

      emscripten_log(EM_LOG_CONSOLE, "SETPGID from %d: %d %d", msg->pid, msg->_u.getpgid_msg.pid, msg->_u.getpgid_msg.pgid);

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

      emscripten_log(EM_LOG_CONSOLE, "IS_OPEN from %d: %d", msg->pid, msg->_u.is_open_msg.fd);

      msg->_errno = ENOENT;

      if (process_get_fd(msg->pid, msg->_u.is_open_msg.fd, &msg->_u.is_open_msg.type, &msg->_u.is_open_msg.major, &msg->_u.is_open_msg.remote_fd) == 0) {

	struct driver * drv = device_get_driver(msg->_u.is_open_msg.type, msg->_u.is_open_msg.major);

	if (drv) {

	  strcpy(msg->_u.is_open_msg.peer, drv->peer);

	  emscripten_log(EM_LOG_CONSOLE, "IS_OPEN found %d %d %d %s", msg->_u.is_open_msg.type, msg->_u.is_open_msg.major, msg->_u.is_open_msg.remote_fd, msg->_u.is_open_msg.peer);

	  msg->_errno = 0;
	}
      }
      msg->msg_id |= 0x80;

      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == READLINK) {
      
      emscripten_log(EM_LOG_CONSOLE, "READLINK from %d: %s", msg->pid, msg->_u.readlink_msg.pathname_or_buf);

      char * pathname;
      char str[1024];

      // TODO: other self conversion
      if (strncmp(msg->_u.readlink_msg.pathname_or_buf, "/proc/self/", 11) == 0) {

	sprintf(str, "/proc/%d/%s", msg->pid & 0xffff, msg->_u.readlink_msg.pathname_or_buf+11);

	pathname = &str[0];
      }
      else {

	pathname = msg->_u.readlink_msg.pathname_or_buf;
      }
      
      struct vnode * node = vfs_find_node(pathname, NULL);

      if (node->type == VSYMLINK) {

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
      char * trail = NULL;

      int res = vfs_stat((const char *)path, &stat_buf, &vnode, &trail);

      if (res == 0) {

	if (vnode == NULL) {

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
	  
	  if ( (vnode->type == VMOUNT) && trail )
	    strcat(node_path, trail);

	  strcpy(msg->_u.stat_msg.pathname_or_buf, node_path);

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

      emscripten_log(EM_LOG_CONSOLE, "Response from STAT from %d: errno=%d", msg->pid, msg->_errno);
      
      // Forward response to process

      struct sockaddr_un addr;

      process_get_peer_addr(msg->pid, &addr);
      
      sendto(sock, buf, 1256, 0, (struct sockaddr *)&addr, sizeof(struct sockaddr_un));
      
    }
    else if (msg->msg_id == LSTAT) {
      
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
      char * trail = NULL;

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

	  if ( (vnode->type == VMOUNT) && trail)
	    strcat(node_path, trail);

	  strcpy(msg->_u.stat_msg.pathname_or_buf, node_path);
	  
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

      emscripten_log(EM_LOG_CONSOLE, "Response from LSTAT from %d", msg->pid);

      // Forward response to process

      struct sockaddr_un addr;

      process_get_peer_addr(msg->pid, &addr);
      
      sendto(sock, buf, 1256, 0, (struct sockaddr *)&addr, sizeof(struct sockaddr_un));
      
    }
    else if (msg->msg_id == TIMERFD_CREATE) {

      emscripten_log(EM_LOG_CONSOLE, "TIMERFD_CREATE from %d (%d)", msg->pid, msg->_u.timerfd_create_msg.clockid);

      msg->_u.timerfd_create_msg.fd = process_create_fd(msg->pid, -3, 0, 0, msg->_u.timerfd_create_msg.clockid & 0xffff, msg->_u.timerfd_create_msg.flags);

      msg->msg_id |= 0x80;
      msg->_errno = 0;
      
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == GETCWD) {

      emscripten_log(EM_LOG_CONSOLE, "GETCWD from %d", msg->pid);

      strcpy((char *)msg->_u.cwd_msg.buf, process_getcwd(msg->pid));
      msg->_u.cwd_msg.len = strlen((char *)msg->_u.cwd_msg.buf)+1;
      
      msg->msg_id |= 0x80;
      msg->_errno = 0;

      sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr)); 
    }
    else if (msg->msg_id == CHDIR) {

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

      char * trail = NULL;

      struct vnode * vnode = vfs_find_node(dir, &trail);
  
      if (vnode) {

	emscripten_log(EM_LOG_CONSOLE, "CHDIR resolved %s", dir);

	char new_dir[1024];
	
	vfs_get_path(vnode, new_dir);

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

	  msg->_u.cwd2_msg.major = vnode->_u.dev.major;
	  msg->_u.cwd2_msg.minor = vnode->_u.dev.minor;
	  
	  strcpy(msg->_u.cwd2_msg.buf, new_dir);

	  emscripten_log(EM_LOG_CONSOLE, "CHDIR from %d: %s -> send to driver", msg->pid, msg->_u.cwd2_msg.buf);

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

      emscripten_log(EM_LOG_CONSOLE, "Return from CHDIR from %d: %s", msg->pid, msg->_u.cwd2_msg.buf);

      if (msg->_errno == 0) {

	if (process_chdir(msg->pid, (char *)msg->_u.cwd2_msg.buf) < 0)
	    msg->_errno = ENOENT;
      }

      struct sockaddr_un addr;

      process_get_peer_addr(msg->pid, &addr);

      sendto(sock, buf, 1256, 0, (struct sockaddr *)&addr, sizeof(struct sockaddr_un));
    }
    else if (msg->msg_id == GETDENTS) {

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

      emscripten_log(EM_LOG_CONSOLE, "WAIT from %d: pid=%d option=%d", msg->pid, msg->_u.wait_msg.pid, msg->_u.wait_msg.options);

      if (msg->_u.wait_msg.pid=process_wait(msg->pid, msg->_u.wait_msg.pid, msg->_u.wait_msg.options, &msg->_u.wait_msg.status)) {

	emscripten_log(EM_LOG_CONSOLE, "WAIT -> %d status=%d", msg->_u.wait_msg.pid, msg->_u.wait_msg.status);

	msg->msg_id |= 0x80;

	if (msg->_u.wait_msg.pid >= 0)
	  msg->_errno = 0;
	else
	  msg->_errno = ECHILD;
	
	sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      }
      
    }
    else if (msg->msg_id == EXIT) {

      emscripten_log(EM_LOG_CONSOLE, "EXIT from %d: status=%d", msg->pid, msg->_u.exit_msg.status);

      do_exit(sock, itimers, msg, bytes_rec, &remote_addr);

    }
    else if (msg->msg_id == SEEK) {

      emscripten_log(EM_LOG_CONSOLE, "SEEK from %d: fd=%d off=%d whence=%d", msg->pid, msg->_u.seek_msg.fd, msg->_u.seek_msg.offset, msg->_u.seek_msg.whence);

      msg->msg_id |= 0x80;
      
      msg->_u.seek_msg.offset = vfs_seek(msg->_u.seek_msg.fd, msg->_u.seek_msg.offset, msg->_u.seek_msg.whence);

      if (msg->_u.seek_msg.offset >= 0)  {

	emscripten_log(EM_LOG_CONSOLE, "SEEK: done");
	
	msg->_errno = 0;
      }
      else {

	msg->_errno = EBADF;
      }
      
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == SIGACTION) {

      emscripten_log(EM_LOG_CONSOLE, "SIGACTION from %d: signum=%d", msg->pid, msg->_u.sigaction_msg.signum);

      msg->_errno = process_sigaction(msg->pid, msg->_u.sigaction_msg.signum, &msg->_u.sigaction_msg.act);
      
      msg->msg_id |= 0x80;
      
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

    }
    else if (msg->msg_id == SIGPROCMASK) {

      emscripten_log(EM_LOG_CONSOLE, "SIGPROGMASK from %d: how=%d", msg->pid, msg->_u.sigprocmask_msg.how);

      msg->_errno = process_sigprocmask(msg->pid, msg->_u.sigprocmask_msg.how, &msg->_u.sigprocmask_msg.sigset);
      
      msg->msg_id |= 0x80;
      
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

    }
    else if (msg->msg_id == END_OF_SIGNAL) {

      emscripten_log(EM_LOG_CONSOLE, "END_OF_SIGNAL from %d: pid=%d sig=%d", msg->pid, msg->_u.kill_msg.pid, msg->_u.kill_msg.sig);

      // In case of a pending wait

      int ret = process_exit_child(msg->pid, sock);
	
      emscripten_log(EM_LOG_CONSOLE, "KILL: process_exit_child: %d", ret);

      //TODO other cases
      }
    else if (msg->msg_id == KILL) {

      emscripten_log(EM_LOG_CONSOLE, "KILL from %d: pid=%d sig=%d", msg->pid, msg->_u.kill_msg.pid, msg->_u.kill_msg.sig);

      msg->msg_id |= 0x80;
      msg->_errno = 0;

      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

      msg->msg_id &= 0x7f;
      
      if (!(msg->_u.kill_msg.pid & 0x60000000)) { // unique process

	int action = process_kill(msg->_u.kill_msg.pid, msg->_u.kill_msg.sig, &msg->_u.kill_msg.act, sock);

	emscripten_log(EM_LOG_CONSOLE, "KILL from %d: action=%d", msg->pid, action);
	if (action == 1) { // Default action

	  msg->pid = msg->_u.kill_msg.pid;
	  do_exit(sock, itimers, msg, bytes_rec, NULL);
	}
      }
      else if (msg->_u.kill_msg.pid & 0x40000000) { // session

	nb_processes_to_kill = process_get_session(msg->_u.kill_msg.pid & 0x0fffffff, processes_to_kill, 128);

	emscripten_log(EM_LOG_CONSOLE, "<-- process_get_session: session=%d ; %d proc to kill", msg->_u.kill_msg.pid & 0x0fffffff, nb_processes_to_kill);

	process_index = 0;
	process_sig = msg->_u.kill_msg.sig;

	process_to_kill(sock, itimers);
      }

      else if (msg->_u.kill_msg.pid & 0x20000000) { // group

	nb_processes_to_kill = process_get_group(msg->_u.kill_msg.pid & 0x0fffffff, processes_to_kill, 128);

	emscripten_log(EM_LOG_CONSOLE, "<-- process_get_group: grp=%d ; %d proc to kill", msg->_u.kill_msg.pid & 0x0fffffff, nb_processes_to_kill);

	process_index = 0;
	process_sig = msg->_u.kill_msg.sig;

	process_to_kill(sock, itimers);
      }
    }
    else if (msg->msg_id == EXA_RELEASE_SIGNAL) {
      
      emscripten_log(EM_LOG_CONSOLE, "EXA_RELEASE_SIGNAL from %d: sig=%d", msg->pid, msg->_u.exa_release_signal_msg.sig);
      
      process_signal_delivered(msg->pid, msg->_u.exa_release_signal_msg.sig);

      msg->msg_id |= 0x80;

      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == SETITIMER) {

      emscripten_log(EM_LOG_CONSOLE, "SETITIMER from %d: %d %d %d %d", msg->pid, msg->_u.setitimer_msg.val_sec, msg->_u.setitimer_msg.val_usec, msg->_u.setitimer_msg.it_sec, msg->_u.setitimer_msg.it_usec);

      int fd = process_setitimer(msg->pid, msg->_u.setitimer_msg.which, msg->_u.setitimer_msg.val_sec, msg->_u.setitimer_msg.val_usec, msg->_u.setitimer_msg.it_sec, msg->_u.setitimer_msg.it_usec);

      int i;

      // Find if there is already a timer for this pid
      for (i = 0; i < NB_ITIMERS_MAX; ++i) {
      
	if (itimers[i].pid == (msg->pid & 0xffff)) {

	  itimers[i].fd = fd;
	  itimers[i].once = (msg->_u.setitimer_msg.it_sec == 0) && (msg->_u.setitimer_msg.it_usec == 0);
	  break;
	}
      }

      if (i == NB_ITIMERS_MAX) {

	// Timer not found so we add it at the first free slot

	for (i = 0; i < NB_ITIMERS_MAX; ++i) {
      
	  if (itimers[i].fd < 0) {

	    itimers[i].pid = msg->pid & 0xffff;
	    itimers[i].fd = fd;
	    itimers[i].once = (msg->_u.setitimer_msg.it_sec == 0) && (msg->_u.setitimer_msg.it_usec == 0);
	    break;
	  }
	}
      }

      emscripten_log(EM_LOG_CONSOLE, "SETITIMER from %d: timerfd=%d", msg->pid, fd);

      msg->msg_id |= 0x80;
      
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == FACCESSAT) {
      
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
      
      char * trail = NULL;
      
      struct vnode * vnode = vfs_find_node((const char *)path, &trail);

      if (vnode == NULL) {

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

	if (trail)
	  strcat(node_path, trail);

	strcpy(msg->_u.faccessat_msg.pathname, node_path);

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

      struct sockaddr_un addr;

      process_get_peer_addr(msg->pid, &addr);

      sendto(sock, buf, 1256, 0, (struct sockaddr *)&addr, sizeof(struct sockaddr_un));
    }
    else if (msg->msg_id == FSTAT) {

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

       struct sockaddr_un addr;

       process_get_peer_addr(msg->pid, &addr);

       sendto(sock, buf, 256, 0, (struct sockaddr *)&addr, sizeof(struct sockaddr_un));
     }
     else if (msg->msg_id == UNAME) {
      
       emscripten_log(EM_LOG_CONSOLE, "UNAME from %d", msg->pid);

       msg->msg_id |= 0x80;
       msg->_errno = 0;

       int len = 0;

       strcpy(msg->_u.uname_msg.buf+len, UTS_SYSNAME);
       len += 65;

       strcpy(msg->_u.uname_msg.buf+len, UTS_NODENAME);
       len += 65;

       strcpy(msg->_u.uname_msg.buf+len, UTS_RELEASE);
       len += 65;

       strcpy(msg->_u.uname_msg.buf+len, UTS_VERSION);
       len += 65;

       strcpy(msg->_u.uname_msg.buf+len, UTS_MACHINE);
       len += 65;

       strcpy(msg->_u.uname_msg.buf+len, UTS_DOMAINNAME);
       len += 65;
      
       msg->_u.uname_msg.len = len;

       emscripten_log(EM_LOG_CONSOLE, "UNAME: %s %s %s", msg->_u.uname_msg.buf, msg->_u.uname_msg.buf+65, msg->_u.uname_msg.buf+130);
      
       sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

     }
    else if (msg->msg_id == FSYNC) {
      
      emscripten_log(EM_LOG_CONSOLE, "resmgr: FSYNC from %d: %d", msg->pid, msg->_u.fsync_msg.fd);
      
      msg->_errno = 0;
      msg->msg_id |= 0x80;
      
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

    }
    else if (msg->msg_id == UNLINKAT) {

      char * path;
      char new_path[1024];

      emscripten_log(EM_LOG_CONSOLE, "UNLINKAT from %d: %d %s", msg->pid, msg->_u.unlinkat_msg.dirfd, msg->_u.unlinkat_msg.path);

      if (msg->_u.unlinkat_msg.path[0] == '/') {

	path = msg->_u.unlinkat_msg.path;
      }
      else if (msg->_u.unlinkat_msg.dirfd == AT_FDCWD) {

	char * cwd = process_getcwd(msg->pid);

	if (cwd[strlen(cwd)-1] == '/')
	  sprintf(new_path, "%s%s", cwd, msg->_u.unlinkat_msg.path);
	else
	  sprintf(new_path, "%s/%s", cwd, msg->_u.unlinkat_msg.path);

	path = &new_path[0];
      }
      else {
	emscripten_log(EM_LOG_CONSOLE, "UNLINKAT OTHER THAN AT_FDCWD IS NOT IMPLEMENTED !!");
	continue;
      }

      emscripten_log(EM_LOG_CONSOLE, "UNLINKAT from %d: %s", msg->pid, path);
      
      char * trail = NULL;
      
      struct vnode * vnode = vfs_find_node((const char *)path, &trail);

      if (vnode == NULL) {

	emscripten_log(EM_LOG_CONSOLE, "UNLINKAT from %d: %s not found", msg->pid, path);

	msg->msg_id |= 0x80;
	msg->_errno = ENOENT;

	sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      }
      else if (vnode->type == VMOUNT) {

	struct sockaddr_un driver_addr;

	msg->_u.unlinkat_msg.type = vnode->_u.dev.type;
	msg->_u.unlinkat_msg.major = vnode->_u.dev.major;
	msg->_u.unlinkat_msg.minor = vnode->_u.dev.minor;

	char node_path[1024];
	
	vfs_get_path(vnode, node_path);

	if (trail)
	  strcat(node_path, trail);

	strcpy(msg->_u.unlinkat_msg.path, node_path);

	emscripten_log(EM_LOG_CONSOLE, "UNLINKAT: VMOUNT %s %s %s", node_path, trail, msg->_u.unlinkat_msg.path);

	driver_addr.sun_family = AF_UNIX;
	strcpy(driver_addr.sun_path, device_get_driver(vnode->_u.dev.type, vnode->_u.dev.major)->peer);

	sendto(sock, buf, 1256, 0, (struct sockaddr *) &driver_addr, sizeof(driver_addr));
      }
      else {

	msg->_errno = vfs_unlink(vnode);

	msg->msg_id |= 0x80;

	sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
	
      }
    }
    else if (msg->msg_id == (UNLINKAT|0x80)) {

      // Forward response to process

      struct sockaddr_un addr;

      process_get_peer_addr(msg->pid, &addr);

      sendto(sock, buf, 256, 0, (struct sockaddr *)&addr, sizeof(struct sockaddr_un));
    }
    else if (msg->msg_id == RENAMEAT) {

      // struct renameat_message is longer than 1256, read remaining bytes

      char * buf2 = malloc(12+sizeof(struct renameat_message));

      memmove(buf2, buf, bytes_rec);

      int rem_bytes_rec = recvfrom(sock, buf2+bytes_rec, 12+sizeof(struct renameat_message)-bytes_rec, 0, (struct sockaddr *) &remote_addr, &len);

      struct message * msg2 = (struct message *)&buf2[0];
      
      emscripten_log(EM_LOG_CONSOLE, "RENAMEAT from %d: %d %s %d %s", msg2->pid, msg2->_u.renameat_msg.olddirfd, msg2->_u.renameat_msg.oldpath, msg2->_u.renameat_msg.newdirfd, msg2->_u.renameat_msg.newpath);

      char * oldpath;
      char oldpath2[1024];

      if (msg2->_u.renameat_msg.oldpath[0] == '/') {

	oldpath = msg2->_u.renameat_msg.oldpath;
      }
      else if (msg2->_u.renameat_msg.olddirfd == AT_FDCWD) {

	char * cwd = process_getcwd(msg->pid);

	if (cwd[strlen(cwd)-1] == '/')
	  sprintf(oldpath2, "%s%s", cwd, msg2->_u.renameat_msg.oldpath);
	else
	  sprintf(oldpath2, "%s/%s", cwd, msg2->_u.renameat_msg.oldpath);

	oldpath = &oldpath2[0];
      }
      else {

	emscripten_log(EM_LOG_CONSOLE, "RENAMEAT OTHER THAN AT_FDCWD IS NOT IMPLEMENTED !!");
	continue;
      }
      
      char * oldtrail = NULL;
      
      struct vnode * oldvnode = vfs_find_node((const char *)oldpath, &oldtrail);

      if (oldvnode->type == NULL) {

	msg2->msg_id |= 0x80;
	msg2->_errno = ENOENT;

	sendto(sock, buf2, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

	free(buf2);
	
	continue;
      }
      
      char * newpath;
      char newpath2[1024];

      if (msg2->_u.renameat_msg.newpath[0] == '/') {

	newpath = msg2->_u.renameat_msg.newpath;
      }
      else if (msg2->_u.renameat_msg.newdirfd == AT_FDCWD) {

	char * cwd = process_getcwd(msg->pid);

	if (cwd[strlen(cwd)-1] == '/')
	  sprintf(newpath2, "%s%s", cwd, msg2->_u.renameat_msg.newpath);
	else
	  sprintf(newpath2, "%s/%s", cwd, msg2->_u.renameat_msg.newpath);
	
	newpath = &newpath2[0];
      }
      else {

	emscripten_log(EM_LOG_CONSOLE, "RENAMEAT OTHER THAN AT_FDCWD IS NOT IMPLEMENTED !!");
	continue;
      }

      emscripten_log(EM_LOG_CONSOLE, "RENAMEAT: %s %s", oldpath, newpath);
      
      char * newtrail = NULL;
      
      struct vnode * newvnode = vfs_find_node((const char *)newpath, &newtrail);
      
      if (oldvnode->type == VMOUNT) {

	if ( (newvnode->type == VMOUNT) && (oldvnode->_u.dev.type == newvnode->_u.dev.type) && (oldvnode->_u.dev.major == newvnode->_u.dev.major) && (oldvnode->_u.dev.minor == newvnode->_u.dev.minor) ) {

	  struct sockaddr_un driver_addr;
	  
	  char node_path[1024];
	
	  vfs_get_path(oldvnode, node_path);

	  if (oldtrail)
	    strcat(node_path, oldtrail);

	  strncpy(msg2->_u.renameat_msg.oldpath, node_path, 1024);

	  if (newtrail)
	    strncpy(msg2->_u.renameat_msg.newpath, newtrail, 1024);

	  msg2->_u.renameat_msg.type = oldvnode->_u.dev.type;
	  msg2->_u.renameat_msg.major = oldvnode->_u.dev.major;
	  msg2->_u.renameat_msg.minor = oldvnode->_u.dev.minor;

	  emscripten_log(EM_LOG_CONSOLE, "RENAMEAT: VMOUNT %s %s (%d %d %d)", msg2->_u.renameat_msg.oldpath, msg2->_u.renameat_msg.newpath, msg2->_u.renameat_msg.type, msg2->_u.renameat_msg.major, msg2->_u.renameat_msg.minor);

	  driver_addr.sun_family = AF_UNIX;
	  strcpy(driver_addr.sun_path, device_get_driver(oldvnode->_u.dev.type, oldvnode->_u.dev.major)->peer);

	  sendto(sock, buf2, 12+sizeof(struct renameat_message), 0, (struct sockaddr *) &driver_addr, sizeof(driver_addr));
	  
	}
	else {

	  emscripten_log(EM_LOG_CONSOLE, "RENAMEAT: MOVE ACROSS FILE SYSTEMS IS NOT IMPLEMENTED");

	  msg2->msg_id |= 0x80;
	  msg2->_errno = EACCES;

	  sendto(sock, buf2, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
	}
      }
      else {
	
	msg2->_errno = vfs_rename(oldvnode, newpath);

	msg2->msg_id |= 0x80;

	sendto(sock, buf2, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      }

      free(buf2);
    }
    else if (msg->msg_id == (RENAMEAT|0x80)) {

      emscripten_log(EM_LOG_CONSOLE, "Return of RENAMEAT: pid=%d errno=%d", msg->pid, msg->_errno);

      // Forward response to process

      struct sockaddr_un addr;

      process_get_peer_addr(msg->pid, &addr);

      sendto(sock, buf, 256, 0, (struct sockaddr *)&addr, sizeof(struct sockaddr_un));
    }
    else if (msg->msg_id == PTHREAD_CREATE) {
      
      emscripten_log(EM_LOG_CONSOLE, "resmgr: PTHREAD_CREATE from %d: tid=%d", msg->pid, msg->_u.pthread_create_msg.tid);

      //TODO
      
      msg->_errno = 0;
      msg->msg_id |= 0x80;
      
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

    }
    else if (msg->msg_id == PTHREAD_EXIT) {
      
      emscripten_log(EM_LOG_CONSOLE, "resmgr: PTHREAD_EXIT from %d: status=%d", msg->pid, msg->_u.pthread_exit_msg.status);

      //TODO
      
      msg->_errno = 0;
      msg->msg_id |= 0x80;
      
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == FTRUNCATE) {

      emscripten_log(EM_LOG_CONSOLE, "resmgr: FTRUNCATE from %d: fd=%d length=%d", msg->pid, msg->_u.ftruncate_msg.fd, msg->_u.ftruncate_msg.length);

      int ret = vfs_ftruncate(msg->_u.ftruncate_msg.fd, msg->_u.ftruncate_msg.length);
      msg->_errno = ret;
      msg->msg_id |= 0x80;
      
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      
    }
    else if (msg->msg_id == TRUNCATE) {

      emscripten_log(EM_LOG_CONSOLE, "resmgr: TRUNCATE from %d: path=%s length=%d", msg->pid, msg->_u.truncate_msg.buf, msg->_u.truncate_msg.length);

      //TODO
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

    fd = process_opened_fd(msg->pid, &type, &major, &remote_fd, (job == EXEC_JOB)?FD_CLOEXEC:0);

    if (fd < 0)
      break;

    emscripten_log(EM_LOG_CONSOLE, "close_opened_fd: process_opened_fd remote_fd=%d", remote_fd);

    // Get the fd of the process

    // Close the fd for this process
    process_close_fd(msg->pid, fd);

    // Remove /proc/<pid>/fd/<fd> entry
    process_del_proc_fd_entry(msg->pid, fd);

    // Find fd in other processes
    if (process_find_open_fd(type, major, remote_fd) < 0) {

      // No more fd, close the fd in the driver

      if ( (type == FS_DEV) && (major == vfs_major) ) {

	vfs_close(remote_fd);
      }
      else { // Send close  msg to driver

	struct message * msg2 = malloc(256); // do not change msg

	msg2->msg_id = CLOSE;
	msg2->pid = msg->pid & 0xffff;
	
	msg2->_u.close_msg.fd = remote_fd;

	struct sockaddr_un driver_addr;

	driver_addr.sun_family = AF_UNIX;
	strcpy(driver_addr.sun_path, device_get_driver(type, major)->peer);

	emscripten_log(EM_LOG_CONSOLE, "CLOSE send to: %s", driver_addr.sun_path);

	sendto(sock, (char *)msg2, 256, 0, (struct sockaddr *) &driver_addr, sizeof(driver_addr));

	free(msg2);
	
	return 1; // Need to wait CLOSE response before closing the other ones
      }
    }
  }

  return 0;
}

int do_exit(int sock, struct itimer * itimers, struct message * msg, int len, struct sockaddr_un * remote_addr) {

  emscripten_log(EM_LOG_CONSOLE, "--> do_exit: pid=%d", msg->pid);

  if (process_get_state(msg->pid) > ZOMBIE_STATE)
    return 0;

  // Close all opened fd

  // Find if there is already a timer for this pid

  for (int i = 0; i < NB_ITIMERS_MAX; ++i) {
      
    if (itimers[i].pid == (msg->pid & 0xffff)) {

      itimers[i].fd = -1;

      emscripten_log(EM_LOG_CONSOLE, "do_exit: clear itimer %d", i);
      break;
    }
  }
      
  process_clearitimer(msg->pid);

  unsigned char type;
  unsigned short major;
  int remote_fd;
      
  if (process_opened_fd(msg->pid, &type, &major, &remote_fd, 0) >= 0) {

    emscripten_log(EM_LOG_CONSOLE, "EXIT from %d: there are opened fd", msg->pid);

    if (close_opened_fd(EXIT_JOB, sock, msg) > 0) {

      msg->msg_id |= 0x80;

      add_pending_job(jobs, EXIT_JOB, msg->pid, msg, len, remote_addr);
	
      return 1; // Wait CLOSE response before closing the other opened fd
    }
  }

  finish_exit(sock, msg);

  return 0;
}

int finish_exit(int sock, struct message * msg) {
      
  int exit_status = msg->_u.exit_msg.status;
  int pid = msg->pid & 0xffff;
  int ppid;

  emscripten_log(EM_LOG_CONSOLE, "--> finish_exit= pid=%d", pid);

  process_to_zombie(pid, exit_status << 8);

  ppid = process_getppid(pid);

  char buf2[256];
  struct message * msg2 = &buf2[0];

  //TOFIX: bash does not display prompt after child exit

  if (ppid > 1) {
    
    if (process_kill(ppid, SIGCHLD, &msg2->_u.kill_msg.act, sock) == 2) {

      emscripten_log(EM_LOG_CONSOLE, "finish_exit: SIGCHLD custom handler");
      
      return 0;
    }
  }

  int ret = process_exit(pid, sock);
  
  emscripten_log(EM_LOG_CONSOLE, "finish_exit: <-- process_exit %d", ret);

  return 0;
}

void process_to_kill(int sock, struct itimer * itimers) {

  while (process_index < nb_processes_to_kill) {

    struct message msg;

    msg._u.kill_msg.pid = processes_to_kill[process_index];
    msg.pid = msg._u.kill_msg.pid;
    msg._u.kill_msg.sig = process_sig;
    
    int action = process_kill(msg._u.kill_msg.pid, msg._u.kill_msg.sig, &msg._u.kill_msg.act, sock);

    if (action == 1) { // Default action

      do_exit(sock, itimers, &msg, 256, NULL);
      return;
    }

    ++process_index;
  }

  nb_processes_to_kill = 0;
  process_index = 0;
}
