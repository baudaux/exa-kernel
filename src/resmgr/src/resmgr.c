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

#include "vfs.h"
#include "process.h"
#include "device.h"
#include "unordered_map.h"

#include "msg.h"

#include <emscripten.h>

/* Be careful when changing this path as it may be also used in javascript */

#define RESMGR_ROOT "/var"
#define RESMGR_FILE "resmgr.peer"
#define RESMGR_PATH RESMGR_ROOT "/" RESMGR_FILE

int main() {

  int sock;
  struct sockaddr_un local_addr, remote_addr, tty_addr;
  int bytes_rec;
  socklen_t len;
  char buf[1256];

  int execve_size;
  int execve_pid;
  char execve_msg[1256];

  // Use console.log as tty is not yet started
  emscripten_log(EM_LOG_CONSOLE, "Starting resmgr v0.1.0 ...");

  vfs_init();
  process_init();
  device_init();

  /* Create the server local socket */
  sock = socket(AF_UNIX, SOCK_DGRAM, 0);

  // TODO: Add close on exec
  
  memset(&local_addr, 0, sizeof(local_addr));
  local_addr.sun_family = AF_UNIX;
  strcpy(local_addr.sun_path, RESMGR_PATH);

  /* Bind socket to RESMGR_PATH : path is not created as we are in resmgr ... */
  bind(sock, (struct sockaddr *) &local_addr, sizeof(local_addr));

  /* ... so we need to add it in vfs */
  struct vnode * vnode = vfs_find_node(RESMGR_ROOT, NULL);
  vfs_add_file(vnode, RESMGR_FILE);

  /* Register vfs driver */
  unsigned short vfs_major = device_register_driver(FS_DEV, "vfs", RESMGR_PATH);
  unsigned short vfs_minor = 1;

  device_register_device(FS_DEV, vfs_major, vfs_minor, "vfs1");

  // First, we create tty process
  
  create_tty_process();
  
  while (1) {
    
    bytes_rec = recvfrom(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, &len);

    struct message * msg = (struct message *)&buf[0];

    //emscripten_log(EM_LOG_CONSOLE, "resmgr: msg %d received from %s (%d)", msg->msg_id, remote_addr.sun_path,bytes_rec);

    if (msg->msg_id == REGISTER_DRIVER) {
      
      emscripten_log(EM_LOG_CONSOLE, "REGISTER_DRIVER %s (%d)", msg->_u.dev_msg.dev_name, msg->_u.dev_msg.dev_type);

      // Add driver
      msg->_u.dev_msg.major = device_register_driver(msg->_u.dev_msg.dev_type, (const char *)msg->_u.dev_msg.dev_name, (const char *)remote_addr.sun_path);

      if (msg->_u.dev_msg.major == 1) {

	// TTY driver: add /dev/tty with minor 0
	
	struct vnode * vnode = vfs_find_node("/dev", NULL);
	
	vfs_add_dev(vnode, "tty", CHR_DEV, 1, 0);
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

	if (strcmp((const char *)&(pathname[0]),"/etc") == 0) {

	  memset(buf, 0, 1256);
	  msg->msg_id = WRITE;
	  msg->_u.io_msg.fd = -1; // minor == 1

	  sprintf((char *)msg->_u.io_msg.buf,"\r\nstart sysvinit");

	  msg->_u.io_msg.len = strlen((char *)(msg->_u.io_msg.buf))+1;

	  sendto(sock, buf, 1256, 0, (struct sockaddr *) &tty_addr, sizeof(tty_addr));

	  create_init_process();

	  dump_processes();
	}
      }
    }
    else if (msg->msg_id == SOCKET) {

      msg->msg_id |= 0x80;
      msg->_errno = 0;

      emscripten_log(EM_LOG_CONSOLE, "SOCKET %d %d %d %d", msg->pid, msg->_u.socket_msg.domain, msg->_u.socket_msg.type, msg->_u.socket_msg.protocol);

      msg->_u.socket_msg.fd = process_create_fd(msg->pid, -2, (unsigned char)(msg->_u.socket_msg.type & 0xff), (unsigned short)(msg->_u.socket_msg.domain & 0xffff), (unsigned short)(msg->_u.socket_msg.protocol & 0xffff));

      // Add /proc/<pid>/fd/<fd> entry
      process_add_proc_fd_entry(msg->pid, msg->_u.socket_msg.fd, "socket");

      if (msg->_u.socket_msg.type & SOCK_CLOEXEC) {

	// TODO
      }

      if (msg->_u.socket_msg.type & SOCK_NONBLOCK) {

	// TODO
      }

      emscripten_log(EM_LOG_CONSOLE, "SOCKET created %d", msg->_u.socket_msg.fd);

      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
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

	emscripten_log(EM_LOG_CONSOLE, "vfs_get_path: %s", new_path);
	
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
	  
	  msg->_u.open_msg.fd = process_create_fd(msg->pid, msg->_u.open_msg.remote_fd, msg->_u.open_msg.type, msg->_u.open_msg.major, msg->_u.open_msg.minor);

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

      emscripten_log(EM_LOG_CONSOLE, "Response from OPEN from %d: %d %x %x %s %d %d", msg->pid, msg->_errno, msg->_u.open_msg.flags, msg->_u.open_msg.mode, msg->_u.open_msg.pathname,msg->pid, msg->_u.open_msg.remote_fd);

      if (msg->_errno == 0) {

	msg->_u.open_msg.fd = process_create_fd(msg->pid, msg->_u.open_msg.remote_fd, msg->_u.open_msg.type, msg->_u.open_msg.major, msg->_u.open_msg.minor);

	// Add /proc/<pid>/fd/<fd> entry
	process_add_proc_fd_entry(msg->pid, msg->_u.open_msg.fd, (char *)msg->_u.open_msg.pathname);
      }

      // Forward response to process

      sendto(sock, buf, 1256, 0, (struct sockaddr *)process_get_peer_addr(msg->pid), sizeof(struct sockaddr_un));
      
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
	process_del_proc_fd_entry(msg->pid, msg->_u.open_msg.fd);

	// Find fd in other processes
	if (process_find_open_fd(type, major, remote_fd) < 0) {

	  // No more fd, close the fd in the driver

	  // Forward msg to driver

	  msg->_u.close_msg.fd = remote_fd;

	  if (major != vfs_major) {

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

      emscripten_log(EM_LOG_CONSOLE, "Response from CLOSE from %d (%s)", msg->pid, process_get_peer_addr(msg->pid)->sun_path);

      // Forward response to process

      sendto(sock, buf, 256, 0, (struct sockaddr *)process_get_peer_addr(msg->pid), sizeof(struct sockaddr_un));
      
    }
    else if (msg->msg_id == READ) {

      emscripten_log(EM_LOG_CONSOLE, "READ from %d: %d %d", msg->pid, msg->_u.io_msg.fd, msg->_u.io_msg.len);

    }
    else if (msg->msg_id == WRITE) {

      emscripten_log(EM_LOG_CONSOLE, "WRITE from %d: %d %d", msg->pid, msg->_u.io_msg.fd, msg->_u.io_msg.len);

      //TODO : read remaining bytes if needed (beyond 1256)

      msg->msg_id |= 0x80;
      
      if (vfs_write(msg->_u.io_msg.fd, msg->_u.io_msg.buf, msg->_u.io_msg.len) >= 0)  {

	 emscripten_log(EM_LOG_CONSOLE, "WRITE from %d: done");
	      
	msg->_errno = 0;
      }
      else {

	msg->_errno = EBADF;
      }
      
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

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

      emscripten_log(EM_LOG_CONSOLE, "FORK from %d", msg->pid);

      msg->_u.fork_msg.child = process_fork(-1, msg->pid, NULL);
      
      msg->msg_id |= 0x80;
      msg->_errno = 0;

      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      
    }
    else if (msg->msg_id == EXECVE) {

      emscripten_log(EM_LOG_CONSOLE, "EXECVE from %d: %lu", msg->pid, msg->_u.execve_msg.args_size);

      if (msg->_u.execve_msg.args_size == 0xffffffff) {

	if (msg->pid == ((struct message *)execve_msg)->pid) {

	  ((struct message *)execve_msg)->msg_id |= 0x80;

	  sendto(sock, execve_msg, execve_size, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
	}
      }
      else {

	execve_size = bytes_rec;
	memcpy(execve_msg, msg, bytes_rec);
      }
    }
    else if (msg->msg_id == DUP) {

      emscripten_log(EM_LOG_CONSOLE, "DUP from %d", msg->pid);

      msg->_u.dup_msg.new_fd = process_dup(msg->pid, msg->_u.dup_msg.fd, msg->_u.dup_msg.new_fd);
      
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

	sprintf(str, "/proc/%d/%s", msg->pid, msg->_u.readlink_msg.pathname_or_buf+11);

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
      char * trail;

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

	  if (vnode->type == VMOUNT)
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

      emscripten_log(EM_LOG_CONSOLE, "Response from STAT from %d", msg->pid);

      // Forward response to process
      
      sendto(sock, buf, 1256, 0, (struct sockaddr *)process_get_peer_addr(msg->pid), sizeof(struct sockaddr_un));
      
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
      
      sendto(sock, buf, 1256, 0, (struct sockaddr *)process_get_peer_addr(msg->pid), sizeof(struct sockaddr_un));
      
    }
    else if (msg->msg_id == TIMERFD_CREATE) {

      emscripten_log(EM_LOG_CONSOLE, "TIMERFD_CREATE from %d (%d)", msg->pid, msg->_u.timerfd_create_msg.clockid);

      msg->_u.timerfd_create_msg.fd = process_create_fd(msg->pid, -3, 0, 0, msg->_u.timerfd_create_msg.clockid & 0xffff);

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

      char * trail= 0;

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
	  
	  strcpy(msg->_u.cwd_msg.buf, new_dir);

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

      emscripten_log(EM_LOG_CONSOLE, "Return from CHDIR from %d: %s", msg->pid, msg->_u.cwd_msg.buf);

      if (msg->_errno == 0) {

	if (process_chdir(msg->pid, (char *)msg->_u.cwd_msg.buf) < 0)
	    msg->_errno = ENOENT;
      }

      sendto(sock, buf, 1256, 0, (struct sockaddr *)process_get_peer_addr(msg->pid), sizeof(struct sockaddr_un));
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

      emscripten_log(EM_LOG_CONSOLE, "WAIT from %d", msg->pid);

      if (msg->_u.wait_msg.pid=process_wait(msg->pid, msg->_u.wait_msg.pid, msg->_u.wait_msg.options, &msg->_u.wait_msg.status)) {
	
	sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      }
      
    }
    else if (msg->msg_id == EXIT) {

      emscripten_log(EM_LOG_CONSOLE, "EXIT from %d: status=%d", msg->pid, msg->_u.exit_msg.status);

      int pid = msg->pid;
      int ppid;
      
      if (ppid=process_exit(pid, msg->_u.exit_msg.status << 8)) {

	msg->msg_id = WAIT|0x80;
	msg->pid = ppid;
	msg->_errno = 0;

	msg->_u.wait_msg.pid = pid;
	msg->_u.wait_msg.status = msg->_u.exit_msg.status << 8;

	emscripten_log(EM_LOG_CONSOLE, "EXIT: Send wait response to parent %d", msg->pid);
	 // Forward response to process
	
	 sendto(sock, buf, 1256, 0, (struct sockaddr *)process_get_peer_addr(msg->pid), sizeof(struct sockaddr_un));
	}

    }
  }
  
  return 0;
}
