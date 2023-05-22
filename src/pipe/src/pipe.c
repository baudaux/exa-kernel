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
#include "circular_buffer.h"

#include <emscripten.h>

#define DEBUG 0

#define PIPE_VERSION "pipe v0.1.0"

#define PIPE_PATH "/var/pipe.peer"
#define RESMGR_PATH "/var/resmgr.peer"

#define NB_FD_MAX     32
#define PIPE_SIZE     1024

struct pipe {

  int read_fd;
  int write_fd;
  int flags;
  struct circular_buffer buf;
};

struct pipe fds[NB_FD_MAX];

int major;

void init_fds() {

  for (int i=0; i<NB_FD_MAX; ++i) {

    fds[i].read_fd = -1;
    fds[i].write_fd = -1;
  }
}

int find_fd(int fd[2], int flags) {

  for (int i=0; i<NB_FD_MAX; ++i) {

    if ( (fds[i].read_fd < 0) && ((fds[i].write_fd < 0)) ) {

      fds[i].read_fd = fd[0] = 2*i;
      fds[i].write_fd = fd[1] = 2*i+1;
      fds[i].flags = flags;

      init_circular_buffer(&fds[i].buf, PIPE_SIZE);
      
      return i;
    }
  }

  return -1;
}

int main() {

  int sock;
  struct sockaddr_un local_addr, resmgr_addr, remote_addr;
  int bytes_rec;
  socklen_t len;
  char buf[1256];
  
  if (DEBUG)
    emscripten_log(EM_LOG_CONSOLE, "Starting " PIPE_VERSION "...");

  /*int fd = open("/dev/tty1", O_WRONLY | O_NOCTTY);
  
  if (fd >= 0)
    write(fd, "\n\r[" PIPE_VERSION "]", strlen("\n\r[" PIPE_VERSION "]")+1);

    close(fd);*/

  init_fds();
  
  /* Create the server local socket */
  sock = socket (AF_UNIX, SOCK_DGRAM, 0);
  if (sock < 0) {
    return -1;
  }

  /* Bind server socket to NETFS_PATH */
  memset(&local_addr, 0, sizeof(local_addr));
  local_addr.sun_family = AF_UNIX;
  strcpy(local_addr.sun_path, PIPE_PATH);
  
  if (bind(sock, (struct sockaddr *) &local_addr, sizeof(struct sockaddr_un))) {
    
    return -1;
  }

  memset(&resmgr_addr, 0, sizeof(resmgr_addr));
  resmgr_addr.sun_family = AF_UNIX;
  strcpy(resmgr_addr.sun_path, RESMGR_PATH);

  struct message * msg = (struct message *)&buf[0];
  
  msg->msg_id = REGISTER_DRIVER;
  msg->_u.dev_msg.dev_type = CHR_DEV;
  
  memset(msg->_u.dev_msg.dev_name, 0, sizeof(msg->_u.dev_msg.dev_name));
  
  strcpy((char *)&msg->_u.dev_msg.dev_name[0], "pipe");
  
  sendto(sock, buf, 1256, 0, (struct sockaddr *) &resmgr_addr, sizeof(resmgr_addr));

  while (1) {
    
    bytes_rec = recvfrom(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, &len);

    if (DEBUG)
      emscripten_log(EM_LOG_CONSOLE,"*** pipe: %d", msg->msg_id);

    if (msg->msg_id == (REGISTER_DRIVER|0x80)) {

      if (msg->_errno)
	continue;

      major = msg->_u.dev_msg.major;

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE,"REGISTER_DRIVER successful: major=%d", major);
    }
    else if (msg->msg_id == PIPE) {

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE,"pipe: PIPE");

      if (find_fd(msg->_u.pipe_msg.remote_fd, msg->_u.pipe_msg.flags) >= 0) {

	if (DEBUG)
	  emscripten_log(EM_LOG_CONSOLE,"pipe: PIPE %d %d", msg->_u.pipe_msg.remote_fd[0], msg->_u.pipe_msg.remote_fd[1]);

	msg->_errno = 0;
	
      } else {

	msg->_errno = -1;
      }

      msg->_u.pipe_msg.type = CHR_DEV;
      msg->_u.pipe_msg.major = major;
      msg->_u.pipe_msg.minor = 0;
      strcpy(msg->_u.pipe_msg.peer, PIPE_PATH);

      msg->msg_id |= 0x80;
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == CLOSE) {

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE,"pipe: CLOSE %d", msg->_u.close_msg.fd);

      int i = msg->_u.close_msg.fd / 2;

      if ( (i >= 0) && (i < NB_FD_MAX) ) {

	if ((msg->_u.close_msg.fd % 2) == 0) {
	  fds[i].read_fd = -1;

	  if (fds[i].write_fd == -1) {

	    //TODO
	  }
	}
	else {
	  fds[i].write_fd = -1;

	  if (fds[i].read_fd == -1) {

	    //TODO
	  }
	}

	msg->_errno = 0;
      }
      else {

	msg->_errno = -1;
      }

      msg->msg_id |= 0x80;
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == READ) {

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE,"pipe: READ %d", msg->_u.io_msg.fd);

      int i = msg->_u.io_msg.fd / 2;

      if ( (i >= 0) && (i < NB_FD_MAX) ) {
	
	if ((msg->_u.io_msg.fd % 2) == 0) {

	  int len = read_circular_buffer(&fds[i].buf, msg->_u.io_msg.len, msg->_u.io_msg.buf);

	  if (len > 0) {

	    msg->_u.io_msg.len = len;
	    msg->_errno = 0;
	  }
	  else if (fds[i].write_fd == -1) {

	    msg->_u.io_msg.len = 0;
	    msg->_errno = 0;
	  }
	  else {

	    //TODO: add job
	  }
	}
	else {
	  msg->_errno = -1;
	}
      }
      else {

	msg->_errno = -1;
      }

      msg->msg_id |= 0x80;
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      
    }
    else if (msg->msg_id == WRITE) {

      
    }
    
  }
  
  return 0;
}
