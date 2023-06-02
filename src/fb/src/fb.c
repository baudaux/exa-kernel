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
#include <fcntl.h>
#include <stropts.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <sys/ioctl.h>

#include <time.h>
#include <sys/timerfd.h>

#include <linux/fb.h>

#include "msg.h"

#include <emscripten.h>

#ifndef DEBUG
#define DEBUG 0
#endif

#define FB_VERSION "[fb v0.1.0]"

#define FB_PATH "/var/fb.peer"
#define RESMGR_PATH "/var/resmgr.peer"

static int major = 0;
static int minor = 0;


int main() {

  int sock;
  struct sockaddr_un local_addr, resmgr_addr, remote_addr, ioctl_addr;
  int bytes_rec;
  socklen_t len;
  char buf[1256];
  int fb_opened = 0;
  
  if (DEBUG)
    emscripten_log(EM_LOG_CONSOLE, "Starting " FB_VERSION "...");
  
  /* Create the server local socket */
  sock = socket (AF_UNIX, SOCK_DGRAM, 0);
  if (sock < 0) {
    return -1;
  }

  /* Bind server socket to TTY_PATH */
  memset(&local_addr, 0, sizeof(local_addr));
  local_addr.sun_family = AF_UNIX;
  strcpy(local_addr.sun_path, FB_PATH);
  
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
  
  strcpy((char *)&msg->_u.dev_msg.dev_name[0], "fb");
  
  sendto(sock, buf, 256, 0, (struct sockaddr *) &resmgr_addr, sizeof(resmgr_addr));

  while (1) {
    
    bytes_rec = recvfrom(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, &len);

    if (bytes_rec <= 0) {

      continue;
    }

    //emscripten_log(EM_LOG_CONSOLE, "tty: recfrom: %d", bytes_rec);

    if (msg->msg_id == (REGISTER_DRIVER|0x80)) {

      if (msg->_errno)
	continue;

      major = msg->_u.dev_msg.major;

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "REGISTER_DRIVER successful: major=%d", major);

      msg->msg_id = REGISTER_DEVICE;

      msg->_u.dev_msg.dev_type = CHR_DEV;
      msg->_u.dev_msg.major = major;
      msg->_u.dev_msg.minor = minor++;

      memset(msg->_u.dev_msg.dev_name, 0, sizeof(msg->_u.dev_msg.dev_name));
      sprintf((char *)&msg->_u.dev_msg.dev_name[0], "fb%d", msg->_u.dev_msg.minor);
  
      sendto(sock, buf, 256, 0, (struct sockaddr *) &resmgr_addr, sizeof(resmgr_addr));
    }
    else if (msg->msg_id == (REGISTER_DEVICE|0x80)) {

      if (msg->_errno)
	continue;

      //emscripten_log(EM_LOG_CONSOLE, "REGISTER_DEVICE successful: %d,%d,%d", msg->_u.dev_msg.dev_type, msg->_u.dev_msg.major, msg->_u.dev_msg.minor);
    }
    else if (msg->msg_id == OPEN) {

      //emscripten_log(EM_LOG_CONSOLE, "tty: OPEN from %d (%d), %d", msg->pid, msg->_u.open_msg.sid, msg->_u.open_msg.minor);

      if (fb_opened) {
	msg->_errno = 1;
      }
      else {
	msg->_errno = 0;
	fb_opened = 1;
	msg->_u.open_msg.remote_fd = 1;
      }

      msg->msg_id |= 0x80;
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));     
      
    }
    else if (msg->msg_id == READ) {

      

	msg->msg_id |= 0x80;
	sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      
    }
    else if (msg->msg_id == WRITE) {
      
      

      msg->msg_id |= 0x80;
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == SEEK) {

      //emscripten_log(EM_LOG_CONSOLE, "fb: SEEK from %d", msg->pid);

      msg->msg_id |= 0x80;
      msg->_errno = ESPIPE;
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == IOCTL) {

      //emscripten_log(EM_LOG_CONSOLE, "fb: IOCTL from %d: %d", msg->pid, msg->_u.ioctl_msg.op);

      if (msg->_u.ioctl_msg.op == FBIOGET_VSCREENINFO) {

	struct fb_var_screeninfo * vinfo = (struct fb_var_screeninfo *)msg->_u.ioctl_msg.buf;

	double scale = EM_ASM_DOUBLE({

	    return window.devicePixelRatio;
	  });

	vinfo->xres = (uint32_t) scale*800;
	vinfo->yres = (uint32_t) scale*600;
	vinfo->bits_per_pixel = 32;
	

	msg->_errno = 0;
      }
      else if (msg->_u.ioctl_msg.op == FBIOGET_FSCREENINFO) {

	struct fb_fix_screeninfo * finfo = (struct fb_fix_screeninfo *)msg->_u.ioctl_msg.buf;

	double scale = EM_ASM_DOUBLE({

	    return window.devicePixelRatio;
	  });

	finfo->line_length = (uint32_t) scale*800*4;

	msg->_errno = 0;
	
      }
      else {

	msg->_errno = 1;
      }
      
      msg->msg_id |= 0x80;
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == CLOSE) {

      //emscripten_log(EM_LOG_CONSOLE, "tty: CLOSE from %d, %d", msg->pid, msg->_u.close_msg.fd);

      if (fb_opened) {

	fb_opened = 0;
	msg->_errno = 0;
      }
      else {

	msg->_errno = 1;
      }

      msg->msg_id |= 0x80;
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));     
      
    }
    
  }
  
  return 0;
}
