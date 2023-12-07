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
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "msg.h"

#ifndef DEBUG
#define DEBUG 0
#endif

#include <emscripten.h>

#if DEBUG
#else
#define emscripten_log(...)
#endif

#define AV_VERSION "[av v0.1.0]"

#define AV_PATH "/var/av.peer"
#define RESMGR_PATH "/var/resmgr.peer"

#define AUDIO_INPUT  1
#define VIDEO_INPUT  2
#define AUDIO_OUTPUT 4

static int major = 0;
static int minor = 0;

EM_JS(int, probe_media_devices, (), {

    return Asyncify.handleSleep(function (wakeUp) {

      if (navigator && navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {

	console.log("probe_media_devices");
	
	// List cameras and microphones.
	navigator.mediaDevices
	  .enumerateDevices()
	  .then((devices) => {

	      let media_devices = 0;

	      devices.forEach((device) => {
		  console.log(device.kind + ": "+device.label+" id = "+device.deviceId);
		  
		  if (device.kind == "audioinput")
		    media_devices = media_devices | 1;
		  else if (device.kind == "videoinput")
		    media_devices = media_devices | 2;
		  else if (device.kind == "audiooutput")
		    media_devices = media_devices | 4;
		});

	      wakeUp(media_devices);
	    })
	  .catch((err) => {
	      console.error(err.name+": "+err.message);

	      wakeUp(0);
	    });
      }
      else {

	wakeUp(0);
      }
      
    });
  });

int main() {

  int sock;
  struct sockaddr_un local_addr, resmgr_addr, remote_addr, ioctl_addr;
  int bytes_rec;
  socklen_t len;
  char buf[1500];
  int video_input_opened = 0;
  
  emscripten_log(EM_LOG_CONSOLE, "Starting " AV_VERSION "...");
  
  /* Create the server local socket */
  sock = socket (AF_UNIX, SOCK_DGRAM, 0);
  if (sock < 0) {
    return -1;
  }
  
  /* Bind server socket to AV_PATH */
  memset(&local_addr, 0, sizeof(local_addr));
  local_addr.sun_family = AF_UNIX;
  strcpy(local_addr.sun_path, AV_PATH);
  
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
  
  strcpy((char *)&msg->_u.dev_msg.dev_name[0], "av");
  
  sendto(sock, buf, 256, 0, (struct sockaddr *) &resmgr_addr, sizeof(resmgr_addr));

  while (1) {
    
    bytes_rec = recvfrom(sock, buf, 1500, 0, (struct sockaddr *) &remote_addr, &len);

    if (bytes_rec <= 0) {

      continue;
    }
    
    emscripten_log(EM_LOG_CONSOLE, "av: recvfrom %d bytes (%d)", bytes_rec, buf[0]);

    if (msg->msg_id == (REGISTER_DRIVER|0x80)) {

      if (msg->_errno)
	continue;
      
      major = msg->_u.dev_msg.major;

      emscripten_log(EM_LOG_CONSOLE, "REGISTER_DRIVER successful: major=%d", major);

      int media_devices = probe_media_devices();

      emscripten_log(EM_LOG_CONSOLE, "av: media_devices = %x", media_devices);

      if (media_devices & VIDEO_INPUT) {

	msg->msg_id = REGISTER_DEVICE;

	msg->_u.dev_msg.dev_type = CHR_DEV;
	msg->_u.dev_msg.major = major;
	msg->_u.dev_msg.minor = VIDEO_INPUT;

	memset(msg->_u.dev_msg.dev_name, 0, sizeof(msg->_u.dev_msg.dev_name));
	sprintf((char *)&msg->_u.dev_msg.dev_name[0], "video0");
  
	sendto(sock, buf, 256, 0, (struct sockaddr *) &resmgr_addr, sizeof(resmgr_addr));
      }
      
    }
    else if (msg->msg_id == (REGISTER_DEVICE|0x80)) {

      if (msg->_errno)
	continue;

      emscripten_log(EM_LOG_CONSOLE, "REGISTER_DEVICE successful: %d,%d,%d", msg->_u.dev_msg.dev_type, msg->_u.dev_msg.major, msg->_u.dev_msg.minor);
      
    }
    else if (msg->msg_id == OPEN) {

      emscripten_log(EM_LOG_CONSOLE, "av: OPEN from %d (%d), %d", msg->pid, msg->_u.open_msg.sid, msg->_u.open_msg.minor);

      if (msg->_u.open_msg.minor == VIDEO_INPUT) {
	
	if (video_input_opened) {
	  msg->_errno = 1;
	}
	else {
	  msg->_errno = 0;
	  video_input_opened = 1;
	  msg->_u.open_msg.remote_fd = VIDEO_INPUT;
	}

	msg->msg_id |= 0x80;
	sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      }
      
    }
    else if (msg->msg_id == CLOSE) {

      //emscripten_log(EM_LOG_CONSOLE, "tty: CLOSE from %d, %d", msg->pid, msg->_u.close_msg.fd);

      if (msg->pid, msg->_u.close_msg.fd == VIDEO_INPUT) {

	if (video_input_opened) {

	  video_input_opened = 0;
	  msg->_errno = 0;
	}
	else {

	  msg->_errno = 1;
	}

	msg->msg_id |= 0x80;
	sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      }
      
    }
    
    
  }
  
  return 0;
}
