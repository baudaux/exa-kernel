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

#include "msg.h"

#ifndef DEBUG
#define DEBUG 0
#endif

#include <emscripten.h>

#if DEBUG
#else
#define emscripten_log(...)
#endif

#define IP_VERSION "[ip v0.1.0]"

#define IP_PATH "/var/ip.peer"
#define RESMGR_PATH "/var/resmgr.peer"

static int major = 0;
static int minor = 0;

EM_JS(int, do_connect_websocket, (), {

    let url;

    if (window.location.protocol == "https")
      url = "wss://";
    else
      url = "ws://";

    url += window.location.host;

    console.log("Connecting to " + url);

    Module.websocket = new WebSocket(url);

    Module.websocket.binaryType = "arraybuffer";

    Module.websocket.onopen = function(e) {
      
      console.log("[open] Connection established");
      
      Module.websocket.send("Hello, exaequos !");
    };

    Module.websocket.onmessage = function(event) {

      console.log("[message] Data received from server:");

      let buf = new Uint8Array(event.data);

      let msg = {
		    
        from: "websocket",
	buf: buf,
	len: buf.length
      };

      let sock = Module['fd_table'][Module.mySock];

      sock.recv_queue.push(msg);
      
      if (sock.notif_select) {

	sock.notif_select(sock.select_fd, sock.select_rw);
      }
      else if (sock.notif) {
	
	sock.notif();
	}
    };

    Module.websocket.onclose = function(event) {
      
      /*if (event.wasClean) {
	
	console.log("[close] Connection closed cleanly, code="+event.code + " reason="+event.reason);
      } else {
	
	console.log("[close] Connection died");
	}*/
    };
  });

EM_JS(int, do_send_websocket, (char * buf, int len), {

    Module.websocket.send(Module.HEAPU8.slice(buf, buf+len));
  });

int main() {

  int sock;
  struct sockaddr_un local_addr, resmgr_addr, remote_addr, ioctl_addr;
  int bytes_rec;
  socklen_t len;
  char buf[1256];
  int fb_opened = 0;
  
  emscripten_log(EM_LOG_CONSOLE, "Starting " IP_VERSION "...");
  
  /* Create the server local socket */
  sock = socket (AF_UNIX, SOCK_DGRAM, 0);
  if (sock < 0) {
    return -1;
  }

  emscripten_log(EM_LOG_CONSOLE, "Socket: %d", sock);

  EM_ASM({

      Module.mySock = $0;
      
    }, sock);

  /* Bind server socket to TTY_PATH */
  memset(&local_addr, 0, sizeof(local_addr));
  local_addr.sun_family = AF_UNIX;
  strcpy(local_addr.sun_path, IP_PATH);
  
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
  
  strcpy((char *)&msg->_u.dev_msg.dev_name[0], "ip");
  
  sendto(sock, buf, 256, 0, (struct sockaddr *) &resmgr_addr, sizeof(resmgr_addr));

  while (1) {
    
    bytes_rec = recvfrom(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, &len);

    if (bytes_rec <= 0) {

      continue;
    }
    
    emscripten_log(EM_LOG_CONSOLE, "ip: recvfrom %d bytes (%d)", bytes_rec, buf[0]);

    if (msg->msg_id == (REGISTER_DRIVER|0x80)) {

      if (msg->_errno)
	continue;
      
      major = msg->_u.dev_msg.major;

      emscripten_log(EM_LOG_CONSOLE, "REGISTER_DRIVER successful: major=%d", major);

      msg->msg_id = REGISTER_DEVICE;

      msg->_u.dev_msg.dev_type = CHR_DEV;
      msg->_u.dev_msg.major = major;
      msg->_u.dev_msg.minor = minor++;

      memset(msg->_u.dev_msg.dev_name, 0, sizeof(msg->_u.dev_msg.dev_name));
      sprintf((char *)&msg->_u.dev_msg.dev_name[0], "ip%d", msg->_u.dev_msg.minor);
  
      sendto(sock, buf, 256, 0, (struct sockaddr *) &resmgr_addr, sizeof(resmgr_addr));
    }
    else if (msg->msg_id == (REGISTER_DEVICE|0x80)) {

      if (msg->_errno)
	continue;

      emscripten_log(EM_LOG_CONSOLE, "REGISTER_DEVICE successful: %d,%d,%d", msg->_u.dev_msg.dev_type, msg->_u.dev_msg.major, msg->_u.dev_msg.minor);

      do_connect_websocket();
    }
    else if (msg->msg_id == SOCKET) {
      
      emscripten_log(EM_LOG_CONSOLE, "ip: SOCKET %d %d %d %d", msg->pid, msg->_u.socket_msg.domain, msg->_u.socket_msg.type, msg->_u.socket_msg.protocol);

      do_send_websocket(msg, 12+16); //header + first part of seocket message
    }
    else if (msg->msg_id == (SOCKET|0x80)) {
      
      emscripten_log(EM_LOG_CONSOLE, "ip: Return of SOCKET -> fd=%d ", msg->_u.socket_msg.fd);
      
      msg->_u.socket_msg.remote_fd = msg->_u.socket_msg.fd;

      msg->_u.socket_msg.dev_type = CHR_DEV;
      msg->_u.socket_msg.major = major;
      msg->_u.socket_msg.minor = minor;
      strcpy((char *)msg->_u.socket_msg.peer, IP_PATH);

      sendto(sock, buf, 256, 0, (struct sockaddr *) &resmgr_addr, sizeof(resmgr_addr));
    }
    else if (msg->msg_id == BIND) {
      
      emscripten_log(EM_LOG_CONSOLE, "ip: BIND %d %d", msg->pid, msg->_u.bind_msg.fd);

      do_send_websocket(msg, bytes_rec);
    }
    else if (msg->msg_id == (BIND|0x80)) {

      struct sockaddr_un s_addr;
	
      memset(&s_addr, 0, sizeof(s_addr));
      s_addr.sun_family = AF_UNIX;
      sprintf(s_addr.sun_path, "channel.process.%d", msg->pid);

      sendto(sock, buf, 256, 0, (struct sockaddr *) &s_addr, sizeof(s_addr));
    }
    else if (msg->msg_id == SENDTO) {
      
      emscripten_log(EM_LOG_CONSOLE, "ip: SENDTO %d %d (%d bytes)", msg->pid, msg->_u.sendto_msg.fd, msg->_u.sendto_msg.len);

      do_send_websocket(msg, bytes_rec);
    }
    else if (msg->msg_id == (SENDTO|0x80)) {

      struct sockaddr_un s_addr;
	
      memset(&s_addr, 0, sizeof(s_addr));
      s_addr.sun_family = AF_UNIX;
      sprintf(s_addr.sun_path, "channel.process.%d", msg->pid);

      sendto(sock, buf, 256, 0, (struct sockaddr *) &s_addr, sizeof(s_addr));
    }
    else if (msg->msg_id == READ_SOCKET) {
      
      emscripten_log(EM_LOG_CONSOLE, "ip: READ_SOCKET %d %d (%d bytes)", msg->pid, msg->_u.readsocket_msg.fd, msg->_u.readsocket_msg.len);

      
    }
    else if (msg->msg_id == SELECT) {
      
      emscripten_log(EM_LOG_CONSOLE, "ip: SELECT from %d: %d %d %d", msg->pid, msg->_u.select_msg.fd, msg->_u.select_msg.read_write, msg->_u.select_msg.start_stop);

      
  }
  
  return 0;
}
