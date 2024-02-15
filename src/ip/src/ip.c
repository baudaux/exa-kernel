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
#include <sys/ioctl.h>
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

#define NB_QUEUES_MAX 64

struct packet {

  int addr_len;
  char addr[40];
  int len;
  char * buf;
  int offset;
  struct packet * next;
};

struct queue {

  int fd;
  int flags;
  int pending_read_select; // 0: none, 1: recv, 2: select, 3: read
  int pending_process_fd;
  int pending_pid;
  int pending_len;
  struct packet * first_packet;
  struct packet * last_packet;
};

static int major = 0;
static int minor = 0;

static struct queue queues[NB_QUEUES_MAX];

static void init_queues() {

  for (int i = 0; i < NB_QUEUES_MAX; ++i) {

    queues[i].fd = -1;
  }
}

static int queue_alloc(int fd, int flags) {

  for (int i = 0; i < NB_QUEUES_MAX; ++i) {

    if (queues[i].fd < 0) {

      queues[i].fd = fd;
      queues[i].flags = flags;
      queues[i].pending_read_select = 0;
      queues[i].pending_pid = -1;
      queues[i].pending_process_fd = -1;
      queues[i].first_packet = NULL;
      queues[i].last_packet = NULL;
      
      return i;
    }
  }

  return -1;
}

static int queue_add_packet(struct readsocket_message * msg) {

  for (int i = 0; i < NB_QUEUES_MAX; ++i) {

    if (queues[i].fd == msg->fd) {

      if (msg->len > 0) {

	struct packet * packet = malloc(sizeof(struct packet));

	packet->addr_len = msg->addr_len;

	if (msg->addr_len > 0)
	  memmove(packet->addr, msg->addr, msg->addr_len);
      
	packet->len = msg->len;

	packet->buf = malloc(msg->len);
	
	memmove(packet->buf, msg->buf, msg->len);

	packet->offset = 0;
	packet->next = NULL;
      
	if (queues[i].last_packet)
	  queues[i].last_packet->next = packet;

	queues[i].last_packet = packet;

	if (!queues[i].first_packet)
	  queues[i].first_packet = packet;
      }

      return i;
    }
  }

  return -1;
}

static int queue_not_empty(int fd) {

  for (int i = 0; i < NB_QUEUES_MAX; ++i) {

    if (queues[i].fd == fd) {

      return (queues[i].first_packet != NULL);
    }
  }

  return 0;
}

static int queue_is_nonblock(int fd) {

  for (int i = 0; i < NB_QUEUES_MAX; ++i) {

    if (queues[i].fd == fd) {

      return (queues[i].flags & O_NONBLOCK);
    }
  }

  return 0;
}

static int queue_set_nonblock(int fd, int onoff) {

  for (int i = 0; i < NB_QUEUES_MAX; ++i) {

    if (queues[i].fd == fd) {

      if (onoff)
	queues[i].flags |= O_NONBLOCK; // on = non blocking
      else
	queues[i].flags &= ~O_NONBLOCK; //off = blocking
      
      break;
    }
  }

  return 0;
}

static int queue_set_pending(int fd, int read_select, int pid, int arg) {

  for (int i = 0; i < NB_QUEUES_MAX; ++i) {

    if (queues[i].fd == fd) {
      
      queues[i].pending_read_select = read_select;
      queues[i].pending_pid = pid;

      if ( (read_select == 1) || (read_select == 3) ){ // recv/read

	queues[i].pending_len = arg;
      }
      else { // select
	
	queues[i].pending_process_fd = arg;
      }
	
      return i;
    }
  }

  return -1;
}

static int queue_pending(int fd, int * pid, int * arg) {

  for (int i = 0; i < NB_QUEUES_MAX; ++i) {

    if (queues[i].fd == fd) {
      
      if (queues[i].pending_read_select) {

	*pid = queues[i].pending_pid;

	if ( (queues[i].pending_read_select == 1) || (queues[i].pending_read_select == 3) )
	  *arg = queues[i].pending_len;
	else
	  *arg = queues[i].pending_process_fd;
	
	return queues[i].pending_read_select;
      }
      else {

	return 0;
      }
	
      return i;
    }
  }

  return 0;
}

int queue_read(int fd, char * addr, int * addr_len, char * buf, int len) {

  for (int i = 0; i < NB_QUEUES_MAX; ++i) {

    if (queues[i].fd == fd) {

      if (addr && (queues[i].first_packet->addr_len > 0))
	memmove(addr, queues[i].first_packet->addr, queues[i].first_packet->addr_len);
      if (addr_len)
	*addr_len = queues[i].first_packet->addr_len;

      int read_len = ((queues[i].first_packet->len-queues[i].first_packet->offset)<=len)?queues[i].first_packet->len-queues[i].first_packet->offset:len;
      
      if (buf && (read_len > 0))
	memmove(buf, queues[i].first_packet->buf+queues[i].first_packet->offset, read_len);

      if (read_len < (queues[i].first_packet->len-queues[i].first_packet->offset)) {
	queues[i].first_packet->offset += read_len;
      }
      else {

	if (queues[i].first_packet->buf)
	  free(queues[i].first_packet->buf);
	
	struct packet * p = queues[i].first_packet;

	queues[i].first_packet = p->next;
	
	free(p);

	if (queues[i].last_packet == p)
	  queues[i].last_packet = NULL;
      }

      return read_len;
    }
  }

  return -1;
}

EM_JS(int, do_connect_websocket, (const char * host), {

    let url;

    console.log(window.location.protocol);

    if (window.location.protocol == "https:")
      url = "wss://";
    else
      url = "ws://";

    let h = "";

    if (host)
      h = UTF8ToString(host);

    if (h == "")
      url += window.location.host;
    else
      url += h;

    console.log("Connecting to " + url);

    Module.websocket = new WebSocket(url);

    Module.websocket.binaryType = "arraybuffer";

    Module.websocket.onopen = function(e) {
      
      console.log("[open] Connection established");
      
      Module.websocket.send("Hello, exaequos !");
    };

    Module.websocket.onerror = function(e) {

      console.log(e);
    };

    Module.websocket.onmessage = function(event) {

      let buf = new Uint8Array(event.data);

      //console.log("[message] Data received from server: "+buf.length+" bytes");

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

int main(int argc, char * argv[]) {
  
  int sock;
  struct sockaddr_un local_addr, resmgr_addr, remote_addr, ioctl_addr;
  int bytes_rec;
  socklen_t len;
  char buf[1500];
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

  init_queues();

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
    
    bytes_rec = recvfrom(sock, buf, 1500, 0, (struct sockaddr *) &remote_addr, &len);

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

      if (argc > 1) {
	
	do_connect_websocket(argv[1]);
      }
      else {
	do_connect_websocket("vps-04ec407a.vps.ovh.net:443");
      }
    }
    else if (msg->msg_id == SOCKET) {
      
      emscripten_log(EM_LOG_CONSOLE, "ip: SOCKET %d %d %d %d", msg->pid, msg->_u.socket_msg.domain, msg->_u.socket_msg.type, msg->_u.socket_msg.protocol);

      do_send_websocket(msg, 12+16); //header + first part of seocket message
    }
    else if (msg->msg_id == (SOCKET|0x80)) {
      
      emscripten_log(EM_LOG_CONSOLE, "ip: Return of SOCKET -> fd=%d type=%x", msg->_u.socket_msg.fd, msg->_u.socket_msg.type);

      if (msg->_errno == 0) {

	if (queue_alloc(msg->_u.socket_msg.fd, msg->_u.socket_msg.type) < 0) {

	  emscripten_log(EM_LOG_CONSOLE, "ip: Cannot allocate queue for %d", msg->_u.socket_msg.fd);
	  
	  msg->_errno = ENOMEM;
	}
      }
      
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

      /*for (int i=0; i < msg->_u.sendto_msg.addr_len; ++i) {

	emscripten_log(EM_LOG_CONSOLE, "ip: addr %d -> %d", i, msg->_u.sendto_msg.addr[i]);
	}*/
      
      struct message * msg2 = msg;

      if (msg->_u.sendto_msg.len > (bytes_rec - 68)) {

	msg2 = (struct message *)malloc(68+msg->_u.sendto_msg.len);

	memmove(msg2, msg, bytes_rec);

	int bytes_rec2 = recvfrom(sock, msg2->_u.sendto_msg.message+bytes_rec, msg->_u.sendto_msg.len - (bytes_rec - 68), 0, (struct sockaddr *) &remote_addr, &len);
      }

      do_send_websocket(msg2, bytes_rec);

      if (msg2 != msg)
	free(msg2);
    }
    else if (msg->msg_id == (SENDTO|0x80)) {

      struct sockaddr_un s_addr;
	
      memset(&s_addr, 0, sizeof(s_addr));
      s_addr.sun_family = AF_UNIX;
      sprintf(s_addr.sun_path, "channel.process.%d", msg->pid);

      sendto(sock, buf, 256, 0, (struct sockaddr *) &s_addr, sizeof(s_addr));
    }
    else if (msg->msg_id == READ_SOCKET) {
      
      emscripten_log(EM_LOG_CONSOLE, "ip: READ_SOCKET fd=%d (%d bytes)", msg->_u.readsocket_msg.fd, msg->_u.readsocket_msg.len);

      struct readsocket_message * msg2 = &msg->_u.readsocket_msg;

      if (msg->_u.readsocket_msg.len > (bytes_rec - 64)) {

	msg2 = (struct readsocket_message *)malloc(52+msg->_u.readsocket_msg.len);

	memmove(msg2, &msg->_u.readsocket_msg, bytes_rec - 12);

	int bytes_rec2 = recvfrom(sock, ((char *)msg2)+bytes_rec - 12, msg->_u.readsocket_msg.len - (bytes_rec - 64), 0, (struct sockaddr *) &remote_addr, &len);

	emscripten_log(EM_LOG_CONSOLE, "and additional %d bytes", bytes_rec2);
      }

      emscripten_log(EM_LOG_CONSOLE, "%.*s", msg2->len, msg2->buf);

      queue_add_packet(msg2);

      if (msg2 != &msg->_u.readsocket_msg) {

	free(msg2);
      }

      int pid, arg;
      
      int read_select = queue_pending(msg->_u.readsocket_msg.fd, &pid, &arg);
      
      queue_set_pending(msg->_u.readsocket_msg.fd, 0, 0, 0);
      
      if (read_select == 1) { // recv pending
	
	int len = arg; // len bytes to read

	emscripten_log(EM_LOG_CONSOLE, "ip: READ_SOCKET --> recv pending !!!!! %d bytes", len);

	int buf2_size = 12+sizeof(struct recvfrom_message)+len;
	
	char * buf2 = malloc(buf2_size);
	struct message * msg2 = (struct message *)&buf2[0];

	msg2->_u.recvfrom_msg.len = queue_read(msg->_u.readsocket_msg.fd, msg2->_u.recvfrom_msg.addr, &msg2->_u.recvfrom_msg.addr_len, msg2->_u.recvfrom_msg.buf, len);

	emscripten_log(EM_LOG_CONSOLE, "ip: RECVFROM from %d --> %d bytes read", pid, msg2->_u.recvfrom_msg.len);

	msg2->msg_id = RECVFROM|0x80;
	msg2->pid = pid;
	msg2->_errno = 0;
	
	msg2->_u.recvfrom_msg.fd = msg->_u.readsocket_msg.fd;

	struct sockaddr_un s_addr;
	
	memset(&s_addr, 0, sizeof(s_addr));
	s_addr.sun_family = AF_UNIX;
	sprintf(s_addr.sun_path, "channel.process.%d", pid);

	sendto(sock, buf2, buf2_size, 0, (struct sockaddr *) &s_addr, sizeof(s_addr));

	free(buf2);
      }
      else if (read_select == 3) { // read pending
	
	int len = arg; // len bytes to read

	emscripten_log(EM_LOG_CONSOLE, "ip: READ_SOCKET --> read pending !!!!! %d bytes", len);

	int buf2_size = 12+sizeof(struct io_message)+len;
	
	char * buf2 = malloc(buf2_size);
	struct message * msg2 = (struct message *)&buf2[0];

	msg2->_u.io_msg.len = queue_read(msg->_u.readsocket_msg.fd, NULL, NULL, msg2->_u.io_msg.buf, len);

	emscripten_log(EM_LOG_CONSOLE, "ip: READ from %d --> %d bytes read", pid, msg2->_u.io_msg.len);

	msg2->msg_id = READ|0x80;
	msg2->pid = pid;
	msg2->_errno = 0;
	
	msg2->_u.io_msg.fd = msg->_u.readsocket_msg.fd;

	struct sockaddr_un s_addr;
	
	memset(&s_addr, 0, sizeof(s_addr));
	s_addr.sun_family = AF_UNIX;
	sprintf(s_addr.sun_path, "channel.process.%d", pid);

	sendto(sock, buf2, buf2_size, 0, (struct sockaddr *) &s_addr, sizeof(s_addr));

	free(buf2);
      }
      else if (read_select == 2) { // select pending

	int process_fd = arg;
	
	emscripten_log(EM_LOG_CONSOLE, "ip: READ_SOCKET --> select pending !!!!! %d fd=%d remote_fd=%d", pid, process_fd, msg->_u.readsocket_msg.fd);

	msg->msg_id = SELECT|0x80;
	msg->pid = pid;
	msg->_errno = 0;

	msg->_u.select_msg.fd = process_fd;
	msg->_u.select_msg.remote_fd = msg->_u.readsocket_msg.fd;
	msg->_u.select_msg.read_write = 0;
	msg->_u.select_msg.start_stop = 1;

	struct sockaddr_un s_addr;
	
	memset(&s_addr, 0, sizeof(s_addr));
	s_addr.sun_family = AF_UNIX;
	sprintf(s_addr.sun_path, "channel.process.%d", pid);

	sendto(sock, buf, 256, 0, (struct sockaddr *) &s_addr, sizeof(s_addr));
      }
    }
    else if (msg->msg_id == SELECT) {
      
      emscripten_log(EM_LOG_CONSOLE, "ip: SELECT from %d: %d %d %d", msg->pid, msg->_u.select_msg.remote_fd, msg->_u.select_msg.read_write, msg->_u.select_msg.start_stop);

      if (msg->_u.select_msg.read_write == 0) { // read

	if (msg->_u.select_msg.start_stop) { //start

	  if (queue_not_empty(msg->_u.select_msg.remote_fd)) {

	    emscripten_log(EM_LOG_CONSOLE, "ip: SELECT --> queue not empty !!!!!");
	    
	    queue_set_pending(msg->_u.select_msg.remote_fd, 0, 0, 0);

	    msg->msg_id |= 0x80;

	    msg->_errno = 0;
	    sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
	  }
	  else { // set select pending

	    queue_set_pending(msg->_u.select_msg.remote_fd, 2, msg->pid, msg->_u.select_msg.fd);
	  }
	}
	else { // stop

	  queue_set_pending(msg->_u.select_msg.remote_fd, 0, 0, 0);
	}
      }
      else { // write

	if (msg->_u.select_msg.start_stop) { // start

	  msg->msg_id |= 0x80;

	  msg->_errno = 0;
	  sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
	}
      }
    }
    else if (msg->msg_id == RECVFROM) {
      
      emscripten_log(EM_LOG_CONSOLE, "ip: RECVFROM from %d: %d %d", msg->pid, msg->_u.recvfrom_msg.fd, msg->_u.recvfrom_msg.len);

      if (queue_not_empty(msg->_u.recvfrom_msg.fd)) {

	int buf2_size = 12+sizeof(struct recvfrom_message)+msg->_u.recvfrom_msg.len;
	char * buf2 = malloc(buf2_size);
	struct message * msg2 = (struct message *)&buf2[0];

	msg2->_u.recvfrom_msg.len = queue_read(msg->_u.recvfrom_msg.fd, msg2->_u.recvfrom_msg.addr, &msg2->_u.recvfrom_msg.addr_len, msg2->_u.recvfrom_msg.buf, msg->_u.recvfrom_msg.len);

	emscripten_log(EM_LOG_CONSOLE, "ip: RECVFROM from %d --> %d bytes read", msg->pid, msg2->_u.recvfrom_msg.len);

	msg2->msg_id = RECVFROM|0x80;
	msg2->pid = msg->pid;
	msg2->_errno = 0;
	
	msg2->_u.recvfrom_msg.fd = msg->_u.recvfrom_msg.fd;

	sendto(sock, buf2, buf2_size, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

	free(buf2);
      }
      else if (queue_is_nonblock(msg->_u.recvfrom_msg.fd)) {

	msg->msg_id |= 0x80;

	msg->_errno = EAGAIN;

	msg->_u.recvfrom_msg.len = 0; // no data in queue
	
	sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      }
      else { // set read pending

	queue_set_pending(msg->_u.recvfrom_msg.fd, 1, msg->pid, msg->_u.recvfrom_msg.len);
      }
    }
    else if (msg->msg_id == CONNECT) {
      
      emscripten_log(EM_LOG_CONSOLE, "ip: CONNECT %d %d", msg->pid, msg->_u.sendto_msg.fd);

      do_send_websocket(msg, bytes_rec);
    }
    else if (msg->msg_id == (CONNECT|0x80)) {

      struct sockaddr_un s_addr;
	
      memset(&s_addr, 0, sizeof(s_addr));
      s_addr.sun_family = AF_UNIX;
      sprintf(s_addr.sun_path, "channel.process.%d", msg->pid);

      sendto(sock, buf, 256, 0, (struct sockaddr *) &s_addr, sizeof(s_addr));
    }
    else if (msg->msg_id == WRITE) {

      emscripten_log(EM_LOG_CONSOLE, "ip: WRITE from %d: %d bytes", msg->pid, msg->_u.io_msg.len);

      struct message * msg2 = msg;

      if (msg->_u.io_msg.len > (bytes_rec - 20)) {

	msg2 = (struct message *)malloc(20+msg->_u.io_msg.len);

	memmove(msg2, msg, bytes_rec);

	int bytes_rec2 = recvfrom(sock, msg2->_u.io_msg.buf+bytes_rec, msg->_u.io_msg.len - (bytes_rec - 20), 0, (struct sockaddr *) &remote_addr, &len);
      }
      
      do_send_websocket(msg, bytes_rec);

      if (msg2 != msg)
	free(msg2);
    }
    else if (msg->msg_id == (WRITE|0x80)) {

      struct sockaddr_un s_addr;
	
      memset(&s_addr, 0, sizeof(s_addr));
      s_addr.sun_family = AF_UNIX;
      sprintf(s_addr.sun_path, "channel.process.%d", msg->pid);

      sendto(sock, buf, 256, 0, (struct sockaddr *) &s_addr, sizeof(s_addr));
    }
    else if (msg->msg_id == READ) {
      
      emscripten_log(EM_LOG_CONSOLE, "ip: READ from %d: fd=%d %d bytes", msg->pid, msg->_u.io_msg.fd, msg->_u.io_msg.len);

      if (queue_not_empty(msg->_u.io_msg.fd)) {

	int buf2_size = 12+sizeof(struct io_message)+msg->_u.io_msg.len;
	char * buf2 = malloc(buf2_size);
	struct message * msg2 = (struct message *)&buf2[0];

	msg2->_u.io_msg.len = queue_read(msg->_u.io_msg.fd, NULL, NULL, msg2->_u.io_msg.buf, msg->_u.io_msg.len);

	emscripten_log(EM_LOG_CONSOLE, "ip: READ from %d --> %d bytes read", msg->pid, msg2->_u.io_msg.len);

	msg2->msg_id = READ|0x80;
	msg2->pid = msg->pid;
	msg2->_errno = 0;
	
	msg2->_u.io_msg.fd = msg->_u.io_msg.fd;
	
	sendto(sock, buf2, buf2_size, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

	free(buf2);
      }
      else if (queue_is_nonblock(msg->_u.io_msg.fd)) {

	msg->msg_id |= 0x80;

	msg->_errno = 0;
	
	msg->_u.io_msg.len = 0; // no data in queue
	
	sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      }
      else { // set read pending

	queue_set_pending(msg->_u.io_msg.fd, 3, msg->pid, msg->_u.io_msg.len);
      }
    }
    else if (msg->msg_id == CLOSE) {

      emscripten_log(EM_LOG_CONSOLE, "ip: CLOSE from %d: %d", msg->pid, msg->_u.close_msg.fd);

      do_send_websocket(msg, bytes_rec);
    }
    else if (msg->msg_id == (CLOSE|0x80)) {

      emscripten_log(EM_LOG_CONSOLE, "ip: Return of CLOSE from %d: %d", msg->pid, msg->_u.close_msg.fd);

      sendto(sock, buf, 256, 0, (struct sockaddr *) &resmgr_addr, sizeof(resmgr_addr));
    }
    else if (msg->msg_id == FCNTL) {
      
      emscripten_log(EM_LOG_CONSOLE, "ip: FCNTL from %d: %d %d", msg->pid, msg->_u.fcntl_msg.fd, msg->_u.fcntl_msg.cmd);

      msg->_u.fcntl_msg.ret = 0;
      msg->_errno = 0;

      if (msg->_u.fcntl_msg.cmd == F_SETFL) {
	
	int flags;

	memcpy(&flags, msg->_u.fcntl_msg.buf, sizeof(int));

	for (int i = 0; i < NB_QUEUES_MAX; ++i) {

	  if (queues[i].fd == msg->_u.fcntl_msg.fd) {

	    queues[i].flags = flags;
	    break;
	  }
	}
      }

      msg->msg_id |= 0x80;
      
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == GETSOCKNAME) {

      do_send_websocket(msg, bytes_rec);
    }
    else if (msg->msg_id == (GETSOCKNAME|0x80)) {

      struct sockaddr_un s_addr;
	
      memset(&s_addr, 0, sizeof(s_addr));
      s_addr.sun_family = AF_UNIX;
      sprintf(s_addr.sun_path, "channel.process.%d", msg->pid);

      sendto(sock, buf, 256, 0, (struct sockaddr *) &s_addr, sizeof(s_addr));
    }
    else if (msg->msg_id == GETPEERNAME) {

      do_send_websocket(msg, bytes_rec);
    }
    else if (msg->msg_id == (GETPEERNAME|0x80)) {

      struct sockaddr_un s_addr;
	
      memset(&s_addr, 0, sizeof(s_addr));
      s_addr.sun_family = AF_UNIX;
      sprintf(s_addr.sun_path, "channel.process.%d", msg->pid);

      sendto(sock, buf, 256, 0, (struct sockaddr *) &s_addr, sizeof(s_addr));
    }
    else if (msg->msg_id == IOCTL) {

      emscripten_log(EM_LOG_CONSOLE, "ip: IOCTL from %d: %d", msg->pid, msg->_u.ioctl_msg.op);
      
      if (msg->_u.ioctl_msg.op == FIONBIO) {

	int onoff = 0;
	
	memcpy(&onoff, msg->_u.ioctl_msg.buf, sizeof(int));

	emscripten_log(EM_LOG_CONSOLE, "ip: IOCTL FIONBIO onoff=%d", onoff);

	queue_set_nonblock(msg->_u.ioctl_msg.fd, onoff);
	
	msg->msg_id |= 0x80;
	msg->_errno = 0;
      
	sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      }
    }
    else if (msg->msg_id == SETSOCKOPT) {
      
      emscripten_log(EM_LOG_CONSOLE, "ip: SETSOCKOPT from %d: fd=%d", msg->pid, msg->_u.setsockopt_msg.fd);
      
      do_send_websocket(msg, bytes_rec);
    }
    else if (msg->msg_id == (SETSOCKOPT|0x80)) {
      
      emscripten_log(EM_LOG_CONSOLE, "ip: Return from SETSOCKOPT from %d: fd=%d", msg->pid, msg->_u.setsockopt_msg.fd);
      
      struct sockaddr_un s_addr;
	
      memset(&s_addr, 0, sizeof(s_addr));
      s_addr.sun_family = AF_UNIX;
      sprintf(s_addr.sun_path, "channel.process.%d", msg->pid);

      sendto(sock, buf, 256, 0, (struct sockaddr *) &s_addr, sizeof(s_addr));
    }
  }
  
  return 0;
}
