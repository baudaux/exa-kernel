/*
 * Copyright (C) 2026 Benoit Baudaux
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

#define LLM_VERSION "[llm v0.1.0]"

#define LLM_PATH "/var/llm.peer"
#define RESMGR_PATH "/var/resmgr.peer"

static int major = 0;
static int minor = 0;

#define LLM_LEN_MAX 65536

static char llm_answer[LLM_LEN_MAX];
static int llm_answer_length = 0;
static int llm_read_offset = 0;
static int llm_answer_finished = 0;

static int llm_read_pending = 0;
static int llm_read_pending_len = 0;
static int llm_read_pending_pid = 0;
static int llm_read_pending_fd = 0;
static struct sockaddr_un llm_read_pending_addr;

int send_reply(int sock) {

  int len = ((llm_answer_length - llm_read_offset) < llm_read_pending_len)?(llm_answer_length-llm_read_offset):llm_read_pending_len;
  
  struct message * reply = (struct message *) malloc(12+sizeof(struct io_message)+len);
  
  reply->msg_id = READ|0x80;
  reply->pid = llm_read_pending_pid;
  reply->_u.io_msg.fd = llm_read_pending_fd;
  
  reply->_u.io_msg.len = len;

  memcpy(reply->_u.io_msg.buf, llm_answer+llm_read_offset, reply->_u.io_msg.len);

  llm_read_offset += reply->_u.io_msg.len;

  if (llm_read_offset >= llm_answer_length) {

    llm_read_offset = 0;
    llm_answer_length = 0;
  }
	
  reply->_errno = 0;
      
  sendto(sock, reply, 12+sizeof(struct io_message)+reply->_u.io_msg.len, 0, (struct sockaddr *) &llm_read_pending_addr, sizeof(llm_read_pending_addr));
  
  free(reply);
}

int main(int argc, char * argv[]) {
  
  int sock;
  struct sockaddr_un local_addr, resmgr_addr, remote_addr, ioctl_addr;
  int bytes_rec;
  socklen_t len;
  char buf[1500];
  int fb_opened = 0;
  
  emscripten_log(EM_LOG_CONSOLE, "Starting " LLM_VERSION "...");
  
  /* Create the server local socket */
  sock = socket (AF_UNIX, SOCK_DGRAM, 0);
  if (sock < 0) {
    return -1;
  }

  /* Bind server socket to LLM_PATH */
  memset(&local_addr, 0, sizeof(local_addr));
  local_addr.sun_family = AF_UNIX;
  strcpy(local_addr.sun_path, LLM_PATH);
  
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
  
  strcpy((char *)&msg->_u.dev_msg.dev_name[0], "llm");
  
  sendto(sock, buf, 256, 0, (struct sockaddr *) &resmgr_addr, sizeof(resmgr_addr));

  while (1) {
    
    bytes_rec = recvfrom(sock, buf, 1500, 0, (struct sockaddr *) &remote_addr, &len);

    if (bytes_rec <= 0) {

      continue;
    }
    
    emscripten_log(EM_LOG_CONSOLE, "llm: recvfrom %d bytes (%d)", bytes_rec, buf[0]);

    if (msg->msg_id == (REGISTER_DRIVER|0x80)) {

      if (msg->_errno)
	continue;
      
      major = msg->_u.dev_msg.major;

      emscripten_log(EM_LOG_CONSOLE, "llm: REGISTER_DRIVER successful: major=%d", major);

    }
    else if (msg->msg_id == MOUNT) { // It is means that the model is loaded
      
      msg->msg_id = REGISTER_DEVICE;
      
      msg->_u.dev_msg.dev_type = CHR_DEV;
      msg->_u.dev_msg.major = major;
      msg->_u.dev_msg.minor = minor++;

      memset(msg->_u.dev_msg.dev_name, 0, sizeof(msg->_u.dev_msg.dev_name));
      sprintf((char *)&msg->_u.dev_msg.dev_name[0], "llm%d", msg->_u.dev_msg.minor);
  
      sendto(sock, buf, 256, 0, (struct sockaddr *) &resmgr_addr, sizeof(resmgr_addr));
    }
    else if (msg->msg_id == (REGISTER_DEVICE|0x80)) {

      if (msg->_errno)
	continue;

      emscripten_log(EM_LOG_CONSOLE, "llm: REGISTER_DEVICE successful: %d,%d,%d", msg->_u.dev_msg.dev_type, msg->_u.dev_msg.major, msg->_u.dev_msg.minor);
    }
    else if (msg->msg_id == OPEN) {

      emscripten_log(EM_LOG_CONSOLE, "llm: OPEN");

      int loaded = EM_ASM_INT({

	  return window.llm_loaded;
	  
	});

      llm_answer_length = 0;
      llm_read_offset = 0;
      llm_answer_finished = 0;
      llm_read_pending = 0;

      msg->_u.open_msg.remote_fd = 0;
      msg->_errno = 0;
      
      msg->msg_id |= 0x80;
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == CLOSE) {

      emscripten_log(EM_LOG_CONSOLE, "llm: CLOSE");

      EM_ASM({

	  window.llm_closed = 1;
	  
	});

      msg->_errno = 0;
      
      msg->msg_id |= 0x80;
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == WRITE) {

      emscripten_log(EM_LOG_CONSOLE, "llm: WRITE from %d: fd=%d -> %d bytes", msg->pid, msg->_u.io_msg.fd, msg->_u.io_msg.len);

      llm_answer_finished = 0;
      
      char * buf2 = msg->_u.io_msg.buf;

      if (msg->_u.io_msg.len > (bytes_rec - 20)) {
	
	emscripten_log(EM_LOG_CONSOLE, "llm: WRITE need to read %d remaining bytes (%d read)", msg->_u.io_msg.len - (bytes_rec - 20), bytes_rec - 20);

	buf2 = (char *)malloc(msg->_u.io_msg.len);

	memcpy(buf2, msg->_u.io_msg.buf, bytes_rec - 20);

	int bytes_rec2 = recvfrom(sock, buf2+bytes_rec - 20, msg->_u.io_msg.len - (bytes_rec - 20), 0, (struct sockaddr *) &remote_addr, &len);

	emscripten_log(EM_LOG_CONSOLE, "llm: WRITE %d read", bytes_rec2);
      }

      int res = EM_ASM_INT({

	  window.chat(UTF8ToString($0, $1));
	  
	}, buf2, msg->_u.io_msg.len);

      msg->_errno = 0;

      msg->msg_id |= 0x80;
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      
      if (buf2 != msg->_u.io_msg.buf) {

	free(buf2);
      }

    }
    else if (msg->msg_id == READ_TTY) {  // It is not tty but this msg id is safe
      
      if (msg->_u.io_msg.len == 0) { // End of llm answer

	llm_answer_finished = 1;
      }
      else {

	llm_answer_finished = 0;

	if ((llm_answer_length+msg->_u.io_msg.len) < LLM_LEN_MAX) {
	
	  memcpy(llm_answer+llm_answer_length, msg->_u.io_msg.buf, msg->_u.io_msg.len);
	  
	  llm_answer_length += msg->_u.io_msg.len;

	  llm_answer[llm_answer_length] = 0;
	}
      }

      if (llm_read_pending) {
	
	send_reply(sock);
	
	llm_read_pending = 0;
      }
    }
    else if (msg->msg_id == READ) {

      emscripten_log(EM_LOG_CONSOLE, "llm: READ from %d: fd=%d", msg->pid, msg->_u.io_msg.fd);

      llm_read_pending_len = msg->_u.io_msg.len;
      llm_read_pending_pid = msg->pid;
      llm_read_pending_fd = msg->_u.io_msg.fd;
      memcpy(&llm_read_pending_addr, &remote_addr, sizeof(remote_addr));

      if ((llm_answer_length > 0) || llm_answer_finished) {

	if ( (llm_answer_length == 0) && llm_answer_finished) { // Reset llm_answer_finished as we reply an empty response
	  
	  llm_answer_finished = 0;
	}

	send_reply(sock);
      }
      else {

	llm_read_pending = 1;
      }

    }
    
  }
  
  return 0;
}
