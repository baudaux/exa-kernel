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
#include <sys/ioctl.h>

#include "msg.h"
#include "circular_buffer.h"
#include "jobs.h"

#ifndef DEBUG
#define DEBUG 0
#endif

#if DEBUG
#include <emscripten.h>
#else
#define emscripten_log(...)
#endif

#define PIPE_VERSION "pipe v0.1.0"

#define PIPE_PATH "/var/pipe.peer"
#define RESMGR_PATH "/var/resmgr.peer"

#define NB_FD_MAX     32
#define PIPE_SIZE     65536

#define NB_JOBS_MAX   64

enum {
  // NO_JOB=0
  WRITE_JOB  = 0x20000000,
  IO_JOB     = 0x40000000,
  SELECT_JOB = 0x80000000,
};

static struct job jobs[NB_JOBS_MAX];

struct pipe {

  int read_fd;
  int write_fd;
  int flags;
  struct circular_buffer buf;
};

static struct pipe fds[NB_FD_MAX];

static int major;

static int last_fd = 0;

void init_fds() {

  for (int i=0; i < NB_FD_MAX; ++i) {
    
    fds[i].read_fd = -1;
    fds[i].write_fd = -1;
  }
}

int find_free_fd(int fd[2], int flags) {

  for (int i=0; i < NB_FD_MAX; ++i) {

    if ( (fds[i].read_fd < 0) && ((fds[i].write_fd < 0)) ) {

      last_fd += 2;
      
      fds[i].read_fd = fd[0] = last_fd;
      fds[i].write_fd = fd[1] = last_fd+1;
      fds[i].flags = flags;

      init_circular_buffer(&fds[i].buf, PIPE_SIZE);
      
      return i;
    }
  }

  return -1;
}

int find_fd(int fd) {

  int read_fd = fd-(fd%2); // read fd is even

  for (int i=0; i < NB_FD_MAX; ++i) {

    if (fds[i].read_fd == read_fd) {

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
  
  emscripten_log(EM_LOG_CONSOLE, "Starting " PIPE_VERSION "...");

  /*int fd = open("/dev/tty1", O_WRONLY | O_NOCTTY);
  
  if (fd >= 0)
    write(fd, "\n\r[" PIPE_VERSION "]", strlen("\n\r[" PIPE_VERSION "]")+1);

    close(fd);*/

  init_fds();

  jobs_init(jobs, NB_JOBS_MAX);
  
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

    emscripten_log(EM_LOG_CONSOLE, "*** pipe: %d from %s", msg->msg_id, remote_addr.sun_path);

    if (msg->msg_id == (REGISTER_DRIVER|0x80)) {

      if (msg->_errno)
	continue;

      major = msg->_u.dev_msg.major;

      emscripten_log(EM_LOG_CONSOLE, "REGISTER_DRIVER successful: major=%d", major);
    }
    else if (msg->msg_id == PIPE) {

      emscripten_log(EM_LOG_CONSOLE, "pipe: PIPE");

      if (find_free_fd(msg->_u.pipe_msg.remote_fd, msg->_u.pipe_msg.flags) >= 0) {

	emscripten_log(EM_LOG_CONSOLE, "pipe: PIPE %d %d", msg->_u.pipe_msg.remote_fd[0], msg->_u.pipe_msg.remote_fd[1]);

	msg->_errno = 0;
	
      } else {

	msg->_errno = ENOMEM;
      }

      msg->_u.pipe_msg.type = CHR_DEV;
      msg->_u.pipe_msg.major = major;
      msg->_u.pipe_msg.minor = 0;
      strcpy(msg->_u.pipe_msg.peer, PIPE_PATH);

      msg->msg_id |= 0x80;
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == CLOSE) {

      emscripten_log(EM_LOG_CONSOLE, "pipe: CLOSE %d", msg->_u.close_msg.fd);

      int i = find_fd(msg->_u.close_msg.fd); /*msg->_u.close_msg.fd / 2*/

      if (i >= 0) {

	if ((msg->_u.close_msg.fd % 2) == 0) { // read end is closed
	  
	  fds[i].read_fd = -1;

	  if (fds[i].write_fd == -1) {

	    free_circular_buffer(&fds[i].buf);
	  }
	  else { // Check if pending write or select

	    char * buf2;
	    int buf2_size;
	    struct sockaddr_un * addr2;

	    unsigned long job = get_pending_job_by_type(jobs, msg->_u.close_msg.fd+1, 0x1fffffff, &buf2, &buf2_size, &addr2);

	    emscripten_log(EM_LOG_CONSOLE, "pipe: CLOSE -> pending job = %lu", job);

	    if (job) { // a write or select is pending
	      
	      if ((job & 0xE0000000) == (WRITE_JOB|IO_JOB)) { // write in this case

		struct message * msg2 = (struct message *)&buf2[0];
		
		emscripten_log(EM_LOG_CONSOLE, "pipe: CLOSE -> pending write job len=%d", msg2->_u.io_msg.len);

		int buf3_size = 8 +12;
		char * buf3 = (char *)malloc(buf3_size);
		struct message * msg3 = (struct message *)&buf3[0];
		
		msg3->msg_id = (WRITE|0x80);
		msg3->pid = msg2->pid;
		msg3->_errno = EPIPE; //TODO: or send signal

		msg3->_u.io_msg.fd = msg2->_u.io_msg.fd;
		msg3->_u.io_msg.len = 0;
		  
		sendto(sock, buf3, buf3_size, 0, (struct sockaddr *) addr2, sizeof(*addr2));
		del_pending_job(jobs, job, msg3->pid);

		free(buf3);
	      }
	      else if ( (job & 0xC0000000) == SELECT_JOB) {

		struct message * msg2 = (struct message *)&buf2[0];

		msg2->msg_id = (SELECT|0x80);

		msg2->_errno = EPIPE; //TODO: or send signal
		  
		sendto(sock, buf2, buf2_size, 0, (struct sockaddr *) addr2, sizeof(*addr2));
		del_pending_job(jobs, job, msg2->pid);
	      }
	    }
	  }
	}
	else { // write end is closed
	  
	  fds[i].write_fd = -1;

	  if (fds[i].read_fd == -1) {

	    free_circular_buffer(&fds[i].buf);
	  }
	  else { // Check if pending read or select

	    char * buf2;
	    int buf2_size;
	    struct sockaddr_un * addr2;

	    unsigned long job = get_pending_job_by_type(jobs, msg->_u.close_msg.fd-1, 0x1fffffff, &buf2, &buf2_size, &addr2);

	    emscripten_log(EM_LOG_CONSOLE, "pipe: CLOSE -> pending job = %lu", job);

	    if (job) { // a read or select is pending
	      
	      if ((job & 0xE0000000) == IO_JOB) { // read in this case

		struct message * msg2 = (struct message *)&buf2[0];
		
		emscripten_log(EM_LOG_CONSOLE, "pipe: CLOSE -> pending read job len=%d addr=%s", msg2->_u.io_msg.len, addr2->sun_path);

		int buf3_size = 8 +12;
		char * buf3 = (char *)malloc(buf3_size);
		struct message * msg3 = (struct message *)&buf3[0];
		
		msg3->msg_id = (READ|0x80);
		msg3->pid = msg2->pid;
		msg3->_errno = 0;

		msg3->_u.io_msg.fd = msg2->_u.io_msg.fd;
		msg3->_u.io_msg.len = 0;
		  
		sendto(sock, buf3, buf3_size, 0, (struct sockaddr *) addr2, sizeof(*addr2));
		
		del_pending_job(jobs, job, msg3->pid);

		free(buf3);
	      }
	      else if ( (job & 0xC0000000) == SELECT_JOB) {

		struct message * msg2 = (struct message *)&buf2[0];

		msg2->msg_id = (SELECT|0x80);

		msg2->_errno = EPIPE; //TODO: or send signal
		
		  
		sendto(sock, buf2, buf2_size, 0, (struct sockaddr *) addr2, sizeof(*addr2));
		del_pending_job(jobs, job, msg2->pid);
	      }
	    }
	  }
	}

	msg->_errno = 0;
      }
      else {

	msg->_errno = EBADFD;
      }

      msg->msg_id |= 0x80;
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == READ) {

      emscripten_log(EM_LOG_CONSOLE, "pipe: READ from %d: fd=%d", msg->pid, msg->_u.io_msg.fd);

      int i = find_fd(msg->_u.io_msg.fd); //msg->_u.io_msg.fd / 2;

      if (i >= 0) {
	
	if ((msg->_u.io_msg.fd % 2) == 0) {

	  int len = read_circular_buffer(&fds[i].buf, msg->_u.io_msg.len, msg->_u.io_msg.buf);

	  emscripten_log(EM_LOG_CONSOLE, "pipe: READ -> len=%d", len);

	  if (len > 0) {

	    msg->_u.io_msg.len = len;
	    msg->_errno = 0;

	    char * buf2;
	    int buf2_size;
	    struct sockaddr_un * addr2;

	    unsigned long job = get_pending_job_by_type(jobs, msg->_u.io_msg.fd+1, 0x1fffffff, &buf2, &buf2_size, &addr2);

	    emscripten_log(EM_LOG_CONSOLE, "pipe: WRITE -> pending job = %lu", job);

	    if (job) { // a write or select is pending
	      
	      if ( (job & 0xE0000000) == (WRITE_JOB|IO_JOB)) { // write in this case

		struct message * msg2 = (struct message *)&buf2[0];
		
		emscripten_log(EM_LOG_CONSOLE, "pipe: WRITE -> pending write job  len=%d", msg2->_u.io_msg.len);

		int len2 = write_circular_buffer(&fds[i].buf, msg2->_u.io_msg.len, msg2->_u.io_msg.buf);

		if (len2 ==  msg2->_u.io_msg.len) { // all pending write has been  be performed
		  
		  int buf3_size = 8 +12;
		  char * buf3 = (char *)malloc(buf3_size);
		  struct message * msg3 = (struct message *)&buf3[0];
		  
		  msg3->msg_id = (WRITE|0x80);
		  msg3->pid = msg2->pid;
		  msg3->_errno = 0;

		  msg3->_u.io_msg.fd = msg2->_u.io_msg.fd;
		  msg3->_u.io_msg.len = len2;
		  
		  sendto(sock, buf3, buf3_size, 0, (struct sockaddr *) addr2, sizeof(*addr2));
		  del_pending_job(jobs, job, msg3->pid);

		  free(buf3);
		}
		else {

		  if (len2 > 0) { // skip the first len bytes already written

		    msg2->_u.io_msg.len -= len2;
		    memmove(msg2->_u.io_msg.buf, msg2->_u.io_msg.buf+len2, msg2->_u.io_msg.len); // memmove is used as regions can overlap
		  }
		}
	      }
	      else if ( (job & 0xE0000000) == (WRITE_JOB|SELECT_JOB)) {
		
		struct message * msg2 = (struct message *)&buf2[0];

		msg2->msg_id |= 0x80;

		msg2->_errno = 0;
		  
		sendto(sock, buf2, buf2_size, 0, (struct sockaddr *) addr2, sizeof(*addr2));
		del_pending_job(jobs, job, msg2->pid);
	      }
	    }
	    
	  }
	  else if (fds[i].write_fd == -1) { // write end has been closed

	    msg->_u.io_msg.len = 0;
	    msg->_errno = 0;
	  }
	  else if (fds[i].flags & O_NONBLOCK) {
	    
	    msg->_errno = EAGAIN;
	  }
	  else {

	    emscripten_log(EM_LOG_CONSOLE, "pipe: READ from %d: add pending job addr=%s", msg->pid, remote_addr.sun_path);

	    msg->msg_id |= 0x80;
	    
	    add_pending_job(jobs, IO_JOB | msg->_u.io_msg.fd, msg->pid, msg, bytes_rec, &remote_addr);

	    continue; // do not send read ack since write is pending
	  }
	}
	else {
	  msg->_errno = EBADFD;
	}
      }
      else {

	msg->_errno = EBADFD;
      }
      
      msg->msg_id |= 0x80;
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      
    }
    else if (msg->msg_id == WRITE) {

      emscripten_log(EM_LOG_CONSOLE,"pipe: WRITE from %d: fd=%d len=%d", msg->pid, msg->_u.io_msg.fd, msg->_u.io_msg.len);

      char * buf1 = msg->_u.io_msg.buf;

      if (msg->_u.io_msg.len > (bytes_rec - 20)) {

	emscripten_log(EM_LOG_CONSOLE, "pipe: WRITE need to read %d remaining bytes (%d read)", msg->_u.io_msg.len - (bytes_rec - 20), bytes_rec - 20);

	buf1 =(char *)malloc(msg->_u.io_msg.len);

	memcpy(buf1, msg->_u.io_msg.buf, bytes_rec - 20);

	int bytes_rec2 = recvfrom(sock, buf1+bytes_rec - 20, msg->_u.io_msg.len - (bytes_rec - 20), 0, (struct sockaddr *) &remote_addr, &len);

	emscripten_log(EM_LOG_CONSOLE, "pipe: WRITE %d read", bytes_rec2);
      }

      int i = find_fd(msg->_u.io_msg.fd); //msg->_u.io_msg.fd / 2;

      if (i >= 0) {
	
	if ((msg->_u.io_msg.fd % 2) == 1) {

	  int len = write_circular_buffer(&fds[i].buf, msg->_u.io_msg.len, buf1);

	  emscripten_log(EM_LOG_CONSOLE,"pipe: WRITE %d bytes written (%d)", len, count_circular_buffer(&fds[i].buf));

	  if (len > 0) {

	    char * buf2;
	    int buf2_size;
	    struct sockaddr_un * addr2;

	    unsigned long job = get_pending_job_by_type(jobs, msg->_u.io_msg.fd-1, 0x1fffffff, &buf2, &buf2_size, &addr2);

	    emscripten_log(EM_LOG_CONSOLE,"pipe: WRITE -> pending job = %lu", job);

	    if (job) { // a read or select is pending
	      
	      if ( (job & 0xE0000000) == IO_JOB) { // read in this case

		struct message * msg2 = (struct message *)&buf2[0];
		
		emscripten_log(EM_LOG_CONSOLE,"pipe: WRITE -> pending job READ_WRITE_JOB len=%d", msg2->_u.io_msg.len);

		int buf3_size = msg2->_u.io_msg.len +8 +12;
		char * buf3 = (char *)malloc(buf3_size);
		struct message * msg3 = (struct message *)&buf3[0];
		
		msg3->_u.io_msg.len = read_circular_buffer(&fds[i].buf, msg2->_u.io_msg.len, msg3->_u.io_msg.buf);

		emscripten_log(EM_LOG_CONSOLE,"pipe: WRITE -> msg2->_u.io_msg.len=%d buf3_size=%d msg3->_u.io_msg.len=%d", msg2->_u.io_msg.len, buf3_size, msg3->_u.io_msg.len);

		if (msg3->_u.io_msg.len > 0) {

		  emscripten_log(EM_LOG_CONSOLE,"pipe: WRITE -> return of read %s", addr2->sun_path);
		  
		  msg3->msg_id = (READ|0x80);
		  msg3->pid = msg2->pid;
		  msg3->_errno = 0;

		  msg3->_u.io_msg.fd = msg2->_u.io_msg.fd;
		  
		  sendto(sock, buf3, buf3_size, 0, (struct sockaddr *) addr2, sizeof(*addr2));
		  del_pending_job(jobs, job, msg3->pid);
		}

		free(buf3);
	      }
	      else if ( (job & 0xE0000000) == SELECT_JOB) {
		
		struct message * msg2 = (struct message *)&buf2[0];

		emscripten_log(EM_LOG_CONSOLE,"pipe: WRITE -> pending job SELECT: %d %d", msg2->_u.select_msg.fd, msg2->_u.select_msg.remote_fd);

		msg2->msg_id |= 0x80;

		msg2->_errno = 0;
		  
		sendto(sock, buf2, buf2_size, 0, (struct sockaddr *) addr2, sizeof(*addr2));
		del_pending_job(jobs, job, msg2->pid);
	      }
	    }
	  }

	  if (len < msg->_u.io_msg.len) { // all buf could not be written

	    if (len > 0) {
	      msg->_u.io_msg.len -= len;
	      memmove(buf1, buf1+len, msg->_u.io_msg.len); // memmove is used as regions can overlap
	    }
	    
	    msg->msg_id |= 0x80;

	    if (buf1 == msg->_u.io_msg.buf) {
	      add_pending_job(jobs, WRITE_JOB | IO_JOB | msg->_u.io_msg.fd, msg->pid, msg, msg->_u.io_msg.len+20, &remote_addr);
	    }
	    else {

	      // Allocate msg2 that can be bigger than msg

	      struct message * msg2 = malloc(msg->_u.io_msg.len+20);

	      if (msg2) {

		memmove(msg2, msg, 20);
		memmove(msg2->_u.io_msg.buf, buf1, msg->_u.io_msg.len);

		// using msg2 !!
	      
		add_pending_job(jobs, WRITE_JOB | IO_JOB | msg->_u.io_msg.fd, msg->pid, msg2, msg->_u.io_msg.len+20, &remote_addr);

		free(msg2);
	      }
	      
	    }
	    
	    continue; // do not send write ack since write is pending
	  }
	}
	else {
	  msg->_errno = EBADFD;
	}
      }
      else {

	msg->_errno = EBADFD;
      }

      msg->msg_id |= 0x80;
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

      if (buf1 != msg->_u.io_msg.buf) {

	free(buf1);
      }
      
    }
    else if (msg->msg_id == SEEK) {

      //emscripten_log(EM_LOG_CONSOLE, "pipe: SEEK from %d", msg->pid);

      msg->msg_id |= 0x80;
      msg->_errno = ESPIPE;
      
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == IOCTL) {

      emscripten_log(EM_LOG_CONSOLE, "pipe: IOCTL from %d: %d", msg->pid, msg->_u.ioctl_msg.op);

      msg->_errno = 0;
      
      if (msg->_u.ioctl_msg.op == TIOCGWINSZ) {

	msg->_errno = ENOTTY;
      }

      msg->msg_id |= 0x80;
      
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == FCNTL) {
      
      emscripten_log(EM_LOG_CONSOLE, "ip: FCNTL from %d: %d %d", msg->pid, msg->_u.fcntl_msg.fd, msg->_u.fcntl_msg.cmd);

      msg->_u.fcntl_msg.ret = 0;
      msg->_errno = 0;

      if (msg->_u.fcntl_msg.cmd == F_SETFL) {

	int flags;

	memcpy(&flags, msg->_u.fcntl_msg.buf, sizeof(int));

	int i = find_fd(msg->_u.fcntl_msg.fd);

	if (i >= 0) {

	  fds[i].flags = flags;
	}
      }

      msg->msg_id |= 0x80;
      
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == SELECT) {
      
      emscripten_log(EM_LOG_CONSOLE, "pipe: SELECT from %d: %d %d %d %d", msg->pid, msg->_u.select_msg.fd, msg->_u.select_msg.remote_fd, msg->_u.select_msg.read_write, msg->_u.select_msg.start_stop);

      int answer = 0;
      msg->_errno = 0;

      int i = find_fd(msg->_u.select_msg.remote_fd);  //msg->_u.select_msg.remote_fd / 2;

      if (i >= 0) {
      
	if (msg->_u.select_msg.start_stop) { // start

	  if (msg->_u.select_msg.read_write) { // write
	
	    if ((msg->_u.select_msg.remote_fd % 2) == 1) {

	      if (count_circular_buffer(&fds[i].buf) <= (PIPE_SIZE-2)) {

		emscripten_log(EM_LOG_CONSOLE, "pipe: SELECT from %d: %d bytes in queue %d (write)", msg->pid, count_circular_buffer(&fds[i].buf), i);
		
		answer = 1;
	      }
	      else if (!msg->_u.select_msg.once) {

		add_pending_job(jobs, SELECT_JOB | msg->_u.select_msg.remote_fd, msg->pid, msg, bytes_rec, &remote_addr);
	      }
	    }
	  }
	  else { // read

	    if ((msg->_u.select_msg.remote_fd % 2) == 0) {

	      if (count_circular_buffer(&fds[i].buf) > 0) {

		emscripten_log(EM_LOG_CONSOLE, "pipe: SELECT from %d: %d bytes in queue %d (read)", msg->pid, count_circular_buffer(&fds[i].buf), i);
		
		answer = 1;
	      }
	      else if (fds[i].write_fd == -1) { // write end has been closed

		emscripten_log(EM_LOG_CONSOLE, "pipe: SELECT from %d: write end has been closed", msg->pid);
		
		answer = 1;
		msg->_errno = EPIPE;
		msg->_u.select_msg.once = 2; //POLLHUP
	      }
	      else if (!msg->_u.select_msg.once) {
		
		add_pending_job(jobs, SELECT_JOB | msg->_u.select_msg.remote_fd, msg->pid, msg, bytes_rec, &remote_addr);
	      }
	    }
	  }
	}
	else {

	  del_pending_job(jobs, SELECT_JOB | msg->_u.select_msg.remote_fd, msg->pid);
	}
      }
      
      if (answer > 0) {

	emscripten_log(EM_LOG_CONSOLE, "pipe: SELECT from %d: answer remote_fd=%d", msg->pid, msg->_u.select_msg.remote_fd);

	msg->msg_id |= 0x80;
	
	sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      }
    }
  }
  
  return 0;
}
