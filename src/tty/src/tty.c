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
#include <stdlib.h>
#include <sys/sysmacros.h>
#include <sys/ttydefaults.h>
#include <errno.h>

#include <sys/ioctl.h>
#include <termios.h>

#include <time.h>
#include <sys/timerfd.h>

#include "msg.h"
#include "circular_buffer.h"

#ifndef DEBUG
#define DEBUG 0
#endif

#include <emscripten.h>

#if DEBUG
#else
#define emscripten_log(...)
#endif

#define TTY_VERSION "[tty v0.1.0]"

#define TTY_PATH "/var/tty.peer"
#define RESMGR_PATH "/var/resmgr.peer"

#define NB_TTY_MAX       32
#define NB_CLIENT_MAX    64

#define TTY_BUF_SIZE     (16*1024)

#define TTY_TIMEOUT      15

enum tty_dev_type {

  TTY = 0,
  PTM,
  PTS
};

struct device_ops {

  int (*open)(const char * pathname, int flags, mode_t mode, unsigned short minor, pid_t pid, pid_t sid);
  ssize_t (*read)(int fd, void * buf, size_t len);
  ssize_t (*write)(int fd, const void * buf, size_t len);
  int (*ioctl)(int fd, int op, unsigned char * buf, size_t len, pid_t pid, pid_t sid, pid_t pgrp);
  int (*close)(int fd);
  ssize_t (*enqueue)(int fd, void * buf, size_t len, struct message * reply_msg);
  int (*select)(pid_t pid, int remote_fd, int fd, int read_write, int start_stop, int once, struct sockaddr_un * sock_addr);
  int (*flush)(int fd);
};

struct pending_request {

  pid_t pid;
  int fd;
  size_t len;
  struct sockaddr_un client_addr;
};

struct write_pending_request {

  pid_t pid;
  int fd;
  size_t len;
  char * buf;
  int offset;
  size_t orig_len;
  struct sockaddr_un client_addr;
};

struct select_pending_request {

  pid_t pid;
  int remote_fd;
  int fd;
  struct sockaddr_un client_addr;
};

struct device_desc {

  struct termios ctrl;
  struct device_ops * ops;
  struct winsize ws;

  struct pending_request read_pending;
  struct select_pending_request read_select_pending;
  struct write_pending_request write_pending;

  struct circular_buffer rx_buf;
  struct circular_buffer tx_buf;

  int timer;
  int timer_started;

  int data_written;
  
  pid_t session;
  pid_t fg_pgrp;

  enum tty_dev_type type;

  int ptm_fd; // used for pts dev

  int state; // 0: closed; 1: open
};

struct client {

  pid_t pid;
  unsigned short minor;
  int flags;
  unsigned short mode;
  int pts_dev_minor; // used by ptm
};

static struct sockaddr_un resmgr_addr;
static int sock;

static unsigned short major;
static unsigned short minor = 0;

static struct device_desc devices[NB_TTY_MAX];

static int last_fd = 0;

static struct client clients[NB_CLIENT_MAX];

// TODO : do not use fd as index

struct device_desc * get_device(unsigned short m) {

  return &devices[m];
}

struct device_desc * get_device_from_fd(int fd) {

  return &devices[clients[fd].minor];
}

struct device_desc * get_device_from_session(pid_t sid, unsigned short * min) {

  for (unsigned short i = 1; i <= minor; i++) {

    if (devices[i].session == sid) {

      *min = i;
      return &devices[i];
    }
  }

  return NULL;
}

static int add_client(int fd, pid_t pid, unsigned short m, int flags, unsigned short mode) {

  clients[fd].pid = pid;
  clients[fd].minor = m;
  clients[fd].flags = flags;
  clients[fd].mode = mode;
  clients[fd].pts_dev_minor = -1;
  
  devices[m].state = 1;

  return fd;
}

static int del_pts_client(int fd) {

  clients[fd].pid = -1;
  
  int found = 0;
  
  for (int i = 1; i <= last_fd; ++i) {

    if ( (clients[i].pid >= 0) && (clients[fd].minor == clients[i].minor) )
      found = 1;
  }

  if (!found) { // no other open client for this device
    
    emscripten_log(EM_LOG_CONSOLE,"!! pts closed: need to notify other side i.e ptm");

    devices[clients[fd].minor].state = 0;

    struct device_desc * ptm_dev = get_device_from_fd(devices[clients[fd].minor].ptm_fd);

    unsigned char reply_buf[256];
    struct message * reply_msg = (struct message *)&reply_buf[0];
      
    if ( (ptm_dev->read_pending.fd >= 0) && (ptm_dev->read_pending.len > 0) ) { // Pending read

      reply_msg->msg_id = READ|0x80;
      reply_msg->pid = ptm_dev->read_pending.pid;
      reply_msg->_errno = 0;
      reply_msg->_u.io_msg.fd = ptm_dev->read_pending.fd;

      size_t sent_len = 0;
      
      reply_msg->_u.io_msg.len = sent_len;

      sendto(sock, reply_buf, 256, 0, (struct sockaddr *) &ptm_dev->read_pending.client_addr, sizeof(ptm_dev->read_pending.client_addr));

      ptm_dev->read_pending.len = 0; // unset read pending
      ptm_dev->read_pending.fd = -1;
    }
    else if (ptm_dev->read_select_pending.fd >= 0) {

      emscripten_log(EM_LOG_CONSOLE, "del_client: pending read select: fd=%d", ptm_dev->read_select_pending.fd);

      int i;

      reply_msg->msg_id = SELECT|0x80;
      reply_msg->pid = ptm_dev->read_select_pending.pid;
      reply_msg->_errno = 0;
      reply_msg->_u.select_msg.remote_fd = ptm_dev->read_select_pending.remote_fd;
      reply_msg->_u.select_msg.fd = ptm_dev->read_select_pending.fd;
      reply_msg->_u.select_msg.read_write = 0; // read
      reply_msg->_u.select_msg.once = 2; // hangup
	
      sendto(sock, reply_buf, 1256, 0, (struct sockaddr *) &ptm_dev->read_select_pending.client_addr, sizeof(ptm_dev->read_select_pending.client_addr));

      ptm_dev->read_select_pending.fd = -1; // unset read select pending
      ptm_dev->read_select_pending.remote_fd = -1;
    }
  }

  return fd;
}

static int del_ptmx_client(int fd) {

  clients[fd].pid = -1;

  emscripten_log(EM_LOG_CONSOLE, "!! ptm closed: need to notify other side i.e processes belonging to the session %d", devices[clients[fd].pts_dev_minor].session);
  char buf[256];
  struct message * msg = (struct message *)&buf[0];
      
  msg->msg_id = KILL;
  msg->pid = 2; // PID of TTY driver
  msg->_u.kill_msg.pid = devices[clients[fd].pts_dev_minor].session | 0x40000000; // meaning session id
  msg->_u.kill_msg.sig = SIGHUP;
  
  sendto(sock, buf, 256, 0, (struct sockaddr *) &resmgr_addr, sizeof(resmgr_addr));

  return fd;
}

static void init_ctrl(struct termios * ctrl) {

  ctrl->c_iflag = TTYDEF_IFLAG;
  ctrl->c_oflag = TTYDEF_OFLAG;
  ctrl->c_cflag = TTYDEF_CFLAG;
  ctrl->c_lflag = TTYDEF_LFLAG;

  ctrl->c_cflag |= B9600;

  ctrl->c_line = 0;

  ctrl->c_cc[VINTR] = 3;    // C-C
  ctrl->c_cc[VQUIT] = 28;   // C-backslash
  ctrl->c_cc[VERASE] = 127;
  ctrl->c_cc[VKILL] = 21;   // C-U
  ctrl->c_cc[VEOF] = 4;     // C-D
  ctrl->c_cc[VTIME] = 0;
  ctrl->c_cc[VMIN] = 1;
  ctrl->c_cc[VSWTC] = 0;
  ctrl->c_cc[VSTART] = 0;
  ctrl->c_cc[VSTOP] = 0;
  ctrl->c_cc[VSUSP] = 26;   // C-Z
  ctrl->c_cc[VEOL] = 0;
  ctrl->c_cc[VREPRINT] = 0;
  ctrl->c_cc[VDISCARD] = 0;
  ctrl->c_cc[VWERASE] = 23; // C-W
  ctrl->c_cc[VLNEXT] = 0;
  ctrl->c_cc[VEOL2] = 0;
  
  ctrl->__c_ispeed = B9600;
  ctrl->__c_ospeed = B9600;
}

int register_device(unsigned short m, struct device_ops * dev_ops, enum tty_dev_type type) {

  devices[m].ops = dev_ops;

  if ( (type == TTY) || (type == PTS) ) {

    init_ctrl(&devices[m].ctrl);
    
    init_circular_buffer(&devices[m].rx_buf, TTY_BUF_SIZE);
    init_circular_buffer(&devices[m].tx_buf, TTY_BUF_SIZE);
  }
  
  if ( (type == TTY) || (type == PTS) )
    devices[m].timer = timerfd_create(CLOCK_MONOTONIC, 0);
  else
    devices[m].timer = -1;
      
  devices[m].timer_started = 0;
  devices[m].data_written = 0;

  devices[m].read_pending.fd = -1;
  devices[m].read_select_pending.fd = -1;
  devices[m].write_pending.fd = -1;
  
  devices[m].session = 0;
  devices[m].fg_pgrp = 0;

  devices[m].type = type;

  devices[m].ptm_fd = -1;

  devices[m].state = 0; // closed

  return 0;
}


EM_JS(int, probe_terminal, (), {

    let buf_size = 256;

    let buf = new Uint8Array(buf_size);
    
    buf[0] = 23; // PROBE_TTY

    let msg = {

       from: "/var/tty.peer",
       buf: buf,
       len: buf_size
    };

    let bc = Module.get_broadcast_channel("/dev/tty1");
    
    bc.postMessage(msg);
  });

EM_JS(int, write_terminal, (char * buf, unsigned long len), {

    let msg = {

       from: "/var/tty.peer",
       write: 1,
       buf: Module.HEAPU8.slice(buf, buf+len),
       len: len
    };

    let bc = Module.get_broadcast_channel("/dev/tty1");
    
    bc.postMessage(msg);

    return len;
  });

static void start_timer(struct device_desc * dev) {

  struct itimerspec ts;
  
  if (!dev->timer_started) {

    //emscripten_log(EM_LOG_CONSOLE,"start_timer");

    dev->timer_started = 1;
     
    unsigned long long val_msec = TTY_TIMEOUT;
    unsigned long long int_msec = TTY_TIMEOUT;
     
    ts.it_interval.tv_sec = int_msec / 1000ull;
    ts.it_interval.tv_nsec = (int_msec % 1000ull) * 1000000ull;
    ts.it_value.tv_sec = val_msec / 1000ull;
    ts.it_value.tv_nsec = (val_msec % 1000ull) * 1000000ull;
     
    timerfd_settime(dev->timer, 0, &ts, NULL);
  }
}

static void stop_timer(struct device_desc * dev) {

  struct itimerspec ts;
  
  if (dev->timer_started) {
    
    //emscripten_log(EM_LOG_CONSOLE,"stop_timer");
    
    dev->timer_started = 0;
    
    ts.it_interval.tv_sec = 0;
    ts.it_interval.tv_nsec = 0;
    ts.it_value.tv_sec = 0;
    ts.it_value.tv_nsec = 0;
     
    timerfd_settime(dev->timer, 0, &ts, NULL);
  }
}

static int local_tty_open(const char * pathname, int flags, mode_t mode, unsigned short m, pid_t pid, pid_t sid) {

  ++last_fd;

  add_client(last_fd, pid, m, flags, mode);

  emscripten_log(EM_LOG_CONSOLE,"local_tty_open: fd=%d", last_fd);

  //emscripten_log(EM_LOG_CONSOLE,"local_tty_open: %d %d", get_device_from_fd(last_fd)->session, get_device_from_fd(last_fd)->fg_pgrp);
  
  return last_fd;
}

static ssize_t local_tty_read(int fd, void * buf, size_t len) {

  emscripten_log(EM_LOG_CONSOLE, "local_tty_read: len=%d", len);
  
  struct device_desc * dev = (fd == -1)?get_device(1):get_device_from_fd(fd);
  
  size_t len2 = 0;

  if (dev->ctrl.c_lflag & ICANON) {

    // Search EOL
    int i;

    if (find_eol_circular_buffer(&dev->rx_buf, &i) > 0) {

      len2 = count_circular_buffer_index(&dev->rx_buf, i)+1;
    }
  }
  else {

    len2 = count_circular_buffer(&dev->rx_buf);
  }

  if (len2 > 0) {
      
    size_t sent_len = (len2 <= len)?len2:len;

    read_circular_buffer(&dev->rx_buf, sent_len, buf);
    
    return sent_len;
  }
    
  return 0;
}

static int local_tty_flush(int fd) {

  struct device_desc * dev = (fd == -1)?get_device(1):get_device_from_fd(fd);
  
  struct itimerspec ts;

  char * ptr;
  
  int count = get_circular_buffer_head(&dev->tx_buf, &ptr);

  if (count > 0) {
    
    write_terminal(ptr, count);

    count = get_circular_buffer_tail(&dev->tx_buf, &ptr);

    if (count > 0) {

      write_terminal(ptr, count);
    }

    empty_circular_buffer(&dev->tx_buf);

    return 1;
  }

  return 0;
}

static int tty_write_char(struct device_desc * dev, char c) {

  if ( (c == '\n') && (dev->ctrl.c_oflag & ONLCR) ) {

    if (count_circular_buffer(&dev->tx_buf) > (TTY_BUF_SIZE-5))
      return 0;

    enqueue_circular_buffer(&dev->tx_buf, '\r');
  }
  else if ( (c == '\r') && (dev->ctrl.c_oflag & OCRNL) ) {

    if (count_circular_buffer(&dev->tx_buf) > (TTY_BUF_SIZE-5))
      return 0;
    
    enqueue_circular_buffer(&dev->tx_buf, '\n');
  }
  else if ( (c == '\r') && (dev->ctrl.c_oflag & ONLRET) ) {

    return 1;
  }
  else if (count_circular_buffer(&dev->tx_buf) > (TTY_BUF_SIZE-5))
      return 0;
  
  enqueue_circular_buffer(&dev->tx_buf, c);

  return 1;
}

static ssize_t local_tty_write(int fd, const void * buf, size_t count) {

  struct device_desc * dev = (fd == -1)?get_device(1):get_device_from_fd(fd);

  unsigned char * data = (unsigned char *)buf;

  emscripten_log(EM_LOG_CONSOLE, "local_tty_write: count=%d", count);

  if (count_circular_buffer(&dev->tx_buf) > (TTY_BUF_SIZE-count-5)) {

    if (dev->ops->flush)
      dev->ops->flush(fd);
  }

  for (int i = 0; i < count; ++i) {

    tty_write_char(dev, data[i]);
  }

  //emscripten_log(EM_LOG_CONSOLE, "local_tty_write: tx_buf count=%d", count_circular_buffer(&dev->tx_buf));

  if (count > 0) {

    dev->data_written = 1;
    
    start_timer(dev);
  }
  
  return count;
}

static int local_tty_ioctl(int fd, int op, unsigned char * buf, size_t len, pid_t pid, pid_t sid, pid_t pgid) {

  emscripten_log(EM_LOG_CONSOLE,"local_tty_ioctl: fd=%d op=%d", fd, op);
  
  switch(op) {

  case TIOCGWINSZ:
    
    memcpy(buf, &(get_device_from_fd(fd)->ws), sizeof(struct winsize));

    break;

  case TCGETS:

    //emscripten_log(EM_LOG_CONSOLE,"local_tty_ioctl: TCGETS");

    memcpy(buf, &(get_device_from_fd(fd)->ctrl), sizeof(struct termios));

    break;

  case TCSETS:
  case TCSETSW:
  case TCSETSF:

    //emscripten_log(EM_LOG_CONSOLE,"local_tty_ioctl: TCSETS");

    memcpy(&(get_device_from_fd(fd)->ctrl), buf, sizeof(struct termios));

    break;

  case TCFLSH:

    //emscripten_log(EM_LOG_CONSOLE,"local_tty_ioctl: TCFLSH");
    
    break;

  case TIOCGPGRP:

    //emscripten_log(EM_LOG_CONSOLE,"local_tty_ioctl: TIOCGPGRP %d", get_device_from_fd(fd)->fg_pgrp);

    if (get_device_from_fd(fd)->fg_pgrp == 0)
      return -1;

    memcpy(buf, &(get_device_from_fd(fd)->fg_pgrp), sizeof(int));
    
    break;

  case TIOCSPGRP:

    //emscripten_log(EM_LOG_CONSOLE,"local_tty_ioctl: TIOCSPGRP %d", *((int *)buf));

    memcpy(&(get_device_from_fd(fd)->fg_pgrp), buf, sizeof(int));

    break;

  case TIOCNOTTY:

    //emscripten_log(EM_LOG_CONSOLE,"local_tty_ioctl: TIOCNOTTY");

    break;

  case TIOCSCTTY:
    {
      int arg;

      memcpy(&arg, buf, sizeof(int));

      emscripten_log(EM_LOG_CONSOLE,"local_tty_ioctl: TIOCSCTTY (%d %d %d %d %d)", fd, get_device_from_fd(fd)->session, pid, sid, arg);

      if ( (pid == sid) && (get_device_from_fd(fd)->session == 0) && (!arg) ) {

	get_device_from_fd(fd)->session = sid;
	get_device_from_fd(fd)->fg_pgrp = pgid;
      }
      else if (arg) { // arg is non null so terminal can be stolen

	get_device_from_fd(fd)->session = sid;
	get_device_from_fd(fd)->fg_pgrp = pgid;
      }
    }
    
    break;

  default:
    break;
  }
  
  return 0;
}

static int local_tty_close(int fd) {

  return 0;
}

static int enqueue(struct device_desc * dev, int fd, void * buf, size_t count, struct message * reply_msg, ssize_t (*write)(int, const void *, size_t)) {

  unsigned char * data = (unsigned char *)buf;

  unsigned char echo_buf[1024];
  
  int j = 0;

  for (int i = 0; i < count; ++i) {

    if (data[i] == dev->ctrl.c_cc[VINTR]) { // Ctrl-C (if not changed)

      emscripten_log(EM_LOG_CONSOLE, "tty: enqueue -> SIGINT !!!");

      // Send SGINT to foreground process group
      
      reply_msg->msg_id = KILL;
      reply_msg->pid = 2; // PID of TTY driver
      reply_msg->_u.kill_msg.pid = dev->fg_pgrp | 0x20000000; // meaning process group id
      reply_msg->_u.kill_msg.sig = SIGINT;

      return 0;
    }
    else if (data[i] == dev->ctrl.c_cc[VEOF]) { // Ctrl-D (if not changed)

      return -1; // EOF
    }
    else if ( (data[i] == '\r') && (dev->ctrl.c_iflag & IGNCR) ) {

      //emscripten_log(EM_LOG_CONSOLE, "local_tty_enqueue: IGNCR");
      
      // do nothing
    }
    else if ( (data[i] == '\r') && (dev->ctrl.c_iflag & ICRNL) ) {

      //emscripten_log(EM_LOG_CONSOLE, "local_tty_enqueue: ICRNL");

      data[j] = '\n';
      ++j;
    }
    else if ( (data[i] == '\n') && (dev->ctrl.c_iflag & INLCR) ) {

      //emscripten_log(EM_LOG_CONSOLE, "local_tty_enqueue: INLCR");

      data[j] = '\r';
      ++j;
    }
    else {

      data[j] = data[i];
      ++j;
    }
  }

  emscripten_log(EM_LOG_CONSOLE, "enqueue: j=%d", j);

  for (int i = 0; i < j; ++i) {
    
    if (data[i] == dev->ctrl.c_cc[VERASE]) {

      if ( (dev->ctrl.c_lflag & (ICANON | ECHOE)) == (ICANON | ECHOE)) {
	
	// erase previous char (if any)

	char c;

	//if (del_char(dev) >= 0) {
	if (undo_enqueue_circular_buffer(&dev->rx_buf, &c) > 0) {

	  if ( (c == '\r') || (c == '\n') ) {

	    enqueue_circular_buffer(&dev->rx_buf, c); // undo
	  }
	  else {

	    write(fd, "\x1b[D\x1b[K", 6);
	  }
	}
      }
      else {

	// enqueue
	enqueue_circular_buffer(&dev->rx_buf, data[i]);
      }
    
    }
    else if (data[i] == dev->ctrl.c_cc[VWERASE]) {

      if ( (dev->ctrl.c_lflag & (ICANON | ECHOE)) == (ICANON | ECHOE)) {

	// erase previous word

	
      }
      else {

	// enqueue
	enqueue_circular_buffer(&dev->rx_buf, data[i]);
      }
    
    }
    else if (data[i] == dev->ctrl.c_cc[VKILL]) {

      if ( (dev->ctrl.c_lflag & (ICANON | ECHOK)) == (ICANON | ECHOK)) {

	// erase current line

	
      }
      else {

	// enqueue
	enqueue_circular_buffer(&dev->rx_buf, data[i]);
      }
    
    }
    else {

      if (dev->ctrl.c_lflag & ECHO) {

	if ( (dev->ctrl.c_lflag & ECHOCTL) &&
	     ( (data[i] == 0x7) || (data[i] == 0x8) ||
	       (data[i] == 0xB) || (data[i] == 0xC) ||
	       (data[i] == 0xE) || (data[i] == 0xF) ||
	       (data[i] == 0x18) || (data[i] == 0x1A) || (data[i] == 0x1B) ) ) {

	  char c = data[i] + 0x40;
	  
	  write(fd, "^", 1);
	  enqueue_circular_buffer(&dev->rx_buf, '^');
	  write(fd, &c, 1);
	  enqueue_circular_buffer(&dev->rx_buf, c);
	}
	else {

	  write(fd, data+i, 1);
	  enqueue_circular_buffer(&dev->rx_buf, data[i]);
	}
      }
      else {

	enqueue_circular_buffer(&dev->rx_buf, data[i]);
      }
      
    }
  }

  //emscripten_log(EM_LOG_CONSOLE, "local_tty_enqueue: j=%d %d", j, count_circular_buffer(&dev->rx_buf));

  if (j > 0) { // data has been enqueued

    if ( (dev->read_pending.fd >= 0) && (dev->read_pending.len > 0) ) { // Pending read
      
      emscripten_log(EM_LOG_CONSOLE, "enqueue: pending read %d", dev->read_pending.len);
      
      size_t len = 0;

      if (dev->ctrl.c_lflag & ICANON) {

	// Search EOL
	int i;

	if (find_eol_circular_buffer(&dev->rx_buf, &i) > 0) {

	  len = count_circular_buffer_index(&dev->rx_buf, i)+1;
	}
      }
      else {

	len = count_circular_buffer(&dev->rx_buf);
      }

      emscripten_log(EM_LOG_CONSOLE, "enqueue: pending read len=%d", len);

      if (len > 0) {

	reply_msg->msg_id = READ|0x80;
	reply_msg->pid = dev->read_pending.pid;
	reply_msg->_errno = 0;
	reply_msg->_u.io_msg.fd = dev->read_pending.fd;

	size_t sent_len = (len <= dev->read_pending.len)?len:dev->read_pending.len;
      
	reply_msg->_u.io_msg.len = sent_len;

	//emscripten_log(EM_LOG_CONSOLE, "(2) dev->read_pending.len=%d dev->start=%d len=%d sent_len=%d", dev->read_pending.len, dev->start, len, sent_len);

	read_circular_buffer(&dev->rx_buf, sent_len, (char *)reply_msg->_u.io_msg.buf);

	//emscripten_log(EM_LOG_CONSOLE, "local_tty_enqueue: after pending read sent_len=%d remaining=%d", sent_len, count_circular_buffer(&dev->rx_buf));

	return sent_len;
      }
    }
    else if (dev->read_select_pending.fd >= 0) {

      emscripten_log(EM_LOG_CONSOLE, "enqueue: pending read select");
      
      int i;

      if ( !(dev->ctrl.c_lflag & ICANON) || (find_eol_circular_buffer(&dev->rx_buf, &i) > 0) ) {

	reply_msg->msg_id = SELECT|0x80;
	reply_msg->pid = dev->read_select_pending.pid;
	reply_msg->_errno = 0;
	reply_msg->_u.select_msg.remote_fd = dev->read_select_pending.remote_fd;
	reply_msg->_u.select_msg.fd = dev->read_select_pending.fd;
	reply_msg->_u.select_msg.read_write = 0; // read
	reply_msg->_u.select_msg.once = 0;
      }
    }
  }
  
  return 0;
}

static ssize_t local_tty_enqueue(int fd, void * buf, size_t count, struct message * reply_msg) {

  struct device_desc * dev = (fd == -1)?get_device(1):get_device_from_fd(fd);

  emscripten_log(EM_LOG_CONSOLE, "local_tty_enqueue: count=%d %d", count, count_circular_buffer(&dev->rx_buf));

  int len = enqueue(dev, fd, buf, count, reply_msg, &local_tty_write);
  
  return len;
}

static void add_read_select_pending_request(pid_t pid, int remote_fd, int fd, struct sockaddr_un * sock_addr) {

  emscripten_log(EM_LOG_CONSOLE, "--> add_read_select_pending_request from pid=%d: remote_fd=%d fd=%d", pid, remote_fd, fd);

  struct device_desc * dev = get_device_from_fd(remote_fd);

  if (dev) {

    dev->read_select_pending.pid = pid;
    dev->read_select_pending.remote_fd = remote_fd;
    dev->read_select_pending.fd = fd;
    memcpy(&dev->read_select_pending.client_addr, sock_addr, sizeof(struct sockaddr_un));

    //emscripten_log(EM_LOG_CONSOLE, "add_read_select_pending_request: %s", dev->read_select_pending.client_addr.sun_path);
  }
}

static void del_read_select_pending_request(pid_t pid, int remote_fd, int fd, struct sockaddr_un * sock_addr) {

  struct device_desc * dev = get_device_from_fd(remote_fd);

  if (dev) {

    dev->read_select_pending.remote_fd = -1;
    dev->read_select_pending.fd = -1;
  }
}

static int local_tty_select(pid_t pid, int remote_fd, int fd, int read_write, int start_stop, int once, struct sockaddr_un * sock_addr) {

  //emscripten_log(EM_LOG_CONSOLE, "local_tty_select");

  struct device_desc * dev = get_device_from_fd(remote_fd);

  if (start_stop) { // start

    if (read_write) { // write

      if (count_circular_buffer(&dev->tx_buf) < (TTY_BUF_SIZE-16)) {
	
	return 1;
      }
    }
    else { // read
      
      if (count_circular_buffer(&dev->rx_buf) > 0) { // input buffer contains char

	return 1;
      }
      else if (!once) {

	add_read_select_pending_request(pid, remote_fd, fd, sock_addr);
      }
    }
  }
  else { // stop

    if (!read_write) { // read
      
      del_read_select_pending_request(pid, remote_fd, fd, sock_addr);
    }
  }
  
  return 0;
}

static struct device_ops local_tty_ops = {

  .open = local_tty_open,
  .read = local_tty_read,
  .write = local_tty_write,
  .ioctl = local_tty_ioctl,
  .close = local_tty_close,
  .enqueue = local_tty_enqueue,
  .select = local_tty_select,
  .flush = local_tty_flush,
};

static int pts_open(const char * pathname, int flags, mode_t mode, unsigned short m, pid_t pid, pid_t sid) {

  emscripten_log(EM_LOG_CONSOLE, "pts_open");

  return local_tty_open(pathname, flags, mode, m, pid, sid);
}

static ssize_t pts_read(int fd, void * buf, size_t len) {

  emscripten_log(EM_LOG_CONSOLE, "pts_read: %d bytes", len);
  
  return local_tty_read(fd, buf, len);
}

static int notify_ptm(struct device_desc * pts_dev) {

  struct device_desc * ptm_dev = get_device_from_fd(pts_dev->ptm_fd);
  
  size_t len = count_circular_buffer(&pts_dev->tx_buf);

  emscripten_log(EM_LOG_CONSOLE, "notify_ptm: len=%d", len);

  if (len == 0)
    return 0;

  if ( (ptm_dev->read_pending.fd >= 0) && (ptm_dev->read_pending.len > 0) ) { // Pending read

    size_t sent_len = (len <= ptm_dev->read_pending.len)?len:ptm_dev->read_pending.len;

    int buf_size = 20+sent_len; // message is 5 * 4 bytes + buffer

    unsigned char * reply_buf = (unsigned char * )malloc(buf_size);
    struct message * reply_msg = (struct message *)&reply_buf[0];

    reply_msg->msg_id = READ|0x80;
    reply_msg->pid = ptm_dev->read_pending.pid;
    reply_msg->_errno = 0;
    reply_msg->_u.io_msg.fd = ptm_dev->read_pending.fd;
    reply_msg->_u.io_msg.len = sent_len;

    read_circular_buffer(&pts_dev->tx_buf, sent_len, (char *)reply_msg->_u.io_msg.buf);
    
    sendto(sock, reply_buf, buf_size, 0, (struct sockaddr *) &ptm_dev->read_pending.client_addr, sizeof(ptm_dev->read_pending.client_addr));

    free(reply_buf);

    ptm_dev->read_pending.len = 0; // unset read pending
    ptm_dev->read_pending.fd = -1;

    return 1;
  }
  else if (ptm_dev->read_select_pending.fd >= 0) {

    unsigned char reply_buf[256];
    struct message * reply_msg = (struct message *)&reply_buf[0];

    int i;

    reply_msg->msg_id = SELECT|0x80;
    reply_msg->pid = ptm_dev->read_select_pending.pid;
    reply_msg->_errno = 0;
    reply_msg->_u.select_msg.remote_fd = ptm_dev->read_select_pending.remote_fd;
    reply_msg->_u.select_msg.fd = ptm_dev->read_select_pending.fd;
    reply_msg->_u.select_msg.read_write = 0; // read
    reply_msg->_u.select_msg.once = 0;

    sendto(sock, reply_buf, 1256, 0, (struct sockaddr *) &ptm_dev->read_select_pending.client_addr, sizeof(ptm_dev->read_select_pending.client_addr));
    
    ptm_dev->read_select_pending.fd = -1; // unset read select pending
    ptm_dev->read_select_pending.remote_fd = -1;

    return 1;
  }

  return 0;
}

static ssize_t pts_write(int fd, const void * buf, size_t count) {
  
  emscripten_log(EM_LOG_CONSOLE, "pts_write: fd=%d %d bytes", fd, count);

  struct device_desc * dev = (fd == -1)?get_device(1):get_device_from_fd(fd);

  struct device_desc * ptm_dev;
  int ptm_fd;

  if (dev->ptm_fd < 0) { // Not a pts but a ptm, case when ptmx_write calls enqueue that calls pts_write

    dev = &devices[clients[fd].pts_dev_minor]; // dev is now pts dev
    ptm_dev = get_device_from_fd(fd);
    ptm_fd = fd;
  }
  else {

    ptm_dev = get_device_from_fd(devices[clients[fd].minor].ptm_fd);
    ptm_fd = devices[clients[fd].minor].ptm_fd;
  }

  unsigned char * data = (unsigned char *)buf;
  
  for (int i = 0; i < count; ++i) {
    
    if (!tty_write_char(dev, data[i])) {

      if (i > 0)
	notify_ptm(dev); // pts dev

      return i;
    }
  }

  size_t len = count_circular_buffer(&dev->tx_buf);

  if (len > 0) {

    notify_ptm(dev); // pts dev
  }
  
  return count;
}

static int pts_ioctl(int fd, int op, unsigned char * buf, size_t len, pid_t pid, pid_t sid, pid_t pgid) {

  emscripten_log(EM_LOG_CONSOLE, "pts_ioctl");

  return local_tty_ioctl(fd, op, buf, len, pid, sid, pgid);
}

static int pts_select(pid_t pid, int remote_fd, int fd, int read_write, int start_stop, int once, struct sockaddr_un * sock_addr) {

  emscripten_log(EM_LOG_CONSOLE, "pts_select");

  return local_tty_select(pid, remote_fd, fd, read_write, start_stop, once, sock_addr);
}

static int pts_flush(int fd) {

  emscripten_log(EM_LOG_CONSOLE, "pts_flush: fd=%d", fd);
  
  struct device_desc * dev = get_device_from_fd(fd);
  
  return notify_ptm(dev);
}

static int pts_close(int fd) {

  emscripten_log(EM_LOG_CONSOLE, "!!! pts_close: fd=%d", fd);

  del_pts_client(fd);

  return 0;
}

static struct device_ops pts_ops = {

  .open = pts_open,
  .read = pts_read,
  .write = pts_write,
  .ioctl = pts_ioctl,
  .close = pts_close,
  .enqueue = NULL,
  .select = pts_select,
  .flush = pts_flush,
};

static int ptmx_open(const char * pathname, int flags, mode_t mode, unsigned short m, pid_t pid, pid_t sid) {
  
  ++last_fd;
  
  add_client(last_fd, pid, m, flags, mode);

  emscripten_log(EM_LOG_CONSOLE, "ptmx_open: fd=%d", last_fd);
  
  minor += 1;
  
  register_device(minor, &pts_ops, PTS);

  devices[minor].ptm_fd = last_fd; // pts dev stores fd of ptm client
  
  clients[last_fd].pts_dev_minor = minor; // ptm client stores minor of pts dev

  emscripten_log(EM_LOG_CONSOLE, "ptmx_open: create PTM fd=%d & PTS minor=%d", devices[minor].ptm_fd, clients[last_fd].pts_dev_minor);
  
  char buf[1256];
  struct message * msg = (struct message *)&buf[0];
      
  msg->msg_id = REGISTER_DEVICE;
  
  msg->_u.dev_msg.dev_type = CHR_DEV;
  msg->_u.dev_msg.major = major;
  msg->_u.dev_msg.minor = minor;
  
  memset(msg->_u.dev_msg.dev_name, 0, sizeof(msg->_u.dev_msg.dev_name));
  sprintf((char *)&msg->_u.dev_msg.dev_name[0], "pts/%d", msg->_u.dev_msg.minor);
  
  sendto(sock, buf, 256, 0, (struct sockaddr *) &resmgr_addr, sizeof(resmgr_addr));
  
  return last_fd;
}

static ssize_t ptmx_read(int fd, void * buf, size_t len) {
  
  struct device_desc * ptm_dev = (fd == -1)?get_device(1):get_device_from_fd(fd);
  
  struct device_desc * pts_dev = &devices[clients[fd].pts_dev_minor];

  emscripten_log(EM_LOG_CONSOLE, "ptmx_read: len=%d", len);

  if (pts_dev->state == 1) { // device open
  
    size_t len2 = count_circular_buffer(&pts_dev->tx_buf);
  
    size_t read_len = (len2 <= len)?len2:len;

    emscripten_log(EM_LOG_CONSOLE, "ptmx_read: read_len=%d", read_len);
  
    if (read_len > 0) {
    
      read_circular_buffer(&pts_dev->tx_buf, read_len, buf);
      
      if ( (pts_dev->write_pending.fd >= 0) && (count_circular_buffer(&pts_dev->tx_buf) < (TTY_BUF_SIZE-1024)) ) { // Pending write and enough space for writing

	int write_len = (pts_dev->write_pending.len<(TTY_BUF_SIZE-count_circular_buffer(&pts_dev->tx_buf)-5))?pts_dev->write_pending.len:(TTY_BUF_SIZE-count_circular_buffer(&pts_dev->tx_buf)-5);

	int i = 0;
	
	for (; i < write_len; ++i) {
    
	  if (!tty_write_char(pts_dev, pts_dev->write_pending.buf[pts_dev->write_pending.offset+i])) {

	    break;
	  }
	}

	pts_dev->write_pending.len -= i;

	if (pts_dev->write_pending.len > 0) {

	  pts_dev->write_pending.offset += i;
	}
	else {

	  unsigned char reply_buf[256];
	  struct message * reply_msg = (struct message *)&reply_buf[0];

	  reply_msg->msg_id = WRITE|0x80;
	  reply_msg->pid = pts_dev->write_pending.pid;
	  reply_msg->_errno = 0;
	  reply_msg->_u.io_msg.fd = pts_dev->write_pending.fd;
	  reply_msg->_u.io_msg.len = pts_dev->write_pending.orig_len;

	  sendto(sock, reply_buf, 256, 0, (struct sockaddr *) &pts_dev->write_pending.client_addr, sizeof(pts_dev->write_pending.client_addr));

	  pts_dev->write_pending.len = 0; // unset write pending
	  pts_dev->write_pending.fd = -1;

	  free(pts_dev->write_pending.buf);
	}
      }
    
      return read_len;
    }
    
  }
  
  return 0;
}

static ssize_t ptmx_write(int fd, const void * buf, size_t count) {

  //struct device_desc * dev = (fd == -1)?get_device(1):get_device_from_fd(fd);

  unsigned char * data = (unsigned char *)buf;

  emscripten_log(EM_LOG_CONSOLE, "ptmx_write: fd=%d count=%d", fd, count);

  struct device_desc * pts_dev = &devices[clients[fd].pts_dev_minor];

  if (pts_dev->state == 0)  // closed
    return 0;
  
  unsigned char reply_buf[1256];
  struct message * reply_msg = (struct message *)&reply_buf[0];

  reply_msg->msg_id = 0;

  int len = enqueue(pts_dev, fd, buf, count, reply_msg, &pts_write);

  if (len == -1) { // EOF

     if ( (pts_dev->read_pending.fd >= 0) && (pts_dev->read_pending.len > 0) ) { // Pending read

	reply_msg->msg_id = READ|0x80;
	reply_msg->pid = pts_dev->read_pending.pid;
	reply_msg->_errno = 0;
	reply_msg->_u.io_msg.fd = pts_dev->read_pending.fd;
	reply_msg->_u.io_msg.len = 0;

	sendto(sock, reply_buf, 256, 0, (struct sockaddr *) &pts_dev->read_pending.client_addr, sizeof(pts_dev->read_pending.client_addr));

	pts_dev->read_pending.len = 0; // unset read pending
	pts_dev->read_pending.fd = -1;
     }
     else if (pts_dev->read_select_pending.fd >= 0) {

	reply_msg->msg_id = SELECT|0x80;
	reply_msg->pid = pts_dev->read_select_pending.pid;
	reply_msg->_errno = 0;
	reply_msg->_u.select_msg.remote_fd = pts_dev->read_select_pending.remote_fd;
	reply_msg->_u.select_msg.fd = pts_dev->read_select_pending.fd;
	reply_msg->_u.select_msg.read_write = 0;
	reply_msg->_u.select_msg.once = 0;
	
	sendto(sock, reply_buf, 256, 0, (struct sockaddr *) &pts_dev->read_select_pending.client_addr, sizeof(pts_dev->read_select_pending.client_addr));
	
	pts_dev->read_select_pending.fd = -1; // unset read select pending
	pts_dev->read_select_pending.remote_fd = -1;
     }
  }
  else if (reply_msg->msg_id == (READ|0x80)) {
    
    emscripten_log(EM_LOG_CONSOLE, "ptmx_write: send %d bytes to %s", len, pts_dev->read_pending.client_addr.sun_path);
    
    sendto(sock, reply_buf, 1256, 0, (struct sockaddr *) &pts_dev->read_pending.client_addr, sizeof(pts_dev->read_pending.client_addr));
    
    pts_dev->read_pending.len = 0; // unset read pending
    pts_dev->read_pending.fd = -1;
  }
  else if (reply_msg->msg_id == (SELECT|0x80)) {
    
    sendto(sock, reply_buf, 256, 0, (struct sockaddr *) &pts_dev->read_select_pending.client_addr, sizeof(pts_dev->read_select_pending.client_addr));

    pts_dev->read_select_pending.fd = -1; // unset read select pending
    pts_dev->read_select_pending.remote_fd = -1;
  }
  else if (reply_msg->msg_id == KILL) {
    
    sendto(sock, reply_buf, 256, 0, (struct sockaddr *) &resmgr_addr, sizeof(resmgr_addr));
  }

  return count;
}

static int ptmx_ioctl(int fd, int op, unsigned char * buf, size_t len, pid_t pid, pid_t sid, pid_t pgid) {

  emscripten_log(EM_LOG_CONSOLE,"ptmx_ioctl: fd=%d op=%d", fd, op);

  switch (op) {

  case TIOCGPTN:
    {

      int ptn = clients[fd].pts_dev_minor;

      memcpy(buf, &ptn, sizeof(int));

      break;
    }

   case TIOCSPTLCK:
    {

      break;
    }
    
  case TIOCSWINSZ:
    {

      memcpy(&(devices[clients[fd].pts_dev_minor].ws), buf, sizeof(struct winsize));
      emscripten_log(EM_LOG_CONSOLE,"ptmx_ioctl: TIOCSWINSZ row=%d col=%d", devices[clients[fd].pts_dev_minor].ws.ws_row, devices[clients[fd].pts_dev_minor].ws.ws_col);
      
      break;
    }
    
  default:

    return -1;
    break;
  }
  
  return 0;
}

static int ptmx_close(int fd) {

  emscripten_log(EM_LOG_CONSOLE, "!!! ptmx_close: fd=%d", fd);

  //TOTEST
  //return 0;

  del_ptmx_client(fd);
  
  return 0;
}

static int ptmx_select(pid_t pid, int remote_fd, int fd, int read_write, int start_stop, int once, struct sockaddr_un * sock_addr) {

  struct device_desc * dev = get_device_from_fd(remote_fd);

  struct device_desc * pts_dev = &devices[clients[remote_fd].pts_dev_minor];

  emscripten_log(EM_LOG_CONSOLE, "!!! ptmx_select: fd=%d rw=%d start=%d %x %d", fd, read_write, start_stop, pts_dev, pts_dev->state);

  if (start_stop) { // start

    if (pts_dev->state == 0) { // closed

      emscripten_log(EM_LOG_CONSOLE, "!!! ptmx_select: pts dev CLOSED");

      return 2; // POLLHUP
    }
    else if (read_write) { // write

      // TOTO
    }
    else { // read
      
      if (count_circular_buffer(&pts_dev->tx_buf) > 0) { // input buffer contains char
	
	  emscripten_log(EM_LOG_CONSOLE, "ptmx_select: %d bytes in tx queue", count_circular_buffer(&pts_dev->tx_buf));
	
	  return 1;
      }
      else if (!once) {

	emscripten_log(EM_LOG_CONSOLE, "ptmx_select: add pending request: remote_fd=%d", remote_fd);

	add_read_select_pending_request(pid, remote_fd, fd, sock_addr);
      }
     
    }
  }
  else { // stop

    if (!read_write) { // read
      
      del_read_select_pending_request(pid, remote_fd, fd, sock_addr);
    }
  }
  
  return 0;
}

static struct device_ops ptmx_ops = {

  .open = ptmx_open,
  .read = ptmx_read,
  .write = ptmx_write,
  .ioctl = ptmx_ioctl,
  .close = ptmx_close,
  .enqueue = NULL,
  .select = ptmx_select,
  .flush = NULL,
};

static void add_read_pending_request(pid_t pid, int fd, size_t len, struct sockaddr_un * sock_addr) {

  emscripten_log(EM_LOG_CONSOLE, "--> add_read_pending_request from pid=%d: fd=%d len=%d", pid, fd, len);

  struct device_desc * dev = get_device_from_fd(fd);

  dev->read_pending.pid = pid;
  dev->read_pending.fd = fd;
  dev->read_pending.len = len;
  memcpy(&dev->read_pending.client_addr, sock_addr, sizeof(struct sockaddr_un));
}

static void add_write_pending_request(pid_t pid, int fd, size_t len, size_t orig_len, char * buf, struct sockaddr_un * sock_addr) {

  emscripten_log(EM_LOG_CONSOLE, "--> add_write_pending_request from pid=%d: fd=%d len=%d", pid, fd, len);

  struct device_desc * dev = get_device_from_fd(fd);
  
  dev->write_pending.pid = pid;
  dev->write_pending.fd = fd;
  dev->write_pending.len = len;
  dev->write_pending.orig_len = orig_len;
  dev->write_pending.buf = (char *)malloc(len);
  dev->write_pending.offset = 0;
  memcpy(dev->write_pending.buf, buf, len);
  
  memcpy(&dev->write_pending.client_addr, sock_addr, sizeof(struct sockaddr_un));
}

int main() {

  struct sockaddr_un local_addr, remote_addr, ioctl_addr;
  int bytes_rec;
  socklen_t len;
  char buf[1256];
  char ioctl_buf[1256];
  
  // Use console.log as tty is not yet started
  emscripten_log(EM_LOG_CONSOLE, "Starting " TTY_VERSION "...");
  
  /* Create the server local socket */
  sock = socket (AF_UNIX, SOCK_DGRAM, 0);
  if (sock < 0) {
    return -1;
  }

  /* Bind server socket to TTY_PATH */
  memset(&local_addr, 0, sizeof(local_addr));
  local_addr.sun_family = AF_UNIX;
  strcpy(local_addr.sun_path, TTY_PATH);
  
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
  
  strcpy((char *)&msg->_u.dev_msg.dev_name[0], "tty");
  
  sendto(sock, buf, 256, 0, (struct sockaddr *) &resmgr_addr, sizeof(resmgr_addr));

  struct device_desc * dev1 = get_device(1);

  while (1) {

    fd_set rfds;
    int retval;

    FD_ZERO(&rfds);
    FD_SET(sock, &rfds);

    int timer_fd_max = 0;
    
    for (int i=0; i < NB_TTY_MAX; ++i) {

      if (devices[i].state && devices[i].timer_started) {
	
	FD_SET(devices[i].timer, &rfds);

	if (devices[i].timer > timer_fd_max)
	  timer_fd_max = devices[i].timer;
      }
    }
    
    retval = select(((sock > timer_fd_max)?sock:timer_fd_max)+1, &rfds, NULL, NULL, NULL);
    
    if (retval < 0)
      continue;

    if (!FD_ISSET(sock, &rfds) ) { // A timer has elapsed

      for (int i=0; i < NB_TTY_MAX; ++i) {

	if (devices[i].state && devices[i].timer_started) {
	
	  if (FD_ISSET(devices[i].timer, &rfds)) {

	    uint64_t count; // Be careful, shall read 8 bytes otherwise read fails

	    read(devices[i].timer, &count, sizeof(count));
	    
	    int j = 0;

	    // Find a client of the pts dev for passing to to flush
	    // Whatever the client, only the pts dev is needed
	    
	    for (j=0; j < NB_CLIENT_MAX; ++j) {

	      if (clients[j].minor == i) {
		
		if (!devices[i].ops->flush(j)) {

		  stop_timer(&devices[i]);
		}
		
		break;
	      }
	    }

	    break;
	  }
	}
      }
     
      continue;
    }
    
    bytes_rec = recvfrom(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, &len);

    if (bytes_rec <= 0) {

      continue;
    }

    emscripten_log(EM_LOG_CONSOLE, "tty: recfrom %s: %d bytes (%d)", remote_addr.sun_path, bytes_rec, msg->msg_id);

    if (msg->msg_id == (REGISTER_DRIVER|0x80)) {

      if (msg->_errno)
	continue;

      major = msg->_u.dev_msg.major;

      emscripten_log(EM_LOG_CONSOLE, "REGISTER_DRIVER successful: major=%d", major);
      // Probe terminal
      probe_terminal();
    }
    else if (msg->msg_id == (PROBE_TTY|0x80)) {

      emscripten_log(EM_LOG_CONSOLE, "PROBE_TTY successful: rows=%d cols=%d",msg->_u.probe_tty_msg.rows, msg->_u.probe_tty_msg.cols);

      minor += 1;
      
      register_device(minor, &local_tty_ops, TTY);

      get_device(1)->ws.ws_row = msg->_u.probe_tty_msg.rows;
      get_device(1)->ws.ws_col = msg->_u.probe_tty_msg.cols;
      
      local_tty_write(-1, TTY_VERSION, strlen(TTY_VERSION));

      // Terminal probed: minor = 1
      msg->msg_id = REGISTER_DEVICE;

      msg->_u.dev_msg.dev_type = CHR_DEV;
      msg->_u.dev_msg.major = major;
      msg->_u.dev_msg.minor = minor;

      memset(msg->_u.dev_msg.dev_name, 0, sizeof(msg->_u.dev_msg.dev_name));
      sprintf((char *)&msg->_u.dev_msg.dev_name[0], "tty%d", msg->_u.dev_msg.minor);
  
      sendto(sock, buf, 256, 0, (struct sockaddr *) &resmgr_addr, sizeof(resmgr_addr));
    }
    else if (msg->msg_id == (READ_TTY)) {

      unsigned char reply_buf[1256];
      struct message * reply_msg = (struct message *)&reply_buf[0];

      //emscripten_log(EM_LOG_CONSOLE, "tty: READ_TTY");
      
      reply_msg->msg_id = 0;

      get_device(1)->ops->enqueue(-1, msg->_u.read_tty_msg.buf, msg->_u.read_tty_msg.len, reply_msg);

      if (reply_msg->msg_id == (READ|0x80)) {

	struct device_desc * dev = get_device(1);

	dev->read_pending.len = 0; // unset read pending
	dev->read_pending.fd = -1;

	sendto(sock, reply_buf, 1256, 0, (struct sockaddr *) &dev->read_pending.client_addr, sizeof(dev->read_pending.client_addr));
      }
      else if (reply_msg->msg_id == (SELECT|0x80)) {

	struct device_desc * dev = get_device(1);

	//emscripten_log(EM_LOG_CONSOLE, "Reply to select: %s", dev->read_select_pending.client_addr.sun_path);

	dev->read_select_pending.fd = -1; // unset read select pending
	dev->read_select_pending.remote_fd = -1;

	sendto(sock, reply_buf, 256, 0, (struct sockaddr *) &dev->read_select_pending.client_addr, sizeof(dev->read_select_pending.client_addr));
      }
      
    }
    else if (msg->msg_id == (REGISTER_DEVICE|0x80)) {

      if (msg->_errno)
	continue;

      //emscripten_log(EM_LOG_CONSOLE, "REGISTER_DEVICE successful: %d,%d,%d", msg->_u.dev_msg.dev_type, msg->_u.dev_msg.major, msg->_u.dev_msg.minor);

      if (msg->_u.dev_msg.minor == 1) { // first tty has been registered

	minor += 1;
      
	register_device(minor, &ptmx_ops, PTM);
      
	msg->msg_id = REGISTER_DEVICE;

	msg->_u.dev_msg.dev_type = CHR_DEV;
	msg->_u.dev_msg.major = major;
	msg->_u.dev_msg.minor = minor;

	strcpy(msg->_u.dev_msg.dev_name, "ptmx");
  
	sendto(sock, buf, 256, 0, (struct sockaddr *) &resmgr_addr, sizeof(resmgr_addr));
      }
    }
    else if (msg->msg_id == OPEN) {

      emscripten_log(EM_LOG_CONSOLE, "tty: OPEN from %d (%d), %d", msg->pid, msg->_u.open_msg.sid, msg->_u.open_msg.minor);

      if (msg->_u.open_msg.minor == 0) { // /dev/tty

	emscripten_log(EM_LOG_CONSOLE, "tty: OPEN /dev/tty from session = %d", msg->_u.open_msg.sid);

	unsigned short min;
	
	struct device_desc * dev = get_device_from_session(msg->_u.open_msg.sid, &min);
	
	if (!dev) {

	  //emscripten_log(EM_LOG_CONSOLE, "tty: OPEN /dev/tty from session %d -> NONE", msg->_u.open_msg.sid);

	  msg->msg_id |= 0x80;

	  msg->_errno = ENOENT;
	    
	  sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
	  continue;
	}

	emscripten_log(EM_LOG_CONSOLE, "tty: OPEN /dev/tty from session -> min=%d", min);

	msg->_u.open_msg.minor = min;
      }

      int remote_fd = get_device(msg->_u.open_msg.minor)->ops->open("", msg->_u.open_msg.flags, msg->_u.open_msg.mode, msg->_u.open_msg.minor, msg->pid, msg->_u.open_msg.sid);

      //emscripten_log(EM_LOG_CONSOLE, "tty: OPEN -> %d", remote_fd);

      msg->_u.open_msg.remote_fd = remote_fd;
      
      if ( (get_device(msg->_u.open_msg.minor)->type != PTM) && (!(msg->_u.open_msg.flags & O_NOCTTY)) ) {

	if ( (get_device(msg->_u.open_msg.minor)->session == 0) && (msg->pid ==  msg->_u.open_msg.sid) ) {

	  emscripten_log(EM_LOG_CONSOLE, "!!!! tty: set controlling tty of session %d (min=%d)", msg->_u.open_msg.sid, msg->_u.open_msg.minor);
	  
	  // tty is not yet controlled so it is now controlling the sid session
	  get_device(msg->_u.open_msg.minor)->session = msg->_u.open_msg.sid;
	}
	
      }

      msg->msg_id |= 0x80;
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));     
      
    }
    else if (msg->msg_id == READ) {

      emscripten_log(EM_LOG_CONSOLE, "tty: READ from %d: %d", msg->pid, msg->_u.io_msg.len);

      struct device_desc * dev = get_device_from_fd(msg->_u.io_msg.fd);

      int buf_size = 20+msg->_u.io_msg.len;

      unsigned char * reply_buf = (unsigned char * )malloc(buf_size);
      struct message * reply_msg = (struct message *)&reply_buf[0];

      int count = dev->ops->read(msg->_u.io_msg.fd, reply_msg->_u.io_msg.buf, msg->_u.io_msg.len);
      
      if (count > 0) {
	
	reply_msg->msg_id = READ|0x80;
	reply_msg->pid = msg->pid;
	reply_msg->_errno = 0;
	reply_msg->_u.io_msg.fd = msg->_u.io_msg.fd;
	reply_msg->_u.io_msg.len = count;
	
	sendto(sock, reply_buf, buf_size, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      }
      else if (msg->_u.io_msg.len == 0) {
	
	msg->msg_id |= 0x80;
	msg->_errno = 0;
	sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      }
      else if (clients[msg->_u.io_msg.fd].flags & O_NONBLOCK) {

	msg->msg_id |= 0x80;
	msg->_errno = EAGAIN;
	sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      }
      else {

	add_read_pending_request(msg->pid, msg->_u.io_msg.fd, msg->_u.io_msg.len, &remote_addr);
      }

      free(reply_buf);
    }
    else if (msg->msg_id == WRITE) {
      
      emscripten_log(EM_LOG_CONSOLE, "tty: WRITE from %d, length=%d", msg->pid, msg->_u.io_msg.len);

      char * buf2 = msg->_u.io_msg.buf;

      if (msg->_u.io_msg.len > (bytes_rec - 20)) { // message is 5 * 4 bytes + buffer

	emscripten_log(EM_LOG_CONSOLE, "tty: WRITE need to read %d remaining bytes (%d read)", msg->_u.io_msg.len - (bytes_rec - 20), bytes_rec - 20);

	buf2 =(char *)malloc(msg->_u.io_msg.len);

	memcpy(buf2, msg->_u.io_msg.buf, bytes_rec - 20);

	int bytes_rec2 = recvfrom(sock, buf2+bytes_rec - 20, msg->_u.io_msg.len - (bytes_rec - 20), 0, (struct sockaddr *) &remote_addr, &len);

	emscripten_log(EM_LOG_CONSOLE, "tty: WRITE %d read", bytes_rec2);
      }

      struct device_desc * dev;

      int nb_bytes_written = 0;

      if (msg->_u.io_msg.fd == -1) {

	dev = get_device(1);

        nb_bytes_written = dev->ops->write(-1, buf2, msg->_u.io_msg.len);
      }
      else {
      
	dev = get_device_from_fd(msg->_u.io_msg.fd);

	nb_bytes_written = dev->ops->write(msg->_u.io_msg.fd, buf2, msg->_u.io_msg.len);	
      }

      if (msg->_u.io_msg.len > 0) {

	dev->data_written = 1;
      }

      if (nb_bytes_written == msg->_u.io_msg.len) {

	msg->msg_id |= 0x80;
	msg->_errno = 0;
	sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      }
      else {

	add_write_pending_request(msg->pid, msg->_u.io_msg.fd, msg->_u.io_msg.len-nb_bytes_written, msg->_u.io_msg.len, buf2+nb_bytes_written, &remote_addr);
      }

      if (buf2 != msg->_u.io_msg.buf) {

	free(buf2);
      }
      
    }
    else if (msg->msg_id == SEEK) {

      //emscripten_log(EM_LOG_CONSOLE, "tty: SEEK from %d", msg->pid);

      msg->msg_id |= 0x80;
      msg->_errno = ESPIPE;
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == IOCTL) {

      emscripten_log(EM_LOG_CONSOLE, "tty: IOCTL from %d: %d (fd=%d)", msg->pid, msg->_u.ioctl_msg.op, msg->_u.ioctl_msg.fd);
      
      if (msg->_u.ioctl_msg.op == TIOCSCTTY) {

	// Ask sid to resmsgr

	// Store request and addr
	memcpy(ioctl_buf, buf, 1256);
	memcpy(&ioctl_addr, &remote_addr, sizeof(remote_addr));

	msg->msg_id = GETSID;
	msg->_u.getsid_msg.pid = 0;

	sendto(sock, buf, 256, 0, (struct sockaddr *) &resmgr_addr, sizeof(resmgr_addr));	
      }
      else {

	msg->_errno = get_device_from_fd(msg->_u.ioctl_msg.fd)->ops->ioctl(msg->_u.ioctl_msg.fd, msg->_u.ioctl_msg.op, msg->_u.ioctl_msg.buf, msg->_u.ioctl_msg.len, msg->pid, 0, 0);
      
	msg->msg_id |= 0x80;
	sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      }
    }
    else if (msg->msg_id == (GETSID|0x80)) {

      //emscripten_log(EM_LOG_CONSOLE, "tty: return from GETSID %d %d", msg->pid, msg->_u.getsid_msg.sid);

      struct message * ioctl_msg = (struct message *)&ioctl_buf[0];

      ioctl_msg->_errno = get_device_from_fd(ioctl_msg->_u.ioctl_msg.fd)->ops->ioctl(ioctl_msg->_u.ioctl_msg.fd, ioctl_msg->_u.ioctl_msg.op, ioctl_msg->_u.ioctl_msg.buf, ioctl_msg->_u.ioctl_msg.len, msg->pid, msg->_u.getsid_msg.sid, msg->_u.getsid_msg.pgid);
      
      ioctl_msg->msg_id |= 0x80;
      sendto(sock, ioctl_buf, 256, 0, (struct sockaddr *) &ioctl_addr, sizeof(ioctl_addr));
      
    }
    else if (msg->msg_id == CLOSE) {

      //emscripten_log(EM_LOG_CONSOLE, "tty: CLOSE from %d, %d", msg->pid, msg->_u.close_msg.fd);

      msg->_errno = get_device_from_fd(msg->_u.close_msg.fd)->ops->close(msg->_u.close_msg.fd);

      // very temporary
      clients[msg->_u.close_msg.fd].pid = -1;

      msg->msg_id |= 0x80;
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      
    }
    else if (msg->msg_id == STAT) {
      
      //emscripten_log(EM_LOG_CONSOLE, "tty: STAT from %d: %s", msg->pid, msg->_u.stat_msg.pathname_or_buf);

      char * tty = strrchr(msg->_u.stat_msg.pathname_or_buf, '/')+1;

      if (strncmp(tty, "tty", 3) == 0) {

	int min = atoi(tty+3);
	
	//emscripten_log(EM_LOG_CONSOLE, "tty: min=%d", min);

	struct stat stat_buf;

	stat_buf.st_dev = makedev(major, min);
	stat_buf.st_ino = (ino_t)&devices[min];

	//emscripten_log(EM_LOG_CONSOLE, "tty: STAT -> %d %lld", stat_buf.st_dev, stat_buf.st_ino);

	msg->_u.stat_msg.len = sizeof(struct stat);
	memcpy(msg->_u.stat_msg.pathname_or_buf, &stat_buf, sizeof(struct stat));

	msg->_errno = 0;
      }
      else {

	msg->_errno = ENOENT;
      }

      msg->msg_id |= 0x80;
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

    }
    else if (msg->msg_id == LSTAT) {
      
      //emscripten_log(EM_LOG_CONSOLE, "tty: LSTAT from %d: %s", msg->pid, msg->_u.stat_msg.pathname_or_buf);

      char * tty = strrchr(msg->_u.stat_msg.pathname_or_buf, '/')+1;

      if (strncmp(tty, "tty", 3) == 0) {

	int min = atoi(tty+3);
	
	//emscripten_log(EM_LOG_CONSOLE, "tty: min=%d", min);

	struct stat stat_buf;

	stat_buf.st_dev = makedev(major, min);
	stat_buf.st_ino = (ino_t)&devices[min];
	stat_buf.st_mode = S_IFCHR;

	//emscripten_log(EM_LOG_CONSOLE, "tty: LSTAT -> %d %lld", stat_buf.st_dev, stat_buf.st_ino);
	
	msg->_u.stat_msg.len = sizeof(struct stat);
	memcpy(msg->_u.stat_msg.pathname_or_buf, &stat_buf, sizeof(struct stat));

	msg->_errno = 0;
      }
      else {

	msg->_errno = ENOENT;
      }

      msg->msg_id |= 0x80;
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

    }
    else if (msg->msg_id == FSTAT) {
      
      //emscripten_log(EM_LOG_CONSOLE, "tty: FSTAT from %d: %d -> minor=%d", msg->pid, msg->_u.fstat_msg.fd, clients[msg->_u.fstat_msg.fd].minor);

      struct stat stat_buf;

      int min = clients[msg->_u.fstat_msg.fd].minor;

      stat_buf.st_dev = makedev(major, min);
      stat_buf.st_ino = (ino_t)&devices[min];
      stat_buf.st_mode = S_IFCHR;

      //emscripten_log(EM_LOG_CONSOLE, "tty: FSTAT -> %d %lld", stat_buf.st_dev, stat_buf.st_ino);

      msg->_u.fstat_msg.len = sizeof(struct stat);
      memcpy(msg->_u.fstat_msg.buf, &stat_buf, sizeof(struct stat));

      msg->msg_id |= 0x80;

      msg->_errno = 0;
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

    }
    else if (msg->msg_id == SELECT) {
      
      emscripten_log(EM_LOG_CONSOLE, "tty: SELECT from %d: %d %d %d %d (%x) once=%d", msg->pid, msg->_u.select_msg.fd, msg->_u.select_msg.remote_fd, msg->_u.select_msg.read_write, msg->_u.select_msg.start_stop, get_device_from_fd(msg->_u.select_msg.remote_fd)->ops->select, msg->_u.select_msg.once);

      int ret = get_device_from_fd(msg->_u.select_msg.remote_fd)->ops->select(msg->pid, msg->_u.select_msg.remote_fd, msg->_u.select_msg.fd, msg->_u.select_msg.read_write, msg->_u.select_msg.start_stop, msg->_u.select_msg.once, &remote_addr);

      if (ret > 0) {

	 msg->msg_id |= 0x80;

	 msg->_errno = 0;
	 
	 if (ret == 2) {
	   msg->_u.select_msg.once = 2; // pollhup
	 }
	 else {
	   msg->_u.select_msg.once = 0;
	 }

	 emscripten_log(EM_LOG_CONSOLE, "tty: SELECT -> once=%d", msg->_u.select_msg.once);
	 
	 sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      }
    }
    else if (msg->msg_id == FCNTL) {
      
      emscripten_log(EM_LOG_CONSOLE, "tty: FCNTL from %d: %d %d", msg->pid, msg->_u.fcntl_msg.fd, msg->_u.fcntl_msg.cmd);

      msg->_u.fcntl_msg.ret = 0;
      msg->_errno = 0;

      if (msg->_u.fcntl_msg.cmd == F_SETFL) {

	int flags;

	memcpy(&flags, msg->_u.fcntl_msg.buf, sizeof(int));

	clients[msg->_u.fcntl_msg.fd].flags = flags;
      }

      msg->msg_id |= 0x80;
      
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
  }
  
  return 0;
}
