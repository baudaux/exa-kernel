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

#ifndef _MSG_H
#define _MSG_H

#include <sys/socket.h>
#include <sys/un.h>

#include <signal.h>

#define DEV_NAME_LENGTH_MAX  128

enum message_id {
  
  REGISTER_DRIVER = 1,
  UNREGISTER_DRIVER,
  REGISTER_DEVICE,
  UNREGISTER_DEVICE,
  MOUNT = 5,
  UMOUNT,
  FORK,
  EXECVE,
  SOCKET,
  BIND = 10,
  OPEN,
  READ,
  WRITE,
  IOCTL,
  CLOSE = 15,
  SETSID,
  FCNTL,
  GETSID,
  DUP,
  GETPPID = 20,
  GETPGID,
  SETPGID,
  PROBE_TTY,
  READ_TTY,
  WRITE_TTY = 25,
  IS_OPEN,
  READLINK,
  STAT,
  FSTAT,
  LSTAT = 30,
  SELECT,
  SCTTY,
  TIMERFD_CREATE,
  GETCWD,
  CHDIR = 35,
  GETDENTS,
  WAIT,
  EXIT,
  SEEK,
  SIGACTION = 40,
  SIGPROCMASK,
  KILL,
};

enum dev_type {

  BLK_DEV = 0,
  CHR_DEV,
  FS_DEV
};

struct device_message {

  unsigned char dev_type; /* enum dev_type */
  unsigned char dev_name[DEV_NAME_LENGTH_MAX];
  unsigned short major;
  unsigned short minor;
};

struct socket_message {

  int fd;
  int domain;
  int type;
  int protocol;
};

struct bind_message {

  int fd;
  struct sockaddr addr;
};

struct open_message {
  
  int fd;
  int remote_fd;
  int flags;
  unsigned short mode;
  unsigned char type;
  unsigned short major;
  unsigned short minor;
  unsigned char peer[108];
  unsigned char pathname[1024];
  int sid;
};

struct close_message {

  int fd;
};

struct io_message {
  
  int fd;
  unsigned long len;
  unsigned char buf[];
};

struct ioctl_message {
  
  int fd;
  int op;
  unsigned long len;
  unsigned char buf[];
};

struct fcntl_message {
  
  int fd;
  int cmd;
};

struct mount_message {

  unsigned char dev_type;
  unsigned short major;
  unsigned short minor;
  char pathname[1024];
};

struct getsid_message {

  pid_t pid;
  pid_t sid;
  pid_t pgid;
};

struct setsid_message {

  pid_t sid;
};

struct fork_message {

  pid_t child;
};

struct execve_message {

  unsigned long args_size;
};

struct dup_message {
  
  int fd;
  int new_fd;
};

struct getpgid_message {

  pid_t pid;
  pid_t pgid;
};

struct getppid_message {

  pid_t ppid;
};

struct probe_tty_message {
  
  unsigned short rows;
  unsigned short cols;
};

struct read_tty_message {
  
  unsigned long len;
  unsigned char buf[];
};

struct is_open_message {
  
  int fd;
  int remote_fd;
  unsigned char type;
  unsigned short major;
  char peer[108];
};

struct readlink_message {
  
  int dirfd;
  int len;
  char pathname_or_buf[1024];
};

struct stat_message {
  
  int len;
  char pathname_or_buf[1024];
  unsigned char type;
  unsigned short major;
  unsigned short minor;
};

struct fstat_message {
  
  int fd;
  int len;
  char buf[1024];
};

struct select_message {
  
  int fd;
  int read_write; // 0: read, 1: write
  int start_stop; // 1: start, 0: stop
  int remote_fd;
};

struct timerfd_create_message {

  int clockid;
  int fd;
};

struct cwd_message {
  
  unsigned long len;
  unsigned char buf[];
};

struct getdents_message {

  int fd;
  unsigned long len;
  unsigned char buf[];
};

struct wait_message {

  int pid;
  int options;
  int status;
};

struct exit_message {

  int status;
};

struct seek_message {

  int fd;
  int offset;
  int whence;
};

struct sigaction_message {

  int signum;
  struct sigaction act;
};

struct sigprocmask_message {

  int how;
  int sigsetsize;
  char sigset[];
};

struct kill_message {

  int pid;
  int sig;
  struct sigaction act;
};

struct message {

  unsigned char msg_id; /* enum message_id on 7 bits, for answer the most significant bit is set to 1 */
  
  pid_t pid;

  int _errno;

  union {
    
    struct device_message dev_msg;
    struct socket_message socket_msg;
    struct bind_message bind_msg;
    struct open_message open_msg;
    struct close_message close_msg;
    struct io_message io_msg;
    struct ioctl_message ioctl_msg;
    struct fcntl_message fcntl_msg;
    struct mount_message mount_msg;
    struct getsid_message getsid_msg;
    struct setsid_message setsid_msg;
    struct fork_message fork_msg;
    struct execve_message execve_msg;
    struct dup_message dup_msg;
    struct getpgid_message getpgid_msg;
    struct getppid_message getppid_msg;
    struct probe_tty_message probe_tty_msg;
    struct read_tty_message read_tty_msg;
    struct is_open_message is_open_msg;
    struct readlink_message readlink_msg;
    struct stat_message stat_msg;
    struct fstat_message fstat_msg;
    struct select_message select_msg;
    struct timerfd_create_message timerfd_create_msg;
    struct cwd_message cwd_msg;
    struct getdents_message getdents_msg;
    struct wait_message wait_msg;
    struct exit_message exit_msg;
    struct seek_message seek_msg;
    struct sigaction_message sigaction_msg;
    struct sigprocmask_message sigprocmask_msg;
    struct kill_message kill_msg;
    
  } _u;
};

#endif // _MSG_H
