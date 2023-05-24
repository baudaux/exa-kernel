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

#include "process.h"
#include "vfs.h"

#include <string.h>
#include <signal.h>

#include <sys/timerfd.h>

#include <emscripten.h>

#define DEBUG 0

#define NO_PARENT 0

#define RESMGR_ID 1
#define TTY_ID    2
#define NETFS_ID  3
#define PIPE_ID   4
#define INIT_ID   5

static struct process processes[NB_PROCESSES_MAX];
static int nb_processes = 0;

static struct vnode * vfs_proc;

pid_t process_fork(pid_t pid, pid_t ppid, const char * name);

void process_init() {

  struct vnode * vnode = vfs_find_node("/", NULL);

  // Add /proc
  vfs_proc = vfs_add_dir(vnode, "proc");
  
  for (int i = 0; i < NB_PROCESSES_MAX; ++i) {

    processes[i].pid = -1;
  }

  process_fork(RESMGR_ID, NO_PARENT, "resmgr");
}

void add_proc_entry(pid_t pid) {

  char str[8];

  sprintf(str, "%d", pid);

  // Add /proc/<pid>
  struct vnode * vfs_proc_pid = vfs_add_dir(vfs_proc, str);

  // Add /proc/<pid>/fd
  struct vnode * vfs_proc_pid_fd = vfs_add_dir(vfs_proc_pid, "fd");
}

void del_proc_entry(pid_t pid) {

  char str[16];

  sprintf(str, "/proc/%d", pid);

  struct vnode * vnode = vfs_find_node(str, NULL);

  if (vnode)
    vfs_del_tree(vnode);
}

void process_add_proc_fd_entry(pid_t pid, int fd, char * link) {

  char str[32];
  char str2[8];

  sprintf(str, "/proc/%d/fd", pid);

  sprintf(str2, "%d", fd);

  struct vnode * vfs_proc_pid_fd = vfs_find_node(str, NULL);

  if (vfs_proc_pid_fd)
    vfs_add_symlink(vfs_proc_pid_fd, str2, link, NULL);
}

void process_del_proc_fd_entry(pid_t pid, int fd) {

  char str[32];

  sprintf(str, "/proc/%d/fd/%d", pid, fd);
  
  struct vnode * vfs_proc_pid_fd = vfs_find_node(str, NULL);

  if (vfs_proc_pid_fd)
    vfs_del_node(vfs_proc_pid_fd);
}

pid_t create_tty_process() {

  process_fork(TTY_ID, NO_PARENT, "tty");

  pid_t pid = fork();
  
  if (pid == -1) { // Error
    
    if (DEBUG)
      emscripten_log(EM_LOG_CONSOLE,"Error while creating tty process ...");
    
    return -1;
    
  } else if (pid == 0) { // Child process

    if (DEBUG)
      emscripten_log(EM_LOG_CONSOLE,"starting tty process...");

    execl ("/bin/tty", "/bin/tty", (void*)0);
    
  } else { // Parent process

    if (DEBUG)
      emscripten_log(EM_LOG_CONSOLE,"tty process created: %d",pid);

    return pid;
  }

  return 0;
}

pid_t create_netfs_process() {

  process_fork(NETFS_ID, NO_PARENT, "netfs");
  
  pid_t pid = fork();
  
  if (pid == -1) { // Error
    
    if (DEBUG)
      emscripten_log(EM_LOG_CONSOLE,"Error while creating netfs process ...");
    
    return -1;
    
  } else if (pid == 0) { // Child process

    if (DEBUG)
      emscripten_log(EM_LOG_CONSOLE,"starting netfs process...");

    execl ("/bin/netfs", "/bin/netfs", (void*)0);
    
  } else { // Parent process
    
    if (DEBUG)
      emscripten_log(EM_LOG_CONSOLE,"netfs process created: %d",pid);

    return pid;
  }

  return 0;
}

pid_t create_pipe_process() {

  process_fork(PIPE_ID, NO_PARENT, "pipe");
  
  pid_t pid = fork();
  
  if (pid == -1) { // Error
    
    if (DEBUG)
      emscripten_log(EM_LOG_CONSOLE,"Error while creating pipe process ...");
    
    return -1;
    
  } else if (pid == 0) { // Child process

    if (DEBUG)
      emscripten_log(EM_LOG_CONSOLE,"starting pipe process...");

    execl ("/bin/pipe", "/bin/pipe", (void*)0);
    
  } else { // Parent process
    
    if (DEBUG)
      emscripten_log(EM_LOG_CONSOLE,"pipe process created: %d",pid);

    return pid;
  }

  return 0;
}

pid_t create_init_process() {

  process_fork(INIT_ID, NO_PARENT, "init");
  
  pid_t pid = fork();
  
  if (pid == -1) { // Error
    
    if (DEBUG)
      emscripten_log(EM_LOG_CONSOLE,"Error while creating init process ...");
    
    return -1;
    
  } else if (pid == 0) { // Child process

    if (DEBUG)
      emscripten_log(EM_LOG_CONSOLE,"starting init process...");

    execl ("/bin/sysvinit", "/bin/sysvinit", "--init", (void*)0);
    
  } else { // Parent process
    
    if (DEBUG)
      emscripten_log(EM_LOG_CONSOLE, "init process created: %d", pid);

    return pid;
  }

  return 0;
}

pid_t process_fork(pid_t pid, pid_t ppid, const char * name) {

  if (DEBUG)
    emscripten_log(EM_LOG_CONSOLE,"process_fork: %d %d", pid, ppid);
  
  if (pid < 0)
    pid = nb_processes;
  else
    nb_processes = pid;

  if (pid >= NB_PROCESSES_MAX)
    return -1;

  add_proc_entry(pid);
  
  processes[pid].proc_state = RUNNING_STATE;
  
  processes[pid].pid = pid;
  processes[pid].ppid = ppid;

  if (ppid >= 0) {

    if (DEBUG)
      emscripten_log(EM_LOG_CONSOLE,"(2) process_fork: %d %d %d %d", pid, ppid, processes[ppid].pgid, processes[ppid].sid);

    processes[pid].pgid =  processes[ppid].pgid;
    processes[pid].sid =  processes[ppid].sid;

    strcpy(processes[pid].cwd, processes[ppid].cwd);

    processes[pid].umask = processes[ppid].umask;
    memcpy(&processes[pid].sigprocmask, &processes[ppid].sigprocmask, sizeof(sigset_t));

    memcpy(&processes[pid].sigactions, &processes[ppid].sigactions, 32*sizeof(struct sigaction));
    
  }
  else {

    processes[pid].pgid = 0;
    processes[pid].sid = 0;

    strcpy(processes[pid].cwd, "");

    sigemptyset(&processes[pid].sigprocmask);

    memset(&processes[pid].sigactions, 0, 32*sizeof(struct sigaction));
  }

  if (name)
    strcpy(processes[pid].name, name);
  else
    strcpy(processes[pid].name, "");

  sigemptyset(&processes[pid].sigpending);
  sigemptyset(&processes[pid].sigdelivering);
    
  for (int i = 0; i < NB_FILES_MAX; ++i) {

    processes[pid].fds[i].fd = -1;
  }

  processes[pid].status = 0;
  processes[pid].wait_child = 0;
  processes[pid].wait_pid = 0;
  processes[pid].wait_options = 0;

  processes[pid].peer_addr.sun_family = AF_UNIX;
  sprintf(processes[pid].peer_addr.sun_path, "channel.process.%d", pid);

  if (ppid > 0) {

    for (int i = 0; i < (NB_FILES_MAX/8+1); ++i)
      processes[pid].fd_map[i] = processes[ppid].fd_map[i];
    
    for (int i = 0; i < NB_FILES_MAX; ++i) {

      if (processes[ppid].fds[i].fd >= 0) {
	
	processes[pid].fds[i].fd = processes[ppid].fds[i].fd;
	processes[pid].fds[i].remote_fd = processes[ppid].fds[i].remote_fd;
	processes[pid].fds[i].type = processes[ppid].fds[i].type;
	processes[pid].fds[i].major = processes[ppid].fds[i].major;
	processes[pid].fds[i].minor = processes[ppid].fds[i].minor;
	processes[pid].fds[i].flags = processes[ppid].fds[i].flags;
	//strcpy(processes[pid].fds[i].peer, processes[ppid].fds[i].peer);
      }
    }
  }
  else {

    for (int i = 0; i < (NB_FILES_MAX/8+1); ++i)
      processes[pid].fd_map[i] = 0;
  }

  processes[pid].timerfd = -1;
  
  ++nb_processes;

  return pid;
}

void dump_processes() {

  if (DEBUG)
    emscripten_log(EM_LOG_CONSOLE,"**** processes ****");

  for (int i = 0; i < nb_processes; ++i) {

    if (DEBUG)
      emscripten_log(EM_LOG_CONSOLE, "* %d %d %d %d %s %d", processes[i].pid, processes[i].ppid, processes[i].pgid, processes[i].sid, processes[i].name, processes[i].proc_state);
  }
}

int process_find_smallest_fd(pid_t pid) {

  int i, j;

  for (i = 0; i < NB_FILES_MAX; ++i) {

    if ((processes[pid].fd_map[i/8] & 1 << (i%8)) == 0)
      return i;
  }

  return -1;
}

int process_create_fd(pid_t pid, int remote_fd, unsigned char type, unsigned short major, unsigned short minor, int flags) {
  
  int i;
  
  for (i = 0; i < NB_FILES_MAX; ++i) {

    if (processes[pid].fds[i].fd == -1)
      break;
  }

  if (i >= NB_FILES_MAX)
    return -1;

  int fd = process_find_smallest_fd(pid);

  processes[pid].fd_map[fd/8] |= (1 << (fd%8));

  processes[pid].fds[i].fd = fd;
  processes[pid].fds[i].remote_fd = remote_fd;
  processes[pid].fds[i].type = type;
  processes[pid].fds[i].major = major;
  processes[pid].fds[i].minor = minor;
  processes[pid].fds[i].flags = flags;

  if (DEBUG)
    emscripten_log(EM_LOG_CONSOLE,"process_create_fd: %d, %d, %d", pid, remote_fd, fd);

  return fd;
}

int process_get_fd(pid_t pid, int fd, unsigned char * type, unsigned short * major, int * remote_fd) {

  for (int i = 0; i < NB_FILES_MAX; ++i) {

    if (processes[pid].fds[i].fd == fd) {
      
      *type = processes[pid].fds[i].type;
      *major = processes[pid].fds[i].major;
      *remote_fd = processes[pid].fds[i].remote_fd;

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE,"process_get_fd: %d, %d, %d (%d)", pid, *remote_fd, fd, i);

      return 0;
    }
  }

  if (DEBUG)
    emscripten_log(EM_LOG_CONSOLE,"process_get_fd: %d, %d not found", pid, fd);

  return -1;
}

int process_close_fd(pid_t pid, int fd) {

  for (int i = 0; i < NB_FILES_MAX; ++i) {

    if (processes[pid].fds[i].fd == fd) {

      processes[pid].fds[i].fd = -1;
      
      processes[pid].fd_map[fd/8] &= ~(1 << (fd%8));

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE,"process_close_fd: %d, %d (%i)", pid, fd, i);
      
      return 0;
    }
  }

  if (DEBUG)
    emscripten_log(EM_LOG_CONSOLE,"process_close_fd: %d, %d not found", pid, fd);

  return -1;
}

int process_find_open_fd(unsigned char type, unsigned short major, int remote_fd) {

  for (int j = 0; j < nb_processes; ++j) {

    for (int i = 0; i < NB_FILES_MAX; ++i) {

      if (processes[j].fds[i].fd != -1) {

	if ( (processes[j].fds[i].type == type) && (processes[j].fds[i].major == major) && (processes[j].fds[i].remote_fd == remote_fd) ) {

	  //emscripten_log(EM_LOG_CONSOLE,"process_find_open_fd: %d, %d, %d", j, j, remote_fd);
	  return 1;
	  
	}
      }
    }
  }

  return -1;
}

int process_set_fd_flags(pid_t pid, int fd, int flags) {

  for (int i = 0; i < NB_FILES_MAX; ++i) {

    if (processes[pid].fds[i].fd == fd) {

      processes[pid].fds[i].flags = flags;
      
      return 0;
    }
  }

  return -1;
}

int process_get_fd_flags(pid_t pid, int fd) {

  for (int i = 0; i < NB_FILES_MAX; ++i) {

    if (processes[pid].fds[i].fd == fd) {

      return processes[pid].fds[i].flags;
    }
  }

  return -1;
}

struct sockaddr_un * process_get_peer_addr(pid_t pid) {

  return &processes[pid].peer_addr;
}

pid_t process_group_exists(pid_t pgid) {

  for (int i = 0; i < nb_processes; ++i) {

    if (processes[i].pgid == pgid)
      return i;
  }

  return 0;
}

pid_t process_setsid(pid_t pid) {

  if (!process_group_exists(pid)) { // process is not process group leader

    if (DEBUG)
      emscripten_log(EM_LOG_CONSOLE,"process_setsid: successful -> %d", pid);
     
    processes[pid].pgid = pid;
    processes[pid].sid = pid;

    // TODO inform tty driver
    
    return pid;
  }

  return -1;
}

pid_t process_getsid(pid_t pid) {
  
  return processes[pid].sid;
}

pid_t process_getppid(pid_t pid) {

  return processes[pid].ppid;
}

pid_t process_getpgid(pid_t pid) {

  return processes[pid].pgid;
}

int process_setpgid(pid_t pid, pid_t pgid) {

  if (pgid == 0) {

    processes[pid].pgid = pid;
    return 0;
  }

  pid_t i = process_group_exists(pgid);

  if (!i)
    return -1;

  if (processes[pid].sid != processes[i].sid)
    return -1;

  processes[pid].pgid = pgid;

  return 0;
}

int process_dup(pid_t pid, int fd, int new_fd) {

  int i;
  
  for (i = 0; i < NB_FILES_MAX; ++i) {

    if (processes[pid].fds[i].fd == fd)
      break;
  }

  if (i >= NB_FILES_MAX)
    return -1;

  if (new_fd >= 0) {

    if (new_fd == fd) {

      return new_fd;
    }
    else {

      process_close_fd(pid, new_fd);

      // TODO inform tty driver
    }
  }
  else {
    
    new_fd = process_find_smallest_fd(pid);
  }
  
  int j;
  
  for (j = 0; j < NB_FILES_MAX; ++j) {

    if (processes[pid].fds[j].fd == -1)
      break;
  }

  if (j >= NB_FILES_MAX)
    return -1;

  processes[pid].fds[j].fd = new_fd;
  processes[pid].fds[j].remote_fd = processes[pid].fds[i].remote_fd;
  processes[pid].fds[j].type = processes[pid].fds[i].type;
  processes[pid].fds[j].major = processes[pid].fds[i].major;
  processes[pid].fds[j].minor = processes[pid].fds[i].minor;
  processes[pid].fds[j].flags = processes[pid].fds[i].flags;

  processes[pid].fd_map[new_fd/8] |= (1 << (new_fd%8));
  
  return new_fd;
}

char * process_getcwd(pid_t pid) {

  return processes[pid].cwd;
}

int process_chdir(pid_t pid, char * dir) {

  if (strlen(dir) < (1024-1))
    strcpy(processes[pid].cwd, dir);

  return 0;
}

EM_JS(void, exit_proc, (int pid), {

    let m = {
	    
      type: 4,   // exit
      pid: pid
    };

    window.parent.postMessage(m);
});

void process_terminate(pid_t pid) {

  processes[pid].proc_state = EXITED_STATE;

  //TOTEST
  exit_proc(pid);
}

pid_t process_wait(pid_t ppid, pid_t pid, int options, int * status) {

  processes[ppid].wait_child = 1;
  processes[ppid].wait_pid = pid;
  processes[ppid].wait_options = options;
  
  for (int i = 0; i < nb_processes; ++i) {

    if ( (processes[i].ppid == ppid) && (processes[i].proc_state == ZOMBIE_STATE) ) {
      if ( (pid == -1) || (pid == i) ) {

	// TODO: add other conditions (group)

	if (DEBUG)
	  emscripten_log(EM_LOG_CONSOLE, "process_wait: found child pid %d", i);
	
	*status = processes[i].status;

	process_terminate(i);
	
	return i;
      }
    }
  }
  
  return 0;
}

pid_t process_exit(pid_t pid, int status) {

  processes[pid].proc_state = ZOMBIE_STATE;
  processes[pid].status = status;

  del_proc_entry(pid);

  int ppid = processes[pid].ppid;

  //TODO : stop timers
  
  if (processes[ppid].wait_child &&
      ( (processes[ppid].wait_pid == -1) || (processes[ppid].wait_pid == pid) ) ) {

    // TODO: add other conditions (group)

    if (DEBUG)
      emscripten_log(EM_LOG_CONSOLE, "process_exit: found parent pid %d", ppid);
    
    process_terminate(pid);
      
    return ppid;
  }
  
  return 0;
}

int process_sigaction(pid_t pid, int signum, struct sigaction * act) {

  struct sigaction old;

  if (!signum || (signum > NSIG) )
    return -1;

  memcpy(&old, &processes[pid].sigactions[signum-1], sizeof(struct sigaction));

  memcpy(&processes[pid].sigactions[signum-1], act, sizeof(struct sigaction));

  memcpy(act, &old, sizeof(struct sigaction));

  return 0;
}

int process_sigprocmask(pid_t pid, int how, sigset_t * set) {

  sigset_t old;
  unsigned char * set2 = (unsigned char *)set;
  unsigned char * mask = (unsigned char *)&processes[pid].sigprocmask;

  memcpy(&old, &processes[pid].sigprocmask, sizeof(sigset_t));

  switch(how) {

  case SIG_BLOCK:

    for (int i = 0; i < NSIG; ++i) {

      if (set2[i/8] & (1 << (i%8))) {

	mask[i/8] |= 1 << (i%8);
      }
    }
    
    break;

  case SIG_UNBLOCK:

    for (int i = 0; i < NSIG; ++i) {

      if (set2[i/8] & (1 << (i%8))) {

	mask[i/8] &= ~(1 << (i%8));
      }
    }

    break;

  case SIG_SETMASK:

    memcpy(&processes[pid].sigprocmask, set, sizeof(sigset_t));
    break;

  default:
    
    break;
  }

  memcpy(set, &old, sizeof(sigset_t));
  
  return 0;
}

int process_kill(pid_t pid, int signum, struct sigaction * act) {

    if ( (signum == SIGKILL) || (signum == SIGSTOP) ) {

      sigaddset(&processes[pid].sigpending, signum);

      // Cannot change default behaviour for SIGKILL and SIGSTOP
      
      return 1; // Default action
    }
    else if ( (((int)processes[pid].sigactions[signum-1].sa_handler) != -2) && (!sigismember(&processes[pid].sigdelivering, signum)) ) { // Signal not ignored

      sigaddset(&processes[pid].sigpending, signum);

      if (sigismember(&processes[pid].sigprocmask, signum))
	return 0; // No action
      
      memcpy(act, &processes[pid].sigactions[signum-1], sizeof(struct sigaction));

      if ( ((int)processes[pid].sigactions[signum-1].sa_handler) == 0)
	return 1; // Default action

      sigaddset(&processes[pid].sigdelivering, signum);
      
      return 2; // Custom action
    }

    return 0; // No action
}

void process_signal_delivered(pid_t pid, int signum) {

  sigdelset(&processes[pid].sigdelivering, signum);
}

int process_setitimer(pid_t pid, int which, int val_sec, int val_usec, int it_sec, int it_usec) {

  if (processes[pid].timerfd < 0)
    processes[pid].timerfd = timerfd_create(CLOCK_MONOTONIC, 0);

  struct itimerspec ts;
     
  ts.it_interval.tv_sec = it_sec;
  ts.it_interval.tv_nsec = it_usec * 1000;
  ts.it_value.tv_sec = val_sec;
  ts.it_value.tv_nsec = val_usec * 1000;
  
  if ( (ts.it_value.tv_sec == 0) && (ts.it_value.tv_nsec == 0) ) {

    ts.it_value.tv_sec = it_sec;
    ts.it_value.tv_nsec = it_usec * 1000;
  }
     
  timerfd_settime(processes[pid].timerfd, 0, &ts, NULL);
  
  return processes[pid].timerfd;
}

void process_clearitimer(pid_t pid) {
 
  if (processes[pid].timerfd >= 0)
    close(processes[pid].timerfd);
}

int process_opened_fd(pid_t pid, unsigned char * type, unsigned short * major, int * remote_fd, int flag) {

  for (int i = 0; i < NB_FILES_MAX; ++i) {

    if (processes[pid].fds[i].fd >= 0) {

      if (!flag || (processes[pid].fds[i].flags & O_CLOEXEC)) {

	*type = processes[pid].fds[i].type;
	*major = processes[pid].fds[i].major;
	*remote_fd = processes[pid].fds[i].remote_fd;

	return processes[pid].fds[i].fd;
      }
    }
  }

  return -1;
}
