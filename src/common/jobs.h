#ifndef _JOBS_H
#define _JOBS_H

#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#define NO_JOB    0
#define LAST_JOB  0xffffffff

struct job {

  unsigned long type;
  pid_t pid;
  int size;
  char * buf;
  struct sockaddr_un addr;
};

void jobs_init(struct job * jobs, size_t size);

unsigned long is_pending_job(struct job * jobs, pid_t pid);
unsigned long get_pending_job(struct job * jobs, pid_t pid, char ** buf, int * size, struct sockaddr_un ** addr);
unsigned long get_pending_job_by_type(struct job * jobs, unsigned long job, unsigned long mask, char ** buf, int * size, struct sockaddr_un ** addr);

unsigned long add_pending_job(struct job * jobs, unsigned long job, pid_t pid, char * buf, size_t size, struct sockaddr_un * addr);
unsigned long continue_pending_job(struct job * jobs, pid_t pid, int sock);
unsigned long del_pending_job(struct job * jobs, unsigned long job, pid_t pid);

#endif // _JOBS_H
