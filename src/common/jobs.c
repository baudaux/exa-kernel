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
#include <stdlib.h>

#include "jobs.h"

#include <emscripten.h>

#define DEBUG 1

void jobs_init(struct job * jobs, size_t size) {

  for (int i=0; i<(size-1); ++i,++jobs) {

    jobs->type = NO_JOB;
    jobs->buf = NULL;
  }

  jobs->type = LAST_JOB;
}

unsigned long is_pending_job(struct job * jobs, pid_t pid) {

  for (; jobs->type != LAST_JOB; ++jobs) {

    if ( (jobs->type != NO_JOB) && (jobs->pid == pid) ) {

      return jobs->type;
    }
  }
  
  return NO_JOB;
}

unsigned long get_pending_job(struct job * jobs, pid_t pid, char ** buf, int * size, struct sockaddr_un ** addr) {

  for (; jobs->type != LAST_JOB; ++jobs) {

    if ( (jobs->type != NO_JOB) && (jobs->pid == pid) ) {

      *buf = jobs->buf;
      *size = jobs->size;
      *addr = &(jobs->addr);

      return jobs->type;
    }
  }
  
  return NO_JOB;
}

unsigned long get_pending_job_by_type(struct job * jobs, unsigned long job, unsigned long mask, char ** buf, int * size, struct sockaddr_un ** addr) {

  if (DEBUG)
    emscripten_log(EM_LOG_CONSOLE, "jobs: get_pending_job_by_type: find job=%lu mask=%lu", job, mask);

  for (; jobs->type != LAST_JOB; ++jobs) {

    if ( (jobs->type != NO_JOB) && ((jobs->type & mask) == job) ) {

      *buf = jobs->buf;
      *size = jobs->size;
      *addr = &(jobs->addr);

      return jobs->type;
    }
  }
  
  return NO_JOB;
}

unsigned long add_pending_job(struct job * jobs, unsigned long job, pid_t pid, char * buf, size_t size, struct sockaddr_un * addr) {

  if (DEBUG)
    emscripten_log(EM_LOG_CONSOLE, "jobs: add_pending_job: job=%d pid=%d", job, pid);

  for (; jobs->type != LAST_JOB; ++jobs) {

    if (jobs->type == NO_JOB) {

      jobs->type = job;
      jobs->pid = pid;
      memcpy((void *)&(jobs->addr), (void *)addr, sizeof(*addr));

      jobs->size = size;

      if (size > 0) {

	jobs->buf = malloc(size);

	if (jobs->buf) {
	  memcpy((void *)(jobs->buf), (void *)buf, size);

	  return job;
	}
	else {

	  jobs->type = NO_JOB;
	  return NO_JOB;
	}
	
      }
    }
  }

  return NO_JOB;
}

unsigned long continue_pending_job(struct job * jobs, pid_t pid, int sock) {

  if (DEBUG)
    emscripten_log(EM_LOG_CONSOLE, "jobs: continue_pending_job");

  for (; jobs->type != LAST_JOB; ++jobs) {

    if ( (jobs->type != NO_JOB) && (jobs->pid == pid) ) {

      if (DEBUG)
	emscripten_log(EM_LOG_CONSOLE, "jobs: continue_pending_job !!!: job=%d pid=%d", jobs->type, pid);

      sendto(sock, jobs->buf, jobs->size, 0, (struct sockaddr *) &(jobs->addr), sizeof(jobs->addr));
      
      jobs->type = NO_JOB;

      if (jobs->buf)
	free(jobs->buf);
    }
  }
  
  return NO_JOB;
}

unsigned long del_pending_job(struct job * jobs, unsigned long job, pid_t pid) {

  if (DEBUG)
    emscripten_log(EM_LOG_CONSOLE, "jobs: del_pending_job");
  
  for (; jobs->type != LAST_JOB; ++jobs) {

    if ( (jobs->type == job) && (jobs->pid == pid) ) {

      jobs->type = NO_JOB;

      if (jobs->buf)
	free(jobs->buf);
      
      return job;
    }
  }

  return NO_JOB;
}
