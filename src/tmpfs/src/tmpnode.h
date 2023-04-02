/*
 * Copyright (C) 2022 Benoit Baudaux
 */

#ifndef _TMPNODE_H
#define _TMPNODE_H

#include <stdio.h>

enum tmpnode_enum {

  TMPDIR = 0,
  TMPFILE
};

struct tmpnode {

  struct tmpnode * parent;

  enum tmpnode_enum node_type;
  char node_name[FILENAME_MAX];
  
  union {
    struct tmpnode * dir_child;
    struct {
      unsigned char * buffer;
      size_t buffer_size;
      size_t file_size;
    } _f;
  } _u;

  struct tmpnode * next;
};

struct tmpnode * create_tmpdir(struct tmpnode * parent, const char * dir_name);

struct tmpnode * create_tmpfile(struct tmpnode * parent, const char * file_name);

#endif
