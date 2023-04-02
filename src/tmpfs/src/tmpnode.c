/*
 * Copyright (C) 2022 Benoit Baudaux
 */

#include "tmpnode.h"

#include <stdlib.h>
#include <string.h>

struct tmpnode * create_tmpdir(struct tmpnode * parent, const char * dir_name) {

  struct tmpnode * f;

  if (parent && (parent->node_type != TMPDIR)) {
    return NULL;
  }

  f = malloc(sizeof(struct tmpnode));

  if (!f)
    return NULL;

  f->parent = parent;
  f->node_type = TMPDIR;

  strcpy(f->node_name,dir_name);

  f->_u.dir_child = NULL;
  f->next = NULL;

  if (parent) {

    if (!parent->_u.dir_child) {
      parent->_u.dir_child = f;
    }
    else {
      struct tmpnode * p = parent->_u.dir_child;

      while (p->next) {

	p = p->next;
      }

      p->next = f;
    }
  }

  return f;
}

struct tmpnode * create_tmpfile(struct tmpnode * parent, const char * file_name) {

  struct tmpnode * f;

  if (parent && (parent->node_type != TMPDIR)) {
    return NULL;
  }

  f = malloc(sizeof(struct tmpnode));

  if (!f)
    return NULL;

  f->parent = parent;
  f->node_type = TMPFILE;

  strcpy(f->node_name,file_name);

  f->_u.dir_child = NULL;
  f->next = NULL;

  if (parent) {

    if (!parent->_u.dir_child) {
      parent->_u.dir_child = f;
    }
    else {
      struct tmpnode * p = parent->_u.dir_child;

      while (p->next) {

	p = p->next;
      }

      p->next = f;
    }
  }

  return f;
}
