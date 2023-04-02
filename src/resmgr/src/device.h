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

#ifndef _DEVICE_H
#define _DEVICE_H

#include "msg.h"


#define NB_DEV_MAX 16

struct driver {

  unsigned char type;
  unsigned short major;
  const char name[DEV_NAME_LENGTH_MAX];
  const char peer[108];
};

struct device {

  unsigned char type;
  unsigned short major;
  unsigned short minor;
  const char name[DEV_NAME_LENGTH_MAX];

  struct device * next;
};

void device_init();

unsigned short device_register_driver(unsigned char type, const char * name, const char * peer);

int device_register_device(unsigned char type, unsigned short major, unsigned short minor, const char * name);

struct driver * device_get_driver(unsigned char type, unsigned short major);

struct device * device_get_device(unsigned char type, unsigned short major, unsigned short minor);

#endif // _DEVICE_H
