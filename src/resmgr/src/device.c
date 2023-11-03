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

#include "device.h"
#include "msg.h"
#include "vfs.h"

#ifndef DEBUG
#define DEBUG 0
#endif

#if DEBUG
#include <emscripten.h>
#else
#define emscripten_log(...)
#endif

static unsigned short majors[3];

static struct driver drivers[3][NB_DEV_MAX];
static struct device * devices;

int add_driver(unsigned short major, unsigned char type, const char * name, const char * peer);

void device_init() {

  memset(majors, 0, sizeof(majors));
  memset(drivers, 0, sizeof(drivers));
  devices = NULL;
  
  struct vnode * vnode = vfs_find_node("/", NULL);

  // Add /dev
  struct vnode * devnode = vfs_add_dir(vnode, "dev");

  // Add /dev/pts
  vfs_add_dir(devnode, "pts");

  // Add /bin for netfs
  vfs_add_dir(vnode, "bin");

  // Add /usr for netfs
  vfs_add_dir(vnode, "usr");

  // Add /etc for netfs
  vfs_add_dir(vnode, "etc");
  
  // Add /var
  struct vnode * var = vfs_add_dir(vnode, "var");

  // Add /var/run
  vfs_add_dir(var, "run");

  // Add /tmp for netfs
  vfs_add_dir(vnode, "tmp");

  // Add /home
  vfs_add_dir(vnode, "home");

  // Add /media
  struct vnode * media = vfs_add_dir(vnode, "media");
  
  // Add /media/localhost
  vfs_add_dir(media, "localhost");
}

unsigned short device_register_driver(unsigned char type, const char * name, const char * peer) {

  if (type > FS_DEV)
    return 0;

  if (majors[type] >= (NB_DEV_MAX-1))
    return 0;
  
  majors[type] += 1;
  
  int ret = add_driver(majors[type], type, name, peer);
  
  return majors[type];
}

int device_register_device(unsigned char type, unsigned short major, unsigned short minor, const char * name) {

  if ( (major == 0) || (drivers[type][major].major != major) )
    return -1;

  struct device * dev = (struct device *)malloc(sizeof(struct device));

  dev->type = type;
  dev->major = major;
  dev->minor = minor;
  strcpy((char *)dev->name, name);
  dev->next = NULL;

  if (devices == NULL) {

    devices = dev;
  }
  else {

    struct device * d = devices;

    while (d->next) {

      d = d->next;
    }

    d->next = dev;
  }

  if ( (type == CHR_DEV) || ((type == BLK_DEV)) ) {

    // name can be a path, so find last '/'

    char * s = strrchr(name, '/');

    char root[128] = "/dev";

    if (s) {

      strcat(root, "/");
      strncat(root, name, s-name);
      root[5+s-name] = 0;
      
      name = s+1;
    }
    
    // add device in /dev or /dev/...
    struct vnode * vnode = vfs_find_node(root, NULL);
    
    if (vnode) {
      vfs_add_dev(vnode, name, type, major, minor);

      if ( (type == CHR_DEV) && (major == 1) && (!vfs_find_node("/dev/console", NULL)) ) {
	vfs_add_dev(vnode, "console", type, major, minor);
      }
    }
  }
  
  return 0;
}

struct driver * device_get_driver(unsigned char type, unsigned short major) {

  return &drivers[type][major];
}

struct device * device_get_device(unsigned char type, unsigned short major, unsigned short minor) {

  struct device * dev = devices;

  while (dev) {

    if ( (dev->type == type) && (dev->major == major) && (dev->minor == minor) )
      break;

    dev = dev->next;
  }

  return dev;
}

int add_driver(unsigned short major, unsigned char type, const char * name, const char * peer) {
  
  if (drivers[type][major].major != 0)
    return -1;

  drivers[type][major].major = major;
  drivers[type][major].type = type;
  strcpy((char *)drivers[type][major].name, name);
  strcpy((char *)drivers[type][major].peer, peer);
    
  return 0;
}
