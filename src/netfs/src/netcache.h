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

#ifndef _NETCACHE_H
#define _NETCACHE_H

#include <sys/types.h>
#include <sys/stat.h>

#define ENOTCACHED 7777

void netcache_init();

int netcache_get_stat(const char * path, struct stat * stat);
int netcache_set_stat(const char * path, struct stat * stat, int _errno);

char * netcache_get_dents(const char * path, int * len, int * _errno);
int netcache_set_dents(const char * path, char * data_buf, int len, int _errno);

int netcache_read(const char * path, int offset, char * buf, int count);
int netcache_write(const char * path, char * buf, int count);

#endif // _NETCACHE_H
