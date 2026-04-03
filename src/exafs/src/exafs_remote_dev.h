/*
 * Copyright (C) 2026 Benoit Baudaux
 *
 * This file is part of EXA.
 *
 * EXA is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundationt, either version 3 of the License, or (at your option) any later version.
 *
 * EXA is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with EXA. If not, sees <https://www.gnu.org/licenses/>.
 */

#ifndef _EXAFS_REMOTE_DEV_H
#define _EXAFS_REMOTE_DEV_H

#include "sys/types.h"

struct exafs_ctx;

int exafs_remote_init_repo(const char * repo_name, const char * view);

int exafs_remote_clean_repo(uint32_t ctx_id);

int exafs_remote_read(uint32_t ctx_id, uint32_t id, void * buffer, int len, int off);

int exafs_remote_read_range(uint32_t ctx_id, uint32_t id_min, uint32_t id_max, void * buffer, int len, uint32_t * last_obj);

int exafs_remote_read_set(uint32_t ctx_id, uint32_t * obj_set, int nb_obj, char * data, int size);

int exafs_remote_write(uint32_t ctx_id, uint32_t id, void * buffer, int len);

int exafs_remote_write_range(uint32_t ctx_id, void * buffer, int len);

int exafs_remote_write_rand(uint32_t ctx_id, uint32_t max_reserved_id, void * buffer, uint32_t len, uint32_t * id);

int exafs_remote_delete(uint32_t ctx_id, uint32_t id);

int exafs_remote_delete_range(uint32_t ctx_id, uint32_t id_min, uint32_t id_max);

int exafs_remote_delete_set(uint32_t ctx_id, uint32_t * buffer, int len);

#endif // _EXAFS_REMOTE_DEV_H
