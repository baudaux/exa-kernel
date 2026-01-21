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

#ifndef _EXAFS_LOCAL_DEV_H
#define _EXAFS_LOCAL_DEV_H

#include "sys/types.h"

struct exafs_ctx;

int exafs_local_clean_repo(struct exafs_ctx * ctx, const char * repo_name);

int exafs_local_read(struct exafs_ctx * ctx, uint32_t id, void * buffer, int len, int off);

int exafs_local_read_range(struct exafs_ctx * ctx, uint32_t id_min, uint32_t id_max, void * buffer, int len, uint32_t * last_obj);

int exafs_local_write(struct exafs_ctx * ctx, uint32_t id, void * buffer, int len);

int exafs_local_write_range(struct exafs_ctx * ctx, void * buffer, int len);

int exafs_local_write_rand(struct exafs_ctx * ctx, uint32_t max_reserved_id, void * buffer, uint32_t len, uint32_t * id);

int exafs_local_delete(struct exafs_ctx * ctx, uint32_t id);

int exafs_local_delete_range(struct exafs_ctx * ctx, uint32_t id_min, uint32_t id_max);


#endif // _EXAFS_LOCAL_DEV_H
