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

struct exafs_ctx;

int exafs_local_read(struct exafs_ctx * ctx, int id, void * buffer, int len);

int exafs_local_write(struct exafs_ctx * ctx, int id, void * buffer, int len);


#endif // _EXAFS_LOCAL_DEV_H
