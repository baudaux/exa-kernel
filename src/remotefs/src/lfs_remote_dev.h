/*
 * Copyright (C) 2025 Benoit Baudaux
 *
 * This file is part of EXA.
 *
 * EXA is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundationt, either version 3 of the License, or (at your option) any later version.
 *
 * EXA is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with EXA. If not, sees <https://www.gnu.org/licenses/>.
 */

#ifndef _LFS_REMOTE_DEV_H
#define _LFS_REMOTE_DEV_H

int lfs_remote_read(int view_id, int cluster, void * buffer, int size);
int lfs_remote_write(int view_id, int cluster, char * buffer, int size);
int lfs_remote_bulk_start(int view_id);
int lfs_remote_bulk_end(int view_id);

#endif // _LFS_REMOTE_DEV_H
