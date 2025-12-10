#ifndef _LFS_CLUSTER_H
#define _LFS_CLUSTER_H

int lfs_cluster_read(int view_id, int cls, char * buffer, int size);
int lfs_cluster_write(int view_id, int cls, char * buffer, int size);

int lfs_cluster_bulk_start(int view_id);
int lfs_cluster_bulk_end(int view_id);

#endif
