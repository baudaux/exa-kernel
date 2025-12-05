#ifndef _LFS_CLUSTER_H
#define _LFS_CLUSTER_H

int lfs_cluster_read(int cls, char * buffer, int size);
int lfs_cluster_write(int cls, char * buffer, int size);

#endif
