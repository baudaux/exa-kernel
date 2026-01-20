**Design of exafs**

exafs is a power-loss resilient filesystem running in the Web browser and storing data in indexedDB and in a remote server (and why not in RAM as well ?)

It aims at replacing the current exaequOS filesystem (littlefs) that is intended for flash device and not adapted to object storing locally and remotely (https://github.com/littlefs-project/littlefs/blob/master/DESIGN.md)

exafs is a Unix-style filesystem with inode structure.

# Structure

*Object*

It is the storing unit of exafs. It is a variable-length object that is identified by an id (32 bits). Length can vary from a few bytes to 1M byte (configurable).

*Superblock*

There are 4 superblocks that occupy the 4 first objects. It contains:
1. the object id of the first snapshot for inode table
2. , dir entries
3. Generation number
4. CRC

*Metadata log*

Metadata log starts just after the 4 superblocks and can contain 10000 objects (configurable). Logs are added sequentially.

*Extent*

An extent is a partial (contiguous) content of a file or directory. It is characterized by an offset, the data length and the data bytes.

An extent is stored in an object. Extents are located after metadata log (higher object id).

*Directory*

In volatile memory, a directory content is stored in a hash table of subdir element (name, inode id). and node type for accelerating getdents ??

In persistent memory, the directory operations are stored in the metedata log.

At directory creation, '.' and '..' subdirectories are automatically created.

# Formating

1. Current repo is cleaned
2. A new fs_uid is generated
3. Superblocks are written (4)
4. Root directory is created (and links . and ..)
5. Home directory is created

# Mounting

1. The 4 superblocks are read
2. The valid superblock (correct crc) with the highest generation is chosen
3. All the metadata log records are read and replayed
4. When metadata is about an inode not in RAM (except creation), it is read from the latest applicable snapshot (pointed by the superblock) before applying the log record.

# Snapshots

*inode table*

It is stored by group of 128 (?) inodes. For a given snapshot, all objects id are consecutive. Snapshot starts by a snapshot descriptor, whose object id is referenced by the superblock.

The snapshot descriptor contains:
1. number of inodes
2. number of objects (1 000 000 by default ?)
3. number of inodes per object (128 ?)
4. The id of the next descriptor (zero by default), in case there are more than 1000 objects

Descriptor and object are duplicated for handling copy-in-write (COW). Old and new version are stored consecutively (a and b).

If an inode has been deleted or is not allocated In a given object, its number is put to zero.

Each obect contain:
1. The generation number,
2. For each inode, id of extent containing either list of extents (case of file) or directory entries (case of directory).
3. CRC

When loading a snapshot object, all the included inodes (with a valid number) are added into the inode table.

*mapping*

   id -->    0        1        2        3        4       5
        +--------+--------+--------+--------+--------+--------+
        | Desc a | Desc b | Grp1 a | Grp1 b | Grp2 a | Grp2 b | ....
        +--------+--------+--------+--------+--------+--------+

id = <# Group>/2 + 1

# Extents

Extents contain the content of a file or a list of extents or directory entries.

*Writing*
When a file is written, an extent is first written at a random free location using `write_rand` interface function. Then associated metadata record is written in the logs (inode id, size, offset, object id).

*Compacting*
During compacting (while doing a snapshot ?), all continous extents are gathered into one. Data of latest extents replace data of first extents if any intersection.

*Reading*

# Low level access

*Clean repository*

`int clean_repo(struct exafs_ctx * ctx, char * repo_name);`

It removes all the objects of the repo identified by it is name. "home" is the name of the default local repo.

*Read object*

`int read(struct exafs_ctx * ctx, uint64_t id, void * buffer, int len);`

It reads object `id` and puts data in buffer whose size is `len`. It returns the number of bytes read, if successful (len is greater than the object size).

If object is bigger than `len`bytes, the function returns `- <object size>`.

*Read range of objects*

`int read_range(struct exafs_ctx * ctx, uint64_t id_min, uint64_t id_max, void * buffer, uint64_t len);`

It reads objects from `id_min` to `id_max` and puts data in buffer whose size is `len`. It returns the number of bytes read (headers + content).

The buffer will contain a list of (object header + object content). Object header if composed of two fields: `id` (uint32_t) and `length` (uint32_t).

Reading is stopped as soon as an object is not found. There is no partial read. So buffer will contain only objects than can be read entirely.

*Write object*

`int write(struct exafs_ctx * ctx, uint64_t id, void * buffer, uint64_t len);`

It write object `id` whose data is in buffer whose size is `len`. It returns the number of bytes written.

*Write object at any location*

`int write_rand(struct exafs_ctx * ctx, uint64_t max_reserved_id, void * buffer, uint64_t len, uint64 * id);`

It write an object at any random free slot after `max_reserved_id` (1 000 000 ?). Object data is in `buffer` and size is `len`. It returns the number of bytes written and object ìd is put in `id`.

*Write range of objects*

Needed ?

`int write_range(struct exafs_ctx * ctx, void * buffer, uint64_t len);`

It write objects contained in buffer (of size `len`).

The buffer will contain a list of (object header + object content). Object header if composed of two fields: `id` (uint32_t) and `length` (uint32_t).

*Delete object*

`int delete(struct exafs_ctx * ctx, uint32_t id);`

It deletes object `id`.

*Delete range of objects*

`int delete_range(struct exafs_ctx * ctx, uint32_t id_min, uint32_t id_max);`

It deletes objects from `id_min` to `id_max`.

*Find next free object*

`int find_free_slot(struct exafs_ctx * ctx, uint32_t from, uint32_t to);`

It find a free slot that does not contain an object, starting at `from` til `to` (included). 

# Hash table

Using git repo uthash with hashing function xxHash64

```
#include "xxhash.h"

// Fold a 64-bit hash to 32 bits (xor high/low)
static inline unsigned fold64_to_32(uint64_t h) {
    return (unsigned)(h ^ (h >> 32));
}

#define HASH_FUNCTION(keyptr, keylen, hashv)                          \
    do {                                                              \
        uint64_t h64 = XXH3_64bits((const void*)(keyptr), (size_t)(keylen)); \
        hashv = fold64_to_32(h64);                                    \
    } while (0)
```
