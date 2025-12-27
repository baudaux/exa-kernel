DEBUG ?= 0
EMCC ?= emcc

all: exa/lfs.js exa/lfs.wasm

exa/lfs.js exa/lfs.wasm &: src/lfs.c src/lfs_block.c ../../external/littlefs/lfs.c ../../external/littlefs/lfs_util.c src/lfs_cache.c src/lfs_cluster.c src/lfs_remote_dev.c src/lfs_local_dev.c | exa
	$(EMCC) $^ -o exa/lfs.js -I../include -I../../external/littlefs -I../../external/libsodium/src/libsodium/include -sASYNCIFY -sINITIAL_MEMORY=16MB -sALLOW_MEMORY_GROWTH=1 -sTOTAL_STACK=512kB -sASYNCIFY_STACK_SIZE=256000  -O3 -sASYNCIFY_IMPORTS=store_remote_salt,get_remote_salt,lfs_remote_read,lfs_remote_write,lfs_remote_bulk_start,lfs_remote_bulk_end,store_local_salt,get_local_salt,lfs_local_read,lfs_local_write,lfs_local_bulk_start,lfs_local_bulk_end -DDEBUG=$(DEBUG) -DLFS_NO_DEBUG -DLFS_NO_WARN -DLFS_NO_ERROR -lsodium -L../../external/libsodium/src/libsodium/.libs/

exa:
	mkdir -p exa

clean:
	rm -f exa/lfs.js exa/lfs.wasm

.PHONY: all clean
