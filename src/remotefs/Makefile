DEBUG ?= 0
EMCC ?= emcc

all: exa/remotefs.js exa/remotefs.wasm

exa/remotefs.js exa/remotefs.wasm &: src/remotefs.c src/lfs_block.c ../../external/littlefs/lfs.c ../../external//littlefs/lfs_util.c src/lfs_cache.c src/lfs_cluster.c | exa
	$(EMCC) $^ -o exa/remotefs.js -I../include -I../../external/littlefs -sASYNCIFY -sINITIAL_MEMORY=16MB -sALLOW_MEMORY_GROWTH=1 -sTOTAL_STACK=512kB -sASYNCIFY_STACK_SIZE=256000 -DLFS_NO_DEBUG -DLFS_NO_WARN -DLFS_NO_ERROR -O3 -sASYNCIFY_IMPORTS=lfs_cluster_read,lfs_cluster_write,lfs_cluster_bulk_start,lfs_cluster_bulk_end -DDEBUG=$(DEBUG)

exa:
	mkdir -p exa

clean:
	rm -f exa/remotefs.js exa/remotefs.wasm

.PHONY: all clean
