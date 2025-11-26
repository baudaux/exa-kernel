DEBUG ?= 0
EMCC ?= emcc

all: exa/remotefs.js exa/remotefs.wasm

exa/remotefs.js exa/remotefs.wasm &: src/remotefs.c src/lfs_block.c src/lfs.c src/lfs_util.c | exa
	$(EMCC) $^ -o exa/remotefs.js -I../include -sASYNCIFY -sINITIAL_MEMORY=16MB -sALLOW_MEMORY_GROWTH=1 -sTOTAL_STACK=512kB -sASYNCIFY_STACK_SIZE=256000 -DLFS_NO_DEBUG -DLFS_NO_WARN -DLFS_NO_ERROR -O3 -sASYNCIFY_IMPORTS=lfs_blk_read,lfs_blk_erase,lfs_blk_prog -DDEBUG=$(DEBUG)

exa:
	mkdir -p exa

clean:
	rm -f exa/remotefs.js exa/remotefs.wasm

.PHONY: all clean
