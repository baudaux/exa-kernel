DEBUG ?= 0
EMCC ?= emcc

all: exa/exafs.js exa/exafs.wasm

exa/exafs.js exa/exafs.wasm &: src/exafs_driver.c src/exafs.c src/exafs_util.c src/exafs_local_dev.c | exa
	$(EMCC) $^ -o exa/exafs.js -I../include -sASYNCIFY -sINITIAL_MEMORY=16MB -sALLOW_MEMORY_GROWTH=1 -sTOTAL_STACK=512kB -sASYNCIFY_STACK_SIZE=256000  -O3 -sASYNCIFY_IMPORTS=exafs_local_read,exafs_local_write -DDEBUG=$(DEBUG)

#LFS_YES_TRACE


exa:
	mkdir -p exa

clean:
	rm -f exa/exafs.js exa/exafs.wasm

.PHONY: all clean
