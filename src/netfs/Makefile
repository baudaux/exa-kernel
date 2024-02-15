DEBUG ?= 0
EMCC ?= emcc

all: exa/netfs.js exa/netfs.wasm

exa/netfs.js exa/netfs.wasm &: src/netfs.c src/netcache.c | exa
	$(EMCC) $^ -o exa/netfs.js -I../include -sASYNCIFY -sINITIAL_MEMORY=16MB -sTOTAL_STACK=512kB -sASYNCIFY_STACK_SIZE=256000 -sALLOW_MEMORY_GROWTH=1 -sASYNCIFY_IMPORTS=do_fetch_head,do_fetch -g -DDEBUG=$(DEBUG)

exa:
	mkdir -p exa

clean:
	rm -f exa/netfs.js exa/netfs.wasm

.PHONY: all clean
