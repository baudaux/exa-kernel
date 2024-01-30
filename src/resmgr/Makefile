DEBUG ?= 0
EMCC ?= emcc

all: exa/resmgr.js exa/resmgr.wasm

exa/resmgr.js exa/resmgr.wasm &: src/resmgr.c src/vfs.c src/device.c src/process.c ../common/jobs.c | exa
	$(EMCC) $^ -o exa/resmgr.js -I../include -I../common -sTOTAL_MEMORY=10MB -sTOTAL_STACK=512kB -sASYNCIFY_STACK_SIZE=256000 -sALLOW_MEMORY_GROWTH=1 -O3 -DDEBUG=$(DEBUG)

exa:
	mkdir -p exa

clean:
	rm -f exa/resmgr.js exa/resmgr.wasm

.PHONY: all clean
