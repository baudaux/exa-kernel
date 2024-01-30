DEBUG ?= 0
EMCC ?= emcc

all: exa/av.js exa/av.wasm

exa/av.js exa/av.wasm &: src/av.c | exa
	$(EMCC) $^ -o exa/av.js -I../include -I../common -sASYNCIFY -sINITIAL_MEMORY=16MB -sTOTAL_STACK=512kB -sASYNCIFY_STACK_SIZE=256000 -sALLOW_MEMORY_GROWTH=1 -O3 -sASYNCIFY_IMPORTS=probe_media_devices -DDEBUG=$(DEBUG)

exa:
	mkdir -p exa

clean:
	rm -f exa/av.js exa/av.wasm

.PHONY: all clean
