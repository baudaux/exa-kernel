DEBUG ?= 0
EMCC ?= emcc

all: exa/ip.js exa/ip.wasm

exa/ip.js exa/ip.wasm &: src/ip.c | exa
	$(EMCC) $^ -o exa/ip.js -I../include -I../common -sASYNCIFY -sINITIAL_MEMORY=16MB -sTOTAL_STACK=512kB -sASYNCIFY_STACK_SIZE=256000 -sALLOW_MEMORY_GROWTH=1 -O3 -DDEBUG=$(DEBUG)

exa:
	mkdir -p exa

clean:
	rm -f exa/ip.js exa/ip.wasm

.PHONY: all clean
