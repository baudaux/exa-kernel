DEBUG ?= 0
EMCC ?= emcc

all: exa/fb.js exa/fb.wasm

exa/fb.js exa/fb.wasm &: src/fb.c | exa
	$(EMCC) $^ -o exa/fb.js -I../include -I../common -sASYNCIFY -sTOTAL_MEMORY=10MB -sTOTAL_STACK=256kB -O3 -DDEBUG=$(DEBUG)

exa:
	mkdir -p exa

clean:
	rm -f exa/fb.js exa/fb.wasm

.PHONY: all clean
