DEBUG ?= 0
EMCC ?= emcc

all: exa/pipe.js exa/pipe.wasm

exa/pipe.js exa/pipe.wasm &: src/pipe.c ../common/circular_buffer.c ../common/jobs.c | exa
	$(EMCC) $^ -o exa/pipe.js -I../include -I../common -sASYNCIFY -sINITIAL_MEMORY=16MB -sALLOW_MEMORY_GROWTH=1 -sTOTAL_STACK=128kB -O3 -DDEBUG=$(DEBUG)

exa:
	mkdir -p exa

clean:
	rm -f exa/pipe.js exa/pipe.wasm

.PHONY: all clean
