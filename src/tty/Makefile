DEBUG ?= 0
EMCC ?= emcc

all: exa/tty.js exa/tty.wasm

exa/tty.js exa/tty.wasm &: src/tty.c ../common/circular_buffer.c | exa
	$(EMCC) $^ -o exa/tty.js -I../include -I../common -sASYNCIFY -sTOTAL_MEMORY=10MB -sTOTAL_STACK=512kB -sASYNCIFY_STACK_SIZE=256000 -O3 -DDEBUG=$(DEBUG)

exa:
	mkdir -p exa

clean:
	rm -f exa/tty.js exa/tty.wasm

.PHONY: all clean
