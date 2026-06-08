DEBUG ?= 0
EMCC ?= emcc

all: exa/llm.js exa/llm.wasm

exa/llm.js exa/llm.wasm &: src/llm.c | exa
	$(EMCC) $^ -o exa/llm.js -I../include -I../common -sASYNCIFY -sTOTAL_MEMORY=10MB -sTOTAL_STACK=512kB -sASYNCIFY_STACK_SIZE=256000 -O3 -DDEBUG=$(DEBUG)

exa:
	mkdir -p exa

clean:
	rm -f exa/llm.js exa/llm.wasm

.PHONY: all clean
