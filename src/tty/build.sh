#!/bin/sh

set -x

../../../../emscripten/emcc src/tty.c ../common/circular_buffer.c -o exa/tty.js -I../include -I../common -sASYNCIFY -sTOTAL_MEMORY=10MB -sTOTAL_STACK=512kB -sASYNCIFY_STACK_SIZE=256000 -O3 "$@"
