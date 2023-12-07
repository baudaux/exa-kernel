#!/bin/sh

set -x

../../../../emscripten/emcc src/av.c -o exa/av.js -I../include -I../common -sASYNCIFY -sINITIAL_MEMORY=16MB -sTOTAL_STACK=512kB -sASYNCIFY_STACK_SIZE=256000 -sALLOW_MEMORY_GROWTH=1 -O3 -sASYNCIFY_IMPORTS=probe_media_devices "$@"
