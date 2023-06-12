#!/bin/sh

set -x

../../../../emscripten/emcc src/resmgr.c src/vfs.c src/device.c src/process.c ../common/jobs.c -o exa/resmgr.js -I../include -I../common -sTOTAL_MEMORY=10MB -sTOTAL_STACK=512kB -sASYNCIFY_STACK_SIZE=256000 -sALLOW_MEMORY_GROWTH=1 -O3 "$@"
