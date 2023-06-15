#!/bin/sh

set -x

../../../../emscripten/emcc src/netfs.c src/netcache.c -o exa/netfs.js -I../include -sASYNCIFY -sINITIAL_MEMORY=16MB -sTOTAL_STACK=512kB -sASYNCIFY_STACK_SIZE=256000 -sALLOW_MEMORY_GROWTH=1 -sASYNCIFY_IMPORTS=do_fetch_head,do_fetch -O3 "$@"
