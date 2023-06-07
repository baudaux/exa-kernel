#!/bin/sh

set -x

../../../../emscripten/emcc src/netfs.c -o exa/netfs.js -I../include -sASYNCIFY -sTOTAL_MEMORY=10MB -sTOTAL_STACK=256kB -sASYNCIFY_IMPORTS=do_fetch_head,do_fetch -O2 "$@"
