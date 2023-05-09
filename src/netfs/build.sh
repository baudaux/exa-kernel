#!/bin/sh

../../../../emscripten/emcc src/netfs.c -o exa/netfs.js -I../include -sASYNCIFY -sTOTAL_MEMORY=1MB -sTOTAL_STACK=128kB -sASYNCIFY_IMPORTS=do_fetch_head,do_fetch -O3
