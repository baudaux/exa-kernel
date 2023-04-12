#!/bin/sh

../../../../emscripten/emcc src/resmgr.c src/vfs.c src/device.c src/process.c src/unordered_map.c -o exa/resmgr.js -I../include -sTOTAL_MEMORY=10MB -sTOTAL_STACK=512kB -O2 -sALLOW_MEMORY_GROWTH=1
