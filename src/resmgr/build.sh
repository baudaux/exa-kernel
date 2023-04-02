#!/bin/sh

../../../../emscripten/emcc src/resmgr.c src/vfs.c src/device.c src/process.c src/unordered_map.c -o exa/resmgr.js -I../include -sTOTAL_MEMORY=1MB -sTOTAL_STACK=128kB -O2
