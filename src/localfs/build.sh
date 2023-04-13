#!/bin/sh

../../../../emscripten/emcc src/localfs.c src/lfs_block.c src/lfs.c src/lfs_util.c -o exa/localfs.js -I../include -sASYNCIFY -sTOTAL_MEMORY=10MB -sTOTAL_STACK=512kB -O2 -sASYNCIFY_IMPORTS=lfs_blk_read,lfs_blk_erase,lfs_blk_prog
