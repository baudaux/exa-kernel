#!/bin/sh

set -x

../../../../emscripten/emcc src/localfs.c src/lfs_block.c src/lfs.c src/lfs_util.c -o exa/localfs.js -I../include -sASYNCIFY -sTOTAL_MEMORY=10MB -sTOTAL_STACK=512kB -DLFS_NO_DEBUG -DLFS_NO_WARN -DLFS_NO_ERROR -O2 -sASYNCIFY_IMPORTS=lfs_blk_read,lfs_blk_erase,lfs_blk_prog "$@"
