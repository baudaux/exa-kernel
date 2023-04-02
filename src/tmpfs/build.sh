#!/bin/sh

../../../../emscripten/emcc src/tmpfs.c src/tmpnode.c -o exa/tmpfs.js -I../include -sASYNCIFY -sTOTAL_MEMORY=64KB -sTOTAL_STACK=32kB
