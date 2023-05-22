#!/bin/sh

../../../../emscripten/emcc src/tty.c ../common/circular_buffer.c -o exa/tty.js -I../include -I../common -sASYNCIFY -sTOTAL_MEMORY=1024KB -sTOTAL_STACK=256kB -O3
