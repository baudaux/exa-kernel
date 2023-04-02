#!/bin/sh

../../../../emscripten/emcc src/tty.c -o exa/tty.js -I../include -sASYNCIFY -sTOTAL_MEMORY=1024KB -sTOTAL_STACK=256kB -O2
