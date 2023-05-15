#!/bin/sh

../../../../emscripten/emcc src/pipe.c -o exa/pipe.js -I../include -sASYNCIFY -sTOTAL_MEMORY=1MB -sTOTAL_STACK=128kB -O3
