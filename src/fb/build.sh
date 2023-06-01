#!/bin/sh

set -x

../../../../emscripten/emcc src/fb.c -o exa/fb.js -I../include -I../common -sASYNCIFY -sTOTAL_MEMORY=10MB -sTOTAL_STACK=256kB -O3 "$@"
