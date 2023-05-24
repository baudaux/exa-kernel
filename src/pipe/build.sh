#!/bin/sh

../../../../emscripten/emcc src/pipe.c ../common/circular_buffer.c ../common/jobs.c -o exa/pipe.js -I../include -I../common -sASYNCIFY -sTOTAL_MEMORY=10MB -sTOTAL_STACK=128kB -O3
