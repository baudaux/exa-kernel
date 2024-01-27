DEBUG ?= 0
EMCC ?= emcc

all:
	make -C ./src/av DEBUG=$(DEBUG) EMCC=$(EMCC)
	make -C ./src/fb DEBUG=$(DEBUG) EMCC=$(EMCC)
	make -C ./src/ip DEBUG=$(DEBUG) EMCC=$(EMCC)
	make -C ./src/localfs DEBUG=$(DEBUG) EMCC=$(EMCC)
	make -C ./src/netfs DEBUG=$(DEBUG) EMCC=$(EMCC)
	make -C ./src/pipe DEBUG=$(DEBUG) EMCC=$(EMCC)
	make -C ./src/resmgr DEBUG=$(DEBUG) EMCC=$(EMCC)
	make -C ./src/tty DEBUG=$(DEBUG) EMCC=$(EMCC)

clean:
	make -C ./src/av clean
	make -C ./src/fb clean
	make -C ./src/ip clean
	make -C ./src/localfs clean
	make -C ./src/netfs clean
	make -C ./src/pipe clean
	make -C ./src/resmgr clean
	make -C ./src/tty clean

.PHONY: all clean
