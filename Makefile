DEBUG ?= 0
EMCC ?= emcc

SUBDIRS = av fb ip localfs netfs pipe resmgr tty remotefs

SUBDIRS_CLEAN = $(foreach dir,$(SUBDIRS),$(dir)-clean)

all: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C ./src/$@ DEBUG=$(DEBUG) EMCC=$(EMCC)

clean: $(SUBDIRS_CLEAN)

$(SUBDIRS_CLEAN):
	$(MAKE) -C ./src/$(subst -clean,,$@) clean

.PHONY: $(SUBDIRS) $(SUBDIRS_CLEAN) all clean
