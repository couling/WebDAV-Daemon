-include build/*.d

all: build/webdavd build/rap

build/webdavd build/rap: shared.c

build/%: %.c | build
	gcc -std=c99 -o $@ -O3 $(filter %.c,$^) -MMD -lmicrohttpd

build:
	mkdir $@
    
clean:
	rm -rf build