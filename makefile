-include build/*.d

all: build/webdavd build/rap build/testrap build/items.txt

build/items.txt:
	cp items.txt build/items.txt

build/webdavd build/rap build/testrap: shared.c

build/%: %.c | build
	gcc -std=gnu99 -Werror -o $@ -O3 $(filter %.c,$^) -MMD -lmicrohttpd

build:
	mkdir $@
    
clean:
	rm -rf build

