-include build/*.d

all: build/webdavd build/rap

#-O3

build/webdavd: webdavd.c shared.c | build
	gcc -std=gnu99 -Werror -o $@ -g -pthread  $(filter %.c,$^) -MMD -lmicrohttpd

build/rap: rap.c shared.c | build
	gcc -std=gnu99 -Werror -o $@ -g -I/usr/include/libxml2 $(filter %.c,$^) -MMD -lpam -lxml2

build:
	mkdir $@
	
clean:
	rm -rf build

