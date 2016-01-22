-include build/*.d

all: build/webdavd build/rap build/testrap

build/webdavd build/rap build/testrap: shared.c

#-O3

build/%: %.c | build
	gcc -std=gnu99 -Werror -o $@ -g $(filter %.c,$^) -MMD -lmicrohttpd -lpam

build:
	mkdir $@
    
clean:
	rm -rf build

