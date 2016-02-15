GCC_COMPILE_PART=gcc -std=gnu99 -pthread -g -o $@ -MMD $(filter %.c,$^) $(filter %.o,$^)

all: build/webdavd build/rap

#-O3
#-g

build/webdavd: build/webdavd.o build/shared.o build/configuration.o | build
	${GCC_COMPILE_PART} -lmicrohttpd -lxml2 -lgnutls

build/rap: build/rap.o build/shared.o | build
	${GCC_COMPILE_PART} -lpam -lxml2

build/%.o: %.c | build
	${GCC_COMPILE_PART} -I/usr/include/libxml2 -c

build:
	mkdir $@
	
clean:
	rm -rf build

-include build/*.d
