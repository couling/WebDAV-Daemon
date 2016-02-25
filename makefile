CFLAGS=-O3 -s
GCC_COMPILE_PART=gcc ${CFLAGS} -Werror -Wall -Wno-pointer-sign -std=gnu99 -pthread -o $@ -MMD $(filter %.c,$^) $(filter %.o,$^)

all: build/webdavd build/rap

build/webdavd: build/webdavd.o build/shared.o build/configuration.o build/rap-control.o build/xml.o build/lockdb.o| build
	${GCC_COMPILE_PART} -lmicrohttpd -lxml2 -lgnutls

build/rap: build/rap.o build/shared.o build/xml.o| build
	${GCC_COMPILE_PART} -lpam -lxml2

build/%.o: %.c | build
	${GCC_COMPILE_PART} -I/usr/include/libxml2 -c

build:
	mkdir $@
	
clean:
	rm -rf build
	
package: all
	cd build; package-project ../manifest

-include build/*.d
