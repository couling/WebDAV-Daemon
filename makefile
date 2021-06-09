CFLAGS=-O3 -s
STATIC_FLAGS=-Werror -Wall -Wno-pointer-sign  -Wno-unused-result -std=gnu99 -pthread

ifdef HAVE_SYSTEMD
DEFS+=-DHAVE_SYSTEMD=1
LIBSYSTEMD=-lsystemd
endif

all: build/rap build/webdavd
	ls -lh $^

build/webdavd: build/webdavd.o build/shared.o build/configuration.o build/xml.o
	gcc ${CFLAGS} ${STATIC_FLAGS} -o $@ $(filter %.o,$^) -lmicrohttpd -lxml2 -lgnutls -luuid ${LIBSYSTEMD}

build/rap: build/rap.o build/shared.o build/xml.o
	gcc ${CFLAGS} ${STATIC_FLAGS} -o $@ $(filter %.o,$^) -lpam -lxml2

build/%.o: %.c makefile | build
	gcc ${CFLAGS} ${STATIC_FLAGS} ${DEFS} -MMD -o $@ $(filter %.c,$^) -I/usr/include/libxml2 -c

build:
	mkdir $@
	
clean:
	rm -rf build
	
package: all
	cd build; package-project ../manifest

-include build/*.d
