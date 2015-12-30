all: build/webdav

build/webdav: main.c | build
	gcc -std=c99 -o $@ -O3 $< -lmicrohttpd

build:
	mkdir $@
    
clean:
	rm -rf build