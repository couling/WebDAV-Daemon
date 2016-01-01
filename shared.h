#ifndef WEBDAV_SHARED_H
#define WEBDAV_SHARED_H

typedef enum {
	OPEN_FILE
} RAPAction;

typedef enum {
	READ_SUCCESS,
	READ_WRITE_SUCCESS,
	AUTH_BOUNCE
} RAPResult;

typedef struct {
	int fdIn;
	int fdOut;
} DataSession;

void * mallocSafe(size_t size);

int forkExec(const char * program, char *const argv[], DataSession * dataSession, int errFd);

#endif
