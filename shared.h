#ifndef WEBDAV_SHARED_H
#define WEBDAV_SHARED_H

#define RAP_PATH "/usr/sbin/rap"
#define RAP_PATH_MAX 4096
struct User {
	char * user;
	char * password;
};

enum RAPAction {
	OPEN_FILE
};

enum RAPResult {
	READ_SUCCESS, READ_WRITE_SUCCESS, AUTH_BOUNCE
};

struct DataSession {
	int fdIn;
	int fdOut;
};

void * mallocSafe(size_t size);

int forkPipeExec(const char * program, char * const argv[], struct DataSession * dataSession, int errFd);

#endif
