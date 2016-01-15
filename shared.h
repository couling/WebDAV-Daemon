#ifndef WEBDAV_SHARED_H
#define WEBDAV_SHARED_H

#include <stdlib.h>
#include <sys/socket.h>
#include <stdarg.h>

#define RAP_PATH "/usr/sbin/rap"

enum RapConstant {
	RAP_INVALID_METHOD,

	RAP_AUTHENTICATE,
	RAP_READ_FILE,
	RAP_WRITE_FILE,
	RAP_LIST_FOLDER,

	RAP_SUCCESS,
	RAP_NOT_FOUND,
	RAP_ACCESS_DENIED,
	RAP_AUTH_FAILLED,
	RAP_BAD_REQUEST,

	RAP_MIN_REQUEST = RAP_AUTHENTICATE,
	RAP_MAX_REQUEST = RAP_LIST_FOLDER,
	RAP_MIN_RESPONSE = RAP_SUCCESS,
	RAP_MAX_RESPONSE = RAP_BAD_REQUEST
};

#define RAP_USER_INDEX 0
#define RAP_PASSWORD_INDEX 1

#define RAP_HOST_INDEX 0
#define RAP_FILE_INDEX 1

void * mallocSafe(size_t size);
void stdLog(const char * str, ...);
void stdLogError(int errorNumber, const char * str, ...);

#define MAX_BUFFER_PARTS 2

ssize_t sendMessage(int sock, enum RapConstant mID, int fd, int bufferCount, struct iovec buffer[]);
ssize_t recvMessage(int sock, enum RapConstant * mID, int * fd, int * bufferCount, struct iovec * buffers);



#endif
