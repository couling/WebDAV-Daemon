#ifndef WEBDAV_SHARED_H
#define WEBDAV_SHARED_H

#include <stdlib.h>
#include <sys/socket.h>
#include <stdarg.h>

enum RapConstant {
	RAP_AUTHENTICATE = 1,
	RAP_READ_FILE,
	RAP_WRITE_FILE,
	RAP_PROPFIND,

	RAP_SUCCESS,
	RAP_CONTINUE,
	RAP_NOT_FOUND,
	RAP_ACCESS_DENIED,
	RAP_AUTH_FAILLED,
	RAP_INTERNAL_ERROR,
	RAP_BAD_REQUEST,

	RAP_MIN_REQUEST = RAP_AUTHENTICATE,
	RAP_MAX_REQUEST = RAP_PROPFIND,
	RAP_MIN_RESPONSE = RAP_SUCCESS,
	RAP_MAX_RESPONSE = RAP_BAD_REQUEST
};

#define RAP_USER_INDEX 0
#define RAP_PASSWORD_INDEX 1

#define RAP_HOST_INDEX  0
#define RAP_FILE_INDEX  1
#define RAP_DEPTH_INDEX 2

#define RAP_DATE_INDEX     0
#define RAP_FILE_INDEX     1
#define RAP_LOCATION_INDEX 2

#define PIPE_READ      0
#define PIPE_WRITE     1

void * mallocSafe(size_t size);
void * reallocSafe(void * mem, size_t newSize);

void stdLog(const char * str, ...);
void stdLogError(int errorNumber, const char * str, ...);

#define MAX_BUFFER_PARTS 3
#define INCOMING_BUFFER_SIZE 4096
ssize_t sendMessage(int sock, enum RapConstant mID, int fd, int bufferCount, struct iovec buffer[]);
ssize_t recvMessage(int sock, enum RapConstant * mID, int * fd, int * bufferCount, struct iovec * buffers, char * incomingBuffer, size_t incomingBufferSize);
char * iovecToString(struct iovec * iovec);
#endif
