#ifndef WEBDAV_SHARED_H
#define WEBDAV_SHARED_H

#include <stdlib.h>
#include <sys/socket.h>
#include <stdarg.h>
#include <libxml/xmlreader.h>

enum RapConstant {
	RAP_AUTHENTICATE = 1,
	RAP_READ_FILE,
	RAP_WRITE_FILE,
	RAP_PROPFIND,

	RAP_SUCCESS,
	RAP_MULTISTATUS,
	RAP_CONTINUE,
	RAP_NOT_FOUND,
	RAP_ACCESS_DENIED,
	RAP_AUTH_FAILLED,
	RAP_INSUFFICIENT_STORAGE,
	RAP_CONFLICT,
	RAP_BAD_CLIENT_REQUEST,
	RAP_INTERNAL_ERROR,
	RAP_BAD_RAP_REQUEST,

	RAP_MIN_REQUEST = RAP_AUTHENTICATE,
	RAP_MAX_REQUEST = RAP_PROPFIND,
	RAP_MIN_RESPONSE = RAP_SUCCESS,
	RAP_MAX_RESPONSE = RAP_BAD_RAP_REQUEST
};

#define RAP_USER_INDEX 0
#define RAP_PASSWORD_INDEX 1
#define RAP_RHOST_INDEX 2

#define RAP_HOST_INDEX  0
#define RAP_FILE_INDEX  1
#define RAP_DEPTH_INDEX 2

#define RAP_DATE_INDEX     0
#define RAP_MIME_INDEX     1
#define RAP_LOCATION_INDEX 2

#define PIPE_READ      0
#define PIPE_WRITE     1

#define WEBDAV_NAMESPACE "DAV:"

void * mallocSafe(size_t size);
void * reallocSafe(void * mem, size_t newSize);
char * copyString(const char * string);

char * timeNow(char * t);
size_t getWebDate(time_t rawtime, char * buf, size_t bufSize);

void stdLog(const char * str, ...);
void stdLogError(int errorNumber, const char * str, ...);

#define MAX_BUFFER_PARTS 3
#define INCOMING_BUFFER_SIZE 4096

struct Message {
	enum RapConstant mID;
	int fd;
	int bufferCount;
	struct iovec buffers[MAX_BUFFER_PARTS];
};

ssize_t sendMessage(int sock, struct Message * message);
ssize_t recvMessage(int sock, struct Message * message, char * incomingBuffer, size_t incomingBufferSize);
char * iovecToString(struct iovec * iovec);

int lockToUser(const char * user);

// XML
void suppressReaderErrors(xmlTextReaderPtr reader);
int stepInto(xmlTextReaderPtr reader);
int stepOver(xmlTextReaderPtr reader);
int stepOut(xmlTextReaderPtr reader);
int stepOverText(xmlTextReaderPtr reader, const char ** text);
int elementMatches(xmlTextReaderPtr reader, const char * namespace, const char * nodeName);
const char * nodeTypeToName(int nodeType);

char * loadFileToBuffer(const char * file, size_t * size);
#endif
