#ifndef WEBDAV_SHARED_H
#define WEBDAV_SHARED_H

#include <stdlib.h>
#include <sys/socket.h>
#include <stdarg.h>
#include <libxml/xmlreader.h>

#define RAP_CONTROL_SOCKET 3

enum RapConstant {
	RAP_AUTHENTICATE = 1,
	RAP_READ_FILE,
	RAP_WRITE_FILE,
	RAP_PROPFIND,

	RAP_SUCCESS = 200,
	RAP_MULTISTATUS = 207,
	RAP_CONTINUE = 100,
	RAP_NOT_FOUND = 404,
	RAP_ACCESS_DENIED = 403,
	RAP_AUTH_FAILLED = 401,
	RAP_INSUFFICIENT_STORAGE = 507,
	RAP_CONFLICT = 409,
	RAP_BAD_CLIENT_REQUEST = 400,
	RAP_INTERNAL_ERROR = 500
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

#define PARENT_SOCKET 0
#define CHILD_SOCKET  1

#define WEBDAV_NAMESPACE "DAV:"

void * mallocSafe(size_t size);
void * reallocSafe(void * mem, size_t newSize);
char * copyString(const char * string);

char * timeNow(char * t);
size_t getWebDate(time_t rawtime, char * buf, size_t bufSize);

void stdLog(const char * str, ...);
void stdLogError(int errorNumber, const char * str, ...);

#define MAX_MESSAGE_PARAMS 3
#define INCOMING_BUFFER_SIZE 4096

typedef struct iovec MessageParam;

typedef struct Message {
	enum RapConstant mID;
	int fd;
	int bufferCount;
	MessageParam params[MAX_MESSAGE_PARAMS];
} Message;

ssize_t sendMessage(int sock, Message * message);
ssize_t recvMessage(int sock, Message * message, char * incomingBuffer, size_t incomingBufferSize);
char * messageParamToString(MessageParam * iovec);

int lockToUser(const char * user);

// XML
void xmlReaderSuppressErrors(xmlTextReaderPtr reader);
int stepInto(xmlTextReaderPtr reader);
int stepOver(xmlTextReaderPtr reader);
int stepOut(xmlTextReaderPtr reader);
int stepOverText(xmlTextReaderPtr reader, const char ** text);
int elementMatches(xmlTextReaderPtr reader, const char * namespace, const char * nodeName);
const char * nodeTypeToName(int nodeType);

char * loadFileToBuffer(const char * file, size_t * size);
#endif
