#ifndef WEBDAV_SHARED_H
#define WEBDAV_SHARED_H

#define _FILE_OFFSET_BITS 64

#include <sys/file.h>
#include <sys/socket.h>
#include <stdarg.h>

#define RAP_CONTROL_SOCKET 3

typedef enum RapConstant {
	RAP_REQUEST_AUTHENTICATE = 1,

	// sent by startProcessingRequest to start processing an HTTP method
	RAP_REQUEST_GET,
	RAP_REQUEST_PUT,
	RAP_REQUEST_PROPFIND,
	RAP_REQUEST_PROPPATCH,
	RAP_REQUEST_LOCK,
	RAP_REQUEST_MKCOL,
	RAP_REQUEST_MOVE,
	RAP_REQUEST_DELETE,

	// sent by rap, processed by finishProcessingRequest
	RAP_INTERIM_RESPOND_LOCK,
	RAP_INTERIM_RESPOND_RELOCK,

	// sent by finishProcessingRequest to complete processing a request
	RAP_COMPLETE_REQUEST_LOCK,

	// sent by rap once a request has completed - deliberately HTTP response codes
	RAP_RESPOND_CONTINUE = 100,
	RAP_RESPOND_OK = 200,
	RAP_RESPOND_CREATED = 201,
	RAP_RESPOND_OK_NO_CONTENT = 204,
	RAP_RESPOND_MULTISTATUS = 207,
	RAP_RESPOND_BAD_CLIENT_REQUEST = 400,
	RAP_RESPOND_AUTH_FAILLED = 401,
	RAP_RESPOND_ACCESS_DENIED = 403,
	RAP_RESPOND_NOT_FOUND = 404,
	RAP_RESPOND_CONFLICT = 409,
	RAP_RESPOND_LOCKED = 423,
	RAP_RESPOND_INTERNAL_ERROR = 500,
	RAP_RESPOND_INSUFFICIENT_STORAGE = 507

} RapConstant;

// Auth Request
#define RAP_PARAM_AUTH_USER         0
#define RAP_PARAM_AUTH_PASSWORD     1
#define RAP_PARAM_AUTH_RHOST        2

// Generic Requet
#define RAP_PARAM_REQUEST_LOCK      0
#define RAP_PARAM_REQUEST_FILE      1
#define RAP_PARAM_REQUEST_DEPTH     2

// Generic Response
#define RAP_PARAM_RESPONSE_DATE     0
#define RAP_PARAM_RESPONSE_MIME     1
#define RAP_PARAM_RESPONSE_LOCATION 2

// Lock interim response
#define RAP_PARAM_LOCK_LOCATION     0
#define RAP_PARAM_LOCK_TYPE         1
#define RAP_PARAM_LOCK_TOKEN        1
#define RAP_PARAM_LOCK_TIMEOUT      2

// Error responses
#define RAP_PARAM_ERROR_LOCATION    0
#define RAP_PARAM_ERROR_REASON      1
#define RAP_PARAM_ERROR_NAMESPACE   2

#define PIPE_READ     0
#define PIPE_WRITE    1

#define PARENT_SOCKET 0
#define CHILD_SOCKET  1

typedef char LockToken[37];

#define LOCK_TOKEN_URN_PREFIX "urn:uuid:"
#define LOCK_TOKEN_PREFIX "<urn:uuid:"
#define LOCK_TOKEN_PREFIX_LENGTH (sizeof(LOCK_TOKEN_PREFIX) - 1)
#define LOCK_TOKEN_SUFFIX ">"
#define LOCK_TOKEN_LENGTH (LOCK_TOKEN_PREFIX_LENGTH + sizeof(LockToken) + sizeof(LOCK_TOKEN_SUFFIX))

typedef enum LockType {
	LOCK_TYPE_SHARED = LOCK_SH | LOCK_NB,
	LOCK_TYPE_EXCLUSIVE = LOCK_EX | LOCK_NB
} LockType;

/*
 * #define QUOTE(name) #name
 * #define STR(macro) QUOTE(macro)
 *
 */

void * mallocSafe(size_t size);
void * reallocSafe(void * mem, size_t newSize);
#define freeSafe(foo) /*stdLog("%p free(%s)", foo, QUOTE(foo) );*/ free(foo)
char * copyString(const char * string);

size_t timeNow(char * buf, size_t bufSize);
size_t getWebDate(time_t rawtime, char * buf, size_t bufSize);
size_t getLocalDate(time_t rawtime, char * buf, size_t bufSize);

void stdLog(const char * str, ...);
void stdLogError(int errorNumber, const char * str, ...);

#define MAX_MESSAGE_PARAMS 3
#define INCOMING_BUFFER_SIZE 4096
typedef struct iovec MessageParam;
#define NULL_PARAM ( ( MessageParam ) { .iov_base = NULL, .iov_len = 0} )

typedef struct Message {
	enum RapConstant mID;
	int fd;
	int paramCount;
	MessageParam params[MAX_MESSAGE_PARAMS];
} Message;

ssize_t sendMessage(int sock, Message * message);
ssize_t recvMessage(int sock, Message * message, char * incomingBuffer, size_t incomingBufferSize);
ssize_t sendRecvMessage(int sock, Message * message, char * incomingBuffer, size_t incomingBufferSize);

char * messageParamToString(MessageParam * iovec);
MessageParam stringToMessageParam(const char * string);

int lockToUser(const char * user);

char * loadFileToBuffer(const char * file, size_t * size);

#endif
