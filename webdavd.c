// TODO ssl
// TODO auth modes other than basic?
// TODO correct failure codes on collections
// TODO configuration file & getopt


#include "shared.h"

#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <limits.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <microhttpd.h>
#include <errno.h>

#define RAP_PATH "/usr/sbin/rap"
#define MIME_FILE_PATH "/etc/mime.types"

#define ACCEPT_HEADER "OPTIONS, GET, HEAD, DELETE, PROPFIND, PUT, PROPPATCH, COPY, MOVE, LOCK, UNLOCK"

struct RestrictedAccessProcessor {
	int pid;
	int socketFd;
	char * user;
	char * password;
	int writeDataFd;
	int readDataFd;
	int responseAlreadyGiven;
};

// Used as a place holder for failed auth requests which failed due to invalid credentials
static const struct RestrictedAccessProcessor AUTH_FAILED_RAP = { .pid = 0, .socketFd = -1, .user = "<auth failed>",
		.password = "", .writeDataFd = -1, .readDataFd = -1, .responseAlreadyGiven = 1 };

// Used as a place holder for failed auth requests which failed due to errors
static const struct RestrictedAccessProcessor AUTH_ERROR_RAP = { .pid = 0, .socketFd = -1, .user = "<auth error>",
		.password = "", .writeDataFd = -1, .readDataFd = -1, .responseAlreadyGiven = 1 };

#define AUTH_FAILED ((struct RestrictedAccessProcessor *)&AUTH_FAILED_RAP)
#define AUTH_ERROR ((struct RestrictedAccessProcessor *)&AUTH_ERROR_RAP)

struct MimeType {
	const char * ext;
	const char * type;
};

struct Header {
	const char * key;
	const char * value;
};

static struct MHD_Daemon **daemons;
static int daemonPorts[] = { 8080 };
static int daemonCount = sizeof(daemonPorts) / sizeof(daemonPorts[0]);
size_t mimeFileBufferSize;
char * mimeFileBuffer;
struct MimeType * mimeTypes = NULL;
int mimeTypeCount = 0;

static struct MHD_Response * INTERNAL_SERVER_ERROR_PAGE;
static struct MHD_Response * UNAUTHORIZED_PAGE;
static struct MHD_Response * METHOD_NOT_SUPPORTED_PAGE;

///////////////////////
// Response Queueing //
///////////////////////

//#define queueAuthRequiredResponse(request) ( MHD_queue_response(request, MHD_HTTP_UNAUTHORIZED, UNAUTHORIZED_PAGE) )
//#define queueInternalServerError(request) ( MHD_queue_response(request, MHD_HTTP_INTERNAL_SERVER_ERROR, INTERNAL_SERVER_ERROR_PAGE) )

static void logAccess(int statusCode, const char * method, const char * user, const char * url) {
	stdLog("%d %s %s %s", statusCode, method, user, url);
}

static void addHeaderSafe(struct MHD_Response * response, const char * headerKey, const char * headerValue) {
	if (headerValue == NULL) {
		stdLogError(0, "Attempt to add null value as header %s:", headerKey);
		return;
	}
	if (MHD_add_response_header(response, headerKey, headerValue) != MHD_YES) {
		stdLogError(errno, "Could not add response header %s: %s", headerKey, headerValue);
		exit(255);
	}
}

static int compareExt(const void * a, const void * b) {
	return strcmp(((struct MimeType *) a)->ext, ((struct MimeType *) b)->ext);
}

static struct MimeType * findMimeType(const char * file) {
	if (!file) {
		return NULL;
	}
	struct MimeType type;
	type.ext = file + strlen(file) - 1;
	while (1) {
		if (*type.ext == '/') {
			return NULL;
		} else if (*type.ext == '.') {
			type.ext++;
			break;
		} else {
			type.ext--;
			if (type.ext < file) {
				return NULL;
			}
		}
	}

	return bsearch(&type, mimeTypes, mimeTypeCount, sizeof(struct MimeType), &compareExt);
}

static ssize_t fdContentReader(int *fd, uint64_t pos, char *buf, size_t max) {
	size_t bytesRead = read(*fd, buf, max);
	if (bytesRead < 0) {
		stdLogError(errno, "Could not read content from fd");
		return MHD_CONTENT_READER_END_WITH_ERROR;
	}
	if (bytesRead == 0) {
		return MHD_CONTENT_READER_END_OF_STREAM;
	}
	while (bytesRead < max) {
		size_t newBytesRead = read(*fd, buf + bytesRead, max - bytesRead);
		if (newBytesRead <= 0) {
			break;
		}
		bytesRead += newBytesRead;
	}
	return bytesRead;
}

static void fdContentReaderCleanup(int *fd) {
	close(*fd);
	free(fd);
}

static struct MHD_Response * createFdStreamResponse(int fd, const char * mimeType, time_t date) {
	int * fdAllocated = mallocSafe(sizeof(int));
	*fdAllocated = fd;
	struct MHD_Response * response = MHD_create_response_from_callback(-1, 4096,
			(MHD_ContentReaderCallback) &fdContentReader, fdAllocated,
			(MHD_ContentReaderFreeCallback) &fdContentReaderCleanup);
	if (!response) {
		free(fdAllocated);
		return NULL;
	}
	char dateBuf[100];
	getWebDate(date, dateBuf, 100);
	addHeaderSafe(response, "Date", dateBuf);
	if (mimeType != NULL) {
		addHeaderSafe(response, "Content-Type", mimeType);
	}
	addHeaderSafe(response, "Dav", "1");
	return response;
}

static struct MHD_Response * createFdFileResponse(size_t size, int fd, const char * mimeType, time_t date) {
	struct MHD_Response * response = MHD_create_response_from_fd(size, fd);
	if (!response) {
		close(fd);
		return NULL;
	}
	char dateBuf[100];
	getWebDate(date, dateBuf, 100);
	addHeaderSafe(response, "Date", dateBuf);
	if (mimeType != NULL) {
		addHeaderSafe(response, "Content-Type", mimeType);
	}
	addHeaderSafe(response, "Dav", "1");
	return response;
}

static struct MHD_Response * createFileResponse(struct MHD_Connection *request, const char * fileName) {
	int fd = open(fileName, O_RDONLY);
	if (fd == -1) {
		stdLogError(errno, "Could not open file for response", fileName);
		return NULL;
	}

	struct stat statBuffer;
	fstat(fd, &statBuffer);
	struct MimeType * mimeType = findMimeType(fileName);

	return createFdFileResponse(statBuffer.st_size, fd, mimeType ? mimeType->type : NULL, statBuffer.st_mtime);
}

static int createRapResponse(struct MHD_Connection *request, struct Message * message, struct MHD_Response ** response) {
	// Queue the response
	switch (message->mID) {
	case RAP_MULTISTATUS:
	case RAP_SUCCESS: {
		// Get Mime type and date
		const char * mimeType = iovecToString(&message->buffers[RAP_FILE_INDEX]);
		time_t date = *((time_t *) message->buffers[RAP_DATE_INDEX].iov_base);
		const char * location =
				message->bufferCount > RAP_LOCATION_INDEX ? iovecToString(&message->buffers[RAP_LOCATION_INDEX]) : NULL;

		struct stat stat;
		fstat(message->fd, &stat);
		if (mimeType[0] == '\0') {
			if (location) {
				struct MimeType * found = findMimeType(location);
				mimeType = found ? found->type : NULL;
			} else {
				mimeType = NULL;
			}
		}

		if ((stat.st_mode & S_IFMT) == S_IFREG) {
			*response = createFdFileResponse(stat.st_size, message->fd, mimeType, date);
		} else {
			*response = createFdStreamResponse(message->fd, mimeType, date);
		}

		if (location) {
			addHeaderSafe(*response, "Location", location);
		}

		return (message->mID == RAP_SUCCESS ? MHD_HTTP_OK : 207);
	}

	case RAP_ACCESS_DENIED:
		*response = createFileResponse(request, "/usr/share/webdavd/HTTP_FORBIDDEN.html");
		return MHD_HTTP_FORBIDDEN;

	case RAP_NOT_FOUND:
		*response = createFileResponse(request, "/usr/share/webdavd/HTTP_NOT_FOUND.html");
		return MHD_HTTP_FORBIDDEN;

	case RAP_BAD_CLIENT_REQUEST:
		*response = createFileResponse(request, "/usr/share/webdavd/HTTP_BAD_REQUEST.html");
		return MHD_HTTP_BAD_REQUEST;

	default:
		stdLogError(0, "invalid response from RAP %d", (int) message->mID);
		/* no break */

	case RAP_BAD_RAP_REQUEST:
	case RAP_INTERNAL_ERROR:
		return MHD_HTTP_INTERNAL_SERVER_ERROR;
	}

}

///////////////////////////
// End Response Queueing //
///////////////////////////

////////////////////
// RAP Processing //
////////////////////

static int forkRapProcess(const char * path, int * newSockFd) {
	// Create unix domain socket for
	int sockFd[2];
	int result = socketpair(PF_LOCAL, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockFd);
	if (result != 0) {
		stdLogError(errno, "Could not create socket pair");
		return 0;
	}

	result = fork();

	if (result) {
		// parent
		close(sockFd[1]);
		if (result != -1) {
			*newSockFd = sockFd[0];
			//stdLog("New RAP %d on %d", result, sockFd[0]);
			return result;
		} else {
			// fork failed so close parent pipes and return non-zero
			close(sockFd[0]);
			stdLogError(errno, "Could not fork");
			return 0;
		}
	} else {
		// child
		// Sort out socket
		//stdLog("Starting rap: %s", path);
		if (dup2(sockFd[1], STDIN_FILENO) == -1 || dup2(sockFd[1], STDOUT_FILENO) == -1) {
			stdLogError(errno, "Could not assign new socket (%d) to stdin/stdout", newSockFd[1]);
			exit(255);
		}
		char * argv[] = { NULL };
		execv(path, argv);
		stdLogError(errno, "Could not start rap: %s", path);
		exit(255);
	}
}

static void destroyRap(struct RestrictedAccessProcessor * processor) {
	close(processor->socketFd);
	free(processor->user);
	free(processor);
}

static struct RestrictedAccessProcessor * createRap(struct MHD_Connection *request, const char * user,
		const char * password) {

	struct RestrictedAccessProcessor * processor = mallocSafe(sizeof(struct RestrictedAccessProcessor));
	processor->pid = forkRapProcess(RAP_PATH, &(processor->socketFd));
	if (!processor->pid) {
		free(processor);
		return AUTH_ERROR;
	}
	size_t userLen = strlen(user) + 1;
	size_t passLen = strlen(password) + 1;
	size_t bufferSize = userLen + passLen;
	processor->user = mallocSafe(bufferSize);
	processor->password = processor->user + userLen;
	memcpy(processor->user, user, userLen);
	memcpy(processor->password, password, passLen);
	struct Message message = { .mID = RAP_AUTHENTICATE, .fd = -1, .bufferCount = 2, .buffers = { { .iov_len = userLen,
			.iov_base = processor->user }, { .iov_len = passLen, .iov_base = processor->password } } };
	if (sendMessage(processor->socketFd, &message) <= 0) {
		destroyRap(processor);
		return AUTH_ERROR;
	}
	char incomingBuffer[INCOMING_BUFFER_SIZE];
	ssize_t readResult = recvMessage(processor->socketFd, &message, incomingBuffer, INCOMING_BUFFER_SIZE);
	if (readResult <= 0 || message.mID != RAP_SUCCESS) {
		destroyRap(processor);
		if (readResult < 0) {
			stdLogError(0, "Could not read result from RAP ");
			return AUTH_ERROR;
		} else if (readResult == 0) {
			stdLogError(0, "RAP closed socket unexpectedly");
			return AUTH_ERROR;
		} else {
			stdLogError(0, "Access denied for user %s %d %zd", user, message.mID, readResult);
			return AUTH_FAILED;
		}
	}

	return processor;
}

static void releaseRap(struct RestrictedAccessProcessor * processor) {
	//stdLog("release %d on %d", processor->pid, processor->socketFd);
	destroyRap(processor);
}

static struct RestrictedAccessProcessor * acquireRap(struct MHD_Connection *request) {
	// TODO reuse RAP
	char * user;
	char * password;
	user = MHD_basic_auth_get_username_password(request, &(password));
	struct RestrictedAccessProcessor * processor;
	if (user && password) {
		processor = createRap(request, user, password);
	} else {
		stdLogError(0, "Rejecting request without auth");
		processor = AUTH_FAILED;
	}
	//stdLog("acquire %d on %d", processor->pid, processor->socketFd);
	return processor;
}

static void cleanupAfterRap(int sig, siginfo_t *siginfo, void *context) {
	int status;
	waitpid(siginfo->si_pid, &status, 0);
	if (status == 139) {
		stdLogError(0, "RAP %d failed with segmentation fault", siginfo->si_pid);
	}
	//stdLog("Child finished PID: %d staus: %d", siginfo->si_pid, status);
}

////////////////////////
// End RAP Processing //
////////////////////////

///////////////////////////////////////
// Low Level HTTP handling (Signpost //
///////////////////////////////////////

static int filterGetHeader(struct Header * header, enum MHD_ValueKind kind, const char *key, const char *value) {
	if (!strcmp(key, header->key)) {
		header->value = value;
		return MHD_NO;
	}
	return MHD_YES;
}

static const char * getHeader(struct MHD_Connection *request, const char * headerKey) {
	struct Header header = { .key = headerKey, .value = NULL };
	MHD_get_connection_values(request, MHD_HEADER_KIND, (MHD_KeyValueIterator) &filterGetHeader, &header);
	return header.value;
}

static int completeUpload(struct MHD_Connection *request, struct RestrictedAccessProcessor * processor,
		struct MHD_Response ** response) {

	if (processor->writeDataFd == -1) {
		*response = createFileResponse(request, "/usr/share/webdavd/HTTP_INSUFFICIENT_STORAGE.html");
		return MHD_HTTP_INSUFFICIENT_STORAGE;
	} else {
		// Closing this pipe signals to the rap that there is no more data
		// This MUST happen before the recvMessage a few lines below or the RAP
		// will NOT send a message and recvMessage will hang.
		close(processor->writeDataFd);
		processor->writeDataFd = -1;
		struct Message message;
		char incomingBuffer[INCOMING_BUFFER_SIZE];
		int readResult = recvMessage(processor->socketFd, &message, incomingBuffer, INCOMING_BUFFER_SIZE);
		if (readResult <= 0) {
			if (readResult == 0) {
				stdLogError(0, "RAP closed socket unexpectedly while waiting for response");
			}
			return MHD_HTTP_INTERNAL_SERVER_ERROR;
		}

		if (readResult > 0) {
			return createRapResponse(request, &message, response);
		} else {
			return MHD_HTTP_INTERNAL_SERVER_ERROR;
		}
	}
}

static void processUploadData(struct MHD_Connection * request, const char * upload_data, size_t upload_data_size,
		struct RestrictedAccessProcessor * processor) {

	if (processor->writeDataFd != -1) {
		// size_t ignore = write(STDERR_FILENO, upload_data, *upload_data_size);
		size_t bytesWritten = write(processor->writeDataFd, upload_data, upload_data_size);
		if (bytesWritten < upload_data_size) {
			// not all data could be written to the file handle and therefore
			// the operation has now failed. There's nothing we can do now but report the error
			// This may not actually be desirable and so we need to consider slamming closed the connection.
			close(processor->writeDataFd);
			processor->writeDataFd = -1;
		}
	}
}

static int processNewRequest(struct MHD_Connection * request, const char * url, const char * host, const char * method,
		struct RestrictedAccessProcessor * rapSession, struct MHD_Response ** response) {

	// Interpret the method
	struct Message message;
	message.fd = rapSession->readDataFd;
	message.buffers[RAP_HOST_INDEX].iov_len = strlen(host) + 1;
	message.buffers[RAP_HOST_INDEX].iov_base = (void *) host;
	message.buffers[RAP_FILE_INDEX].iov_len = strlen(url) + 1;
	message.buffers[RAP_FILE_INDEX].iov_base = (void *) url;
	// TODO PUT
	// TODO PROPPATCH
	// TODO MKCOL
	// TODO HEAD
	// TODO DELETE
	// TODO COPY
	// TODO MOVE
	// TODO LOCK
	// TODO UNLOCK
	//stdLog("%s %s data", method, writeHandle ? "with" : "without");
	if (!strcmp("GET", method)) {
		message.mID = RAP_READ_FILE;
		message.bufferCount = 2;
	} else if (!strcmp("PROPFIND", method)) {
		message.mID = RAP_PROPFIND;
		const char * depth = getHeader(request, "Depth");
		if (depth) {
			message.buffers[RAP_DEPTH_INDEX].iov_base = (void *) depth;
			message.buffers[RAP_DEPTH_INDEX].iov_len = strlen(depth) + 1;
		} else {
			message.buffers[RAP_DEPTH_INDEX].iov_base = "infinity";
			message.buffers[RAP_DEPTH_INDEX].iov_len = sizeof("infinity");
		}
		message.bufferCount = 3;
	} else if (!strcmp("OPTIONS", method)) {
		*response = createFileResponse(request, "/usr/share/webdavd/OPTIONS.html");
		addHeaderSafe(*response, "Accept", ACCEPT_HEADER);
		return MHD_HTTP_OK;
	} else {
		stdLogError(0, "Can not cope with method: %s (%s data)", method,
				(rapSession->writeDataFd != -1 ? "with" : "without"));
		return MHD_HTTP_METHOD_NOT_ALLOWED;
	}

	// Send the request to the RAP
	size_t ioResult = sendMessage(rapSession->socketFd, &message);
	rapSession->readDataFd = -1; // this will always be closed by sendMessage even on failure!
	if (ioResult <= 0) {
		return MHD_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Get result from RAP
	char incomingBuffer[INCOMING_BUFFER_SIZE];
	ioResult = recvMessage(rapSession->socketFd, &message, incomingBuffer, INCOMING_BUFFER_SIZE);
	if (ioResult <= 0) {
		if (ioResult == 0) {
			stdLogError(0, "RAP closed socket unexpectedly while waiting for response");
		}
		return MHD_HTTP_INTERNAL_SERVER_ERROR;
	}

	if (message.mID == RAP_CONTINUE) {
		return MHD_HTTP_CONTINUE;
	} else {
		return createRapResponse(request, &message, response);
	}
}

static int requestHasData(struct MHD_Connection *request) {
	if (getHeader(request, "Content-Length")) {
		return 1;
	} else {
		const char * te = getHeader(request, "Transfer-Encoding");
		return te && !strcmp(te, "chunked");
	}
}

static int sendResponse(struct MHD_Connection *request, int statusCode, struct MHD_Response * response,
		struct RestrictedAccessProcessor * rapSession, const char * method, const char * url) {

	// This doesn't really belong here but its a good safty check. We should never try to send a response
	// when the data pipes are still open
	if (rapSession->readDataFd != -1) {
		stdLogError(0, "readDataFd was not properly closed before sending response");
		close(rapSession->readDataFd);
		rapSession->readDataFd = -1;
	}
	if (rapSession->writeDataFd != -1) {
		stdLogError(0, "writeDataFd was not properly closed before sending response");
		close(rapSession->writeDataFd);
		rapSession->writeDataFd = -1;
	}

	logAccess(statusCode, method, rapSession->user, url);
	switch (statusCode) {
	case MHD_HTTP_INTERNAL_SERVER_ERROR:
		return MHD_queue_response(request, MHD_HTTP_INTERNAL_SERVER_ERROR, INTERNAL_SERVER_ERROR_PAGE);
	case MHD_HTTP_UNAUTHORIZED:
		return MHD_queue_response(request, MHD_HTTP_UNAUTHORIZED, UNAUTHORIZED_PAGE);
	case MHD_HTTP_METHOD_NOT_ACCEPTABLE:
		return MHD_queue_response(request, MHD_HTTP_METHOD_NOT_ACCEPTABLE, METHOD_NOT_SUPPORTED_PAGE);
	default: {
		int queueResult = MHD_queue_response(request, statusCode, response);
		MHD_destroy_response(response);
		return queueResult;
	}
	}
}

static int answerToRequest(void *cls, struct MHD_Connection *request, char *url, const char *method,
		const char *version, const char *upload_data, size_t *upload_data_size,
		struct RestrictedAccessProcessor ** rapSession) {

	if (*rapSession) {
		if (*upload_data_size) {
			// Finished uploading data
			if (!(*rapSession)->responseAlreadyGiven) {
				processUploadData(request, upload_data, *upload_data_size, *rapSession);
			}
			*upload_data_size = 0;
			return MHD_YES;
		} else {
			// Uploading more data
			if ((*rapSession)->responseAlreadyGiven) {
				releaseRap(*rapSession);
				return MHD_YES;
			} else {
				struct MHD_Response * response;
				int statusCode = completeUpload(request, *rapSession, &response);
				int result = sendResponse(request, statusCode, response, *rapSession, method, url);
				if (*rapSession != AUTH_ERROR && *rapSession != AUTH_FAILED) {
					releaseRap(*rapSession);
				}
				return result;
			}
		}
	} else {
		const char * host = getHeader(request, "Host");
		if (host == NULL) {
			// TODO something more meaningful here.
			host = "";
		}

		// Authenticate all new requests regardless of anything else
		*rapSession = acquireRap(request);
		if (*rapSession == AUTH_FAILED) {
			return sendResponse(request, MHD_HTTP_UNAUTHORIZED, NULL, *rapSession, method, url);
		} else if (*rapSession == AUTH_ERROR) {
			return sendResponse(request, MHD_HTTP_INTERNAL_SERVER_ERROR, NULL, *rapSession, method, url);
		} else {
			if (requestHasData(request)) {
				// If we have data to send then create a pipe to pump it through
				int pipeEnds[2];
				if (pipe(pipeEnds)) {
					stdLogError(errno, "Could not create write pipe");
					return sendResponse(request, MHD_HTTP_INTERNAL_SERVER_ERROR, NULL, *rapSession, method, url);
				}
				(*rapSession)->readDataFd = pipeEnds[PIPE_READ];
				(*rapSession)->writeDataFd = pipeEnds[PIPE_WRITE];
				struct MHD_Response * response;

				int statusCode = processNewRequest(request, url, host, method, *rapSession, &response);

				if (statusCode == MHD_HTTP_CONTINUE) {
					// do not queue a response for contiune
					(*rapSession)->responseAlreadyGiven = 0;
					//logAccess(statusCode, method, (*rapSession)->user, url);
					return MHD_YES;
				} else {
					(*rapSession)->responseAlreadyGiven = 1;
					return sendResponse(request, statusCode, response, *rapSession, method, url);
				}
			} else {
				(*rapSession)->readDataFd = -1;
				(*rapSession)->writeDataFd = -1;
				struct MHD_Response * response;

				int statusCode = processNewRequest(request, url, host, method, *rapSession, &response);

				if (statusCode == MHD_HTTP_CONTINUE) {
					stdLogError(0, "RAP returned CONTINUE when there is no data");
					int ret = sendResponse(request, MHD_HTTP_INTERNAL_SERVER_ERROR, NULL, *rapSession, method, url);
					releaseRap(*rapSession);
					return ret;
				} else {
					int ret = sendResponse(request, statusCode, response, *rapSession, method, url);
					releaseRap(*rapSession);
					return ret;
				}
			}
		}
	}
}

///////////////////////////////////////////
// End Low Level HTTP handling (Signpost //
///////////////////////////////////////////

////////////////////
// Initialisation //
////////////////////

static char * loadFileToBuffer(const char * file, size_t * size) {
	int fd = open(file, O_RDONLY);
	struct stat stat;
	if (fd == -1 || fstat(fd, &stat)) {
		stdLogError(errno, "Could not open file %s", file);
		return NULL;
	}
	char * buffer = mallocSafe(stat.st_size);
	if (stat.st_size != 0) {
		size_t bytesRead = read(fd, buffer, stat.st_size);
		if (bytesRead != stat.st_size) {
			stdLogError(bytesRead < 0 ? errno : 0, "Could not read whole file %s", MIME_FILE_PATH);
			free(mimeFileBuffer);
			return NULL;
		}
	}
	*size = stat.st_size;
	return buffer;
}

static void initializeMimeTypes() {
	// Load Mime file into memory
	mimeFileBuffer = loadFileToBuffer(MIME_FILE_PATH, &mimeFileBufferSize);
	if (!mimeFileBuffer) {
		exit(1);
	}

	// Parse mimeFile;
	char * partStartPtr = mimeFileBuffer;
	int found;
	char * type = NULL;
	do {
		found = 0;
		// find the start of the part
		while (partStartPtr < mimeFileBuffer + mimeFileBufferSize && !found) {
			switch (*partStartPtr) {
			case '#':
				// skip to the end of the line
				while (partStartPtr < mimeFileBuffer + mimeFileBufferSize && *partStartPtr != '\n') {
					partStartPtr++;
				}
				// Fall through to incrementing partStartPtr
				partStartPtr++;
				break;
			case ' ':
			case '\t':
			case '\r':
			case '\n':
				if (*partStartPtr == '\n') {
					type = NULL;
				}
				partStartPtr++;
				break;
			default:
				found = 1;
				break;
			}
		}

		// Find the end of the part
		char * partEndPtr = partStartPtr + 1;
		found = 0;
		while (partEndPtr < mimeFileBuffer + mimeFileBufferSize && !found) {
			switch (*partEndPtr) {
			case ' ':
			case '\t':
			case '\r':
			case '\n':
				if (type == NULL) {
					type = partStartPtr;
				} else {
					mimeTypes = reallocSafe(mimeTypes, sizeof(struct MimeType) * (mimeTypeCount + 1));
					mimeTypes[mimeTypeCount].type = type;
					mimeTypes[mimeTypeCount].ext = partStartPtr;
					mimeTypeCount++;
				}
				if (*partEndPtr == '\n') {
					type = NULL;
				}
				*partEndPtr = '\0';
				found = 1;
				break;
			default:
				partEndPtr++;
				break;
			}
		}
		partStartPtr = partEndPtr + 1;
	} while (partStartPtr < mimeFileBuffer + mimeFileBufferSize);

	qsort(mimeTypes, mimeTypeCount, sizeof(struct MimeType), &compareExt);
}

static void initializeStaticResponse(struct MHD_Response ** response, const char * fileName) {
	size_t bufferSize;
	char * buffer;

	buffer = loadFileToBuffer(fileName, &bufferSize);
	if (buffer == NULL) {
		exit(1);
	}
	*response = MHD_create_response_from_buffer(bufferSize, buffer, MHD_RESPMEM_MUST_FREE);
	if (!*response) {
		stdLogError(errno, "Could not create response buffer");
		exit(255);
	}

	struct MimeType * type = findMimeType(fileName);
	if (type) {
		addHeaderSafe(*response, "Content-Type", type->type);
	}
}

static void initializeStaticResponses() {
	initializeStaticResponse(&INTERNAL_SERVER_ERROR_PAGE, "/usr/share/webdavd/HTTP_INTERNAL_SERVER_ERROR.html");
	initializeStaticResponse(&UNAUTHORIZED_PAGE, "/usr/share/webdavd/HTTP_UNAUTHORIZED.html");
	addHeaderSafe(UNAUTHORIZED_PAGE, "WWW-Authenticate", "Basic realm=\"My Server\"");
	initializeStaticResponse(&METHOD_NOT_SUPPORTED_PAGE, "/usr/share/webdavd/HTTP_METHOD_NOT_SUPPORTED.html");
	addHeaderSafe(METHOD_NOT_SUPPORTED_PAGE, "Allow",
			"OPTIONS, GET, HEAD, DELETE, PROPFIND, PUT, PROPPATCH, COPY, MOVE, LOCK, UNLOCK");
}

////////////////////////
// End Initialisation //
////////////////////////z

//////////
// Main //
//////////

int main(int argCount, char ** args) {
	initializeMimeTypes();
	initializeStaticResponses();
	struct sigaction act;
	memset(&act, 0, sizeof(act));
	act.sa_sigaction = &cleanupAfterRap;
	act.sa_flags = SA_SIGINFO;
	if (sigaction(SIGCHLD, &act, NULL) < 0) {
		stdLogError(errno, "Could not set handler method for finished child threads");
		return 255;
	}

	// Start up the daemons
	daemons = mallocSafe(sizeof(struct MHD_Daemon *) * daemonCount);
	for (int i = 0; i < daemonCount; i++) {
		daemons[i] = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY | MHD_USE_PEDANTIC_CHECKS, daemonPorts[i], NULL, NULL,
				(MHD_AccessHandlerCallback) &answerToRequest, NULL, MHD_OPTION_END);

		if (!daemons[i]) {
			stdLogError(errno, "Unable to initialise daemon on port %d", daemonPorts[i]);
			exit(255);
		}
	}

	pthread_exit(NULL);
}

//////////////
// End Main //
//////////////
