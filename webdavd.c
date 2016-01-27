// TODO ssl?
// TODO auth modes?
// TODO Basic http methods
// TODO webdav addaional methods
// TODO XML?
// TODO etags
// TODO correct failure codes on collections
// TODO access logging

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

struct RestrictedAccessProcessor {
	int pid;
	int socketFd;
	char * user;
	char * password;
};

struct WriteHandle {
	int fd;
	int failed;
	struct RestrictedAccessProcessor * rap;
};

struct MainHeaderInfo {
	char * host;
	int dataSent;
};

struct MimeType {
	const char * ext;
	const char * type;
};

static struct MHD_Daemon **daemons;
static int daemonPorts[] = { 80 };
static int daemonCount = sizeof(daemonPorts) / sizeof(daemonPorts[0]);
size_t mimeFileBufferSize;
char * mimeFileBuffer;
struct MimeType * mimeTypes = NULL;
int mimeTypeCount = 0;

static struct MHD_Response * INTERNAL_SERVER_ERROR_PAGE;
static struct MHD_Response * UNAUTHORIZED_PAGE;
static struct MHD_Response * OPTIONS_PAGE;

///////////////////////
// Response Queueing //
///////////////////////

#define queueAuthRequiredResponse(request) ( MHD_queue_response(request, MHD_HTTP_UNAUTHORIZED, UNAUTHORIZED_PAGE) )
#define queueInternalServerError(request) ( MHD_queue_response(request, MHD_HTTP_INTERNAL_SERVER_ERROR, INTERNAL_SERVER_ERROR_PAGE) )

static int compareExt(const void * a, const void * b) {
	return strcmp(((struct MimeType *) a)->ext, ((struct MimeType *) b)->ext);
}

static size_t getWebDate(time_t rawtime, char * buf, size_t bufSize) {
	struct tm * timeinfo = localtime(&rawtime);
	return strftime(buf, bufSize, "%a, %d %b %Y %H:%M:%S %Z", timeinfo);
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
		return MHD_CONTENT_READER_END_WITH_ERROR;
	}
	if (bytesRead == 0) {
		return MHD_CONTENT_READER_END_OF_STREAM;
	}
	return bytesRead;
}

static void fdContentReaderCleanup(int *fd) {
	close(*fd);
	free(fd);
	void *MHD_ContentReaderFreeCallback(void *cls);
}

static struct MHD_Response * fdContentReaderCreate(int fd, const char * mimeType, time_t date) {
	int * fdAllocated = mallocSafe(sizeof(int));
	*fdAllocated = fd;
	struct MHD_Response * response = MHD_create_response_from_callback(-1, 4096,
			(MHD_ContentReaderCallback) &fdContentReader, fdAllocated,
			(MHD_ContentReaderFreeCallback) & fdContentReaderCleanup);
	if (!response) {
		free(fdAllocated);
		return NULL;
	}
	char dateBuf[100];
	getWebDate(date, dateBuf, 100);
	if ((MHD_add_response_header(response, "Date", dateBuf) != MHD_YES)
			|| (mimeType && MHD_add_response_header(response, "Content-Type", mimeType) != MHD_YES)) {
		MHD_destroy_response(response);
		return NULL;
	}
	return response;

}

static struct MHD_Response * fdFileContentReaderCreate(size_t size, int fd, const char * mimeType, time_t date) {
	struct MHD_Response * response = MHD_create_response_from_fd(size, fd);
	if (!response) {
		close(fd);
		return NULL;
	}
	char dateBuf[100];
	getWebDate(date, dateBuf, 100);
	if ((MHD_add_response_header(response, "Date", dateBuf) != MHD_YES)
			|| (mimeType && MHD_add_response_header(response, "Content-Type", mimeType) != MHD_YES)) {
		MHD_destroy_response(response);
		return NULL;
	}
	return response;
}

static int queueFileResponse(struct MHD_Connection *request, int responseCode, const char * fileName) {
	int fd = open(fileName, O_RDONLY);

	if (fd == -1) {
		return queueInternalServerError(request);
	}

	struct stat statBuffer;
	if (fstat(fd, &statBuffer)) {
		close(fd);
		return queueInternalServerError(request);
	}

	struct MimeType * mimeType = findMimeType(fileName);
	struct MHD_Response * response = fdFileContentReaderCreate(statBuffer.st_size, fd, mimeType ? mimeType->type : NULL,
			statBuffer.st_mtime);
	if (!response) {
		return MHD_NO;
	}

	int result = MHD_queue_response(request, responseCode, response);
	MHD_destroy_response(response);
	return result;
}

static int queueRapResponse(struct MHD_Connection *request, enum RapConstant mID, int fd, int messageParts,
		struct iovec * message) {

	// Get Mime type and date
	const char * mimeType;
	if (RAP_FILE_INDEX < messageParts) {
		mimeType = iovecToString(&message[RAP_FILE_INDEX]);
	} else {
		mimeType = NULL;
	}
	time_t date;
	if (RAP_DATE_INDEX < messageParts) {
		date = *((time_t *) message[RAP_DATE_INDEX].iov_base);
	} else {
		time(&date);
	}

	// Queue the response
	switch (mID) {
	case RAP_SUCCESS: {
		struct stat stat;
		fstat(fd, &stat);
		struct MHD_Response * response;
		if ((stat.st_mode & S_IFMT) == S_IFREG) {
			struct MimeType * found = findMimeType(mimeType);
			mimeType = found ? found->type : NULL;
			response = fdFileContentReaderCreate(stat.st_size, fd, mimeType, date);
		} else {
			response = fdContentReaderCreate(fd, mimeType, date);
		}

		if (RAP_LOCATION_INDEX
				< messageParts&& MHD_add_response_header(response, "Location", iovecToString(&message[RAP_LOCATION_INDEX])) != MHD_YES) {
			MHD_destroy_response(response);
			queueInternalServerError(request);
		}

		int ret = MHD_queue_response(request, MHD_HTTP_OK, response);
		MHD_destroy_response(response);
		return ret;
	}

	case RAP_INTERNAL_ERROR:
		return queueInternalServerError(request);

	case RAP_ACCESS_DENIED:
		return queueFileResponse(request, MHD_HTTP_FORBIDDEN, "/usr/share/webdavd/HTTP_FORBIDDEN.html");

	case RAP_NOT_FOUND:
		return queueFileResponse(request, MHD_HTTP_NOT_FOUND, "/usr/share/webdavd/HTTP_NOT_FOUND.html");

	case RAP_BAD_REQUEST:
		stdLogError(0, "RAP reported bad request");
		return queueInternalServerError(request);

	default:
		stdLogError(0, "invalid response from RAP %d", (int) mID);
		return queueInternalServerError(request);
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
		// stdLog("Starting rap: %s", path);
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

static int createRap(struct MHD_Connection *request, struct RestrictedAccessProcessor ** newProcessor,
		const char * user, const char * password) {

	struct RestrictedAccessProcessor * processor = mallocSafe(sizeof(struct RestrictedAccessProcessor));
	processor->pid = forkRapProcess(RAP_PATH, &(processor->socketFd));
	if (!processor->pid) {
		free(processor);
		*newProcessor = NULL;
		return queueInternalServerError(request);
	}
	size_t userLen = strlen(user) + 1;
	size_t passLen = strlen(password) + 1;
	size_t bufferSize = userLen + passLen;
	processor->user = mallocSafe(bufferSize);
	processor->password = processor->user + userLen;
	memcpy(processor->user, user, userLen);
	memcpy(processor->password, password, passLen);
	struct iovec message[MAX_BUFFER_PARTS] = { { .iov_len = userLen, .iov_base = processor->user }, {
			.iov_len = passLen, .iov_base = processor->password } };
	if (sendMessage(processor->socketFd, RAP_AUTHENTICATE, -1, 2, message) <= 0) {
		destroyRap(processor);
		free(processor);
		*newProcessor = NULL;
		return queueInternalServerError(request);
	}
	// TODO implement timeout ... possibly using "select"
	int bufferCount = MAX_BUFFER_PARTS;
	enum RapConstant responseCode;
	size_t readResult = recvMessage(processor->socketFd, &responseCode, NULL, &bufferCount, message);
	if (readResult <= 0 || responseCode != RAP_SUCCESS) {
		destroyRap(processor);
		*newProcessor = NULL;
		if (readResult < 0) {
			stdLogError(errno, "Could not read result from RAP ");
			return queueInternalServerError(request);
		} else if (readResult == 0) {
			stdLogError(0, "RAP closed socket unexpectedly");
			return queueInternalServerError(request);
		} else {
			stdLogError(0, "Access denied for user %s", user);
			return queueAuthRequiredResponse(request);
		}

	}

	*newProcessor = processor;

	return MHD_YES;
}

static void releaseRap(struct RestrictedAccessProcessor * processor) {
	destroyRap(processor);
}

static int acquireRap(struct MHD_Connection *request, struct RestrictedAccessProcessor ** processor) {
	// TODO reuse RAP
	char * user;
	char * password;
	user = MHD_basic_auth_get_username_password(request, &(password));
	if (user && password) {
		return createRap(request, processor, user, password);
	} else {
		*processor = NULL;
		stdLogError(errno, "Rejecting request without auth");
		return queueAuthRequiredResponse(request);
	}
}

static void cleanupAfterRap(int sig, siginfo_t *siginfo, void *context) {
	int status;
	waitpid(siginfo->si_pid, &status, 0);
	//stdLog("Child finished PID: %d staus: %d", siginfo->si_pid, status);
}

////////////////////////
// End RAP Processing //
////////////////////////

///////////////////////////////////////
// Low Level HTTP handling (Signpost //
///////////////////////////////////////

static int filterMainHeaderInfo(struct MainHeaderInfo * mainHeaderInfo, enum MHD_ValueKind kind, const char *key,
		const char *value) {
	if (!strcmp(key, "Host")) {
		mainHeaderInfo->host = (char *) value;
	} else if (!strcmp(key, "Content-Length") || (!strcmp(key, "Transfer-Encoding") && !strcmp(value, "chunked"))) {
		mainHeaderInfo->dataSent = 1;
	}
	return MHD_YES;
}

static int completeUpload(struct MHD_Connection *request, struct WriteHandle * writeHandle) {
	if (!writeHandle->failed) {
		close(writeHandle->fd);

		enum RapConstant mID;
		int fd;
		int messageParts = MAX_BUFFER_PARTS;
		struct iovec message[MAX_BUFFER_PARTS];
		int readResult = recvMessage(writeHandle->fd, &mID, &fd, &messageParts, message);
		if (readResult <= 0) {
			if (readResult == 0) {
				stdLogError(0, "RAP closed socket unexpectedly while waiting for response");
			}
		}

		releaseRap(writeHandle->rap);
		free(writeHandle);
		if (readResult > 0) {
			return queueRapResponse(request, mID, fd, messageParts, message);
		} else {
			return queueInternalServerError(request);
		}
	} else {
		free(writeHandle);
		return MHD_YES;
	}
}

static void abortSession(struct WriteHandle * writeHandle, struct RestrictedAccessProcessor * rapSession) {
	if (writeHandle) {
		close(writeHandle->fd);
		writeHandle->failed = 1;
	}
	releaseRap(rapSession);
}

static int processUploadData(struct MHD_Connection * request, const char * upload_data, size_t * upload_data_size,
		struct WriteHandle * writeHandle) {
	if (writeHandle->failed) {
		return MHD_YES;
	}

	size_t bytesWritten = write(writeHandle->fd, upload_data, *upload_data_size);
	if (bytesWritten < *upload_data_size) {
		// not all data could be written to the file handle and therefore
		// the operation has now failed. There's nothing we can do now but report the error
		// We will still return MHD_YES and so spool through the data provided
		// This may not actually be desirable and so we need to consider slamming closed the connection.
		abortSession(writeHandle, writeHandle->rap);
		return queueFileResponse(request, MHD_HTTP_INSUFFICIENT_STORAGE,
				"/usr/share/webdavd/HTTP_INSUFFICIENT_STORAGE.html");
	}
	return MHD_YES;
}

static int processNewRequest(struct MHD_Connection * request, const char * url, const char * host, const char * method,
		struct WriteHandle * writeHandle) {

	// Get a RAP
	struct RestrictedAccessProcessor * rapSession;
	int ret = acquireRap(request, &rapSession);
	if (!rapSession) {
		return ret;
	}

	// Interpret the method
	int messageParts = 2;
	struct iovec message[MAX_BUFFER_PARTS] = { { .iov_len = strlen(host) + 1, .iov_base = (void *) host }, { .iov_len =
			strlen(url) + 1, .iov_base = (void *) url } };
	enum RapConstant mID;
	// TODO PUT
	// TODO PROPFIND
	// TODO PROPPATCH
	// TODO MKCOL
	// TODO HEAD
	// TODO DELETE
	// TODO COPY
	// TODO MOVE
	// TODO LOCK
	// TODO UNLOCK
	// TODO OPTIONS????
	if (!strcmp("GET", method)) {
		mID = RAP_READ_FILE;
	} else if (!strcmp("OPTIONS", method)) {
		releaseRap(rapSession);
		return MHD_queue_response(request, MHD_HTTP_OK, OPTIONS_PAGE);
	} else {
		// TODO add "Allow" header
		stdLogError(0, "Can not cope with method: %s (%s data)", method, (writeHandle ? "with" : "without"));
		return queueFileResponse(request, MHD_HTTP_METHOD_NOT_ACCEPTABLE,
				"/usr/share/webdavd/HTTP_METHOD_NOT_SUPPORTED.html");
	}

	// If we have data to send then create a pipe to pump it through
	int fd;
	if (writeHandle) {
		int pipeEnds[2];
		if (pipe(pipeEnds)) {
			stdLogError(errno, "Could not create write pipe");
			return queueInternalServerError(request);
		}
		writeHandle->fd = pipeEnds[PIPE_WRITE];
		fd = pipeEnds[PIPE_READ];
		writeHandle->failed = 0;
		writeHandle->rap = rapSession;
	} else {
		fd = -1;
	}

	// Send the request to the RAP
	if (sendMessage(rapSession->socketFd, mID, fd, messageParts, message) < 0) {
		abortSession(writeHandle, rapSession);
		return queueInternalServerError(request);
	}

	// Get result from RAP
	messageParts = MAX_BUFFER_PARTS;
	int readResult = recvMessage(rapSession->socketFd, &mID, &fd, &messageParts, message);
	if (readResult <= 0) {
		if (readResult == 0) {
			stdLogError(0, "RAP closed socket unexpectedly while waiting for response");
		}
		abortSession(writeHandle, rapSession);
		return queueInternalServerError(request);
	}

	if (mID == RAP_CONTINUE) {
		if (!writeHandle) {
			stdLogError(0, "RAP returned RAP_CONTINUE when no data was sent");
		}
		return MHD_YES;
	} else {
		abortSession(writeHandle, rapSession);
		return queueRapResponse(request, mID, fd, messageParts, message);
	}
}

static int answerToRequest(void *cls, struct MHD_Connection *request, char *url, const char *method,
		const char *version, const char *upload_data, size_t *upload_data_size, struct WriteHandle ** writeHandle) {

	// We can only accept http 1.1 sessions
	// Http 1.0 is old and REALLY shouldn't be used
	// It misses out the "Host" header which is required for this program to function correctly
	if (strcmp(version, "HTTP/1.1")) {
		stdLogError(0, "HTTP Version not supported, only HTTP/1.1 is accepted. Supplied: %s", version);
		return queueFileResponse(request, MHD_HTTP_HTTP_VERSION_NOT_SUPPORTED,
				"/usr/share/webdavd/HTTP_VERSION_NOT_SUPPORTED.html");
	}

	if (*writeHandle) {
		if (*upload_data_size)
			return processUploadData(request, upload_data, upload_data_size, *writeHandle);
		else
			return completeUpload(request, *writeHandle);
	} else {
		// Get the host header and determine if data is to be sent
		struct MainHeaderInfo mainHeaderInfo = { .dataSent = 0, .host = NULL };
		if (!MHD_get_connection_values(request, MHD_HEADER_KIND, (MHD_KeyValueIterator) &filterMainHeaderInfo,
				&mainHeaderInfo)) {
			return queueInternalServerError(request);
		}
		if (mainHeaderInfo.dataSent) {
			*writeHandle = mallocSafe(sizeof(struct WriteHandle));
			(*writeHandle)->failed = 1; // Initialise it so that nothing is saved unless otherwise set
			(*writeHandle)->fd = -1; // we have nothing to write to until we have something to write to.
			(*writeHandle)->rap = NULL;
		}
		return processNewRequest(request, url, mainHeaderInfo.host, method, *writeHandle);
	}
}

///////////////////////////////////////////
// End Low Level HTTP handling (Signpost //
///////////////////////////////////////////

////////////////////
// Initialisation //
////////////////////

static void initializeDaemin(int port, struct MHD_Daemon **newDaemon) {
	*newDaemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY | MHD_USE_PEDANTIC_CHECKS, port, NULL, NULL,
			(MHD_AccessHandlerCallback) &answerToRequest, NULL, MHD_OPTION_END);

	if (!*newDaemon) {
		stdLogError(errno, "Unable to initialise daemon on port %d", port);
		exit(255);
	}
}

static char * loadFileToBuffer(const char * file, size_t * size) {
	int fd = open(file, O_RDONLY);
	struct stat stat;
	if (fd == -1 || fstat(fd, &stat) || stat.st_size == 0) {
		if (stat.st_size == 0) {
			stdLogError(0, "Could not determine size of %s", file);
		} else {
			stdLogError(errno, "Could not open file %s", file);
		}
		return NULL;
	}
	char * buffer = mallocSafe(stat.st_size);
	size_t bytesRead = read(fd, buffer, stat.st_size);
	if (bytesRead != stat.st_size) {
		stdLogError(bytesRead < 0 ? errno : 0, "Could not read whole file %s", MIME_FILE_PATH);
		free(mimeFileBuffer);
		return NULL;
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
	if (type && MHD_add_response_header(*response, "Content-Type", type->type) != MHD_YES) {
		exit(255);
	}
}

static void initializeStaticResponses() {
	initializeStaticResponse(&INTERNAL_SERVER_ERROR_PAGE, "/usr/share/webdavd/HTTP_INTERNAL_SERVER_ERROR.html");
	initializeStaticResponse(&UNAUTHORIZED_PAGE, "/usr/share/webdavd/HTTP_UNAUTHORIZED.html");
	if (MHD_add_response_header(UNAUTHORIZED_PAGE, "WWW-Authenticate", "Basic realm=\"My Server\"") != MHD_YES) {
		stdLogError(errno, "Could not initialize pages");
		exit(255);
	}
	initializeStaticResponse(&OPTIONS_PAGE, "/usr/share/webdavd/OPTIONS.html");
	if (MHD_add_response_header(OPTIONS_PAGE, "Dav", "1") != MHD_YES
			|| MHD_add_response_header(OPTIONS_PAGE, "Allow",
					"OPTIONS, GET, HEAD, DELETE, PROPFIND, PUT, PROPPATCH, COPY, MOVE, LOCK, UNLOCK") != MHD_YES) {

	}
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
		initializeDaemin(daemonPorts[i], &(daemons[i]));
	}

	pthread_exit(NULL);
}

//////////////
// End Main //
//////////////
