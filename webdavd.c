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
#include <pwd.h>
#include <errno.h>
#include <dirent.h>

#define RAP_PATH "/usr/sbin/rap"
#define MIME_FILE_PATH "/etc/mime.types"

static struct MHD_Daemon **daemons;
static int daemonPorts[] = { 80 };
static int daemonCount = sizeof(daemonPorts) / sizeof(daemonPorts[0]);

struct RestrictedAccessProcessor {
	int pid;
	int socketFd;
	char * user;
	char * password;
};

struct WriteHandle {
	int fd;
	int failed;
};

struct Header {
	const char * headerKey;
	const char * headerValue;
};

struct MainHeaderInfo {
	char * host;
	int dataSent;
};

struct MimeType {
	const char * ext;
	const char * type;
};

char * mimeFileBuffer;
struct MimeType * mimeTypes = NULL;
int mimeTypeCount = 0;

static int compareExt(const void * a, const void * b) {
	return strcmp(((struct MimeType *) a)->ext, ((struct MimeType *) b)->ext);
}

static struct MimeType * findMimeType(const char * file) {
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

static int initializeMimeTypes() {
	// Load Mime file into memory
	int mimeTypeFd = open(MIME_FILE_PATH, O_RDONLY);
	struct stat mimeStat;
	if (mimeTypeFd == -1 || fstat(mimeTypeFd, &mimeStat) || mimeStat.st_size == 0) {
		if (mimeStat.st_size == 0) {
			stdLogError(0, "Could not determine size of %s", MIME_FILE_PATH);
		} else {
			stdLogError(errno, "Could not open mime type file %s", MIME_FILE_PATH);
		}
		return 0;
	}

	mimeFileBuffer = mallocSafe(mimeStat.st_size);
	size_t bytesRead = read(mimeTypeFd, mimeFileBuffer, mimeStat.st_size);
	if (bytesRead != mimeStat.st_size) {
		stdLogError(bytesRead < 0 ? errno : 0, "Could not read whole mime file %s", MIME_FILE_PATH);
		free(mimeFileBuffer);
		return 0;
	}

	// Parse mimeFile;
	char * partStartPtr = mimeFileBuffer;
	int found;
	char * type = NULL;
	do {
		found = 0;
		// find the start of the part
		while (partStartPtr < mimeFileBuffer + mimeStat.st_size && !found) {
			switch (*partStartPtr) {
			case '#':
				// skip to the end of the line
				while (partStartPtr < mimeFileBuffer + mimeStat.st_size && *partStartPtr != '\n') {
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
		while (partEndPtr < mimeFileBuffer + mimeStat.st_size && !found) {
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
	} while (partStartPtr < mimeFileBuffer + mimeStat.st_size);

	qsort(mimeTypes, mimeTypeCount, sizeof(struct MimeType), &compareExt);
	return 1;
}

static int queueStringResponse(struct MHD_Connection *request, int httpResponseCode, char * string, int headerCount,
		struct Header * headers) {

	struct MHD_Response * response = MHD_create_response_from_buffer(strlen(string), string, MHD_RESPMEM_MUST_COPY);
	if (!response)
		return MHD_NO;
	for (int i = 0; i < headerCount; i++) {
		if (!MHD_add_response_header(response, headers[i].headerKey, headers[i].headerValue)) {
			MHD_destroy_response(response);
			return MHD_NO;
		}
	}

	int ret = MHD_queue_response(request, httpResponseCode, response);
	MHD_destroy_response(response);
	return ret;
}

static int queueSimpleStringResponse(struct MHD_Connection *request, int httpResponseCode, char * string) {
	struct MHD_Response * response = MHD_create_response_from_buffer(strlen(string), string, MHD_RESPMEM_MUST_COPY);
	if (!response)
		return MHD_NO;

	int ret = MHD_queue_response(request, httpResponseCode, response);
	MHD_destroy_response(response);
	return ret;
}

static int queueAuthRequiredResponse(struct MHD_Connection *request) {
	struct Header headers[] = { { .headerKey = "WWW-Authenticate", .headerValue = "Basic realm=\"My Server\"" } };
	return queueStringResponse(request, MHD_HTTP_UNAUTHORIZED, "Access Denied!", 1, headers);
}

static int queueInternalServerError(struct MHD_Connection * request) {
	return queueSimpleStringResponse(request, MHD_HTTP_INTERNAL_SERVER_ERROR, "Internal Error!");
}

static ssize_t directoryReader(DIR * directory, uint64_t pos, char *buf, size_t max) {
	struct dirent *dp;
	ssize_t written = 0;

	while (written < max - 257 && (dp = readdir(directory)) != NULL) {
		int newlyWritten;
		if (dp->d_name[0] != '.' || (dp->d_name[1] != '\0' && (dp->d_name[1] != '.' || dp->d_name[2] != '\0'))) {
			if (dp->d_type == DT_DIR) {
				newlyWritten = sprintf(buf, "%s/\n", dp->d_name);
			} else {
				newlyWritten = sprintf(buf, "%s\n", dp->d_name);
			}
			written += newlyWritten;
			buf += newlyWritten;
		}
	}

	if (written == 0) {
		written = MHD_CONTENT_READER_END_OF_STREAM;
	}
	return written;
}

static void directoryReaderCleanup(DIR * directory) {
	closedir(directory);
}

static struct MHD_Response * directoryReaderCreate(size_t size, int fd) {
	DIR * dir = fdopendir(fd);
	if (!dir) {
		close(fd);
		stdLogError(errno, "Could not list directory from fd");
		return NULL;
	}
	struct MHD_Response * response = MHD_create_response_from_callback(-1, 4096,
			(MHD_ContentReaderCallback) &directoryReader, dir,
			(MHD_ContentReaderFreeCallback) & directoryReaderCleanup);
	if (!response) {
		closedir(dir);
		return NULL;
	} else {
		return response;
	}
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

static struct MHD_Response * fdContentReaderCreate(size_t size, int fd) {
	int * fdAllocated = mallocSafe(sizeof(int));
	*fdAllocated = fd;
	struct MHD_Response * response = MHD_create_response_from_callback(-1, 4096,
			(MHD_ContentReaderCallback) &fdContentReader, fdAllocated,
			(MHD_ContentReaderFreeCallback) & fdContentReaderCleanup);
	if (!response) {
		free(fdAllocated);
		return NULL;
	} else {
		return response;
	}
}

static struct MHD_Response * fdFileContentReaderCreate(size_t size, int fd) {
	struct MHD_Response * response = MHD_create_response_from_fd(size, fd);
// TODO date header
// TODO mime header
	if (!response) {
		close(fd);
		return NULL;
	} else {
		return response;
	}
}

static int queueFdResponse(struct MHD_Connection *request, int fd, struct MimeType * mimeType) {
	struct stat statBuffer;
	if (fstat(fd, &statBuffer)) {
		close(fd);
		return queueInternalServerError(request);
	}

	typedef struct MHD_Response * (*ResponseCreator)(size_t, int fd);
	ResponseCreator responseCreator;
	size_t size;

	switch (statBuffer.st_mode & S_IFMT) {
	case S_IFREG:
		responseCreator = &fdFileContentReaderCreate;
		size = statBuffer.st_size;
		break;

	case S_IFDIR:
		responseCreator = &directoryReaderCreate;
		size = -1;
		break;

	default:
		responseCreator = &fdContentReaderCreate;
		size = -1;
	}

	struct MHD_Response * response = responseCreator(size, fd);
	if (!response) {
		return queueInternalServerError(request);
	}
	if (mimeType) {
		if (MHD_add_response_header(response, "Content-Type", mimeType->type) != MHD_YES) {
			return queueInternalServerError(request);
		}
	}
	int ret = MHD_queue_response(request, MHD_HTTP_OK, response);
	MHD_destroy_response(response);
	return ret;
}

static int queueFileResponse(struct MHD_Connection *request, const char * file, int responseCode) {
	int fd = open(file, O_RDONLY);

	if (fd == -1) {
		return queueInternalServerError(request);
	}

	struct stat statBuffer;
	if (fstat(fd, &statBuffer)) {
		close(fd);
		return queueInternalServerError(request);
	}

	struct MHD_Response * response = fdFileContentReaderCreate(statBuffer.st_size, fd);
	if (!response) {
		return MHD_NO;
	}
	int result = MHD_queue_response(request, responseCode, response);
	MHD_destroy_response(response);
	return result;
}

static int filterMainHeaderInfo(struct MainHeaderInfo * mainHeaderInfo, enum MHD_ValueKind kind, const char *key,
		const char *value) {
	if (!strcmp(key, "Host")) {
		mainHeaderInfo->host = (char *) value;
	} else if (!strcmp(key, "Content-Length") || (!strcmp(key, "Transfer-Encoding") && !strcmp(value, "chunked"))) {
		mainHeaderInfo->dataSent = 1;
	}
	return MHD_YES;
}

static int forkSockExec(const char * path, int * newSockFd) {
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

static void destroyRestrictedAccessProcessor(struct RestrictedAccessProcessor * processor) {
	close(processor->socketFd);
	free(processor->user);
	free(processor);
}

static int createRestrictedAccessProcessor(struct MHD_Connection *request,
		struct RestrictedAccessProcessor ** newProcessor, const char * user, const char * password) {

	struct RestrictedAccessProcessor * processor = mallocSafe(sizeof(struct RestrictedAccessProcessor));
	processor->pid = forkSockExec(RAP_PATH, &(processor->socketFd));
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
		destroyRestrictedAccessProcessor(processor);
		free(processor);
		*newProcessor = NULL;
		return queueInternalServerError(request);
	}
// TODO implement timeout ... possibly using "select"
	int bufferCount = MAX_BUFFER_PARTS;
	enum RapConstant responseCode;
	size_t readResult = recvMessage(processor->socketFd, &responseCode, NULL, &bufferCount, message);
	if (readResult <= 0 || responseCode != RAP_SUCCESS) {
		destroyRestrictedAccessProcessor(processor);
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

static int authLookup(struct MHD_Connection *request, struct RestrictedAccessProcessor ** processor) {
// TODO reuse RAP
	char * user;
	char * password;
	user = MHD_basic_auth_get_username_password(request, &(password));
	if (user && password) {
		return createRestrictedAccessProcessor(request, processor, user, password);
	} else {
		*processor = NULL;
		return queueAuthRequiredResponse(request);
	}
}

static void releaseRap(struct RestrictedAccessProcessor * processor) {
	destroyRestrictedAccessProcessor(processor);
}

static enum RapConstant selectRAPAction(const char * method) {
	// TODO analyse method to give the correct response;
	if (!strcmp("GET", method))
		return RAP_READ_FILE;
	else
		return RAP_INVALID_METHOD;
}

static int processNewRequest(struct MHD_Connection *request, const char *url, const char *method,
		struct WriteHandle **writeHandle) {

	// Interpret the method
	enum RapConstant mID = selectRAPAction(method);
	if (mID == RAP_INVALID_METHOD) {
		struct Header headers[0];
		headers[0].headerKey = "Allow";
		headers[0].headerValue = "GET, HEAD, PUT";
		return queueStringResponse(request, MHD_HTTP_METHOD_NOT_ACCEPTABLE, "Method Not Supported", 1, headers);
	}

	// Get a RAP
	struct RestrictedAccessProcessor * rapSocketSession;
	if (!authLookup(request, &rapSocketSession)) {
		// This only happens if a systemic error happens (eg a loss of connection)
		// It does NOT account for authentication failures (access denied).
		return MHD_NO;
	}

	// If the user was not authenticated (access denied) then the authLookup will return the appropriate response
	if (!rapSocketSession)
		return MHD_YES;

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
	}

	// Format the url.
	struct passwd * pw = getpwnam(rapSocketSession->user);
	size_t urlLen = strlen(mainHeaderInfo.host) + strlen(pw->pw_dir) + 1;
	char stackBuffer[2048];
	char * newUrl = urlLen < 2048 ? stackBuffer : mallocSafe(urlLen + 1);
	sprintf(newUrl, "%s%s", pw->pw_dir, url);

	// Send the request to the RAP
	struct iovec message[MAX_BUFFER_PARTS] = { { .iov_len = strlen(mainHeaderInfo.host) + 1, .iov_base =
			(void*) mainHeaderInfo.host }, { .iov_len = strlen(newUrl) + 1, .iov_base = newUrl } };

	if (sendMessage(rapSocketSession->socketFd, mID, -1, 2, message) < 0) {
		if (newUrl != stackBuffer) {
			free(newUrl);
		}
		return queueInternalServerError(request);
	}
	if (newUrl != stackBuffer) {
		free(newUrl);
	}

	// Get result from RAP
	int fd;
	int bufferCount = 0;
	int readResult = recvMessage(rapSocketSession->socketFd, &mID, &fd, &bufferCount, NULL);
	if (readResult <= 0) {
		if (readResult == 0) {
			stdLogError(0, "RAP closed socket unexpectedly while waiting for response");
		}
		return queueInternalServerError(request);
	}

	// Release the RAP.
	releaseRap(rapSocketSession);

	// Queue the response
	switch (mID) {
	case RAP_SUCCESS_SOURCE_DATA:
		return queueFdResponse(request, fd, findMimeType(newUrl));
	case RAP_SUCCESS_SINK_DATA:
		(*writeHandle)->fd = fd;
		(*writeHandle)->failed = 0;
		return MHD_YES;
	case RAP_ACCESS_DENIED:
		return queueFileResponse(request, "HTTP_FORBIDDEN.html", MHD_HTTP_FORBIDDEN);
	case RAP_NOT_FOUND:
		return queueFileResponse(request, "HTTP_NOT_FOUND.html", MHD_HTTP_NOT_FOUND);
	case RAP_BAD_REQUEST:
		stdLogError(0, "RAP reported bad request");
		return queueInternalServerError(request);
	default:
		stdLogError(0, "invalid response from RAP %d", (int) mID);
		return queueInternalServerError(request);
	}

}

static int processUploadData(struct MHD_Connection *request, const char *upload_data, size_t * upload_data_size,
		struct WriteHandle ** writeHandle) {
	if ((*writeHandle)->failed) {
		return MHD_YES;
	}

	size_t bytesWritten = write((*writeHandle)->fd, upload_data, *upload_data_size);
	if (bytesWritten < *upload_data_size) {
		// not all data could be written to the file handle and therefore
		// the operation has now failed. There's nothing we can do now but report the error
		// We will still return MHD_YES and so spool through the data provided
		// This may not actually be desirable and so we need to consider slamming closed the connection.
		(*writeHandle)->failed = 1;
		close((*writeHandle)->fd);
		return queueSimpleStringResponse(request, MHD_HTTP_INSUFFICIENT_STORAGE, "Upload failed!");
	}
	return MHD_YES;
}

static int completeUpload(struct MHD_Connection *request, struct WriteHandle ** writeHandle) {
	if (!(*writeHandle)->failed) {
		close((*writeHandle)->fd);
		free(*writeHandle);
		return queueSimpleStringResponse(request, MHD_HTTP_OK, "Upload Complete!");
	}
	return MHD_YES;
}

static int answerToRequest(void *cls, struct MHD_Connection *request, char *url, const char *method,
		const char *version, const char *upload_data, size_t *upload_data_size, struct WriteHandle ** writeHandle) {

	// We can only accept http 1.1 sessions
	// Http 1.0 is old and REALLY shouldn't be used
	// It misses out the "Host" header which is required for this program to function correctly
	if (strcmp(version, "HTTP/1.1")) {
		stdLogError(0, "HTTP Version not supported, only HTTP/1.1 is accepted. Supplied: %s", version);
		return queueSimpleStringResponse(request, MHD_HTTP_HTTP_VERSION_NOT_SUPPORTED,
				"HTTP Version not supported, only HTTP 1.1 is accepted");
	}

	if (*writeHandle) {
		if (*upload_data_size)
			return processUploadData(request, upload_data, upload_data_size, writeHandle);
		else
			return completeUpload(request, writeHandle);
	} else {
		return processNewRequest(request, url, method, writeHandle);
	}
}

static void initializeDaemin(int port, struct MHD_Daemon **newDaemon) {
	*newDaemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY | MHD_USE_PEDANTIC_CHECKS, port, NULL, NULL,
			(MHD_AccessHandlerCallback) &answerToRequest, NULL, MHD_OPTION_END);

	if (!*newDaemon) {
		stdLogError(errno, "Unable to initialise daemon on port %d", port);
		exit(255);
	}
}

static void cleanupZombyChildren(int sig, siginfo_t *siginfo, void *context) {
	int status;
	waitpid(siginfo->si_pid, &status, 0);
	stdLog("Child finished PID: %d staus: %d", siginfo->si_pid, status);
}

int main(int argCount, char ** args) {
	// Avoid zombie children
	initializeMimeTypes();
	struct sigaction act;
	memset(&act, 0, sizeof(act));
	act.sa_sigaction = &cleanupZombyChildren;
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
