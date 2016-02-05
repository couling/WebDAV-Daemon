// TODO ssl
// TODO auth modes other than basic?
// TODO correct failure codes on collections
// TODO configuration file & getopt
// TODO single root parent with multiple configured server processes

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
#include <semaphore.h>
#include <microhttpd.h>
#include <errno.h>

////////////////
// Structures //
////////////////

struct RestrictedAccessProcessor {
	int rapSessionInUse;
	time_t rapCreated;
	int pid;
	int socketFd;
	const char * user;
	int writeDataFd;
	int readDataFd;
	int responseAlreadyGiven;
};

struct RapGroup {
	const char * user;
	const char * password;
	int rapSessionCount;
	struct RestrictedAccessProcessor * rapSession;
};

struct MimeType {
	const char * ext;
	const char * type;
};

struct Header {
	const char * key;
	const char * value;
};

////////////////////
// End Structures //
////////////////////

///////////////////////////
// Webdavd Configuration //
///////////////////////////

struct DaemonConfig {
	int port;
	const char * host;
	int sslEnabled;
};

struct SSLConfig {
	int chainFileCount;
	const char * keyFile;
	const char * certificate;
	const char ** chainFiles;

};

struct WebdavdConfiguration {
	const char * restrictedUser;

	// Daemons
	int daemonCount;
	struct DaemonConfig * daemons;

	// RAP
	time_t rapMaxSessionLife;
	int rapMaxSessionsPerUser;
	const char * pamServiceName;

	// files
	const char * mimeTypesFile;
	const char * rapBinary;
	const char * accessLog;
	const char * errorLog;

	// Add static files

	// SSL
	int sslCertCount;
	struct SSLConfig * sslCerts;
}static config;

///////////////////////////////
// End Webdavd Configuration //
///////////////////////////////

// All Daemons
// Not sure why we keep these, they're not used for anything
static struct MHD_Daemon **daemons;

// Mime Database.
// TODO find a way to move this to the RAP.
static size_t mimeFileBufferSize;
static char * mimeFileBuffer;
static struct MimeType * mimeTypes = NULL;
static int mimeTypeCount = 0;

static sem_t rapDBLock;
static int rapDBSize;
static struct RapGroup * rapDB;

#define ACCEPT_HEADER "OPTIONS, GET, HEAD, DELETE, PROPFIND, PUT, PROPPATCH, COPY, MOVE, LOCK, UNLOCK"

static struct MHD_Response * INTERNAL_SERVER_ERROR_PAGE;
static struct MHD_Response * UNAUTHORIZED_PAGE;
static struct MHD_Response * METHOD_NOT_SUPPORTED_PAGE;

// Used as a place holder for failed auth requests which failed due to invalid credentials
static const struct RestrictedAccessProcessor AUTH_FAILED_RAP = { .pid = 0, .socketFd = -1, .user = "<auth failed>",
		.writeDataFd = -1, .readDataFd = -1, .responseAlreadyGiven = 1 };

// Used as a place holder for failed auth requests which failed due to errors
static const struct RestrictedAccessProcessor AUTH_ERROR_RAP = { .pid = 0, .socketFd = -1, .user = "<auth error>",
		.writeDataFd = -1, .readDataFd = -1, .responseAlreadyGiven = 1 };

#define AUTH_FAILED ((struct RestrictedAccessProcessor *)&AUTH_FAILED_RAP)
#define AUTH_ERROR ((struct RestrictedAccessProcessor *)&AUTH_ERROR_RAP)

/////////
// Log //
/////////

static void logAccess(int statusCode, const char * method, const char * user, const char * url) {
	stdLog("%d %s %s %s", statusCode, method, user, url);
}

/////////////
// End Log //
/////////////

//////////
// Mime //
//////////

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

//////////////
// End Mime //
//////////////

///////////////////////
// Response Creation //
///////////////////////

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
	stdLog("destroying rap %d on %d", processor->pid, processor->socketFd);
	processor->socketFd = -1;
}

static struct RestrictedAccessProcessor * createRap(struct RestrictedAccessProcessor * processor, const char * user,
		const char * password) {

	processor->pid = forkRapProcess(config.rapBinary, &(processor->socketFd));
	if (!processor->pid) {
		return AUTH_ERROR;
	}

	struct Message message;
	message.mID = RAP_AUTHENTICATE;
	message.fd = -1;
	message.bufferCount = 2;
	message.buffers[RAP_USER_INDEX].iov_len = strlen(user) + 1;
	message.buffers[RAP_USER_INDEX].iov_base = (void *) user;
	message.buffers[RAP_PASSWORD_INDEX].iov_len = strlen(password) + 1;
	message.buffers[RAP_PASSWORD_INDEX].iov_base = (void *) password;

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
			stdLogError(0, "Access denied for user %s", user);
			return AUTH_FAILED;
		}
	}

	processor->user = user;
	time(&processor->rapCreated);

	stdLog("RAP %d authenticated on %d", processor->pid, processor->socketFd);

	return processor;
}

static int compareRapGroup(const void * rapA, const void * rapB) {
	int result = strcmp(((struct RapGroup *) rapA)->user, ((struct RapGroup *) rapB)->user);
	if (result == 0) {
		result = strcmp(((struct RapGroup *) rapA)->password, ((struct RapGroup *) rapB)->password);
	}
	return result;
}

static struct RestrictedAccessProcessor * acquireRapFromDb(const char * user, const char * password) {
	struct RapGroup groupToFind = { .user = user, .password = password };
	sem_wait(&rapDBLock);
	struct RapGroup *groupFound = bsearch(&groupToFind, rapDB, rapDBSize, sizeof(struct RapGroup), &compareRapGroup);
	struct RestrictedAccessProcessor * rapSessionFound = NULL;
	if (groupFound) {
		time_t expireTime;
		time(&expireTime);
		expireTime -= config.rapMaxSessionLife;
		for (int i = 0; i < groupFound->rapSessionCount; i++) {
			if (groupFound->rapSession[i].socketFd != -1 && !groupFound->rapSession[i].rapSessionInUse
					&& groupFound->rapSession[i].rapCreated >= expireTime) {
				rapSessionFound = &groupFound->rapSession[i];
				groupFound->rapSession[i].rapSessionInUse = 1;
				break;
			}
		}
	}
	sem_post(&rapDBLock);
	return rapSessionFound;
}

static struct RestrictedAccessProcessor * addRapToDb(struct RestrictedAccessProcessor * rapSession,
		const char * password) {
	struct RestrictedAccessProcessor * newRapSession;
	struct RapGroup groupToFind;
	groupToFind.user = rapSession->user;
	groupToFind.password = password;
	sem_wait(&rapDBLock);
	struct RapGroup *groupFound = bsearch(&groupToFind, rapDB, rapDBSize, sizeof(struct RapGroup), &compareRapGroup);
	if (groupFound) {
		newRapSession = NULL;
		for (int i = 0; i < groupFound->rapSessionCount; i++) {
			if (groupFound->rapSession[i].socketFd == -1) {
				newRapSession = &groupFound->rapSession[i];
				break;
			}
		}
		if (!newRapSession) {
			// TODO limit session count
			groupFound->rapSessionCount++;
			groupFound->rapSession = reallocSafe(groupFound->rapSession,
					sizeof(struct RestrictedAccessProcessor) * groupFound->rapSessionCount);
			newRapSession = &groupFound->rapSession[groupFound->rapSessionCount - 1];
		}
	} else {
		rapDBSize++;
		rapDB = reallocSafe(rapDB, rapDBSize * sizeof(struct RapGroup));
		groupFound = &rapDB[rapDBSize - 1];
		size_t userSize = strlen(groupToFind.user) + 1;
		size_t passwordSize = strlen(groupToFind.password) + 1;
		size_t bufferSize = userSize + passwordSize;
		char * buffer = mallocSafe(bufferSize);
		memcpy(buffer, groupToFind.user, userSize);
		memcpy(buffer + userSize, groupToFind.password, passwordSize);
		groupFound->user = buffer;
		groupFound->password = buffer + userSize;
		groupFound->rapSessionCount = 1;
		groupFound->rapSession = mallocSafe(sizeof(struct RestrictedAccessProcessor));
		newRapSession = &groupFound->rapSession[0];
		qsort(rapDB, rapDBSize, sizeof(struct RapGroup), &compareRapGroup);
	}
	*newRapSession = *rapSession;
	newRapSession->user = groupFound->user;
	newRapSession->rapSessionInUse = 1;
	sem_post(&rapDBLock);
	return newRapSession;
}

static void releaseRap(struct RestrictedAccessProcessor * processor) {
	processor->rapSessionInUse = 0;
}

static struct RestrictedAccessProcessor * acquireRap(struct MHD_Connection *request) {
	char * user;
	char * password;
	user = MHD_basic_auth_get_username_password(request, &password);
	if (user && password) {
		struct RestrictedAccessProcessor * rapSession = acquireRapFromDb(user, password);
		if (rapSession) {
			return rapSession;
		} else {
			struct RestrictedAccessProcessor newSession;
			rapSession = createRap(&newSession, user, password);
			if (rapSession != &newSession) {
				return rapSession;
			} else {
				return addRapToDb(rapSession, password);
			}
		}
	} else {
		stdLogError(0, "Rejecting request without auth");
		return AUTH_FAILED;
	}
}

static void cleanupAfterRap(int sig, siginfo_t *siginfo, void *context) {
	int status;
	waitpid(siginfo->si_pid, &status, 0);
	if (status == 139) {
		stdLogError(0, "RAP %d failed with segmentation fault", siginfo->si_pid);
	}
	//stdLog("Child finished PID: %d staus: %d", siginfo->si_pid, status);
}

static void * rapTimeoutWorker(void * ignored) {
	// TODO actually free() something
	while (1) {
		sleep(config.rapMaxSessionLife / 2);
		time_t expireTime;
		time(&expireTime);
		expireTime -= config.rapMaxSessionLife;
		stdLog("Cleaning");
		sem_wait(&rapDBLock);
		for (int group = 0; group < rapDBSize; group++) {
			for (int rap = 0; rap < rapDB[group].rapSessionCount; rap++) {
				if (!rapDB[group].rapSession[rap].rapSessionInUse && rapDB[group].rapSession[rap].socketFd != -1
						&& rapDB[group].rapSession[rap].rapCreated < expireTime) {
					destroyRap(&rapDB[group].rapSession[rap]);
				}
			}
		}
		sem_post(&rapDBLock);
	}
	return NULL;
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
			stdLogError(bytesRead < 0 ? errno : 0, "Could not read whole file %s", file);
			free(mimeFileBuffer);
			return NULL;
		}
	}
	*size = stat.st_size;
	return buffer;
}

static void initializeMimeTypes() {
	// Load Mime file into memory
	mimeFileBuffer = loadFileToBuffer(config.mimeTypesFile, &mimeFileBufferSize);
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

static void initializeRapDatabase() {
	struct sigaction act;
	memset(&act, 0, sizeof(act));
	act.sa_sigaction = &cleanupAfterRap;
	act.sa_flags = SA_SIGINFO;
	if (sigaction(SIGCHLD, &act, NULL) < 0) {
		stdLogError(errno, "Could not set handler method for finished child threads");
		exit(255);
	}

	sem_init(&rapDBLock, 0, 1);

	rapDBSize = 0;
	rapDB = NULL;

	pthread_t newThread;
	if (pthread_create(&newThread, NULL, &rapTimeoutWorker, NULL)) {
		stdLogError(errno, "Could not create worker thread for rap db");
		exit(255);
	}
}

////////////////////////
// End Initialisation //
////////////////////////z

//////////
// Main //
//////////

#define CONFIG_NAMESPACE "http://couling.me/webdavd"

char * copyString(const char * string) {
	if (!string) {
		return NULL;
	}
	size_t stringSize = strlen(string) + 1;
	char * newString = mallocSafe(stringSize);
	memcpy(newString, string, stringSize);
	return newString;
}

int configureServer(xmlTextReaderPtr reader, const char * configFile, struct WebdavdConfiguration * config) {
	config->restrictedUser = NULL;
	config->daemonCount = 0;
	config->daemons = NULL;
	config->rapMaxSessionLife = 60 * 5;
	config->rapMaxSessionsPerUser = 10;
	config->rapBinary = NULL;
	config->pamServiceName = NULL;
	config->mimeTypesFile = NULL;
	config->accessLog = NULL;
	config->errorLog = NULL;
	config->sslCertCount = 0;
	config->sslCerts = NULL;

	int result = stepInto(reader);
	while (result && xmlTextReaderDepth(reader) == 2) {
		if (xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT
				&& !strcmp(xmlTextReaderConstNamespaceUri(reader), CONFIG_NAMESPACE)) {

			//<listen><port>80</port><host>localhost</host><encryption>disabled</encryption></listen>
			if (!strcmp(xmlTextReaderConstLocalName(reader), "listen")) {
				int index = config->daemonCount++;
				config->daemons = reallocSafe(config->daemons, sizeof(*config->daemons) * config->daemonCount);
				config->daemons[index].host = NULL;
				config->daemons[index].sslEnabled = 0;
				config->daemons[index].port = -1;
				result = stepInto(reader);
				while (result && xmlTextReaderDepth(reader) == 3) {
					if (xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT
							&& !strcmp(xmlTextReaderConstNamespaceUri(reader), CONFIG_NAMESPACE)) {
						if (!strcmp(xmlTextReaderConstLocalName(reader), "port")) {
							if (config->daemons[index].port != -1) {
								stdLogError(0, "port specified for listen more than once int %s", configFile);
								exit(1);
							}
							const char * portString;
							result = stepOverText(reader, &portString);
							if (portString != NULL) {
								char * endP;
								long int parsedPort = strtol(portString, &endP, 10);
								if (!*endP && parsedPort >= 0 && parsedPort <= 0xFFFF) {
									config->daemons[index].port = parsedPort;
								} else {
									stdLogError(0, "%s is not a valid port in %s", portString, configFile);
									exit(1);
								}
							}
						} else if (!strcmp(xmlTextReaderConstLocalName(reader), "host")) {
							if (config->daemons[index].host != NULL) {
								stdLogError(0, "host specified for listen more than once int %s", configFile);
								exit(1);
							}
							const char * hostString;
							result = stepOverText(reader, &hostString);
							config->daemons[index].host = copyString(hostString);
						} else if (!strcmp(xmlTextReaderConstLocalName(reader), "encryption")) {
							const char * encryptionString;
							result = stepOverText(reader, &encryptionString);
							if (encryptionString) {
								if (!strcmp(encryptionString, "none")) {
									config->daemons[index].sslEnabled = 0;
								} else if (!strcmp(encryptionString, "ssl")) {
									config->daemons[index].sslEnabled = 1;
								} else {
									stdLogError(0, "invalid encryption method %s in %s", encryptionString, configFile);
									exit(1);
								}
							}
						}
					} else {
						result = stepOver(reader);
					}
				}
				if (config->daemons[index].port == -1) {
					stdLogError(0, "port not specified for listen in %s", configFile);
					exit(1);
				}
			}

			//<session-timeout>5:00</session-timeout>
			else if (!strcmp(xmlTextReaderConstLocalName(reader), "session-timeout")) {
				const char * sessionTimeoutString;
				result = stepOverText(reader, &sessionTimeoutString);
				if (sessionTimeoutString) {
					long int hour = 0, minute = 0, second;
					char * endPtr;
					second = strtol(sessionTimeoutString, &endPtr, 10);
					if (*endPtr) {
						if (*endPtr != ':' || endPtr == sessionTimeoutString) {
							stdLogError(0, "Invalid session timeout length %s in %s", sessionTimeoutString, configFile);
							exit(1);
						}
						minute = second;

						char * endPtr2;
						endPtr++;
						second = strtol(endPtr, &endPtr2, 10);
						if (*endPtr2) {
							if (*endPtr2 != ':' || endPtr2 == endPtr) {
								stdLogError(0, "Invalid session timeout length %s in %s", sessionTimeoutString,
										configFile);
								exit(1);
							}
							hour = minute;
							minute = second;
							endPtr2++;
							second = strtol(endPtr2, &endPtr, 10);
							if (*endPtr != '\0') {
								stdLogError(0, "Invalid session timeout length %s in %s", sessionTimeoutString,
										configFile);
								exit(1);
							}
						}
					}
					config->rapMaxSessionLife = (((hour * 60) + minute) * 60) + second;
				}
			}

			//<max-user-sessions>10</max-user-sessions>
			else if (!strcmp(xmlTextReaderConstLocalName(reader), "max-user-sessions")) {
				const char * sessionCountString;
				result = stepOverText(reader, &sessionCountString);
				if (sessionCountString) {
					char * endPtr;
					long int maxUserSessions = strtol(sessionCountString, &endPtr, 10);
					if (*endPtr || maxUserSessions < 0 || maxUserSessions > 0xFFFFFFF) {
						stdLogError(0, "Invalid max-user-sessions %s in %s", maxUserSessions, configFile);
						exit(1);
					}
					config->rapMaxSessionsPerUser = maxUserSessions;
				}
			}

			//<restricted>nobody</restricted>
			else if (!strcmp(xmlTextReaderConstLocalName(reader), "restricted")) {
				if (config->restrictedUser) {
					stdLogError(0, "restricted-user specified more than once in %s", configFile);
					exit(1);
				}
				const char * restrictedUser;
				result = stepOverText(reader, &restrictedUser);
				config->restrictedUser = copyString(restrictedUser);
			}

			//<mime-file>/etc/mime.types</mime-file>
			else if (!strcmp(xmlTextReaderConstLocalName(reader), "mime-file")) {
				if (config->mimeTypesFile) {
					stdLogError(0, "restricted-user specified more than once in %s", configFile);
					exit(1);
				}
				const char * mimeTypesFile;
				result = stepOverText(reader, &mimeTypesFile);
				config->mimeTypesFile = copyString(mimeTypesFile);
			}

			//<rap-binary>/usr/sbin/rap</rap-binary>
			else if (!strcmp(xmlTextReaderConstLocalName(reader), "rap-binary")) {
				if (config->rapBinary) {
					stdLogError(0, "restricted-user specified more than once in %s", configFile);
					exit(1);
				}
				const char * rapBinary;
				result = stepOverText(reader, &rapBinary);
				config->rapBinary = copyString(rapBinary);
			}

			//<static-error-dir>/usr/share/webdavd</static-error-dir>
			// TODO <static-error-dir>/usr/share/webdavd</static-error-dir>

			//<pam-service>webdavd</pam-service>
			else if (!strcmp(xmlTextReaderConstLocalName(reader), "pam-service")) {
				if (config->pamServiceName) {
					stdLogError(0, "restricted-user specified more than once in %s", configFile);
					exit(1);
				}
				const char * pamServiceName;
				result = stepOverText(reader, &pamServiceName);
				config->pamServiceName = copyString(pamServiceName);
			}

			//<access-log>/var/log/access.log</access-log>
			else if (!strcmp(xmlTextReaderConstLocalName(reader), "access-log")) {
				if (config->accessLog) {
					stdLogError(0, "restricted-user specified more than once in %s", configFile);
					exit(1);
				}
				const char * accessLog;
				result = stepOverText(reader, &accessLog);
				config->accessLog = copyString(accessLog);
			}

			//<error-log>/var/log/error.log</error-log>
			else if (!strcmp(xmlTextReaderConstLocalName(reader), "error-log")) {
				if (config->errorLog) {
					stdLogError(0, "restricted-user specified more than once in %s", configFile);
					exit(1);
				}
				const char * errorLog;
				result = stepOverText(reader, &errorLog);
				config->errorLog = copyString(errorLog);
			}

			//<ssl-cert>...</ssl-cert>
			else if (!strcmp(xmlTextReaderConstLocalName(reader), "ssl-cert")) {
				int index = config->sslCertCount++;
				config->sslCerts = reallocSafe(config->sslCerts, sizeof(*config->sslCerts) * config->sslCertCount);
				config->sslCerts[index].certificate = NULL;
				config->sslCerts[index].chainFileCount = 0;
				config->sslCerts[index].chainFiles = NULL;
				config->sslCerts[index].keyFile = NULL;
				result = stepInto(reader);
				while (result && xmlTextReaderDepth(reader) == 3) {
					if (xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT
							&& !strcmp(xmlTextReaderConstNamespaceUri(reader), CONFIG_NAMESPACE)) {
						if (!strcmp(xmlTextReaderConstLocalName(reader), "certificate")) {
							if (config->sslCerts[index].certificate) {
								stdLogError(0, "more than one certificate specified in ssl-cert %s", configFile);
								exit(1);
							}
							const char * certificate;
							result = stepOverText(reader, &certificate);
							config->sslCerts[index].certificate = copyString(certificate);
						} else if (!strcmp(xmlTextReaderConstLocalName(reader), "key")) {
							if (config->sslCerts[index].keyFile) {
								stdLogError(0, "more than one key specified in ssl-cert %s", configFile);
								exit(1);
							}
							const char * keyFile;
							result = stepOverText(reader, &keyFile);
							config->sslCerts[index].keyFile = copyString(keyFile);
						} else if (!strcmp(xmlTextReaderConstLocalName(reader), "chain")) {
							const char * chainFile;
							result = stepOverText(reader, &chainFile);
							if (chainFile) {
								int chainFileIndex = config->sslCerts[index].chainFileCount++;
								config->sslCerts[index].chainFiles = reallocSafe(config->sslCerts[index].chainFiles,
										config->sslCerts[index].chainFileCount
												* sizeof(*config->sslCerts[index].chainFiles));
								config->sslCerts[index].chainFiles[chainFileIndex] = copyString(chainFile);
							}
						} else {
							result = stepOver(reader);
						}
					} else {
						result = stepOver(reader);
					}
				}
				if (!config->sslCerts[index].certificate) {
					stdLogError(0, "certificate not specified in ssl-cert in %s", configFile);
				}
				if (!config->sslCerts[index].keyFile) {
					stdLogError(0, "key not specified in ssl-cert in %s", configFile);
				}
			} else {
				result = stepOver(reader);
			}

		} else {
			result = stepOver(reader);
		}
	}

	if (!config->rapBinary) {
		config->rapBinary = "/usr/sbin/rap";
	}
	if (!config->mimeTypesFile) {
		config->mimeTypesFile = "/etc/mime.types";
	}
	if (!config->accessLog) {
		config->accessLog = "/var/log/webdavd-access.log";
	}
	if (!config->errorLog) {
		config->errorLog = "/var/log/webdavd-error.log";
	}
	if (!config->pamServiceName) {
		config->pamServiceName = "webdav";
	}

	return result;
}

void configure(const char * configFile) {
	xmlTextReaderPtr reader = xmlReaderForFile(configFile, NULL, XML_PARSE_NOENT);
	if (!reader || !stepInto(reader)) {
		stdLogError(0, "could not create xml reader for %s", configFile);
		exit(1);
	}
	if (!elementMatches(reader, CONFIG_NAMESPACE, "server-config")) {
		stdLogError(0, "root node is not server-config in namespace %s %s", CONFIG_NAMESPACE, configFile);
		exit(1);
	}

	int result = stepInto(reader);

	while (result && xmlTextReaderDepth(reader) == 1) {
		if (elementMatches(reader, CONFIG_NAMESPACE, "server")) {
			result = configureServer(reader, configFile, &config);
			break;
		} else {
			stdLog("Warning: skipping %s:%s in %s", xmlTextReaderConstNamespaceUri(reader),
					xmlTextReaderConstLocalName(reader), configFile);
			result = stepOver(reader);
		}
	}

	xmlFreeTextReader(reader);
}

int main(int argCount, char ** args) {
	if (argCount > 1) {
		for (int i = 1; i < argCount; i++) {
			configure(args[i]);
		}
	} else {
		configure("/etc/webdavd");
	}

	initializeMimeTypes();
	initializeStaticResponses();
	initializeRapDatabase();

	// Start up the daemons
	daemons = mallocSafe(sizeof(struct MHD_Daemon *) * config.daemonCount);
	for (int i = 0; i < config.daemonCount; i++) {
		daemons[i] = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY | MHD_USE_PEDANTIC_CHECKS, config.daemons[i].port, NULL,
		NULL, (MHD_AccessHandlerCallback) &answerToRequest, NULL, MHD_OPTION_END);

		if (!daemons[i]) {
			stdLogError(errno, "Unable to initialise daemon on port %d", config.daemons[i].port);
			exit(255);
		}
	}

	pthread_exit(NULL);
}

//////////////
// End Main //
//////////////
