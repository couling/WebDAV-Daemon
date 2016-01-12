#include <sys/stat.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <limits.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <microhttpd.h>

#include "shared.h"

static struct MHD_Daemon **daemons;
static int daemonPorts[] = { 8888 };
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

static int fdContentReader(int *fd, uint64_t pos, char *buf, size_t max) {
	size_t bytesRead = read(*fd, buf, max);
	if (bytesRead < 0) {
		// error
		return -2;
	}
	if (bytesRead == 0) {
		// End of stream
		return -1;
	}
	return bytesRead;
}

static void fdContentReaderCleanup(int *fd) {
	close(*fd);
	free(fd);
	void *MHD_ContentReaderFreeCallback(void *cls);
}

static int queueFdResponse(struct MHD_Connection *request, int fd) {
	struct stat statBuffer;
	if (!fstat(fd, &statBuffer) && (statBuffer.st_mode | S_IFMT == S_IFREG)) {
		fprintf(stderr, "Serving regular file\n");
		struct MHD_Response * response = MHD_create_response_from_fd((uint64_t) statBuffer.st_size, fd);
		if (!response)
			return MHD_NO;
		int ret = MHD_queue_response(request, MHD_HTTP_OK, response);
		MHD_destroy_response(response);
		return ret;
	} else {
		int * fdAllocated = mallocSafe(sizeof(int));
		*fdAllocated = fd;
		struct MHD_Response * response = MHD_create_response_from_callback(-1, 4096,
				(MHD_ContentReaderCallback) &fdContentReader, fdAllocated,
				(MHD_ContentReaderFreeCallback) & fdContentReaderCleanup);
		if (!response)
			return MHD_NO;
		int ret = MHD_queue_response(request, MHD_HTTP_OK, response);
		MHD_destroy_response(response);
		return ret;
	}
}

static int filterHostHeader(const char ** host, enum MHD_ValueKind kind, const char *key, const char *value) {
	if (!strcmp(key, "Host")) {
		*host = value;
	}
	return MHD_YES;
}

static int forkSockExec(const char * path, int * newSockFd) {
	// Create unix domain socket for
	int sockFd[2];
	int result = socketpair(PF_LOCAL, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockFd);
	if (result != 0) {
		perror("socketpair() failed");
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
			return 0;
		}
	} else {
		// child
		// Sort out socket
		if (dup2(sockFd[1], STDIN_FILENO) == -1 || dup2(sockFd[1], STDOUT_FILENO) == -1) {
			fprintf(stderr, "Could not assign new socket (%d) to stdin/stdout\n", newSockFd[1]);
			perror("Assigning socket to stdin/stdout");
			exit(255);
		}

		//close(newSockFd[0]);
		//close(newSockFd[1]);
		char * argv[] = { NULL };
		execv(path, argv);
		perror("Could not run program");
		exit(255);
	}
}

static void destroyRestrictedAccessProcessor(struct RestrictedAccessProcessor * processor) {
	close(processor->socketFd);
	free(processor->user);
}

static int createRestrictedAccessProcessor(struct MHD_Connection *request,
		struct RestrictedAccessProcessor ** newProcessor, const char * user, const char * password) {

	struct RestrictedAccessProcessor * processor = mallocSafe(sizeof(struct RestrictedAccessProcessor));
	processor->pid = forkSockExec(RAP_PATH, &(processor->socketFd));
	if (!processor->pid) {
		free(processor);
		*newProcessor = NULL;
		perror("Could not fork ");
		return queueInternalServerError(request);
	}
	size_t userLen = strlen(user) + 1;
	size_t passLen = strlen(password) + 1;
	size_t bufferSize = userLen + passLen;
	processor->user = mallocSafe(bufferSize);
	processor->password = processor->user + userLen;
	memcpy(processor->user, user, userLen);
	memcpy(processor->password, password, passLen);
	struct iovec message[3];
	enum RAPAction action = RAP_AUTHENTICATE;
	message[RAP_ACTION_INDEX].iov_len = sizeof(action);
	message[RAP_ACTION_INDEX].iov_base = &action;
	message[RAP_USER_INDEX].iov_len = userLen;
	message[RAP_USER_INDEX].iov_base = processor->user;
	message[RAP_PASSWORD_INDEX].iov_len = passLen;
	message[RAP_PASSWORD_INDEX].iov_base = processor->password;
	if (sock_fd_write(processor->socketFd, 3, message, -1) <= 0) {
		destroyRestrictedAccessProcessor(processor);
		free(processor);
		*newProcessor = NULL;
		perror("sendmsg auth");
		return queueInternalServerError(request);
	}
	enum RAPResult authResult;
	// TODO implement timeout ... possibly using "select"
	message[0].iov_len = sizeof(authResult);
	message[0].iov_base = &authResult;

	int bufferCount = 1;
	size_t readResult = sock_fd_read(processor->socketFd, &bufferCount, message, NULL);
	if (readResult <= 0 || authResult != RAP_SUCCESS) {
		destroyRestrictedAccessProcessor(processor);
		free(processor);
		*newProcessor = NULL;
		if (readResult < 0) {
			perror("Could not read result from RAP ");
		} else if (readResult == 0) {
			fprintf(stderr, "RAP closed socket unexpectedly\n");
		} else {
			fprintf(stderr, "Access deined for user %s\n", user);
		}
		return queueInternalServerError(request);
	}

	// TODO check the response code from the request

	*newProcessor = processor;

	return MHD_YES;
}

static int authLookup(struct MHD_Connection *request, struct RestrictedAccessProcessor ** processor) {
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

static enum RAPAction selectRAPAction(const char * method) {
// TODO analyse method to give the correct response;
	if (!strcmp("GET", method))
		return RAP_READ_FILE;
	else
		return RAP_INVALID_METHOD;
}

static int processNewRequest(struct MHD_Connection *request, const char *url, const char *method,
		struct WriteHandle **writeHandle) {
	// TODO handle put requests!

	// Interpret the method
	enum RAPAction action = selectRAPAction(method);
	if (action == RAP_INVALID_METHOD) {
		// TODO handle bad responses to bulky PUT requests.
		struct Header headers[0];
		headers[0].headerKey = "Allow";
		headers[0].headerValue = "GET, HEAD, PUT";
		return queueStringResponse(request, MHD_HTTP_METHOD_NOT_ACCEPTABLE, "Method Not Supported", 1, headers);
	}

	// Get the host header
	char * host;
	if (!MHD_get_connection_values(request, MHD_HEADER_KIND, (MHD_KeyValueIterator) &filterHostHeader, &host)) {
		return queueInternalServerError(request);
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

	// Send the request to the RAP
	struct iovec message[3];
	message[RAP_ACTION_INDEX].iov_len = sizeof(action);
	message[RAP_ACTION_INDEX].iov_base = &action;
	message[RAP_HOST_INDEX].iov_len = strlen(host) + 1;
	message[RAP_HOST_INDEX].iov_base = host;
	message[RAP_FILE_INDEX].iov_len = strlen(url) + 1;
	message[RAP_FILE_INDEX].iov_base = (void *) url;

	if (sock_fd_write(rapSocketSession->socketFd, 3, message, -1) < 0) {
		perror("Sending request to RAP");
		return queueInternalServerError(request);
	}

	// Get result from RAP
	int fd;
	enum RAPResult result;
	message[0].iov_len = sizeof(result);
	message[0].iov_base = &result;
	int bufferCount = 1;
	int readResult = sock_fd_read(rapSocketSession->socketFd, &bufferCount, message, &fd);
	if (readResult <= 0) {
		if (readResult < 0) {
			perror("Reading response from RAP");
		} else {
			fprintf(stderr, "RAP closed socket unexpectedly while waiting for response\n");
		}
		return MHD_NO;
	}

	switch (result) {
	case RAP_SUCCESS:
		return queueFdResponse(request, fd);
	case RAP_ACCESS_DENIED:
		return queueSimpleStringResponse(request, MHD_HTTP_FORBIDDEN, "Access denied");
	case RAP_NOT_FOUND:
		return queueSimpleStringResponse(request, MHD_HTTP_NOT_FOUND, "File not found");
	default:
		fprintf(stderr, "invalid response from RAP %d\n", (int) result);
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
		return queueSimpleStringResponse(request, MHD_HTTP_OK, "Upload failed!");
	}

	return MHD_YES;
}

static int answerToRequest(void *cls, struct MHD_Connection *request, const char *url, const char *method,
		const char *version, const char *upload_data, size_t *upload_data_size, struct WriteHandle ** writeHandle) {

	// We can only accept http 1.1 sessions
	// Http 1.0 is old and REALLY shouldn't be used
	// It misses out the "Host" header which is required for this program to function correctly
	if (strcmp(version, "HTTP/1.1")) {
		fprintf(stderr, "HTTP Version not supported, only HTTP/1.1 is accepted. Supplied: %s\n", version);
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
		fprintf(stderr, "Unable to initialise daemon on port %d\n", port);
		exit(255);
	}
}

static void cleanupZombyChildren(int sig, siginfo_t *siginfo, void *context) {
	int status;
	waitpid(siginfo->si_pid, &status, 0);
	fprintf(stderr, "Child finished PID: %d staus: %d\n", siginfo->si_pid, status);
}

int main(int argCount, char ** args) {
	// Avoid zombie children
	struct sigaction act;
	memset(&act, 0, sizeof(act));
	act.sa_sigaction = &cleanupZombyChildren;
	act.sa_flags = SA_SIGINFO;
	if (sigaction(SIGCHLD, &act, NULL) < 0) {
		perror("sigaction");
		return 255;
	}

	// Start up the daemons
	daemons = mallocSafe(sizeof(struct MHD_Daemon *) * daemonCount);
	for (int i = 0; i < daemonCount; i++) {
		initializeDaemin(daemonPorts[i], &(daemons[i]));
	}

	pthread_exit(NULL);
}
