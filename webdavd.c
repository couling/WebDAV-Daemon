#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <microhttpd.h>
#include <limits.h>

#include "shared.h"

#define PORT 8888

struct MHD_Daemon **daemons;
int daemonCount;

struct RestrictedAccessProcessor {
	int pid;
	struct DataSession dataSession;
	struct User user;
	char * socketFile;
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

static int queueAuthRequired(struct MHD_Connection *request) {
	struct Header headers[] = { { .headerKey = "WWW-Authenticate", .headerValue = "Basic realm=\"My Server\"" } };
	return queueStringResponse(request, MHD_HTTP_UNAUTHORIZED, "Access Denied!", 1, headers);
}

static void destroyRestrictedAccessProcessor(struct RestrictedAccessProcessor * processor) {
	close(processor->dataSession.fdIn);
	close(processor->dataSession.fdOut);
	free(processor->socketFile);
	free(processor->user.user);
}

static int createRestrictedAccessProcessor(struct RestrictedAccessProcessor * processor, const struct User * user) {
	processor->pid = forkPipeExec(RAP_PATH, NULL, &(processor->dataSession), STDERR_FILENO);
	if (!processor->pid) {
		perror("Could not fork ");
		return MHD_NO;
	}
	size_t userLen = strlen(user->user) + 1;
	size_t passLen = strlen(user->password) + 1;
	size_t bufferSize = userLen + passLen;
	processor->user.user = mallocSafe(bufferSize);
	processor->user.password = processor->user.user + userLen;
	processor->socketFile = mallocSafe(RAP_PATH_MAX);
	memcpy(processor->user.user, user->user, userLen);
	memcpy(processor->user.password, user->password, passLen);
	if (write(processor->dataSession.fdIn, processor->user.user, bufferSize) != bufferSize) {
		destroyRestrictedAccessProcessor(processor);
		return MHD_NO;
	}

	// TODO implement timeout ... possibly using "select"
	size_t bytesRead = 0;
	do {
		size_t newBytesRead = read(processor->dataSession.fdOut, processor->socketFile + bytesRead,
		RAP_PATH_MAX - bytesRead);

		bytesRead += newBytesRead;
		if (newBytesRead <= 0 || (bytesRead == RAP_PATH_MAX && processor->socketFile[bytesRead - 1] != '\0')) {
			fprintf(stderr, "RAP did not provide complete path\n");
			destroyRestrictedAccessProcessor(processor);
			return MHD_NO;
		}
	} while (processor->socketFile[bytesRead - 1] != '\0');

	return MHD_YES;
}

static int authLookup(struct MHD_Connection *request, struct User * foundUser, struct DataSession * dataSession) {
	foundUser->user = MHD_basic_auth_get_username_password(request, &(foundUser->password));

	if (foundUser->user && foundUser->password) {
		struct RestrictedAccessProcessor rap;
		if (!createRestrictedAccessProcessor(&rap, foundUser)) {
			return queueAuthRequired(request);
		}

		// TODO connect to unix domain socket

		destroyRestrictedAccessProcessor(&rap);
		return MHD_YES;
	}

	foundUser->password = NULL;

	// Authentication failed.
	return queueAuthRequired(request);
}

static int processNewRequest(struct MHD_Connection *request, const char *url, const char *method,
		struct WriteHandle **writeHandle) {

	struct User user;
	struct DataSession rapSocketSession;
	if (!authLookup(request, &user, &rapSocketSession)) {
		// This only happens if a systemic error happens (eg a loss of connection)
		// It does NOT account for authentication failures (access denied).
		return MHD_NO;
	}

	// If the user was not authenticated (access denied) then the authLookup will return the appropriate response
	if (!user.user)
		return MHD_YES;

	// TODO send request to the RAP socket and get back the file handle response
	char dummyString[1024];
	sprintf(dummyString, "User %s Home %s", user.user, user.password);
	struct MHD_Response * response = MHD_create_response_from_buffer(strlen(dummyString), dummyString,
			MHD_RESPMEM_MUST_COPY);
	int ret = MHD_queue_response(request, MHD_HTTP_OK, response);
	MHD_destroy_response(response);

	printf("User %s Home %s URL %s\n", user.user, user.password, url);

	return ret;
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
	if (strcmp(method, "1.1")) {
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

int main(int argCount, char ** args) {
	daemonCount = 1;
	daemons = mallocSafe(sizeof(struct MHD_Daemon *) * daemonCount);

	daemons[0] = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY | MHD_USE_PEDANTIC_CHECKS,
	PORT, NULL, NULL, (MHD_AccessHandlerCallback) &answerToRequest, NULL, MHD_OPTION_END);

	if (!daemons[0]) {
		fprintf(stderr, "Unable to initialise daemon on port %d\n", PORT);
		exit(255);
	}

	pthread_exit(NULL);

	//MHD_stop_daemon(daemon);
	//return 0;
}
