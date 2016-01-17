#include "shared.h"

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>

#define BUFFER_SIZE 4096

static int authenticated = 0;
static const char * authenticatedUser;

#define respond(result, fd) sendMessage(STDOUT_FILENO, result, fd, 0, NULL)

static char * iovecToString(struct iovec * iovec) {
	char * buffer = iovec->iov_base;
	buffer[iovec->iov_len -1] = '\0';
	return buffer;
}

static size_t listFolder(int bufferCount, struct iovec * bufferHeaders) {
	return respond(RAP_BAD_REQUEST, -1);
}

static size_t writeFile(int bufferCount, struct iovec * bufferHeaders) {
	return respond(RAP_BAD_REQUEST, -1);
}

static size_t readFile(int bufferCount, struct iovec * bufferHeaders) {
	if (!authenticated || bufferCount != 2) {
		if (!authenticated) {
			stdLogError(0, "Not authenticated RAP");
		} else {
			stdLogError(0, "Get request did not provide correct buffers: %d buffer(s)", bufferCount);
		}
		return respond(RAP_BAD_REQUEST, -1);
	}

	char * host = iovecToString(&bufferHeaders[RAP_HOST_INDEX]);
	char * file = iovecToString(&bufferHeaders[RAP_FILE_INDEX]);

	int fd = open(file, O_RDONLY);
	if (fd == -1) {
		int e = errno;
		switch (e) {
		case EACCES:
			stdLogError(e, "GET access denied %s %s %s", authenticatedUser, host, file);
			return respond(RAP_ACCESS_DENIED, -1);
		case ENOENT:
		default:
			stdLogError(e, "GET not found %s %s %s", authenticatedUser, host, file);
			return respond(RAP_NOT_FOUND, -1);
		}
	} else {
		stdLog("GET success %s %s %s", authenticatedUser, host, file);
		return respond(RAP_SUCCESS_SOURCE_DATA, fd);
	}
}

static int pamAuthenticate(const char * user, const char * password) {
	return strcmp("philip", user) && !strcmp("BBB", password);
}

static size_t authenticate(int bufferCount, struct iovec * bufferHeaders) {
	if (authenticated || bufferCount != 2) {
		if (authenticated) {
			stdLogError(0, "Login for already logged in RAP");
		} else {
			stdLogError(0, "Login did not provide both user and password and gave %d buffer(s)", bufferCount);
		}
		return respond(RAP_BAD_REQUEST, -1);
	}

	char * user = (char *) bufferHeaders[RAP_USER_INDEX].iov_base;
	char * password = (char *) bufferHeaders[RAP_PASSWORD_INDEX].iov_base;
	size_t userBufferSize = bufferHeaders[RAP_USER_INDEX].iov_len;
	user[userBufferSize - 1] = '\0'; // Guarantee a null terminated string
	password[bufferHeaders[RAP_PASSWORD_INDEX].iov_len - 1] = '\0'; // Guarantee a null terminated string

	int authResult;
	if (!pamAuthenticate(user, password)) {
		stdLog("Login accepted for %s", user);
		authenticated = 1;
		char * aUser = mallocSafe(userBufferSize);
		memcpy(aUser, user, userBufferSize);
		authenticatedUser = aUser;
		return respond(RAP_SUCCESS, -1);
	} else {
		stdLogError(0, "Login denied for %s", user);
		return respond(RAP_AUTH_FAILLED, -1);
	}
}

typedef size_t (*handlerMethod)(int bufferCount, struct iovec * bufferHeaders);
static handlerMethod handlerMethods[] = { authenticate, readFile, writeFile, listFolder };

int main(int argCount, char ** args) {
	int bufferCount;
	struct iovec bufferHeaders[MAX_BUFFER_PARTS];
	enum RapConstant mID;
	size_t ioResult;
	do {
		bufferCount = MAX_BUFFER_PARTS;

		// Read a message
		ioResult = recvMessage(STDIN_FILENO, &mID, NULL, &bufferCount, bufferHeaders);
		if (ioResult <= 0) {
			if (ioResult < 0) {
				exit(1);
			} else {
				continue;
			}
		}

		// Handle the message
		if (mID > RAP_MAX_REQUEST || mID < RAP_MIN_REQUEST) {
			ioResult = respond(RAP_BAD_REQUEST, -1);
			continue;
		}
		ioResult = handlerMethods[mID - RAP_MIN_REQUEST](bufferCount, bufferHeaders);
		if (ioResult < 0) {
			ioResult = 0;
		}

	} while (ioResult);
	return 0;
}
