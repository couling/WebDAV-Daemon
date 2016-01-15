#include "shared.h"

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>

#define BUFFER_SIZE 4096

static int authenticated = 0;

#define respond(result, fd) sendMessage(STDOUT_FILENO, result, fd, 0, NULL)

static size_t listFolder(int bufferCount, struct iovec * bufferHeaders) {
	return respond(RAP_BAD_REQUEST, -1);
}

static size_t writeFile(int bufferCount, struct iovec * bufferHeaders) {
	return respond(RAP_BAD_REQUEST, -1);
}

static size_t readFile(int bufferCount, struct iovec * bufferHeaders) {
	if (!authenticated || bufferCount != 3) {
		return respond(RAP_BAD_REQUEST, -1);
	}
	const char * file = "items.txt";
	int fd = open(file, O_RDONLY);
	if (fd == -1) {
		int e = errno;
		switch (e) {
		case EACCES:
			return respond(RAP_ACCESS_DENIED, -1);
		case ENOENT:
		default:
			return respond(RAP_NOT_FOUND, -1);
		}
	} else {
		return respond(RAP_SUCCESS, fd);
	}
}

static size_t authenticate(int bufferCount, struct iovec * bufferHeaders) {
	if (authenticated || bufferCount != 2) {
		if (authenticated) {
			fprintf(stderr, "Login request for already logged in RAP\n");
		} else {
			fprintf(stderr, "Login request did not provide both user and password and gave %d buffer(s)\n",
					bufferCount);
		}
		return respond(RAP_BAD_REQUEST, -1);
	}

	char * user = (char *) bufferHeaders[RAP_USER_INDEX].iov_base;
	char * password = (char *) bufferHeaders[RAP_PASSWORD_INDEX].iov_base;
	user[bufferHeaders[RAP_USER_INDEX].iov_len - 1] = '\0';
	password[bufferHeaders[RAP_PASSWORD_INDEX].iov_len - 1] = '\0';

	if (!strcmp("AAA", user) && !strcmp("BBB", password)) {
		fprintf(stderr, "Login request accepted for %s\n", user);
		return respond(RAP_SUCCESS, -1);
	} else {
		fprintf(stderr, "Login request denied for %s\n", user);
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
		size_t ioResult = recvMessage(STDIN_FILENO, &mID, NULL, &bufferCount, bufferHeaders);
		if (ioResult <= 0) {
			if (ioResult < 0) {
				perror("Reading auth from socket");
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
			perror("sendmsg:");
			ioResult = 0;
		}

	} while (ioResult);
	return 0;
}
