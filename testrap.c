#include "shared.h"

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>

#define BUFFER_SIZE 4096

static int authenticated = 0;

static size_t respond(enum RAPResult result, int fd) {
	struct iovec header;
	header.iov_base = &result;
	header.iov_len = sizeof(result);
	return sock_fd_write(STDOUT_FILENO, 1, &header, fd);
}

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
	char * user = (char *) bufferHeaders[RAP_USER_INDEX].iov_base;
	char * password = (char *) bufferHeaders[RAP_PASSWORD_INDEX].iov_base;
	user[BUFFER_SIZE - 1] = '\0';
	password[BUFFER_SIZE - 1] = '\0';

	fprintf(stderr, "Login request for %s %s\n", user, password);
	if (authenticated || bufferCount != 3) {
		return respond(RAP_BAD_REQUEST, -1);
	}

	if (!strcmp("AAA", user) && !strcmp("BBB", password)) {
		return respond(RAP_SUCCESS, -1);
	} else {
		return respond(RAP_AUTH_FAILLED, -1);
	}
}

// RAP_AUTHENTICATE, RAP_INVALID_METHOD, RAP_READ_FILE, RAP_WRITE_FILE, RAP_LIST_FOLDER
typedef size_t (*handlerMethod)(int bufferCount, struct iovec * bufferHeaders);
static handlerMethod handlerMethods[] = { authenticate, NULL, readFile, writeFile, listFolder };

int main(int argCount, char ** args) {
	int bufferCount = 3;
	char buffer[3][BUFFER_SIZE];
	struct iovec bufferHeaders[3];
	size_t ioResult;
	do {
		// Initialise buffers
		for (int i = 0; i < 3; i++) {
			bufferHeaders[i].iov_len = BUFFER_SIZE;
			bufferHeaders[i].iov_base = buffer[i];
		}

		// Read a message
		size_t ioResult = sock_fd_read(STDIN_FILENO, &bufferCount, bufferHeaders, NULL);
		if (ioResult <= 0) {
			if (ioResult < 0) {
				perror("Reading auth from socket");
				exit(1);
			} else {
				continue;
			}
		}

		// Handle the message
		enum RAPAction request = *((enum RAPAction *) buffer[RAP_ACTION_INDEX]);
		if (request < 0 || request > RAP_MAX || request == RAP_INVALID_METHOD) {
			ioResult = respond(RAP_BAD_REQUEST, -1);
			continue;
		}
		fprintf(stderr, "Request for %d with %d buffers:", (int) request, bufferCount);
		for (int i=1; i<bufferCount; i++) {
			fprintf(stderr, " %d",(int)bufferHeaders[i].iov_len);
			int x =write(STDERR_FILENO, bufferHeaders[i].iov_base, bufferHeaders[i].iov_len);
		}
		fprintf(stderr, "\n");
		ioResult = handlerMethods[request](bufferCount, bufferHeaders);

	} while (ioResult);
	return 0;
}
