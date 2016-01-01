#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include "shared.h"

void * mallocSafe(size_t size) {
	void * result = malloc(size);
	if (result) {
		return result;
	} else {
		fprintf(stderr, "Could not allocate memory! Exiting.\n");
		exit(255);
	}
}

static void moveFd(int fromFd, int toFd) {
	if (dup2(fromFd, toFd) == -1) {
		fprintf(stderr, "Could not move FD\n");
		exit(255);
	} else {
		close(fromFd);
	}
}

#define FD_READ  0
#define FD_WRITE 1

int forkPipeExec(const char * path, char * const argv[], DataSession * dataSession, int errFd) {
	// Create pipes for stdin and stdout
	int inFd[2];
	int outFd[2];
	int result = pipe2(inFd, O_CLOEXEC);
	if (!result) {
		return result;
	}

	result = pipe2(outFd, O_CLOEXEC);
	if (!result) {
		close(inFd[0]);
		close(inFd[1]);
		return result;
	}

	result = fork();
	if (result) {
		// parent
		close(inFd[FD_READ]);
		close(outFd[FD_WRITE]);
		if (result == -1) {
			// fork failed so close parent pipes and return non-zero
			close(inFd[FD_WRITE]);
			close(outFd[FD_READ]);
			return result;
		}

		dataSession->fdIn = inFd[FD_WRITE];
		dataSession->fdOut = outFd[FD_WRITE];

		return 0;
	} else {
		// child
		// Sort out pipes
		close(inFd[FD_WRITE]);
		close(outFd[FD_READ]);
		moveFd(inFd[FD_READ], STDIN_FILENO);
		moveFd(outFd[FD_WRITE], STDOUT_FILENO);
		if (STDERR_FILENO != errFd) {
			moveFd(errFd, STDERR_FILENO);
		}

		execv(path, argv);
		perror("Could not run program");
		exit(255);
	}
}
