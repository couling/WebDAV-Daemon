#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include "shared.h"

void * mallocSafe(size_t size) {
	void * allocatedMemory = malloc(size);
	if (allocatedMemory) {
		return allocatedMemory;
	} else {
		perror("Could not allocate memory! Exiting!");
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

int forkPipeExec(const char * path, char * const argv[], struct DataSession * dataSession, int errFd) {
	// Create pipes for stdin and stdout
	int inFd[2];
	int outFd[2];
	int result = pipe2(inFd, O_CLOEXEC);
	if (!result) {
		return 0;
	}

	result = pipe2(outFd, O_CLOEXEC);
	if (!result) {
		close(inFd[0]);
		close(inFd[1]);
		return 0;
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
			return 0;
		}

		dataSession->fdIn = inFd[FD_WRITE];
		dataSession->fdOut = outFd[FD_WRITE];

		return result;
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

		if (argv) {
			execv(path, argv);
		} else {
			char * const blankArg[] = { NULL };
			execv(path, blankArg);
		}
		perror("Could not run program");
		exit(255);
	}
}
