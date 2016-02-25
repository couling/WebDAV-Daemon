#include "rap-control.h"

#include "shared.h"
#include "configuration.h"

#include <errno.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>

typedef struct RAPDB {
	RAP * firstRapSession;
} RAPDB;

// Used as a place holder for failed auth requests which failed due to invalid credentials
const RAP AUTH_FAILED_RAP = { .pid = 0, .socketFd = -1, .user = "<auth failed>", .writeDataFd = -1, .readDataFd = -1,
		.responseAlreadyGiven = 1 };

// Used as a place holder for failed auth requests which failed due to errors
const RAP AUTH_ERROR_RAP = { .pid = 0, .socketFd = -1, .user = "<auth error>", .writeDataFd = -1, .readDataFd = -1,
		.responseAlreadyGiven = 1 };


static pthread_key_t rapDBThreadKey;

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

	// We set this timeout so that a hung RAP will eventually clean itself up
	struct timeval timeout;
	timeout.tv_sec = config.rapTimeoutRead;
	timeout.tv_usec = 0;
	if (setsockopt(sockFd[PARENT_SOCKET], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
		stdLogError(errno, "Could not set timeout");
		close(sockFd[PARENT_SOCKET]);
		close(sockFd[CHILD_SOCKET]);
		return 0;
	}

	result = fork();
	if (result) {

		// parent
		close(sockFd[CHILD_SOCKET]);
		if (result != -1) {
			*newSockFd = sockFd[PARENT_SOCKET];
			//stdLog("New RAP %d on %d", result, sockFd[0]);
			return result;
		} else {
			// fork failed so close parent pipes and return non-zero
			close(sockFd[PARENT_SOCKET]);
			stdLogError(errno, "Could not fork");
			return 0;
		}
	} else {

		// child
		close(sockFd[PARENT_SOCKET]);
		if (sockFd[CHILD_SOCKET] == RAP_CONTROL_SOCKET) {
			// If by some chance this socket has opened as pre-defined RAP_CONTROL_SOCKET we
			// won't dup2 but we do need to remove the close-on-exec flag
			int flags = fcntl(sockFd[CHILD_SOCKET], F_GETFD);
			if (fcntl(sockFd[CHILD_SOCKET], F_SETFD, flags & ~FD_CLOEXEC) == -1) {
				stdLogError(errno, "Could not clear close-on-exec for control socket", sockFd[CHILD_SOCKET],
						(int) RAP_CONTROL_SOCKET);
				exit(255);
			}
		} else {
			// Assign the control socket to the correct FD so the RAP can use it
			// This previously abused STD_IN and STD_OUT for this but instead we now
			// reserve a different FD (3) AKA RAP_CONTROL_SOCKET
			if (dup2(sockFd[CHILD_SOCKET], RAP_CONTROL_SOCKET) == -1) {
				stdLogError(errno, "Could not assign new socket (%d) to %d", newSockFd[1], (int) RAP_CONTROL_SOCKET);
				exit(255);
			}
		}

		char * argv[] =
				{ (char *) config.rapBinary, (char *) config.pamServiceName, (char *) config.mimeTypesFile, NULL };
		execv(path, argv);

		stdLogError(errno, "Could not start rap: %s", path);
		exit(255);
	}
}

static void destroyRap(RAP * rapSession) {
	close(rapSession->socketFd);
	if (rapSession->readDataFd != -1) {
		stdLogError(0, "readDataFd was not properly closed before destroying rap");
		close(rapSession->readDataFd);
	}
	if (rapSession->writeDataFd != -1) {
		stdLogError(0, "writeDataFd was not properly closed before destroying rap");
		close(rapSession->writeDataFd);
	}

	free((void *) rapSession->user);
	free((void *) rapSession->password);
	*(rapSession->prevPtr) = rapSession->next;
	free(rapSession);
}

static RAP * createRap(RAPDB * db, const char * user, const char * password, const char * rhost) {
	int socketFd;
	int pid = forkRapProcess(config.rapBinary, &socketFd);
	if (!pid) {
		return AUTH_ERROR;
	}

	// Send Auth Request
	Message message;
	message.mID = RAP_AUTHENTICATE;
	message.fd = -1;
	message.bufferCount = 3;
	message.params[RAP_USER_INDEX].iov_len = strlen(user) + 1;
	message.params[RAP_USER_INDEX].iov_base = (void *) user;
	message.params[RAP_PASSWORD_INDEX].iov_len = strlen(password) + 1;
	message.params[RAP_PASSWORD_INDEX].iov_base = (void *) password;
	message.params[RAP_RHOST_INDEX].iov_len = strlen(rhost) + 1;
	message.params[RAP_RHOST_INDEX].iov_base = (void *) rhost;
	if (sendMessage(socketFd, &message) <= 0) {
		close(socketFd);
		return AUTH_ERROR;
	}

	// Read Auth Result
	char incomingBuffer[INCOMING_BUFFER_SIZE];
	ssize_t readResult = recvMessage(socketFd, &message, incomingBuffer, INCOMING_BUFFER_SIZE);
	if (readResult <= 0 || message.mID != RAP_SUCCESS) {
		close(socketFd);
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

	// If successfully authenticated then populate the RAP structure and add it to the DB
	RAP * newRap = mallocSafe(sizeof(RAP));
	newRap->pid = pid;
	newRap->socketFd = socketFd;
	newRap->user = copyString(user);
	newRap->password = copyString(password);
	time(&newRap->rapCreated);
	newRap->next = db->firstRapSession;
	newRap->prevPtr = &db->firstRapSession;
	newRap->writeDataFd = -1;
	newRap->readDataFd = -1;
	// newRap->responseAlreadyGiven // this is set elsewhere
	db->firstRapSession = newRap;

	return newRap;
}

void releaseRap(RAP * processor) {
}

RAP * acquireRap(const char * user, const char * password, const char * clientIp) {
	if (user && password) {
		RAPDB * rapDB = pthread_getspecific(rapDBThreadKey);
		if (!rapDB) {
			rapDB = mallocSafe(sizeof(*rapDB));
			memset(rapDB, 0, sizeof(*rapDB));
			pthread_setspecific(rapDBThreadKey, rapDB);
		} else {
			time_t expires;
			time(&expires);
			expires -= config.rapMaxSessionLife;
			RAP * rap = rapDB->firstRapSession;
			while (rap) {
				if (rap->rapCreated < expires) {
					destroyRap(rap);
				} else if (!strcmp(user, rap->user) && !strcmp(password, rap->password)) {
					return rap;
				} else {
					rap = rap->next;
				}
			}
		}
		return createRap(rapDB, user, password, clientIp);
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

static void deInitializeRapDatabase(void * data) {
	RAPDB * db = data;
	if (db) {
		RAPDB * db = data;
		while (db->firstRapSession) {
			destroyRap(db->firstRapSession);
		}
		free(db);
	}
}

void initializeRapDatabase() {
	struct sigaction act;
	memset(&act, 0, sizeof(act));
	act.sa_sigaction = &cleanupAfterRap;
	act.sa_flags = SA_SIGINFO;
	if (sigaction(SIGCHLD, &act, NULL) < 0) {
		stdLogError(errno, "Could not set handler method for finished child threads");
		exit(255);
	}

	pthread_key_create(&rapDBThreadKey, &deInitializeRapDatabase);
}

////////////////////////
// End RAP Processing //
////////////////////////
