// TODO re-introduce rap pool for clients which do not keep connections alive.

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
#include <semaphore.h>

typedef struct RapList {
	RAP * firstRapSession;
} RapList;

// Used as a place holder for failed auth requests which failed due to invalid credentials
const RAP AUTH_FAILED_RAP = { .pid = 0, .socketFd = -1, .user = "<auth failed>", .requestWriteDataFd = -1, .requestReadDataFd = -1,
		.requestResponseAlreadyGiven = 403, .next = NULL, .prevPtr = NULL };

// Used as a place holder for failed auth requests which failed due to errors
const RAP AUTH_ERROR_RAP = { .pid = 0, .socketFd = -1, .user = "<auth error>", .requestWriteDataFd = -1, .requestReadDataFd = -1,
		.requestResponseAlreadyGiven = 500, .next = NULL, .prevPtr = NULL };

static pthread_key_t rapDBThreadKey;
static sem_t rapPoolLock;
static RapList rapPool;

////////////////////
// RAP Processing //
////////////////////

static time_t getExpiryTime() {
	time_t expires;
	time(&expires);
	expires -= config.rapMaxSessionLife;
	return expires;
}

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

static void removeRapFromList(RAP * rapSession) {
	*(rapSession->prevPtr) = rapSession->next;
	if (rapSession->next != NULL) {
		rapSession->next->prevPtr = rapSession->prevPtr;
	}
}

static void addRapToList(RapList * list, RAP * rapSession) {
	rapSession->next = list->firstRapSession;
	list->firstRapSession = rapSession;
	rapSession->prevPtr = &list->firstRapSession;
	if (rapSession->next) {
		rapSession->next->prevPtr = &rapSession->next;
	}
}

void destroyRap(RAP * rapSession) {
	if (!AUTH_SUCCESS(rapSession)) {
		return;
	}
	close(rapSession->socketFd);
	if (rapSession->requestReadDataFd != -1) {
		stdLogError(0, "readDataFd was not properly closed before destroying rap");
		close(rapSession->requestReadDataFd);
	}
	if (rapSession->requestWriteDataFd != -1) {
		stdLogError(0, "writeDataFd was not properly closed before destroying rap");
		close(rapSession->requestWriteDataFd);
	}

	freeSafe((void * ) rapSession->user);
	freeSafe((void * ) rapSession->password);
	freeSafe((void * ) rapSession->clientIp);
	removeRapFromList(rapSession);
	freeSafe(rapSession);
}

static RAP * createRap(RapList * db, const char * user, const char * password, const char * rhost) {
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
	message.params[RAP_USER_INDEX] = stringToMessageParam(user);
	message.params[RAP_PASSWORD_INDEX] = stringToMessageParam(password);
	message.params[RAP_RHOST_INDEX] = stringToMessageParam(rhost);
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
	RAP * newRap = mallocSafe(sizeof(*newRap));
	newRap->pid = pid;
	newRap->socketFd = socketFd;
	newRap->user = copyString(user);
	newRap->password = copyString(password);
	newRap->clientIp = copyString(rhost);
	time(&newRap->rapCreated);
	newRap->requestWriteDataFd = -1;
	newRap->requestReadDataFd = -1;
	addRapToList(db, newRap);
	// newRap->responseAlreadyGiven // this is set elsewhere
	return newRap;
}

// void releaseRap(RAP * processor) {}

RAP * acquireRap(const char * user, const char * password, const char * clientIp) {
	if (user && password) {
		RAP * rap;
		time_t expires = getExpiryTime();
		RapList * threadRapList = pthread_getspecific(rapDBThreadKey);
		if (!threadRapList) {
			threadRapList = mallocSafe(sizeof(*threadRapList));
			memset(threadRapList, 0, sizeof(*threadRapList));
			pthread_setspecific(rapDBThreadKey, threadRapList);
		} else {
			// Get a rap from this thread's own list
			rap = threadRapList->firstRapSession;
			while (rap) {
				if (rap->rapCreated < expires) {
					RAP * raptmp = rap->next;
					destroyRap(rap);
					rap = raptmp;
				} else if (!strcmp(user, rap->user)
						&& !strcmp(password, rap->password) /*&& !strcmp(clientIp, rap->clientIp)*/) {
					// all requests here will come from the same ip so we don't check it in the above.
					return rap;
				} else {
					rap = rap->next;
				}
			}
		}
		// Get a rap from the central pool.
		if (sem_wait(&rapPoolLock) == -1) {
			stdLogError(errno, "Could not wait for rap pool lock while acquiring rap");
			return AUTH_ERROR;
		} else {
			rap = rapPool.firstRapSession;
			while (rap) {
				if (rap->rapCreated < expires) {
					RAP * raptmp = rap->next;
					destroyRap(rap);
					rap = raptmp;
				} else if (!strcmp(user, rap->user) && !strcmp(password, rap->password)
						&& !strcmp(clientIp, rap->clientIp)) {
					// We will only re-use sessions in the pool if they are from the same ip
					removeRapFromList(rap);
					addRapToList(threadRapList, rap);
					sem_post(&rapPoolLock);
					return rap;
				} else {
					rap = rap->next;
				}
			}
			sem_post(&rapPoolLock);
		}
		return createRap(threadRapList, user, password, clientIp);
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
	RapList * threadRapList = data;
	if (threadRapList) {
		if (threadRapList->firstRapSession) {
			if (sem_wait(&rapPoolLock) == -1) {
				stdLogError(errno, "Could not wait for rap pool lock cleaning up thread");
				do {
					destroyRap(threadRapList->firstRapSession);
				} while (threadRapList->firstRapSession != NULL);
			} else {
				do {
					RAP * rap = threadRapList->firstRapSession;
					removeRapFromList(rap);
					addRapToList(&rapPool, rap);
				} while (threadRapList->firstRapSession != NULL);
				sem_post(&rapPoolLock);
			}
		}
		freeSafe(threadRapList);
	}
}

void runCleanRapPool() {
	time_t expires = getExpiryTime();
	if (sem_wait(&rapPoolLock) == -1) {
		stdLogError(errno, "Could not wait for rap pool lock while cleaning pool");
		return;
	} else {
		RAP * rap = rapPool.firstRapSession;
		while (rap != NULL) {
			RAP * next = rap->next;
			if (rap->rapCreated < expires) {
				destroyRap(rap);
			}
			rap = next;
		}
		sem_post(&rapPoolLock);
	}
}

void initializeRapDatabase() {
	struct sigaction childCleanup = { .sa_sigaction = &cleanupAfterRap, .sa_flags = SA_SIGINFO };
	if (sigaction(SIGCHLD, &childCleanup, NULL) < 0) {
		stdLogError(errno, "Could not set handler method for finished child threads");
		exit(255);
	}

	memset(&rapPool, 0, sizeof(rapPool));
	sem_init(&rapPoolLock, 0, 1);
	pthread_key_create(&rapDBThreadKey, &deInitializeRapDatabase);
}

////////////////////////
// End RAP Processing //
////////////////////////

