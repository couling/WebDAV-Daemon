// TODO find a way to make this work with propfind and proppatch responses which to not return an handle to the file

#include "lockdb.h"

#include "configuration.h"
#include "shared.h"

#include <errno.h>
#include <string.h>
#include <sys/file.h>
#include <search.h>
#include <semaphore.h>
#include <unistd.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <uuid/uuid.h>

typedef char LockToken[37];

typedef struct Lock {
	const char * user;
	const char * file;
	time_t lockAcquired;
	LockType type;
	int fd;
	int useCount;
	int released;
	LockToken lockToken;
} Lock;

static void * rootNode = NULL;
static sem_t lockDBLock;

#define addLockToDb(lock) tsearch(lock, &rootNode, &compareLockToken);
#define findLockInDb(lock) tfind(lock, &rootNode, &compareLockToken);
#define deleteLockFromDb(lock) tdelete(lock, &rootNode, &compareLockToken);

static int compareLockToken(const void * a, const void * b) {
	const Lock * lhs = a;
	const Lock * rhs = b;
	return strcmp(lhs->lockToken, rhs->lockToken);
}

static Lock * findLock(const char * lockToken) {
	Lock toFind;
	strncpy((char *) toFind.lockToken, lockToken, 16);
	return findLockInDb(&toFind);
}

int acquireLock(const char ** lockToken, const char * user, const char * file, LockType lockType, int fd) {
	size_t userSize = strlen(user) + 1;
	size_t fileSize = strlen(file) + 1;
	size_t bufferSize = sizeof(Lock) + userSize + fileSize;

	char * buffer = mallocSafe(bufferSize);
	Lock * newLock = (Lock *) buffer;
	newLock->user = buffer + sizeof(Lock);
	newLock->file = newLock->user + userSize;

	uuid_t uuid;
	uuid_generate(uuid);
	uuid_unparse_upper(uuid, newLock->lockToken);
	memcpy((char *) newLock->user, user, userSize);
	memcpy((char *) newLock->file, file, fileSize);
	time(&newLock->lockAcquired);
	newLock->type = lockType;
	newLock->fd = fd;
	newLock->useCount = 1;
	newLock->released = 0;

	if (sem_wait(&lockDBLock) == -1) {
		stdLogError(errno, "Could not wait for access to lock db");
		close(fd);
		freeSafe(newLock);
		return 0;
	} else {
		addLockToDb(newLock);
		sem_post(&lockDBLock);
		return 1;
	}
}

static void releaseUnusedLock(Lock * lock) {
	lock->useCount--;
	if (lock->useCount == 0) {
		deleteLockFromDb(lock);
		close(lock->fd);
		freeSafe(lock);
	}
}

int useLock(const char * lockToken, const char * file, const char * user, LockType lockType) {
	if (sem_wait(&lockDBLock) == -1) {
		stdLogError(errno, "Could not wait for access to lock db");
		return 0;
	}
	Lock * foundLock = findLock(lockToken);
	if (foundLock != NULL && (lockType == foundLock->type || foundLock->type == LOCK_TYPE_EXCLUSIVE)
			&& !strcmp(foundLock->user, user) && !strcmp(foundLock->file, file) && !foundLock->released) {
		foundLock->useCount++;
		time(&foundLock->lockAcquired);
		sem_post(&lockDBLock);
		return 1;
	} else {
		stdLogError(0, "Could not find lock %s for user %s on file %s", lockToken, user, file);
		sem_post(&lockDBLock);
		return 0;
	}
}

void unuseLock(const char * lockToken) {
	if (sem_wait(&lockDBLock) == -1) {
		stdLogError(errno, "Could not wait for access to lock db lock will left in DB after unsuseLock()");
	} else {
		Lock * foundLock = findLock(lockToken);
		if (foundLock != NULL) {
			releaseUnusedLock(foundLock);
		}
		sem_post(&lockDBLock);
	}
}

int releaseLock(const char * lockToken, const char * file, const char * user, int fd) {
	// TODO better return values to distinguish between internal error and non-existant lock
	if (sem_wait(&lockDBLock) == -1) {
		stdLogError(errno, "Could not wait for access to lock db");
		return 0;
	}
	Lock * foundLock = findLock(lockToken);
	if (foundLock != NULL && !strcmp(foundLock->user, user) && !strcmp(foundLock->file, file) && !foundLock->released) {
		foundLock->useCount--;
		releaseUnusedLock(foundLock);
		sem_post(&lockDBLock);
		return 1;
	} else {
		stdLogError(0, "Could not find lock %s for user %s on file %s", lockToken, user, file);
		sem_post(&lockDBLock);
		return 0;
	}
}

static time_t expiryTime;
static int readyForReleaseCount;
static Lock ** readyForRelease;

static void cleanAction(const void *nodep, const VISIT which, const int depth) {
	switch (which) {
	case postorder:
	case leaf: {
		Lock ** node = (Lock **) nodep;
		Lock * lock = *node;
		if (lock->lockAcquired < expiryTime && !lock->released) {
			int index = readyForReleaseCount++;
			if (!(readyForReleaseCount & 0xF)) {
				readyForRelease = reallocSafe(readyForRelease, (readyForReleaseCount | 0xF) * sizeof(*readyForRelease));
			}
			readyForRelease[index] = lock;
		}
		break;
	}

	default:
		break;
	}
}

void runCleanLocks() {
	if (sem_wait(&lockDBLock) == -1) {
		stdLogError(errno, "Could not wait for access to lock db");
	} else {
		if (rootNode) {
			time(&expiryTime);
			expiryTime -= config.maxLockTime;
			readyForReleaseCount = 0;
			readyForRelease = NULL;
			twalk(&rootNode, &cleanAction);

			if (readyForReleaseCount > 0) {
				int i = 0;
				do {
					readyForRelease[i]->released = 1;
					releaseUnusedLock(readyForRelease[i]);
				} while (i < readyForReleaseCount);
				freeSafe(readyForRelease);
			}
		}

		sem_post(&lockDBLock);
	}
}

void initializeLockDB() {
	time_t timeNow;
	time(&timeNow);
	srandom(timeNow);
	if (sem_init(&lockDBLock, 0, 1) == -1) {
		stdLogError(errno, "Could not create lock for lockdb");
		exit(255);
	}
}

