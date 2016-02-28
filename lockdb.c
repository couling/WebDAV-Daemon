#include "lockdb.h"

int acquireLock(const char ** lockToken, const char * user, int fd, const char * file, LockType lockType) {
	return 0;
}

int checkLock(const char * lockTocken, const char * file, const char * user, LockType lockType) {
	return 0;
}

int releaseLock(const char * lockToken, const char * file, const char * user, LockType lockType) {
	return 0;
}

