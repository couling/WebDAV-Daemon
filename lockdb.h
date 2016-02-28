#ifndef LOCKDB_H
#define LOCKDB_H

typedef enum LockType {
	LOCK_TYPE_SHARED, LOCK_TYPE_EXCLUSIVE
} LockType;

int acquireLock(const char ** lockToken, const char * user, int fd, const char * file, LockType lockType);
int checkLock(const char * lockTocken, const char * file, const char * user, LockType lockType);
int releaseLock(const char * lockToken, const char * file, const char * user, LockType lockType);

#endif
