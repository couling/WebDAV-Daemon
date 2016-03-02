#ifndef LOCKDB_H
#define LOCKDB_H

#include <sys/file.h>

typedef enum LockType {
	LOCK_TYPE_SHARED = LOCK_SH | LOCK_NB,   //
	LOCK_TYPE_EXCLUSIVE = LOCK_EX | LOCK_NB //
} LockType;

int acquireLock(const char ** lockToken, const char * user, const char * file, LockType lockType, int fd);
int useLock(const char * lockToken, const char * file, const char * user, LockType lockType);
void unuseLock(const char * lockToken);
int releaseLock(const char * lockToken, const char * file, const char * user, int fd);

void initializeLockDB();
void runCleanLocks();

#endif
