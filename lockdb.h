#ifndef LOCKDB_H
#define LOCKDB_H

#include "shared.h"

int acquireLock(const char ** lockToken, const char * user, const char * file, LockType lockType, int fd);
int refreshLock(const char * lockToken, const char * user, const char * file);
int useLock(const char * lockToken, const char * file, const char * user, LockType lockType);
void unuseLock(const char * lockToken);
int releaseLock(const char * lockToken, const char * file, const char * user);

void initializeLockDB();
void runCleanLocks();

#endif
