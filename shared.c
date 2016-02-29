#include "shared.h"

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>

char * timeNow(char * t) {
	time_t rawtime;
	time(&rawtime);
	struct tm * timeinfo;
	timeinfo = localtime(&rawtime);
	strftime(t, 100, "%a %b %d %H:%M:%S %Y", timeinfo);
	return t;
}

void stdLog(const char * str, ...) {
	char buffer[10240];
	int remaining = 10240;
	char * ptr = buffer;
	char t[100];
	int written = snprintf(ptr, remaining, "%s [%d] ", timeNow(t), getpid());
	ptr += written;
	remaining -= written;
	va_list ap;
	va_start(ap, str);
	written = vsnprintf(ptr, remaining, str, ap);
	ptr += written;
	remaining -= written;
	va_end(ap);
	written = snprintf(ptr, remaining, "\n");
	ptr += written;
	//remaining -= written;
	size_t ignored __attribute__ ((unused)) = write(STDERR_FILENO, buffer, ptr - buffer);
}

void stdLogError(int errorNumber, const char * str, ...) {
	char buffer[10240];
	int remaining = 10240;
	char * ptr = buffer;
	char t[100];
	int written = snprintf(ptr, remaining, "%s [%d] Error: ", timeNow(t), getpid());
	ptr += written;
	remaining -= written;
	va_list ap;
	va_start(ap, str);
	written = vsnprintf(ptr, remaining, str, ap);
	ptr += written;
	remaining -= written;
	va_end(ap);
	remaining -= written;
	if (errorNumber) {
		written = snprintf(ptr, remaining, " - %s\n", strerror(errorNumber));
		ptr += written;
		//remaining -= written;
	} else {
		written = snprintf(ptr, remaining, "\n");
		ptr += written;
	}
	size_t ignored __attribute__ ((unused)) = write(STDERR_FILENO, buffer, ptr - buffer);
}

void * mallocSafe(size_t size) {
	void * allocatedMemory = malloc(size);
	if (allocatedMemory) {
		//stdLog("%p malloc(%zd)", allocatedMemory, size );
		return allocatedMemory;
	} else {
		stdLogError(errno, "Could not allocation %zd bytes of memory", size);
		exit(255);
	}
}

void * reallocSafe(void * mem, size_t newSize) {
	if (mem == NULL) {
		return mallocSafe(newSize);
	}
	void * allocatedMemory = realloc(mem, newSize);
	if (allocatedMemory) {
		//stdLog("%p realloc(%p, %zd)", allocatedMemory, mem, newSize );
		return allocatedMemory;
	} else {
		stdLogError(errno, "Could not allocation %zd bytes of memory", newSize);
		exit(255);
	}
}

ssize_t sendMessage(int sock, Message * message) {
	//stdLog("sendm %d", sock);
	ssize_t size;
	struct msghdr msg;
	char ctrl_buf[CMSG_SPACE(sizeof(int))];
	struct iovec messageParts[MAX_MESSAGE_PARAMS + 1];

	if (message->bufferCount > MAX_MESSAGE_PARAMS || message->bufferCount < 0) {
		stdLogError(0, "Can not send message with %d parts", message->bufferCount);
		if (message->fd != -1) {
			close(message->fd);
		}
		return -1;
	}

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = messageParts;
	msg.msg_iovlen = message->bufferCount + 1;
	messageParts[0].iov_base = message;
	messageParts[0].iov_len = sizeof(*message);
	memcpy(&(messageParts[1]), message->params, sizeof(*message->params) * message->bufferCount);

	if (message->fd != -1) {
		memset(&ctrl_buf, 0, sizeof(ctrl_buf));
		msg.msg_control = &ctrl_buf;
		msg.msg_controllen = sizeof(ctrl_buf);
		struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		int * fd = (int *) CMSG_DATA(cmsg);
		*fd = message->fd;
	} else {
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
	}

	size = sendmsg(sock, &msg, 0);
	if (message->fd != -1) {
		close(message->fd);
	}
	if (size < 0) {
		stdLogError(errno, "Could not send socket message");
	}
	return size;
}

ssize_t recvMessage(int sock, Message * message, char * incomingBuffer, size_t incomingBufferSize) {
	//stdLog("recvm %d", sock);

	struct msghdr msg;
	char ctrl_buf[CMSG_SPACE(sizeof(int))];
	struct iovec messageParts[2];

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = messageParts;
	msg.msg_iovlen = 2;
	msg.msg_control = ctrl_buf;
	msg.msg_controllen = sizeof(ctrl_buf);
	messageParts[0].iov_base = message;
	messageParts[0].iov_len = sizeof(*message);
	messageParts[1].iov_base = incomingBuffer;
	messageParts[1].iov_len = incomingBufferSize;

	memset(incomingBuffer, 0, incomingBufferSize);

	ssize_t size = recvmsg(sock, &msg, MSG_CMSG_CLOEXEC);
	// this is there to stop random EINTR failures. never yet found out what cause them
	// but this seems to fix them.
	if (size < 0 && errno == EINTR) {
		int retryCount = 20;
		do {
			//stdLogError(EINTR, "Could not receive socket message intr %d %zd ... retry", sock, size);
			retryCount--;
			size = recvmsg(sock, &msg, MSG_CMSG_CLOEXEC);
		} while (size < 0 && errno == EINTR && retryCount > 0);
	}
	if (size <= 0) {
		if (size < 0) {
			stdLogError(errno, "Could not receive socket message %d %zd", sock, size);
		}
		return size;
	}

	struct cmsghdr * cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg && cmsg->cmsg_len == CMSG_LEN(sizeof(int)) && cmsg->cmsg_level == SOL_SOCKET
			&& cmsg->cmsg_type == SCM_RIGHTS) {
		int * fd = (int *) CMSG_DATA(cmsg);
		message->fd = *fd;
	} else {
		message->fd = -1;
	}

	if (size < sizeof(*message) || message->bufferCount < 0 || message->bufferCount > MAX_MESSAGE_PARAMS) {
		stdLogError(0, "Invalid message received %zd %d", size, message->bufferCount);
		if (message->fd != -1) {
			close(message->fd);
		}
		return -1;
	}

	char * partPtr = incomingBuffer;
	for (int i = 0; i < message->bufferCount; i++) {
		message->params[i].iov_base = partPtr;
		partPtr += message->params[i].iov_len;
		if (partPtr > incomingBuffer + size - sizeof(*message)) {
			stdLogError(0, "Invalid message received: parts too long\n");
			if (message->fd != -1) {
				close(message->fd);
			}
			return -1;
		}
	}
	for (int i = message->bufferCount; i < MAX_MESSAGE_PARAMS; i++) {
		message->params[i].iov_base = NULL;
		message->params[i].iov_len = 0;
	}

	return size;
}

char * messageParamToString(MessageParam * iovec) {
	char * buffer = iovec->iov_base;
	buffer[iovec->iov_len - 1] = '\0';
	return buffer;
}

size_t getWebDate(time_t rawtime, char * buf, size_t bufSize) {
	struct tm * timeinfo = gmtime(&rawtime);
	return strftime(buf, bufSize, "%a, %d %b %Y %H:%M:%S %Z", timeinfo);
}

int lockToUser(const char * user) {
	struct passwd * pwd = getpwnam(user);
	if (!pwd) {
		stdLogError(errno, "Could not find user %s", user);
		return 0;
	}
	if (initgroups(user, pwd->pw_gid) || setgid(pwd->pw_gid) || setuid(pwd->pw_uid)) {
		stdLogError(errno, "Could not lock down to user %s", user);
		return 0;
	}
	return 1;
}

char * copyString(const char * string) {
	if (!string) {
		return NULL;
	}
	size_t stringSize = strlen(string) + 1;
	char * newString = mallocSafe(stringSize);
	memcpy(newString, string, stringSize);
	return newString;
}

char * loadFileToBuffer(const char * file, size_t * size) {
	int fd = open(file, O_RDONLY | O_CLOEXEC);
	struct stat stat;
	if (fd == -1 || fstat(fd, &stat)) {
		stdLogError(errno, "Could not open file %s", file);
		return NULL;
	}

	size_t totalBytesRead = 0;
	char * buffer = mallocSafe(stat.st_size);
	while (totalBytesRead < stat.st_size) {
		if (stat.st_size != 0) {
			size_t bytesRead = read(fd, buffer + totalBytesRead, stat.st_size - totalBytesRead);
			if (bytesRead <= 0) {
				stdLogError(bytesRead < 0 ? errno : 0, "Could not read whole file %s", file);
				freeSafe(buffer);
				close(fd);
				return NULL;
			} else {
				totalBytesRead += bytesRead;
			}
		}
	}
	*size = stat.st_size;
	close(fd);
	return buffer;
}

