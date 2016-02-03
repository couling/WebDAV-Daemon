#include "shared.h"

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <errno.h>
#include <time.h>

static char * timeNow() {
	time_t rawtime;
	time(&rawtime);
	struct tm * timeinfo;
	timeinfo = localtime(&rawtime);
	static char t[100];
	strftime(t, 100, "%a %b %d %H:%M:%S %Y", timeinfo);
	return t;
}

void stdLog(const char * str, ...) {
	char buffer[10240];
	int remaining = 10240;
	char * ptr = buffer;
	int written = snprintf(ptr, remaining, "%s [%d] ", timeNow(), getpid());
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
	size_t ignored = write(STDERR_FILENO, buffer, ptr - buffer);
}

void stdLogError(int errorNumber, const char * str, ...) {
	char buffer[10240];
	int remaining = 10240;
	char * ptr = buffer;
	int written = snprintf(ptr, remaining, "%s [%d] Error: ", timeNow(), getpid());
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
	remaining -= written;
	if (errorNumber) {
		written = snprintf(ptr, remaining, "%s [%d] Error: %s\n", timeNow(), getpid(), strerror(errorNumber));
		ptr += written;
		//remaining -= written;
	}
	size_t ignored = write(STDERR_FILENO, buffer, ptr - buffer);
}

void * mallocSafe(size_t size) {
	void * allocatedMemory = malloc(size);
	if (allocatedMemory) {
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
		return allocatedMemory;
	} else {
		stdLogError(errno, "Could not allocation %zd bytes of memory", newSize);
		exit(255);
	}
}

ssize_t sendMessage(int sock, struct Message * message) {
	//stdLog("sendm %d", sock);
	ssize_t size;
	struct msghdr msg;
	char ctrl_buf[CMSG_SPACE(sizeof(int))];
	struct iovec liovec[MAX_BUFFER_PARTS + 1];

	if (message->bufferCount > MAX_BUFFER_PARTS || message->bufferCount < 0) {
		stdLogError(0, "Can not send message with %d parts", message->bufferCount);
		if (message->fd != -1) {
			close(message->fd);
		}
		return -1;
	}

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = liovec;
	msg.msg_iovlen = message->bufferCount + 1;
	liovec[0].iov_base = message;
	liovec[0].iov_len = sizeof(*message);
	memcpy(&(liovec[1]), message->buffers, sizeof(struct iovec) * message->bufferCount);

	if (message->fd != -1) {
		memset(&ctrl_buf, 0, sizeof(ctrl_buf));
		msg.msg_control = &ctrl_buf;
		msg.msg_controllen = sizeof(ctrl_buf);
		struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		*((int *) CMSG_DATA(cmsg)) = message->fd;
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

ssize_t recvMessage(int sock, struct Message * message, char * incomingBuffer, size_t incomingBufferSize) {
	//stdLog("recvm %d", sock);

	struct msghdr msg;
	char ctrl_buf[CMSG_SPACE(sizeof(int))];
	struct iovec iovec[2];

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = iovec;
	msg.msg_iovlen = 2;
	msg.msg_control = ctrl_buf;
	msg.msg_controllen = sizeof(ctrl_buf);
	iovec[0].iov_base = message;
	iovec[0].iov_len = sizeof(*message);
	iovec[1].iov_base = incomingBuffer;
	iovec[1].iov_len = incomingBufferSize;

	memset(incomingBuffer, 0, incomingBufferSize);

	// TODO implement timeout ... possibly using "select"
	ssize_t size = recvmsg(sock, &msg, MSG_CMSG_CLOEXEC);
	// this is there to stop random EINTR failures. never yet found out what cause them
	// but this seems to fix them.
	if (size < 0 && errno == EINTR) {
		stdLogError(0, "Could not receive socket message intr %d %zd ... retry", sock, size);
		int retryCount = 20;
		do {
			retryCount --;
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
		message->fd = *((int *) CMSG_DATA(cmsg));
	} else {
		message->fd = -1;
	}

	if (size < sizeof(*message) || message->bufferCount < 0 || message->bufferCount > MAX_BUFFER_PARTS) {
		stdLogError(0, "Invalid message received %zd %d", size, message->bufferCount);
		if (message->fd != -1) {
			close(message->fd);
		}
		return -1;
	}

	char * partPtr = incomingBuffer;
	for (int i = 0; i < message->bufferCount; i++) {
		message->buffers[i].iov_base = partPtr;
		partPtr += message->buffers[i].iov_len;
		if (partPtr > incomingBuffer + size - sizeof(*message)) {
			stdLogError(0, "Invalid message received: parts too long\n");
			if (message->fd != -1) {
				close(message->fd);
			}
			return -1;
		}
	}
	for (int i = message->bufferCount; i < MAX_BUFFER_PARTS; i++) {
		message->buffers[i].iov_base = NULL;
		message->buffers[i].iov_len = 0;
	}

	return size;
}

char * iovecToString(struct iovec * iovec) {
	char * buffer = iovec->iov_base;
	buffer[iovec->iov_len - 1] = '\0';
	return buffer;
}

size_t getWebDate(time_t rawtime, char * buf, size_t bufSize) {
	struct tm * timeinfo = localtime(&rawtime);
	return strftime(buf, bufSize, "%a, %d %b %Y %H:%M:%S %Z", timeinfo);
}

