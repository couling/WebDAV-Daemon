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

struct MessageHeader {
	enum RapConstant mID;
	int partCount;
	size_t partLengths[MAX_BUFFER_PARTS];
};

ssize_t sendMessage(int sock, enum RapConstant mID, int fd, int bufferCount, struct iovec buffer[]) {
	ssize_t size;
	struct msghdr msg;
	char ctrl_buf[CMSG_SPACE(sizeof(int))];
	struct iovec liovec[MAX_BUFFER_PARTS + 1];
	struct MessageHeader messageHeader;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = liovec;
	msg.msg_iovlen = bufferCount + 1;
	liovec[0].iov_base = &messageHeader;
	liovec[0].iov_len = sizeof(messageHeader);
	memcpy(&(liovec[1]), buffer, sizeof(struct iovec) * bufferCount);

	memset(&messageHeader, 0, sizeof(messageHeader));
	messageHeader.mID = mID;
	messageHeader.partCount = bufferCount;
	for (int i = 0; i < bufferCount; i++) {
		messageHeader.partLengths[i] = buffer[i].iov_len;
	}

	if (fd != -1) {
		memset(&ctrl_buf, 0, sizeof(ctrl_buf));
		msg.msg_control = &ctrl_buf;
		msg.msg_controllen = sizeof(ctrl_buf);
		struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		*((int *) CMSG_DATA(cmsg)) = fd;
	} else {
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
	}

	size = sendmsg(sock, &msg, 0);
	if (fd != -1) {
		close(fd);
	}
	if (size < 0) {
		stdLogError(errno, "Could not send socket message");
	}
	return size;
}

#define INCOMING_BUFFER_SIZE 10239

ssize_t recvMessage(int sock, enum RapConstant * mID, int * fd, int * bufferCount, struct iovec * buffers) {
	ssize_t size;
	struct msghdr msg;
	char ctrl_buf[CMSG_SPACE(sizeof(int))];
	struct iovec iovec[2];
	int dummyBufferCount = 0;
	// TODO refactor to remove the need for static
	static char incomingBuffer[INCOMING_BUFFER_SIZE + 1];

	if (!bufferCount) {
		bufferCount = &dummyBufferCount;
	}

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = iovec;
	msg.msg_iovlen = 1;
	msg.msg_control = &ctrl_buf;
	msg.msg_controllen = sizeof(ctrl_buf);
	iovec[0].iov_base = incomingBuffer;
	iovec[0].iov_len = INCOMING_BUFFER_SIZE;

	memset(incomingBuffer, 0, INCOMING_BUFFER_SIZE);

	size = recvmsg(sock, &msg, MSG_CMSG_CLOEXEC);
	if (size < 0) {
		stdLogError(errno, "Could not receive socket message");
		return -1;
	}
	if (size == 0) {
		return 0;
	}

	// Null terminate the buffer to avoid buffer overread
	incomingBuffer[size] = '\0';

	struct cmsghdr * cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg && cmsg->cmsg_len == CMSG_LEN(sizeof(int)) && cmsg->cmsg_level == SOL_SOCKET
			&& cmsg->cmsg_type == SCM_RIGHTS) {
		int recievedFd = *((int *) CMSG_DATA(cmsg));
		if (fd) {
			*fd = recievedFd;
		} else {
			stdLogError(0, "closing ignored fd");
			close(recievedFd);
		}
	} else if (fd) {
		// report back to the calling method that no FD was recieved.
		*fd = -1;
	}

	struct MessageHeader * messageHeader = (struct MessageHeader *) (&incomingBuffer);
	if (size < sizeof(struct MessageHeader) || messageHeader->partCount > *bufferCount
			|| messageHeader->partCount < 0) {
		stdLogError(0, "Invalid message recieved");
		if (fd || *fd != -1) {
			close(*fd);
		}
		return -1;
	}

	*mID = messageHeader->mID;
	*bufferCount = messageHeader->partCount;
	char * partPtr = &incomingBuffer[sizeof(struct MessageHeader)];
	for (int i = 0; i < messageHeader->partCount; i++) {
		buffers[i].iov_base = partPtr;
		buffers[i].iov_len = messageHeader->partLengths[i];
		partPtr += messageHeader->partLengths[i];
		if (partPtr > incomingBuffer + size) {
			stdLogError(0, "Invalid message recieved: parts too long\n");
			if (fd || *fd != -1) {
				close(*fd);
			}
			return -1;
		}
	}

	return size;
}

char * iovecToString(struct iovec * iovec) {
	char * buffer = iovec->iov_base;
	buffer[iovec->iov_len - 1] = '\0';
	return buffer;
}
