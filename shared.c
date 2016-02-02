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

ssize_t sendMessage(int sock, struct Message * message) {
	//stdLog("sendm %d", sock);
	ssize_t size;
	struct msghdr msg;
	char ctrl_buf[CMSG_SPACE(sizeof(int))];
	struct iovec liovec[MAX_BUFFER_PARTS + 1];
	struct MessageHeader messageHeader;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = liovec;
	msg.msg_iovlen = message->bufferCount + 1;
	liovec[0].iov_base = &messageHeader;
	liovec[0].iov_len = sizeof(messageHeader);
	memcpy(&(liovec[1]), message->buffers, sizeof(struct iovec) * message->bufferCount);

	memset(&messageHeader, 0, sizeof(messageHeader));
	messageHeader.mID = message->mID;
	messageHeader.partCount = message->bufferCount;
	for (int i = 0; i < message->bufferCount; i++) {
		messageHeader.partLengths[i] = message->buffers[i].iov_len;
	}

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
	ssize_t size;
	struct msghdr msg;
	char ctrl_buf[CMSG_SPACE(sizeof(int))];
	struct iovec iovec[2];

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = iovec;
	msg.msg_iovlen = 1;
	msg.msg_control = &ctrl_buf;
	msg.msg_controllen = sizeof(ctrl_buf);
	iovec[0].iov_base = incomingBuffer;
	iovec[0].iov_len = incomingBufferSize - 1;

	memset(incomingBuffer, 0, incomingBufferSize);

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
		message->fd = *((int *) CMSG_DATA(cmsg));
	} else {
		message->fd = -1;
	}

	struct MessageHeader * messageHeader = (struct MessageHeader *) (incomingBuffer);
	if (size
			< sizeof(struct MessageHeader)|| messageHeader->partCount < 0 || messageHeader->partCount > MAX_BUFFER_PARTS) {
		stdLogError(0, "Invalid message received %d", messageHeader->partCount);
		if (message->fd != -1) {
			close(message->fd);
		}
		return -1;
	}

	message->mID = messageHeader->mID;
	message->bufferCount = messageHeader->partCount;
	char * partPtr = &incomingBuffer[sizeof(struct MessageHeader)];
	for (int i = 0; i < messageHeader->partCount; i++) {
		message->buffers[i].iov_base = partPtr;
		message->buffers[i].iov_len = messageHeader->partLengths[i];
		partPtr += messageHeader->partLengths[i];
		if (partPtr > incomingBuffer + size) {
			stdLogError(0, "Invalid message received: parts too long\n");
			if (message->fd != -1) {
				close(message->fd);
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

size_t getWebDate(time_t rawtime, char * buf, size_t bufSize) {
	struct tm * timeinfo = localtime(&rawtime);
	return strftime(buf, bufSize, "%a, %d %b %Y %H:%M:%S %Z", timeinfo);
}

