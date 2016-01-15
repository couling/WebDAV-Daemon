#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include "shared.h"

void * mallocSafe(size_t size) {
	void * allocatedMemory = malloc(size);
	if (allocatedMemory) {
		return allocatedMemory;
	} else {
		perror("Could not allocate memory! Exiting!");
		exit(255);
	}
}

struct MessageHeader {
	enum RapConstant mID;
	int partCount;
	size_t partLengths[MAX_BUFFER_PARTS];
};

void hexWrite(size_t bufferSize, void * buffer) {
	for (size_t x = 0; x < bufferSize; x++) {
		fprintf(stderr, "%d%d ", (((char *) buffer)[x] & 0xF0) >> 4, ((char *) buffer)[x] & 0x0F);
		if (!((x + 1) % 8)) {
			fprintf(stderr, "\n");
		}
	}
	if ((bufferSize) % 8) {
		fprintf(stderr, "\n");
	}
}

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
	memcpy(&(liovec[1]), &buffer, sizeof(struct iovec) * bufferCount);

	memset(&messageHeader, 0, sizeof(messageHeader));
	messageHeader.mID = mID;
	messageHeader.partCount = bufferCount;
	for (int i = 0; i < bufferCount; i++) {
		messageHeader.partLengths[i] = buffer[i].iov_len;
	}

	if (fd != -1) {
		msg.msg_control = &ctrl_buf;
		msg.msg_controllen = sizeof(ctrl_buf);
		((struct cmsghdr *) ctrl_buf)->cmsg_len = sizeof(ctrl_buf);
		((struct cmsghdr *) ctrl_buf)->cmsg_level = SOL_SOCKET;
		((struct cmsghdr *) ctrl_buf)->cmsg_type = SCM_RIGHTS;
		*((int *) CMSG_DATA((struct cmsghdr * ) ctrl_buf)) = fd;
	} else {
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
	}

	size = sendmsg(sock, &msg, 0);
	if (size < 0) {
		perror("sendmsg");
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
	static char incomingBuffer2[INCOMING_BUFFER_SIZE + 1];

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

	size = recvmsg(sock, &msg, 0);
	if (size < 0) {
		perror("recvmsg");
		return -1;
	}
	if (size == 0) {
		return 0;
	}

	hexWrite(size, incomingBuffer);

	// Null terminate the buffer to avoid buffer overread
	incomingBuffer[size] = '\0';

	struct cmsghdr * cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg && cmsg->cmsg_len == CMSG_LEN(sizeof(int)) && cmsg->cmsg_level == SOL_SOCKET
			&& cmsg->cmsg_type != SCM_RIGHTS) {
		int recievedFd = *((int *) CMSG_DATA(cmsg));
		if (fd) {
			*fd = recievedFd;
		} else {
			fprintf(stderr, "Warning: closing ignored fd\n");
			close(recievedFd);
		}
	} else if (fd) {
		// report back to the calling method that no FD was recieved.
		*fd = -1;
	}

	struct MessageHeader * messageHeader = (struct MessageHeader *) (&incomingBuffer);
	if (size < sizeof(struct MessageHeader) || messageHeader->partCount > *bufferCount
			|| messageHeader->partCount < 0) {
		fprintf(stderr, "Invalid message recieved\n");
		if (fd || *fd != -1) {
			close(*fd);
		}
		return -1;
	}

	*mID = messageHeader->mID;
	*bufferCount = messageHeader->partCount;
	char * partPtr = incomingBuffer + sizeof(messageHeader);
	for (int i = 0; i < messageHeader->partCount; i++) {
		if (partPtr >= incomingBuffer + size) {
			fprintf(stderr, "Invalid message recieved: parts too long\n");
			if (fd || *fd != -1) {
				close(*fd);
			}
			return -1;
		}
		buffers[i].iov_base = partPtr;
		buffers[i].iov_len = messageHeader->partLengths[i];
		partPtr += messageHeader->partLengths[i];
	}

	return size;
}
