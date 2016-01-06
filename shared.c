#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
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

ssize_t sock_fd_write(int sock, int bufferCount, struct iovec * buffers, int fd) {
	ssize_t size;
	struct msghdr msg;
	char ctrl_buf[CMSG_SPACE(sizeof(int))];

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = buffers;
	msg.msg_iovlen = bufferCount;
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

	return sendmsg(sock, &msg, 0);
}

ssize_t sock_fd_read(int sock, int * bufferCount, struct iovec * buffers, int *fd) {
	ssize_t size;
	struct msghdr msg;
	struct iovec iov[1];
	char ctrl_buf[CMSG_SPACE(sizeof(int))];

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = buffers;
	msg.msg_iovlen = *bufferCount;
	msg.msg_control = &ctrl_buf;
	msg.msg_controllen = sizeof(ctrl_buf);

	size = recvmsg(sock, &msg, 0);
	if (size < 0) {
		perror("recvmsg");
		return -1;
	}
	if (size == 0) {
		return 0;
	}
	*bufferCount = msg.msg_iovlen;
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

	return size;
}
