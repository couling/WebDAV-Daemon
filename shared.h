#ifndef WEBDAV_SHARED_H
#define WEBDAV_SHARED_H

#define RAP_PATH "/usr/sbin/rap"

enum RAPAction {
	RAP_INVALID_METHOD, RAP_READ_FILE, RAP_WRITE_FILE, RAP_LIST_FOLDER
};

enum RAPResult {
	RAP_SUCCESS, RAP_NOT_FOUND, RAP_ACCESS_DENIED, RAP_AUTH_FAILLED
};

#define RAP_USER_INDEX 0
#define RAP_PASSWORD_INDEX 1

#define RAP_ACTION_INDEX 0
#define RAP_HOST_INDEX 1
#define RAP_FILE_INDEX 2



void * mallocSafe(size_t size);
ssize_t sock_fd_read(int sock, int bufferCount, struct iovec * buffers, int *fd);
ssize_t sock_fd_write(int sock, int bufferCount, struct iovec * buffers, int fd);

#endif
