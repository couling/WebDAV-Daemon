#ifndef WEBDAV_SHARED_H
#define WEBDAV_SHARED_H

typedef enum {
	OPEN_FILE
} RAPAction;

typedef enum {
	READ_SUCCESS,
	READ_WRITE_SUCCESS,
	AUTH_BOUNCE
} RAPResult;

#endif
