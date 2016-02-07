#include "shared.h"

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <dirent.h>
#include <security/pam_appl.h>

#define BUFFER_SIZE 4096

static int authenticated = 0;
static const char * authenticatedUser;

static size_t respond(enum RapConstant result, int fd) {
	struct Message message = { .mID = result, .fd = fd, .bufferCount = 0 };
	return sendMessage(STDOUT_FILENO, &message);
}

struct PropertySet {
	char creationDate;
	// TODO char displayName;
	char contentLength;
	// TODO char contentType;
	// TODO etag
	char lastModified;
	char resourceType;
};

static int parsePropFind(int fd, struct PropertySet * properties) {
	memset(properties, 0, sizeof(struct PropertySet));
	xmlTextReaderPtr reader = xmlReaderForFd(fd, NULL, NULL, XML_PARSE_NOENT);
	int readResult;
	if (!reader || !stepInto(reader)) {
		stdLogError(0, "could not create xml reader");
		close(fd);
		return 0;
	}

	if (!elementMatches(reader, "DAV:", "propfind")) {
		stdLogError(0, "Request body was not a propfind document");
		readResult = 0;
		goto CLEANUP;
	}

	readResult = stepInto(reader);
	while (readResult && xmlTextReaderDepth(reader) > 0 && !elementMatches(reader, "DAV:", "prop")) {
		stepOver(reader);
	}

	if (!readResult) {
		goto CLEANUP;
	}

	readResult = stepInto(reader);
	while (readResult && xmlTextReaderDepth(reader) > 1) {
		if (!strcmp(xmlTextReaderConstNamespaceUri(reader), "DAV:")) {
			const char * nodeName = xmlTextReaderConstLocalName(reader);
			if (!strcmp(nodeName, "resourcetype")) {
				properties->resourceType = 1;
			} else if (!strcmp(nodeName, "creationdate")) {
				properties->creationDate = 1;
			} else if (!strcmp(nodeName, "contentlength")) {
				properties->contentLength = 1;
			} else if (!strcmp(nodeName, "lastmodified")) {
				properties->lastModified = 1;
			}
		}
		stepOver(reader);
	}

	if (!readResult) {
		goto CLEANUP;
	}

	// finish up
	while (stepOver(reader))
		// consume the rest of the input
		;

	CLEANUP:

	xmlFreeTextReader(reader);
	close(fd);
	return readResult;
}

static void writePropFindResponsePart(const char * fileName, struct PropertySet * properties, struct stat * fileStat,
		FILE * writeHandle) {
	fprintf(writeHandle, "<d:response><d:href>%s</d:href><d:propstat><d:prop>", fileName);
	if (properties->contentLength) {
		fprintf(writeHandle, "<d:contentlength>%zd</d:contentlength>", fileStat->st_size);
	}
	if (properties->creationDate) {
		char dateBuffer[100];
		getWebDate(fileStat->st_ctime, dateBuffer, 100);
		fprintf(writeHandle, "<d:creationdate>%s</d:creationdate>", dateBuffer);
	}
	if (properties->lastModified) {
		char dateBuffer[100];
		getWebDate(fileStat->st_mtime, dateBuffer, 100);
		fprintf(writeHandle, "<d:lastmodified>%s</d:lastmodified>", dateBuffer);
	}
	if (properties->resourceType) {
		if ((fileStat->st_mode & S_IFMT) == S_IFDIR) {
			fprintf(writeHandle, "<d:resourcetype><d:collection /></d:resourcetype>");
		} else {
			fprintf(writeHandle, "<d:resourcetype></d:resourcetype>");
		}
	}
	fprintf(writeHandle, "</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>");

	//<d:getetag>"56a341a7873fd"</d:getetag>
	//<d:getlastmodified>Sat, 23 Jan 2016 09:02:31 GMT</d:getlastmodified>
}

static int respondToPropFind(const char * file, const char * host, struct PropertySet * properties, int depth) {
	// stdLog("propfind respnd %d", depth);
	struct stat fileStat;

	if (stat(file, &fileStat)) {
		int e = errno;
		switch (e) {
		case EACCES:
			stdLogError(e, "PROPFIND access denied %s %s %s", authenticatedUser, host, file);
			return respond(RAP_ACCESS_DENIED, -1);
		case ENOENT:
		default:
			stdLogError(e, "PROPFIND not found %s %s %s", authenticatedUser, host, file);
			return respond(RAP_NOT_FOUND, -1);
		}
	}

	int pipeEnds[2];
	if (pipe(pipeEnds)) {
		stdLogError(errno, "Could not create pipe to write content");
		return respond(RAP_INTERNAL_ERROR, -1);
	}

	char * filePath;
	size_t filePathSize = strlen(file);
	if ((fileStat.st_mode & S_IFMT) == S_IFDIR && file[filePathSize - 1] != '/') {
		filePath = mallocSafe(filePathSize + 2);
		memcpy(filePath, file, filePathSize);
		filePath[filePathSize] = '/';
		filePath[filePathSize + 1] = '\0';
		filePathSize++;
	} else {
		filePath = (char *) file;
	}

	time_t fileTime;
	time(&fileTime);
	struct Message message = { .mID = RAP_MULTISTATUS, .fd = pipeEnds[PIPE_READ], .bufferCount = 2 };
	message.buffers[RAP_DATE_INDEX].iov_base = &fileTime;
	message.buffers[RAP_DATE_INDEX].iov_len = sizeof(fileTime);
	message.buffers[RAP_MIME_INDEX].iov_base = "application/xml";
	message.buffers[RAP_MIME_INDEX].iov_len = sizeof("application/xml");
	message.buffers[RAP_LOCATION_INDEX].iov_base = filePath;
	message.buffers[RAP_LOCATION_INDEX].iov_len = filePathSize + 1;
	size_t messageResult = sendMessage(STDOUT_FILENO, &message);
	if (messageResult <= 0) {
		if (filePath != file) {
			free(filePath);
		}
		close(pipeEnds[PIPE_WRITE]);
		return messageResult;
	}

	// We've set up the pipe and sent read end across so now write the result
	FILE * outPipe = fdopen(pipeEnds[PIPE_WRITE], "w");
	DIR * dir;
	fprintf(outPipe, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<d:multistatus xmlns:d=\"DAV:\">");
	writePropFindResponsePart(filePath, properties, &fileStat, outPipe);
	if (depth > 1 && (fileStat.st_mode & S_IFMT) == S_IFDIR && (dir = opendir(filePath))) {
		struct dirent * dp;
		char * childFileName = mallocSafe(filePathSize + 257);
		size_t maxSize = 255;
		strcpy(childFileName, filePath);
		while ((dp = readdir(dir)) != NULL) {
			if (dp->d_name[0] != '.' || (dp->d_name[1] != '\0' && dp->d_name[1] != '.') || dp->d_name[2] != '\0') {
				size_t nameSize = strlen(dp->d_name);
				if (nameSize > maxSize) {
					childFileName = reallocSafe(childFileName, filePathSize + nameSize + 2);
					maxSize = nameSize;
				}
				strcpy(childFileName + filePathSize, dp->d_name);
				if (!stat(childFileName, &fileStat)) {
					if ((fileStat.st_mode & S_IFMT) == S_IFDIR) {
						childFileName[filePathSize + nameSize] = '/';
						childFileName[filePathSize + nameSize + 1] = '\0';
					}
					writePropFindResponsePart(childFileName, properties, &fileStat, outPipe);
				}
			}
		}
		free(childFileName);
	}
	fprintf(outPipe, "</d:multistatus>");
	fclose(outPipe);
	if (filePath != file) {
		free(filePath);
	}
	return messageResult;

}

static size_t propfind(struct Message * requestMessage) {
	if (requestMessage->fd == -1) {
		stdLogError(0, "No body sent in propfind request");
		return respond(RAP_BAD_CLIENT_REQUEST, -1);
	}

	if (!authenticated || requestMessage->bufferCount != 3) {
		if (!authenticated) {
			stdLogError(0, "Not authenticated RAP");
		} else {
			stdLogError(0, "Get request did not provide correct buffers: %d buffer(s)", requestMessage->bufferCount);
		}
		close(requestMessage->fd);
		return respond(RAP_BAD_RAP_REQUEST, -1);
	}

	int ret = respond(RAP_CONTINUE, -1);

	const char * depthString = iovecToString(&requestMessage->buffers[RAP_DEPTH_INDEX]);

	struct PropertySet properties;
	if (!parsePropFind(requestMessage->fd, &properties)) {
		return respond(RAP_BAD_CLIENT_REQUEST, -1);
	}

	return respondToPropFind(iovecToString(&requestMessage->buffers[RAP_FILE_INDEX]),
			iovecToString(&requestMessage->buffers[RAP_HOST_INDEX]), &properties, (strcmp("0", depthString) ? 2 : 1));
}

static size_t writeFile(struct Message * requestMessage) {
	return respond(RAP_BAD_RAP_REQUEST, -1);
}

static size_t readFile(struct Message * requestMessage) {
	if (requestMessage->fd != -1) {
		stdLogError(0, "read file request sent incoming data!");
		close(requestMessage->fd);
	}
	if (!authenticated || requestMessage->bufferCount != 2) {
		if (!authenticated) {
			stdLogError(0, "Not authenticated RAP");
		} else {
			stdLogError(0, "Get request did not provide correct buffers: %d buffer(s)", requestMessage->bufferCount);
		}
		return respond(RAP_BAD_RAP_REQUEST, -1);
	}

	char * host = iovecToString(&requestMessage->buffers[RAP_HOST_INDEX]);
	char * file = iovecToString(&requestMessage->buffers[RAP_FILE_INDEX]);
	int fd = open(file, O_RDONLY);
	if (fd == -1) {
		int e = errno;
		switch (e) {
		case EACCES:
			stdLogError(e, "GET access denied %s %s %s", authenticatedUser, host, file);
			return respond(RAP_ACCESS_DENIED, -1);
		case ENOENT:
		default:
			stdLogError(e, "GET not found %s %s %s", authenticatedUser, host, file);
			return respond(RAP_NOT_FOUND, -1);
		}
	} else {
		struct stat statinfo;
		fstat(fd, &statinfo);

		if ((statinfo.st_mode & S_IFMT) == S_IFDIR) {
			int pipeEnds[2];
			if (pipe(pipeEnds)) {
				stdLogError(errno, "Could not create pipe to write content");
				close(fd);
				return respond(RAP_INTERNAL_ERROR, -1);
			}

			time_t fileTime;
			time(&fileTime);

			struct Message message = { .mID = RAP_SUCCESS, .fd = pipeEnds[PIPE_READ], 3 };
			message.buffers[RAP_DATE_INDEX].iov_base = &fileTime;
			message.buffers[RAP_DATE_INDEX].iov_len = sizeof(fileTime);
			message.buffers[RAP_MIME_INDEX].iov_base = "text/html";
			message.buffers[RAP_MIME_INDEX].iov_len = sizeof("text/html");
			message.buffers[RAP_LOCATION_INDEX] = requestMessage->buffers[RAP_FILE_INDEX];
			size_t messageResult = sendMessage(STDOUT_FILENO, &message);
			if (messageResult <= 0) {
				close(fd);
				close(pipeEnds[PIPE_WRITE]);
				return messageResult;
			}

			// We've set up the pipe and sent read end across so now write the result
			DIR * dir = fdopendir(fd);
			FILE * outPipe = fdopen(pipeEnds[PIPE_WRITE], "w");
			char * sep = (file[strlen(file) - 1] == '/' ? "" : "/");
			fprintf(outPipe, "<html><head><title>%s%s</title></head><body><h1>%s%s</h1><ul>", file, sep, file, sep);
			struct dirent * dp;
			while ((dp = readdir(dir)) != NULL) {
				if (dp->d_name[0] != '.') {
					if (dp->d_type == DT_DIR) {
						fprintf(outPipe, "<li><a href=\"%s%s%s/\">%s/</a></li>", file, sep, dp->d_name, dp->d_name);
					} else {
						fprintf(outPipe, "<li><a href=\"%s%s%s\">%s</a></li>", file, sep, dp->d_name, dp->d_name);
					}
				}
			}
			fprintf(outPipe, "</ul></body></html>");
			closedir(dir);
			fclose(outPipe);
			return messageResult;
		} else {
			struct Message message = { .mID = RAP_SUCCESS, .fd = fd, .bufferCount = 3 };
			message.buffers[RAP_DATE_INDEX].iov_base = &statinfo.st_mtime;
			message.buffers[RAP_DATE_INDEX].iov_len = sizeof(statinfo.st_mtime);
			message.buffers[RAP_MIME_INDEX].iov_base = "";
			message.buffers[RAP_MIME_INDEX].iov_len = sizeof("");
			message.buffers[RAP_LOCATION_INDEX] = requestMessage->buffers[RAP_FILE_INDEX];
			return sendMessage(STDOUT_FILENO, &message);
		}
	}
}

static int pamConverse(int n, const struct pam_message **msg, struct pam_response **resp, char * password) {
	struct pam_response * response = mallocSafe(sizeof(struct pam_response));
	response->resp_retcode = 0;
	size_t passSize = strlen(password) + 1;
	response->resp = mallocSafe(passSize);
	memcpy(response->resp, password, passSize);
	*resp = response;
	return PAM_SUCCESS;
}

static pam_handle_t *pamh;

static void pamCleanup() {
	int pamResult = pam_close_session(pamh, 0);
	pam_end(pamh, pamResult);
}

static int pamAuthenticate(const char * user, const char * password, const char * hostname) {
	static struct pam_conv pamc = { .conv = (int (*)(int num_msg, const struct pam_message **msg,
			struct pam_response **resp, void *appdata_ptr)) &pamConverse };
	pamc.appdata_ptr = (void *) password;
	char ** envList;

	// TODO setup configurable PAM services
	if (pam_start("webdav", user, &pamc, &pamh) != PAM_SUCCESS) {
		stdLogError(0, "Could not start PAM");
		return 0;
	}

	stdLog("auth start");

	// Authenticate and start session
	int pamResult;
	if ((pamResult = pam_set_item(pamh, PAM_RHOST, hostname)) != PAM_SUCCESS
			|| (pamResult = pam_set_item(pamh, PAM_RUSER, user)) != PAM_SUCCESS
			|| (pamResult = pam_authenticate(pamh, PAM_SILENT | PAM_DISALLOW_NULL_AUTHTOK)) != PAM_SUCCESS
			|| (pamResult = pam_acct_mgmt(pamh, PAM_SILENT | PAM_DISALLOW_NULL_AUTHTOK)) != PAM_SUCCESS
			|| (pamResult = pam_setcred(pamh, PAM_ESTABLISH_CRED)) != PAM_SUCCESS
			|| (pamResult = pam_open_session(pamh, 0)) != PAM_SUCCESS) {
		pam_end(pamh, pamResult);
		return 0;
	}

	// Get user details
	if ((pamResult = pam_get_item(pamh, PAM_USER, (const void **) &user)) != PAM_SUCCESS
			|| (envList = pam_getenvlist(pamh)) == NULL) {

		pamResult = pam_close_session(pamh, 0);
		pam_end(pamh, pamResult);

		return 0;
	}

	// Set up environment and switch user
	clearenv();
	for (char ** pam_env = envList; *pam_env != NULL; ++pam_env) {
		putenv(*pam_env);
		free(*pam_env);
	}
	free(envList);

	if (!lockToUser(user)) {
		stdLogError(errno, "Could not set uid or gid");
		pam_close_session(pamh, 0);
		pam_end(pamh, pamResult);
		return 0;
	}

	atexit(&pamCleanup);
	size_t userLen = strlen(user) + 1;
	authenticatedUser = mallocSafe(userLen);
	memcpy((char *) authenticatedUser, user, userLen);

	authenticated = 1;
	stdLog("auth end");
	return 1;
}

static size_t authenticate(struct Message * message) {
	if (message->fd != -1) {
		stdLogError(0, "authenticate request send incoming data!");
		close(message->fd);
	}
	if (authenticated || message->bufferCount != 3) {
		if (authenticated) {
			stdLogError(0, "Login for already logged in RAP");
		} else {
			stdLogError(0, "Login provided %d buffer(s) instead of 3", message->bufferCount);
		}
		return respond(RAP_BAD_RAP_REQUEST, -1);
	}

	char * user = iovecToString(&message->buffers[RAP_USER_INDEX]);
	char * password = iovecToString(&message->buffers[RAP_PASSWORD_INDEX]);
	char * rhost = iovecToString(&message->buffers[RAP_RHOST_INDEX]);

	if (pamAuthenticate(user, password, rhost)) {
		//stdLog("Login accepted for %s", user);
		return respond(RAP_SUCCESS, -1);
	} else {
		return respond(RAP_AUTH_FAILLED, -1);
	}
}

typedef size_t (*handlerMethod)(struct Message * message);
static handlerMethod handlerMethods[] = { authenticate, readFile, writeFile, propfind };

int main(int argCount, char ** args) {
	size_t ioResult;
	struct Message message;
	char incomingBuffer[INCOMING_BUFFER_SIZE];
	do {
		// Read a message
		ioResult = recvMessage(STDIN_FILENO, &message, incomingBuffer, INCOMING_BUFFER_SIZE);
		if (ioResult <= 0) {
			if (ioResult < 0) {
				exit(1);
			} else {
				continue;
			}
		}

		// Handle the message
		if (message.mID > RAP_MAX_REQUEST || message.mID < RAP_MIN_REQUEST) {
			ioResult = respond(RAP_BAD_RAP_REQUEST, -1);
			continue;
		}
		ioResult = handlerMethods[message.mID - RAP_MIN_REQUEST](&message);
		if (ioResult < 0) {
			ioResult = 0;
		}

	} while (ioResult);
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	return 0;
}
