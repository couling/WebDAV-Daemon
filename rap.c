#include "shared.h"

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <sys/stat.h>
#include <dirent.h>
#include <security/pam_appl.h>
#include <libxml/xmlreader.h>

#define BUFFER_SIZE 4096

static int authenticated = 0;
static const char * authenticatedUser;

#define respond(result, fd) sendMessage(STDOUT_FILENO, result, fd, 0, NULL)

/*const char * nodeTypeToName(int nodeType) {
 switch (nodeType) {
 case XML_READER_TYPE_NONE:
 return "XML_READER_TYPE_NONE";
 case XML_READER_TYPE_ELEMENT:
 return "XML_READER_TYPE_ELEMENT";
 case XML_READER_TYPE_ATTRIBUTE:
 return "XML_READER_TYPE_ATTRIBUTE";
 case XML_READER_TYPE_TEXT:
 return "XML_READER_TYPE_TEXT";
 case XML_READER_TYPE_CDATA:
 return "XML_READER_TYPE_CDATA";
 case XML_READER_TYPE_ENTITY_REFERENCE:
 return "XML_READER_TYPE_ENTITY_REFERENCE";
 case XML_READER_TYPE_ENTITY:
 return "XML_READER_TYPE_ENTITY";
 case XML_READER_TYPE_PROCESSING_INSTRUCTION:
 return "XML_READER_TYPE_PROCESSING_INSTRUCTION";
 case XML_READER_TYPE_COMMENT:
 return "XML_READER_TYPE_COMMENT";
 case XML_READER_TYPE_DOCUMENT:
 return "XML_READER_TYPE_DOCUMENT";
 case XML_READER_TYPE_DOCUMENT_TYPE:
 return "XML_READER_TYPE_DOCUMENT_TYPE";
 case XML_READER_TYPE_DOCUMENT_FRAGMENT:
 return "XML_READER_TYPE_DOCUMENT_FRAGMENT";
 case XML_READER_TYPE_NOTATION:
 return "XML_READER_TYPE_NOTATION";
 case XML_READER_TYPE_WHITESPACE:
 return "XML_READER_TYPE_WHITESPACE";
 case XML_READER_TYPE_SIGNIFICANT_WHITESPACE:
 return "XML_READER_TYPE_SIGNIFICANT_WHITESPACE";
 case XML_READER_TYPE_END_ELEMENT:
 return "XML_READER_TYPE_END_ELEMENT";
 case XML_READER_TYPE_END_ENTITY:
 return "XML_READER_TYPE_END_ENTITY";
 case XML_READER_TYPE_XML_DECLARATION:
 return "XML_READER_TYPE_XML_DECLARATION";
 default:
 return NULL;
 }
 }*/

static size_t respondWithHeaders(int responseCode, int fd, time_t fileTime, const char * fileName,
		const char * mimeType, int isDir) {
	struct iovec message[MAX_BUFFER_PARTS];
	message[RAP_DATE_INDEX].iov_base = &fileTime;
	message[RAP_DATE_INDEX].iov_len = sizeof(fileTime);
	message[RAP_MIME_INDEX].iov_base = (void *) mimeType;
	message[RAP_MIME_INDEX].iov_len = strlen(mimeType) + 1;
	size_t fileNameSize = strlen(fileName) + 1;
	if (fileName[fileNameSize - 2] != '/') {
		message[RAP_LOCATION_INDEX].iov_base = mallocSafe(fileNameSize + 1);
		memcpy(message[RAP_LOCATION_INDEX].iov_base, fileName, fileNameSize);
		((char *) message[RAP_LOCATION_INDEX].iov_base)[fileNameSize - 1] = '/';
		((char *) message[RAP_LOCATION_INDEX].iov_base)[fileNameSize] = '\0';
		message[RAP_LOCATION_INDEX].iov_len = fileNameSize + 1;
	} else {
		message[RAP_LOCATION_INDEX].iov_base = (void *) fileName;
		message[RAP_LOCATION_INDEX].iov_len = fileNameSize;
	}
	size_t messageResult = sendMessage(STDOUT_FILENO, responseCode, fd, 3, message);
	if (message[RAP_LOCATION_INDEX].iov_base == fileName) {
		free(message[RAP_LOCATION_INDEX].iov_base);
	}
	return messageResult;
}

static int stepInto(xmlTextReaderPtr reader) {
	// Skip all significant white space
	int result;
	do {
		result = xmlTextReaderRead(reader);
	} while (result && xmlTextReaderNodeType(reader) == XML_READER_TYPE_SIGNIFICANT_WHITESPACE);
	return result;
}

static int stepOver(xmlTextReaderPtr reader) {
	int depth = xmlTextReaderDepth(reader);
	do {
		if (!stepInto(reader)) {
			return 0;
		}
	} while (xmlTextReaderDepth(reader) > depth);
	return 1;
}

static int elementMatches(xmlTextReaderPtr reader, const char * namespace, const char * nodeName) {
	return xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT
			&& !strcmp(xmlTextReaderConstNamespaceUri(reader), namespace)
			&& !strcmp(xmlTextReaderConstLocalName(reader), nodeName);
}

struct PropertySet {
	char resourceType;
};

static int parsePropFind(int fd, struct PropertySet * properties) {
	memset(properties, 0, sizeof(struct PropertySet));
	xmlTextReaderPtr reader = xmlReaderForFd(fd, NULL, NULL, XML_PARSE_NOENT);
	int readResult;
	if (!reader) {
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
			if (!strcmp(xmlTextReaderConstLocalName(reader), "resourcetype")) {
				properties->resourceType = 1;
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

	CLEANUP: xmlFreeTextReader(reader);
	close(fd);
	return readResult;
}

static int respondToPropFind(const char * file, const char * host, struct PropertySet * properties, int depth) {
	struct stat fileStat;

	if (stat(file, &fileStat)) {
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
	}

	int pipeEnds[2];
	if (pipe(pipeEnds)) {
		stdLogError(errno, "Could not create pipe to write content");
		return respond(RAP_INTERNAL_ERROR, -1);
	}
	time_t fileTime;
	time(&fileTime);

	size_t messageResult = respondWithHeaders(RAP_MULTISTATUS, pipeEnds[PIPE_READ], fileTime, file, "application/xml",
			(fileStat.st_mode & S_IFMT) == S_IFDIR);

	if (messageResult <= 0) {
		close(pipeEnds[PIPE_WRITE]);
		return messageResult;
	}

	// We've set up the pipe and sent read end across so now write the result
	FILE * outPipe = fdopen(pipeEnds[PIPE_WRITE], "w");
	char * sep = ((fileStat.st_mode & S_IFMT) == S_IFDIR && file[strlen(file) - 1] == '/' ? "" : "/");
	fprintf(outPipe, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<d:multistatus xmlns:d=\"DAV:\">");
	fprintf(outPipe, "</d:multistatus>");

	/*fprintf(outPipe, "<html><head><title>%s%s</title></head><body><h1>%s%s</h1><ul>", file, sep, file, sep);
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
	closedir(dir);*/
	fclose(outPipe);
	return messageResult;

}

static size_t propfind(int bufferCount, struct iovec * bufferHeaders, int fd) {
	if (fd == -1) {
		stdLogError(0, "No body sent in propfind request");
		return respond(RAP_BAD_REQUEST, -1);
	}

	if (!authenticated || bufferCount != 3) {
		if (!authenticated) {
			stdLogError(0, "Not authenticated RAP");
		} else {
			stdLogError(0, "Get request did not provide correct buffers: %d buffer(s)", bufferCount);
		}
		close(fd);
		return respond(RAP_BAD_REQUEST, -1);
	}

	int ret = respond(RAP_CONTINUE, -1);

	struct PropertySet properties;
	if (!parsePropFind(fd, &properties)) {
		return respond(RAP_BAD_REQUEST, -1);
	}

	return respondToPropFind(iovecToString(&bufferHeaders[RAP_FILE_INDEX]),
			iovecToString(&bufferHeaders[RAP_HOST_INDEX]), &properties,
			*((int *) bufferHeaders[RAP_DEPTH_INDEX].iov_base));
}

static size_t writeFile(int bufferCount, struct iovec * bufferHeaders, int fd) {
	return respond(RAP_BAD_REQUEST, -1);
}

static size_t readFile(int bufferCount, struct iovec * bufferHeaders, int incomingFd) {
	if (incomingFd != -1) {
		stdLogError(0, "read file request send incoming data!");
		close(incomingFd);
	}
	if (!authenticated || bufferCount != 2) {
		if (!authenticated) {
			stdLogError(0, "Not authenticated RAP");
		} else {
			stdLogError(0, "Get request did not provide correct buffers: %d buffer(s)", bufferCount);
		}
		return respond(RAP_BAD_REQUEST, -1);
	}

	char * host = iovecToString(&bufferHeaders[RAP_HOST_INDEX]);
	char * file = iovecToString(&bufferHeaders[RAP_FILE_INDEX]);
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
			stdLog("GET dir success %s %s %s", authenticatedUser, host, file);
			size_t messageResult = respondWithHeaders(RAP_SUCCESS, pipeEnds[PIPE_READ], fileTime, file, "text/html", 1);
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
			stdLog("GET success %s %s %s", authenticatedUser, host, file);
			return respondWithHeaders(RAP_SUCCESS, fd, statinfo.st_mtime, file, "", 0);
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

static int pamAuthenticate(const char * user, const char * password) {
	char hostname[] = "localhost";
	static struct pam_conv pamc = { .conv = (int (*)(int num_msg, const struct pam_message **msg,
			struct pam_response **resp, void *appdata_ptr)) &pamConverse };
	pamc.appdata_ptr = (void *) password;
	struct passwd * pwd;
	char ** envList;

	// TODO setup multiple PAM services
	if (pam_start("webdavd", user, &pamc, &pamh) != PAM_SUCCESS) {
		stdLogError(0, "Could not start PAM");
		return 0;
	}

	// Authenticate and start session
	int pamResult;
	if ((pamResult = pam_set_item(pamh, PAM_RHOST, hostname)) != PAM_SUCCESS
			|| (pamResult = pam_set_item(pamh, PAM_RUSER, user)) != PAM_SUCCESS

			|| (pamResult = pam_authenticate(pamh, PAM_SILENT | PAM_DISALLOW_NULL_AUTHTOK)) != PAM_SUCCESS
			|| (pamResult = pam_acct_mgmt(pamh, PAM_SILENT | PAM_DISALLOW_NULL_AUTHTOK)) != PAM_SUCCESS || (pamResult =
					pam_setcred(pamh, PAM_ESTABLISH_CRED)) != PAM_SUCCESS
			|| (pamResult = pam_open_session(pamh, 0)) != PAM_SUCCESS) {
		pam_end(pamh, pamResult);
		return 0;
	}

	// Get user details
	if ((pamResult = pam_get_item(pamh, PAM_USER, (const void **) &user)) != PAM_SUCCESS
			|| (pwd = getpwnam(user)) == NULL || (envList = pam_getenvlist(pamh)) == NULL) {

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

	if (initgroups(user, pwd->pw_gid) || setgid(pwd->pw_gid) || setuid(pwd->pw_uid)) {
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

	return 1;
}

static size_t authenticate(int bufferCount, struct iovec * bufferHeaders, int fd) {
	if (fd != -1) {
		stdLogError(0, "authenticate request send incoming data!");
		close(fd);
	}
	if (authenticated || bufferCount != 2) {
		if (authenticated) {
			stdLogError(0, "Login for already logged in RAP");
		} else {
			stdLogError(0, "Login did not provide both user and password and gave %d buffer(s)", bufferCount);
		}
		return respond(RAP_BAD_REQUEST, -1);
	}

	char * user = iovecToString(&bufferHeaders[RAP_USER_INDEX]);
	char * password = iovecToString(&bufferHeaders[RAP_PASSWORD_INDEX]);

	// TODO REMOVE THIS!
	authenticated = 1;
	authenticatedUser = "philip";
	return respond(RAP_SUCCESS, -1);
	if (pamAuthenticate(user, password)) {
		//stdLog("Login accepted for %s", user);
		return respond(RAP_SUCCESS, -1);
	} else {
		return respond(RAP_AUTH_FAILLED, -1);
	}
}

typedef size_t (*handlerMethod)(int bufferCount, struct iovec * bufferHeaders, int fd);
static handlerMethod handlerMethods[] = { authenticate, readFile, writeFile, propfind };

int main(int argCount, char ** args) {
	int bufferCount;
	struct iovec bufferHeaders[MAX_BUFFER_PARTS];
	enum RapConstant mID;
	size_t ioResult;
	int incomingFd;
	do {
		bufferCount = MAX_BUFFER_PARTS;

		// Read a message
		char incomingBuffer[INCOMING_BUFFER_SIZE];
		ioResult = recvMessage(STDIN_FILENO, &mID, &incomingFd, &bufferCount, bufferHeaders, incomingBuffer,
		INCOMING_BUFFER_SIZE);
		if (ioResult <= 0) {
			if (ioResult < 0) {
				exit(1);
			} else {
				continue;
			}
		}

		// Handle the message
		if (mID > RAP_MAX_REQUEST || mID < RAP_MIN_REQUEST) {
			ioResult = respond(RAP_BAD_REQUEST, -1);
			continue;
		}
		ioResult = handlerMethods[mID - RAP_MIN_REQUEST](bufferCount, bufferHeaders, incomingFd);
		if (ioResult < 0) {
			ioResult = 0;
		}

	} while (ioResult);
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	return 0;
}
