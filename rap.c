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

static size_t respond(enum RapConstant result, int fd) {
	return sendMessage(STDOUT_FILENO, result, fd, 0, NULL);
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
	int result;
	do {
		result = xmlTextReaderRead(reader);
	} while (result && xmlTextReaderDepth(reader) > depth
			&& xmlTextReaderNodeType(reader) == XML_READER_TYPE_SIGNIFICANT_WHITESPACE);
	return result;
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
	if (!reader /*|| !stepInto(reader)*/) {
		stdLogError(0, "could not create xml reader");
		close(fd);
		return 0;
	}

	stdLog("%s %s", xmlTextReaderConstNamespaceUri(reader), xmlTextReaderConstLocalName(reader));
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

	CLEANUP:

	xmlFreeTextReader(reader);
	close(fd);
	return readResult;
}

static void writePropFindResponsePart(const char * fileName, struct PropertySet * properties, struct stat * fileStat,
		FILE * writeHandle) {
	fprintf(writeHandle, "<d:response><d:href>%s</d:href><d:propstat><d:prop>", fileName);
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
	stdLog("propfind respnd");
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

	char * filePath;
	size_t filePathSize = strlen(file);
	if ((fileStat.st_mode & S_IFMT) == S_IFDIR && file[filePathSize - 1] != '/') {
		filePath = mallocSafe(filePathSize + 2);
		memcpy(filePath, file, filePathSize);
		filePath[filePathSize - 2] = '/';
		filePath[filePathSize - 1] = '\0';
		filePathSize++;
	}

	time_t fileTime;
	time(&fileTime);
	struct iovec message[MAX_BUFFER_PARTS];
	message[RAP_DATE_INDEX].iov_base = &fileTime;
	message[RAP_DATE_INDEX].iov_len = sizeof(fileTime);
	message[RAP_MIME_INDEX].iov_base = "application/xml";
	message[RAP_MIME_INDEX].iov_len = sizeof("application/xml");
	message[RAP_LOCATION_INDEX].iov_base = filePath;
	message[RAP_LOCATION_INDEX].iov_len = filePathSize + 1;
	size_t messageResult = sendMessage(STDOUT_FILENO, RAP_MULTISTATUS, pipeEnds[PIPE_READ], 2, message);
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
					if ((fileStat.st_mode & S_IFMT) == S_IFDIR && childFileName[filePathSize + nameSize - 1] != '/') {
						childFileName[filePathSize + nameSize] = '\0';
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

static size_t propfind(int bufferCount, struct iovec * bufferHeaders, int fd) {
	if (fd == -1) {
		stdLogError(0, "No body sent in propfind request");
		return respond(RAP_BAD_RAP_REQUEST, -1);
	}

	if (!authenticated || bufferCount != 3) {
		if (!authenticated) {
			stdLogError(0, "Not authenticated RAP");
		} else {
			stdLogError(0, "Get request did not provide correct buffers: %d buffer(s)", bufferCount);
		}
		close(fd);
		return respond(RAP_BAD_RAP_REQUEST, -1);
	}

	int ret = respond(RAP_CONTINUE, -1);

	struct PropertySet properties;
	if (!parsePropFind(fd, &properties)) {
		stdLog("responding bad request");
		return respond(RAP_BAD_RAP_REQUEST, -1);
	}

	return respondToPropFind(iovecToString(&bufferHeaders[RAP_FILE_INDEX]),
			iovecToString(&bufferHeaders[RAP_HOST_INDEX]), &properties,
			*((int *) bufferHeaders[RAP_DEPTH_INDEX].iov_base));
}

static size_t writeFile(int bufferCount, struct iovec * bufferHeaders, int fd) {
	return respond(RAP_BAD_RAP_REQUEST, -1);
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
		return respond(RAP_BAD_RAP_REQUEST, -1);
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

			struct iovec message[MAX_BUFFER_PARTS];
			message[RAP_DATE_INDEX].iov_base = &fileTime;
			message[RAP_DATE_INDEX].iov_len = sizeof(fileTime);
			message[RAP_MIME_INDEX].iov_base = "text/html";
			message[RAP_MIME_INDEX].iov_len = sizeof("text/html");
			message[RAP_LOCATION_INDEX] = bufferHeaders[RAP_FILE_INDEX];
			size_t messageResult = sendMessage(STDOUT_FILENO, RAP_SUCCESS, pipeEnds[PIPE_READ], 3, message);
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
			struct iovec message[MAX_BUFFER_PARTS];
			message[RAP_DATE_INDEX].iov_base = &statinfo.st_mtime;
			message[RAP_DATE_INDEX].iov_len = sizeof(statinfo.st_mtime);
			message[RAP_MIME_INDEX].iov_base = "";
			message[RAP_MIME_INDEX].iov_len = sizeof("");
			message[RAP_LOCATION_INDEX] = bufferHeaders[RAP_FILE_INDEX];
			return sendMessage(STDOUT_FILENO, RAP_SUCCESS, fd, 3, message);
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
		return respond(RAP_BAD_RAP_REQUEST, -1);
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
			ioResult = respond(RAP_BAD_RAP_REQUEST, -1);
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
