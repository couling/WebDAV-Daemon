#include "shared.h"
#include "xml.h"

//#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <dirent.h>
#include <locale.h>
#include <security/pam_appl.h>

#define BUFFER_SIZE 40960

typedef struct MimeType {
	const char * fileExtension;
	const char * type;
	size_t typeStringSize;
} MimeType;

// Authentication
static int authenticated = 0;
static const char * authenticatedUser;
static const char * pamService;
static pam_handle_t *pamh;

// Mime Database.
static size_t mimeFileBufferSize;
static char * mimeFileBuffer;
static MimeType * mimeTypes = NULL;
static int mimeTypeCount = 0;

static MimeType UNKNOWN_MIME_TYPE = { .fileExtension = "", .type = "application/octet-stream", .typeStringSize =
		sizeof("application/octet-stream") };
static MimeType XML_MIME_TYPE = { .fileExtension = "", .type = "application/xml; charset=utf-8", .typeStringSize =
		sizeof("application/xml; charset=utf-8") };

static ssize_t respond(enum RapConstant result, int fd) {
	Message message = { .mID = result, .fd = fd, .bufferCount = 0 };
	return sendMessage(RAP_CONTROL_SOCKET, &message);
}

static char * normalizeDirName(const char * file, size_t * filePathSize, int isDir) {
	char * filePath = mallocSafe(*filePathSize + 2);
	memcpy(filePath, file, *filePathSize + 1);
	if (isDir && file[*filePathSize - 1] != '/') {
		filePath[*filePathSize] = '/';
		filePath[*filePathSize + 1] = '\0';
		(*filePathSize)++;
	}
	return filePath;
}

static size_t formatFileSize(char * buffer, size_t bufferSize, off_t size) {
	static char * suffix[] = { "B", "KiB", "MiB", "GiB", "TiB", "PiB" "EiB", "ZiB", "YiB" };
	int magnitude = 0;
	off_t tmpSize = size;
	while (magnitude < 8 && (tmpSize & 1023) != tmpSize) {
		magnitude++;
		tmpSize >>= 10;
	}
	double divisor;
	char * format;
	if (magnitude > 0) {
		divisor = ((off_t) 1) << (magnitude * 10);
		if (tmpSize >= 100) {
			format = "%.0f %s";
		} else if (tmpSize >= 10) {
			format = "%.1f %s";
		} else {
			format = "%.2f %s";
		}
	} else {
		divisor = 1;
		format = "%.0f %s";
	}
	double dsize = size;
	dsize /= divisor;
	return snprintf(buffer, bufferSize, format, dsize, suffix[magnitude]);
}

//////////
// Mime //
//////////

static int compareExt(const void * a, const void * b) {
	return strcmp(((MimeType *) a)->fileExtension, ((MimeType *) b)->fileExtension);
}

static MimeType * findMimeType(const char * file) {

	if (!file) {
		return &UNKNOWN_MIME_TYPE;
	}
	MimeType type;
	type.fileExtension = file + strlen(file) - 1;
	while (1) {
		if (*type.fileExtension == '/') {
			return &UNKNOWN_MIME_TYPE;
		} else if (*type.fileExtension == '.') {
			type.fileExtension++;
			break;
		} else {
			type.fileExtension--;
			if (type.fileExtension < file) {
				return &UNKNOWN_MIME_TYPE;
			}
		}
	}

	MimeType * result = bsearch(&type, mimeTypes, mimeTypeCount, sizeof(*mimeTypes), &compareExt);
	return result ? result : &UNKNOWN_MIME_TYPE;
}

static void initializeMimeTypes(const char * mimeTypesFile) {
	// Load Mime file into memory
	mimeFileBuffer = loadFileToBuffer(mimeTypesFile, &mimeFileBufferSize);
	if (!mimeFileBuffer) {
		exit(1);
	}

	// Parse mimeFile;
	char * partStartPtr = mimeFileBuffer;
	int found;
	char * type = NULL;
	do {
		found = 0;
		// find the start of the part
		while (partStartPtr < mimeFileBuffer + mimeFileBufferSize && !found) {
			switch (*partStartPtr) {
			case '#':
				// skip to the end of the line
				while (partStartPtr < mimeFileBuffer + mimeFileBufferSize && *partStartPtr != '\n') {
					partStartPtr++;
				}
				// Fall through to incrementing partStartPtr
				partStartPtr++;
				break;
			case ' ':
			case '\t':
			case '\r':
			case '\n':
				if (*partStartPtr == '\n') {
					type = NULL;
				}
				partStartPtr++;
				break;
			default:
				found = 1;
				break;
			}
		}

		// Find the end of the part
		char * partEndPtr = partStartPtr + 1;
		found = 0;
		while (partEndPtr < mimeFileBuffer + mimeFileBufferSize && !found) {
			switch (*partEndPtr) {
			case ' ':
			case '\t':
			case '\r':
			case '\n':
				if (type == NULL) {
					type = partStartPtr;
				} else {
					mimeTypes = reallocSafe(mimeTypes, sizeof(*mimeTypes) * (mimeTypeCount + 1));
					mimeTypes[mimeTypeCount].type = type;
					mimeTypes[mimeTypeCount].fileExtension = partStartPtr;
					mimeTypes[mimeTypeCount].typeStringSize = partEndPtr - partStartPtr + 1;
					mimeTypeCount++;
				}
				if (*partEndPtr == '\n') {
					type = NULL;
				}
				*partEndPtr = '\0';
				found = 1;
				break;
			default:
				partEndPtr++;
				break;
			}
		}
		partStartPtr = partEndPtr + 1;
	} while (partStartPtr < mimeFileBuffer + mimeFileBufferSize);

	qsort(mimeTypes, mimeTypeCount, sizeof(*mimeTypes), &compareExt);
}

//////////////
// End Mime //
//////////////

//////////////
// PROPFIND //
//////////////

#define PROPFIND_RESOURCE_TYPE "resourcetype"
#define PROPFIND_CREATION_DATE "creationdate"
#define PROPFIND_CONTENT_LENGTH "getcontentlength"
#define PROPFIND_LAST_MODIFIED "getlastmodified"
#define PROPFIND_DISPLAY_NAME "displayname"
#define PROPFIND_CONTENT_TYPE "getcontenttype"
#define PROPFIND_USED_BYTES "quota-used-bytes"
#define PROPFIND_AVAILABLE_BYTES "quota-available-bytes"
#define PROPFIND_ETAG "getetag"
#define PROPFIND_WINDOWS_ATTRIBUTES "Win32FileAttributes"

typedef struct PropertySet {
	char creationDate;
	char displayName;
	char contentLength;
	char contentType;
	char etag;
	char lastModified;
	char resourceType;
	char usedBytes;
	char availableBytes;
	char windowsHidden;
} PropertySet;

static int parsePropFind(int fd, PropertySet * properties) {
	xmlTextReaderPtr reader = xmlReaderForFd(fd, NULL, NULL, XML_PARSE_NOENT);
	xmlReaderSuppressErrors(reader);

	int readResult;
	if (!reader || !stepInto(reader)) {
		stdLogError(0, "could not create xml reader");
		close(fd);
		return 0;
	}

	if (xmlTextReaderNodeType(reader) == XML_READER_TYPE_NONE) {
		// No body has been sent
		// so assume the client is asking for everything.
		readResult = 1;
		memset(properties, 1, sizeof(*properties));
		goto CLEANUP;
	} else {
		memset(properties, 0, sizeof(PropertySet));
	}

	if (!elementMatches(reader, WEBDAV_NAMESPACE, "propfind")) {
		stdLogError(0, "Request body was not a propfind document");
		readResult = 0;
		goto CLEANUP;
	}

	readResult = stepInto(reader);
	while (readResult && xmlTextReaderDepth(reader) > 0 && !elementMatches(reader, WEBDAV_NAMESPACE, "prop")) {
		stepOver(reader);
	}

	if (!readResult) {
		goto CLEANUP;
	}

	readResult = stepInto(reader);
	while (readResult && xmlTextReaderDepth(reader) > 1) {
		if (!strcmp(xmlTextReaderConstNamespaceUri(reader), WEBDAV_NAMESPACE)) {
			const char * nodeName = xmlTextReaderConstLocalName(reader);
			if (!strcmp(nodeName, PROPFIND_RESOURCE_TYPE)) {
				properties->resourceType = 1;
			} else if (!strcmp(nodeName, PROPFIND_CREATION_DATE)) {
				properties->creationDate = 1;
			} else if (!strcmp(nodeName, PROPFIND_CONTENT_LENGTH)) {
				properties->contentLength = 1;
			} else if (!strcmp(nodeName, PROPFIND_LAST_MODIFIED)) {
				properties->lastModified = 1;
			} else if (!strcmp(nodeName, PROPFIND_DISPLAY_NAME)) {
				properties->displayName = 1;
			} else if (!strcmp(nodeName, PROPFIND_CONTENT_TYPE)) {
				properties->contentType = 1;
			} else if (!strcmp(nodeName, PROPFIND_AVAILABLE_BYTES)) {
				properties->availableBytes = 1;
			} else if (!strcmp(nodeName, PROPFIND_USED_BYTES)) {
				properties->usedBytes = 1;
			} else if (!strcmp(nodeName, PROPFIND_ETAG)) {
				properties->etag = 1;
			}
		} else if (!strcmp(xmlTextReaderConstNamespaceUri(reader), MICROSOFT_NAMESPACE)) {
			const char * nodeName = xmlTextReaderConstLocalName(reader);
			if (!strcmp(nodeName, PROPFIND_WINDOWS_ATTRIBUTES)) {
				properties->windowsHidden = 1;
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

static void writePropFindResponsePart(const char * fileName, const char * displayName, PropertySet * properties,
		struct stat * fileStat, xmlTextWriterPtr writer) {

	xmlTextWriterStartElementNS(writer, "d", "response", NULL);
	xmlTextWriterStartElementNS(writer, "d", "href", NULL);
	xmlTextWriterWriteURL(writer, fileName);
	xmlTextWriterEndElement(writer);
	xmlTextWriterStartElementNS(writer, "d", "propstat", NULL);
	xmlTextWriterStartElementNS(writer, "d", "prop", NULL);

	if (properties->etag) {
		char buffer[200];
		snprintf(buffer, sizeof(buffer), "\"%lld-%lld\"", (long long) fileStat->st_size,
				(long long) fileStat->st_mtime);
		xmlTextWriterWriteElementString(writer, "d", PROPFIND_ETAG, buffer);
	}
	if (properties->creationDate) {
		char buffer[100];
		getWebDate(fileStat->st_ctime, buffer, 100);
		xmlTextWriterWriteElementString(writer, "d", PROPFIND_CREATION_DATE, buffer);
	}
	if (properties->lastModified) {
		char buffer[100];
		getWebDate(fileStat->st_ctime, buffer, 100);
		xmlTextWriterWriteElementString(writer, "d", PROPFIND_LAST_MODIFIED, buffer);
	}
	if (properties->resourceType) {
		xmlTextWriterStartElementNS(writer, "d", PROPFIND_RESOURCE_TYPE, NULL);
		if ((fileStat->st_mode & S_IFMT) == S_IFDIR) {
			xmlTextWriterStartElementNS(writer, "d", "collection", NULL);
			xmlTextWriterEndElement(writer);
		}
		xmlTextWriterEndElement(writer);
	}
	//if (properties->displayName) {
	//	xmlTextWriterWriteElementString(writer, PROPFIND_DISPLAY_NAME, displayName);
	//}
	if ((fileStat->st_mode & S_IFMT) == S_IFDIR) {
		if (properties->availableBytes) {
			struct statvfs fsStat;
			if (!statvfs(fileName, &fsStat)) {
				char buffer[100];
				unsigned long long size = fsStat.f_bavail * fsStat.f_bsize;
				snprintf(buffer, sizeof(buffer), "%llu", size);
				xmlTextWriterWriteElementString(writer, "d", PROPFIND_AVAILABLE_BYTES, buffer);
				if (properties->usedBytes) {
					size = (fsStat.f_blocks - fsStat.f_bfree) * fsStat.f_bsize;
					snprintf(buffer, sizeof(buffer), "%llu", size);
					xmlTextWriterWriteElementString(writer, "d", PROPFIND_USED_BYTES, buffer);
				}
			}
		}
		if (properties->usedBytes) {
			struct statvfs fsStat;
			if (!statvfs(fileName, &fsStat)) {
				char buffer[100];
				unsigned long long size = (fsStat.f_blocks - fsStat.f_bfree) * fsStat.f_bsize;
				snprintf(buffer, sizeof(buffer), "%llu", size);
				xmlTextWriterWriteElementString(writer, "d", PROPFIND_USED_BYTES, buffer);
			}
		}
		if (properties->windowsHidden) {
			xmlTextWriterWriteElementString(writer, "z", PROPFIND_WINDOWS_ATTRIBUTES,
					displayName[0] == '.' ? "00000012" : "00000010");
		}
	} else {
		if (properties->contentLength) {
			char buffer[100];
			snprintf(buffer, sizeof(buffer), "%lld", (long long) fileStat->st_size);
			xmlTextWriterWriteElementString(writer, "d", PROPFIND_CONTENT_LENGTH, buffer);
		}
		if (properties->contentType) {
			xmlTextWriterWriteElementString(writer, "d", PROPFIND_CONTENT_TYPE, findMimeType(fileName)->type);
		}
		if (properties->windowsHidden) {
			xmlTextWriterWriteElementString(writer, "z", PROPFIND_WINDOWS_ATTRIBUTES,
					displayName[0] == '.' ? "00000022" : "00000020");
		}

	}
	xmlTextWriterEndElement(writer);
	xmlTextWriterWriteElementString(writer, "d", "status", "HTTP/1.1 200 OK");
	xmlTextWriterEndElement(writer);
	xmlTextWriterEndElement(writer);

}

static int respondToPropFind(const char * file, PropertySet * properties, int depth) {
	struct stat fileStat;
	if (stat(file, &fileStat)) {
		int e = errno;
		switch (e) {
		case EACCES:
			stdLogError(e, "PROPFIND access denied %s %s", authenticatedUser, file);
			return respond(RAP_ACCESS_DENIED, -1);
		case ENOENT:
		default:
			stdLogError(e, "PROPFIND not found %s %s", authenticatedUser, file);
			return respond(RAP_NOT_FOUND, -1);
		}
	}

	int pipeEnds[2];
	if (pipe(pipeEnds)) {
		stdLogError(errno, "Could not create pipe to write content");
		return respond(RAP_INTERNAL_ERROR, -1);
	}

	size_t fileNameSize = strlen(file);
	size_t filePathSize = fileNameSize;
	char * filePath = normalizeDirName(file, &filePathSize, (fileStat.st_mode & S_IFMT) == S_IFDIR);

	const char * displayName = &file[fileNameSize - 2];
	while (displayName >= file && *displayName != '/') {
		displayName--;
	}
	displayName++;

	time_t fileTime;
	time(&fileTime);
	Message message = { .mID = RAP_MULTISTATUS, .fd = pipeEnds[PIPE_READ], .bufferCount = 2 };
	message.params[RAP_DATE_INDEX].iov_base = &fileTime;
	message.params[RAP_DATE_INDEX].iov_len = sizeof(fileTime);
	message.params[RAP_MIME_INDEX].iov_base = (void *) XML_MIME_TYPE.type;
	message.params[RAP_MIME_INDEX].iov_len = XML_MIME_TYPE.typeStringSize;
	message.params[RAP_LOCATION_INDEX].iov_base = filePath;
	message.params[RAP_LOCATION_INDEX].iov_len = filePathSize + 1;
	ssize_t messageResult = sendMessage(RAP_CONTROL_SOCKET, &message);
	if (messageResult <= 0) {
		freeSafe(filePath);
		close(pipeEnds[PIPE_WRITE]);
		return messageResult;
	}

	// We've set up the pipe and sent read end across so now write the result
	xmlTextWriterPtr writer = xmlNewFdTextWriter(pipeEnds[PIPE_WRITE]);
	DIR * dir;
	xmlTextWriterStartDocument(writer, "1.0", "utf-8", NULL);
	xmlTextWriterStartElementNS(writer, "d", "multistatus", WEBDAV_NAMESPACE);
	xmlTextWriterWriteAttribute(writer, "xmlns:z", MICROSOFT_NAMESPACE);
	writePropFindResponsePart(filePath, displayName, properties, &fileStat, writer);
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
					writePropFindResponsePart(childFileName, dp->d_name, properties, &fileStat, writer);
				}
			}
		}
		closedir(dir);
		freeSafe(childFileName);
	}
	xmlTextWriterEndElement(writer);
	xmlFreeTextWriter(writer);
	freeSafe(filePath);
	return messageResult;

}

static ssize_t propfind(Message * requestMessage) {
	if (!authenticated || requestMessage->bufferCount != 3) {
		if (!authenticated) {
			stdLogError(0, "Not authenticated RAP");
		} else {
			stdLogError(0, "Get request did not provide correct buffers: %d buffer(s)", requestMessage->bufferCount);
		}
		close(requestMessage->fd);
		return respond(RAP_INTERNAL_ERROR, -1);
	}

	char * depthString = messageParamToString(&requestMessage->params[RAP_DEPTH_INDEX]);
	char * file = messageParamToString(&requestMessage->params[RAP_FILE_INDEX]);

	PropertySet properties;
	if (requestMessage->fd == -1) {
		memset(&properties, 1, sizeof(properties));
	} else {
		int ret = respond(RAP_CONTINUE, -1);
		if (ret < 0) {
			return ret;
		}
		if (!parsePropFind(requestMessage->fd, &properties)) {
			return respond(RAP_BAD_CLIENT_REQUEST, -1);
		}
	}

	return respondToPropFind(file, &properties, (strcmp("0", depthString) ? 2 : 1));
}

//////////////////
// End PROPFIND //
//////////////////

///////////////
// PROPPATCH //
///////////////

static ssize_t proppatch(Message * requestMessage) {
	if (requestMessage->fd != -1) {
		respond(RAP_CONTINUE, -1);
		char buffer[BUFFER_SIZE];
		ssize_t bytesRead;
		while ((bytesRead = read(requestMessage->fd, buffer, sizeof(buffer))) > 0) {
			ssize_t __attribute__ ((unused)) ignored = write(STDERR_FILENO, buffer, bytesRead);
		}
		char c = '\n';
		ssize_t __attribute__ ((unused)) ignored = write(STDOUT_FILENO, &c, 1);
		close(requestMessage->fd);

	}
	return respond(RAP_SUCCESS, -1);
}

///////////////////
// End PROPPATCH //
///////////////////

/////////
// PUT //
/////////

static ssize_t writeFile(Message * requestMessage) {
	if (requestMessage->fd == -1) {
		stdLogError(0, "write file request sent without incoming data!");
		return respond(RAP_INTERNAL_ERROR, -1);
	}
	if (!authenticated) {
		stdLogError(0, "Not authenticated RAP");
		return respond(RAP_INTERNAL_ERROR, -1);
	}
	if (requestMessage->bufferCount != 2) {
		stdLogError(0, "Get request did not provide correct buffers: %d buffer(s)", requestMessage->bufferCount);
		return respond(RAP_INTERNAL_ERROR, -1);
	}

	char * file = messageParamToString(&requestMessage->params[RAP_FILE_INDEX]);
	// TODO change file mode
	int fd = open(file, O_WRONLY | O_CREAT, 0660);
	if (fd == -1) {
		int e = errno;
		switch (e) {
		case EACCES:
			stdLogError(e, "PUT access denied %s %s", authenticatedUser, file);
			return respond(RAP_ACCESS_DENIED, -1);
		case ENOENT:
		default:
			stdLogError(e, "PUT not found %s %s", authenticatedUser, file);
			return respond(RAP_CONFLICT, -1);
		}
	}
	int ret = respond(RAP_CONTINUE, -1);
	if (ret < 0) {
		return ret;
	}

	char buffer[BUFFER_SIZE];
	ssize_t bytesRead;

	while ((bytesRead = read(requestMessage->fd, buffer, sizeof(buffer))) > 0) {
		ssize_t bytesWritten = write(fd, buffer, bytesRead);
		if (bytesWritten < bytesRead) {
			stdLogError(errno, "Could wite data to file %s", file);
			close(fd);
			close(requestMessage->fd);
			return respond(RAP_INSUFFICIENT_STORAGE, -1);
		}
	}

	close(fd);
	close(requestMessage->fd);
	return respond(RAP_SUCCESS, -1);
}

/////////////
// End PUT //
/////////////

/////////
// GET //
/////////

static int compareDirent(const void * a, const void * b) {
	const struct dirent * lhs = *((const struct dirent **) a);
	const struct dirent * rhs = *((const struct dirent **) b);
	int result = strcoll(lhs->d_name, rhs->d_name);
	if (result != 0) {
		return result;
	}
	return strcmp(lhs->d_name, rhs->d_name);
}

static void listDir(const char * file, int dirFd, int writeFd) {
	DIR * dir = fdopendir(dirFd);
	xmlTextWriterPtr writer = xmlNewFdTextWriter(writeFd);

	size_t fileSize = strlen(file);
	char * filePath = normalizeDirName(file, &fileSize, 1);

	size_t entryCount = 0, allocatedEntries = 0;
	struct dirent ** directoryEntries = NULL;
	struct dirent * dp;
	while ((dp = readdir(dir)) != NULL) {
		int index = entryCount++;
		if (entryCount > allocatedEntries) {
			allocatedEntries += 200;
			directoryEntries = reallocSafe(directoryEntries, sizeof(struct dirent **) * allocatedEntries);
		}
		directoryEntries[index] = dp;
	}

	qsort(directoryEntries, entryCount, sizeof(*directoryEntries), &compareDirent);

	xmlTextWriterStartElement(writer, "html");
	xmlTextWriterStartElement(writer, "head");
	xmlTextWriterWriteElementString(writer, NULL, "title", filePath);
	xmlTextWriterEndElement(writer);
	xmlTextWriterStartElement(writer, "body");
	xmlTextWriterWriteElementString(writer, NULL, "h1", filePath);
	xmlTextWriterStartElement(writer, "table");
	xmlTextWriterWriteAttribute(writer, "cellpadding", "5");
	xmlTextWriterWriteAttribute(writer, "cellspacing", "5");
	xmlTextWriterWriteAttribute(writer, "border", "1");

	for (size_t i = 0; i < entryCount; i++) {
		dp = directoryEntries[i];
		if (dp->d_name[0] != '.') {
			xmlTextWriterStartElement(writer, "tr");
			xmlTextWriterWriteElementString(writer, NULL, "td", dp->d_type == DT_DIR ? "dir" : "file");
			xmlTextWriterStartElement(writer, "td");
			xmlTextWriterStartElement(writer, "a");
			xmlTextWriterStartAttribute(writer, "href");
			xmlTextWriterWriteURL(writer, filePath);
			xmlTextWriterWriteURL(writer, dp->d_name);
			if (dp->d_type == DT_DIR)
				xmlTextWriterWriteString(writer, "/");
			xmlTextWriterEndAttribute(writer);
			xmlTextWriterWriteString(writer, dp->d_name);
			if (dp->d_type == DT_DIR)
				xmlTextWriterWriteString(writer, "/");
			xmlTextWriterEndElement(writer);
			if (dp->d_type == DT_REG) {
				struct stat stat;
				fstatat(dirFd, dp->d_name, &stat, 0);
				char buffer[30];
				formatFileSize(buffer, sizeof(buffer), stat.st_size);
				xmlTextWriterWriteElementString(writer, NULL, "td", buffer);
			} else {
				xmlTextWriterWriteElementString(writer, NULL, "td", "-");
			}
			xmlTextWriterWriteElementString(writer, NULL, "td",
					dp->d_type == DT_DIR ? "-" : findMimeType(dp->d_name)->type);
			xmlTextWriterEndElement(writer);
			xmlTextWriterEndElement(writer);
		}
	}
	xmlTextWriterEndElement(writer);
	xmlTextWriterEndElement(writer);
	xmlTextWriterEndElement(writer);

	freeSafe(filePath);
	xmlFreeTextWriter(writer);
	closedir(dir);
	freeSafe(directoryEntries);
}

static ssize_t readFile(Message * requestMessage) {
	if (requestMessage->fd != -1) {
		stdLogError(0, "read file request sent incoming data!");
		close(requestMessage->fd);
	}
	if (!authenticated) {
		stdLogError(0, "Not authenticated RAP");
		return respond(RAP_INTERNAL_ERROR, -1);
	}
	if (requestMessage->bufferCount != 2) {
		stdLogError(0, "Get request did not provide correct buffers: %d buffer(s)", requestMessage->bufferCount);
		return respond(RAP_INTERNAL_ERROR, -1);
	}

	char * file = messageParamToString(&requestMessage->params[RAP_FILE_INDEX]);
	int fd = open(file, O_RDONLY);
	if (fd == -1) {
		int e = errno;
		switch (e) {
		case EACCES:
			stdLogError(e, "GET access denied %s %s %s", authenticatedUser, file);
			return respond(RAP_ACCESS_DENIED, -1);
		case ENOENT:
		default:
			stdLogError(e, "GET not found %s %s %s", authenticatedUser, file);
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

			Message message = { .mID = RAP_SUCCESS, .fd = pipeEnds[PIPE_READ], 3 };
			message.params[RAP_DATE_INDEX].iov_base = &fileTime;
			message.params[RAP_DATE_INDEX].iov_len = sizeof(fileTime);
			message.params[RAP_MIME_INDEX].iov_base = "text/html";
			message.params[RAP_MIME_INDEX].iov_len = sizeof("text/html");
			message.params[RAP_LOCATION_INDEX] = requestMessage->params[RAP_FILE_INDEX];
			ssize_t messageResult = sendMessage(RAP_CONTROL_SOCKET, &message);
			if (messageResult <= 0) {
				close(fd);
				close(pipeEnds[PIPE_WRITE]);
				return messageResult;
			}

			listDir(file, fd, pipeEnds[PIPE_WRITE]);
			return messageResult;
		} else {
			Message message = { .mID = RAP_SUCCESS, .fd = fd, .bufferCount = 3 };
			message.params[RAP_DATE_INDEX].iov_base = &statinfo.st_mtime;
			message.params[RAP_DATE_INDEX].iov_len = sizeof(statinfo.st_mtime);
			MimeType * mimeType = findMimeType(file);
			message.params[RAP_MIME_INDEX].iov_base = (char *) mimeType->type;
			message.params[RAP_MIME_INDEX].iov_len = mimeType->typeStringSize;
			message.params[RAP_LOCATION_INDEX] = requestMessage->params[RAP_FILE_INDEX];
			return sendMessage(RAP_CONTROL_SOCKET, &message);
		}
	}
}

/////////////
// End GET //
/////////////

//////////////////
// Authenticate //
//////////////////

static int pamConverse(int n, const struct pam_message **msg, struct pam_response **resp, char * password) {
	struct pam_response * response = mallocSafe(sizeof(struct pam_response));
	response->resp_retcode = 0;
	size_t passSize = strlen(password) + 1;
	response->resp = mallocSafe(passSize);
	memcpy(response->resp, password, passSize);
	*resp = response;
	return PAM_SUCCESS;
}

static void pamCleanup() {
	int pamResult = pam_close_session(pamh, 0);
	pam_end(pamh, pamResult);
}

static int pamAuthenticate(const char * user, const char * password, const char * hostname) {
	static struct pam_conv pamc = { .conv = (int (*)(int num_msg, const struct pam_message **msg,
			struct pam_response **resp, void *appdata_ptr)) &pamConverse };
	pamc.appdata_ptr = (void *) password;
	char ** envList;

	if (pam_start(pamService, user, &pamc, &pamh) != PAM_SUCCESS) {
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
			|| (envList = pam_getenvlist(pamh)) == NULL) {

		pamResult = pam_close_session(pamh, 0);
		pam_end(pamh, pamResult);

		return 0;
	}

	// Set up environment and switch user
	clearenv();
	for (char ** pam_env = envList; *pam_env != NULL; ++pam_env) {
		putenv(*pam_env);
		freeSafe(*pam_env);
	}
	freeSafe(envList);

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
	return 1;
}

static ssize_t authenticate(Message * message) {
	if (message->fd != -1) {
		stdLogError(0, "authenticate request send incoming data!");
		close(message->fd);
	}
	if (authenticated) {
		stdLogError(0, "Login for already logged in RAP");
		return respond(RAP_INTERNAL_ERROR, -1);
	}
	if (authenticated) {
		stdLogError(0, "Login provided %d buffer(s) instead of 3", message->bufferCount);
		return respond(RAP_INTERNAL_ERROR, -1);
	}

	char * user = messageParamToString(&message->params[RAP_USER_INDEX]);
	char * password = messageParamToString(&message->params[RAP_PASSWORD_INDEX]);
	char * rhost = messageParamToString(&message->params[RAP_RHOST_INDEX]);

	if (pamAuthenticate(user, password, rhost)) {
		//stdLog("Login accepted for %s", user);
		return respond(RAP_SUCCESS, -1);
	} else {
		return respond(RAP_AUTH_FAILLED, -1);
	}
}

//////////////////////
// End Authenticate //
//////////////////////

int main(int argCount, char * args[]) {
	setlocale(LC_ALL, "");
	ssize_t ioResult;
	Message message;
	char incomingBuffer[INCOMING_BUFFER_SIZE];
	if (argCount > 1) {
		pamService = args[1];
	} else {
		pamService = "webdav";
	}

	if (argCount > 2) {
		initializeMimeTypes(args[2]);
	} else {
		initializeMimeTypes("/etc/mime.types");
	}

	do {
		// Read a message
		ioResult = recvMessage(RAP_CONTROL_SOCKET, &message, incomingBuffer, INCOMING_BUFFER_SIZE);
		if (ioResult <= 0) {
			continue;
		}

		switch (message.mID) {
		case RAP_AUTHENTICATE:
			ioResult = authenticate(&message);
			break;
		case RAP_GET:
			ioResult = readFile(&message);
			break;
		case RAP_PUT:
			ioResult = writeFile(&message);
			break;
		case RAP_PROPFIND:
			ioResult = propfind(&message);
			break;
		case RAP_PROPPATCH:
			ioResult = proppatch(&message);
			break;
		default:
			stdLogError(0, "Invalid rap request id %d", message.mID);
			ioResult = respond(RAP_INTERNAL_ERROR, -1);
		}
		if (ioResult < 0) {
			ioResult = 0;
		}

	} while (ioResult);

	return ioResult < 0 ? -1 : 0;
}
