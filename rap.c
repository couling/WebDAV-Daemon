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

#define WEBDAV_NAMESPACE "DAV:"
#define EXTENSIONS_NAMESPACE "urn:couling-webdav:"
#define MICROSOFT_NAMESPACE "urn:schemas-microsoft-com:"

#define NEW_FILE_PERMISSIONS 0666
#define NEW_DIR_PREMISSIONS  0777

#define IS_DIR_CHILD(name) ((name)[0] != '.' || ((name)[1] != '\0' && ((name)[1] != '.' || (name)[2] != '\0')))

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

static MimeType UNKNOWN_MIME_TYPE = {
		.fileExtension = "",
		.type = "application/octet-stream",
		.typeStringSize = sizeof("application/octet-stream") };

static MimeType XML_MIME_TYPE = {
		.fileExtension = "",
		.type = "application/xml; charset=utf-8",
		.typeStringSize = sizeof("application/xml; charset=utf-8") };

static ssize_t respond(RapConstant result) {
	Message message = { .mID = result, .fd = -1, .paramCount = 0 };
	return sendMessage(RAP_CONTROL_SOCKET, &message);
}

static void normalizeDirName(char * buffer, const char * file, size_t * filePathSize, int isDir) {
	memcpy(buffer, file, *filePathSize + 1);
	if (isDir && file[*filePathSize - 1] != '/') {
		buffer[*filePathSize] = '/';
		buffer[*filePathSize + 1] = '\0';
		(*filePathSize)++;
	}
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

////////////////////
// Error Response //
////////////////////

static ssize_t writeErrorResponse(RapConstant responseCode, const char * textError, const char * error,
		const char * file) {
	int pipeEnds[2];
	if (pipe(pipeEnds)) {
		stdLogError(errno, "Could not create pipe to write content");
		return respond(RAP_RESPOND_INTERNAL_ERROR);
	}

	time_t fileTime;
	time(&fileTime);
	Message message = { .mID = responseCode, .fd = pipeEnds[PIPE_READ], .paramCount = 2 };
	message.params[RAP_PARAM_RESPONSE_DATE] = toMessageParam(fileTime);
	message.params[RAP_PARAM_RESPONSE_MIME] = makeMessageParam(XML_MIME_TYPE.type,
			XML_MIME_TYPE.typeStringSize);
	message.params[RAP_PARAM_RESPONSE_LOCATION] = stringToMessageParam(file);

	ssize_t messageResult = sendMessage(RAP_CONTROL_SOCKET, &message);
	if (messageResult <= 0) {
		close(pipeEnds[PIPE_WRITE]);
		return messageResult;
	}

	// We've set up the pipe and sent read end across so now write the result
	xmlTextWriterPtr writer = xmlNewFdTextWriter(pipeEnds[PIPE_WRITE]);
	xmlTextWriterStartDocument(writer, "1.0", "utf-8", NULL);
	xmlTextWriterStartElementNS(writer, "d", "error", WEBDAV_NAMESPACE);
	xmlTextWriterWriteAttributeNS(writer, "xmlns", "x", NULL, EXTENSIONS_NAMESPACE);
	if (error) {
		xmlTextWriterStartElementNS(writer, "d", error, NULL);
		xmlTextWriterStartElementNS(writer, "d", "href", NULL);
		xmlTextWriterWriteURL(writer, file);
		xmlTextWriterEndElement(writer);
		xmlTextWriterEndElement(writer);
	}
	if (textError) {
		xmlTextWriterStartElementNS(writer, "x", "text-error", NULL);
		xmlTextWriterStartElementNS(writer, "x", "href", NULL);
		xmlTextWriterWriteURL(writer, file);
		xmlTextWriterWriteElementString(writer, "x", "text", textError);
		xmlTextWriterEndElement(writer);
		xmlTextWriterEndElement(writer);
	}

	xmlTextWriterEndElement(writer);
	xmlFreeTextWriter(writer);
	return messageResult;
}

////////////////////////
// End Error Response //
////////////////////////

//////////
// LOCK //
//////////

typedef struct LockRequest {
	int isNewLock;
	LockType type;
} LockRequest;

static void parseLockRequest(int fd, LockRequest * lockRequest) {
	memset(lockRequest, 0, sizeof(LockRequest));
	if (fd == -1) return;
	xmlTextReaderPtr reader = xmlReaderForFd(fd, NULL, NULL, XML_PARSE_NOENT);
	xmlReaderSuppressErrors(reader);

	if (!reader || !stepInto(reader) || !elementMatches(reader, WEBDAV_NAMESPACE, "lockinfo")) {
		if (reader) xmlFreeTextReader(reader);
		close(fd);
		return;
	}

	lockRequest->isNewLock = 1;
	int readResult = stepInto(reader);
	while (readResult && xmlTextReaderDepth(reader) == 1) {
		if (isNamespaceElement(reader, WEBDAV_NAMESPACE)) {
			const char * nodeName = xmlTextReaderConstLocalName(reader);
			if (!strcmp(nodeName, "lockscope")) {
				readResult = stepInto(reader);
				while (readResult && xmlTextReaderDepth(reader) == 2) {
					if (isNamespaceElement(reader, WEBDAV_NAMESPACE)) {
						nodeName = xmlTextReaderConstLocalName(reader);
						if (!strcmp(nodeName, "shared")) {
							if (lockRequest->type != LOCK_TYPE_EXCLUSIVE) {
								lockRequest->type = LOCK_TYPE_SHARED;
							}
						} else if (!strcmp(nodeName, "exclusive")) {
							lockRequest->type = LOCK_TYPE_EXCLUSIVE;
						}
					}
					readResult = stepOver(reader);
				}
			} else if (!strcmp(nodeName, "locktype")) {
				readResult = stepInto(reader);
				while (readResult && xmlTextReaderDepth(reader) == 2) {
					if (isNamespaceElement(reader, WEBDAV_NAMESPACE)) {
						nodeName = xmlTextReaderConstLocalName(reader);
						if (!strcmp(nodeName, "read") && lockRequest->type != LOCK_TYPE_EXCLUSIVE) {
							lockRequest->type = LOCK_TYPE_SHARED;
						} else if (!strcmp(nodeName, "write")) {
							lockRequest->type = LOCK_TYPE_EXCLUSIVE;
						}
					}
					readResult = stepOver(reader);
				}
			} else {
				readResult = stepOver(reader);
			}
		}
	}

	// finish up
	while (readResult) {
		readResult = stepOver(reader);
	}

	xmlFreeTextReader(reader);
	close(fd);
}

static ssize_t writeLockResponse(const char * fileName, LockRequest * request, const char * lockToken,
		time_t timeout) {
	int pipeEnds[2];
	if (pipe(pipeEnds)) {
		stdLogError(errno, "Could not create pipe to write content");
		return respond(RAP_RESPOND_INTERNAL_ERROR);
	}

	time_t fileTime;
	time(&fileTime);
	Message message = { .mID = RAP_RESPOND_OK, .fd = pipeEnds[PIPE_READ], .paramCount = 2 };
	message.params[RAP_PARAM_RESPONSE_DATE] = toMessageParam(fileTime);
	message.params[RAP_PARAM_RESPONSE_MIME] = makeMessageParam(XML_MIME_TYPE.type,
			XML_MIME_TYPE.typeStringSize);
	message.params[RAP_PARAM_RESPONSE_LOCATION] = stringToMessageParam(fileName);

	ssize_t messageResult = sendMessage(RAP_CONTROL_SOCKET, &message);
	if (messageResult <= 0) {
		close(pipeEnds[PIPE_WRITE]);
		return messageResult;
	}

	// We've set up the pipe and sent read end across so now write the result
	xmlTextWriterPtr writer = xmlNewFdTextWriter(pipeEnds[PIPE_WRITE]);
	xmlTextWriterStartDocument(writer, "1.0", "utf-8", NULL);
	xmlTextWriterStartElementNS(writer, "d", "prop", WEBDAV_NAMESPACE);
	xmlTextWriterStartElementNS(writer, "d", "lockdiscovery", NULL);
	xmlTextWriterStartElementNS(writer, "d", "activelock", NULL);
	// <d:locktype><d:write></d:locktype>
	xmlTextWriterStartElementNS(writer, "d", "locktype", NULL);
	xmlTextWriterWriteElementString(writer, "d", (request->type == LOCK_TYPE_EXCLUSIVE ? "write" : "read"),
	NULL);
	xmlTextWriterEndElement(writer);
	// <d:lockscope><d:exclusive></d:lockscope>
	xmlTextWriterStartElementNS(writer, "d", "lockscope", NULL);
	xmlTextWriterWriteElementString(writer, "d",
			(request->type == LOCK_TYPE_EXCLUSIVE ? "exclusive" : "shared"), NULL);
	xmlTextWriterEndElement(writer);
	// <d:depth>Infinity</d:depth>
	xmlTextWriterWriteElementString(writer, "d", "depth", "infinity");
	// <d:owner>Bob</d:owner>
	xmlTextWriterWriteElementString(writer, "d", "owner", authenticatedUser);
	// <d:lockroot><d:href>/foo/bar</d:lockroot></d:href>
	xmlTextWriterStartElementNS(writer, "d", "lockroot", NULL);
	xmlTextWriterStartElementNS(writer, "d", "href", NULL);
	xmlTextWriterWriteURL(writer, fileName);
	xmlTextWriterEndElement(writer);
	xmlTextWriterEndElement(writer);
	// <d:locktoken><d:href>urn:uuid:e71d4fae-5dec-22d6-fea5-00a0c91e6be4</d:href></d:locktoken>
	xmlTextWriterStartElementNS(writer, "d", "locktoken", NULL);
	xmlTextWriterStartElementNS(writer, "d", "href", NULL);
	xmlTextWriterWriteFormatString(writer, LOCK_TOKEN_URN_PREFIX "%s", lockToken);
	xmlTextWriterEndElement(writer);
	xmlTextWriterEndElement(writer);

	xmlTextWriterStartElement(writer, "d:timeout");
	xmlTextWriterWriteFormatString(writer, "Second-%d", (int) timeout);
	xmlTextWriterEndElement(writer);

	xmlTextWriterEndElement(writer);
	xmlTextWriterEndElement(writer);
	xmlTextWriterEndElement(writer);

	xmlFreeTextWriter(writer);
	return messageResult;
}

static ssize_t lockFile(Message * message) {
	const char * file = messageParamToString(&message->params[RAP_PARAM_REQUEST_FILE]);
	LockProvisions providedLock = messageParamTo(LockProvisions, message->params[RAP_PARAM_REQUEST_LOCK]);
	//const char * depth = messageParamToString(&message->params[RAP_PARAM_REQUEST_DEPTH]);
	//if (depth == NULL) depth = "infinity";
	respond(RAP_RESPOND_CONTINUE);

	LockRequest lockRequest;
	parseLockRequest(message->fd, &lockRequest);

	Message interimMessage;
	char incomingBuffer[INCOMING_BUFFER_SIZE];
	ssize_t ioResponse;

	if (lockRequest.isNewLock) {
		if (providedLock.source) {
			// Lock token must be empty but isn't
			stdLogError(0, "lock token \"If\" header provided for new lock");
			return writeErrorResponse(RAP_RESPOND_BAD_CLIENT_REQUEST,
					"lock token \"If\" header provided for new lock", "lock-token-submitted", file);
		}

		int openFlags = (lockRequest.type == LOCK_TYPE_EXCLUSIVE ? O_WRONLY | O_CREAT : O_RDONLY);
		interimMessage.fd = open(file, openFlags, NEW_FILE_PERMISSIONS);
		if (interimMessage.fd == -1) {
			int e = errno;
			stdLogError(e, "Could not open file for lock %s", file);
			switch (e) {
			case EACCES:
				return writeErrorResponse(RAP_RESPOND_ACCESS_DENIED, strerror(e), NULL, file);
			case ENOENT:
				return writeErrorResponse(RAP_RESPOND_NOT_FOUND, strerror(e), NULL, file);
			default:
				return writeErrorResponse(RAP_RESPOND_NOT_FOUND, strerror(e), NULL, file);
			}
		}

		struct stat s;
		fstat(interimMessage.fd, &s);
		if ((s.st_mode & S_IFMT) != S_IFREG) {
			stdLogError(0, "Refusing to lock non-regular file %s", file);
			close(interimMessage.fd);
			return writeErrorResponse(RAP_RESPOND_CONFLICT, "Refusing to non-regular file", NULL, file);
		}

		if (flock(interimMessage.fd, lockRequest.type | LOCK_NB) == -1) {
			int e = errno;
			stdLogError(e, "Could not lock file %s", file);
			close(interimMessage.fd);
			return writeErrorResponse(RAP_RESPOND_LOCKED, strerror(e), "no-conflicting-lock", file);
		}

		interimMessage.mID = RAP_INTERIM_RESPOND_LOCK;
		interimMessage.paramCount = 2;
		interimMessage.params[RAP_PARAM_LOCK_LOCATION] = message->params[RAP_PARAM_REQUEST_FILE];
		interimMessage.params[RAP_PARAM_LOCK_TYPE] = toMessageParam(lockRequest.type);
	} else {
		if (!providedLock.source) {
			// Lock token must not be empty
			return writeErrorResponse(RAP_RESPOND_BAD_CLIENT_REQUEST,
					"No lock tokent submitted for refresh request", "lock-token-submitted", file);
		}
		interimMessage.mID = RAP_INTERIM_RESPOND_RELOCK;
		interimMessage.fd = -1;
		interimMessage.paramCount = 1;
		interimMessage.params[RAP_PARAM_LOCK_LOCATION] = message->params[RAP_PARAM_REQUEST_FILE];
	}

	ioResponse = sendRecvMessage(RAP_CONTROL_SOCKET, &interimMessage, incomingBuffer, INCOMING_BUFFER_SIZE);
	if (ioResponse <= 0) return ioResponse;

	if (interimMessage.mID == RAP_COMPLETE_REQUEST_LOCK) {
		const char * lockToken = messageParamToString(&interimMessage.params[RAP_PARAM_LOCK_TOKEN]);
		time_t timeout = messageParamTo(time_t, interimMessage.params[RAP_PARAM_LOCK_TIMEOUT]);
		return writeLockResponse(file, &lockRequest, lockToken, timeout);
	} else {
		const char * reason = messageParamToString(&interimMessage.params[RAP_PARAM_ERROR_REASON]);
		const char * davReason = messageParamToString(&interimMessage.params[RAP_PARAM_ERROR_DAV_REASON]);
		//const char * errorNamespace = messageParamToString(&interimMessage.params[RAP_PARAM_ERROR_NAMESPACE]);

		return writeErrorResponse(interimMessage.mID, reason, davReason, file);
	}

}

//////////////
// End Lock //
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
		if (reader) xmlFreeTextReader(reader);
		close(fd);
		return 0;
	}

	if (xmlTextReaderNodeType(reader) == XML_READER_TYPE_NONE) {
		// No body has been sent
		// so assume the client is asking for everything.
		memset(properties, 1, sizeof(*properties));
		xmlFreeTextReader(reader);
		close(fd);
		return 1;
	} else {
		memset(properties, 0, sizeof(PropertySet));
	}

	if (!elementMatches(reader, WEBDAV_NAMESPACE, "propfind")) {
		stdLogError(0, "Request body was not a propfind document");
		xmlFreeTextReader(reader);
		close(fd);
		return 0;
	}

	readResult = stepInto(reader);
	while (readResult && xmlTextReaderDepth(reader) > 0 && !elementMatches(reader, WEBDAV_NAMESPACE, "prop")) {
		stepOver(reader);
	}

	if (!readResult) {
		xmlFreeTextReader(reader);
		close(fd);
		return 0;
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
		readResult = stepOver(reader);
	}

	readResult = 1;

	// finish up
	while (stepOver(reader))
		// consume the rest of the input
		;

	xmlFreeTextReader(reader);
	close(fd);
	return readResult;
}

static void writePropFindResponsePart(const char * fileName, const char * displayName,
		PropertySet * properties, struct stat * fileStat, xmlTextWriterPtr writer) {

	xmlTextWriterStartElementNS(writer, "d", "response", NULL);
	xmlTextWriterStartElementNS(writer, "d", "href", NULL);
	xmlTextWriterWriteURL(writer, fileName);
	xmlTextWriterEndElement(writer);
	xmlTextWriterStartElementNS(writer, "d", "propstat", NULL);
	xmlTextWriterStartElementNS(writer, "d", "prop", NULL);

	if (properties->etag) {
		char buffer[200];
		snprintf(buffer, sizeof(buffer), "%lld-%lld", (long long) fileStat->st_size,
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
		struct statvfs fsStat;
		if ((properties->availableBytes || properties->usedBytes) && statvfs(fileName, &fsStat) != -1) {
			if (properties->availableBytes) {
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
			if (properties->usedBytes) {
				char buffer[100];
				unsigned long long size = (fsStat.f_blocks - fsStat.f_bfree) * fsStat.f_bsize;
				snprintf(buffer, sizeof(buffer), "%llu", size);
				xmlTextWriterWriteElementString(writer, "d", PROPFIND_USED_BYTES, buffer);
			}
			// When listing directories we only list this FS space in the directory not its children.
			// It's not technically standards compliant but is is not likely to cause a problem in practice.
			properties->availableBytes = 0;
			properties->usedBytes = 0;
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

static int respondToPropFind(const char * file, LockType lockProvided, PropertySet * properties, int depth) {
	size_t fileNameSize = strlen(file);
	size_t filePathSize = fileNameSize;
	if (fileNameSize > MAX_VARABLY_DEFINED_ARRAY) {
		stdLogError(0, "URI was too large to process %zd", fileNameSize);
		return writeErrorResponse(RAP_RESPOND_URI_TOO_LARGE, "URI was too large to process", NULL, file);
	}

	struct stat fileStat;
	int fd = open(file, O_RDONLY);
	if (fd == -1 || fstat(fd, &fileStat) == -1
			|| (lockProvided == LOCK_TYPE_NONE && flock(fd, LOCK_TYPE_SHARED) == -1)) {
		if (fd != -1) close(fd);
		int e = errno;
		switch (e) {
		case EACCES:
			stdLogError(e, "PROPFIND access denied %s %s", authenticatedUser, file);
			return writeErrorResponse(RAP_RESPOND_ACCESS_DENIED, strerror(e), NULL, file);
		case EWOULDBLOCK:
			stdLogError(e, "PROPFIND file locked %s %s", authenticatedUser, file);
			return writeErrorResponse(RAP_RESPOND_LOCKED, strerror(e), NULL, file);
		case ENOENT:
		default:
			stdLogError(e, "PROPFIND not found %s %s", authenticatedUser, file);
			return writeErrorResponse(RAP_RESPOND_NOT_FOUND, strerror(e), NULL, file);
		}
	}

	char filePath[fileNameSize];
	normalizeDirName(filePath, file, &filePathSize, (fileStat.st_mode & S_IFMT) == S_IFDIR);

	int pipeEnds[2];
	if (pipe(pipeEnds)) {
		close(fd);
		stdLogError(errno, "Could not create pipe to write content");
		return respond(RAP_RESPOND_INTERNAL_ERROR);
	}

	const char * displayName = &file[fileNameSize - 2];
	while (displayName >= file && *displayName != '/') {
		displayName--;
	}
	displayName++;

	time_t fileTime;
	time(&fileTime);
	Message message = { .mID = RAP_RESPOND_MULTISTATUS, .fd = pipeEnds[PIPE_READ], .paramCount = 2 };
	message.params[RAP_PARAM_RESPONSE_DATE] = toMessageParam(fileTime);
	message.params[RAP_PARAM_RESPONSE_MIME] = makeMessageParam(XML_MIME_TYPE.type,
			XML_MIME_TYPE.typeStringSize);
	message.params[RAP_PARAM_RESPONSE_LOCATION] = makeMessageParam(filePath, filePathSize + 1);
	ssize_t messageResult = sendMessage(RAP_CONTROL_SOCKET, &message);
	if (messageResult <= 0) {
		freeSafe(filePath);
		close(pipeEnds[PIPE_WRITE]);
		close(fd);
		return messageResult;
	}

	// We've set up the pipe and sent read end across so now write the result
	xmlTextWriterPtr writer = xmlNewFdTextWriter(pipeEnds[PIPE_WRITE]);
	DIR * dir;
	xmlTextWriterStartDocument(writer, "1.0", "utf-8", NULL);
	xmlTextWriterStartElementNS(writer, "d", "multistatus", WEBDAV_NAMESPACE);
	xmlTextWriterWriteAttribute(writer, "xmlns:z", MICROSOFT_NAMESPACE);
	writePropFindResponsePart(filePath, displayName, properties, &fileStat, writer);
	if (depth > 1 && (fileStat.st_mode & S_IFMT) == S_IFDIR && (dir = fdopendir(fd))) {
		struct dirent * dp;
		char * childFileName = mallocSafe(filePathSize + 257);
		size_t maxSize = 255;
		memcpy(childFileName, filePath, filePathSize);
		while ((dp = readdir(dir)) != NULL) {
			if (IS_DIR_CHILD(dp->d_name)) {
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
	} else {
		close(fd);
	}
	xmlTextWriterEndElement(writer);
	xmlFreeTextWriter(writer);
	return messageResult;

}

static ssize_t propfind(Message * requestMessage) {
	if (requestMessage->paramCount != 3) {
		stdLogError(0, "PROPFIND request did not provide correct buffers: %d buffer(s)",
				requestMessage->paramCount);
		close(requestMessage->fd);
		return respond(RAP_RESPOND_INTERNAL_ERROR);
	}

	char * file = messageParamToString(&requestMessage->params[RAP_PARAM_REQUEST_FILE]);
	char * depthString = messageParamToString(&requestMessage->params[RAP_PARAM_REQUEST_DEPTH]);
	LockProvisions lockProvisions = messageParamTo(LockProvisions,
			requestMessage->params[RAP_PARAM_REQUEST_LOCK]);
	if (!depthString) depthString = "1";

	PropertySet properties;
	if (requestMessage->fd == -1) {
		memset(&properties, 1, sizeof(properties));
	} else {
		int ret = respond(RAP_RESPOND_CONTINUE);
		if (ret < 0) {
			return ret;
		}
		if (!parsePropFind(requestMessage->fd, &properties)) {
			return respond(RAP_RESPOND_BAD_CLIENT_REQUEST);
		}
	}

	return respondToPropFind(file, lockProvisions.source, &properties, (strcmp("0", depthString) ? 2 : 1));
}

//////////////////
// End PROPFIND //
//////////////////

///////////////
// PROPPATCH //
///////////////

static ssize_t proppatch(Message * requestMessage) {
	if (requestMessage->fd != -1) {
		respond(RAP_RESPOND_CONTINUE);
		char buffer[BUFFER_SIZE];
		ssize_t bytesRead;
		while ((bytesRead = read(requestMessage->fd, buffer, sizeof(buffer))) > 0) {
			//ssize_t __attribute__ ((unused)) ignored = write(STDERR_FILENO, buffer, bytesRead);
		}

		//char c = '\n';
		//ssize_t __attribute__ ((unused)) ignored = write(STDOUT_FILENO, &c, 1);
		close(requestMessage->fd);
		PropertySet p;
		memset(&p, 1, sizeof(p));
		const char * file = messageParamToString(&requestMessage->params[RAP_PARAM_REQUEST_FILE]);
		return respondToPropFind(file, LOCK_TYPE_SHARED, &p, 1);

	} else {
		return respond(RAP_RESPOND_BAD_CLIENT_REQUEST);
	}
}

///////////////////
// End PROPPATCH //
///////////////////

///////////
// MKCOL //
///////////

static ssize_t mkcol(Message * requestMessage) {
	if (requestMessage->fd != -1) {
		// stdLogError(0, "MKCOL request sent incoming data!");
		close(requestMessage->fd);
	}

	const char * fileName = messageParamToString(&requestMessage->params[RAP_PARAM_REQUEST_FILE]);

	if (mkdir(fileName, NEW_DIR_PREMISSIONS) == -1) {
		int e = errno;
		stdLogError(e, "MKCOL Can not create directory %s", fileName);
		switch (e) {
		case EACCES:
			return writeErrorResponse(RAP_RESPOND_ACCESS_DENIED, strerror(e), NULL, fileName);
		case ENOSPC:
		case EDQUOT:
			return writeErrorResponse(RAP_RESPOND_INSUFFICIENT_STORAGE, strerror(e), NULL, fileName);
		case ENOENT:
		case EPERM:
		case EEXIST:
		case ENOTDIR:
		default:
			return writeErrorResponse(RAP_RESPOND_CONFLICT, strerror(e), NULL, fileName);
		}
	}
	return respond(RAP_RESPOND_CREATED);
}

///////////////
// End MKCOL //
///////////////

//////////
// COPY //
//////////

typedef struct FileCopyData {
	struct FileCopyData * next;
	const char * source;
	const char * target;
	size_t sourceNameLength;
	size_t targetNameLength;
	int type;
} FileCopyData;

static ssize_t copyErrorCleanup(FileCopyData * files, const char * action, const char * source,
		const char * target) {
	int e = errno;
	while (files) {
		if (files->type == S_IFDIR) rmdir(files->target);
		else unlink(files->target);
		FileCopyData * next = files->next;
		freeSafe(files);
		files = next;
	}

	stdLogError(e, "Could not %s file %s to %s", action, source, target);
	switch (e) {
	case EPERM:
	case EACCES:
		return writeErrorResponse(RAP_RESPOND_ACCESS_DENIED, strerror(e), NULL, source);
	case ENOSPC:
	case EDQUOT:
		return writeErrorResponse(RAP_RESPOND_INSUFFICIENT_STORAGE, strerror(e), NULL, source);
	case ENOENT:
	case ENOTDIR:
		return writeErrorResponse(RAP_RESPOND_NOT_FOUND, strerror(e), NULL, source);
	default:
		return writeErrorResponse(RAP_RESPOND_CONFLICT, strerror(e), NULL, source);

	}
}

// Copies the head of the copied list and pushes more onto this is a direcory.
// If the copy fails the item is popped of the head of the list
// If the copy succeeds and is a file then the list is unchanged except that ->type will be set.
// If the copy succeeds and is a directory then copied child members are added to the head.
static int copyFileRecursive(FileCopyData ** copied) {
// We are given the file to copy at the head of the "copied" list.
	FileCopyData * toCopy = *copied;
	struct stat fileStat;
	if (lstat(toCopy->source, &fileStat) == -1) goto error_exit;
	toCopy->type = fileStat.st_mode & S_IFMT;
	int mode = fileStat.st_mode & 0777;

	switch (toCopy->type) {
	case S_IFREG: {
		int oldFd = open(toCopy->source, O_RDONLY);
		if (oldFd == -1) goto error_exit;
		int newFd = open(toCopy->target, O_WRONLY | O_CREAT | O_EXCL, 0600);
		if (newFd == -1) {
			close(oldFd);
			goto error_exit;
		}
		char readBuffer[BUFFER_SIZE];
		ssize_t bytesRead = 0;
		ssize_t bytesWritten = 0;
		while ((bytesRead == bytesWritten) && ((bytesRead = read(oldFd, readBuffer, BUFFER_SIZE)) > 0)) {
			bytesWritten = write(newFd, readBuffer, bytesRead);
		}
		close(oldFd);
		close(newFd);
		if (bytesRead != 0) return 0;
		chmod(toCopy->target, mode);
		break;
	}

	case S_IFDIR: {
		if (mkdir(toCopy->target, 0700) == -1) {
			goto error_exit;
		} else {
			DIR * dir = opendir(toCopy->source);
			if (!dir) return 0;
			for (struct dirent * entry = readdir(dir); entry; entry = readdir(dir)) {
				if (!IS_DIR_CHILD(entry->d_name)) continue;

				size_t childNameLength = strlen(entry->d_name);
				FileCopyData * childToCopy = mallocSafe(
						sizeof(FileCopyData) + toCopy->sourceNameLength + childNameLength
								+ toCopy->targetNameLength + childNameLength + 2);

				// store the source right after the structure
				size_t size = toCopy->sourceNameLength + childNameLength + 1;
				char * ptr = (char *) (childToCopy + 1);
				memcpy(ptr, toCopy->source, toCopy->sourceNameLength);
				ptr[toCopy->sourceNameLength - 1] = '/';
				memcpy(ptr + toCopy->sourceNameLength, entry->d_name, childNameLength + 1);
				childToCopy->source = ptr;
				childToCopy->sourceNameLength = size;

				size = toCopy->targetNameLength + childNameLength + 1;
				ptr += childToCopy->sourceNameLength;
				memcpy(ptr, toCopy->target, toCopy->targetNameLength);
				ptr[toCopy->targetNameLength - 1] = '/';
				memcpy(ptr + toCopy->targetNameLength, entry->d_name, childNameLength + 1);
				childToCopy->target = ptr;
				childToCopy->targetNameLength = size;

				childToCopy->next = *copied;
				*copied = childToCopy;

				if (!copyFileRecursive(copied)) {
					closedir(dir);
					return 0;
				}
			}
			closedir(dir);
			chmod(toCopy->target, mode);
			break;
		}
	}

	case S_IFLNK: {
		char linkTarget[4096];
		if (readlink(toCopy->source, linkTarget, sizeof(linkTarget)) == -1
				|| symlink(toCopy->target, linkTarget) == -1) {
			goto error_exit;
		}
		break;
	}

	case S_IFIFO: {
		if (mkfifo(toCopy->target, 0600) == -1) {
			goto error_exit;
		}
		chmod(toCopy->target, mode);
		break;
	}

		// TODO other file types
	case S_IFBLK:
	case S_IFCHR:
	case S_IFSOCK:
	default:
		errno = ENOTSUP;
		goto error_exit;
	}


	lchown(toCopy->target, fileStat.st_uid, fileStat.st_gid);
	return 1;

	error_exit: *copied = toCopy;
	freeSafe(toCopy);
	return 0;
}

static ssize_t copyFile(Message * requestMessage) {
	if (requestMessage->fd != -1) {
		// stdLogError(0, "MKCOL request sent incoming data!");
		close(requestMessage->fd);
	}

	const char * source = messageParamToString(&requestMessage->params[RAP_PARAM_REQUEST_FILE]);
	const char * target = messageParamToString(&requestMessage->params[RAP_PARAM_REQUEST_TARGET]);

	if (!target) {
		return writeErrorResponse(RAP_RESPOND_BAD_CLIENT_REQUEST, "No target header specified", NULL, source);
	}

	FileCopyData * copied = mallocSafe(sizeof(FileCopyData));
	copied->source = source;
	copied->target = target;
	copied->sourceNameLength = messageParamSize(requestMessage->params[RAP_PARAM_REQUEST_FILE]);
	copied->targetNameLength = messageParamSize(requestMessage->params[RAP_PARAM_REQUEST_TARGET]);
	copied->next = NULL;
	if (copyFileRecursive(&copied)) {
		while (copied) {
			FileCopyData * next = copied->next;
			freeSafe(copied);
			copied = next;
		}
		return respond(RAP_RESPOND_CREATED);
	} else {
		return copyErrorCleanup(copied, "copy", source, target);
	}

}

//////////////
// End COPY //
//////////////

//////////
// MOVE //
//////////

static ssize_t moveFile(Message * requestMessage) {
	if (requestMessage->fd != -1) {
		// stdLogError(0, "MKCOL request sent incoming data!");
		close(requestMessage->fd);
	}

	const char * sourceFile = messageParamToString(&requestMessage->params[RAP_PARAM_REQUEST_FILE]);
	const char * targetFile = messageParamToString(&requestMessage->params[RAP_PARAM_REQUEST_TARGET]);
	if (!targetFile) {
		stdLogError(0, "target not specified in MOVE request");
		return writeErrorResponse(RAP_RESPOND_BAD_CLIENT_REQUEST, "Target not specified", NULL, sourceFile);
	}

	FileCopyData * copiedFiles = NULL;
	if (rename(sourceFile, targetFile) == -1) {
		if (errno == EXDEV) {
			FileCopyData * copiedFiles = mallocSafe(sizeof(FileCopyData));
			copiedFiles->source = sourceFile;
			copiedFiles->target = targetFile;
			copiedFiles->sourceNameLength = messageParamSize(requestMessage->params[RAP_PARAM_REQUEST_FILE]);
			copiedFiles->targetNameLength = messageParamSize(
					requestMessage->params[RAP_PARAM_REQUEST_TARGET]);
			copiedFiles->next = NULL;
			if (!copyFileRecursive(&copiedFiles)) {
				return copyErrorCleanup(copiedFiles, "move", sourceFile, targetFile);
			}
			while (copiedFiles) {
				if (copiedFiles->type == S_IFDIR) rmdir(copiedFiles->source);
				else unlink(copiedFiles->source);
				FileCopyData * next = copiedFiles->next;
				freeSafe(copiedFiles);
				copiedFiles = next;
			}
		} else {
			return copyErrorCleanup(copiedFiles, "move", sourceFile, targetFile);
		}
	}

	return respond(RAP_RESPOND_OK_NO_CONTENT);

}

//////////////
// End MOVE //
//////////////

////////////
// DELETE //
////////////

static ssize_t deleteFileRecursive(int fd, const char * file) {
	DIR * dir = fdopendir(fd);
	struct dirent * dp;
	while ((dp = readdir(dir)) != NULL) {
		if (IS_DIR_CHILD(dp->d_name)) {
			int childFd = openat(fd, dp->d_name, O_RDONLY);
			if (childFd == -1) goto respond_error;
			struct stat fileStat;
			fstat(childFd, &fileStat);
			// TODO lock
			if ((fileStat.st_mode & S_IFMT) == S_IFDIR) {
				deleteFileRecursive(childFd, file);
			} else {
				close(childFd);
			}
			if (!unlinkat(fd, dp->d_name, AT_REMOVEDIR)) goto respond_error;
		}
	}
	closedir(dir);

	return 0;

	respond_error: {
		int e = errno;
		closedir(dir);
		stdLogError(e, "Could not delete file %s", file);
		if (fd != -1) close(fd);
		switch (e) {
		case EACCES:
		case EPERM:
			return writeErrorResponse(RAP_RESPOND_ACCESS_DENIED, strerror(e), NULL, file);
		case ENOTDIR:
		case ENOENT:
			return writeErrorResponse(RAP_RESPOND_NOT_FOUND, strerror(e), NULL, file);
		default:
			return writeErrorResponse(RAP_RESPOND_INTERNAL_ERROR, strerror(e), NULL, file);
		}
	}
}

static ssize_t deleteFile(Message * requestMessage) {
	if (requestMessage->fd != -1) {
		// stdLogError(0, "MKCOL request sent incoming data!");
		close(requestMessage->fd);
	}

	const char * file = messageParamToString(&requestMessage->params[RAP_PARAM_REQUEST_FILE]);

	int fd = open(file, O_RDONLY);
	if (fd == -1) goto respond_error;

	struct stat fileStat;
	if (fstat(fd, &fileStat) == -1) goto respond_error;
	if ((fileStat.st_mode & S_IFMT) == S_IFDIR) {
		ssize_t result = deleteFileRecursive(fd, file);
		fd = -1;
		if (result != 0 || rmdir(file) == -1) goto respond_error;
	} else {
		// Check if we have the apropriate lock on this file.
		LockProvisions locks = messageParamTo(LockProvisions, requestMessage->params[RAP_PARAM_REQUEST_LOCK]);
		if (locks.source != LOCK_TYPE_EXCLUSIVE) {
			// We have no lock but we need one so acquire it now.
			if (flock(fd, LOCK_TYPE_EXCLUSIVE | LOCK_NB) == -1) {
				close(fd);
				int e = errno;
				stdLogError(e, "Could not delete locked file %s", file);
				return writeErrorResponse(RAP_RESPOND_LOCKED, strerror(e), "lock-token-submitted", file);
			}
		}
		if (unlink(file) == -1) goto respond_error;
		close(fd);
	}

	return respond(RAP_RESPOND_OK_NO_CONTENT);

	respond_error: {
		int e = errno;
		stdLogError(e, "Could not delete file %s", file);
		if (fd != -1) close(fd);
		switch (e) {
		case EACCES:
		case EPERM:
			return writeErrorResponse(RAP_RESPOND_ACCESS_DENIED, strerror(e), NULL, file);
		case ENOTDIR:
		case ENOENT:
			return writeErrorResponse(RAP_RESPOND_NOT_FOUND, strerror(e), NULL, file);
		default:
			return writeErrorResponse(RAP_RESPOND_INTERNAL_ERROR, strerror(e), NULL, file);
		}
	}
}

////////////////
// End DELETE //
////////////////

/////////
// PUT //
/////////

static ssize_t writeFile(Message * requestMessage) {
	if (requestMessage->fd == -1) {
		stdLogError(0, "PUT request sent without incoming data!");
		return respond(RAP_RESPOND_INTERNAL_ERROR);
	}

	char * file = messageParamToString(&requestMessage->params[RAP_PARAM_REQUEST_FILE]);
	int fd = open(file, O_WRONLY | O_CREAT | O_TRUNC, NEW_FILE_PERMISSIONS);
	if (fd == -1) {
		int e = errno;
		switch (e) {
		case EACCES:
			stdLogError(e, "PUT access denied %s %s", authenticatedUser, file);
			return writeErrorResponse(RAP_RESPOND_ACCESS_DENIED, strerror(errno), NULL, file);
		case ENOENT:
		default:
			stdLogError(e, "PUT not found %s %s", authenticatedUser, file);
			return writeErrorResponse(RAP_RESPOND_NOT_FOUND, strerror(errno), NULL, file);
		}
	}
// Check if we have the apropriate lock on this file.
	LockProvisions locks = messageParamTo(LockProvisions, requestMessage->params[RAP_PARAM_REQUEST_LOCK]);
	if (locks.source != LOCK_TYPE_EXCLUSIVE) {
		// We have no lock but we need one so acquire it now.
		if (flock(fd, LOCK_TYPE_EXCLUSIVE | LOCK_NB) == -1) {
			close(fd);
			int e = errno;
			const char * etxt = strerror(e);
			stdLogError(e, "Could not write locked file %s", file);
			return writeErrorResponse(RAP_RESPOND_LOCKED, etxt, "lock-token-submitted", file);
		}
	}
	int ret = respond(RAP_RESPOND_CONTINUE);
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
			return respond(RAP_RESPOND_INSUFFICIENT_STORAGE);
		}
	}

	close(fd);
	close(requestMessage->fd);
	return respond(RAP_RESPOND_CREATED);
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

static void listDir(const char * fileName, int dirFd, int writeFd) {
	DIR * dir = fdopendir(dirFd);
	xmlTextWriterPtr writer = xmlNewFdTextWriter(writeFd);

	size_t entryCount = 0;
	struct dirent ** directoryEntries = NULL;
	struct dirent * dp;
	while ((dp = readdir(dir)) != NULL) {
		int index = entryCount++;
		if (!(index & 0x7F)) {
			directoryEntries = reallocSafe(directoryEntries, sizeof(struct dirent **) * (entryCount + 0x7F));
		}
		directoryEntries[index] = dp;
	}

	qsort(directoryEntries, entryCount, sizeof(*directoryEntries), &compareDirent);

	xmlTextWriterStartElement(writer, "html");
	xmlTextWriterStartElement(writer, "head");
	xmlTextWriterWriteElementString(writer, NULL, "title", fileName);
	xmlTextWriterEndElement(writer);
	xmlTextWriterStartElement(writer, "body");
	xmlTextWriterWriteElementString(writer, NULL, "h1", fileName);
	xmlTextWriterStartElement(writer, "table");
	xmlTextWriterWriteAttribute(writer, "cellpadding", "5");
	xmlTextWriterWriteAttribute(writer, "cellspacing", "5");
	xmlTextWriterWriteAttribute(writer, "border", "1");
	xmlTextWriterWriteElementString(writer, NULL, "th", "Type");
	xmlTextWriterWriteElementString(writer, NULL, "th", "Name");
	xmlTextWriterWriteElementString(writer, NULL, "th", "Size");
	xmlTextWriterWriteElementString(writer, NULL, "th", "Mime Type");
	xmlTextWriterWriteElementString(writer, NULL, "th", "Last Modified");
	for (size_t i = 0; i < entryCount; i++) {
		dp = directoryEntries[i];
		if (dp->d_name[0] != '.') {
			struct stat stat;
			fstatat(dirFd, dp->d_name, &stat, 0);
			char buffer[100];

			xmlTextWriterStartElement(writer, "tr");

			// File or Dir
			xmlTextWriterWriteElementString(writer, NULL, "td", dp->d_type == DT_DIR ? "dir" : "file");

			// File Name
			xmlTextWriterStartElement(writer, "td");
			xmlTextWriterStartElement(writer, "a");
			xmlTextWriterStartAttribute(writer, "href");
			xmlTextWriterWriteURL(writer, fileName);
			xmlTextWriterWriteURL(writer, dp->d_name);
			if (dp->d_type == DT_DIR) xmlTextWriterWriteString(writer, "/");
			xmlTextWriterEndAttribute(writer);
			xmlTextWriterWriteString(writer, dp->d_name);
			if (dp->d_type == DT_DIR) xmlTextWriterWriteString(writer, "/");
			xmlTextWriterEndElement(writer);

			// File Size
			if (dp->d_type == DT_REG) {
				formatFileSize(buffer, sizeof(buffer), stat.st_size);
				xmlTextWriterWriteElementString(writer, NULL, "td", buffer);
			} else {
				xmlTextWriterWriteElementString(writer, NULL, "td", "-");
			}

			// MimeType
			xmlTextWriterWriteElementString(writer, NULL, "td",
					dp->d_type == DT_DIR ? "-" : findMimeType(dp->d_name)->type);

			// Last Modified
			getLocalDate(stat.st_mtime, buffer, sizeof(buffer));
			xmlTextWriterWriteElementString(writer, NULL, "td", buffer);

			xmlTextWriterEndElement(writer);
			xmlTextWriterEndElement(writer);
		}
	}
	xmlTextWriterEndElement(writer);
	xmlTextWriterEndElement(writer);
	xmlTextWriterEndElement(writer);

	xmlFreeTextWriter(writer);
	closedir(dir);
	freeSafe(directoryEntries);
}

static ssize_t readFile(Message * requestMessage) {
	if (requestMessage->fd != -1) {
		stdLogError(0, "GET request sent incoming data!");
		close(requestMessage->fd);
	}

	char * file = messageParamToString(&requestMessage->params[RAP_PARAM_REQUEST_FILE]);
	int fd = open(file, O_RDONLY);
	if (fd == -1) {
		int e = errno;
		switch (e) {
		case EACCES:
			stdLogError(e, "GET access denied %s %s", authenticatedUser, file);
			return writeErrorResponse(RAP_RESPOND_ACCESS_DENIED, strerror(errno), NULL, file);
		case ENOENT:
		default:
			stdLogError(e, "GET not found %s %s", authenticatedUser, file);
			return writeErrorResponse(RAP_RESPOND_NOT_FOUND, strerror(errno), NULL, file);
		}
	} else {
		struct stat statinfo;
		fstat(fd, &statinfo);
		if ((statinfo.st_mode & S_IFMT) == S_IFDIR) {
			size_t fileNameSize = strlen(file);
			if (fileNameSize > MAX_VARABLY_DEFINED_ARRAY) {
				stdLogError(0, "URI was too large to process %zd", fileNameSize);
				return writeErrorResponse(RAP_RESPOND_URI_TOO_LARGE, "URI was too large to process", NULL,
						file);
			}
			char fileName[fileNameSize];
			normalizeDirName(fileName, file, &fileNameSize, 1);

			// we cant't lock a directory so we don't try to acquire a lock here.
			int pipeEnds[2];
			if (pipe(pipeEnds)) {
				stdLogError(errno, "Could not create pipe to write content");
				close(fd);
				return respond(RAP_RESPOND_INTERNAL_ERROR);
			}

			time_t fileTime;
			time(&fileTime);

			Message message = { .mID = RAP_RESPOND_OK, .fd = pipeEnds[PIPE_READ], 3 };
			message.params[RAP_PARAM_RESPONSE_DATE] = toMessageParam(fileTime);
			message.params[RAP_PARAM_RESPONSE_MIME] = toMessageParam("text/html");
			message.params[RAP_PARAM_RESPONSE_LOCATION] = requestMessage->params[RAP_PARAM_REQUEST_FILE];
			ssize_t messageResult = sendMessage(RAP_CONTROL_SOCKET, &message);
			if (messageResult <= 0) {
				close(fd);
				close(pipeEnds[PIPE_WRITE]);
				return messageResult;
			}

			listDir(fileName, fd, pipeEnds[PIPE_WRITE]);
			return messageResult;
		} else {
			// Check if we have the apropriate lock on this file.
			LockProvisions locks = messageParamTo(LockProvisions,
					requestMessage->params[RAP_PARAM_REQUEST_LOCK]);
			if (locks.source == LOCK_TYPE_NONE) {
				// We have no lock but we need one so acquire it now.
				if (flock(fd, LOCK_TYPE_SHARED | LOCK_NB) == -1) {
					close(fd);
					int e = errno;
					const char * etxt = strerror(e);
					stdLogError(e, "Could not read locked file %s", file);
					return writeErrorResponse(RAP_RESPOND_LOCKED, etxt, "lock-token-submitted", file);
				}
			}
			Message message = { .mID = RAP_RESPOND_OK, .fd = fd, .paramCount = 3 };
			message.params[RAP_PARAM_RESPONSE_DATE] = toMessageParam(statinfo.st_mtime);
			MimeType * mimeType = findMimeType(file);
			message.params[RAP_PARAM_RESPONSE_MIME] = makeMessageParam(mimeType->type,
					mimeType->typeStringSize);
			message.params[RAP_PARAM_RESPONSE_LOCATION] = requestMessage->params[RAP_PARAM_REQUEST_FILE];
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
			|| (pamResult = pam_set_item(pamh, PAM_RUSER, user)) != PAM_SUCCESS || (pamResult =
					pam_authenticate(pamh, PAM_SILENT | PAM_DISALLOW_NULL_AUTHTOK)) != PAM_SUCCESS
			|| (pamResult = pam_acct_mgmt(pamh, PAM_SILENT | PAM_DISALLOW_NULL_AUTHTOK)) != PAM_SUCCESS
			|| (pamResult = pam_setcred(pamh, PAM_ESTABLISH_CRED)) != PAM_SUCCESS || (pamResult =
					pam_open_session(pamh, 0)) != PAM_SUCCESS) {
		pam_end(pamh, pamResult);
		return 0;
	}

// Get user details
	if ((pamResult = pam_get_item(pamh, PAM_USER, (const void **) &user)) != PAM_SUCCESS || (envList =
			pam_getenvlist(pamh)) == NULL) {

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

	char * user = messageParamToString(&message->params[RAP_PARAM_AUTH_USER]);
	char * password = messageParamToString(&message->params[RAP_PARAM_AUTH_PASSWORD]);
	char * rhost = messageParamToString(&message->params[RAP_PARAM_AUTH_RHOST]);

	if (pamAuthenticate(user, password, rhost)) {
		//stdLog("Login accepted for %s", user);
		return respond(RAP_RESPOND_OK);
	} else {
		return respond(RAP_RESPOND_AUTH_FAILLED);
	}
}

//////////////////////
// End Authenticate //
//////////////////////

int main(int argCount, char * args[]) {
	setlocale(LC_ALL, "");
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

	ssize_t ioResult;
	Message message;
	do {
		ioResult = recvMessage(RAP_CONTROL_SOCKET, &message, incomingBuffer, INCOMING_BUFFER_SIZE);
		if (ioResult <= 0) {
			if (errno == EBADF) {
				stdLogError(0, "Worker threads (%s) must only be created by webdavd", args[0]);
			}
			break;
		}

		if (message.mID == RAP_REQUEST_AUTHENTICATE) {
			ioResult = authenticate(&message);
		} else {
			stdLogError(0, "Invalid request id %d on unauthenticted worker", message.mID);
			ioResult = respond(RAP_RESPOND_INTERNAL_ERROR);
		}

	} while (ioResult > 0 && !authenticated);

	while (ioResult > 0) {
		// Read a message
		ioResult = recvMessage(RAP_CONTROL_SOCKET, &message, incomingBuffer, INCOMING_BUFFER_SIZE);
		if (ioResult <= 0) return ioResult == 0 ? 0 : 1;

		switch (message.mID) {
		case RAP_REQUEST_GET:
			ioResult = readFile(&message);
			break;
		case RAP_REQUEST_PUT:
			ioResult = writeFile(&message);
			break;
		case RAP_REQUEST_MKCOL:
			ioResult = mkcol(&message);
			break;
		case RAP_REQUEST_DELETE:
			ioResult = deleteFile(&message);
			break;
		case RAP_REQUEST_MOVE: // TODO lock
			ioResult = moveFile(&message);
			break;
		case RAP_REQUEST_COPY: // TODO lock
			ioResult = copyFile(&message);
			break;
		case RAP_REQUEST_PROPFIND:
			ioResult = propfind(&message);
			break;
		case RAP_REQUEST_PROPPATCH:
			ioResult = proppatch(&message);
			break;
		case RAP_REQUEST_LOCK:
			ioResult = lockFile(&message);
			break;
		default:
			if (message.mID >= 400 && message.mID <= 499) {
				const char * location = messageParamToString(&message.params[RAP_PARAM_ERROR_LOCATION]);
				const char * reason = messageParamToString(&message.params[RAP_PARAM_ERROR_REASON]);
				const char * davReason = messageParamToString(&message.params[RAP_PARAM_ERROR_DAV_REASON]);
				ioResult = writeErrorResponse(message.mID, reason, davReason, location);
			} else {
				stdLogError(0, "Invalid request id %d on authenticated worker", message.mID);
				ioResult = respond(RAP_RESPOND_INTERNAL_ERROR);
			}
		}
	}

	return ioResult < 0 ? 1 : 0;
}
