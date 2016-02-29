// TODO auth modes other than basic?
// TODO check into what happens when a connection is closed early during upload.
// TODO prevent PUT clobbering files.

#include "shared.h"
#include "configuration.h"
#include "rap-control.h"

#include <errno.h>
#include <fcntl.h>
#include <gnutls/abstract.h>
#include <microhttpd.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>

////////////////
// Structures //
////////////////

typedef struct Header {
	const char * key;
	const char * value;
} Header;

typedef struct SSLCertificate {
	const char * hostname;
	int certCount;
	gnutls_pcert_st * certs;
	gnutls_privkey_t key;
} SSLCertificate;

typedef struct MHD_Connection Request;
typedef struct MHD_Response Response;

typedef struct FDResponse {
	int fd;
	off_t pos;
	off_t offset;
	off_t size;
} FDResponseData;

////////////////////
// End Structures //
////////////////////

#define ACCEPT_HEADER "OPTIONS, GET, HEAD, DELETE, PROPFIND, PUT, PROPPATCH, COPY, MOVE" //, LOCK, UNLOCK"

static Response * INTERNAL_SERVER_ERROR_PAGE;
static Response * UNAUTHORIZED_PAGE;
static Response * METHOD_NOT_SUPPORTED_PAGE;

const char * FORBIDDEN_PAGE;
const char * NOT_FOUND_PAGE;
const char * BAD_REQUEST_PAGE;
const char * INSUFFICIENT_STORAGE_PAGE;
const char * OPTIONS_PAGE;
const char * CONFLICT_PAGE;
const char * OK_PAGE;

static int sslCertificateCount;
static SSLCertificate * sslCertificates = NULL;

// All Daemons
// Not sure why we keep these, they're not used for anything
static struct MHD_Daemon **daemons;

/////////////
// Utility //
/////////////

static void logAccess(int statusCode, const char * method, const char * user, const char * url, const char * client) {
	char t[100];
	printf("%s %s %s %d %s %s\n", timeNow(t), client, user, statusCode, method, url);
	fflush(stdout);
}

static void initializeLogs() {
	// Error log first
	if (config.errorLog) {
		int errorLog = open(config.errorLog, O_CREAT | O_APPEND | O_WRONLY | O_CLOEXEC, 420);
		if (errorLog == -1 || dup2(errorLog, STDERR_FILENO) == -1) {
			stdLogError(errno, "Could not open error log file %s", config.errorLog);
			exit(1);
		}
		close(errorLog);
	}

	if (config.accessLog) {
		int accessLogFd = open(config.accessLog, O_CREAT | O_APPEND | O_WRONLY | O_CLOEXEC, 420);
		if (accessLogFd == -1 || dup2(accessLogFd, STDOUT_FILENO) == -1) {
			stdLogError(errno, "Could not open access log file %s", config.accessLog);
			exit(1);
		}
	}

}

static void getRequestIP(char * buffer, size_t bufferSize, Request * request) {
	const struct sockaddr * addressInfo =
			MHD_get_connection_info(request, MHD_CONNECTION_INFO_CLIENT_ADDRESS)->client_addr;
	static unsigned char IPV4_PREFIX[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF };
	switch (addressInfo->sa_family) {
	case AF_INET: {
		struct sockaddr_in * v4Address = (struct sockaddr_in *) addressInfo;
		unsigned char * address = (unsigned char *) (&v4Address->sin_addr);
		snprintf(buffer, bufferSize, "%d.%d.%d.%d", address[0], address[1], address[2], address[3]);
		break;
	}

	case AF_INET6: {
		struct sockaddr_in6 * v6Address = (struct sockaddr_in6 *) addressInfo;
		// See RFC 5952 section 4 for formatting rules
		// find 0 run
		unsigned char * address = (unsigned char *) (&v6Address->sin6_addr);
		if (!memcmp(IPV4_PREFIX, address, sizeof(IPV4_PREFIX))) {
			snprintf(buffer, bufferSize, "%d.%d.%d.%d", address[sizeof(IPV4_PREFIX)], address[sizeof(IPV4_PREFIX) + 1],
					address[sizeof(IPV4_PREFIX) + 2], address[sizeof(IPV4_PREFIX) + 3]);
			break;
		}

		unsigned char * longestRun = NULL;
		int longestRunSize = 0;
		unsigned char * currentRun = NULL;
		int currentRunSize = 0;
		for (int i = 0; i < 16; i += 2) {
			if (*(address + i) == 0 && *(address + i + 1) == 0) {
				if (currentRunSize == 0) {
					currentRunSize = 2;
					currentRun = (address + i);
				} else {
					currentRunSize += 2;
					if (currentRunSize > longestRunSize) {
						longestRun = currentRun;
						longestRunSize = currentRunSize;
					}
				}
			} else {
				currentRunSize = 0;
			}
		}

		int bytesWritten;
		if (longestRunSize == 16) {
			bytesWritten = snprintf(buffer, bufferSize, "::");
			buffer += bytesWritten;
			bufferSize -= bytesWritten;
		} else {
			for (int i = 0; i < 16; i += 2) {
				if (&address[i] == longestRun) {
					bytesWritten = snprintf(buffer, bufferSize, i > 0 ? ":" : "::");
					buffer += bytesWritten;
					bufferSize -= bytesWritten;
					i += longestRunSize - 2;
				} else {
					if (*(address + i) == 0) {
						bytesWritten = snprintf(buffer, bufferSize, "%x%s", *(address + i + 1), i < 14 ? ":" : "");
						buffer += bytesWritten;
						bufferSize -= bytesWritten;
					} else {
						bytesWritten = snprintf(buffer, bufferSize, "%x%02x%s", *(address + i), *(address + i + 1),
								i < 14 ? ":" : "");
						buffer += bytesWritten;
						bufferSize -= bytesWritten;
					}
				}
			}
		}

		break;
	}

	default:
		snprintf(buffer, bufferSize, "<unknown address>");
	}
}

static int filterGetHeader(Header * header, enum MHD_ValueKind kind, const char *key, const char *value) {
	if (!strcmp(key, header->key)) {
		header->value = value;
		return MHD_NO;
	}
	return MHD_YES;
}

static const char * getHeader(Request *request, const char * headerKey) {
	Header header = { .key = headerKey, .value = NULL };
	MHD_get_connection_values(request, MHD_HEADER_KIND, (MHD_KeyValueIterator) &filterGetHeader, &header);
	return header.value;
}

/////////////////
// End Utility //
/////////////////

/////////
// SSL //
/////////

static int sslCertificateCompareHost(const void * a, const void * b) {
	SSLCertificate * lhs = (SSLCertificate *) a;
	SSLCertificate * rhs = (SSLCertificate *) b;
	return strcmp(lhs->hostname, rhs->hostname);
}

static SSLCertificate * findCertificateForHost(const char * hostname) {
	SSLCertificate toFind = { .hostname = hostname };
	SSLCertificate * found = bsearch(&toFind, sslCertificates, sslCertificateCount, sizeof(*sslCertificates),
			&sslCertificateCompareHost);
	if (!found) {
		char * newHostName = copyString(hostname);
		char * wildCardHostName = newHostName;
		do {
			wildCardHostName++;
			if (wildCardHostName[0] == '.') {
				wildCardHostName[-1] = '*';
				toFind.hostname = &wildCardHostName[-1];
				found = bsearch(&toFind, sslCertificates, sslCertificateCount, sizeof(*sslCertificates),
						&sslCertificateCompareHost);
			}
		} while (!found && *wildCardHostName);
		freeSafe(newHostName);
	}
	return found;
}

static int sslSNICallback(gnutls_session_t session, const gnutls_datum_t* req_ca_dn, int nreqs,
		const gnutls_pk_algorithm_t* pk_algos, int pk_algos_length, gnutls_pcert_st** pcert, unsigned int *pcert_length,
		gnutls_privkey_t * pkey) {

	SSLCertificate * found = NULL;

	char name[1024];
	size_t name_len = sizeof(name) - 1;
	unsigned int type;
	if (GNUTLS_E_SUCCESS == gnutls_server_name_get(session, name, &name_len, &type, 0)) {
		name[name_len] = '\0';
		found = findCertificateForHost(name);
	}

	// Returning certificate
	if (!found) {
		found = &sslCertificates[0];
	}
	*pkey = found->key;
	*pcert_length = found->certCount;
	*pcert = found->certs;
	return 0;
}

static int loadSSLCertificateFile(const char * fileName, gnutls_x509_crt_t * x509Certificate, gnutls_pcert_st * cert) {
	size_t fileSize;
	gnutls_datum_t certData;

	memset(cert, 0, sizeof(*cert));
	memset(x509Certificate, 0, sizeof(*x509Certificate));

	certData.data = loadFileToBuffer(fileName, &fileSize);
	if (!certData.data) {
		return -1;
	}
	certData.size = fileSize;

	int ret;
	if ((ret = gnutls_x509_crt_init(x509Certificate)) < 0) {
		freeSafe(certData.data);
		return ret;
	}

	ret = gnutls_x509_crt_import(*x509Certificate, &certData, GNUTLS_X509_FMT_PEM);
	freeSafe(certData.data);
	if (ret < 0) {
		gnutls_x509_crt_deinit(*x509Certificate);
		return ret;
	}

	if ((ret = gnutls_pcert_import_x509(cert, *x509Certificate, 0)) < 0) {
		gnutls_x509_crt_deinit(*x509Certificate);
		return ret;
	}
	return ret;
}

static int loadSSLKeyFile(const char * fileName, gnutls_privkey_t * key) {
	size_t fileSize;
	gnutls_datum_t keyData;
	keyData.data = loadFileToBuffer(fileName, &fileSize);
	if (!keyData.data) {
		return -1;
	}

	keyData.size = fileSize;

	int ret = gnutls_privkey_init(key);
	if (ret < 0) {
		freeSafe(keyData.data);
		return ret;
	}

	ret = gnutls_privkey_import_x509_raw(*key, &keyData, GNUTLS_X509_FMT_PEM, NULL, 0);
	freeSafe(keyData.data);
	if (ret < 0) {
		gnutls_privkey_deinit(*key);
	}

	return ret;
}

static int loadSSLCertificate(SSLConfig * sslConfig) {
	// Now load the files in earnest
	SSLCertificate newCertificate;
	gnutls_x509_crt_t x509Certificate;
	int ret;
	ret = loadSSLKeyFile(sslConfig->keyFile, &newCertificate.key);
	if (ret < 0) {
		stdLogError(0, "Could not load %s: %s", sslConfig->keyFile, gnutls_strerror(ret));
		return 0;
	}
	newCertificate.certCount = sslConfig->chainFileCount + 1;
	newCertificate.certs = mallocSafe(newCertificate.certCount * (sizeof(*newCertificate.certs)));
	for (int i = 0; i < sslConfig->chainFileCount; i++) {
		ret = loadSSLCertificateFile(sslConfig->chainFiles[i], &x509Certificate, &newCertificate.certs[i + 1]);
		if (ret < 0) {
			stdLogError(0, "Could not load %s: %s", sslConfig->chainFiles[i], gnutls_strerror(ret));
			gnutls_privkey_deinit(newCertificate.key);
			for (int j = 0; j < i; j++) {
				gnutls_pcert_deinit(&newCertificate.certs[j + 1]);
			}
			freeSafe(newCertificate.certs);
			return ret;
		}
		gnutls_x509_crt_deinit(x509Certificate);
	}
	ret = loadSSLCertificateFile(sslConfig->certificateFile, &x509Certificate, &newCertificate.certs[0]);
	if (ret < 0) {
		stdLogError(0, "Could not load %s: %s", sslConfig->certificateFile, gnutls_strerror(ret));
		gnutls_privkey_deinit(newCertificate.key);
		for (int i = 1; i < newCertificate.certCount; i++) {
			gnutls_pcert_deinit(&newCertificate.certs[i]);
		}
		freeSafe(newCertificate.certs);
	}

	int found = 0;
	for (int i = 0; ret != GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE; i++) {
		char domainName[1024];
		int critical = 0;
		size_t dataSize = sizeof(domainName);
		int sanType = 0;
		ret = gnutls_x509_crt_get_subject_alt_name2(x509Certificate, i, domainName, &dataSize, &sanType, &critical);
		if (ret != GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE && ret != GNUTLS_E_SHORT_MEMORY_BUFFER
				&& sanType == GNUTLS_SAN_DNSNAME) {

			stdLog("ssl domain %s --> %s", domainName, sslConfig->certificateFile);
			int index = sslCertificateCount++;
			sslCertificates = reallocSafe(sslCertificates, sslCertificateCount * (sizeof(*sslCertificates)));
			sslCertificates[index] = newCertificate;
			sslCertificates[index].hostname = copyString(domainName);
			found = 1;
		}
	}

	gnutls_x509_crt_deinit(x509Certificate);

	if (!found) {
		stdLogError(0, "No subject alternative name found in %s", sslConfig->certificateFile);
		gnutls_privkey_deinit(newCertificate.key);
		for (int i = 0; i < newCertificate.certCount; i++) {
			gnutls_pcert_deinit(&newCertificate.certs[i]);
		}
		freeSafe(newCertificate.certs);
		return -1;
	}

	return 0;
}

static void initializeSSL() {
	for (int i = 0; i < config.sslCertCount; i++) {
		if (loadSSLCertificate(&config.sslCerts[i])) {
			exit(1);
		}
	}
	qsort(sslCertificates, sslCertificateCount, sizeof(*sslCertificates), &sslCertificateCompareHost);
}

/////////////
// End SSL //
/////////////

///////////////////////
// Response Creation //
///////////////////////

static void addHeader(Response * response, const char * headerKey, const char * headerValue) {
	if (headerValue == NULL) {
		stdLogError(0, "Attempt to add null value as header %s:", headerKey);
		return;
	}
	if (MHD_add_response_header(response, headerKey, headerValue) != MHD_YES) {
		stdLogError(errno, "Could not add response header %s: %s", headerKey, headerValue);
		exit(255);
	}
}

static void addStaticHeaders(Response * response) {
	addHeader(response, "DAV", "1");
	addHeader(response, "Accept-Ranges", "bytes");
	addHeader(response, "Server", "couling-webdavd");
	addHeader(response, "Expires", "Thu, 19 Nov 1980 00:00:00 GMT");
	addHeader(response, "Cache-Control", "no-store, no-cache, must-revalidate, post-check=0, pre-check=0");
	addHeader(response, "Pragma", "no-cache");
}

static ssize_t fdContentReader(void *cls, uint64_t pos, char *buf, size_t max) {
	FDResponseData * fdResponsedata = cls;
	if (pos != fdResponsedata->pos) {
		off_t seekTo = pos + fdResponsedata->offset;
		off_t result = lseek(fdResponsedata->fd, pos + fdResponsedata->offset, SEEK_SET);
		if (result != seekTo) {
			stdLogError(errno, "Could not file seek for response");
			return MHD_CONTENT_READER_END_WITH_ERROR;
		} else {
			fdResponsedata->pos = seekTo;
		}
	}
	if (fdResponsedata->size > 0 && fdResponsedata->size - pos < max) {
		max = fdResponsedata->size - pos;
	}

	size_t bytesRead = read(fdResponsedata->fd, buf, max);
	if (bytesRead <= 0) {
		if (bytesRead == 0) {
			return MHD_CONTENT_READER_END_OF_STREAM;
		} else {
			stdLogError(errno, "Could not read content from fd");
			return MHD_CONTENT_READER_END_WITH_ERROR;
		}
	}
	while (bytesRead < max) {
		size_t newBytesRead = read(fdResponsedata->fd, buf + bytesRead, max - bytesRead);
		if (newBytesRead <= 0) {
			break;
		}
		bytesRead += newBytesRead;
	}
	fdResponsedata->pos += bytesRead;
	return bytesRead;
}

static void fdContentReaderCleanup(void *cls) {
	FDResponseData * fdResponseData = cls;
	close(fdResponseData->fd);
	freeSafe(fdResponseData);
}

static Response * createFdResponse(int fd, uint64_t offset, uint64_t size, const char * mimeType, time_t date) {
	FDResponseData * fdResponseData = mallocSafe(sizeof(*fdResponseData));
	fdResponseData->fd = fd;
	fdResponseData->pos = 0;
	fdResponseData->offset = offset;
	fdResponseData->size = size;
	Response * response = MHD_create_response_from_callback(size, 40960, &fdContentReader, fdResponseData,
			&fdContentReaderCleanup);
	if (!response) {
		fdContentReaderCleanup(fdResponseData);
		return NULL;
	}
	char dateBuf[100];
	getWebDate(date, dateBuf, 100);
	addHeader(response, "Date", dateBuf);
	if (mimeType != NULL) {
		addHeader(response, "Content-Type", mimeType);
	}
	addStaticHeaders(response);
	return response;
}

static Response * createFileResponse(Request *request, const char * fileName, const char * mimeType) {
	int fd = open(fileName, O_RDONLY | O_CLOEXEC);
	if (fd == -1) {
		stdLogError(errno, "Could not open file for response", fileName);
		return NULL;
	}

	struct stat statBuffer;
	fstat(fd, &statBuffer);
	return createFdResponse(fd, 0, statBuffer.st_size, mimeType, statBuffer.st_mtime);
}

static int processRangeHeader(off_t * offset, size_t * fileSize, const char *range) {
	int result = strncmp(range, "bytes=", sizeof("bytes=") - 1);
	if (result) {
		return 0;
	}

	long long from, to;

	range += sizeof("bytes=") - 1;
	if (*range == '\0') {
		return 0;
	}

	if (*range == '-') {
		from = 0;
	} else {
		char * endPtr;
		from = strtoll(range, &endPtr, 10);
		if (endPtr == range) {
			return 0;
		} else {
			range = endPtr;
		}
	}

	if (*range == '\0') {
		return 0;
	}

	range++;

	if (*range == '\0') {
		to = *fileSize;
	} else {
		char * endPtr;
		to = strtoll(range, &endPtr, 10);
		if (endPtr == range) {
			return 0;
		}
	}

	*offset = from;
	*fileSize = to - from;

	return 1;
}

static int createRapResponse(Request *request, struct Message * message, Response ** response) {
	// Queue the response
	switch (message->mID) {
	case RAP_MULTISTATUS: {
		const char * mimeType = messageParamToString(&message->params[RAP_FILE_INDEX]);
		time_t date = *((time_t *) message->params[RAP_DATE_INDEX].iov_base);

		if (message->fd == -1) {
			return MHD_HTTP_INTERNAL_SERVER_ERROR;
		}

		*response = createFdResponse(message->fd, 0, -1, mimeType, date);
		return RAP_MULTISTATUS;
	}

	case RAP_SUCCESS: {
		if (message->fd == -1) {
			*response = createFileResponse(request, OK_PAGE, "text/html");
			return RAP_SUCCESS;
		}

		int statusCode = message->mID;
		// Get Mime type and date
		const char * mimeType = messageParamToString(&message->params[RAP_FILE_INDEX]);
		time_t date = *((time_t *) message->params[RAP_DATE_INDEX].iov_base);

		struct stat stat;
		fstat(message->fd, &stat);
		if ((stat.st_mode & S_IFMT) == S_IFREG) {
			off_t offset = 0;
			size_t fileSize = stat.st_size;
			const char * rangeHeader = getHeader(request, "Range");
			if (rangeHeader && processRangeHeader(&offset, &fileSize, rangeHeader)) {
				statusCode = MHD_HTTP_PARTIAL_CONTENT;
			}
			*response = createFdResponse(message->fd, offset, fileSize, mimeType, date);

			char contentRangeHeader[200];
			snprintf(contentRangeHeader, sizeof(contentRangeHeader), "bytes %lld-%lld/%lld", (long long) offset,
					(long long) (fileSize + offset), (long long) stat.st_size);

			addHeader(*response, "Content-Range", contentRangeHeader);
		} else {
			*response = createFdResponse(message->fd, 0, -1, mimeType, date);
		}

		if (message->bufferCount > RAP_LOCATION_INDEX) {
			addHeader(*response, "Location", messageParamToString(&message->params[RAP_LOCATION_INDEX]));
		}

		return statusCode;
	}

	case RAP_ACCESS_DENIED:
		*response = createFileResponse(request, FORBIDDEN_PAGE, "text/html");
		return RAP_ACCESS_DENIED;

	case RAP_NOT_FOUND:
		*response = createFileResponse(request, NOT_FOUND_PAGE, "text/html");
		return RAP_NOT_FOUND;

	case RAP_BAD_CLIENT_REQUEST:
		*response = createFileResponse(request, BAD_REQUEST_PAGE, "text/html");
		return RAP_BAD_CLIENT_REQUEST;

	case RAP_INSUFFICIENT_STORAGE:
		*response = createFileResponse(request, INSUFFICIENT_STORAGE_PAGE, "text/html");
		return RAP_INSUFFICIENT_STORAGE;

	case RAP_CONFLICT:
		*response = createFileResponse(request, CONFLICT_PAGE, "text/html");
		return RAP_CONFLICT;

	case RAP_INTERNAL_ERROR:
	default:
		stdLogError(0, "Error response from RAP %d", (int) message->mID);
		return message->mID;
	}

}

///////////////////////////
// End Response Queueing //
///////////////////////////

//////////////////////////
// Main Handler Methods //
//////////////////////////

static int completeUpload(Request *request, RAP * processor, Response ** response) {

	// Closing this pipe signals to the rap that there is no more data
	// This MUST happen before the recvMessage a few lines below or the RAP
	// will NOT send a message and recvMessage will hang.
	if (processor->writeDataFd != -1) {
		close(processor->writeDataFd);
		processor->writeDataFd = -1;
	}

	Message message;
	char incomingBuffer[INCOMING_BUFFER_SIZE];
	int readResult = recvMessage(processor->socketFd, &message, incomingBuffer, INCOMING_BUFFER_SIZE);
	if (readResult <= 0) {
		if (readResult == 0) {
			stdLogError(0, "RAP closed socket unexpectedly while waiting for response");
		} // else { stdLogError ... has already been sent by recvMessage ... }
		return MHD_HTTP_INTERNAL_SERVER_ERROR;
	}

	if (readResult > 0) {
		return createRapResponse(request, &message, response);
	} else {
		return MHD_HTTP_INTERNAL_SERVER_ERROR;
	}
}

static void processUploadData(Request * request, const char * upload_data, size_t upload_data_size, RAP * processor) {

	if (processor->writeDataFd != -1) {
		size_t bytesWritten = write(processor->writeDataFd, upload_data, upload_data_size);
		if (bytesWritten < upload_data_size) {
			// not all data could be written to the file handle and therefore
			// the operation has now failed. There's nothing we can do now but report the error
			// This may not actually be desirable and so we need to consider slamming closed the connection.
			close(processor->writeDataFd);
			processor->writeDataFd = -1;
		}
	}
}

static int processNewRequest(Request * request, const char * url, const char * host, const char * method,
		RAP * rapSession, Response ** response) {

	// Interpret the method
	Message message;
	message.fd = rapSession->readDataFd;
	message.params[RAP_HOST_INDEX].iov_len = strlen(host) + 1;
	message.params[RAP_HOST_INDEX].iov_base = (void *) host;
	message.params[RAP_FILE_INDEX].iov_len = strlen(url) + 1;
	message.params[RAP_FILE_INDEX].iov_base = (void *) url;
	// TODO MKCOL
	// TODO HEAD
	// TODO DELETE
	// TODO COPY
	// TODO MOVE
	// TODO LOCK
	// TODO UNLOCK
	// TODO PROPPATCH // properly
	//stdLog("%s %s data", method, writeHandle ? "with" : "without");
	if (!strcmp("GET", method)) {
		message.mID = RAP_READ_FILE;
		message.bufferCount = 2;
	} else if (!strcmp("PUT", method)) {
		message.mID = RAP_WRITE_FILE;
		message.bufferCount = 2;
	} else if (!strcmp("PROPFIND", method)) {
		message.mID = RAP_PROPFIND;
		const char * depth = getHeader(request, "Depth");
		if (depth) {
			message.params[RAP_DEPTH_INDEX].iov_base = (void *) depth;
			message.params[RAP_DEPTH_INDEX].iov_len = strlen(depth) + 1;
		} else {
			message.params[RAP_DEPTH_INDEX].iov_base = "infinity";
			message.params[RAP_DEPTH_INDEX].iov_len = sizeof("infinity");
		}
		message.bufferCount = 3;
	} else if (!strcmp("PROPPATCH", method)) {
		message.mID = RAP_PROPPATCH;
		const char * depth = getHeader(request, "Depth");
		if (depth) {
			message.params[RAP_DEPTH_INDEX].iov_base = (void *) depth;
			message.params[RAP_DEPTH_INDEX].iov_len = strlen(depth) + 1;
		} else {
			message.params[RAP_DEPTH_INDEX].iov_base = "infinity";
			message.params[RAP_DEPTH_INDEX].iov_len = sizeof("infinity");
		}
		message.bufferCount = 3;
	} else if (!strcmp("OPTIONS", method)) {
		*response = createFileResponse(request, OPTIONS_PAGE, "text/html");
		addHeader(*response, "Accept", ACCEPT_HEADER);
		return MHD_HTTP_OK;
	} else {
		stdLogError(0, "Can not cope with method: %s (%s data)", method,
				(rapSession->writeDataFd != -1 ? "with" : "without"));
		return MHD_HTTP_METHOD_NOT_ALLOWED;
	}

	// Send the request to the RAP
	size_t ioResult = sendMessage(rapSession->socketFd, &message);
	rapSession->readDataFd = -1; // this will always be closed by sendMessage even on failure!
	if (ioResult <= 0) {
		return MHD_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Get result from RAP
	char incomingBuffer[INCOMING_BUFFER_SIZE];
	ioResult = recvMessage(rapSession->socketFd, &message, incomingBuffer, INCOMING_BUFFER_SIZE);
	if (ioResult <= 0) {
		if (ioResult == 0) {
			stdLogError(0, "RAP closed socket unexpectedly while waiting for response");
		}
		return MHD_HTTP_INTERNAL_SERVER_ERROR;
	}

	if (message.mID == RAP_CONTINUE) {
		if (message.fd != -1) {
			close(message.fd);
		}
		return MHD_HTTP_CONTINUE;
	} else {
		return createRapResponse(request, &message, response);
	}
}

static int sendResponse(Request *request, int statusCode, Response * response, RAP * rapSession, const char * method,
		const char * url) {

	// This doesn't really belong here but its a good safty check. We should never try to send a response
	// when the data pipes are still open
	if (rapSession->readDataFd != -1) {
		stdLogError(0, "readDataFd was not properly closed before sending response");
		close(rapSession->readDataFd);
		rapSession->readDataFd = -1;
	}
	if (rapSession->writeDataFd != -1) {
		stdLogError(0, "writeDataFd was not properly closed before sending response");
		close(rapSession->writeDataFd);
		rapSession->writeDataFd = -1;
	}

	char clientIp[100];
	getRequestIP(clientIp, sizeof(clientIp), request);
	logAccess(statusCode, method, rapSession->user, url, clientIp);
	switch (statusCode) {
	case MHD_HTTP_INTERNAL_SERVER_ERROR:
		return MHD_queue_response(request, MHD_HTTP_INTERNAL_SERVER_ERROR, INTERNAL_SERVER_ERROR_PAGE);
	case MHD_HTTP_UNAUTHORIZED:
		return MHD_queue_response(request, MHD_HTTP_UNAUTHORIZED, UNAUTHORIZED_PAGE);
	case MHD_HTTP_METHOD_NOT_ALLOWED:
		return MHD_queue_response(request, MHD_HTTP_METHOD_NOT_ALLOWED, METHOD_NOT_SUPPORTED_PAGE);
	default: {
		int queueResult = MHD_queue_response(request, statusCode, response);
		MHD_destroy_response(response);
		return queueResult;
	}
	}
}

//////////////////////////////
// END Main Handler Methods //
//////////////////////////////

///////////////////////////////////////
// Low Level HTTP handling (Signpost //
///////////////////////////////////////

static int requestHasData(Request *request) {
	if (getHeader(request, "Content-Length")) {
		return 1;
	} else {
		const char * te = getHeader(request, "Transfer-Encoding");
		return te && !strcmp(te, "chunked");
	}
}

static int answerToRequest(void *cls, Request *request, const char *url, const char *method, const char *version,
		const char *upload_data, size_t *upload_data_size, void ** s) {

	RAP * rapSession = *((RAP **) s);

	if (rapSession) {
		if (*upload_data_size) {
			// Uploading more data
			if (!rapSession->responseAlreadyGiven) {
				processUploadData(request, upload_data, *upload_data_size, rapSession);
			}
			*upload_data_size = 0;
			return MHD_YES;
		} else {
			// Finished uploading data
			if (rapSession->responseAlreadyGiven) {
				if (rapSession->responseAlreadyGiven == RAP_INTERNAL_ERROR) {
					destroyRap(rapSession);
				} else {
					releaseRap(rapSession);
				}
				return MHD_YES;
			} else {
				Response * response;
				int statusCode = completeUpload(request, rapSession, &response);
				int result = sendResponse(request, statusCode, response, rapSession, method, url);
				if (statusCode == RAP_INTERNAL_ERROR) {
					destroyRap(rapSession);
				} else if (AUTH_SUCCESS(rapSession)) {
					releaseRap(rapSession);
				}
				return result;
			}
		}
	} else {
		const char * host = getHeader(request, "Host");
		if (host == NULL) {
			host = "<host-unknown>";
		}

		// Authenticate all new requests regardless of anything else
		char * password;
		char * user = MHD_basic_auth_get_username_password(request, &password);
		char clientIp[100];
		getRequestIP(clientIp, sizeof(clientIp), request);
		rapSession = acquireRap(user, password, clientIp);
		*s = rapSession;
		if (AUTH_SUCCESS(rapSession)) {
			//urlDecode((char *) url);
			if (requestHasData(request)) {
				// If we have data to send then create a pipe to pump it through
				// To avoid the "non-standard" pipe2() we use unix domain sockets with socketpair
				// this let us set it as a close on exec
				int pipeEnds[2];
				if (socketpair(PF_LOCAL, SOCK_STREAM | SOCK_CLOEXEC, 0, pipeEnds)) {
					stdLogError(errno, "Could not create write pipe");
					return sendResponse(request, MHD_HTTP_INTERNAL_SERVER_ERROR, NULL, rapSession, method, url);
				}

				rapSession->readDataFd = pipeEnds[CHILD_SOCKET];
				rapSession->writeDataFd = pipeEnds[PARENT_SOCKET];

				Response * response;
				int statusCode = processNewRequest(request, url, host, method, rapSession, &response);

				if (statusCode == RAP_CONTINUE) {
					// do not queue a response for contiune
					rapSession->responseAlreadyGiven = 0;
					//logAccess(statusCode, method, (*rapSession)->user, url);
					return MHD_YES;
				} else {
					rapSession->responseAlreadyGiven = statusCode;
					return sendResponse(request, statusCode, response, rapSession, method, url);
				}
			} else {
				rapSession->readDataFd = -1;
				rapSession->writeDataFd = -1;
				Response * response;

				int statusCode = processNewRequest(request, url, host, method, rapSession, &response);

				if (statusCode == RAP_CONTINUE) {
					stdLogError(0, "RAP returned CONTINUE when there is no data");
					int ret = sendResponse(request, MHD_HTTP_INTERNAL_SERVER_ERROR, NULL, rapSession, method, url);
					releaseRap(rapSession);
					return ret;
				} else {
					int ret = sendResponse(request, statusCode, response, rapSession, method, url);
					if (statusCode == RAP_INTERNAL_ERROR) {
						destroyRap(rapSession);
					} else {
						releaseRap(rapSession);
					}
					return ret;
				}
			}
		} else if (rapSession == AUTH_FAILED) {
			return sendResponse(request, MHD_HTTP_UNAUTHORIZED, NULL, rapSession, method, url);
		} else /*if (*rapSession == AUTH_ERROR)*/{
			return sendResponse(request, MHD_HTTP_INTERNAL_SERVER_ERROR, NULL, rapSession, method, url);
		}
	}
}

static int answerForwardToRequest(void *cls, Request *request, const char *url, const char *method, const char *version,
		const char *upload_data, size_t *upload_data_size, void ** s) {
	if (*s != NULL) {
		return MHD_YES;
	}
	*s = cls;

	DaemonConfig * daemon = (DaemonConfig *) cls;
	Response * response = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_MUST_COPY);
	if (!response) {
		stdLogError(errno, "Unable to create 301 response");
		return MHD_queue_response(request, MHD_HTTP_INTERNAL_SERVER_ERROR, INTERNAL_SERVER_ERROR_PAGE);
	}

	const char * host = daemon->forwardToHost ? daemon->forwardToHost : getHeader(request, "Host");
	if (!host) {
		host = daemon->host;
		if (!host) {
			return MHD_queue_response(request, MHD_HTTP_INTERNAL_SERVER_ERROR, INTERNAL_SERVER_ERROR_PAGE);
		}
	}

	size_t bufferSize = strlen(host) + strlen(url) + 10;
	char * buffer = mallocSafe(bufferSize);
	if ((daemon->forwardToIsEncrypted && daemon->forwardToPort == 443)
			|| (!daemon->forwardToIsEncrypted && daemon->forwardToPort == 80)) {
		// default ports
		snprintf(buffer, bufferSize, "%s://%s%s", daemon->forwardToIsEncrypted ? "https" : "http", host, url);
	} else {
		snprintf(buffer, bufferSize, "%s://%s:%d%s", daemon->forwardToIsEncrypted ? "https" : "http", host,
				daemon->forwardToPort, url);
	}

	addHeader(response, "Location", buffer);
	int result = MHD_queue_response(request, MHD_HTTP_MOVED_PERMANENTLY, response);
	MHD_destroy_response(response);
	return result;
}

///////////////////////////////////////////
// End Low Level HTTP handling (Signpost //
///////////////////////////////////////////

////////////////////
// Initialisation //
////////////////////

static void initializeStaticResponse(Response ** response, const char * fileName, const char * mimeType) {
	size_t bufferSize;
	char * buffer;

	buffer = loadFileToBuffer(fileName, &bufferSize);
	if (buffer == NULL) {
		exit(1);
	}
	*response = MHD_create_response_from_buffer(bufferSize, buffer, MHD_RESPMEM_MUST_FREE);
	if (!*response) {
		stdLogError(errno, "Could not create response buffer");
		exit(255);
	}

	if (mimeType) {
		addHeader(*response, "Content-Type", mimeType);
	}
}

static char * createStaticFileName(const char * string) {
	size_t staticSize = strlen(config.staticResponseDir);
	size_t stringSize = strlen(string);
	char * result = mallocSafe(staticSize + stringSize + 2);
	memcpy(result, config.staticResponseDir, staticSize);
	result[staticSize] = '/';
	memcpy(result + staticSize + 1, string, stringSize + 1);
	return result;
}

static void initializeStaticResponses() {
	char * string;
	string = createStaticFileName("HTTP_INTERNAL_SERVER_ERROR.html");
	initializeStaticResponse(&INTERNAL_SERVER_ERROR_PAGE, string, "text/html");
	freeSafe(string);

	string = createStaticFileName("HTTP_UNAUTHORIZED.html");
	initializeStaticResponse(&UNAUTHORIZED_PAGE, string, "text/html");
	addHeader(UNAUTHORIZED_PAGE, "WWW-Authenticate", "Basic realm=\"My Server\"");
	freeSafe(string);

	string = createStaticFileName("HTTP_METHOD_NOT_SUPPORTED.html");
	initializeStaticResponse(&METHOD_NOT_SUPPORTED_PAGE, string, "text/html");
	addHeader(METHOD_NOT_SUPPORTED_PAGE, "Allow", ACCEPT_HEADER);
	freeSafe(string);

	FORBIDDEN_PAGE = createStaticFileName("HTTP_FORBIDDEN.html");
	NOT_FOUND_PAGE = createStaticFileName("HTTP_NOT_FOUND.html");
	BAD_REQUEST_PAGE = createStaticFileName("HTTP_BAD_REQUEST.html");
	INSUFFICIENT_STORAGE_PAGE = createStaticFileName("HTTP_INSUFFICIENT_STORAGE.html");
	OPTIONS_PAGE = createStaticFileName("OPTIONS.html");
	CONFLICT_PAGE = createStaticFileName("HTTP_CONFLICT.html");
	OK_PAGE = createStaticFileName("HTTP_OK.html");
}

////////////////////////
// End Initialisation //
////////////////////////

//////////
// Main //
//////////

static int getBindAddress(struct sockaddr_in6 * address, DaemonConfig * daemon) {
	memset(address, 0, sizeof(*address));
	address->sin6_family = AF_INET6;
	address->sin6_port = htons(daemon->port);
	if (daemon->host) {
		struct hostent * host = gethostbyname(daemon->host);
		if (!host) {
			stdLogError(errno, "Could not determine ip for hostname %s", daemon->host);
			return 0;
		}
		if (host->h_addrtype == AF_INET) {
			unsigned char addrBytes[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF };
			memcpy(&addrBytes[12], host->h_addr_list[0], 4);
			memcpy(&address->sin6_addr, addrBytes, 16);
		} else if (host->h_addrtype == AF_INET6) {
			memcpy(&address->sin6_addr, host->h_addr_list[0], 16);
		} else {
			stdLogError(0, "Could not determin address type for %s", daemon->host);
		}
	} else {
		address->sin6_addr = in6addr_any;
	}
	return 1;
}

static void runServer() {
	initializeLogs();
	initializeStaticResponses();
	initializeRapDatabase();
	initializeSSL();

	// Start up the daemons

	daemons = mallocSafe(sizeof(*daemons) * config.daemonCount);
	for (int i = 0; i < config.daemonCount; i++) {
		struct sockaddr_in6 address;
		if (getBindAddress(&address, &config.daemons[i])) {
			MHD_AccessHandlerCallback callback;
			if (config.daemons[i].forwardToPort) {
				callback = &answerForwardToRequest;
			} else {
				callback = &answerToRequest;
			}

			if (config.daemons[i].sslEnabled) {
				// https
				if (sslCertificateCount == 0) {
					stdLogError(0, "No certificates available for ssl %s:%d",
							config.daemons[i].host ? config.daemons[i].host : "", config.daemons[i].port);
					continue;
				}
				daemons[i] = MHD_start_daemon(
						MHD_USE_THREAD_PER_CONNECTION | MHD_USE_DUAL_STACK | MHD_USE_PEDANTIC_CHECKS | MHD_USE_SSL,
						0 /* ignored */, NULL, NULL,                     //
						callback, &config.daemons[i],                    //
						MHD_OPTION_SOCK_ADDR, &address,                  // Specifies both host and port
						MHD_OPTION_HTTPS_CERT_CALLBACK, &sslSNICallback, // enable ssl
						MHD_OPTION_PER_IP_CONNECTION_LIMIT, config.maxConnectionsPerIp, //
						MHD_OPTION_END);
			} else {
				// http
				daemons[i] = MHD_start_daemon(
						MHD_USE_THREAD_PER_CONNECTION | MHD_USE_DUAL_STACK | MHD_USE_PEDANTIC_CHECKS, 0 /* ignored */,
						NULL, NULL,                                      //
						callback, &config.daemons[i],                    //
						MHD_OPTION_SOCK_ADDR, &address,                  // Specifies both host and port
						MHD_OPTION_PER_IP_CONNECTION_LIMIT, config.maxConnectionsPerIp, //
						MHD_OPTION_END);
			}
			if (!daemons[i]) {
				stdLogError(errno, "Unable to initialise daemon on port %d", config.daemons[i].port);
			}
		}
	}

	pthread_exit(NULL);
}

int main(int argCount, char ** args) {
	int configCount = 0;
	WebdavdConfiguration * loadedConfig = NULL;
	if (argCount > 1) {
		for (int i = 1; i < argCount; i++) {
			configure(&loadedConfig, &configCount, args[i]);
		}
	} else {
		configure(&loadedConfig, &configCount, "/etc/webdavd");
	}

	for (int i = configCount - 1; i >= 0; i--) {
		int pid;
		// TODO fork on first

		// This code deiberately doesn't fork for the first process
		// and instead uses the main process for the first <server> in the config file.
		if (!i || !(pid = fork())) {
			for (int j = 0; j < configCount; j++) {
				if (j != i) {
					freeConfigurationData(&loadedConfig[j]);
				}
			}

			config = loadedConfig[i];
			runServer();

			stdLogError(errno, "Initialization thread did not self kill");
			exit(1);
		} else {
			if (pid < 0) {
				stdLogError(errno, "Could not fork");
			}
		}
	}
	return 0;
}

//////////////
// End Main //
//////////////
