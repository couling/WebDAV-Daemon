// TODO auth modes other than basic?
// TODO correct failure codes on collections
// TODO single root parent with multiple configured server processes
// TODO protect RAP sessions from DOS attack using a lock per user
// TODO check into what happens when a connection is closed early.

#include "shared.h"
#include "configuration.h"

#include <errno.h>
#include <fcntl.h>
#include <gnutls/abstract.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <limits.h>
#include <microhttpd.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netdb.h>

////////////////
// Structures //
////////////////

struct RestrictedAccessProcessor {
	int rapSessionInUse;
	time_t rapCreated;
	int pid;
	int socketFd;
	const char * user;
	int writeDataFd;
	int readDataFd;
	int responseAlreadyGiven;
};

struct RapGroup {
	const char * user;
	const char * password;
	struct RestrictedAccessProcessor * rapSession;
};

struct Header {
	const char * key;
	const char * value;
};

struct SSLCertificate {
	const char * hostname;
	int certCount;
	gnutls_pcert_st * certs;
	gnutls_privkey_t key;
};

////////////////////
// End Structures //
////////////////////

#define ACCEPT_HEADER "OPTIONS, GET, HEAD, DELETE, PROPFIND, PUT, PROPPATCH, COPY, MOVE" //, LOCK, UNLOCK"

static struct MHD_Response * INTERNAL_SERVER_ERROR_PAGE;
static struct MHD_Response * UNAUTHORIZED_PAGE;
static struct MHD_Response * METHOD_NOT_SUPPORTED_PAGE;

const char * FORBIDDEN_PAGE;
const char * NOT_FOUND_PAGE;
const char * BAD_REQUEST_PAGE;
const char * INSUFFICIENT_STORAGE_PAGE;
const char * OPTIONS_PAGE;
const char * CONFLICT_PAGE;
const char * OK_PAGE;

// Used as a place holder for failed auth requests which failed due to invalid credentials
static const struct RestrictedAccessProcessor AUTH_FAILED_RAP = { .pid = 0, .socketFd = -1, .user = "<auth failed>",
		.writeDataFd = -1, .readDataFd = -1, .responseAlreadyGiven = 1 };

// Used as a place holder for failed auth requests which failed due to errors
static const struct RestrictedAccessProcessor AUTH_ERROR_RAP = { .pid = 0, .socketFd = -1, .user = "<auth error>",
		.writeDataFd = -1, .readDataFd = -1, .responseAlreadyGiven = 1 };

static const struct RestrictedAccessProcessor AUTH_ERROR_BACKOFF = { .pid = 0, .socketFd = -1, .user = "<backoff>",
		.writeDataFd = -1, .readDataFd = -1, .responseAlreadyGiven = 1 };

#define AUTH_FAILED ((struct RestrictedAccessProcessor *)&AUTH_FAILED_RAP)
#define AUTH_ERROR ((struct RestrictedAccessProcessor *)&AUTH_ERROR_RAP)
#define AUTH_BACKOFF ((struct RestrictedAccessProcessor *)&AUTH_ERROR_BACKOFF)

static int sslCertificateCount;
static struct SSLCertificate * sslCertificates = NULL;

static sem_t rapDBLock;
static int rapDBSize;
static struct RapGroup * rapDB;

struct WebdavdConfiguration config;

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
		int errorLog = open(config.errorLog, O_CREAT | O_APPEND | O_WRONLY, 420);
		if (errorLog == -1 || dup2(errorLog, STDERR_FILENO) == -1) {
			stdLogError(errno, "Could not open error log file %s", config.errorLog);
			exit(1);
		}
		close(errorLog);
	}

	if (config.accessLog) {
		int accessLogFd = open(config.accessLog, O_CREAT | O_APPEND | O_WRONLY, 420);
		if (accessLogFd == -1 || dup2(accessLogFd, STDOUT_FILENO) == -1) {
			stdLogError(errno, "Could not open access log file %s", config.accessLog);
			exit(1);
		}
	}

}

static void getRequestIP(char * buffer, size_t bufferSize, struct MHD_Connection * request) {
	const struct sockaddr * addressInfo =
			MHD_get_connection_info(request, MHD_CONNECTION_INFO_CLIENT_ADDRESS)->client_addr;
	static unsigned char IPV4_PREFIX[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF };
	unsigned char * address;
	switch (addressInfo->sa_family) {
	case AF_INET: {
		struct sockaddr_in * v4Address = (struct sockaddr_in *) addressInfo;
		unsigned char * address = (unsigned char *) (&v4Address->sin_addr);
		PRINT_IPV4: snprintf(buffer, bufferSize, "%d.%d.%d.%d", address[0], address[1], address[2], address[3]);
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

		// TODO find the unix user of the socket
		/*
		 case AF_UNIX: {
		 struct sockaddr_un * unixAddress = (struct sockaddr_in6 *)addressInfo;
		 break;
		 }*/

	default:
		snprintf(buffer, bufferSize, "<unknown address>");
	}
}

static int filterGetHeader(struct Header * header, enum MHD_ValueKind kind, const char *key, const char *value) {
	if (!strcmp(key, header->key)) {
		header->value = value;
		return MHD_NO;
	}
	return MHD_YES;
}

static const char * getHeader(struct MHD_Connection *request, const char * headerKey) {
	struct Header header = { .key = headerKey, .value = NULL };
	MHD_get_connection_values(request, MHD_HEADER_KIND, (MHD_KeyValueIterator) &filterGetHeader, &header);
	return header.value;
}

/////////////////
// End Utility //
/////////////////

/////////
// SSL //
/////////

int sslCertificateCompareHost(const void * a, const void * b) {
	struct SSLCertificate * lhs = (struct SSLCertificate *) a;
	struct SSLCertificate * rhs = (struct SSLCertificate *) b;
	return strcmp(lhs->hostname, rhs->hostname);
}

struct SSLCertificate * findCertificateForHost(const char * hostname) {
	// TODO deal with wildcard certificates.
	struct SSLCertificate toFind = { .hostname = hostname };
	return bsearch(&toFind, sslCertificates, sslCertificateCount, sizeof(struct SSLCertificate),
			&sslCertificateCompareHost);
}

int sslSNICallback(gnutls_session_t session, const gnutls_datum_t* req_ca_dn, int nreqs,
		const gnutls_pk_algorithm_t* pk_algos, int pk_algos_length, gnutls_pcert_st** pcert, unsigned int *pcert_length,
		gnutls_privkey_t * pkey) {

	struct SSLCertificate * found = NULL;

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

int loadSSLCertificateFile(const char * fileName, gnutls_x509_crt_t * x509Certificate, gnutls_pcert_st * cert) {
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
		free(certData.data);
		return ret;
	}

	ret = gnutls_x509_crt_import(*x509Certificate, &certData, GNUTLS_X509_FMT_PEM);
	free(certData.data);
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

int loadSSLKeyFile(const char * fileName, gnutls_privkey_t * key) {
	size_t fileSize;
	gnutls_datum_t keyData;
	keyData.data = loadFileToBuffer(fileName, &fileSize);
	if (!keyData.data) {
		return -1;
	}

	keyData.size = fileSize;

	int ret = gnutls_privkey_init(key);
	if (ret < 0) {
		free(keyData.data);
		return ret;
	}

	ret = gnutls_privkey_import_x509_raw(*key, &keyData, GNUTLS_X509_FMT_PEM, NULL, 0);
	free(keyData.data);
	if (ret < 0) {
		gnutls_privkey_deinit(*key);
	}

	return ret;
}

int loadSSLCertificate(struct SSLConfig * sslConfig) {
	// Now load the files in earnest
	struct SSLCertificate newCertificate;
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
			free(newCertificate.certs);
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
		free(newCertificate.certs);
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
			sslCertificates = reallocSafe(sslCertificates, sslCertificateCount);
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
		free(newCertificate.certs);
		return -1;
	}

	return 0;
}

void initializeSSL() {
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

static void addHeaderSafe(struct MHD_Response * response, const char * headerKey, const char * headerValue) {
	if (headerValue == NULL) {
		stdLogError(0, "Attempt to add null value as header %s:", headerKey);
		return;
	}
	if (MHD_add_response_header(response, headerKey, headerValue) != MHD_YES) {
		stdLogError(errno, "Could not add response header %s: %s", headerKey, headerValue);
		exit(255);
	}
}

static void addStaticHeaders(struct MHD_Response * response) {
	// TODO corect this header
	addHeaderSafe(response, "DAV", "1");
	addHeaderSafe(response, "Accept-Ranges", "bytes");
	addHeaderSafe(response, "Keep-Alive", "timeout=30");
	addHeaderSafe(response, "Connection", "Keep-Alive");
	addHeaderSafe(response, "Server", "couling-webdavd");
	addHeaderSafe(response, "Expires", "Thu, 19 Nov 1981 08:52:00 GMT");
	addHeaderSafe(response, "Cache-Control", "no-store, no-cache, must-revalidate, post-check=0, pre-check=0");
	addHeaderSafe(response, "Pragma", "no-cache");
}

static ssize_t fdContentReader(int *fd, uint64_t pos, char *buf, size_t max) {
	size_t bytesRead = read(*fd, buf, max);
	if (bytesRead < 0) {
		stdLogError(errno, "Could not read content from fd");
		return MHD_CONTENT_READER_END_WITH_ERROR;
	}
	if (bytesRead == 0) {
		return MHD_CONTENT_READER_END_OF_STREAM;
	}
	while (bytesRead < max) {
		size_t newBytesRead = read(*fd, buf + bytesRead, max - bytesRead);
		if (newBytesRead <= 0) {
			break;
		}
		bytesRead += newBytesRead;
	}
	return bytesRead;
}

static void fdContentReaderCleanup(int *fd) {
	close(*fd);
	free(fd);
}

static struct MHD_Response * createFdStreamResponse(int fd, const char * mimeType, time_t date) {
	int * fdAllocated = mallocSafe(sizeof(int));
	*fdAllocated = fd;
	struct MHD_Response * response = MHD_create_response_from_callback(-1, 4096,
			(MHD_ContentReaderCallback) &fdContentReader, fdAllocated,
			(MHD_ContentReaderFreeCallback) &fdContentReaderCleanup);
	if (!response) {
		free(fdAllocated);
		return NULL;
	}
	char dateBuf[100];
	getWebDate(date, dateBuf, 100);
	addHeaderSafe(response, "Date", dateBuf);
	if (mimeType != NULL) {
		addHeaderSafe(response, "Content-Type", mimeType);
	}
	addStaticHeaders(response);
	return response;
}

static struct MHD_Response * createFdFileResponse(off_t offset, size_t size, int fd, const char * mimeType, time_t date) {
	struct MHD_Response * response = MHD_create_response_from_fd_at_offset(size, fd, offset);
	if (!response) {
		close(fd);
		return NULL;
	}
	char dateBuf[100];
	getWebDate(date, dateBuf, 100);
	addHeaderSafe(response, "Date", dateBuf);
	if (mimeType != NULL) {
		addHeaderSafe(response, "Content-Type", mimeType);
	}
	addStaticHeaders(response);
	return response;
}

static struct MHD_Response * createFileResponse(struct MHD_Connection *request, const char * fileName,
		const char * mimeType) {
	int fd = open(fileName, O_RDONLY);
	if (fd == -1) {
		stdLogError(errno, "Could not open file for response", fileName);
		return NULL;
	}

	struct stat statBuffer;
	fstat(fd, &statBuffer);
	return createFdFileResponse(0, statBuffer.st_size, fd, mimeType, statBuffer.st_mtime);
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

static int createRapResponse(struct MHD_Connection *request, struct Message * message, struct MHD_Response ** response) {
	// Queue the response
	switch (message->mID) {
	case RAP_MULTISTATUS:
	case RAP_SUCCESS: {
		if (message->fd == -1) {
			*response = createFileResponse(request, OK_PAGE, "text/html");
			return MHD_HTTP_OK;
		}

		// Get Mime type and date
		const char * mimeType = iovecToString(&message->buffers[RAP_FILE_INDEX]);
		time_t date = *((time_t *) message->buffers[RAP_DATE_INDEX].iov_base);

		struct stat stat;
		fstat(message->fd, &stat);

		int statusCode;
		if ((stat.st_mode & S_IFMT) == S_IFREG) {
			if (message->mID == RAP_SUCCESS) {
				const char * rangeHeader = getHeader(request, "Range");
				off_t offset = 0;
				size_t fileSize = stat.st_size;
				if (rangeHeader && processRangeHeader(&offset, &fileSize, rangeHeader)) {
					statusCode = MHD_HTTP_PARTIAL_CONTENT;
					*response = createFdFileResponse(0, stat.st_size, message->fd, mimeType, date);
				} else {
					statusCode = MHD_HTTP_OK;
					*response = createFdFileResponse(0, stat.st_size, message->fd, mimeType, date);
				}
				char contentRangeHeader[200];

				snprintf(contentRangeHeader, sizeof(contentRangeHeader), "bytes %lld-%lld/%lld", (long long) offset,
						(long long) (fileSize + offset), (long long) stat.st_size);

				addHeaderSafe(*response, "Content-Range", contentRangeHeader);
			} else {
				statusCode = 207;
				*response = createFdFileResponse(0, stat.st_size, message->fd, mimeType, date);
			}
		} else {
			statusCode = message->mID == RAP_SUCCESS ? MHD_HTTP_OK : 207;
			*response = createFdStreamResponse(message->fd, mimeType, date);
		}

		if (message->bufferCount > RAP_LOCATION_INDEX) {
			addHeaderSafe(*response, "Location", iovecToString(&message->buffers[RAP_LOCATION_INDEX]));
		}

		return statusCode;
	}

	case RAP_ACCESS_DENIED:
		*response = createFileResponse(request, FORBIDDEN_PAGE, "text/html");
		return MHD_HTTP_FORBIDDEN;

	case RAP_NOT_FOUND:
		*response = createFileResponse(request, NOT_FOUND_PAGE, "text/html");
		return MHD_HTTP_NOT_FOUND;

	case RAP_BAD_CLIENT_REQUEST:
		*response = createFileResponse(request, BAD_REQUEST_PAGE, "text/html");
		return MHD_HTTP_BAD_REQUEST;

	case RAP_INSUFFICIENT_STORAGE:
		*response = createFileResponse(request, INSUFFICIENT_STORAGE_PAGE, "text/html");
		return MHD_HTTP_INSUFFICIENT_STORAGE;

	case RAP_CONFLICT:
		*response = createFileResponse(request, CONFLICT_PAGE, "text/html");
		return MHD_HTTP_CONFLICT;

	default:
		stdLogError(0, "invalid response from RAP %d", (int) message->mID);
		/* no break */

	case RAP_BAD_RAP_REQUEST:
	case RAP_INTERNAL_ERROR:
		return MHD_HTTP_INTERNAL_SERVER_ERROR;
	}

}

///////////////////////////
// End Response Queueing //
///////////////////////////

////////////////////
// RAP Processing //
////////////////////

// TODO change database to thread based.
// that will remove the need for locking as well as binding a RAP to a connection

static int forkRapProcess(const char * path, int * newSockFd) {
	// Create unix domain socket for
	int sockFd[2];
	int result = socketpair(PF_LOCAL, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockFd);
	if (result != 0) {
		stdLogError(errno, "Could not create socket pair");
		return 0;
	}

	result = fork();

	if (result) {
		// parent
		close(sockFd[1]);
		if (result != -1) {
			*newSockFd = sockFd[0];
			//stdLog("New RAP %d on %d", result, sockFd[0]);
			return result;
		} else {
			// fork failed so close parent pipes and return non-zero
			close(sockFd[0]);
			stdLogError(errno, "Could not fork");
			return 0;
		}
	} else {
		// child
		// Sort out socket
		//stdLog("Starting rap: %s", path);
		if (dup2(sockFd[1], STDIN_FILENO) == -1 || dup2(sockFd[1], STDOUT_FILENO) == -1) {
			stdLogError(errno, "Could not assign new socket (%d) to stdin/stdout", newSockFd[1]);
			exit(255);
		}
		char * argv[] =
				{ (char *) config.rapBinary, (char *) config.pamServiceName, (char *) config.mimeTypesFile, NULL };
		execv(path, argv);
		stdLogError(errno, "Could not start rap: %s", path);
		exit(255);
	}
}

static void destroyRap(struct RestrictedAccessProcessor * processor) {
	close(processor->socketFd);
	processor->socketFd = -1;
}

static struct RestrictedAccessProcessor * createRap(struct RestrictedAccessProcessor * processor, const char * user,
		const char * password, const char * rhost) {

	processor->pid = forkRapProcess(config.rapBinary, &(processor->socketFd));
	if (!processor->pid) {
		return AUTH_ERROR;
	}

	struct Message message;
	message.mID = RAP_AUTHENTICATE;
	message.fd = -1;
	message.bufferCount = 3;
	message.buffers[RAP_USER_INDEX].iov_len = strlen(user) + 1;
	message.buffers[RAP_USER_INDEX].iov_base = (void *) user;
	message.buffers[RAP_PASSWORD_INDEX].iov_len = strlen(password) + 1;
	message.buffers[RAP_PASSWORD_INDEX].iov_base = (void *) password;
	message.buffers[RAP_RHOST_INDEX].iov_len = strlen(rhost) + 1;
	message.buffers[RAP_RHOST_INDEX].iov_base = (void *) rhost;

	if (sendMessage(processor->socketFd, &message) <= 0) {
		destroyRap(processor);
		return AUTH_ERROR;
	}

	char incomingBuffer[INCOMING_BUFFER_SIZE];
	ssize_t readResult = recvMessage(processor->socketFd, &message, incomingBuffer, INCOMING_BUFFER_SIZE);
	if (readResult <= 0 || message.mID != RAP_SUCCESS) {
		destroyRap(processor);
		if (readResult < 0) {
			stdLogError(0, "Could not read result from RAP ");
			return AUTH_ERROR;
		} else if (readResult == 0) {
			stdLogError(0, "RAP closed socket unexpectedly");
			return AUTH_ERROR;
		} else {
			stdLogError(0, "Access denied for user %s", user);
			return AUTH_FAILED;
		}
	}

	processor->user = user;
	time(&processor->rapCreated);

	return processor;
}

static int compareRapGroup(const void * rapA, const void * rapB) {
	int result = strcmp(((struct RapGroup *) rapA)->user, ((struct RapGroup *) rapB)->user);
	if (result == 0) {
		result = strcmp(((struct RapGroup *) rapA)->password, ((struct RapGroup *) rapB)->password);
	}
	return result;
}

static struct RestrictedAccessProcessor * acquireRapFromDb(const char * user, const char * password,
		int * activeSessions) {
	struct RapGroup groupToFind = { .user = user, .password = password };
	sem_wait(&rapDBLock);
	struct RapGroup *groupFound = bsearch(&groupToFind, rapDB, rapDBSize, sizeof(struct RapGroup), &compareRapGroup);
	struct RestrictedAccessProcessor * rapSessionFound = NULL;
	*activeSessions = 0;
	if (groupFound) {
		time_t expireTime;
		time(&expireTime);
		expireTime -= config.rapMaxSessionLife;
		for (int i = 0; i < config.rapMaxSessionsPerUser; i++) {
			if (groupFound->rapSession[i].socketFd != -1 && !groupFound->rapSession[i].rapSessionInUse
					&& groupFound->rapSession[i].rapCreated >= expireTime) {
				rapSessionFound = &groupFound->rapSession[i];
				groupFound->rapSession[i].rapSessionInUse = 1;
				(*activeSessions)++;
				break;
			} else if (groupFound->rapSession[i].rapSessionInUse) {
				(*activeSessions)++;
			}
		}
	}
	sem_post(&rapDBLock);
	return rapSessionFound;
}

static struct RestrictedAccessProcessor * addRapToDb(struct RestrictedAccessProcessor * rapSession,
		const char * password) {
	struct RestrictedAccessProcessor * newRapSession;
	struct RapGroup groupToFind;
	groupToFind.user = rapSession->user;
	groupToFind.password = password;
	sem_wait(&rapDBLock);
	struct RapGroup *groupFound = bsearch(&groupToFind, rapDB, rapDBSize, sizeof(struct RapGroup), &compareRapGroup);
	if (groupFound) {
		newRapSession = NULL;
		time_t expireTime;
		time(&expireTime);
		expireTime -= config.rapMaxSessionLife;
		for (int i = 0; i < config.rapMaxSessionsPerUser; i++) {
			if (groupFound->rapSession[i].socketFd == -1) {
				newRapSession = &groupFound->rapSession[i];
				break;
			} else if (groupFound->rapSession[i].rapCreated < expireTime
					&& !groupFound->rapSession[i].rapSessionInUse) {
				destroyRap(&groupFound->rapSession[i]);
				newRapSession = &groupFound->rapSession[i];
			}
		}
		if (!newRapSession) {
			destroyRap(rapSession);
			sem_post(&rapDBLock);
			return AUTH_BACKOFF;
		}
	} else {
		rapDBSize++;
		rapDB = reallocSafe(rapDB, rapDBSize * sizeof(struct RapGroup));
		groupFound = &rapDB[rapDBSize - 1];
		size_t userSize = strlen(groupToFind.user) + 1;
		size_t passwordSize = strlen(groupToFind.password) + 1;
		size_t bufferSize = userSize + passwordSize;
		char * buffer = mallocSafe(bufferSize);
		memcpy(buffer, groupToFind.user, userSize);
		memcpy(buffer + userSize, groupToFind.password, passwordSize);
		groupFound->user = buffer;
		groupFound->password = buffer + userSize;
		groupFound->rapSession = mallocSafe(sizeof(struct RestrictedAccessProcessor) * config.rapMaxSessionsPerUser);
		memset(groupFound->rapSession, 0, sizeof(struct RestrictedAccessProcessor) * config.rapMaxSessionsPerUser);
		for (int i = 1; i < config.rapMaxSessionsPerUser; i++) {
			groupFound->rapSession[i].socketFd = -1;
		}
		newRapSession = &groupFound->rapSession[0];

		for (int i = 1; i < config.rapMaxSessionsPerUser; i++) {

		}
		qsort(rapDB, rapDBSize, sizeof(struct RapGroup), &compareRapGroup);
	}
	*newRapSession = *rapSession;
	newRapSession->user = groupFound->user;
	newRapSession->rapSessionInUse = 1;
	sem_post(&rapDBLock);
	return newRapSession;
}

static void releaseRap(struct RestrictedAccessProcessor * processor) {
	processor->rapSessionInUse = 0;
}

static struct RestrictedAccessProcessor * acquireRap(struct MHD_Connection *request) {
	char * user;
	char * password;
	user = MHD_basic_auth_get_username_password(request, &password);
	if (user && password) {
		int sessionCount;
		struct RestrictedAccessProcessor * rapSession = acquireRapFromDb(user, password, &sessionCount);
		if (rapSession) {
			return rapSession;
		} else {
			if (sessionCount < config.rapMaxSessionsPerUser) {
				char rhost[100];
				getRequestIP(rhost, sizeof(rhost), request);

				struct RestrictedAccessProcessor newSession;
				rapSession = createRap(&newSession, user, password, rhost);
				if (rapSession != &newSession) {
					return rapSession;
				} else {
					return addRapToDb(rapSession, password);
				}
			} else {
				return AUTH_BACKOFF;
			}
		}
	} else {
		stdLogError(0, "Rejecting request without auth");
		return AUTH_FAILED;
	}
}

static void cleanupAfterRap(int sig, siginfo_t *siginfo, void *context) {
	int status;
	waitpid(siginfo->si_pid, &status, 0);
	if (status == 139) {
		stdLogError(0, "RAP %d failed with segmentation fault", siginfo->si_pid);
	}
	//stdLog("Child finished PID: %d staus: %d", siginfo->si_pid, status);
}

static void * rapTimeoutWorker(void * ignored) {
	// TODO actually free() something
	while (1) {
		sleep(config.rapMaxSessionLife / 2);
		time_t expireTime;
		time(&expireTime);
		expireTime -= config.rapMaxSessionLife;
		sem_wait(&rapDBLock);
		for (int group = 0; group < rapDBSize; group++) {
			for (int rap = 0; rap < config.rapMaxSessionsPerUser; rap++) {
				if (!rapDB[group].rapSession[rap].rapSessionInUse && rapDB[group].rapSession[rap].socketFd != -1
						&& rapDB[group].rapSession[rap].rapCreated < expireTime) {
					destroyRap(&rapDB[group].rapSession[rap]);
				}
			}
		}
		sem_post(&rapDBLock);
	}
	return NULL;
}

static void initializeRapDatabase() {
	struct sigaction act;
	memset(&act, 0, sizeof(act));
	act.sa_sigaction = &cleanupAfterRap;
	act.sa_flags = SA_SIGINFO;
	if (sigaction(SIGCHLD, &act, NULL) < 0) {
		stdLogError(errno, "Could not set handler method for finished child threads");
		exit(255);
	}

	sem_init(&rapDBLock, 0, 1);

	rapDBSize = 0;
	rapDB = NULL;

	pthread_t newThread;
	if (pthread_create(&newThread, NULL, &rapTimeoutWorker, NULL)) {
		stdLogError(errno, "Could not create worker thread for rap db");
		exit(255);
	}
}

////////////////////////
// End RAP Processing //
////////////////////////

///////////////////////////////////////
// Low Level HTTP handling (Signpost //
///////////////////////////////////////

static int completeUpload(struct MHD_Connection *request, struct RestrictedAccessProcessor * processor,
		struct MHD_Response ** response) {

	if (processor->writeDataFd == -1) {
		close(processor->writeDataFd);
		processor->writeDataFd = -1;
	}
	// Closing this pipe signals to the rap that there is no more data
	// This MUST happen before the recvMessage a few lines below or the RAP
	// will NOT send a message and recvMessage will hang.
	close(processor->writeDataFd);
	processor->writeDataFd = -1;
	struct Message message;
	char incomingBuffer[INCOMING_BUFFER_SIZE];
	int readResult = recvMessage(processor->socketFd, &message, incomingBuffer, INCOMING_BUFFER_SIZE);
	if (readResult <= 0) {
		if (readResult == 0) {
			stdLogError(0, "RAP closed socket unexpectedly while waiting for response");
		}
		return MHD_HTTP_INTERNAL_SERVER_ERROR;
	}

	if (readResult > 0) {
		return createRapResponse(request, &message, response);
	} else {
		return MHD_HTTP_INTERNAL_SERVER_ERROR;
	}
}

static void processUploadData(struct MHD_Connection * request, const char * upload_data, size_t upload_data_size,
		struct RestrictedAccessProcessor * processor) {

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

static int processNewRequest(struct MHD_Connection * request, const char * url, const char * host, const char * method,
		struct RestrictedAccessProcessor * rapSession, struct MHD_Response ** response) {

	// Interpret the method
	struct Message message;
	message.fd = rapSession->readDataFd;
	message.buffers[RAP_HOST_INDEX].iov_len = strlen(host) + 1;
	message.buffers[RAP_HOST_INDEX].iov_base = (void *) host;
	message.buffers[RAP_FILE_INDEX].iov_len = strlen(url) + 1;
	message.buffers[RAP_FILE_INDEX].iov_base = (void *) url;
	// TODO PUT
	// TODO PROPPATCH
	// TODO MKCOL
	// TODO HEAD
	// TODO DELETE
	// TODO COPY
	// TODO MOVE
	// TODO LOCK
	// TODO UNLOCK
	//stdLog("%s %s data", method, writeHandle ? "with" : "without");
	if (!strcmp("GET", method)) {
		message.mID = RAP_READ_FILE;
		message.bufferCount = 2;
	} else if (!strcmp("PROPFIND", method)) {
		message.mID = RAP_PROPFIND;
		const char * depth = getHeader(request, "Depth");
		if (depth) {
			message.buffers[RAP_DEPTH_INDEX].iov_base = (void *) depth;
			message.buffers[RAP_DEPTH_INDEX].iov_len = strlen(depth) + 1;
		} else {
			message.buffers[RAP_DEPTH_INDEX].iov_base = "infinity";
			message.buffers[RAP_DEPTH_INDEX].iov_len = sizeof("infinity");
		}
		message.bufferCount = 3;
	} else if (!strcmp("OPTIONS", method)) {
		*response = createFileResponse(request, OPTIONS_PAGE, "text/html");
		addHeaderSafe(*response, "Accept", ACCEPT_HEADER);
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
		return MHD_HTTP_CONTINUE;
	} else {
		return createRapResponse(request, &message, response);
	}
}

static int requestHasData(struct MHD_Connection *request) {
	if (getHeader(request, "Content-Length")) {
		return 1;
	} else {
		const char * te = getHeader(request, "Transfer-Encoding");
		return te && !strcmp(te, "chunked");
	}
}

static int sendResponse(struct MHD_Connection *request, int statusCode, struct MHD_Response * response,
		struct RestrictedAccessProcessor * rapSession, const char * method, const char * url) {

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

static int answerToRequest(void *cls, struct MHD_Connection *request, const char *url, const char *method,
		const char *version, const char *upload_data, size_t *upload_data_size, void ** s) {

	struct RestrictedAccessProcessor ** rapSession = (struct RestrictedAccessProcessor **) s;

	if (*rapSession) {
		if (*upload_data_size) {
			// Finished uploading data
			if (!(*rapSession)->responseAlreadyGiven) {
				processUploadData(request, upload_data, *upload_data_size, *rapSession);
			}
			*upload_data_size = 0;
			return MHD_YES;
		} else {
			// Uploading more data
			if ((*rapSession)->responseAlreadyGiven) {
				releaseRap(*rapSession);
				return MHD_YES;
			} else {
				struct MHD_Response * response;
				int statusCode = completeUpload(request, *rapSession, &response);
				int result = sendResponse(request, statusCode, response, *rapSession, method, url);
				if (*rapSession != AUTH_ERROR && *rapSession != AUTH_FAILED) {
					releaseRap(*rapSession);
				}
				return result;
			}
		}
	} else {
		const char * host = getHeader(request, "Host");
		if (host == NULL) {
			// TODO something more meaningful here.
			host = "";
		}

		// Authenticate all new requests regardless of anything else
		*rapSession = acquireRap(request);
		if (*rapSession == AUTH_FAILED || *rapSession == AUTH_BACKOFF) {
			return sendResponse(request, MHD_HTTP_UNAUTHORIZED, NULL, *rapSession, method, url);
		} else if (*rapSession == AUTH_ERROR) {
			return sendResponse(request, MHD_HTTP_INTERNAL_SERVER_ERROR, NULL, *rapSession, method, url);
		} else {
			if (requestHasData(request)) {
				// If we have data to send then create a pipe to pump it through
				int pipeEnds[2];
				if (pipe(pipeEnds)) {
					stdLogError(errno, "Could not create write pipe");
					return sendResponse(request, MHD_HTTP_INTERNAL_SERVER_ERROR, NULL, *rapSession, method, url);
				}
				(*rapSession)->readDataFd = pipeEnds[PIPE_READ];
				(*rapSession)->writeDataFd = pipeEnds[PIPE_WRITE];
				struct MHD_Response * response;

				int statusCode = processNewRequest(request, url, host, method, *rapSession, &response);

				if (statusCode == MHD_HTTP_CONTINUE) {
					// do not queue a response for contiune
					(*rapSession)->responseAlreadyGiven = 0;
					//logAccess(statusCode, method, (*rapSession)->user, url);
					return MHD_YES;
				} else {
					(*rapSession)->responseAlreadyGiven = 1;
					return sendResponse(request, statusCode, response, *rapSession, method, url);
				}
			} else {
				(*rapSession)->readDataFd = -1;
				(*rapSession)->writeDataFd = -1;
				struct MHD_Response * response;

				int statusCode = processNewRequest(request, url, host, method, *rapSession, &response);

				if (statusCode == MHD_HTTP_CONTINUE) {
					stdLogError(0, "RAP returned CONTINUE when there is no data");
					int ret = sendResponse(request, MHD_HTTP_INTERNAL_SERVER_ERROR, NULL, *rapSession, method, url);
					releaseRap(*rapSession);
					return ret;
				} else {
					int ret = sendResponse(request, statusCode, response, *rapSession, method, url);
					releaseRap(*rapSession);
					return ret;
				}
			}
		}
	}
}

static int answerForwardToRequest(void *cls, struct MHD_Connection *request, const char *url, const char *method,
		const char *version, const char *upload_data, size_t *upload_data_size, void ** s) {
	if (*s != NULL) {
		return MHD_YES;
	}
	*s = cls;

	struct DaemonConfig * daemon = (struct DaemonConfig *) cls;
	struct MHD_Response * response = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_MUST_COPY);
	if (!response) {
		stdLogError(errno, "Unable to create 301 response");
		return MHD_queue_response(request, MHD_HTTP_INTERNAL_SERVER_ERROR, INTERNAL_SERVER_ERROR_PAGE);
	}

	const char * host = daemon->forwardToHost ? daemon->forwardToHost : getHeader(request, "Host");

	if (!host) {
		// TODO fix this
		host = "localhost";
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

	addHeaderSafe(response, "Location", buffer);
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

static void initializeStaticResponse(struct MHD_Response ** response, const char * fileName, const char * mimeType) {
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
		addHeaderSafe(*response, "Content-Type", mimeType);
	}
}

static char * createStaticFile(const char * string) {
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
	string = createStaticFile("HTTP_INTERNAL_SERVER_ERROR.html");
	initializeStaticResponse(&INTERNAL_SERVER_ERROR_PAGE, string, "text/html");
	free(string);

	string = createStaticFile("HTTP_UNAUTHORIZED.html");
	initializeStaticResponse(&UNAUTHORIZED_PAGE, string, "text/html");
	addHeaderSafe(UNAUTHORIZED_PAGE, "WWW-Authenticate", "Basic realm=\"My Server\"");
	free(string);

	string = createStaticFile("HTTP_METHOD_NOT_SUPPORTED.html");
	initializeStaticResponse(&METHOD_NOT_SUPPORTED_PAGE, string, "text/html");
	addHeaderSafe(METHOD_NOT_SUPPORTED_PAGE, "Allow", ACCEPT_HEADER);
	free(string);

	FORBIDDEN_PAGE = createStaticFile("HTTP_FORBIDDEN.html");
	NOT_FOUND_PAGE = createStaticFile("HTTP_NOT_FOUND.html");
	BAD_REQUEST_PAGE = createStaticFile("HTTP_BAD_REQUEST.html");
	INSUFFICIENT_STORAGE_PAGE = createStaticFile("HTTP_INSUFFICIENT_STORAGE.html");
	OPTIONS_PAGE = createStaticFile("OPTIONS.html");
	CONFLICT_PAGE = createStaticFile("HTTP_CONFLICT.html");
	OK_PAGE = createStaticFile("HTTP_OK.html");
}

////////////////////////
// End Initialisation //
////////////////////////

//////////
// Main //
//////////

static int getBindAddress(struct sockaddr_in6 * address, int port, const char * bindAddress) {
	memset(address, 0, sizeof(*bindAddress));
	address->sin6_family = AF_INET6;
	address->sin6_port = htons(port);
	if (bindAddress) {
		struct hostent * host = gethostbyname(bindAddress);
		if (!host) {
			stdLogError(errno, "Could not determine ip for hostname %s", bindAddress);
			return 0;
		}
		if (host->h_addrtype == AF_INET) {
			unsigned char addrBytes[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF };
			memcpy(&addrBytes[12], host->h_addr_list[0], 4);
			memcpy(&address->sin6_addr, addrBytes, 16);
		} else if (host->h_addrtype == AF_INET6) {
			memcpy(&address->sin6_addr, host->h_addr_list[0], 16);
		} else {
			stdLogError(0, "Could not determin address type for %s", bindAddress);
		}
	} else {
		address->sin6_addr = in6addr_any;
	}
	return 1;
}

#define flaggs MHD_USE_THREAD_PER_CONNECTION | MHD_USE_DUAL_STACK | MHD_USE_PEDANTIC_CHECKS
int main(int argCount, char ** args) {
	if (argCount > 1) {
		for (int i = 1; i < argCount; i++) {
			configure(args[i]);
		}
	} else {
		configure("/etc/webdavd");
	}

	initializeLogs();
	initializeStaticResponses();
	initializeRapDatabase();
	initializeSSL();

	// Start up the daemons

	daemons = mallocSafe(sizeof(*daemons) * config.daemonCount);
	for (int i = 0; i < config.daemonCount; i++) {
		struct sockaddr_in6 address;
		if (getBindAddress(&address, config.daemons[i].port, config.daemons[i].host)) {
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
				daemons[i] = MHD_start_daemon(flaggs | MHD_USE_SSL, 0 /* ignored */, NULL, NULL, //
						callback, &config.daemons[i],                    //
						MHD_OPTION_SOCK_ADDR, &address,                  // Specifies both host and port
						MHD_OPTION_PER_IP_CONNECTION_LIMIT, 10,          // max connections per ip
						MHD_OPTION_HTTPS_CERT_CALLBACK, &sslSNICallback, // enable ssl
						MHD_OPTION_END);
			} else {
				// http
				daemons[i] = MHD_start_daemon(flaggs, 0 /* ignored */, NULL, NULL, //
						callback, &config.daemons[i],                    //
						MHD_OPTION_SOCK_ADDR, &address,                  // Specifies both host and port
						MHD_OPTION_PER_IP_CONNECTION_LIMIT, 10,          // max connections per ip
						MHD_OPTION_END);
			}
			if (!daemons[i]) {
				stdLogError(errno, "Unable to initialise daemon on port %d", config.daemons[i].port);
			}
		}
	}

	pthread_exit(NULL);
}

//////////////
// End Main //
//////////////
