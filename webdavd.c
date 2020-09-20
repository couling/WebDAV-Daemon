// TODO accept suggested timeout values from clients during LOCK requests

#include "shared.h"
#include "configuration.h"

#include <errno.h>
#include <fcntl.h>
#include <gnutls/abstract.h>
#include <microhttpd.h>
#include <pthread.h>
#include <search.h>
#include <semaphore.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <uuid/uuid.h>

////////////////
// Structures //
////////////////

#define MAX_SESSION_LOCKS 10

typedef char LockToken[37];

typedef struct Lock {
	const char * user;
	const char * file;
	time_t lockAcquired;
	LockType type;
	int fd;
	int useCount;
	int released;
	LockToken lockToken;
} Lock;

typedef struct MHD_Connection Request;
typedef struct MHD_Response Response;

typedef struct RAP {
	// Managed by create / destroy RAP
	int pid;
	int socketFd;
	const char * user;
	const char * password;
	const char * clientIp;

	// Managed by RAP DB
	time_t rapCreated;
	struct RAP * next;
	struct RAP ** prevPtr;

	// Managed per request
	// This is not really data about the rap at all but storing it here saves allocating an extra structure
	int requestWriteDataFd; // Should be closed by uploadComplete()
	int requestReadDataFd;  // Should be closed by processNewRequest() when sent to the RAP.
	int requestResponseAlreadyGiven;
	Response * requestResponseObjectAlreadyGiven;
	int requestLockCount;
	Lock * requestLock[MAX_SESSION_LOCKS];

} RAP;

typedef struct RapList {
	RAP * firstRapSession;
} RapList;

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

typedef struct FDResponseData {
	int fd;
	off_t pos;
	off_t offset;
	off_t size;
	RAP * session;
} FDResponseData;

////////////////////
// End Structures //
////////////////////

// Used as a place holder for failed auth requests which failed due to invalid credentials
static const RAP AUTH_FAILED_RAP = {
		.pid = 0,
		.socketFd = -1,
		.user = "<auth failed>",
		.requestWriteDataFd = -1,
		.requestReadDataFd = -1,
		.requestResponseAlreadyGiven = 401,
		.requestLockCount = 0,
		.next = NULL,
		.prevPtr = NULL };

// Used as a place holder for failed auth requests which failed due to errors
static const RAP AUTH_ERROR_RAP = {
		.pid = 0,
		.socketFd = -1,
		.user = "<auth error>",
		.requestWriteDataFd = -1,
		.requestReadDataFd = -1,
		.requestResponseAlreadyGiven = 500,
		.requestLockCount = 0,
		.next = NULL,
		.prevPtr = NULL };

static pthread_key_t rapDBThreadKey;
static sem_t rapPoolLock;
static RapList rapPool;

#define AUTH_FAILED ( ( RAP *) &AUTH_FAILED_RAP )
#define AUTH_ERROR ( ( RAP *) &AUTH_ERROR_RAP )

#define AUTH_SUCCESS(rap) (rap != AUTH_FAILED && rap != AUTH_ERROR)

static time_t lockExpiryTime;
static int lockReadyForReleaseCount;
static Lock ** readyForRelease;

// TODO create shutdown routine
static int shuttingDown = 0;

#define ACCEPT_HEADER "OPTIONS, GET, HEAD, DELETE, PROPFIND, PUT, PROPPATCH, COPY, MOVE, LOCK, UNLOCK"

static Response * INTERNAL_SERVER_ERROR_PAGE;
static Response * UNAUTHORIZED_PAGE;
static Response * METHOD_NOT_SUPPORTED_PAGE;
static Response * NO_CONTENT_PAGE;

static const char * FORBIDDEN_PAGE;
static const char * NOT_FOUND_PAGE;
static const char * BAD_REQUEST_PAGE;
static const char * INSUFFICIENT_STORAGE_PAGE;
static const char * OPTIONS_PAGE;
static const char * CONFLICT_PAGE;
static const char * OK_PAGE;

static int sslCertificateCount;
static SSLCertificate * sslCertificates = NULL;

static void * rootNode = NULL;
static sem_t lockDBLock;

// All Daemons
// Not sure why we keep these, they're not used for anything
static struct MHD_Daemon **daemons;

#define HEADER_LOCK_TOKEN "Lock-Token"
#define HEADER_DEPTH "Depth"
#define HEADER_TARGET "Destination"

/////////////
// Utility //
/////////////

static void logAccess(int statusCode, const char * method, const char * user, const char * url,
		const char * client) {
	char t[100];
	timeNow(t, sizeof(t));
	printf("%s %s %s %d %s %s\n", t, client, user, statusCode, method, url);
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
			snprintf(buffer, bufferSize, "%d.%d.%d.%d", address[sizeof(IPV4_PREFIX)],
					address[sizeof(IPV4_PREFIX) + 1], address[sizeof(IPV4_PREFIX) + 2],
					address[sizeof(IPV4_PREFIX) + 3]);
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
						bytesWritten = snprintf(buffer, bufferSize, "%x%s", *(address + i + 1),
								i < 14 ? ":" : "");
						buffer += bytesWritten;
						bufferSize -= bytesWritten;
					} else {
						bytesWritten = snprintf(buffer, bufferSize, "%x%02x%s", *(address + i),
								*(address + i + 1), i < 14 ? ":" : "");
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

static int requestHasData(Request *request) {
	if (getHeader(request, "Content-Length")) {
		return 1;
	} else {
		const char * te = getHeader(request, "Transfer-Encoding");
		return te && !strcmp(te, "chunked");
	}
}

static void parseHeaderFilePath(char * resultBuffer, size_t urlLength, const char * url) {
	if (url[0] != '/') {
		// Find the start of the path (after the http://domain.tld/)
		int count = 0;
		size_t start = 1;
		while (start < urlLength && (url[start] == '/' ? ++count : count) < 3) {
			start++;
		}
		url += start;
		urlLength -= start;
	}

	// Decode the % encoded characters
	size_t read = 0;
	size_t write = 0;
	while (read < urlLength) {
		if (url[read] != '%' || read >= urlLength - 2) {
			resultBuffer[write++] = url[read++];
		} else {
			unsigned char c;
			unsigned char c1 = url[read + 1];
			if (c1 >= '0' && c1 <= '9') c = ((c1 - '0') << 4);
			else if (c1 >= 'a' && c1 <= 'f') c = ((c1 - 'a' + 10) << 4);
			else if (c1 >= 'A' && c1 <= 'F') c = ((c1 - 'A' + 10) << 4);
			else {
				resultBuffer[write++] = url[read++];
				continue;
			}

			c1 = url[read + 2];
			if (c1 >= '0' && c1 <= '9') c |= c1 - '0';
			else if (c1 >= 'a' && c1 <= 'f') c |= c1 - 'a' + 10;
			else if (c1 >= 'A' && c1 <= 'F') c |= c1 - 'A' + 10;
			else {
				resultBuffer[write++] = url[read++];
				continue;
			}

			resultBuffer[write++] = c;
			read += 3;
		}
	}
	resultBuffer[write] = '\0';
}

/////////////////
// End Utility //
/////////////////

////////////////////
// RAP Processing //
////////////////////

static time_t getExpiryTime() {
	time_t expires;
	time(&expires);
	expires -= config.rapMaxSessionLife;
	return expires;
}

static int forkRapProcess(const char * path, int * newSockFd) {
	// Create unix domain socket for
	int sockFd[2];
	int result = socketpair(PF_LOCAL, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockFd);
	if (result != 0) {
		stdLogError(errno, "Could not create socket pair");
		return 0;
	}

	// We set this timeout so that a hung RAP will eventually clean itself up
	struct timeval timeout;
	timeout.tv_sec = config.rapTimeoutRead;
	timeout.tv_usec = 0;
	if (setsockopt(sockFd[PARENT_SOCKET], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
		stdLogError(errno, "Could not set timeout");
		close(sockFd[PARENT_SOCKET]);
		close(sockFd[CHILD_SOCKET]);
		return 0;
	}

	result = fork();
	if (result) {

		// parent
		close(sockFd[CHILD_SOCKET]);
		if (result != -1) {
			*newSockFd = sockFd[PARENT_SOCKET];
			//stdLog("New RAP %d on %d", result, sockFd[0]);
			return result;
		} else {
			// fork failed so close parent pipes and return non-zero
			close(sockFd[PARENT_SOCKET]);
			stdLogError(errno, "Could not fork");
			return 0;
		}
	} else {

		// child
		close(sockFd[PARENT_SOCKET]);
		if (sockFd[CHILD_SOCKET] == RAP_CONTROL_SOCKET) {
			// If by some chance this socket has opened as pre-defined RAP_CONTROL_SOCKET we
			// won't dup2 but we do need to remove the close-on-exec flag
			int flags = fcntl(sockFd[CHILD_SOCKET], F_GETFD);
			if (fcntl(sockFd[CHILD_SOCKET], F_SETFD, flags & ~FD_CLOEXEC) == -1) {
				stdLogError(errno, "Could not clear close-on-exec for control socket", sockFd[CHILD_SOCKET],
						(int) RAP_CONTROL_SOCKET);
				exit(255);
			}
		} else {
			// Assign the control socket to the correct FD so the RAP can use it
			// This previously abused STD_IN and STD_OUT for this but instead we now
			// reserve a different FD (3) AKA RAP_CONTROL_SOCKET
			if (dup2(sockFd[CHILD_SOCKET], RAP_CONTROL_SOCKET) == -1) {
				stdLogError(errno, "Could not assign new socket (%d) to %d", newSockFd[1],
						(int) RAP_CONTROL_SOCKET);
				exit(255);
			}
		}

		char * argv[] = {
				(char *) path,
				NULL };
		execv(path, argv);

		stdLogError(errno, "Could not start rap: %s", path);
		exit(255);
	}
}

static void removeRapFromList(RAP * rapSession) {
	*(rapSession->prevPtr) = rapSession->next;
	if (rapSession->next != NULL) {
		rapSession->next->prevPtr = rapSession->prevPtr;
	}
}

static void addRapToList(RapList * list, RAP * rapSession) {
	rapSession->next = list->firstRapSession;
	list->firstRapSession = rapSession;
	rapSession->prevPtr = &list->firstRapSession;
	if (rapSession->next) {
		rapSession->next->prevPtr = &rapSession->next;
	}
}

static void destroyRap(RAP * rapSession) {
	if (!AUTH_SUCCESS(rapSession)) {
		return;
	}
	close(rapSession->socketFd);
	if (rapSession->requestReadDataFd != -1) {
		stdLogError(0, "readDataFd was not properly closed before destroying rap");
		close(rapSession->requestReadDataFd);
	}
	if (rapSession->requestWriteDataFd != -1) {
		stdLogError(0, "writeDataFd was not properly closed before destroying rap");
		close(rapSession->requestWriteDataFd);
	}

	freeSafe((void *) rapSession->user);
	freeSafe((void *) rapSession->password);
	freeSafe((void *) rapSession->clientIp);
	removeRapFromList(rapSession);
	freeSafe(rapSession);
}

static RAP * createRap(RapList * db, const char * user, const char * password, const char * rhost) {
	int socketFd;
	int pid = forkRapProcess(config.rapBinary, &socketFd);
	if (!pid) {
		return AUTH_ERROR;
	}

	// Send Auth Request
	Message message;
	message.mID = RAP_REQUEST_AUTHENTICATE;
	message.fd = -1;
	message.paramCount = 3;
	message.params[RAP_PARAM_AUTH_USER] = stringToMessageParam(user);
	message.params[RAP_PARAM_AUTH_PASSWORD] = stringToMessageParam(password);
	message.params[RAP_PARAM_AUTH_RHOST] = stringToMessageParam(rhost);
	if (sendMessage(socketFd, &message) <= 0) {
		close(socketFd);
		return AUTH_ERROR;
	}

	// Read Auth Result
	char incomingBuffer[INCOMING_BUFFER_SIZE];
	ssize_t readResult = recvMessage(socketFd, &message, incomingBuffer, INCOMING_BUFFER_SIZE);
	if (readResult <= 0 || message.mID != RAP_RESPOND_OK) {
		close(socketFd);
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

	// If successfully authenticated then populate the RAP structure and add it to the DB
	RAP * newRap = mallocSafe(sizeof(*newRap));
	newRap->pid = pid;
	newRap->socketFd = socketFd;
	newRap->user = copyString(user);
	newRap->password = copyString(password);
	newRap->clientIp = copyString(rhost);
	time(&newRap->rapCreated);
	newRap->requestWriteDataFd = -1;
	newRap->requestReadDataFd = -1;
	addRapToList(db, newRap);
	// newRap->responseAlreadyGiven // this is set elsewhere
	return newRap;
}

// void releaseRap(RAP * processor) {}

static RAP * acquireRap(const char * user, const char * password, const char * clientIp) {
	if (user && password) {
		RAP * rap;
		time_t expires = getExpiryTime();
		RapList * threadRapList = pthread_getspecific(rapDBThreadKey);
		if (!threadRapList) {
			threadRapList = mallocSafe(sizeof(*threadRapList));
			memset(threadRapList, 0, sizeof(*threadRapList));
			pthread_setspecific(rapDBThreadKey, threadRapList);
		} else {
			// Get a rap from this thread's own list
			rap = threadRapList->firstRapSession;
			while (rap) {
				if (rap->rapCreated < expires) {
					RAP * raptmp = rap->next;
					destroyRap(rap);
					rap = raptmp;
				} else if (!strcmp(user, rap->user)
						&& !strcmp(password, rap->password) /*&& !strcmp(clientIp, rap->clientIp)*/) {
					// all requests here will come from the same ip so we don't check it in the above.
					return rap;
				} else {
					rap = rap->next;
				}
			}
		}
		// Get a rap from the central pool.
		if (sem_wait(&rapPoolLock) == -1) {
			stdLogError(errno, "Could not wait for rap pool lock while acquiring rap");
			return AUTH_ERROR;
		} else {
			rap = rapPool.firstRapSession;
			while (rap) {
				if (rap->rapCreated < expires) {
					RAP * raptmp = rap->next;
					destroyRap(rap);
					rap = raptmp;
				} else if (!strcmp(user, rap->user) && !strcmp(password, rap->password)
						&& !strcmp(clientIp, rap->clientIp)) {
					// We will only re-use sessions in the pool if they are from the same ip
					removeRapFromList(rap);
					addRapToList(threadRapList, rap);
					sem_post(&rapPoolLock);
					return rap;
				} else {
					rap = rap->next;
				}
			}
			sem_post(&rapPoolLock);
		}
		return createRap(threadRapList, user, password, clientIp);
	} else {
		stdLogError(0, "Rejecting request without auth");
		return AUTH_FAILED;
	}
}

#define releaseRap(processor)

static void cleanupAfterRap(int sig, siginfo_t *siginfo, void *context) {
	int status;
	waitpid(siginfo->si_pid, &status, 0);
	if (status == 139) {
		stdLogError(0, "RAP %d failed with segmentation fault", siginfo->si_pid);
	}
	//stdLog("Child finished PID: %d staus: %d", siginfo->si_pid, status);
}

static void deInitializeRapDatabase(void * data) {
	RapList * threadRapList = data;
	if (threadRapList) {
		if (threadRapList->firstRapSession) {
			if (sem_wait(&rapPoolLock) == -1) {
				stdLogError(errno, "Could not wait for rap pool lock cleaning up thread");
				do {
					destroyRap(threadRapList->firstRapSession);
				} while (threadRapList->firstRapSession != NULL);
			} else {
				do {
					RAP * rap = threadRapList->firstRapSession;
					removeRapFromList(rap);
					addRapToList(&rapPool, rap);
				} while (threadRapList->firstRapSession != NULL);
				sem_post(&rapPoolLock);
			}
		}
		freeSafe(threadRapList);
	}
}

static void runCleanRapPool() {
	time_t expires = getExpiryTime();
	if (sem_wait(&rapPoolLock) == -1) {
		stdLogError(errno, "Could not wait for rap pool lock while cleaning pool");
		return;
	} else {
		RAP * rap = rapPool.firstRapSession;
		while (rap != NULL) {
			RAP * next = rap->next;
			if (rap->rapCreated < expires) {
				destroyRap(rap);
			}
			rap = next;
		}
		sem_post(&rapPoolLock);
	}
}

static void initializeRapDatabase() {
	struct sigaction childCleanup = { .sa_sigaction = &cleanupAfterRap, .sa_flags = SA_SIGINFO };
	if (sigaction(SIGCHLD, &childCleanup, NULL) < 0) {
		stdLogError(errno, "Could not set handler method for finished child threads");
		exit(255);
	}

	memset(&rapPool, 0, sizeof(rapPool));
	sem_init(&rapPoolLock, 0, 1);
	pthread_key_create(&rapDBThreadKey, &deInitializeRapDatabase);
}

////////////////////////
// End RAP Processing //
////////////////////////

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
		const gnutls_pk_algorithm_t* pk_algos, int pk_algos_length, gnutls_pcert_st** pcert,
		unsigned int *pcert_length, gnutls_privkey_t * pkey) {

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

static int loadSSLCertificateFile(const char * fileName, gnutls_x509_crt_t * x509Certificate,
		gnutls_pcert_st * cert) {
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
		ret = loadSSLCertificateFile(sslConfig->chainFiles[i], &x509Certificate,
				&newCertificate.certs[i + 1]);
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
		ret = gnutls_x509_crt_get_subject_alt_name2(x509Certificate, i, domainName, &dataSize, &sanType,
				&critical);
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

///////////
// Locks //
///////////

static int compareLockToken(const void * a, const void * b) {
	const Lock * lhs = a;
	const Lock * rhs = b;
	return strcasecmp(lhs->lockToken, rhs->lockToken);
}

static Lock * findLock(Lock * lockToken) {
	Lock ** result = tfind(lockToken, &rootNode, &compareLockToken);
	return result ? *result : NULL;
}

static Lock * acquireLock(const char * user, const char * file, LockType lockType, int fd) {
	if (lockType != LOCK_TYPE_SHARED && lockType != LOCK_TYPE_EXCLUSIVE) {
		stdLogError(0, "acquireLock called with invalid lockType %d", (int) lockType);
		return NULL;
	}
	size_t userSize = strlen(user) + 1;
	size_t fileSize = strlen(file) + 1;
	size_t bufferSize = sizeof(Lock) + userSize + fileSize;

	char * buffer = mallocSafe(bufferSize);
	Lock * newLock = (Lock *) buffer;
	newLock->user = buffer + sizeof(Lock);
	newLock->file = newLock->user + userSize;

	uuid_t uuid;
	uuid_generate(uuid);
	uuid_unparse_lower(uuid, newLock->lockToken);
	memcpy((char *) newLock->user, user, userSize);
	memcpy((char *) newLock->file, file, fileSize);
	time(&newLock->lockAcquired);
	newLock->type = lockType;
	newLock->fd = fd;
	newLock->useCount = 1;
	newLock->released = 0;

	if (sem_wait(&lockDBLock) == -1) {
		stdLogError(errno, "Could not wait for access to lock db");
		close(fd);
		freeSafe(newLock);
		return NULL;
	} else {
		// Adds the lock to the DB.  Despite its odd name tsearch adds the item if it doesnt already exist.
		Lock * inDB = *((Lock **) tsearch(newLock, &rootNode, &compareLockToken));
		sem_post(&lockDBLock);
		if (inDB != newLock) {
			// This should never happen, but "should" isn't a term we want to play with.
			stdLogError(0, "UUID collision in lock database %s", newLock->lockToken);
			close(newLock->fd);
			freeSafe(newLock);
			return acquireLock(user, file, lockType, fd);
		} else {
			return newLock;
		}
	}
}

static int refreshLock(Lock * lock) {
	if (sem_wait(&lockDBLock) == -1) {
		stdLogError(errno, "Could not wait for access to lock db");
		return 0;
	}
	Lock * foundLock = findLock(lock);
	if (foundLock && !foundLock->released) {
		time(&foundLock->lockAcquired);
		sem_post(&lockDBLock);
		return 1;
	} else {
		sem_post(&lockDBLock);
		stdLogError(0, "Could not find lock %s for user %s on file %s", lock->lockToken, lock->user,
				lock->file);
		return 0;
	}

}

static void releaseUnusedLock(Lock * lock) {
	lock->useCount--;
	if (lock->useCount == 0) {
		tdelete(lock, &rootNode, &compareLockToken);
		close(lock->fd);
		freeSafe(lock);
	}
}

static Lock * useLock(const char * lockToken, const char * file, const char * user) {
	if (strncmp(lockToken, LOCK_TOKEN_PREFIX, LOCK_TOKEN_PREFIX_LENGTH)) {
		stdLogError(0, "Could not find lock %s for user %s on file %s", lockToken, user, file);
		return NULL;
	}
	Lock toFind;
	strncpy((char *) toFind.lockToken, lockToken + LOCK_TOKEN_PREFIX_LENGTH, sizeof(toFind.lockToken) - 1);
	toFind.lockToken[sizeof(toFind.lockToken) - 1] = '\0';

	if (sem_wait(&lockDBLock) == -1) {
		stdLogError(errno, "Could not wait for access to lock db");
		return NULL;
	}
	Lock * foundLock = findLock(&toFind);
	if (foundLock != NULL && !strcmp(foundLock->user, user) && !strcmp(foundLock->file, file)
			&& !foundLock->released) {
		foundLock->useCount++;
		sem_post(&lockDBLock);
		return foundLock;
	} else {
		sem_post(&lockDBLock);
		stdLogError(0, "Could not find lock %s for user %s on file %s", lockToken, user, file);
		return NULL;
	}
}

static void unuseLock(Lock * lockToken) {
	if (sem_wait(&lockDBLock) == -1) {
		stdLogError(errno, "Could not wait for access to lock db lock will left in DB after unsuseLock()");
	} else {
		Lock * foundLock = findLock(lockToken);
		if (foundLock) {
			releaseUnusedLock(foundLock);
		}
		sem_post(&lockDBLock);
	}
}

static int releaseLock(const char * lockToken, const char * file, const char * user) {
	if (strncmp(lockToken, LOCK_TOKEN_PREFIX, LOCK_TOKEN_PREFIX_LENGTH)) {
		stdLogError(0, "Could not find lock %s for user %s on file %s", lockToken, user, file);
		return 0;
	}
	Lock toFind;
	strncpy((char *) toFind.lockToken, lockToken + LOCK_TOKEN_PREFIX_LENGTH, sizeof(toFind.lockToken) - 1);
	toFind.lockToken[sizeof(toFind.lockToken) - 1] = '\0';

	if (sem_wait(&lockDBLock) == -1) {
		stdLogError(errno, "Could not wait for access to lock db");
		return -1;
	}
	Lock * foundLock = findLock(&toFind);
	if (foundLock != NULL && !strcmp(foundLock->user, user) && !strcmp(foundLock->file, file)
			&& !foundLock->released) {
		foundLock->released = 1;
		releaseUnusedLock(foundLock);
		sem_post(&lockDBLock);
		return 1;
	} else {
		sem_post(&lockDBLock);
		stdLogError(0, "Could not find lock %s for user %s on file %s", lockToken, user, file);
		return 0;
	}
}

static void cleanAction(const void *nodep, const VISIT which, const int depth) {
	switch (which) {
	case postorder:
	case leaf: {
		Lock * lock = *((Lock **) nodep);
		if (lock && lock->lockAcquired < lockExpiryTime && !lock->released) {
			int index = lockReadyForReleaseCount++;
			if (!(index & 0xF)) {
				readyForRelease = reallocSafe(readyForRelease,
						(lockReadyForReleaseCount | 0xF) * sizeof(*readyForRelease));
			}
			readyForRelease[index] = lock;
		}
		break;
	}

	default:
		break;
	}
}

static void runCleanLocks() {
	if (sem_wait(&lockDBLock) == -1) {
		stdLogError(errno, "Could not wait for access to lock db");
	} else {
		if (rootNode) {
			time(&lockExpiryTime);
			lockExpiryTime -= config.maxLockTime;
			lockReadyForReleaseCount = 0;
			readyForRelease = NULL;
			twalk(rootNode, &cleanAction);

			if (lockReadyForReleaseCount > 0) {
				int i = 0;
				do {
					readyForRelease[i]->released = 1;
					releaseUnusedLock(readyForRelease[i]);
					i++;
				} while (i < lockReadyForReleaseCount);
				freeSafe(readyForRelease);
			}
		}

		sem_post(&lockDBLock);
	}
}

static void initializeLockDB() {
	if (sem_init(&lockDBLock, 0, 1) == -1) {
		stdLogError(errno, "Could not create lock for lockdb");
		exit(255);
	}
}

static void unuseSessionLocks(RAP * session) {
	if (session && session->requestLockCount) {
		for (int i = 0; i < session->requestLockCount; i++) {
			unuseLock(session->requestLock[i]);
		}
		session->requestLockCount = 0;
	}
}

// have capitalized this because the fact it is a macro needs emphasizing
#define SKIP_WHITE_SPACE(ptr) while (*ptr == ' ' || *ptr == '\t') {ptr++;}

// Parses the If header and checks all specified locks, assigning them to the session.
static int useSessionLocks(RAP * rapSession, Request * request, const char * url) {
	const char * cptr = getHeader(request, "If");
	if (!cptr) return 1;

	char * resource = (char *) url;
	SKIP_WHITE_SPACE(cptr);
	while (*cptr != '\0') {
		// TODO handle NOT condition
		if (*cptr == '<') {
			cptr++;
			size_t i = 0;
			while (cptr[i] != '>' && cptr[i] != '\0') {
				i++;
			}
			if (i == 0 || cptr[i] == '\0') goto return_0;
			if (resource != url) freeSafe(resource);
			resource = mallocSafe(i + 1);
			parseHeaderFilePath(resource, i, cptr);
			cptr += i + 1;
			SKIP_WHITE_SPACE(cptr);
		} else if (*cptr == '(') {
			cptr++;
			SKIP_WHITE_SPACE(cptr);
			while (*cptr != ')') {
				if (*cptr == '<') {
					size_t i = 1;
					while (cptr[i] != '\0' && cptr[i] != '>') {
						i++;
					}
					i++;

					char token[i + 1];
					memcpy(token, cptr, i);
					token[i] = '\0';
					cptr += i;

					Lock * lock = useLock(token, resource, rapSession->user);
					if (!lock) goto return_0;

					int lockIndex = rapSession->requestLockCount++;
					if (rapSession->requestLockCount > MAX_SESSION_LOCKS) {
						rapSession->requestLockCount--;
						unuseLock(lock);
						goto return_0;
					}
					rapSession->requestLock[lockIndex] = lock;

				} else if (*cptr == '[') {
					// TODO parse etag
					goto return_0;
				} else goto return_0;
				SKIP_WHITE_SPACE(cptr);
			}
			cptr++;
			SKIP_WHITE_SPACE(cptr);
		} else goto return_0;
	}

	if (resource != url) freeSafe(resource);
	return 1;

	return_0: unuseSessionLocks(rapSession);
	if (resource != url) freeSafe(resource);
	return 0;
}

///////////////
// End Locks //
///////////////

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
	unuseSessionLocks(fdResponseData->session);
	freeSafe(fdResponseData);
}

static Response * createFdResponse(int fd, uint64_t offset, uint64_t size, const char * mimeType, time_t date,
		RAP * rapSession) {

	FDResponseData * fdResponseData = mallocSafe(sizeof(*fdResponseData));
	fdResponseData->fd = fd;
	fdResponseData->pos = 0;
	fdResponseData->offset = offset;
	fdResponseData->size = size;
	fdResponseData->session = rapSession;
	Response * response = MHD_create_response_from_callback(size, 40960, &fdContentReader, fdResponseData,
			&fdContentReaderCleanup);
	if (!response) {
		stdLogError(errno, "Could not create response");
		exit(255);
	}
	char dateBuf[100];
	getWebDate(date, dateBuf, 100);
	addHeader(response, "Date", dateBuf);
	addHeader(response, "Content-Type", mimeType);
	addHeader(response, "DAV", "1");
	addHeader(response, "Accept-Ranges", "bytes");
	addHeader(response, "Server", "couling-webdavd");
	addHeader(response, "Expires", "Thu, 19 Nov 1980 00:00:00 GMT");
	addHeader(response, "Cache-Control", "no-store, no-cache, must-revalidate, post-check=0, pre-check=0");
	addHeader(response, "Pragma", "no-cache");
        // Adding additional headers from the config file
        for (int i = 0; i < config.addHeadersCount; i++) {
            addHeader(response, config.addHeaders[i].name, config.addHeaders[i].value);
        }

	return response;
}

static Response * createFileResponse(const char * fileName, const char * mimeType, RAP * session) {
	int fd = open(fileName, O_RDONLY | O_CLOEXEC);
	if (fd == -1) {
		stdLogError(errno, "Could not open file for response", fileName);
		exit(1);
	}

	struct stat statBuffer;
	fstat(fd, &statBuffer);
	return createFdResponse(fd, 0, statBuffer.st_size, mimeType, statBuffer.st_mtime, session);
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

static int createResponseFromMessage(Request * request, Message * message, Response ** response,
		RAP * session) {
	RapConstant statusCode = message->mID;

	if (statusCode == RAP_RESPOND_CONTINUE) return RAP_RESPOND_CONTINUE;

	if (statusCode < RAP_RESPOND_CONTINUE || statusCode >= 600) {
		if (message->fd != -1) close(message->fd);
		stdLogError(0, "Response from RAP %d", (int) message->mID);
		return RAP_RESPOND_INTERNAL_ERROR;
	}

	if (message->fd == -1) {
		switch (statusCode) {
		case RAP_RESPOND_OK:
			statusCode = RAP_RESPOND_OK_NO_CONTENT;
			break;

		case RAP_RESPOND_ACCESS_DENIED:
			*response = createFileResponse(FORBIDDEN_PAGE, "text/html", session);
			break;

		case RAP_RESPOND_NOT_FOUND:
			*response = createFileResponse(NOT_FOUND_PAGE, "text/html", session);
			break;

		case RAP_RESPOND_BAD_CLIENT_REQUEST:
			*response = createFileResponse(BAD_REQUEST_PAGE, "text/html", session);
			break;

		case RAP_RESPOND_INSUFFICIENT_STORAGE:
			*response = createFileResponse(INSUFFICIENT_STORAGE_PAGE, "text/html", session);
			break;

		case RAP_RESPOND_CONFLICT:
			*response = createFileResponse(CONFLICT_PAGE, "text/html", session);
			break;

		default:
			*response = 0;
		}
	} else {
		// Get Mime type and date
		const char * mimeType = messageParamToString(&message->params[RAP_PARAM_REQUEST_FILE]);
		time_t date = messageParamTo(time_t, message->params[RAP_PARAM_RESPONSE_DATE]);

		struct stat stat;
		fstat(message->fd, &stat);
		if ((stat.st_mode & S_IFMT) == S_IFREG) {
			if (statusCode == 200) {
				off_t offset = 0;
				size_t fileSize = stat.st_size;
				if (request) {
					const char * rangeHeader = getHeader(request, "Range");
					if (rangeHeader && processRangeHeader(&offset, &fileSize, rangeHeader)) {
						statusCode = MHD_HTTP_PARTIAL_CONTENT;
					}
				}
				*response = createFdResponse(message->fd, offset, fileSize, mimeType, date, session);

				char contentRangeHeader[200];
				snprintf(contentRangeHeader, sizeof(contentRangeHeader), "bytes %lld-%lld/%lld",
						(long long) offset, (long long) (fileSize + offset), (long long) stat.st_size);

				addHeader(*response, "Content-Range", contentRangeHeader);
			} else {
				*response = createFdResponse(message->fd, 0, stat.st_size, mimeType, date, session);
			}
		} else {
			*response = createFdResponse(message->fd, 0, -1, mimeType, date, session);
		}
	}
	return statusCode;
}

static RapConstant writeErrorResponse(RapConstant responseCode, const char * textError, const char * error,
		const char * file, RAP * session, Response ** response) {
	Message message = { .mID = responseCode, .fd = -1, .paramCount = 2 };
	message.params[RAP_PARAM_ERROR_LOCATION] = stringToMessageParam(file);
	message.params[RAP_PARAM_ERROR_DAV_REASON] = stringToMessageParam(error);
	message.params[RAP_PARAM_ERROR_REASON] = stringToMessageParam(textError);
	char buffer[BUFFER_SIZE];
	if (sendRecvMessage(session->socketFd, &message, buffer, BUFFER_SIZE) <= 0) {
		return RAP_RESPOND_INTERNAL_ERROR;
	} else {
		return createResponseFromMessage(NULL, &message, response, session);
	}
}

///////////////////////////
// End Response Creation //
///////////////////////////

//////////////////////////
// Main Handler Methods //
//////////////////////////

static int finishProcessingRequest(Request * request, RAP * processor, Response ** response) {
	Message message;
	char incomingBuffer[INCOMING_BUFFER_SIZE];
	ssize_t readResult = recvMessage(processor->socketFd, &message, incomingBuffer, INCOMING_BUFFER_SIZE);
	if (readResult <= 0) {
		if (readResult == 0) {
			stdLogError(0, "RAP closed socket unexpectedly while waiting for response");
		} // else { stdLogError ... has already been sent by recvMessage ... }
		return RAP_RESPOND_INTERNAL_ERROR;
	}

	const char * location;
	Lock * lock;
	switch (message.mID) {
	case RAP_INTERIM_RESPOND_LOCK: {
		location = messageParamToString(&message.params[RAP_PARAM_LOCK_LOCATION]);
		LockType lockType = messageParamTo(LockType, message.params[RAP_PARAM_LOCK_TYPE]);
		lock = acquireLock(processor->user, location, lockType, message.fd);
		if (!lock) return RAP_RESPOND_INTERNAL_ERROR;

		goto COMPLETE_LOCK;
	}
	case RAP_INTERIM_RESPOND_RELOCK:
		location = messageParamToString(&message.params[RAP_PARAM_LOCK_LOCATION]);
		// A relock request must have a lock token specified, there WILL be a lock in processor->requestLock[0].
		lock = processor->requestLock[0];
		for (int i = 0; i < processor->requestLockCount; i++) {
			if (!refreshLock(processor->requestLock[i])) return RAP_RESPOND_INTERNAL_ERROR;
		}

		COMPLETE_LOCK: message.mID = RAP_COMPLETE_REQUEST_LOCK;
		message.fd = -1;
		message.paramCount = 3;
		// message.params[RAP_PARAM_LOCK_LOCATION] = leave this unchanged
		message.params[RAP_PARAM_LOCK_TOKEN] = stringToMessageParam(lock->lockToken);
		message.params[RAP_PARAM_LOCK_TIMEOUT] = toMessageParam(config.maxLockTime);
		readResult = sendRecvMessage(processor->socketFd, &message, incomingBuffer, INCOMING_BUFFER_SIZE);
		if (readResult <= 0) return RAP_RESPOND_INTERNAL_ERROR;
		int statusCode = createResponseFromMessage(request, &message, response, processor);
		if (statusCode == RAP_RESPOND_OK) {
			char tokenBuffer[200];
			sprintf(tokenBuffer, LOCK_TOKEN_PREFIX "%s" LOCK_TOKEN_SUFFIX, lock->lockToken);
			addHeader(*response, "Lock-Token", tokenBuffer);
			sprintf(tokenBuffer, "Second-%d", (int) config.maxLockTime);
			addHeader(*response, "Timeout", tokenBuffer);
		}
		return statusCode;

	default:
		return createResponseFromMessage(request, &message, response, processor);
	}

}

static int startProcessingRequest(Request * request, const char * url, const char * method, RAP * rapSession,
		Response ** response) {

	char incomingBuffer[INCOMING_BUFFER_SIZE];

	rapSession->requestLockCount = 0;
	LockProvisions requestLocks = { .source = LOCK_TYPE_NONE, .target = LOCK_TYPE_NONE };
	if (!useSessionLocks(rapSession, request, url)) {
		return writeErrorResponse(RAP_RESPOND_CONFLICT, "Lock token not found", NULL, url, rapSession,
				response);
	}

	for (int i = 0; i < rapSession->requestLockCount; i++) {
		if (rapSession->requestLock[i]->file == url || !strcmp(rapSession->requestLock[i]->file, url)) {
			requestLocks.source |= rapSession->requestLock[i]->type;
		}
	}

	// Interpret the method
	//stdLog("%s %s data", method, writeHandle ? "with" : "without");

	Message message;
	// These methods are all passed to the RAP in a very similar way
	if (!strcmp("GET", method) || !strcmp("HEAD", method)) {
		message.mID = RAP_REQUEST_GET;
		message.paramCount = 2;
	} else if (!strcmp("PUT", method)) {
		message.mID = RAP_REQUEST_PUT;
		message.paramCount = 2;
	} else if (!strcmp("PROPFIND", method)) {
		message.mID = RAP_REQUEST_PROPFIND;
		message.paramCount = 3;
		message.params[RAP_PARAM_REQUEST_DEPTH] = stringToMessageParam(getHeader(request, HEADER_DEPTH));
	} else if (!strcmp("PROPPATCH", method)) {
		message.mID = RAP_REQUEST_PROPPATCH;
		message.paramCount = 3;
		message.params[RAP_PARAM_REQUEST_DEPTH] = stringToMessageParam(getHeader(request, HEADER_DEPTH));
	} else if (!strcmp("MKCOL", method)) {
		message.mID = RAP_REQUEST_MKCOL;
		message.paramCount = 2;
	} else if (!strcmp("DELETE", method)) {
		message.mID = RAP_REQUEST_DELETE;
		message.paramCount = 2;
	} else if (!strcmp("LOCK", method)) {
		message.mID = RAP_REQUEST_LOCK;
		message.paramCount = 3;
		message.params[RAP_PARAM_REQUEST_DEPTH] = stringToMessageParam(getHeader(request, HEADER_DEPTH));
		// These methods are handled in a very different way
	} else if (!strcmp("MOVE", method)) {
		const char * unparsedTarget = getHeader(request, HEADER_TARGET);
		size_t size = unparsedTarget ? strlen(unparsedTarget) : 0;
		char target[size + 1];
		if (size > 0) parseHeaderFilePath(target, size, unparsedTarget);
		else target[0] = '\0';

		message.mID = RAP_REQUEST_MOVE;
		message.paramCount = 3;
		message.fd = rapSession->requestReadDataFd;
		rapSession->requestReadDataFd = -1; // sendMessage takes ownership of this even on failure
		message.params[RAP_PARAM_REQUEST_LOCK] = toMessageParam(requestLocks);
		message.params[RAP_PARAM_REQUEST_FILE] = stringToMessageParam(url);
		message.params[RAP_PARAM_REQUEST_TARGET] = stringToMessageParam(target);
		for (int i = 0; i < rapSession->requestLockCount; i++) {
			if (!strcmp(rapSession->requestLock[i]->file, target)) {
				requestLocks.target |= rapSession->requestLock[i]->type;
			}
		}

		if (sendRecvMessage(rapSession->socketFd, &message, incomingBuffer, sizeof(incomingBuffer)) <= 0) {
			return RAP_RESPOND_INTERNAL_ERROR;
		}

		return createResponseFromMessage(request, &message, response, rapSession);

	} else if (!strcmp("COPY", method)) {
		const char * unparsedTarget = getHeader(request, HEADER_TARGET);
		size_t size = unparsedTarget ? strlen(unparsedTarget) : 0;
		if (size > MAX_VARABLY_DEFINED_ARRAY) return RAP_RESPOND_HEADER_TOO_LARGE;
		char target[size + 1];
		if (size > 0) parseHeaderFilePath(target, size, unparsedTarget);
		else target[0] = '\0';

		message.mID = RAP_REQUEST_COPY;
		message.paramCount = 3;
		message.fd = rapSession->requestReadDataFd;
		rapSession->requestReadDataFd = -1; // sendMessage takes ownership of this even on failure
		message.params[RAP_PARAM_REQUEST_LOCK] = toMessageParam(requestLocks);
		message.params[RAP_PARAM_REQUEST_FILE] = stringToMessageParam(url);
		message.params[RAP_PARAM_REQUEST_TARGET] = stringToMessageParam(target);
		for (int i = 0; i < rapSession->requestLockCount; i++) {
			if (!strcmp(rapSession->requestLock[i]->file, target)) {
				requestLocks.target |= rapSession->requestLock[i]->type;
			}
		}

		if (sendRecvMessage(rapSession->socketFd, &message, incomingBuffer, sizeof(incomingBuffer)) <= 0) {
			return RAP_RESPOND_INTERNAL_ERROR;
		}

		return createResponseFromMessage(request, &message, response, rapSession);

	} else if (!strcmp("UNLOCK", method)) {
		const char * lockToken = getHeader(request, HEADER_LOCK_TOKEN);
		int result = releaseLock(lockToken, url, rapSession->user);
		if (result == 1) {
			return RAP_RESPOND_OK_NO_CONTENT;
		} else if (result == 0) {
			message.mID = RAP_RESPOND_CONFLICT;
			message.paramCount = 3;
			message.params[RAP_PARAM_ERROR_LOCATION] = stringToMessageParam(url);
			message.params[RAP_PARAM_ERROR_REASON] = stringToMessageParam("Could not find lock");
			message.params[RAP_PARAM_ERROR_DAV_REASON] = NULL_PARAM;

			if (sendRecvMessage(rapSession->socketFd, &message, incomingBuffer, sizeof(incomingBuffer))
					<= 0) {
				return RAP_RESPOND_INTERNAL_ERROR;
			}

			return createResponseFromMessage(request, &message, response, rapSession);
		} else {
			return RAP_RESPOND_INTERNAL_ERROR;
		}
	} else if (!strcmp("OPTIONS", method)) {
		*response = createFileResponse(OPTIONS_PAGE, "text/html", rapSession);
		addHeader(*response, "Accept", ACCEPT_HEADER);
		return RAP_RESPOND_OK;

	} else {
		stdLogError(0, "Can not cope with method: %s (%s data)", method,
				(rapSession->requestWriteDataFd != -1 ? "with" : "without"));

		return MHD_HTTP_METHOD_NOT_ALLOWED;
	}

	message.fd = rapSession->requestReadDataFd;
	rapSession->requestReadDataFd = -1; // sendMessage takes ownership of this even on failure
	message.params[RAP_PARAM_REQUEST_LOCK] = toMessageParam(requestLocks);
	message.params[RAP_PARAM_REQUEST_FILE] = stringToMessageParam(url);

	if (sendRecvMessage(rapSession->socketFd, &message, incomingBuffer, sizeof(incomingBuffer)) <= 0) {
		return RAP_RESPOND_INTERNAL_ERROR;
	}

	return createResponseFromMessage(request, &message, response, rapSession);

}

//////////////////////////////
// END Main Handler Methods //
//////////////////////////////

////////////////////////////////////////
// Low Level HTTP handling (Signpost) //
////////////////////////////////////////

static int sendResponse(Request * request, int statusCode, Response * response, RAP * rapSession) {
	if (response) {
		int queueResult = MHD_queue_response(request, statusCode, response);
		MHD_destroy_response(response);
		return queueResult;

	} else {

		switch (statusCode) {
		case RAP_RESPOND_CONTINUE:
			stdLogError(0, "Attempt to send a continue (100) response");
			statusCode = MHD_HTTP_INTERNAL_SERVER_ERROR;
			response = INTERNAL_SERVER_ERROR_PAGE;
			break;

		case RAP_RESPOND_INTERNAL_ERROR:
			response = INTERNAL_SERVER_ERROR_PAGE;
			break;

		case RAP_RESPOND_AUTH_FAILLED:
			response = UNAUTHORIZED_PAGE;
			break;

		case MHD_HTTP_METHOD_NOT_ALLOWED:
			response = METHOD_NOT_SUPPORTED_PAGE;
			break;

		default:
			response = NO_CONTENT_PAGE;
		}

		/* Usually the lock is embedded in the response body and released once the response body has been sent.
		 * But for static responses we can't do this because static responses are shared between threads.
		 * As it happens we know that the lock is no longer needed at the point we know we're sending a static
		 * response becase locks don't apply to static responses... so we release it here.
		 * It's counter-intuitive to put it here, but it works and I havn't found a better place to put it. */
		unuseSessionLocks(rapSession);

		return MHD_queue_response(request, statusCode, response);
	}

}

/**
 * Main handler method for handling requests.  This method does quite a lot to make libmicrohttp easier to
 * work with. Primarily this wraps up libmicrohttp's quirky multi-call aproach to handling request bodies.
 *
 * It authenticates all requests making an apropriate RAP session available and then calls
 * startProcessingRequest(). (Only) If startProcessingRequest returns RAP_CONTINUE will
 * finishingProcessingRequest() be called.
 *
 * startProcessingRequest() and finishingProcessingRequest() are given a request and must (as a pair) return a
 * response. The returned int for each is the http status code, the body is returned in the last argument.
 *
 * If a request has a body then this data will be pumped into rapSession->requestWriteDataFd between calling
 * startProcessingRequest() and finishingProcessingRequest().
 * The existance of a body is signalled to startProcessingRequest() by rapSession->requestWriteDataFd != -1.
 * If a body has been sent then startProcessingRequest() must take ownership of rapSession->requestWriteDataFd
 * and set the field to -1 or it will be closed before any data can be pumped.
 *
 * In theory startProcessingRequest may replace with a different fd as long as it closes the one provided.
 * If it does this when rapSession->requestWriteDataFd == -1 then the handle will just be closed since there is
 * no data to send.
 */
static int answerToRequest(void *cls, Request *request, const char *url, const char *method,
		const char *version, const char *upload_data, size_t *upload_data_size, void ** s) {

	RAP * rapSession = *((RAP **) s);

	if (rapSession) {
		if (*upload_data_size) {
			// Uploading more data
			if (rapSession->requestWriteDataFd != -1) {
				size_t bytesWritten = write(rapSession->requestWriteDataFd, upload_data, *upload_data_size);
				if (bytesWritten < *upload_data_size) {
					// not all data could be written to the file handle and therefore
					// the operation has now failed. There's nothing we can do now but report the error
					// This may not actually be desirable and so we need to consider slamming closed the connection.
					close(rapSession->requestWriteDataFd);
					rapSession->requestWriteDataFd = -1;
				}
			}
			*upload_data_size = 0;
			return MHD_YES;
		} else {
			// Finished uploading data
			if (rapSession->requestWriteDataFd != -1) {
				close(rapSession->requestWriteDataFd);
				rapSession->requestWriteDataFd = -1;
			}
			Response * response;
			int statusCode;

			if (rapSession->requestResponseAlreadyGiven) {
				statusCode = rapSession->requestResponseAlreadyGiven;
				response = rapSession->requestResponseObjectAlreadyGiven;
			} else {
				statusCode = finishProcessingRequest(request, rapSession, &response);
				logAccess(statusCode, method, rapSession->user, url, rapSession->clientIp);
			}
			int result = sendResponse(request, statusCode, response, rapSession);
			if (statusCode == RAP_RESPOND_INTERNAL_ERROR) {
				destroyRap(rapSession);
			} else if (AUTH_SUCCESS(rapSession)) {
				releaseRap(rapSession);
			}
			return result;
		}
	} else {
		// All requests must be Authenticated
		char * password;
		char * user = MHD_basic_auth_get_username_password(request, &password);
		char clientIp[100];
		getRequestIP(clientIp, sizeof(clientIp), request);
		rapSession = acquireRap(user, password, clientIp);
		*s = rapSession;
		if (AUTH_SUCCESS(rapSession)) {
			if (requestHasData(request)) {
				// If we have data to send then create a pipe to pump it through
				// To avoid the "non-standard" pipe2() we use unix domain sockets with socketpair
				// this let us set it as a close on exec
				int pipeEnds[2];
				if (socketpair(PF_LOCAL, SOCK_STREAM | SOCK_CLOEXEC, 0, pipeEnds)) {
					stdLogError(errno, "Could not create write pipe");
					rapSession->requestResponseAlreadyGiven = RAP_RESPOND_INTERNAL_ERROR;
					rapSession->requestResponseObjectAlreadyGiven = NULL;
					logAccess(RAP_RESPOND_INTERNAL_ERROR, method, rapSession->user, url, clientIp);
					return MHD_YES;
				}
				rapSession->requestReadDataFd = pipeEnds[CHILD_SOCKET];
				rapSession->requestWriteDataFd = pipeEnds[PARENT_SOCKET];

				Response * response = NULL;
				int statusCode = startProcessingRequest(request, url, method, rapSession, &response);

				if (rapSession->requestReadDataFd != -1) {
					close(rapSession->requestReadDataFd);
					rapSession->requestReadDataFd = -1;
				}

				if (statusCode == RAP_RESPOND_CONTINUE) {
					// do not queue a response for contiune
					rapSession->requestResponseAlreadyGiven = 0;
					//logAccess(statusCode, method, (*rapSession)->user, url);
					return MHD_YES;
				} else {
					if (rapSession->requestWriteDataFd != -1) {
						close(rapSession->requestWriteDataFd);
						rapSession->requestWriteDataFd = -1;
					}
					rapSession->requestResponseAlreadyGiven = statusCode;
					rapSession->requestResponseObjectAlreadyGiven = response;
					logAccess(RAP_RESPOND_INTERNAL_ERROR, method, rapSession->user, url, clientIp);
					return MHD_YES;
				}
			} else {
				rapSession->requestReadDataFd = -1;
				rapSession->requestWriteDataFd = -1;
				Response * response = NULL;

				int statusCode = startProcessingRequest(request, url, method, rapSession, &response);
				if (rapSession->requestReadDataFd != -1) {
					close(rapSession->requestReadDataFd);
					rapSession->requestReadDataFd = -1;
				}
				if (rapSession->requestWriteDataFd != -1) {
					close(rapSession->requestWriteDataFd);
					rapSession->requestWriteDataFd = -1;
				}

				if (statusCode == RAP_RESPOND_CONTINUE) {
					statusCode = finishProcessingRequest(request, rapSession, &response);
				}
				logAccess(statusCode, method, rapSession->user, url, rapSession->clientIp);
				int ret = sendResponse(request, statusCode, response, rapSession);
				if (statusCode == RAP_RESPOND_INTERNAL_ERROR) {
					destroyRap(rapSession);
				} else {
					releaseRap(rapSession);
				}
				return ret;

			}
		} else if (rapSession == AUTH_FAILED) {
			logAccess(RAP_RESPOND_AUTH_FAILLED, method, rapSession->user, url, clientIp);
			if (requestHasData(request)) {
				return MHD_YES;
			} else {
				return sendResponse(request, RAP_RESPOND_AUTH_FAILLED, NULL, rapSession);
			}
		} else /*if (*rapSession == AUTH_ERROR)*/{
			logAccess(RAP_RESPOND_INTERNAL_ERROR, method, rapSession->user, url, clientIp);
			if (requestHasData(request)) {
				return MHD_YES;
			} else {
				return sendResponse(request, RAP_RESPOND_INTERNAL_ERROR, NULL, rapSession);
			}
		}
	}
}

static int answerForwardToRequest(void *cls, Request *request, const char *url, const char *method,
		const char *version, const char *upload_data, size_t *upload_data_size, void ** s) {
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
	if (bufferSize > MAX_VARABLY_DEFINED_ARRAY) return RAP_RESPOND_URI_TOO_LARGE;
	char buffer[bufferSize];
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

////////////////////////////////////////////
// End Low Level HTTP handling (Signpost) //
////////////////////////////////////////////

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

	NO_CONTENT_PAGE = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_MUST_COPY);

	FORBIDDEN_PAGE = createStaticFileName("HTTP_FORBIDDEN.html");
	NOT_FOUND_PAGE = createStaticFileName("HTTP_NOT_FOUND.html");
	BAD_REQUEST_PAGE = createStaticFileName("HTTP_BAD_REQUEST.html");
	INSUFFICIENT_STORAGE_PAGE = createStaticFileName("HTTP_INSUFFICIENT_STORAGE.html");
	OPTIONS_PAGE = createStaticFileName("OPTIONS.html");
	CONFLICT_PAGE = createStaticFileName("HTTP_CONFLICT.html");
	OK_PAGE = createStaticFileName("HTTP_OK.html");
}

static void initializeEnvVariables() {
	setenv("WEBDAVD_PAM_SERVICE", config.pamServiceName, 1);
	setenv("WEBDAVD_MIME_FILE", config.mimeTypesFile, 1);
	if (config.chrootPath) setenv("WEBDAVD_CHROOT_PATH", config.chrootPath, 1);
	else unsetenv("WEBDAVD_CHROOT_PATH");
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

void cleaner() {
	while (!shuttingDown) {
		int total = 60;
		do
			total = sleep(total);
		while (total > 0);
		runCleanRapPool();
		runCleanLocks();
	}
}

static void runServer() {
	if (!lockToUser(config.restrictedUser, NULL)) {
		exit(1);
	}

	initializeLogs();
	initializeStaticResponses();
	initializeRapDatabase();
	initializeLockDB();
	initializeSSL();
	initializeEnvVariables();

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
						MHD_USE_THREAD_PER_CONNECTION | MHD_USE_DUAL_STACK | MHD_USE_PEDANTIC_CHECKS
								| MHD_USE_SSL, 0 /* ignored */, NULL, NULL,                     //
						callback, &config.daemons[i],                    //
						MHD_OPTION_SOCK_ADDR, &address,                  // Specifies both host and port
						MHD_OPTION_HTTPS_CERT_CALLBACK, &sslSNICallback, // enable ssl
						MHD_OPTION_PER_IP_CONNECTION_LIMIT, config.maxConnectionsPerIp, //
						MHD_OPTION_END);
			} else {
				// http
				daemons[i] = MHD_start_daemon(
						MHD_USE_THREAD_PER_CONNECTION | MHD_USE_DUAL_STACK | MHD_USE_PEDANTIC_CHECKS,
						0 /* ignored */,
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

			// Use the main thread as the cleaner thread.
			// We could start a new dedicated cleaner thread here then exit this thread but what would be the point?
			cleaner();
			stdLogError(errno, "Cleaner thread shut down");
			pthread_exit(NULL);
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
