#include "shared.h"

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <security/pam_appl.h>
// #include <security/openpam.h>	/* for openpam_ttyconv() */

#define BUFFER_SIZE 4096

static int authenticated = 0;
static const char * authenticatedUser;

#define respond(result, fd) sendMessage(STDOUT_FILENO, result, fd, 0, NULL)

/*static ssize_t directoryReader(DIR * directory, uint64_t pos, char *buf, size_t max) {
	struct dirent *dp;
	ssize_t written = 0;

	while (written < max - 257 && (dp = readdir(directory)) != NULL) {
		int newlyWritten;
		if (dp->d_name[0] != '.' || (dp->d_name[1] != '\0' && (dp->d_name[1] != '.' || dp->d_name[2] != '\0'))) {
			if (dp->d_type == DT_DIR) {
				newlyWritten = sprintf(buf, "%s/\n", dp->d_name);
			} else {
				newlyWritten = sprintf(buf, "%s\n", dp->d_name);
			}
			written += newlyWritten;
			buf += newlyWritten;
		}
	}

	if (written == 0) {
		written = MHD_CONTENT_READER_END_OF_STREAM;
	}
	return written;
}

static void directoryReaderCleanup(DIR * directory) {
	closedir(directory);
}

static struct MHD_Response * directoryReaderCreate(size_t size, int fd) {
	DIR * dir = fdopendir(fd);
	if (!dir) {
		close(fd);
		stdLogError(errno, "Could not list directory from fd");
		return NULL;
	}
	struct MHD_Response * response = MHD_create_response_from_callback(-1, 4096,
			(MHD_ContentReaderCallback) &directoryReader, dir,
			(MHD_ContentReaderFreeCallback) & directoryReaderCleanup);
	if (!response) {
		closedir(dir);
		return NULL;
	} else {
		return response;
	}
}*/

static size_t listFolder(int bufferCount, struct iovec * bufferHeaders) {
	return respond(RAP_BAD_REQUEST, -1);
}

static size_t writeFile(int bufferCount, struct iovec * bufferHeaders) {
	return respond(RAP_BAD_REQUEST, -1);
}

static size_t readFile(int bufferCount, struct iovec * bufferHeaders) {
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
		stdLog("GET success %s %s %s", authenticatedUser, host, file);
		return respond(RAP_SUCCESS_STATIC_DATA_FD, fd);
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

static size_t authenticate(int bufferCount, struct iovec * bufferHeaders) {
	if (authenticated || bufferCount != 2) {
		if (authenticated) {
			stdLogError(0, "Login for already logged in RAP");
		} else {
			stdLogError(0, "Login did not provide both user and password and gave %d buffer(s)", bufferCount);
		}
		return respond(RAP_BAD_REQUEST, -1);
	}

	char * user = (char *) bufferHeaders[RAP_USER_INDEX].iov_base;
	char * password = (char *) bufferHeaders[RAP_PASSWORD_INDEX].iov_base;
	size_t userBufferSize = bufferHeaders[RAP_USER_INDEX].iov_len;
	user[userBufferSize - 1] = '\0'; // Guarantee a null terminated string
	password[bufferHeaders[RAP_PASSWORD_INDEX].iov_len - 1] = '\0'; // Guarantee a null terminated string

	int authResult;
	if (pamAuthenticate(user, password)) {
		//stdLog("Login accepted for %s", user);
		return respond(RAP_SUCCESS_NO_DATA, -1);
	} else {
		return respond(RAP_AUTH_FAILLED, -1);
	}
}

typedef size_t (*handlerMethod)(int bufferCount, struct iovec * bufferHeaders);
static handlerMethod handlerMethods[] = { authenticate, readFile, writeFile, listFolder };

int main(int argCount, char ** args) {
	int bufferCount;
	struct iovec bufferHeaders[MAX_BUFFER_PARTS];
	enum RapConstant mID;
	size_t ioResult;
	do {
		bufferCount = MAX_BUFFER_PARTS;

		// Read a message
		ioResult = recvMessage(STDIN_FILENO, &mID, NULL, &bufferCount, bufferHeaders);
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
		ioResult = handlerMethods[mID - RAP_MIN_REQUEST](bufferCount, bufferHeaders);
		if (ioResult < 0) {
			ioResult = 0;
		}

	} while (ioResult);
	return 0;
}
