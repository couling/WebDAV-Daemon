#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <microhttpd.h>

#include "shared.h"

#define PORT 8888

char ACCESS_DENIED_STRING[] = "Access Denied!";
char NOT_FOUND_STRING[] = "Not Found!";

typedef struct {
	char * user;
	char * password;
} User;



struct MHD_Daemon **daemons;
int daemonCount;

int queueAuthRequired(struct MHD_Connection *request) {
	struct MHD_Response * response = MHD_create_response_from_buffer(strlen(ACCESS_DENIED_STRING), ACCESS_DENIED_STRING,
			MHD_RESPMEM_MUST_COPY);
	if (!response)
		return MHD_NO;
	if (!MHD_add_response_header(response, "WWW-Authenticate", "Basic realm=\"My Server\"")) {
		MHD_destroy_response(response);
		return MHD_NO;
	}

	int ret = MHD_queue_response(request, MHD_HTTP_UNAUTHORIZED, response);
	MHD_destroy_response(response);
	return ret;
}

int authLookup(struct MHD_Connection *request, User * foundUser) {
	char * user;
	char * password;
	user = MHD_basic_auth_get_username_password(request, &password);
	foundUser->password = password;

	if (foundUser->user) {
		// TODO add PAM authentication
		return MHD_YES;
	}

	foundUser->password = NULL;

	// Authentication failed.
	return queueAuthRequired(request);
}

static int processNewRequest(struct MHD_Connection *request, const char *url, const char *method, DataSession **con_cls) {
	// TODO LOTS
	User user;
	if (!authLookup(request, &user))
		return MHD_NO;

	// If the user was not authenticated then the authLookup will return the appropriate response
	if (!user.user)
		return MHD_YES;

	char dummyString[1024];
	sprintf(dummyString, "User %s Home %s", user.user, user.password);
	struct MHD_Response * response = MHD_create_response_from_buffer(strlen(dummyString), dummyString,
			MHD_RESPMEM_MUST_COPY);
	int ret = MHD_queue_response(request, MHD_HTTP_OK, response);
	MHD_destroy_response(response);

	printf("User %s Home %s\n", user.user, user.password);

	return ret;
}

static int processUploadData(const char *upload_data, size_t * upload_data_size, DataSession *con_cls) {
	// TODO LOTS
}

static int completeUpload(DataSession *con_cls) {
	// TODO LOTS
}

static int answerToRequest(void *cls, struct MHD_Connection *request, const char *url, const char *method,
		const char *version, const char *upload_data, size_t *upload_data_size, DataSession **con_cls) {

	if (*con_cls) {
		if (*upload_data_size)
			return processUploadData(upload_data, upload_data_size, *con_cls);
		else
			return completeUpload(*con_cls);
	} else {
		return processNewRequest(request, url, method, con_cls);
	}
}

int main(int argCount, char ** args) {
	daemonCount = 1;
	daemons = mallocSafe(sizeof(struct MHD_Daemon *) * daemonCount);

	daemons[0] = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY,
	PORT, NULL, NULL, (MHD_AccessHandlerCallback) &answerToRequest, NULL, MHD_OPTION_END);

	if (!daemons[0]) {
		fprintf(stderr, "Unable to initialise daemon on port %d\n", PORT);
		exit(255);
	}

	pthread_exit(NULL);

	//MHD_stop_daemon(daemon);
	//return 0;
}
