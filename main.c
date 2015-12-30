#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <microhttpd.h>

#define PORT 8888

char ACCESS_DENIED_STRING[] = "Access Denied!";
char NOT_FOUND_STRING[] = "Not Found!";

typedef struct {
	char * user;
	char * home;
} User;

struct MHD_Response * translate_request(User * foundUser) {

}

int auth_lookup(struct MHD_Connection *connection, User * foundUser) {
	char * password;
	foundUser->user = MHD_basic_auth_get_username_password(connection, &password);
	foundUser->home = password;
	return foundUser->user != NULL;
}

int answer_to_connection(void *cls, struct MHD_Connection *connection, const char *url, const char *method,
		const char *version, const char *upload_data, size_t *upload_data_size, void **con_cls) {

	User user;
	int returnCode;
	struct MHD_Response * response;

	if (auth_lookup(connection, &user)) {
		printf("auth\n");
		char dummyString[1024];
		sprintf(dummyString, "DUMMY %s %s", user.user, user.home);
		returnCode = MHD_HTTP_OK;
		response = MHD_create_response_from_buffer(strlen(dummyString), dummyString, MHD_RESPMEM_MUST_COPY);

	} else {
		printf("not auth\n");
		returnCode = MHD_HTTP_UNAUTHORIZED;
		response = MHD_create_response_from_buffer(strlen(ACCESS_DENIED_STRING), ACCESS_DENIED_STRING,
				MHD_RESPMEM_MUST_COPY);
		if (MHD_NO == MHD_add_response_header(response, "WWW-Authenticate", "Basic realm=\"My Server\"")) {
			MHD_destroy_response(response);
			return MHD_NO;
		}
	}
	printf("%d!\n", returnCode);
	int ret = MHD_queue_response(connection, returnCode, response);
	MHD_destroy_response(response);
	return ret;
}

int main(int argCount, char ** args) {
	struct MHD_Daemon *daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY,
	PORT, NULL, NULL, &answer_to_connection, NULL, MHD_OPTION_END);

	if (NULL == daemon) {
		return 1;
	}

	pthread_exit(NULL);

	//MHD_stop_daemon(daemon);
	//return 0;
}
