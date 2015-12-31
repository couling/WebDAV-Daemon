#define _GNU_SOURCE
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "shared.h"

pid_t ppid;					// Parent process id
char * boundUser;			// Provided in arg
struct sockaddr_un address; // Generated ready to bind a socket
int socket_fd;				// Bond socket

char * boundPassword;		// Provided on first login and assigned after login
char * boundHome;			// Assigned after login



static void handleRequest(int connection_fd) {
	struct ucred credentials;
	int ucred_length = sizeof(struct ucred);

	/* fill in the user data structure */
	if (getsockopt(connection_fd, SOL_SOCKET, SO_PEERCRED, &credentials, &ucred_length)) {
		fprintf(stderr,"could obtain credentials from unix domain socket %d: %s\n", errno, strerror(errno));
		exit(1);
	}

	if (ppid != credentials.pid) {
		fprintf(stderr, "incorrect PID accessing server\n");
		exit(1);
	}




}

int main(int argCount, char ** args) {
	ppid = getppid();
	boundUser = args[1];
	if (argCount != 2) {
		fprintf(stderr, "Usage: %s <user> <socket directory>\n", args[0]);
		return 1;
	}
	socket_fd = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (socket_fd < 0) {
		fprintf(stderr, "socket() failed %d: %s\n", errno, strerror(errno));
		exit(1);
	}
	memset(&address, 0, sizeof(struct sockaddr_un));
	address.sun_family = AF_UNIX;
	snprintf(address.sun_path, sizeof(address.sun_path), "%s/%d", args[2], getpid());
	if (bind(socket_fd, (struct sockaddr *) &address, sizeof(struct sockaddr_un)) != 0) {
		fprintf(stderr, "bind() failed %d: %s\n", errno, strerror(errno));
		exit(1);
	}
	printf("%s\n", address.sun_path);

	int connection_fd;
	struct sockaddr_un address;
	socklen_t addrlen = sizeof(address);
	while ((connection_fd = accept(socket_fd, (struct sockaddr *) &address, &addrlen)) > -1) {
		pid_t child = fork();
		if (child) {
			/* still inside server process */
			close(connection_fd);
		}
		else {
			/* now inside newly created connection handling process */
			close(socket_fd);
			handleRequest(connection_fd);
			close(connection_fd);
			exit(0);
		}


	}

	close(socket_fd);
	unlink(address.sun_path);

	return 0;
}
