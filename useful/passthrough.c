#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

int logFileFd;

const char * incomingSocketFile = "/var/run/dummy.sock";
const char * outgoingSocketFile = "/var/run/php5-fpm.sock";

// -pthread

struct PumpHandles {
	int incoming;
	int outgoing;
};

void * pump(struct PumpHandles * handles) {
	char buffer[10240];
	size_t bytesRead;
	while ((bytesRead = read(handles->incoming, buffer, sizeof(bytesRead))) > 0) {
		size_t ignored;
		ignored = write(logFileFd, buffer, bytesRead);
		ignored = write(handles->outgoing, buffer, bytesRead);
		if (ignored < bytesRead) {
			break;
		}
	}
	close(handles->outgoing);
	return NULL;
}

void initSocketAddress(struct sockaddr_un * address, const char * fileName) {
	memset(address, 0, sizeof(addr));
	address->sun_family = AF_UNIX;
	strncpy(address->sun_path, fileName, sizeof(address->sun_path) - 1);
}

void handleConnection(int incomingSocket) {
	struct sockaddr_un addr;
	initSocketAddress(addr, outgoingSocketFile);
	int outgoingSocket;
	if ((outgoingSocket = socket(AF_UNIX, SOCK_STREAM, 0)) == -1
			|| connect(outgoingSocket, (struct sockaddr*) &addr, sizeof(addr)) == -1) {
		perror("client socket");
	}

	pthread_t newThread;
	struct PumpHandles h1 = { .incoming = incomingSocket, .outgoing = outgoingSocket };
	struct PumpHandles h2 = { .incoming = outgoingSocket, .outgoing = incomingSocket };

	if (pthread_create(&newThread, NULL, &rapTimeoutWorker, &h1)
			|| pthread_create(&newThread, NULL, &rapTimeoutWorker, &h2)) {
		perror("thread");
	}
}

int main(int argc, char *argv[]) {

	int serverSocket;

	struct sockaddr_un addr;
	initSocketAddress(addr, incomingSocketFile);

	if ((serverSocket = socket(AF_UNIX, SOCK_STREAM, 0)) == -1
			|| bind(serverSocket, (struct sockaddr*) &addr, sizeof(addr)) == -1 || listen(serverSocket, 5) == -1) {
		perror("server socket");
		exit(-1);
	}

	int clientConnection;
	while ((clientConnection = accept(serverSocket, NULL, NULL)) > 0) {
		handleConnection(clientConnection);
	}

	return 0;
}


