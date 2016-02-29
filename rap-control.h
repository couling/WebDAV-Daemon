#ifndef rap_control_h
#define rap_control_h

#include <time.h>

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

	// Managed by Low level handler function
	int writeDataFd; // Should be closed by uploadComplete()
	int readDataFd;  // Should be closed by processNewRequest() when sent to the RAP.
	int responseAlreadyGiven;
	const char * lockToken;
} RAP;

// Used as a place holder for failed auth requests which failed due to invalid credentials
extern const RAP AUTH_FAILED_RAP;

// Used as a place holder for failed auth requests which failed due to errors
extern const RAP AUTH_ERROR_RAP;

#define AUTH_FAILED ( ( RAP *) &AUTH_FAILED_RAP )
#define AUTH_ERROR ( ( RAP *) &AUTH_ERROR_RAP )

#define AUTH_SUCCESS(rap) (rap != AUTH_FAILED && rap != AUTH_ERROR)

void initializeRapDatabase();
RAP * acquireRap(const char * user, const char * password, const char * clientIp);
//void releaseRap(RAP * processor);
#define releaseRap(processor)
void destroyRap(RAP * rapSession);
void runCleanRapPool();

#endif
