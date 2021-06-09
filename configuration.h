#ifndef WEBDAV_CONFIGURATION_H
#define WEBDAV_CONFIGURATION_H

#include <time.h>
#include <stdbool.h>

//////////////////////////////////////
// Webdavd Configuration Structures //
//////////////////////////////////////

typedef struct DaemonConfig {
	int port;
	const char * host;	// For opening socket ourselves
	const char * name;	// For socket activation, i.e. open socket passed to daemon
	int sslEnabled;
	int forwardToIsEncrypted;
	int forwardToPort;
	const char * forwardToHost;
} DaemonConfig;

typedef struct SSLConfig {
	int chainFileCount;
	const char * keyFile;
	const char * certificateFile;
	const char ** chainFiles;

} SSLConfig;

typedef struct WebdavdConfiguration {
	const char * restrictedUser;
	const char * chrootPath;

	// Daemons
	int daemonCount;
	DaemonConfig * daemons;
	int maxConnectionsPerIp;

	// RAP
	time_t rapMaxSessionLife;
	time_t rapTimeoutRead;
	const char * pamServiceName;

	// Max lock time
	time_t maxLockTime;

	// files
	const char * mimeTypesFile;
	const char * rapBinary;
	const char * accessLog;
	const char * errorLog;
	const char * staticResponseDir;

	// SSL
	int sslCertCount;
	SSLConfig * sslCerts;

	// OPTIONS Requests
	int unprotectOptions;

	// Use systemd/xinetd style socket based activation
	bool socketActivation;

} WebdavdConfiguration;

extern WebdavdConfiguration config;

//////////////////////////////////////////
// End Webdavd Configuration Structures //
//////////////////////////////////////////

void configure(WebdavdConfiguration ** config, int * configCount, const char * configFile);
void freeConfigurationData(WebdavdConfiguration * configData);

#define CONFIG_NAMESPACE "http://couling.me/webdavd"

#endif
