#ifndef WEBDAV_CONFIGURATION_H
#define WEBDAV_CONFIGURATION_H

#include <time.h>
#include <libxml/xmlreader.h>

//////////////////////////////////////
// Webdavd Configuration Structures //
//////////////////////////////////////

struct DaemonConfig {
	int port;
	const char * host;
	int sslEnabled;
	int forwardToIsEncrypted;
	int forwardToPort;
	const char * forwardToHost;
};

struct SSLConfig {
	int chainFileCount;
	const char * keyFile;
	const char * certificateFile;
	const char ** chainFiles;

};

struct WebdavdConfiguration {
	const char * restrictedUser;

	// Daemons
	int daemonCount;
	struct DaemonConfig * daemons;
	int maxConnectionsPerIp;

	// RAP
	time_t rapMaxSessionLife;
	int rapMaxSessionsPerUser;
	const char * pamServiceName;

	// files
	const char * mimeTypesFile;
	const char * rapBinary;
	const char * accessLog;
	const char * errorLog;
	const char * staticResponseDir;

	// Add static files

	// SSL
	int sslCertCount;
	struct SSLConfig * sslCerts;
}extern config;

struct ConfigurationFunction {
	const char * nodeName;
	int (*func)(struct WebdavdConfiguration * config, xmlTextReaderPtr reader, const char * configFile);
};

//////////////////////////////////////////
// End Webdavd Configuration Structures //
//////////////////////////////////////////

void configure(const char * configFile);

#define CONFIG_NAMESPACE "http://couling.me/webdavd"

#endif
