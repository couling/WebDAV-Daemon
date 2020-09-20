#include "configuration.h"

#include "shared.h"

#include "xml.h"

#include <string.h>
#include <errno.h>
WebdavdConfiguration config;

///////////////////////
// Handler Functions //
///////////////////////

static int readConfigInt(xmlTextReaderPtr reader, int * value, const char * configFile) {
	const char * nodeName = xmlTextReaderConstLocalName(reader);
	const char * valueString;
	int result = stepOverText(reader, &valueString);
	if (valueString) {
		char * endPtr;
		long int tmp = strtol(valueString, &endPtr, 10);
		if (*endPtr || tmp < 0 || tmp > 0xFFFFFFF) {
			stdLogError(0, "Invalid %s value %s - should be numeric in %s", nodeName, tmp, configFile);
			exit(1);
		}
		*value = tmp;
		xmlFree((char *) valueString);
	}
	return result;
}

static int readConfigString(xmlTextReaderPtr reader, const char ** value) {
	if (*value) {
		xmlFree((char *) *value);
	}
	return stepOverText(reader, value);
}

static int readConfigTime(xmlTextReaderPtr reader, time_t * value, const char * configFile) {
	const char * nodeName = xmlTextReaderConstLocalName(reader);
	const char * sessionTimeoutString;
	int result = stepOverText(reader, &sessionTimeoutString);
	if (sessionTimeoutString) {
		long int hour = 0, minute = 0, second;
		char * endPtr;
		second = strtol(sessionTimeoutString, &endPtr, 10);
		if (*endPtr) {
			if (*endPtr != ':' || endPtr == sessionTimeoutString) {
				stdLogError(0, "Invalid %s %s in %s", nodeName, sessionTimeoutString, configFile);
				exit(1);
			}
			minute = second;

			char * endPtr2;
			endPtr++;
			second = strtol(endPtr, &endPtr2, 10);
			if (*endPtr2) {
				if (*endPtr2 != ':' || endPtr2 == endPtr) {
					stdLogError(0, "Invalid s%s %s in %s", nodeName, sessionTimeoutString, configFile);
					exit(1);
				}
				hour = minute;
				minute = second;
				endPtr2++;
				second = strtol(endPtr2, &endPtr, 10);
				if (*endPtr != '\0') {
					stdLogError(0, "Invalid %s %s in %s", nodeName, sessionTimeoutString, configFile);
					exit(1);
				}
			}
		}
		*value = (((hour * 60) + minute) * 60) + second;
		xmlFree((char *) sessionTimeoutString);
	}
	return result;
}

static int configListen(WebdavdConfiguration * config, xmlTextReaderPtr reader, const char * configFile) {
	//<listen><port>80</port><host>localhost</host><encryption>disabled</encryption></listen>
	int index = config->daemonCount++;
	config->daemons = reallocSafe(config->daemons, sizeof(*config->daemons) * config->daemonCount);
	memset(&config->daemons[index], 0, sizeof(config->daemons[index]));
	int depth = xmlTextReaderDepth(reader) + 1;
	int result = stepInto(reader);
	while (result && xmlTextReaderDepth(reader) == depth) {
		if (xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT
				&& !strcmp(xmlTextReaderConstNamespaceUri(reader),
				CONFIG_NAMESPACE)) {
			if (!strcmp(xmlTextReaderConstLocalName(reader), "port")) {
				result = readConfigInt(reader, &config->daemons[index].port, configFile);
			} else if (!strcmp(xmlTextReaderConstLocalName(reader), "host")) {
				result = readConfigString(reader, &config->daemons[index].host);
			} else if (!strcmp(xmlTextReaderConstLocalName(reader), "encryption")) {
				const char * encryptionString;
				result = stepOverText(reader, &encryptionString);
				if (encryptionString) {
					if (!strcmp(encryptionString, "none")) {
						config->daemons[index].sslEnabled = 0;
					} else if (!strcmp(encryptionString, "ssl")) {
						config->daemons[index].sslEnabled = 1;
					} else {
						stdLogError(0, "invalid encryption method %s in %s", encryptionString, configFile);
						exit(1);
					}
					xmlFree((char *) encryptionString);
				}
			} else if (!strcmp(xmlTextReaderConstLocalName(reader), "forward-to")) {
				int depth2 = xmlTextReaderDepth(reader) + 1;
				result = stepInto(reader);
				config->daemons[index].forwardToIsEncrypted = -1;
				while (result && xmlTextReaderDepth(reader) == depth2) {
					if (xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT
							&& !strcmp(xmlTextReaderConstNamespaceUri(reader), CONFIG_NAMESPACE)) {
						if (!strcmp(xmlTextReaderConstLocalName(reader), "host")) {
							result = readConfigString(reader, &config->daemons[index].forwardToHost);
						} else if (!strcmp(xmlTextReaderConstLocalName(reader), "port")) {
							result = readConfigInt(reader, &config->daemons[index].forwardToPort, configFile);
						} else if (!strcmp(xmlTextReaderConstLocalName(reader), "encryption")) {
							const char * encryptionString;
							result = stepOverText(reader, &encryptionString);
							if (encryptionString) {
								if (!strcmp(encryptionString, "none")) {
									config->daemons[index].forwardToIsEncrypted = 0;
								} else if (!strcmp(encryptionString, "ssl")) {
									config->daemons[index].forwardToIsEncrypted = 1;
								} else {
									stdLogError(0, "invalid encryption method %s in %s", encryptionString,
											configFile);
									exit(1);
								}
								xmlFree((char *) encryptionString);
							}
						} else {
							result = stepOver(reader);
						}
					}
					if (config->daemons[index].forwardToPort == 0) {
						stdLogError(0, "forward-to did not specify a port %s", configFile);
						exit(1);
					}
					if (config->daemons[index].forwardToIsEncrypted == -1) {
						config->daemons[index].forwardToIsEncrypted =
								config->daemons[index].forwardToPort == 443 ? 1 : 0;
					}
				}
			}
		} else {
			result = stepOver(reader);
		}
	}
	if (config->daemons[index].port == -1) {
		stdLogError(0, "port not specified for listen in %s", configFile);
		exit(1);
	}
	return result;
}

static int configSessionTimeout(WebdavdConfiguration * config, xmlTextReaderPtr reader,
		const char * configFile) {
	//<session-timeout>5:00</session-timeout>
	return readConfigTime(reader, &config->rapMaxSessionLife, configFile);
}

static int configMaxIpConnections(WebdavdConfiguration * config, xmlTextReaderPtr reader,
		const char * configFile) {
	// <max-ip-connections>20</max-ip-connections>
	return readConfigInt(reader, &config->maxConnectionsPerIp, configFile);
}

static int configRapTimeout(WebdavdConfiguration * config, xmlTextReaderPtr reader, const char * configFile) {
	// <rap-timeout>2:00</rap-timeout>
	return readConfigTime(reader, &config->rapTimeoutRead, configFile);
}

static int configRestricted(WebdavdConfiguration * config, xmlTextReaderPtr reader, const char * configFile) {
	//<restricted>nobody</restricted>
	return readConfigString(reader, &config->restrictedUser);
}

static int configMimeFile(WebdavdConfiguration * config, xmlTextReaderPtr reader, const char * configFile) {
	//<mime-file>/etc/mime.types</mime-file>
	return readConfigString(reader, &config->mimeTypesFile);
}

static int configRapBinary(WebdavdConfiguration * config, xmlTextReaderPtr reader, const char * configFile) {
	//<rap-binary>/usr/sbin/rap</rap-binary>
	return readConfigString(reader, &config->rapBinary);
}

static int configPamService(WebdavdConfiguration * config, xmlTextReaderPtr reader, const char * configFile) {
	//<pam-service>webdavd</pam-service>
	return readConfigString(reader, &config->pamServiceName);
}

static int configAccessLog(WebdavdConfiguration * config, xmlTextReaderPtr reader, const char * configFile) {
	return readConfigString(reader, &config->accessLog);
}

static int configErrorLog(WebdavdConfiguration * config, xmlTextReaderPtr reader, const char * configFile) {
	return readConfigString(reader, &config->errorLog);
}

static int configMaxLockTime(WebdavdConfiguration * config, xmlTextReaderPtr reader, const char * configFile) {
	// <max-lock-time>120</max-lock-time>
	return readConfigTime(reader, &config->maxLockTime, configFile);
}

static int configChroot(WebdavdConfiguration * config, xmlTextReaderPtr reader, const char * configFile) {
	// <chroot-path>~</chroot-path>
	return readConfigString(reader, &config->chrootPath);
}

//<ssl-cert>...</ssl-cert>
static int configConfigSSLCert(WebdavdConfiguration * config, xmlTextReaderPtr reader,
		const char * configFile) {
	int index = config->sslCertCount++;
	config->sslCerts = reallocSafe(config->sslCerts, sizeof(*config->sslCerts) * config->sslCertCount);
	config->sslCerts[index].certificateFile = NULL;
	config->sslCerts[index].chainFileCount = 0;
	config->sslCerts[index].chainFiles = NULL;
	config->sslCerts[index].keyFile = NULL;
	int depth = xmlTextReaderDepth(reader) + 1;
	int result = stepInto(reader);
	while (result && xmlTextReaderDepth(reader) == depth) {
		if (xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT
				&& !strcmp(xmlTextReaderConstNamespaceUri(reader),
				CONFIG_NAMESPACE)) {
			if (!strcmp(xmlTextReaderConstLocalName(reader), "certificate")) {
				result = readConfigString(reader, &config->sslCerts[index].certificateFile);
			} else if (!strcmp(xmlTextReaderConstLocalName(reader), "key")) {
				result = readConfigString(reader, &config->sslCerts[index].keyFile);
			} else if (!strcmp(xmlTextReaderConstLocalName(reader), "chain")) {
				const char * chainFile;
				result = stepOverText(reader, &chainFile);
				if (chainFile) {
					int chainFileIndex = config->sslCerts[index].chainFileCount++;
					config->sslCerts[index].chainFiles = reallocSafe(config->sslCerts[index].chainFiles,
							config->sslCerts[index].chainFileCount
									* sizeof(*config->sslCerts[index].chainFiles));
					config->sslCerts[index].chainFiles[chainFileIndex] = chainFile;
				}
			} else {
				result = stepOver(reader);
			}
		} else {
			result = stepOver(reader);
		}
	}
	if (!config->sslCerts[index].certificateFile) {
		stdLogError(0, "certificate not specified in ssl-cert in %s", configFile);
	}
	if (!config->sslCerts[index].keyFile) {
		stdLogError(0, "key not specified in ssl-cert in %s", configFile);
	}
	return result;
}

static int configResponseDir(WebdavdConfiguration * config, xmlTextReaderPtr reader, const char * configFile) {
	if (config->staticResponseDir) {
		xmlFree((char *) config->staticResponseDir);
	}
	int result = stepOverText(reader, &config->staticResponseDir);
	if (config->staticResponseDir) {
		size_t stringSize = strlen(config->staticResponseDir);
		if (config->staticResponseDir[stringSize - 1] == '/') {
			((char *) config->staticResponseDir)[stringSize - 1] = '\0';
		}
	}
	return result;
}

static int configAddHeader(WebdavdConfiguration * config, xmlTextReaderPtr reader, const char * configFile) {
	//<add-header name="Access-Control-Allow-Headers">cache-control</add-header>

	// keep track of the number of headers
	int index = config->addHeadersCount++;

	// increase the size of the config-->addHeaders memory area
	config->addHeaders = reallocSafe(config->addHeaders, sizeof(*config->addHeaders) * config->addHeadersCount);
	memset(&config->addHeaders[index], 0, sizeof(config->addHeaders[index]));

	// add the values to the configurations
	config->addHeaders[index].name = xmlTextReaderGetAttribute(reader, "name");
	int result = readConfigString(reader, &config->addHeaders[index].value);
	return result;
}

///////////////////////////
// End Handler Functions //
///////////////////////////

///////////////////
// Configuration //
///////////////////

typedef struct ConfigurationFunction {
	const char * nodeName;
	int (*func)(WebdavdConfiguration * config, xmlTextReaderPtr reader, const char * configFile);
} ConfigurationFunction;

static int compareConfigFunction(const void * a, const void * b) {
	return strcmp(((const ConfigurationFunction *) a)->nodeName,
			((const ConfigurationFunction *) b)->nodeName);
}

// This MUST be sorted in aplabetical order (for nodeName).  The array is binary-searched.
static const ConfigurationFunction configFunctions[] = {
		{ .nodeName = "access-log", .func = &configAccessLog },                // <access-log />
		{ .nodeName = "add-header", .func = &configAddHeader },                // <add-header />
		{ .nodeName = "chroot-path", .func = &configChroot },                  // <chroot />
		{ .nodeName = "error-log", .func = &configErrorLog },                  // <error-log />
		{ .nodeName = "listen", .func = &configListen },                       // <listen />
		{ .nodeName = "max-ip-connections", .func = &configMaxIpConnections }, // <max-ip-connections />
		{ .nodeName = "max-lock-time", .func = &configMaxLockTime },           // <max-lock-time />
		{ .nodeName = "mime-file", .func = &configMimeFile },                  // <mime-file />
		{ .nodeName = "pam-service", .func = &configPamService },              // <pam-service />
		{ .nodeName = "rap-binary", .func = &configRapBinary },                // <rap-binary />
		{ .nodeName = "rap-timeout", .func = &configRapTimeout },              // <rap-timeout />
		{ .nodeName = "restricted", .func = &configRestricted },               // <restricted />
		{ .nodeName = "session-timeout", .func = &configSessionTimeout },      // <session-timeout />
		{ .nodeName = "ssl-cert", .func = &configConfigSSLCert },              // <ssl-cert />
		{ .nodeName = "static-response-dir", .func = &configResponseDir }      // <static-response-dir />
};

static int configFunctionCount = sizeof(configFunctions) / sizeof(*configFunctions);

static int configureServer(WebdavdConfiguration * config, xmlTextReaderPtr reader, const char * configFile) {
	memset(config, 0, sizeof(*config));

	int depth = xmlTextReaderDepth(reader) + 1;
	int result = stepInto(reader);

	while (result && xmlTextReaderDepth(reader) == depth) {
		if (xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT
				&& !strcmp(xmlTextReaderConstNamespaceUri(reader),
				CONFIG_NAMESPACE)) {

			ConfigurationFunction node = { .nodeName = xmlTextReaderConstLocalName(reader) };
			ConfigurationFunction * function = bsearch(&node, configFunctions, configFunctionCount,
					sizeof(*configFunctions), &compareConfigFunction);

			if (function) {
				result = function->func(config, reader, configFile);
			} else {
				result = stepOver(reader);
			}

		} else {
			result = stepOver(reader);
		}
	}

	// Set the defaults for some fields if they were not set.
	if (!config->maxConnectionsPerIp) {
		config->maxConnectionsPerIp = 50;
	}
	if (!config->rapMaxSessionLife) {
		config->rapMaxSessionLife = 60 * 5;
	}
	if (!config->rapTimeoutRead) {
		config->rapTimeoutRead = 120;
	}
	if (!config->rapBinary) {
		config->rapBinary = "/usr/lib/webdavd/webdav-worker";
	}
	if (!config->mimeTypesFile) {
		config->mimeTypesFile = "/etc/mime.types";
	}
	if (!config->staticResponseDir) {
		config->staticResponseDir = "/usr/share/webdavd";
	}
	if (!config->pamServiceName) {
		config->pamServiceName = "webdavd";
	}
	if (!config->maxLockTime) {
		config->maxLockTime = 60;
	}
	if (!config->restrictedUser) {
		config->restrictedUser = "root";
	}

	return result;
}

void configure(WebdavdConfiguration ** config, int * configCount, const char * configFile) {
	xmlTextReaderPtr reader = xmlReaderForFile(configFile, NULL, XML_PARSE_NOENT);
	if (!reader) {
		stdLogError(errno, "Could not load config file %s", configFile);
		exit(1);
	}
	xmlReaderSuppressErrors(reader);
	if (!stepInto(reader)) {
		stdLogError(0, "could not create xml reader for %s", configFile);
		exit(1);
	}
	if (!elementMatches(reader, CONFIG_NAMESPACE, "server-config")) {
		stdLogError(0, "root node is not server-config in namespace %s %s",
		CONFIG_NAMESPACE, configFile);
		exit(1);
	}

	int result = stepInto(reader);

	while (result && xmlTextReaderDepth(reader) == 1) {
		if (elementMatches(reader, CONFIG_NAMESPACE, "server")) {
			int index = (*configCount)++;
			WebdavdConfiguration * newConfig = reallocSafe(*config, *configCount * sizeof(**config));
			*config = newConfig;
			result = configureServer(&newConfig[index], reader, configFile);
		} else {
			stdLog("Warning: skipping %s:%s in %s", xmlTextReaderConstNamespaceUri(reader),
					xmlTextReaderConstLocalName(reader), configFile);
			result = stepOver(reader);
		}
	}

	xmlFreeTextReader(reader);
}

static void xmlFreeIfNotNull(const char * value) {
	if (value) xmlFree((char *) value);
}

static void freeIfNotNull(void * value) {
	if (value) freeSafe(value);
}

void freeConfigurationData(WebdavdConfiguration * configData) {
	xmlFreeIfNotNull(configData->accessLog);
	xmlFreeIfNotNull(configData->errorLog);
	for (int i = 0; i < configData->daemonCount; i++) {
		xmlFreeIfNotNull(configData->daemons[i].host);
		xmlFreeIfNotNull(configData->daemons[i].forwardToHost);
	}
	freeIfNotNull(configData->daemons);
	xmlFreeIfNotNull(configData->mimeTypesFile);
	xmlFreeIfNotNull(configData->pamServiceName);
	xmlFreeIfNotNull(configData->rapBinary);
	xmlFreeIfNotNull(configData->restrictedUser);
	xmlFreeIfNotNull(configData->staticResponseDir);
	for (int i = 0; i < configData->sslCertCount; i++) {
		xmlFreeIfNotNull(configData->sslCerts[i].certificateFile);
		xmlFreeIfNotNull(configData->sslCerts[i].keyFile);
		for (int j = 0; i < configData->sslCerts[i].chainFileCount; j++) {
			xmlFreeIfNotNull(configData->sslCerts[i].chainFiles[j]);
		}
		freeIfNotNull(configData->sslCerts[i].chainFiles);
	}
	freeIfNotNull(configData->sslCerts);
}

///////////////////////
// End Configuration //
///////////////////////
