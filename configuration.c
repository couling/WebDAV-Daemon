#include "configuration.h"

#include "shared.h"

#include <string.h>

///////////////////////
// Handler Functions //
///////////////////////

static int configListen(struct WebdavdConfiguration * config, xmlTextReaderPtr reader, const char * configFile) {
	//<listen><port>80</port><host>localhost</host><encryption>disabled</encryption></listen>
	int index = config->daemonCount++;
	config->daemons = reallocSafe(config->daemons, sizeof(*config->daemons) * config->daemonCount);
	memset(&config->daemons[index], 0, sizeof(config->daemons[index]));
	int depth = xmlTextReaderDepth(reader) + 1;
	int result = stepInto(reader);
	while (result && xmlTextReaderDepth(reader) == depth) {
		if (xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT && !strcmp(xmlTextReaderConstNamespaceUri(reader),
		CONFIG_NAMESPACE)) {
			if (!strcmp(xmlTextReaderConstLocalName(reader), "port")) {
				if (config->daemons[index].port) {
					stdLogError(0, "port specified for listen more than once int %s", configFile);
					exit(1);
				}
				const char * portString;
				result = stepOverText(reader, &portString);
				if (portString != NULL) {
					char * endP;
					long int parsedPort = strtol(portString, &endP, 10);
					if (!*endP && parsedPort > 0 && parsedPort <= 0xFFFF) {
						config->daemons[index].port = parsedPort;
					} else {
						stdLogError(0, "%s is not a valid port in %s", portString, configFile);
						exit(1);
					}
					xmlFree((char *) portString);
				}
			} else if (!strcmp(xmlTextReaderConstLocalName(reader), "host")) {
				if (config->daemons[index].host != NULL) {
					stdLogError(0, "host specified for listen more than once int %s", configFile);
					exit(1);
				}
				result = stepOverText(reader, &config->daemons[index].host);
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
							if (config->daemons[index].forwardToHost) {
								stdLogError(0, "forward-to host specified for listen more than once int %s",
										configFile);
								exit(1);
							}
							result = stepOverText(reader, &config->daemons[index].forwardToHost);
						} else if (!strcmp(xmlTextReaderConstLocalName(reader), "port")) {
							const char * portString;
							result = stepOverText(reader, &portString);
							if (portString != NULL) {
								char * endP;
								long int parsedPort = strtol(portString, &endP, 10);
								if (!*endP && parsedPort > 0 && parsedPort <= 0xFFFF) {
									config->daemons[index].forwardToPort = parsedPort;
								} else {
									stdLogError(0, "%s is not a valid forward-to in %s", portString, configFile);
									exit(1);
								}
								xmlFree((char *) portString);
							}
						} else if (!strcmp(xmlTextReaderConstLocalName(reader), "encryption")) {
							const char * encryptionString;
							result = stepOverText(reader, &encryptionString);
							if (encryptionString) {
								if (!strcmp(encryptionString, "none")) {
									config->daemons[index].forwardToIsEncrypted = 0;
								} else if (!strcmp(encryptionString, "ssl")) {
									config->daemons[index].forwardToIsEncrypted = 1;
								} else {
									stdLogError(0, "invalid encryption method %s in %s", encryptionString, configFile);
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

static int configSessionTimeout(struct WebdavdConfiguration * config, xmlTextReaderPtr reader, const char * configFile) {
	//<session-timeout>5:00</session-timeout>
	const char * sessionTimeoutString;
	int result = stepOverText(reader, &sessionTimeoutString);
	if (sessionTimeoutString) {
		long int hour = 0, minute = 0, second;
		char * endPtr;
		second = strtol(sessionTimeoutString, &endPtr, 10);
		if (*endPtr) {
			if (*endPtr != ':' || endPtr == sessionTimeoutString) {
				stdLogError(0, "Invalid session timeout length %s in %s", sessionTimeoutString, configFile);
				exit(1);
			}
			minute = second;

			char * endPtr2;
			endPtr++;
			second = strtol(endPtr, &endPtr2, 10);
			if (*endPtr2) {
				if (*endPtr2 != ':' || endPtr2 == endPtr) {
					stdLogError(0, "Invalid session timeout length %s in %s", sessionTimeoutString, configFile);
					exit(1);
				}
				hour = minute;
				minute = second;
				endPtr2++;
				second = strtol(endPtr2, &endPtr, 10);
				if (*endPtr != '\0') {
					stdLogError(0, "Invalid session timeout length %s in %s", sessionTimeoutString, configFile);
					exit(1);
				}
			}
		}
		config->rapMaxSessionLife = (((hour * 60) + minute) * 60) + second;
		xmlFree((char *) sessionTimeoutString);
	}
	return result;
}

static int configMaxUserSessions(struct WebdavdConfiguration * config, xmlTextReaderPtr reader, const char * configFile) {
	// <max-user-sessions>10</max-user-sessions>
	const char * sessionCountString;
	int result = stepOverText(reader, &sessionCountString);
	if (sessionCountString) {
		char * endPtr;
		long int maxUserSessions = strtol(sessionCountString, &endPtr, 10);
		if (*endPtr || maxUserSessions < 0 || maxUserSessions > 0xFFFFFFF) {
			stdLogError(0, "Invalid max-user-sessions %s in %s", maxUserSessions, configFile);
			exit(1);
		}
		config->rapMaxSessionsPerUser = maxUserSessions;
		xmlFree(stepOverText);
	}
	return result;
}

static int configMaxIpConnections(struct WebdavdConfiguration * config, xmlTextReaderPtr reader,
		const char * configFile) {
	// <max-ip-connections>20</max-ip-connections>
	const char * sessionCountString;
	int result = stepOverText(reader, &sessionCountString);
	if (sessionCountString) {
		char * endPtr;
		long int maxUserSessions = strtol(sessionCountString, &endPtr, 10);
		if (*endPtr || maxUserSessions < 0 || maxUserSessions > 0xFFFFFFF) {
			stdLogError(0, "Invalid max-user-sessions %s in %s", maxUserSessions, configFile);
			exit(1);
		}
		config->rapMaxSessionsPerUser = maxUserSessions;
		xmlFree((char *) sessionCountString);
	}
	return result;
}

static int configRestricted(struct WebdavdConfiguration * config, xmlTextReaderPtr reader, const char * configFile) {
	//<restricted>nobody</restricted>
	if (config->restrictedUser) {
		stdLogError(0, "restricted-user specified more than once in %s", configFile);
		exit(1);
	}
	return stepOverText(reader, &config->restrictedUser);;
}

static int configMimeFile(struct WebdavdConfiguration * config, xmlTextReaderPtr reader, const char * configFile) {
	//<mime-file>/etc/mime.types</mime-file>
	if (config->mimeTypesFile) {
		stdLogError(0, "restricted-user specified more than once in %s", configFile);
		exit(1);
	}
	return stepOverText(reader, &config->mimeTypesFile);
}

static int configRapBinary(struct WebdavdConfiguration * config, xmlTextReaderPtr reader, const char * configFile) {
	//<rap-binary>/usr/sbin/rap</rap-binary>
	if (config->rapBinary) {
		stdLogError(0, "restricted-user specified more than once in %s", configFile);
		exit(1);
	}
	return stepOverText(reader, &config->rapBinary);
}

static int configPamService(struct WebdavdConfiguration * config, xmlTextReaderPtr reader, const char * configFile) {
	//<pam-service>webdavd</pam-service>
	if (config->pamServiceName) {
		stdLogError(0, "restricted-user specified more than once in %s", configFile);
		exit(1);
	}
	return stepOverText(reader, &config->pamServiceName);
}

static int configAccessLog(struct WebdavdConfiguration * config, xmlTextReaderPtr reader, const char * configFile) {
	if (config->accessLog) {
		stdLogError(0, "restricted-user specified more than once in %s", configFile);
		exit(1);
	}
	return stepOverText(reader, &config->accessLog);
}

static int configErrorLog(struct WebdavdConfiguration * config, xmlTextReaderPtr reader, const char * configFile) {
	if (config->errorLog) {
		stdLogError(0, "restricted-user specified more than once in %s", configFile);
		exit(1);
	}
	return stepOverText(reader, &config->errorLog);
}

//<ssl-cert>...</ssl-cert>
static int configConfigSSLCert(struct WebdavdConfiguration * config, xmlTextReaderPtr reader, const char * configFile) {
	int index = config->sslCertCount++;
	config->sslCerts = reallocSafe(config->sslCerts, sizeof(*config->sslCerts) * config->sslCertCount);
	config->sslCerts[index].certificateFile = NULL;
	config->sslCerts[index].chainFileCount = 0;
	config->sslCerts[index].chainFiles = NULL;
	config->sslCerts[index].keyFile = NULL;
	int depth = xmlTextReaderDepth(reader) + 1;
	int result = stepInto(reader);
	while (result && xmlTextReaderDepth(reader) == depth) {
		if (xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT && !strcmp(xmlTextReaderConstNamespaceUri(reader),
		CONFIG_NAMESPACE)) {
			if (!strcmp(xmlTextReaderConstLocalName(reader), "certificate")) {
				if (config->sslCerts[index].certificateFile) {
					stdLogError(0, "more than one certificate specified in ssl-cert %s", configFile);
					exit(1);
				}
				result = stepOverText(reader, &config->sslCerts[index].certificateFile);
			} else if (!strcmp(xmlTextReaderConstLocalName(reader), "key")) {
				if (config->sslCerts[index].keyFile) {
					stdLogError(0, "more than one key specified in ssl-cert %s", configFile);
					exit(1);
				}
				return stepOverText(reader, &config->sslCerts[index].keyFile);
			} else if (!strcmp(xmlTextReaderConstLocalName(reader), "chain")) {
				const char * chainFile;
				result = stepOverText(reader, &chainFile);
				if (chainFile) {
					int chainFileIndex = config->sslCerts[index].chainFileCount++;
					config->sslCerts[index].chainFiles = reallocSafe(config->sslCerts[index].chainFiles,
							config->sslCerts[index].chainFileCount * sizeof(*config->sslCerts[index].chainFiles));
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

static int configResponseDir(struct WebdavdConfiguration * config, xmlTextReaderPtr reader, const char * configFile) {
	if (config->errorLog) {
		stdLogError(0, "restricted-user specified more than once in %s", configFile);
		exit(1);
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

///////////////////////////
// End Handler Functions //
///////////////////////////

///////////////////
// Configuration //
///////////////////

static int compareConfigFunction(const void * a, const void * b) {
	return strcmp(((const struct ConfigurationFunction *) a)->nodeName,
			((const struct ConfigurationFunction *) b)->nodeName);
}

// This MUST be sorted in aplabetical order (for nodeName).  The array is binary-searched.
static struct ConfigurationFunction configFunctions[] = { { .nodeName = "access-log", .func = &configAccessLog }, //<access-log />
		{ .nodeName = "error-log", .func = &configErrorLog },                  // <error-log />
		{ .nodeName = "listen", .func = &configListen },                       // <listen />
		{ .nodeName = "max-ip-connections", .func = &configMaxIpConnections }, //<max-ip-connections />
		{ .nodeName = "max-user-sessions", .func = &configMaxUserSessions },   // <max-user-sessions />
		{ .nodeName = "mime-file", .func = &configMimeFile },                  // <mime-file />
		{ .nodeName = "pam-service", .func = &configPamService },              // <pam-service />
		{ .nodeName = "rap-binary", .func = &configRapBinary },                // <rap-binary />
		{ .nodeName = "restricted", .func = &configRestricted },               // <restricted />
		{ .nodeName = "session-timeout", .func = &configSessionTimeout },      // <session-timeout />
		{ .nodeName = "ssl-cert", .func = &configConfigSSLCert },              // <ssl-cert />
		{ .nodeName = "static-response-dir", .func = &configResponseDir }      // <static-response-dir />
};

static int configFunctionCount = sizeof(configFunctions) / sizeof(struct ConfigurationFunction);

static int configureServer(struct WebdavdConfiguration * config, xmlTextReaderPtr reader, const char * configFile) {
	memset(config, 0, sizeof(*config));

	int depth = xmlTextReaderDepth(reader) + 1;
	int result = stepInto(reader);

	while (result && xmlTextReaderDepth(reader) == depth) {
		if (xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT && !strcmp(xmlTextReaderConstNamespaceUri(reader),
		CONFIG_NAMESPACE)) {

			struct ConfigurationFunction node = { .nodeName = xmlTextReaderConstLocalName(reader) };
			struct ConfigurationFunction * function = bsearch(&node, configFunctions, configFunctionCount,
					sizeof(*configFunctions), &compareConfigFunction);

			if (function) {
				function->func(config, reader, configFile);
			} else {
				result = stepOver(reader);
			}

		} else {
			result = stepOver(reader);
		}
	}

	// Set the defaults for some fields if they were not set.
	if (!config->maxConnectionsPerIp) {
		config->maxConnectionsPerIp = 20;
	}
	if (!config->rapMaxSessionLife) {
		config->rapMaxSessionLife = 60 * 5;
	}
	if (!config->rapMaxSessionsPerUser) {
		config->rapMaxSessionsPerUser = 10;
	}
	if (!config->rapBinary) {
		config->rapBinary = "/usr/sbin/webdav-rap";
	}
	if (!config->mimeTypesFile) {
		config->mimeTypesFile = "/etc/mime.types";
	}
	if (!config->staticResponseDir) {
		config->staticResponseDir = "/usr/share/webdav";
	}
	if (!config->pamServiceName) {
		config->pamServiceName = "webdav";
	}

	return result;
}

void configure(const char * configFile) {
	xmlTextReaderPtr reader = xmlReaderForFile(configFile, NULL, XML_PARSE_NOENT);
	suppressReaderErrors(reader);
	if (!reader || !stepInto(reader)) {
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
			result = configureServer(&config, reader, configFile);
			break;
		} else {
			stdLog("Warning: skipping %s:%s in %s", xmlTextReaderConstNamespaceUri(reader),
					xmlTextReaderConstLocalName(reader), configFile);
			result = stepOver(reader);
		}
	}

	xmlFreeTextReader(reader);
}

///////////////////////
// End Configuration //
///////////////////////
