/*
 *   daemon = MHD_start_daemon (MHD_USE_SELECT_INTERNALLY | MHD_USE_SSL,
 PORT, NULL, NULL,
 &answer_to_connection, NULL,
 MHD_OPTION_HTTPS_CERT_CALLBACK, &sni_callback,
 MHD_OPTION_END);
 */



#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/abstract.h>

struct Hosts {
	struct Hosts *next;
	const char *hostname;
	gnutls_pcert_st pcrt;
	gnutls_privkey_t key;
};

static struct Hosts *hosts;

int sni_callback(gnutls_session_t session, const gnutls_datum_t* req_ca_dn, int nreqs,
		const gnutls_pk_algorithm_t* pk_algos, int pk_algos_length, gnutls_pcert_st** pcert, unsigned int *pcert_length,
		gnutls_privkey_t * pkey) {
	char name[256];
	size_t name_len;
	struct Hosts *host;
	unsigned int type;

	name_len = sizeof(name);
	if (GNUTLS_E_SUCCESS != gnutls_server_name_get(session, name, &name_len, &type, 0 /* index */))
		return -1;
	for (host = hosts; NULL != host; host = host->next)
		if (0 == strncmp(name, host->hostname, name_len))
			break;
	if (NULL == host) {
		fprintf(stderr, "Need certificate for %.*s\n", (int) name_len, name);
		return -1;
	}
	fprintf(stderr, "Returning certificate for %.*s\n", (int) name_len, name);
	*pkey = host->key;
	*pcert_length = 1;
	*pcert = &host->pcrt;
	return 0;
}

static void load_keys(const char *hostname, const char *CERT_FILE, const char *KEY_FILE) {
	int ret;
	gnutls_datum_t data;
	struct Hosts *host;

	host = malloc(sizeof(struct Hosts));
	host->hostname = hostname;
	host->next = hosts;
	hosts = host;

	ret = gnutls_load_file(CERT_FILE, &data);
	if (ret < 0) {
		fprintf(stderr, "*** Error loading certificate file %s.\n", CERT_FILE);
		exit(1);
	}
	ret = gnutls_pcert_import_x509_raw(&host->pcrt, &data, GNUTLS_X509_FMT_PEM, 0);
	if (ret < 0) {
		fprintf(stderr, "*** Error loading certificate file: %s\n", gnutls_strerror(ret));
		exit(1);
	}
	gnutls_free(data.data);

	ret = gnutls_load_file(KEY_FILE, &data);
	if (ret < 0) {
		fprintf(stderr, "*** Error loading key file %s.\n", KEY_FILE);
		exit(1);
	}

	gnutls_privkey_init(&host->key);
	ret = gnutls_privkey_import_x509_raw(host->key, &data, GNUTLS_X509_FMT_PEM, NULL, 0);
	if (ret < 0) {
		fprintf(stderr, "*** Error loading key file: %s\n", gnutls_strerror(ret));
		exit(1);
	}
	gnutls_free(data.data);
}
