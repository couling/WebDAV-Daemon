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
