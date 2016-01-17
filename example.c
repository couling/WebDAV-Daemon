#include <sys/param.h>
#include <sys/wait.h>

#include <err.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <security/pam_appl.h>
#include <security/openpam.h>	/* for openpam_ttyconv() */

extern char **environ;

static pam_handle_t *pamh;
static struct pam_conv pamc;

static void usage(void) {

	fprintf(stderr, "Usage: su [login [args]]\n");
	exit(1);
}

int main(int argc, char *argv[]) {
	char hostname[MAXHOSTNAMELEN];
	const char *user, *tty;
	char **args, **pam_envlist, **pam_env;
	struct passwd *pwd;
	int o, pam_err, status;
	pid_t pid;

	while ((o = getopt(argc, argv, "h")) != -1)
		switch (o) {
		case 'h':
		default:
			usage();
		}

	argc -= optind;
	argv += optind;

	if (argc > 0) {
		user = *argv;
		--argc;
		++argv;
	} else {
		user = "root";
	}

	/* initialize PAM */
	pamc.conv = &openpam_ttyconv;
	pam_start("su", user, &pamc, &pamh);

	/* set some items */
	gethostname(hostname, sizeof(hostname));
	if ((pam_err = pam_set_item(pamh, PAM_RHOST, hostname)) != PAM_SUCCESS)
		goto pamerr;
	user = getlogin();
	if ((pam_err = pam_set_item(pamh, PAM_RUSER, user)) != PAM_SUCCESS)
		goto pamerr;
	tty = ttyname(STDERR_FILENO);
	if ((pam_err = pam_set_item(pamh, PAM_TTY, tty)) != PAM_SUCCESS)
		goto pamerr;

	/* authenticate the applicant */
	if ((pam_err = pam_authenticate(pamh, 0)) != PAM_SUCCESS)
		goto pamerr;
	if ((pam_err = pam_acct_mgmt(pamh, 0)) == PAM_NEW_AUTHTOK_REQD)
		pam_err = pam_chauthtok(pamh, PAM_CHANGE_EXPIRED_AUTHTOK);
	if (pam_err != PAM_SUCCESS)
		goto pamerr;

	/* establish the requested credentials */
	if ((pam_err = pam_setcred(pamh, PAM_ESTABLISH_CRED)) != PAM_SUCCESS)
		goto pamerr;

	/* authentication succeeded; open a session */
	if ((pam_err = pam_open_session(pamh, 0)) != PAM_SUCCESS)
		goto pamerr;

	/* get mapped user name; PAM may have changed it */
	pam_err = pam_get_item(pamh, PAM_USER, (const void **) &user);
	if (pam_err != PAM_SUCCESS || (pwd = getpwnam(user)) == NULL)
		goto pamerr;

	/* export PAM environment */
	if ((pam_envlist = pam_getenvlist(pamh)) != NULL) {
		for (pam_env = pam_envlist; *pam_env != NULL; ++pam_env) {
			putenv(*pam_env);
			free(*pam_env);
		}
		free(pam_envlist);
	}

	/* build argument list */
	if ((args = calloc(argc + 2, sizeof *args)) == NULL) {
		warn("calloc()");
		goto err;
	}
	*args = pwd->pw_shell;
	memcpy(args + 1, argv, argc * sizeof *args);

	/* fork and exec */
	switch ((pid = fork())) {
	case -1:
		warn("fork()");
		goto err;
	case 0:
		/* child: give up privs and start a shell */

		/* set uid and groups */
		if (initgroups(pwd->pw_name, pwd->pw_gid) == -1) {
			warn("initgroups()");
			_exit(1);
		}
		if (setgid(pwd->pw_gid) == -1) {
			warn("setgid()");
			_exit(1);
		}
		if (setuid(pwd->pw_uid) == -1) {
			warn("setuid()");
			_exit(1);
		}
		execve(*args, args, environ);
		warn("execve()");
		_exit(1);
	default:
		/* parent: wait for child to exit */
		waitpid(pid, &status, 0);

		/* close the session and release PAM resources */
		pam_err = pam_close_session(pamh, 0);
		pam_end(pamh, pam_err);

		exit(WEXITSTATUS(status));
	}

	pamerr: fprintf(stderr, "Sorry\n");
	err: pam_end(pamh, pam_err);
	exit(1);
}
