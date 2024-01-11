/*
 * Copyright (c) 2020, 2021, 2022, 2023 Omar Polo <op@omarpolo.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "gmid.h"

#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <locale.h>
#include <libgen.h>
#include <limits.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <string.h>
#include <syslog.h>
#include <vis.h>

#include "log.h"
#include "proc.h"

#ifndef nitems
#define nitems(_a) (sizeof((_a)) / sizeof((_a)[0]))
#endif

static int main_configure(struct conf *);
static void main_configure_done(struct conf *);
static void main_reload(struct conf *);
static void main_sig_handler(int, short, void *);
static int main_dispatch_server(int, struct privsep_proc *, struct imsg *);
static int main_dispatch_crypto(int, struct privsep_proc *, struct imsg *);
static int main_dispatch_logger(int, struct privsep_proc *, struct imsg *);
static void __dead main_shutdown(struct conf *);
static void main_print_conf(struct conf *);

static struct privsep_proc procs[] = {
	{ "server",	PROC_SERVER,	main_dispatch_server, server },
	{ "crypto",	PROC_CRYPTO,	main_dispatch_crypto, crypto },
	{ "logger",	PROC_LOGGER,	main_dispatch_logger, logger },
};

static const char	*opts = "c:D:fI:hnP:T:U:VvX:";

static const struct option longopts[] = {
	{"help",	no_argument,		NULL,	'h'},
	{"version",	no_argument,		NULL,	'V'},
	{NULL,		0,			NULL,	0},
};

int sock4, sock6;
int privsep_process;
int pidfd = -1;

int debug, verbose;

const char *config_path = SYSCONFDIR "/gmid.conf";
const char *pidfile;

static void
usage(void)
{
	fprintf(stderr,
	    "Version: " GMID_STRING "\n"
	    "Usage: %s [-fnv] [-c config] [-D macro=value] [-P pidfile]\n",
	    getprogname());
}

/*
 * Used by the server process, defined here so gemexp can provide
 * its own implementation.
 */
void
log_request(struct client *c, int code, const char *meta)
{
	struct conf *conf = c->conf;
	char tstamp[64], rfc3339[32];
	char cntmp[64], cn[64] = "-";
	char b[GEMINI_URL_LEN];
	char *fmted;
	const char *t;
	struct tm *tm;
	time_t now;
	int ec;

	if ((now = time(NULL)) == -1)
		fatal("time");
	if ((tm = localtime(&now)) == NULL)
		fatal("localtime");
	if (strftime(tstamp, sizeof(tstamp), "%d/%b%Y:%H:%M:%S %z", tm) == 0)
		fatal("strftime");
	if (strftime(rfc3339, sizeof(rfc3339), "%FT%T%z", tm) == 0)
		fatal("strftime");

	if (c->iri.schema != NULL) {
		/* serialize the IRI */
		strlcpy(b, c->iri.schema, sizeof(b));
		strlcat(b, "://", sizeof(b));

		/* log the decoded host name, but if it was invalid
		 * use the raw one. */
		if (*c->domain != '\0')
			strlcat(b, c->domain, sizeof(b));
		else
			strlcat(b, c->iri.host, sizeof(b));

		if (*c->iri.path != '/')
			strlcat(b, "/", sizeof(b));
		strlcat(b, c->iri.path, sizeof(b)); /* TODO: sanitize UTF8 */
		if (*c->iri.query != '\0') {	    /* TODO: sanitize UTF8 */
			strlcat(b, "?", sizeof(b));
			strlcat(b, c->iri.query, sizeof(b));
		}
	} else {
		if ((t = c->req) == NULL)
			t = "";
		strlcpy(b, t, sizeof(b));
	}

	if (tls_peer_cert_provided(c->ctx)) {
		const char *subj;
		char *n;

		subj = tls_peer_cert_subject(c->ctx);
		if ((n = strstr(subj, "/CN=")) != NULL) {
			strlcpy(cntmp, subj + 4, sizeof(cntmp));
			if ((n = strchr(cntmp, '/')) != NULL)
				*n = '\0';
			strnvis(cn, cntmp, sizeof(cn), VIS_WHITE|VIS_DQ);
		}
	}

	switch (conf->log_format) {
	case LOG_FORMAT_LEGACY:
		ec = asprintf(&fmted, "%s:%s GET %s %d %s", c->rhost,
		    c->rserv, b, code, meta);
		break;

	case LOG_FORMAT_CONDENSED:
		/*
		 * XXX it should log the size of the request and
		 * response.
		 */
		ec = asprintf(&fmted, "%s %s %s %s %s 0 0 %d %s", rfc3339,
		    c->rhost, cn, *c->domain == '\0' ? c->iri.host : c->domain,
		    b, code, meta);
		break;

	/*
	 * Attempt to be compatible with the default Apache httpd'
	 * LogFormat "%h %l %u %t \"%r\" %>s %b"
	 * see <https://httpd.apache.org/docs/current/mod/mod_log_config.html>
	 */
	case LOG_FORMAT_COMMON:
		/*
		 * XXX it should log the size of the response.
		 */
		ec = asprintf(&fmted, "%s %s - %s %s \"%s\" %d 0",
		    *c->domain == '\0' ? c->iri.host : c->domain,
		    c->rhost, cn, tstamp, b, code);
		break;

	/*
	 * Attempt to be compatible with the default nginx' log_format
	 * combined:
	 * '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"';
	 */
	case LOG_FORMAT_COMBINED:
	default:
		/*
		 * XXX it should log the size of the response.
		 */
		ec = asprintf(&fmted, "%s - %s [%s] \"%s\" %d 0 \"-\" \"\"",
		    c->rhost, cn, tstamp, b, code);
		break;
	}

	if (ec == -1)
		fatal("asprintf");

	if (debug)
		fprintf(stderr, "%s\n", fmted);

	proc_compose(conf->ps, PROC_LOGGER, IMSG_LOG_REQUEST,
	    fmted, ec + 1);

	free(fmted);
}

static int
write_pidfile(const char *pidfile)
{
	struct flock	lock;
	int		fd;

	if (pidfile == NULL)
		return -1;

	if ((fd = open(pidfile, O_WRONLY|O_CREAT|O_CLOEXEC, 0600)) == -1)
		fatal("can't open pidfile %s", pidfile);

	lock.l_start = 0;
	lock.l_len = 0;
	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;

	if (fcntl(fd, F_SETLK, &lock) == -1)
		fatalx("can't lock %s, gmid is already running?", pidfile);

	if (ftruncate(fd, 0) == -1)
		fatal("ftruncate %s", pidfile);

	dprintf(fd, "%d\n", getpid());

	return fd;
}

int
main(int argc, char **argv)
{
	struct conf *conf;
	struct privsep *ps;
	const char *errstr, *title = NULL;
	const char *user = NULL, *chroot = NULL;
	size_t i;
	int ch, conftest = 0;
	int proc_instance = 0;
	int proc_id = PROC_PARENT;
	int argc0 = argc;

	setlocale(LC_CTYPE, "");

	/* log to stderr until daemonized */
	log_init(1, LOG_DAEMON);

	while ((ch = getopt_long(argc, argv, opts, longopts, NULL)) != -1) {
		switch (ch) {
		case 'c':
			config_path = absolutify_path(optarg);
			break;
		case 'D':
			if (cmdline_symset(optarg) == -1)
				fatalx("could not parse macro definition: %s",
				    optarg);
			break;
		case 'f':
			debug = 1;
			break;
		case 'h':
			usage();
			return 0;
		case 'I':
			proc_instance = strtonum(optarg, 0, PROC_MAX_INSTANCES,
			    &errstr);
			if (errstr != NULL)
				fatalx("invalid process instance");
			break;
		case 'n':
			conftest++;
			break;
		case 'P':
			pidfile = absolutify_path(optarg);
			break;
		case 'T':
			title = optarg;
			proc_id = proc_getid(procs, nitems(procs), title);
			if (proc_id == PROC_MAX)
				fatalx("invalid process name");
			break;
		case 'U':
			user = optarg;
			break;
		case 'V':
			puts("Version: " GMID_STRING);
			return 0;
		case 'v':
			verbose = 1;
			break;
		case 'X':
			chroot = optarg;
			break;
		default:
			usage();
			return 1;
		}
	}

	if (argc - optind != 0)
		usage();

	conf = config_new();

	/*
	 * Only the parent loads the config, the others get user and
	 * chroot via flags and the rest via imsg.
	 */
	if (proc_id == PROC_PARENT) {
		if (parse_conf(conf, config_path) == -1)
			fatalx("failed to load configuration file");
		if (*conf->chroot != '\0' && *conf->user == '\0')
			fatalx("can't chroot without a user to switch to.");
	} else {
		if (user)
			strlcpy(conf->user, user, sizeof(conf->user));
		if (chroot)
			strlcpy(conf->chroot, chroot, sizeof(conf->chroot));
	}

	if ((ps = calloc(1, sizeof(*ps))) == NULL)
		fatal("calloc");
	ps->ps_env = conf;
	conf->ps = ps;
	if (*conf->user) {
		if (geteuid())
			fatalx("need root privileges");
		if ((ps->ps_pw = getpwnam(conf->user)) == NULL)
			fatalx("unknown user %s", conf->user);
		if (*conf->chroot == '\0')
			strlcpy(conf->chroot, ps->ps_pw->pw_dir,
			    sizeof(conf->chroot));
	}

	if (conftest) {
		conf->conftest = 1;
		if (config_test(conf) == -1)
			fatalx("failed to load the configuration");
		fprintf(stderr, "config OK\n");
		if (conftest > 1)
			main_print_conf(conf);
		return 0;
	}

	ps->ps_instances[PROC_SERVER] = conf->prefork;
	ps->ps_instance = proc_instance;
	if (title != NULL)
		ps->ps_title[proc_id] = title;

	if (*conf->chroot != '\0') {
		for (i = 0; i < nitems(procs); ++i)
			procs[i].p_chroot = conf->chroot;
	}

	log_init(debug, LOG_DAEMON);
	log_setverbose(verbose);
	if (title != NULL)
		log_procinit(title);

	/* only the parent returns */
	proc_init(ps, procs, nitems(procs), debug, argc0, argv, proc_id);

	log_procinit("main");
	if (!debug && daemon(0, 0) == -1)
		fatal("daemon");

	pidfd = write_pidfile(pidfile);

	sandbox_main_process();

	event_init();

	signal(SIGPIPE, SIG_IGN);

	signal_set(&ps->ps_evsigint, SIGINT, main_sig_handler, ps);
	signal_set(&ps->ps_evsigterm, SIGTERM, main_sig_handler, ps);
	signal_set(&ps->ps_evsigchld, SIGCHLD, main_sig_handler, ps);
	signal_set(&ps->ps_evsighup, SIGHUP, main_sig_handler, ps);
	signal_set(&ps->ps_evsigusr1, SIGUSR1, main_sig_handler, ps);

	signal_add(&ps->ps_evsigint, NULL);
	signal_add(&ps->ps_evsigterm, NULL);
	signal_add(&ps->ps_evsigchld, NULL);
	signal_add(&ps->ps_evsighup, NULL);
	signal_add(&ps->ps_evsigusr1, NULL);

	proc_connect(ps);

	if (main_configure(conf) == -1)
		fatal("configuration failed");

	event_dispatch();
	main_shutdown(conf);
	/* NOTREACHED */
	return 0;
}

static int
main_send_logfd(struct conf *conf)
{
	struct privsep	*ps = conf->ps;
	char		 path[PATH_MAX];
	int		 r, fd = -1;

	if (conf->log_access) {
		r = snprintf(path, sizeof(path), "%s%s%s", conf->chroot,
		    *conf->chroot == '\0' ? "" : "/", conf->log_access);
		if (r < 0 || (size_t)r >= sizeof(path)) {
			log_warnx("path too long: %s", conf->log_access);
			goto done;
		}

		fd = open(conf->log_access, O_WRONLY|O_CREAT|O_APPEND, 0600);
		if (fd == -1)
			log_warn("can't open %s", conf->log_access);
	}

 done:
	if (proc_compose_imsg(ps, PROC_LOGGER, -1, IMSG_LOG_ACCESS, -1, fd,
	    NULL, 0) == -1)
		return -1;
	if (proc_compose_imsg(ps, PROC_LOGGER, -1, IMSG_LOG_FACILITY, -1, -1,
	    &conf->log_facility, sizeof(conf->log_facility)) == -1)
		return -1;
	if (proc_compose_imsg(ps, PROC_LOGGER, -1, IMSG_LOG_SYSLOG, -1, -1,
	    &conf->log_syslog, sizeof(conf->log_syslog)) == -1)
		return -1;
	return 0;
}

static int
main_configure(struct conf *conf)
{
	struct privsep	*ps = conf->ps;

	if (main_send_logfd(conf) == -1)
		return -1;

	conf->reload = conf->prefork + 1; /* servers, crypto */

	if (proc_compose(ps, PROC_SERVER, IMSG_RECONF_START, NULL, 0) == -1)
		return -1;
	if (proc_compose(ps, PROC_CRYPTO, IMSG_RECONF_START, NULL, 0) == -1)
		return -1;

	if (config_send(conf) == -1)
		return -1;

	if (proc_compose(ps, PROC_SERVER, IMSG_RECONF_END, NULL, 0) == -1)
		return -1;
	if (proc_compose(ps, PROC_CRYPTO, IMSG_RECONF_END, NULL, 0) == -1)
		return -1;

	return 0;
}

static void
main_configure_done(struct conf *conf)
{
	if (conf->reload == 0) {
		log_warnx("configuration already done");
		return;
	}

	conf->reload--;
	/* send IMSG_CTL_START? */
}

static void
main_reload(struct conf *conf)
{
	if (conf->reload) {
		log_debug("%s: already in progress: %d pending",
		    __func__, conf->reload);
		return;
	}

	log_debug("%s: config file %s", __func__, config_path);
	config_purge(conf);

	if (parse_conf(conf, config_path) == -1) {
		log_warnx("failed to parse the config");
		return;
	}

	main_configure(conf);
}

static void
main_sig_handler(int sig, short ev, void *arg)
{
	struct privsep	*ps = arg;

	/*
	 * Normal signal handler rules don't apply here because libevent
	 * decouples for us.
	 */

	switch (sig) {
	case SIGHUP:
		if (privsep_process != PROC_PARENT)
			return;
		log_info("reload requested with SIGHUP");
		main_reload(ps->ps_env);
		break;
	case SIGCHLD:
		log_warnx("one child died, quitting");
		/* fallthrough */
	case SIGTERM:
	case SIGINT:
		main_shutdown(ps->ps_env);
		break;
	case SIGUSR1:
		main_send_logfd(ps->ps_env);
		break;
	default:
		fatalx("unexpected signal %d", sig);
	}
}

static int
main_dispatch_server(int fd, struct privsep_proc *p, struct imsg *imsg)
{
	struct privsep	*ps = p->p_ps;
	struct conf	*conf = ps->ps_env;

	switch (imsg->hdr.type) {
	case IMSG_RECONF_DONE:
		main_configure_done(conf);
		break;
	default:
		return -1;
	}

	return 0;
}

static int
main_dispatch_crypto(int fd, struct privsep_proc *p, struct imsg *imsg)
{
	struct privsep	*ps = p->p_ps;
	struct conf	*conf = ps->ps_env;

	switch (imsg->hdr.type) {
	case IMSG_RECONF_DONE:
		main_configure_done(conf);
		break;
	default:
		return -1;
	}

	return 0;
}

static int
main_dispatch_logger(int fd, struct privsep_proc *p, struct imsg *imsg)
{
	struct privsep	*ps = p->p_ps;
	struct conf	*conf = ps->ps_env;

	switch (imsg->hdr.type) {
	case IMSG_RECONF_DONE:
		main_configure_done(conf);
		break;
	default:
		return -1;
	}

	return 0;
}

static void __dead
main_shutdown(struct conf *conf)
{
	proc_kill(conf->ps);
	config_purge(conf);
	free(conf->ps);
	/* free(conf); */

	log_info("parent terminating, pid %d", getpid());

	if (pidfd != -1)
		close(pidfd);

	exit(0);
}

static void
main_print_conf(struct conf *conf)
{
	struct vhost	*h;
	/* struct location	*l; */
	/* struct envlist	*e; */
	/* struct alist	*a; */

	if (*conf->chroot != '\0')
		printf("chroot \"%s\"\n", conf->chroot);
	/* XXX: defined mimes? */
	printf("prefork %d\n", conf->prefork);
	/* XXX: protocols? */
	if (*conf->user != '\0')
		printf("user \"%s\"\n", conf->user);

	TAILQ_FOREACH(h, &conf->hosts, vhosts) {
		printf("\nserver \"%s\" {\n", h->domain);
		printf("	cert \"%s\"\n", h->cert);
		printf("	key \"%s\"\n", h->key);
		/* TODO: print locations... */
		printf("}\n");
	}
}
