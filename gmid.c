/*
 * Copyright (c) 2020 Omar Polo <op@omarpolo.com>
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
#include <libgen.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <string.h>

struct vhosthead hosts;

int sock4, sock6;

struct imsgbuf logibuf, exibuf, servibuf[PROC_MAX];

const char *config_path, *certs_dir, *hostname;

struct conf conf;

struct tls_config *tlsconf;
struct tls *ctx;

static void
dummy_handler(int signo)
{
	return;
}

/* wrapper around dirname(3).  dn must be PATH_MAX+1 at least. */
static void
pdirname(const char *path, char *dn)
{
	char	 p[PATH_MAX+1];
	char	*t;

	strlcpy(p, path, sizeof(p));
	t = dirname(p);
	memmove(dn, t, strlen(t)+1);
}

static void
mkdirs(const char *path, mode_t mode)
{
	char	dname[PATH_MAX+1];

	pdirname(path, dname);
	if (!strcmp(dname, "/"))
		return;
	mkdirs(dname, mode);
	if (mkdir(path, mode) != 0 && errno != EEXIST)
		fatal("can't mkdir %s: %s", path, strerror(errno));
}

/* $XDG_DATA_HOME/gmid */
char *
data_dir(void)
{
	const char *home, *xdg;
	char *t;

	if ((xdg = getenv("XDG_DATA_HOME")) == NULL) {
		if ((home = getenv("HOME")) == NULL)
			errx(1, "XDG_DATA_HOME and HOME both empty");
		if (asprintf(&t, "%s/.local/share/gmid", home) == -1)
			err(1, "asprintf");
	} else {
		if (asprintf(&t, "%s/gmid", xdg) == -1)
			err(1, "asprintf");
	}

	mkdirs(t, 0755);
	return t;
}

void
load_local_cert(const char *hostname, const char *dir)
{
	char *cert, *key;
	struct vhost *h;

	if (asprintf(&cert, "%s/%s.cert.pem", dir, hostname) == -1)
		errx(1, "asprintf");
	if (asprintf(&key, "%s/%s.key.pem", dir, hostname) == -1)
		errx(1, "asprintf");

	if (access(cert, R_OK) == -1 || access(key, R_OK) == -1)
		gen_certificate(hostname, cert, key);

	h = TAILQ_FIRST(&hosts);
	h->cert = cert;
	h->key = key;
	h->domain = hostname;
}

void
load_vhosts(void)
{
	struct vhost *h;

	TAILQ_FOREACH(h, &hosts, vhosts) {
		if ((h->dirfd = open(h->dir, O_RDONLY | O_DIRECTORY)) == -1)
			fatal("open %s for domain %s", h->dir, h->domain);
	}
}

int
make_socket(int port, int family)
{
	int sock, v;
	struct sockaddr_in addr4;
	struct sockaddr_in6 addr6;
	struct sockaddr *addr;
	socklen_t len;

        switch (family) {
	case AF_INET:
		bzero(&addr4, sizeof(addr4));
		addr4.sin_family = family;
		addr4.sin_port = htons(port);
		addr4.sin_addr.s_addr = INADDR_ANY;
		addr = (struct sockaddr*)&addr4;
		len = sizeof(addr4);
		break;

	case AF_INET6:
		bzero(&addr6, sizeof(addr6));
		addr6.sin6_family = AF_INET6;
		addr6.sin6_port = htons(port);
		addr6.sin6_addr = in6addr_any;
		addr = (struct sockaddr*)&addr6;
		len = sizeof(addr6);
		break;

	default:
		/* unreachable */
		abort();
	}

	if ((sock = socket(family, SOCK_STREAM, 0)) == -1)
		fatal("socket: %s", strerror(errno));

	v = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v)) == -1)
		fatal("setsockopt(SO_REUSEADDR): %s", strerror(errno));

	v = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &v, sizeof(v)) == -1)
		fatal("setsockopt(SO_REUSEPORT): %s", strerror(errno));

	mark_nonblock(sock);

	if (bind(sock, addr, len) == -1)
		fatal("bind: %s", strerror(errno));

	if (listen(sock, 16) == -1)
		fatal("listen: %s", strerror(errno));

	return sock;
}

void
setup_tls(void)
{
	struct vhost *h;

	if ((tlsconf = tls_config_new()) == NULL)
		fatal("tls_config_new");

	/* optionally accept client certs, but don't try to verify them */
	tls_config_verify_client_optional(tlsconf);
	tls_config_insecure_noverifycert(tlsconf);

	if (tls_config_set_protocols(tlsconf, conf.protos) == -1)
		fatal("tls_config_set_protocols");

	if ((ctx = tls_server()) == NULL)
		fatal("tls_server failure");

	h = TAILQ_FIRST(&hosts);

	/* we need to set something, then we can add how many key we want */
	if (tls_config_set_keypair_file(tlsconf, h->cert, h->key))
		fatal("tls_config_set_keypair_file failed for (%s, %s)",
		    h->cert, h->key);

	while ((h = TAILQ_NEXT(h, vhosts)) != NULL) {
		if (tls_config_add_keypair_file(tlsconf, h->cert, h->key) == -1)
			fatal("failed to load the keypair (%s, %s)",
			    h->cert, h->key);
	}

	if (tls_configure(ctx, tlsconf) == -1)
		fatal("tls_configure: %s", tls_error(ctx));
}

static int
listener_main(struct imsgbuf *ibuf)
{
	drop_priv();
	load_default_mime(&conf.mime);
	load_vhosts();
	loop(ctx, sock4, sock6, ibuf);
	return 0;
}

void
init_config(void)
{
	TAILQ_INIT(&hosts);

	conf.port = 1965;
	conf.ipv6 = 0;
	conf.protos = TLS_PROTOCOL_TLSv1_2 | TLS_PROTOCOL_TLSv1_3;

	init_mime(&conf.mime);

	conf.chroot = NULL;
	conf.user = NULL;

	conf.prefork = 3;
}

void
free_config(void)
{
	struct vhost *h, *th;
	struct location *l, *tl;
	struct envlist *e, *te;
	int v;

	v = conf.verbose;

	free(conf.chroot);
	free(conf.user);
	memset(&conf, 0, sizeof(conf));

	conf.verbose = v;

	TAILQ_FOREACH_SAFE(h, &hosts, vhosts, th) {
		TAILQ_FOREACH_SAFE(l, &h->locations, locations, tl) {
			TAILQ_REMOVE(&h->locations, l, locations);

			free((char*)l->match);
			free((char*)l->lang);
			free((char*)l->default_mime);
			free((char*)l->index);
			free((char*)l->block_fmt);
			free(l);
		}

		TAILQ_FOREACH_SAFE(e, &h->env, envs, te) {
			free(e->name);
			free(e->value);
			free(e);
		}

		TAILQ_REMOVE(&hosts, h, vhosts);
		free(h);
	}

	tls_free(ctx);
	tls_config_free(tlsconf);
}

static int
wait_signal(void)
{
	sigset_t mask;
	int signo;

	sigemptyset(&mask);
	sigaddset(&mask, SIGHUP);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	sigwait(&mask, &signo);

	return signo == SIGHUP;
}

void
drop_priv(void)
{
	struct passwd *pw = NULL;

	if (conf.chroot != NULL && conf.user == NULL)
		fatal("can't chroot without an user to switch to after.");

	if (conf.user != NULL) {
		if ((pw = getpwnam(conf.user)) == NULL)
			fatal("can't find user %s", conf.user);
	}

	if (conf.chroot != NULL) {
		if (chroot(conf.chroot) != 0 || chdir("/") != 0)
			fatal("%s: %s", conf.chroot, strerror(errno));
	}

	if (pw != NULL) {
		if (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1)
			fatal("setresuid(%d): %s", pw->pw_uid,
			    strerror(errno));
	}

	if (getuid() == 0)
		log_warn(NULL, "not a good idea to run a network daemon as root");
}

static void
usage(const char *me)
{
	fprintf(stderr,
	    "USAGE: %s [-fn] [-c config] [-P pidfile] | [-6h] [-d certs-dir] [-H host]\n"
	    "       [-p port] [-x cgi] [dir]\n",
	    me);
}

static void
logger_init(void)
{
	int p[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, p) == -1)
		err(1, "socketpair");

	switch (fork()) {
	case -1:
		err(1, "fork");
	case 0:
		signal(SIGHUP, SIG_IGN);
		close(p[0]);
		setproctitle("logger");
		imsg_init(&logibuf, p[1]);
		drop_priv();
		_exit(logger_main(p[1], &logibuf));
	default:
		close(p[1]);
		imsg_init(&logibuf, p[0]);
		return;
	}
}

static int
serve(int argc, char **argv, struct imsgbuf *ibuf)
{
	char		 path[PATH_MAX];
	int		 i, p[2];
	struct vhost	*h;
	struct location	*l;

        if (config_path == NULL) {
		if (hostname == NULL)
			hostname = "localhost";
		if (certs_dir == NULL)
			certs_dir = data_dir();
		load_local_cert(hostname, certs_dir);

		h = TAILQ_FIRST(&hosts);
		h->domain = "*";

		l = TAILQ_FIRST(&h->locations);
		l->auto_index = 1;
		l->match = "*";

		switch (argc) {
		case 0:
			h->dir = getcwd(path, sizeof(path));
			break;
		case 1:
			h->dir = absolutify_path(argv[0]);
			break;
		default:
			usage(getprogname());
			return 1;
		}

		log_notice(NULL, "serving %s on port %d", h->dir, conf.port);
	}

	/* setup tls before dropping privileges: we don't want user
	 * to put private certs inside the chroot. */
	setup_tls();

	for (i = 0; i < conf.prefork; ++i) {
		if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC,
		    PF_UNSPEC, p) == -1)
			fatal("socketpair: %s", strerror(errno));

		switch (fork()) {
		case -1:
			fatal("fork: %s", strerror(errno));
		case 0:		/* child */
			close(p[0]);
			imsg_init(&exibuf, p[1]);
			setproctitle("server");
			_exit(listener_main(&exibuf));
		default:
			close(p[1]);
			imsg_init(&servibuf[i], p[0]);
		}
	}

	setproctitle("executor");
	drop_priv();
	_exit(executor_main(ibuf));
}

static int
write_pidfile(const char *pidfile)
{
	struct flock	lock;
	int		fd;

	if (pidfile == NULL)
		return -1;

	if ((fd = open(pidfile, O_WRONLY|O_CREAT|O_CLOEXEC, 0600)) == -1)
		fatal("can't open pidfile %s: %s", pidfile, strerror(errno));

	lock.l_start = 0;
	lock.l_len = 0;
	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;

	if (fcntl(fd, F_SETLK, &lock) == -1)
		fatal("can't lock %s, gmid is already running?", pidfile);

	if (ftruncate(fd, 0) == -1)
		fatal("ftruncate: %s: %s", pidfile, strerror(errno));

	dprintf(fd, "%d\n", getpid());

	return fd;
}

static void
setup_configless(int argc, char **argv, const char *cgi)
{
	struct vhost	*host;
	struct location	*loc;

	host = xcalloc(1, sizeof(*host));
	host->cgi = cgi;
	TAILQ_INSERT_HEAD(&hosts, host, vhosts);

	loc = xcalloc(1, sizeof(*loc));
	TAILQ_INSERT_HEAD(&host->locations, loc, locations);

	serve(argc, argv, NULL);
	imsg_compose(&logibuf, IMSG_QUIT, 0, 0, -1, NULL, 0);
	imsg_flush(&logibuf);
}

int
main(int argc, char **argv)
{
	struct imsgbuf exibuf;
	int ch, conftest = 0, configless = 0;
	int pidfd, old_ipv6, old_port;
	const char *pidfile = NULL, *cgi = NULL;

	init_config();

	while ((ch = getopt(argc, argv, "6c:d:fH:hnP:p:vx:")) != -1) {
		switch (ch) {
		case '6':
			conf.ipv6 = 1;
			configless = 1;
			break;

		case 'c':
			config_path = absolutify_path(optarg);
			break;

		case 'd':
			certs_dir = optarg;
			configless = 1;
			break;

		case 'f':
			conf.foreground = 1;
			break;

		case 'H':
			hostname = optarg;
			configless = 1;
			break;

		case 'h':
			usage(*argv);
			return 0;

		case 'n':
			conftest = 1;
			break;

		case 'P':
			pidfile = optarg;
			break;

		case 'p':
			conf.port = parse_portno(optarg);
			configless = 1;
			break;

		case 'v':
			conf.verbose++;
			break;

		case 'x':
			/* drop the starting / (if any) */
			if (*optarg == '/')
				optarg++;
			cgi = optarg;
			configless = 1;
			break;

		default:
			usage(*argv);
			return 1;
		}
	}
	argc -= optind;
	argv += optind;

	if (config_path == NULL) {
		configless = 1;
		conf.foreground = 1;
		conf.prefork = 1;
		conf.verbose++;
	}

	if (config_path != NULL && (argc > 0 || configless))
		errx(1, "can't specify options in config mode.");

	if (conftest) {
		parse_conf(config_path);
		puts("config OK");
		return 0;
	}

	if (!conf.foreground && !configless) {
		if (daemon(1, 1) == -1)
			err(1, "daemon");
	}

	if (config_path != NULL)
		parse_conf(config_path);

	logger_init();

	sock4 = make_socket(conf.port, AF_INET);
	sock6 = -1;
	if (conf.ipv6)
		sock6 = make_socket(conf.port, AF_INET6);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);

	if (configless) {
		setup_configless(argc, argv, cgi);
		return 0;
	}

	pidfd = write_pidfile(pidfile);

	/* Linux seems to call the event handlers even when we're
	 * doing a sigwait.  These dummy handlers are here to avoid
	 * being terminated on SIGHUP, SIGINT or SIGTERM. */
	signal(SIGHUP, dummy_handler);
	signal(SIGINT, dummy_handler);
	signal(SIGTERM, dummy_handler);

	/* wait a sighup and reload the daemon */
	for (;;) {
		int p[2];

		if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC,
		    PF_UNSPEC, p) == -1)
			fatal("socketpair: %s", strerror(errno));

		switch (fork()) {
		case -1:
			fatal("fork: %s", strerror(errno));
		case 0:
			close(p[0]);
			imsg_init(&exibuf, p[1]);
			_exit(serve(argc, argv, &exibuf));
		}

		close(p[1]);
		imsg_init(&exibuf, p[0]);

		if (!wait_signal())
			break;

		log_info(NULL, "reloading configuration %s", config_path);

		/* close the executor (it'll close the servers too) */
		imsg_compose(&exibuf, IMSG_QUIT, 0, 0, -1, NULL, 0);
		imsg_flush(&exibuf);
		close(p[0]);

		old_ipv6 = conf.ipv6;
		old_port = conf.port;

		free_config();
		init_config();
		parse_conf(config_path);

		if (old_port != conf.port) {
			close(sock4);
			close(sock6);
			sock4 = -1;
			sock6 = -1;
		}

		if (sock6 != -1 && old_ipv6 != conf.ipv6) {
			close(sock6);
			sock6 = -1;
		}

		if (sock4 == -1)
			sock4 = make_socket(conf.port, AF_INET);
		if (sock6 == -1 && conf.ipv6)
			sock6 = make_socket(conf.port, AF_INET6);
	}

	imsg_compose(&exibuf, IMSG_QUIT, 0, 0, -1, NULL, 0);
	imsg_flush(&exibuf);

	imsg_compose(&logibuf, IMSG_QUIT, 0, 0, -1, NULL, 0);
	imsg_flush(&logibuf);

	if (pidfd != -1)
		close(pidfd);

	return 0;
}
