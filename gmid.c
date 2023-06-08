/*
 * Copyright (c) 2020, 2021, 2022 Omar Polo <op@omarpolo.com>
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

#include "logger.h"
#include "log.h"

static const char	*opts = "c:D:fhnP:Vv";

static const struct option longopts[] = {
	{"help",	no_argument,		NULL,	'h'},
	{"version",	no_argument,		NULL,	'V'},
	{NULL,		0,			NULL,	0},
};

struct fcgi fcgi[FCGI_MAX];

struct vhosthead hosts;

int sock4, sock6;

struct imsgbuf logibuf, servibuf[PREFORK_MAX];

const char *config_path = "/etc/gmid.conf";
const char *pidfile;

struct conf conf;

static void
dummy_handler(int signo)
{
	return;
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
		memset(&addr4, 0, sizeof(addr4));
		addr4.sin_family = family;
		addr4.sin_port = htons(port);
		addr4.sin_addr.s_addr = INADDR_ANY;
		addr = (struct sockaddr*)&addr4;
		len = sizeof(addr4);
		break;

	case AF_INET6:
		memset(&addr6, 0, sizeof(addr6));
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
		fatal("socket");

	v = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v)) == -1)
		fatal("setsockopt(SO_REUSEADDR)");

	v = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &v, sizeof(v)) == -1)
		fatal("setsockopt(SO_REUSEPORT)");

	mark_nonblock(sock);

	if (bind(sock, addr, len) == -1)
		fatal("bind");

	if (listen(sock, 16) == -1)
		fatal("listen");

	return sock;
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

	if (*conf.chroot != '\0' && *conf.user == '\0')
		fatalx("can't chroot without an user to switch to after.");

	if (*conf.user != '\0') {
		if ((pw = getpwnam(conf.user)) == NULL)
			fatalx("can't find user %s", conf.user);
	}

	if (*conf.chroot != '\0') {
		if (chroot(conf.chroot) != 0 || chdir("/") != 0)
			fatal("%s", conf.chroot);
	}

	if (pw != NULL) {
		if (setgroups(1, &pw->pw_gid) == -1 ||
		    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1 ||
		    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1)
			fatal("cannot drop privileges");
	}

	if (getuid() == 0)
		log_warnx("not a good idea to run a network daemon as root");
}

static void
usage(void)
{
	fprintf(stderr,
	    "Version: " GMID_STRING "\n"
	    "Usage: %s [-fnv] [-c config] [-D macro=value] [-P pidfile]\n",
	    getprogname());
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

static void
serve(void)
{
	int i, p[2];

	for (i = 0; i < conf.prefork; ++i) {
		if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC,
		    PF_UNSPEC, p) == -1)
			fatal("socketpair");

		switch (fork()) {
		case -1:
			fatal("fork");
		case 0:		/* child */
			close(p[0]);
			imsg_init(&servibuf[i], p[1]);
			setproctitle("server");
			_exit(server_main(&servibuf[i], sock4, sock6));
		default:
			close(p[1]);
			imsg_init(&servibuf[i], p[0]);
		}
	}
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
	int i, ch, conftest = 0;
	int pidfd, old_ipv6, old_port;

	setlocale(LC_CTYPE, "");

	/* log to stderr until daemonized */
	log_init(1, LOG_DAEMON);
	logger_init();
	config_init();

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
			conf.foreground = 1;
			break;
		case 'h':
			usage();
			return 0;
		case 'n':
			conftest++;
			break;
		case 'P':
			pidfile = absolutify_path(optarg);
			break;
		case 'V':
			puts("Version: " GMID_STRING);
			return 0;
		case 'v':
			conf.verbose++;
			break;
		default:
			usage();
			return 1;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 0)
		usage();

	parse_conf(config_path);

	if (conftest) {
		fprintf(stderr, "config OK\n");
		if (conftest > 1)
			print_conf();
		return 0;
	}

	if (!conf.foreground) {
		/* log to syslog */
		imsg_compose(&logibuf, IMSG_LOG_TYPE, 0, 0, -1, NULL, 0);
		imsg_flush(&logibuf);
		log_init(0, LOG_DAEMON);

		if (daemon(1, 1) == -1)
			fatal("daemon");
	}
	log_setverbose(conf.verbose);

	sock4 = make_socket(conf.port, AF_INET);
	sock6 = -1;
	if (conf.ipv6)
		sock6 = make_socket(conf.port, AF_INET6);

	signal(SIGPIPE, SIG_IGN);

	pidfd = write_pidfile(pidfile);

	/*
	 * Linux seems to call the event handlers even when we're
	 * doing a sigwait.  These dummy handlers are here to avoid
	 * being terminated on SIGHUP, SIGINT or SIGTERM.
	 */
	signal(SIGHUP, dummy_handler);
	signal(SIGINT, dummy_handler);
	signal(SIGTERM, dummy_handler);

	/* wait a sighup and reload the daemon */
	for (;;) {
		serve();

		if (!wait_signal())
			break;

		log_info("reloading configuration %s", config_path);

		/* close the servers */
		for (i = 0; i < conf.prefork; ++i) {
			imsg_compose(&servibuf[i], IMSG_QUIT, 0, 0, -1,
			    NULL, 0);
			imsg_flush(&servibuf[i]);
			close(servibuf[i].fd);
		}

		old_ipv6 = conf.ipv6;
		old_port = conf.port;

		config_free();
		config_init();
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

	for (i = 0; i < conf.prefork; ++i) {
		imsg_compose(&servibuf[i], IMSG_QUIT, 0, 0, -1, NULL, 0);
		imsg_flush(&servibuf[i]);
		close(servibuf[i].fd);
	}

	imsg_compose(&logibuf, IMSG_QUIT, 0, 0, -1, NULL, 0);
	imsg_flush(&logibuf);
	close(logibuf.fd);

	if (pidfd != -1)
		close(pidfd);

	return 0;
}
