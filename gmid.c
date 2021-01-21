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

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <string.h>

#include "gmid.h"

struct vhost hosts[HOSTSLEN];

int goterror;

int exfd;

struct conf conf;

void
fatal(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	if (conf.foreground) {
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
	} else
		vsyslog(LOG_DAEMON | LOG_CRIT, fmt, ap);

	va_end(ap);
	exit(1);
}

void
logs(int priority, struct client *c,
    const char *fmt, ...)
{
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	char *fmted, *s;
	size_t len;
	int ec;
	va_list ap;

	va_start(ap, fmt);

	if (c == NULL) {
		strncpy(hbuf, "<internal>", sizeof(hbuf));
		sbuf[0] = '\0';
	} else {
		len = sizeof(c->addr);
		ec = getnameinfo((struct sockaddr*)&c->addr, len,
		    hbuf, sizeof(hbuf),
		    sbuf, sizeof(sbuf),
		    NI_NUMERICHOST | NI_NUMERICSERV);
		if (ec != 0)
			fatal("getnameinfo: %s", gai_strerror(ec));
	}

	if (vasprintf(&fmted, fmt, ap) == -1)
		fatal("vasprintf: %s", strerror(errno));

	if (conf.foreground)
		fprintf(stderr, "%s:%s %s\n", hbuf, sbuf, fmted);
	else {
		if (asprintf(&s, "%s:%s %s", hbuf, sbuf, fmted) == -1)
			fatal("asprintf: %s", strerror(errno));
		syslog(priority | LOG_DAEMON, "%s", s);
		free(s);
	}

	free(fmted);

	va_end(ap);
}

/* strchr, but with a bound */
static char *
gmid_strnchr(char *s, int c, size_t len)
{
	size_t i;

	for (i = 0; i < len; ++i)
		if (s[i] == c)
			return &s[i];
	return NULL;
}

void
log_request(struct client *c, char *meta, size_t l)
{
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV], b[GEMINI_URL_LEN];
	char *t;
	size_t len;
	int ec;

	len = sizeof(c->addr);
	ec = getnameinfo((struct sockaddr*)&c->addr, len,
	    hbuf, sizeof(hbuf),
	    sbuf, sizeof(sbuf),
	    NI_NUMERICHOST | NI_NUMERICSERV);
	if (ec != 0)
		fatal("getnameinfo: %s", gai_strerror(ec));

	if (c->iri.schema != NULL) {
		/* serialize the IRI */
		strlcpy(b, c->iri.schema, sizeof(b));
		strlcat(b, "://", sizeof(b));
		strlcat(b, c->iri.host, sizeof(b));
		strlcat(b, "/", sizeof(b));
		strlcat(b, c->iri.path, sizeof(b)); /* TODO: sanitize UTF8 */
		if (*c->iri.query != '\0') {	    /* TODO: sanitize UTF8 */
			strlcat(b, "?", sizeof(b));
			strlcat(b, c->iri.query, sizeof(b));
		}
	} else {
		strlcpy(b, c->req, sizeof(b));
	}

	if ((t = gmid_strnchr(meta, '\r', l)) == NULL)
		t = meta + len;

	if (conf.foreground)
		fprintf(stderr, "%s:%s GET %s %.*s\n", hbuf, sbuf, b,
		    (int)(t - meta), meta);
	else
		syslog(LOG_INFO | LOG_DAEMON, "%s:%s GET %s %.*s",
		    hbuf, sbuf, b, (int)(t - meta), meta);
}

void
sig_handler(int sig)
{
	(void)sig;
}

int
starts_with(const char *str, const char *prefix)
{
	size_t i;

	for (i = 0; prefix[i] != '\0'; ++i)
		if (str[i] != prefix[i])
			return 0;
	return 1;
}

ssize_t
filesize(int fd)
{
	ssize_t len;

	if ((len = lseek(fd, 0, SEEK_END)) == -1)
		return -1;
	if (lseek(fd, 0, SEEK_SET) == -1)
		return -1;
	return len;
}

char *
absolutify_path(const char *path)
{
	char *wd, *r;

	if (*path == '/')
		return strdup(path);

	wd = getcwd(NULL, 0);
	if (asprintf(&r, "%s/%s", wd, path) == -1)
		fatal("asprintf: %s", strerror(errno));
	free(wd);
	return r;
}

void
yyerror(const char *msg)
{
	goterror = 1;
	fprintf(stderr, "%d: %s\n", yylineno, msg);
}

int
parse_portno(const char *p)
{
	char	*errstr;
	int	 n;

	n = strtonum(p, 0, UINT16_MAX, &errstr);
	if (errstr != NULL)
		errx(1, "port number is %s: %s", errstr, p);
	return n;
}

void
parse_conf(const char *path)
{
	if ((yyin = fopen(path, "r")) == NULL)
		fatal("cannot open config %s", path);
	yyparse();
	fclose(yyin);

	if (goterror)
		exit(1);
}

void
load_vhosts(struct tls_config *tlsconf)
{
	struct vhost *h;

	/* we need to set something, then we can add how many key we want */
	if (tls_config_set_keypair_file(tlsconf, hosts->cert, hosts->key))
		fatal("tls_config_set_keypair_file failed");

	for (h = hosts; h->domain != NULL; ++h) {
		if (tls_config_add_keypair_file(tlsconf, h->cert, h->key) == -1)
			fatal("failed to load the keypair (%s, %s)",
			    h->cert, h->key);

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

int
listener_main()
{
	int sock4, sock6;
	struct tls *ctx = NULL;
	struct tls_config *tlsconf;

	load_default_mime(&conf.mime);

	if ((tlsconf = tls_config_new()) == NULL)
		fatal("tls_config_new");

	/* optionally accept client certs, but don't try to verify them */
	tls_config_verify_client_optional(tlsconf);
	tls_config_insecure_noverifycert(tlsconf);

	if (tls_config_set_protocols(tlsconf, conf.protos) == -1)
		fatal("tls_config_set_protocols");

	if ((ctx = tls_server()) == NULL)
		fatal("tls_server failure");

	load_vhosts(tlsconf);

	if (tls_configure(ctx, tlsconf) == -1)
		fatal("tls_configure: %s", tls_error(ctx));

	if (!conf.foreground && daemon(0, 1) == -1)
		exit(1);

	sock4 = make_socket(conf.port, AF_INET);
	sock6 = -1;
	if (conf.ipv6)
		sock6 = make_socket(conf.port, AF_INET6);

	sandbox();
	loop(ctx, sock4, sock6);

	return 0;
}

void
usage(const char *me)
{
	fprintf(stderr,
	    "USAGE: %s [-n] [-c config] | [-6fh] [-C cert] [-d root] [-K key] "
	    "[-p port] [-x cgi-bin]\n",
	    me);
}

int
main(int argc, char **argv)
{
	int ch, p[2];
	const char *config_path = NULL;
	size_t i;
	int conftest = 0;

	bzero(hosts, sizeof(hosts));
	for (i = 0; i < HOSTSLEN; ++i)
		hosts[i].dirfd = -1;

	conf.foreground = 1;
	conf.port = 1965;
	conf.ipv6 = 0;
	conf.protos = TLS_PROTOCOL_TLSv1_2 | TLS_PROTOCOL_TLSv1_3;

	init_mime(&conf.mime);

	while ((ch = getopt(argc, argv, "6C:c:d:fhK:np:x:")) != -1) {
		switch (ch) {
		case '6':
			conf.ipv6 = 1;
			break;

		case 'C':
			hosts[0].cert = optarg;
			break;

		case 'c':
			config_path = optarg;
			break;

		case 'd':
			free((char*)hosts[0].dir);
			if ((hosts[0].dir = absolutify_path(optarg)) == NULL)
				fatal("absolutify_path");
			break;

		case 'f':
			conf.foreground = 1;
			break;

		case 'h':
			usage(*argv);
			return 0;

		case 'K':
			hosts[0].key = optarg;
			break;

		case 'n':
			conftest = 1;
			break;

		case 'p':
			conf.port = parse_portno(optarg);
			break;

		case 'x':
			/* drop the starting / (if any) */
			if (*optarg == '/')
				optarg++;
			hosts[0].cgi = optarg;
			break;

		default:
			usage(*argv);
			return 1;
		}
	}

	if (config_path != NULL) {
		if (hosts[0].cert != NULL || hosts[0].key != NULL ||
		    hosts[0].dir != NULL)
			fatal("can't specify options in conf mode");
		parse_conf(config_path);
	} else {
		if (hosts[0].cert == NULL || hosts[0].key == NULL ||
		    hosts[0].dir == NULL)
			fatal("missing cert, key or root directory to serve");
		hosts[0].domain = "*";
	}

	if (conftest) {
		puts("config OK");
		return 0;
	}

	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);

#ifdef SIGINFO
	signal(SIGINFO, sig_handler);
#endif
	signal(SIGUSR2, sig_handler);

	if (!conf.foreground) {
		signal(SIGHUP, SIG_IGN);
		if (daemon(1, 1) == -1)
			fatal("daemon: %s", strerror(errno));
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, p) == -1)
		fatal("socketpair: %s", strerror(errno));

	switch (fork()) {
	case -1:
		fatal("fork: %s", strerror(errno));

	case 0:			/* child */
		close(p[0]);
		exfd = p[1];
		listener_main();
		_exit(0);

	default:		/* parent */
		close(p[1]);
		return executor_main(p[0]);
	}
}
