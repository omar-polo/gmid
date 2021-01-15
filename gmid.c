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

#include <sys/mman.h>
#include <sys/stat.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <string.h>

#include "gmid.h"

struct vhost hosts[HOSTSLEN];

int connected_clients;
int goterror;

struct conf conf;

struct etm {			/* file extension to mime */
	const char	*mime;
	const char	*ext;
} filetypes[] = {
	{"application/pdf",	"pdf"},

	{"image/gif",		"gif"},
	{"image/jpeg",		"jpg"},
	{"image/jpeg",		"jpeg"},
	{"image/png",		"png"},
	{"image/svg+xml",	"svg"},

	{"text/gemini",		"gemini"},
	{"text/gemini",		"gmi"},
	{"text/markdown",	"markdown"},
	{"text/markdown",	"md"},
	{"text/plain",		"txt"},
	{"text/xml",		"xml"},

	{NULL, NULL}
};

__attribute__ ((format (printf, 1, 2)))
__attribute__ ((__noreturn__))
static inline void
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

int
start_reply(struct pollfd *pfd, struct client *client, int code, const char *reason)
{
	char buf[1030]; 	/* status + ' ' + max reply len + \r\n\0 */
	int len;

	client->code = code;
	client->meta = reason;
	client->state = S_INITIALIZING;

	len = snprintf(buf, sizeof(buf), "%d %s\r\n", code, reason);
	assert(len < (int)sizeof(buf));

	switch (tls_write(client->ctx, buf, len)) {
	case TLS_WANT_POLLIN:
		pfd->events = POLLIN;
		return 0;
	case TLS_WANT_POLLOUT:
		pfd->events = POLLOUT;
		return 0;
	default:
		return 1;
	}
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

const char *
path_ext(const char *path)
{
	const char *end;

	end = path + strlen(path)-1;
	for (; end != path; --end) {
		if (*end == '.')
			return end+1;
		if (*end == '/')
			break;
	}

	return NULL;
}

const char *
mime(const char *path)
{
	const char *ext, *def = "application/octet-stream";
	struct etm *t;

	if ((ext = path_ext(path)) == NULL)
		return def;

	for (t = filetypes; t->mime != NULL; ++t)
		if (!strcmp(ext, t->ext))
			return t->mime;

	return def;
}

int
check_path(struct client *c, const char *path, int *fd)
{
	struct stat sb;

	assert(path != NULL);
	if ((*fd = openat(c->host->dirfd, *path ? path : ".",
	    O_RDONLY | O_NOFOLLOW | O_CLOEXEC)) == -1) {
		return FILE_MISSING;
	}

	if (fstat(*fd, &sb) == -1) {
		LOGN(c, "failed stat for %s: %s", path, strerror(errno));
		return FILE_MISSING;
	}

	if (S_ISDIR(sb.st_mode))
		return FILE_DIRECTORY;

	if (sb.st_mode & S_IXUSR)
		return FILE_EXECUTABLE;

	return FILE_EXISTS;
}

int
open_file(char *fpath, char *query, struct pollfd *fds, struct client *c)
{
	switch (check_path(c, fpath, &c->fd)) {
	case FILE_EXECUTABLE:
		if (c->host->cgi != NULL && starts_with(fpath, c->host->cgi))
			return start_cgi(fpath, "", query, fds, c);

		/* fallthrough */

	case FILE_EXISTS:
		if ((c->len = filesize(c->fd)) == -1) {
			LOGE(c, "failed to get file size for %s", fpath);
			goodbye(fds, c);
			return 0;
		}

		if ((c->buf = mmap(NULL, c->len, PROT_READ, MAP_PRIVATE,
			    c->fd, 0)) == MAP_FAILED) {
			warn("mmap: %s", fpath);
			goodbye(fds, c);
			return 0;
		}
		c->i = c->buf;
		return start_reply(fds, c, SUCCESS, mime(fpath));

	case FILE_DIRECTORY:
		LOGD(c, "%s is a directory, trying %s/index.gmi", fpath, fpath);
		close(c->fd);
		c->fd = -1;
		send_dir(fpath, fds, c);
		return 0;

	case FILE_MISSING:
		if (c->host->cgi != NULL && starts_with(fpath, c->host->cgi))
			return check_for_cgi(fpath, query, fds, c);

		if (!start_reply(fds, c, NOT_FOUND, "not found"))
			return 0;
		goodbye(fds, c);
		return 0;

	default:
		/* unreachable */
		abort();
	}
}

void
send_file(char *path, char *query, struct pollfd *fds, struct client *c)
{
	ssize_t ret, len;

	if (c->fd == -1) {
		if (!open_file(path, query, fds, c))
			return;
		c->state = S_SENDING;
	}

	len = (c->buf + c->len) - c->i;

	while (len > 0) {
		switch (ret = tls_write(c->ctx, c->i, len)) {
		case -1:
			LOGE(c, "tls_write: %s", tls_error(c->ctx));
			goodbye(fds, c);
			return;

		case TLS_WANT_POLLIN:
			fds->events = POLLIN;
			return;

		case TLS_WANT_POLLOUT:
			fds->events = POLLOUT;
			return;

		default:
			c->i += ret;
			len -= ret;
			break;
		}
	}

	goodbye(fds, c);
}

void
send_dir(char *path, struct pollfd *fds, struct client *client)
{
	char fpath[PATHBUF];
	size_t len;

	bzero(fpath, PATHBUF);

	if (path[0] != '.')
		fpath[0] = '.';

	/* this cannot fail since sizeof(fpath) > maxlen of path */
	strlcat(fpath, path, PATHBUF);
	len = strlen(fpath);

	/* add a trailing / in case. */
	if (fpath[len-1] != '/') {
		fpath[len] = '/';
	}

	strlcat(fpath, "index.gmi", sizeof(fpath));

	send_file(fpath, NULL, fds, client);
}

void
handle_handshake(struct pollfd *fds, struct client *c)
{
	struct vhost *h;
	const char *servname;

	switch (tls_handshake(c->ctx)) {
	case 0:  /* success */
	case -1: /* already handshaked */
		break;
	case TLS_WANT_POLLIN:
		fds->events = POLLIN;
		return;
	case TLS_WANT_POLLOUT:
		fds->events = POLLOUT;
		return;
	default:
		/* unreachable */
		abort();
	}

	servname = tls_conn_servername(c->ctx);
	if (servname == NULL)
		goto hostnotfound;

	for (h = hosts; h->domain != NULL; ++h) {
		if (!strcmp(h->domain, servname) || !strcmp(h->domain, "*"))
			break;
	}

	if (h->domain != NULL) {
		c->state = S_OPEN;
		c->host = h;
		handle_open_conn(fds, c);
		return;
	}

hostnotfound:
	/* XXX: check the correct response */
	if (!start_reply(fds, c, BAD_REQUEST, "Wrong host or missing SNI"))
		return;
	goodbye(fds, c);
}

void
handle_open_conn(struct pollfd *fds, struct client *c)
{
	char buf[GEMINI_URL_LEN];
	const char *parse_err = "invalid request";
	struct iri iri;

	bzero(buf, sizeof(buf));

	switch (tls_read(c->ctx, buf, sizeof(buf)-1)) {
	case -1:
		LOGE(c, "tls_read: %s", tls_error(c->ctx));
		goodbye(fds, c);
		return;

	case TLS_WANT_POLLIN:
		fds->events = POLLIN;
		return;

	case TLS_WANT_POLLOUT:
		fds->events = POLLOUT;
		return;
	}

	if (!trim_req_iri(buf) || !parse_iri(buf, &iri, &parse_err)) {
		if (!start_reply(fds, c, BAD_REQUEST, parse_err))
			return;
		goodbye(fds, c);
		return;
	}

	if (strcmp(iri.schema, "gemini") || iri.port_no != conf.port) {
		if (!start_reply(fds, c, PROXY_REFUSED, "won't proxy request"))
			return;
		goodbye(fds, c);
		return;
	}

	LOGI(c, "GET %s%s%s",
	    *iri.path ? iri.path : "/",
	    *iri.query ? "?" : "",
	    *iri.query ? iri.query : "");

	send_file(iri.path, iri.query, fds, c);
}

void
handle(struct pollfd *fds, struct client *client)
{
	switch (client->state) {
	case S_HANDSHAKE:
		handle_handshake(fds, client);
		break;

	case S_OPEN:
                handle_open_conn(fds, client);
		break;

	case S_INITIALIZING:
		if (!start_reply(fds, client, client->code, client->meta))
			return;

		if (client->code != SUCCESS) {
			/* we don't need a body */
			goodbye(fds, client);
			return;
		}

		client->state = S_SENDING;

		/* fallthrough */

	case S_SENDING:
		if (client->child != -1)
			handle_cgi(fds, client);
		else
			send_file(NULL, NULL, fds, client);
		break;

	case S_CLOSING:
		goodbye(fds, client);
		break;

	default:
		/* unreachable */
		abort();
	}
}

void
mark_nonblock(int fd)
{
	int flags;

	if ((flags = fcntl(fd, F_GETFL)) == -1)
		fatal("fcntl(F_GETFL): %s", strerror(errno));
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
		fatal("fcntl(F_SETFL): %s", strerror(errno));
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
do_accept(int sock, struct tls *ctx, struct pollfd *fds, struct client *clients)
{
	int i, fd;
	struct sockaddr_storage addr;
	socklen_t len;

	len = sizeof(addr);
	if ((fd = accept(sock, (struct sockaddr*)&addr, &len)) == -1) {
		if (errno == EWOULDBLOCK)
			return;
		fatal("accept: %s", strerror(errno));
	}

	mark_nonblock(fd);

	for (i = 0; i < MAX_USERS; ++i) {
		if (fds[i].fd == -1) {
			bzero(&clients[i], sizeof(struct client));
			if (tls_accept_socket(ctx, &clients[i].ctx, fd) == -1)
				break; /* goodbye fd! */

			fds[i].fd = fd;
			fds[i].events = POLLIN;

			clients[i].state = S_HANDSHAKE;
			clients[i].fd = -1;
			clients[i].child = -1;
			clients[i].buf = MAP_FAILED;
			clients[i].af = AF_INET;
			clients[i].addr = addr;

			connected_clients++;
			return;
		}
	}

	close(fd);
}

void
goodbye(struct pollfd *pfd, struct client *c)
{
	c->state = S_CLOSING;

	switch (tls_close(c->ctx)) {
	case TLS_WANT_POLLIN:
		pfd->events = POLLIN;
		return;
	case TLS_WANT_POLLOUT:
		pfd->events = POLLOUT;
		return;
	}

	connected_clients--;

	tls_free(c->ctx);
	c->ctx = NULL;

	if (c->buf != MAP_FAILED)
		munmap(c->buf, c->len);

	if (c->fd != -1)
		close(c->fd);

	close(pfd->fd);
	pfd->fd = -1;
}

void
loop(struct tls *ctx, int sock4, int sock6)
{
	int i;
	struct client clients[MAX_USERS];
	struct pollfd fds[MAX_USERS];

	for (i = 0; i < MAX_USERS; ++i) {
		fds[i].fd = -1;
		fds[i].events = POLLIN;
		bzero(&clients[i], sizeof(struct client));
	}

	fds[0].fd = sock4;
	fds[1].fd = sock6;

	for (;;) {
		if (poll(fds, MAX_USERS, INFTIM) == -1) {
			if (errno == EINTR) {
                                warnx("connected clients: %d",
				    connected_clients);
				continue;
			}
			fatal("poll: %s", strerror(errno));
		}

		for (i = 0; i < MAX_USERS; i++) {
			if (fds[i].revents == 0)
				continue;

			if (fds[i].revents & (POLLERR|POLLNVAL))
				fatal("bad fd %d: %s", fds[i].fd,
				    strerror(errno));

			if (fds[i].revents & POLLHUP) {
				/* fds[i] may be the fd of the stdin
				 * of a cgi script that has exited. */
				if (!clients[i].waiting_on_child) {
					goodbye(&fds[i], &clients[i]);
					continue;
				}
			}

			if (fds[i].fd == sock4)
				do_accept(sock4, ctx, fds, clients);
			else if (fds[i].fd == sock6)
				do_accept(sock6, ctx, fds, clients);
			else
				handle(&fds[i], &clients[i]);
		}
	}
}

char *
absolutify_path(const char *path)
{
	char *wd, *r;

	if (*path == '/')
		return strdup(path);

	wd = getwd(NULL);
	if (asprintf(&r, "%s/%s", wd, path) == -1)
		err(1, "asprintf");
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
	char *ep;
	long lval;

	errno = 0;
	lval = strtol(p, &ep, 10);
	if (p[0] == '\0' || *ep != '\0')
		errx(1, "not a number: %s", p);
	if (lval < 0 || lval > UINT16_MAX)
		errx(1, "port number out of range for domain %s: %ld", p, lval);
	return lval;
}

void
parse_conf(const char *path)
{
	if ((yyin = fopen(path, "r")) == NULL)
		err(1, "cannot open config %s", path);
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
		errx(1, "tls_config_set_keypair_file failed");

	for (h = hosts; h->domain != NULL; ++h) {
		if (tls_config_add_keypair_file(tlsconf, h->cert, h->key) == -1)
			errx(1, "failed to load the keypair (%s, %s)",
			    h->cert, h->key);

		if ((h->dirfd = open(h->dir, O_RDONLY | O_DIRECTORY)) == -1)
			err(1, "open %s for domain %s", h->dir, h->domain);
	}
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
	struct tls *ctx = NULL;
	struct tls_config *tlsconf;
	int sock4, sock6, ch;
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

	connected_clients = 0;

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
				err(1, "absolutify_path");
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
			errx(1, "can't specify options in conf mode");
		parse_conf(config_path);
	} else {
		if (hosts[0].cert == NULL || hosts[0].key == NULL ||
		    hosts[0].dir == NULL)
			errx(1, "missing cert, key or root directory to serve");
		hosts[0].domain = "*";
	}

	if (conftest)
                errx(0, "config OK");

	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);

#ifdef SIGINFO
	signal(SIGINFO, sig_handler);
#endif
	signal(SIGUSR2, sig_handler);

	if (!conf.foreground)
		signal(SIGHUP, SIG_IGN);

	if ((tlsconf = tls_config_new()) == NULL)
		err(1, "tls_config_new");

	/* optionally accept client certs, but don't try to verify them */
	tls_config_verify_client_optional(tlsconf);
	tls_config_insecure_noverifycert(tlsconf);

	if (tls_config_set_protocols(tlsconf, conf.protos) == -1)
		err(1, "tls_config_set_protocols");

	load_vhosts(tlsconf);

	if ((ctx = tls_server()) == NULL)
		err(1, "tls_server");

	if (tls_configure(ctx, tlsconf) == -1)
		errx(1, "tls_configure: %s", tls_error(ctx));

	sock4 = make_socket(conf.port, AF_INET);
	if (conf.ipv6)
		sock6 = make_socket(conf.port, AF_INET6);
	else
		sock6 = -1;

	if (!conf.foreground && daemon(0, 1) == -1)
		exit(1);

	sandbox();

	loop(ctx, sock4, sock6);

	close(sock4);
	close(sock6);
	tls_free(ctx);
	tls_config_free(tlsconf);

	return 0;
}
