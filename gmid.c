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
#include <sys/socket.h>
#include <sys/stat.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tls.h>
#include <unistd.h>

#ifndef __OpenBSD__
# define pledge(a, b) 0
# define unveil(a, b) 0
#endif /* __OpenBSD__ */

#ifndef INFTIM
# define INFTIM -1
#endif /* INFTIM */

#define GEMINI_URL_LEN (1024+3)	/* URL max len + \r\n + \0 */

/* large enough to hold a copy of a gemini URL and still have extra room */
#define PATHBUF		2048

#define SUCCESS		20
#define TEMP_FAILURE	40
#define NOT_FOUND	51
#define BAD_REQUEST	59

#ifndef MAX_USERS
#define MAX_USERS	64
#endif

enum {
	S_OPEN,
	S_INITIALIZING,
	S_SENDING,
	S_CLOSING,
};

struct client {
	struct tls	*ctx;
	int		 state;
	int		 code;
	const char	*meta;
	int		 fd, waiting_on_child;
	pid_t		 child;
	char		 sbuf[1024];	  /* static buffer */
	void		*buf, *i;	  /* mmap buffer */
	ssize_t		 len, off;	  /* mmap/static buffer  */
	int		 af;
	struct in_addr	 addr;
};

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

#define LOG(c, fmt, ...)						\
	do {								\
		char buf[INET_ADDRSTRLEN];				\
		if (inet_ntop((c)->af, &(c)->addr, buf, sizeof(buf)) == NULL) \
			err(1, "inet_ntop");				\
		dprintf(logfd, "[%s] " fmt "\n", buf, __VA_ARGS__);	\
	} while (0)

const char *dir;
int dirfd, logfd;
int cgi;
int connected_clients;

void		 siginfo_handler(int);

char		*url_after_proto(char*);
char		*url_start_of_request(char*);
int		 url_trim(struct client*, char*);
char		*adjust_path(char*);
int		 path_isdir(char*);
ssize_t		 filesize(int);

int		 start_reply(struct pollfd*, struct client*, int, const char*);
const char	*path_ext(const char*);
const char	*mime(const char*);
int		 open_file(char*, char*, struct pollfd*, struct client*);
void		 start_cgi(const char*, const char*, struct pollfd*, struct client*);
void		 cgi_setpoll_on_child(struct pollfd*, struct client*);
void		 cgi_setpoll_on_client(struct pollfd*, struct client*);
void		 handle_cgi(struct pollfd*, struct client*);
void		 send_file(char*, char*, struct pollfd*, struct client*);
void		 send_dir(char*, struct pollfd*, struct client*);
void		 handle(struct pollfd*, struct client*);

void		 mark_nonblock(int);
int		 make_soket(int);
void		 do_accept(int, struct tls*, struct pollfd*, struct client*);
void		 goodbye(struct pollfd*, struct client*);
void		 loop(struct tls*, int);

void		 usage(const char*);

void
siginfo_handler(int sig)
{
	(void)sig;
}

char *
url_after_proto(char *url)
{
	char *s;
	const char *proto = "gemini";
	const char *marker = "://";
	size_t i;

	/* a relative URL */
	if ((s = strstr(url, marker)) == NULL)
		return url;

	if (s - strlen(proto) != url)
		return NULL;

	for (i = 0; proto[i] != '\0'; ++i)
		if (url[i] != proto[i])
			return NULL;

	/* a valid gemini:// URL */
	return s + strlen(marker);
}

char *
url_start_of_request(char *url)
{
	char *s, *t;

	if ((s = url_after_proto(url)) == NULL)
		return NULL;

	if ((t = strstr(s, "/")) == NULL)
		return s + strlen(s);
	return t;
}

int
url_trim(struct client *c, char *url)
{
	const char *e = "\r\n";
	char *s;

	if ((s = strstr(url, e)) == NULL)
		return 0;
	s[0] = '\0';
	s[1] = '\0';

	if (s[2] != '\0') {
		LOG(c, "%s", "request longer than 1024 bytes\n");
		return 0;
	}

	return 1;
}

char *
adjust_path(char *path)
{
	char *s, *query;
	size_t len;

	if ((query = strchr(path, '?')) != NULL) {
		*query = '\0';
		query++;
	}

	/* /.. -> / */
	len = strlen(path);
	if (len >= 3) {
		if (!strcmp(&path[len-3], "/..")) {
			path[len-2] = '\0';
		}
	}

	/* if the path is only `..` trim out and exit */
	if (!strcmp(path, "..")) {
		path[0] = '\0';
		return query;
	}

	/* remove every ../ in the path */
	while (1) {
		if ((s = strstr(path, "../")) == NULL)
			return query;
		memmove(s, s+3, strlen(s)+1);	/* copy also the \0 */
	}
}

int
path_isdir(char *path)
{
	if (*path == '\0')
		return 1;
	return path[strlen(path)-1] == '/';
}

int
start_reply(struct pollfd *pfd, struct client *client, int code, const char *reason)
{
	char buf[1030] = {0}; 	/* status + ' ' + max reply len + \r\n\0 */
	int len;
	int ret;

	client->code = code;
	client->meta = reason;
	client->state = S_INITIALIZING;

	len = snprintf(buf, sizeof(buf), "%d %s\r\n", code, reason);
	assert(len < (int)sizeof(buf));
	ret = tls_write(client->ctx, buf, len);
	if (ret == TLS_WANT_POLLIN) {
		pfd->events = POLLIN;
		return 0;
	}

	if (ret == TLS_WANT_POLLOUT) {
		pfd->events = POLLOUT;
		return 0;
	}

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

const char *
path_ext(const char *path)
{
	const char *end;

	end = path + strlen(path)-1; /* the last byte before the NUL */
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
open_file(char *path, char *query, struct pollfd *fds, struct client *c)
{
	char fpath[PATHBUF];
	struct stat sb;

	assert(path != NULL);

	bzero(fpath, sizeof(fpath));

	if (*path != '.')
		fpath[0] = '.';
	strlcat(fpath, path, PATHBUF);

	if ((c->fd = openat(dirfd, fpath,
		    O_RDONLY | O_NOFOLLOW | O_CLOEXEC)) == -1) {
		LOG(c, "open failed: %s", fpath);
		if (!start_reply(fds, c, NOT_FOUND, "not found"))
			return 0;
		goodbye(fds, c);
		return 0;
	}

	if (fstat(c->fd, &sb) == -1) {
		LOG(c, "fstat failed for %s", fpath);
		if (!start_reply(fds, c, TEMP_FAILURE, "internal server error"))
			return 0;
		goodbye(fds, c);
		return 0;
	}

	if (S_ISDIR(sb.st_mode)) {
		LOG(c, "%s is a directory, trying %s/index.gmi", fpath, fpath);
		close(c->fd);
		c->fd = -1;
		send_dir(fpath, fds, c);
		return 0;
	}

	if (cgi && (sb.st_mode & S_IXUSR)) {
		start_cgi(fpath, query, fds, c);
		return 0;
	}

	if ((c->len = filesize(c->fd)) == -1) {
		LOG(c, "failed to get file size for %s", fpath);
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
}

void
start_cgi(const char *path, const char *query,
    struct pollfd *fds, struct client *c)
{
	pid_t pid;
	int p[2];

	if (pipe(p) == -1)
		goto err;

	switch (pid = fork()) {
	case -1:
		goto err;

	case 0: {		/* child */
                char *expath;
		char addr[INET_ADDRSTRLEN];
		char *argv[] = { NULL, NULL, NULL };

		/* skip the initial ./ */
		path += 2;

		close(p[0]);	/* close the read end */
		if (dup2(p[1], 1) == -1)
			goto childerr;

		if (inet_ntop(c->af, &c->addr, addr, sizeof(addr)) == NULL)
                        goto childerr;

		/* skip the ./ at the start of path*/
		if (asprintf(&expath, "%s%s", dir, path) == -1)
			goto childerr;
		argv[0] = argv[1] = expath;

		/* fix the env */
		setenv("SERVER_SOFTWARE", "gmid", 1);
		/* setenv("SERVER_NAME", "", 1); */
		/* setenv("GATEWAY_INTERFACE", "CGI/version", 1); */
		setenv("SERVER_PROTOCOL", "gemini", 1);
		setenv("SERVER_PORT", "1965", 1);
		setenv("PATH_INFO", path, 1);
		setenv("PATH_TRANSLATED", expath, 1);
		if (query != NULL)
			setenv("QUERY_STRING", query, 1);
		setenv("REMOTE_ADDR", addr, 1);

		execvp(expath, argv);
		goto childerr;
	}

	default:		/* parent */
		close(p[1]);	/* close the write end */
		close(c->fd);
		c->fd = p[0];
		c->child = pid;
		mark_nonblock(c->fd);
		c->state = S_SENDING;
		handle_cgi(fds, c);
		return;
	}

err:
	if (!start_reply(fds, c, TEMP_FAILURE, "internal server error"))
		return;
	goodbye(fds, c);
	return;

childerr:
	dprintf(p[1], "%d internal server error\r\n", TEMP_FAILURE);
	close(p[1]);

	/* don't call atexit stuff */
        _exit(1);
}

void
cgi_setpoll_on_child(struct pollfd *fds, struct client *c)
{
	int fd;

	if (c->waiting_on_child)
		return;
	c->waiting_on_child = 1;

	fds->events = POLLIN;

	fd = fds->fd;
	fds->fd = c->fd;
	c->fd = fd;
}

void
cgi_setpoll_on_client(struct pollfd *fds, struct client *c)
{
	int fd;

	if (!c->waiting_on_child)
		return;
	c->waiting_on_child = 0;

	fd = fds->fd;
	fds->fd = c->fd;
	c->fd = fd;
}

void
handle_cgi(struct pollfd *fds, struct client *c)
{
	ssize_t r;

	/* ensure c->fd is the child and fds->fd the client */
	cgi_setpoll_on_client(fds, c);

	while (1) {
		if (c->len == 0) {
			if ((r = read(c->fd, c->sbuf, sizeof(c->sbuf))) == 0)
				goto end;
			if (r == -1) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					cgi_setpoll_on_child(fds, c);
					return;
				}
                                goto end;
			}
			c->len = r;
			c->off = 0;
		}

		while (c->len > 0) {
			switch (r = tls_write(c->ctx, c->sbuf + c->off, c->len)) {
			case -1:
				goto end;

			case TLS_WANT_POLLOUT:
				fds->events = POLLOUT;
				return;

			case TLS_WANT_POLLIN:
				fds->events = POLLIN;
				return;

			default:
                                c->off += r;
				c->len -= r;
				break;
			}
		}
	}

end:
	goodbye(fds, c);
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
			LOG(c, "tls_write: %s", tls_error(c->ctx));
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
handle(struct pollfd *fds, struct client *client)
{
	char buf[GEMINI_URL_LEN];
	char *path;
	char *query;

	switch (client->state) {
	case S_OPEN:
		bzero(buf, GEMINI_URL_LEN);
		switch (tls_read(client->ctx, buf, sizeof(buf)-1)) {
		case -1:
			LOG(client, "tls_read: %s", tls_error(client->ctx));
			goodbye(fds, client);
			return;

		case TLS_WANT_POLLIN:
			fds->events = POLLIN;
			return;

		case TLS_WANT_POLLOUT:
			fds->events = POLLOUT;
			return;
		}

		if (!url_trim(client, buf)) {
			if (!start_reply(fds, client, BAD_REQUEST, "bad request"))
				return;
			goodbye(fds, client);
			return;
		}

		if ((path = url_start_of_request(buf)) == NULL) {
			if (!start_reply(fds, client, BAD_REQUEST, "bad request"))
				return;
			goodbye(fds, client);
			return;
		}

		query = adjust_path(path);
		LOG(client, "get %s%s%s", path,
		    query ? "?" : "",
		    query ? query : "");

		if (path_isdir(path))
			send_dir(path, fds, client);
		else
			send_file(path, query, fds, client);
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
		err(1, "fcntl(F_GETFL)");
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
		err(1, "fcntl(F_SETFL)");
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
		err(1, "socket");

	v = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v)) == -1)
		err(1, "setsockopt(SO_REUSEADDR)");

	v = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &v, sizeof(v)) == -1)
		err(1, "setsockopt(SO_REUSEPORT)");

	mark_nonblock(sock);

	if (bind(sock, addr, len) == -1)
		err(1, "bind");

	if (listen(sock, 16) == -1)
		err(1, "listen");

	return sock;
}

void
do_accept(int sock, struct tls *ctx, struct pollfd *fds, struct client *clients)
{
	int i, fd;
	struct sockaddr_in addr;
	socklen_t len;

	len = sizeof(addr);
	if ((fd = accept(sock, (struct sockaddr*)&addr, &len)) == -1) {
		if (errno == EWOULDBLOCK)
			return;
		err(1, "accept");
	}

	mark_nonblock(fd);

	for (i = 0; i < MAX_USERS; ++i) {
		if (fds[i].fd == -1) {
			bzero(&clients[i], sizeof(struct client));
			if (tls_accept_socket(ctx, &clients[i].ctx, fd) == -1)
				break; /* goodbye fd! */

			fds[i].fd = fd;
			fds[i].events = POLLIN;

			clients[i].state = S_OPEN;
			clients[i].fd = -1;
			clients[i].child = -1;
			clients[i].buf = MAP_FAILED;
			clients[i].af = AF_INET;
			clients[i].addr = addr.sin_addr;

			connected_clients++;
			return;
		}
	}

	close(fd);
}

void
goodbye(struct pollfd *pfd, struct client *c)
{
	ssize_t ret;

	c->state = S_CLOSING;

	ret = tls_close(c->ctx);
	if (ret == TLS_WANT_POLLIN) {
		pfd->events = POLLIN;
		return;
	}
	if (ret == TLS_WANT_POLLOUT) {
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
loop(struct tls *ctx, int sock)
{
	int i, todo;
	struct client clients[MAX_USERS];
	struct pollfd fds[MAX_USERS];

	for (i = 0; i < MAX_USERS; ++i) {
		fds[i].fd = -1;
		fds[i].events = POLLIN;
		bzero(&clients[i], sizeof(struct client));
	}

	fds[0].fd = sock;

	for (;;) {
		if ((todo = poll(fds, MAX_USERS, INFTIM)) == -1) {
			if (errno == EINTR) {
                                warnx("connected clients: %d", connected_clients);
				continue;
			}
			err(1, "poll");
		}

		for (i = 0; i < MAX_USERS; i++) {
			assert(i < MAX_USERS);

			if (fds[i].revents == 0)
				continue;

			if (fds[i].revents & (POLLERR|POLLNVAL))
				err(1, "bad fd %d", fds[i].fd);

			if (fds[i].revents & POLLHUP) {
				/* fds[i] may be the fd of the stdin
				 * of a cgi script that has exited. */
				if (!clients[i].waiting_on_child) {
					goodbye(&fds[i], &clients[i]);
					continue;
				}
			}

			todo--;

			if (i == 0) { /* new client */
				do_accept(sock, ctx, fds, clients);
				continue;
			}

			handle(&fds[i], &clients[i]);
		}
	}
}

void
usage(const char *me)
{
	fprintf(stderr,
	    "USAGE: %s [-h] [-c cert.pem] [-d docs] [-k key.pem]\n",
	    me);
}

int
main(int argc, char **argv)
{
	const char *cert = "cert.pem", *key = "key.pem";
	struct tls *ctx = NULL;
	struct tls_config *conf;
	int sock, ch;

	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);

#ifdef SIGINFO
	signal(SIGINFO, siginfo_handler);
#endif
	signal(SIGUSR2, siginfo_handler);

	connected_clients = 0;

	dir = "docs/";
	logfd = 2;		/* stderr */
	cgi = 0;

	while ((ch = getopt(argc, argv, "c:d:hk:l:x")) != -1) {
		switch (ch) {
		case 'c':
			cert = optarg;
			break;

		case 'd':
			dir = optarg;
			break;

		case 'h':
			usage(*argv);
			return 0;

		case 'k':
			key = optarg;
			break;

		case 'l':
			/* open log file or create it with 644 */
			if ((logfd = open(optarg, O_WRONLY | O_CREAT | O_CLOEXEC,
					S_IRUSR | S_IWUSR | S_IRGRP | S_IWOTH)) == -1)
				err(1, "%s", optarg);
			break;

		case 'x':
			cgi = 1;
			break;

		default:
			usage(*argv);
			return 1;
		}
	}

	if ((conf = tls_config_new()) == NULL)
		err(1, "tls_config_new");

	if (tls_config_set_protocols(conf,
	    TLS_PROTOCOL_TLSv1_2 | TLS_PROTOCOL_TLSv1_3) == -1)
		err(1, "tls_config_set_protocols");

	if (tls_config_set_cert_file(conf, cert) == -1)
		err(1, "tls_config_set_cert_file: %s", cert);

	if (tls_config_set_key_file(conf, key) == -1)
		err(1, "tls_config_set_key_file: %s", key);

	if ((ctx = tls_server()) == NULL)
		err(1, "tls_server");

	if (tls_configure(ctx, conf) == -1)
		errx(1, "tls_configure: %s", tls_error(ctx));

	sock = make_socket(1965, AF_INET);

	if ((dirfd = open(dir, O_RDONLY | O_DIRECTORY)) == -1)
		err(1, "open: %s", dir);

	if (unveil(dir, cgi ? "rx" : "r") == -1)
		err(1, "unveil");

	if (pledge(cgi ? "stdio rpath inet proc exec" : "stdio rpath inet", NULL) == -1)
		err(1, "pledge");

	loop(ctx, sock);

	close(sock);
	tls_free(ctx);
	tls_config_free(conf);
}
