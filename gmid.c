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

#include <sys/socket.h>
#include <sys/stat.h>

#include <netinet/in.h>

#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tls.h>
#include <unistd.h>

#ifndef __OpenBSD__
# define pledge(a, b) 0
# define unveil(a, b) 0
#endif /* __OpenBSD__ */

#define GEMINI_URL_LEN (1024+3)	/* URL max len + \r\n + \0 */

/* large enough to hold a copy of a gemini URL and still have extra room */
#define PATHBUF (2048)

#define FILEBUF 1024

#define SUCCESS		20
#define NOT_FOUND	51
#define BAD_REQUEST	59

int dirfd;

char *
url_after_proto(char *url)
{
	char *s;
	const char *proto = "gemini";
	const char *marker = "://";

	if ((s = strstr(url, marker)) == NULL)
		return url;

	/* not a gemini:// URL */

	if (s - strlen(proto) < url)
		return NULL;
	/* TODO: */
	/* if (strcmp(s - strlen(proto), proto)) */
	/* 	return NULL; */

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
url_trim(char *url)
{
	const char *e = "\r\n";
	char *s;

	if ((s = strstr(url, e)) == NULL)
		return 0;
	s[0] = '\0';
	s[1] = '\0';

	if (s[2] != '\0') {
		fprintf(stderr, "the request was longer than 1024 bytes\n");
		return 0;
	}

	return 1;
}

void
adjust_path(char *path)
{
	char *s;
	size_t len;

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
		return;
	}

	/* remove every ../ in the path */
	while (1) {
		if ((s = strstr(path, "../")) == NULL)
			return;
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

void
start_reply(struct tls *ctx, int code, const char *reason)
{
	char buf[1030] = {0}; 	/* status + ' ' + max reply len + \r\n\0 */
	int len;

	len = snprintf(buf, sizeof(buf), "%d %s\r\n", code, reason);
	assert(len < (int)sizeof(buf));
	tls_write(ctx, buf, len);
}

int
isdir(int fd)
{
	struct stat sb;

	if (fstat(fd, &sb) == -1) {
		warn("fstat");
		return 1; 	/* we'll probably fail later on anyway */
	}

	return S_ISDIR(sb.st_mode);
}

void		 send_dir(char*, struct tls*);

void
send_file(char *path, struct tls *ctx)
{
	int fd;
	char fpath[PATHBUF];
	char buf[FILEBUF];
	size_t i;
	ssize_t t, w;

	bzero(fpath, sizeof(fpath));

	if (*path != '.')
		fpath[0] = '.';
	
	strlcat(fpath, path, PATHBUF);

	if ((fd = openat(dirfd, fpath, O_RDONLY | O_NOFOLLOW)) == -1) {
		warn("open: %s", fpath);
		start_reply(ctx, NOT_FOUND, "not found");
		return;
	}

	if (isdir(fd)) {
		warnx("%s is a directory, trying %s/index.gmi", fpath, fpath);
		close(fd);
		send_dir(fpath, ctx);
		return;
	}

	/* assume it's a text/gemini file */
	start_reply(ctx, SUCCESS, "text/gemini");

        while (1) {
		if ((w = read(fd, buf, sizeof(buf))) == -1) {
			warn("read: %s", fpath);
			goto exit;
		}

		if (w == 0)
			break;

		t = w;
		i = 0;

		while (w > 0) {
			if ((t = tls_write(ctx, buf + i, w)) == -1) {
				warnx("tls_write (path=%s) : %s",
				    fpath,
				    tls_error(ctx));
				goto exit;
			}
			w -= t;
			i += t;
		}
	}

exit:
	close(fd);
}

void
send_dir(char *path, struct tls *ctx)
{
	char fpath[PATHBUF];
	size_t len;

	bzero(fpath, PATHBUF);

	if (*path != '.')
		fpath[0] = '.';

	/* this cannot fail since sizeof(fpath) > maxlen of path */
	strlcat(fpath, path, PATHBUF);
	len = strlen(fpath);

	/* add a trailing / in case. */
	if (fpath[len-1] != '/') {
		fpath[len] = '/';
	}

	strlcat(fpath, "index.gmi", sizeof(fpath));

	send_file(fpath, ctx);
}

void
handle(char *url, struct tls *ctx)
{
	char *path;

	if (!url_trim(url)) {
		start_reply(ctx, BAD_REQUEST, "bad request");
		return;
	}

	if ((path = url_start_of_request(url)) == NULL) {
		start_reply(ctx, BAD_REQUEST, "bad request");
		return;
	}

	adjust_path(path);

	fprintf(stderr, "requested path: %s\n", path);

	if (path_isdir(path))
		send_dir(path, ctx);
	else
		send_file(path, ctx);
}

int
make_socket(int port)
{
	int sock, v;
	struct sockaddr_in addr;

	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
                err(1, "socket");

	v = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v)) == -1)
		err(1, "setsockopt(SO_REUSEADDR)");

	v = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &v, sizeof(v)) == -1)
		err(1, "setsockopt(SO_REUSEPORT)");

	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;

	if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) == -1)
                err(1, "bind");

	if (listen(sock, 16) == -1)
                err(1, "listen");

	return sock;
}

void
loop(struct tls *ctx, int sock)
{
	int fd;
	struct sockaddr_in client;
	socklen_t len;
	struct tls *clientctx;
	char buf[GEMINI_URL_LEN];

	for (;;) {
		len = sizeof(client);
		if ((fd = accept(sock, (struct sockaddr*)&client, &len)) == -1)
                        err(1, "accept");

		if (tls_accept_socket(ctx, &clientctx, fd) == -1) {
			warnx("tls_accept_socket: %s", tls_error(ctx));
			continue;
		}

		bzero(buf, GEMINI_URL_LEN);
		if (tls_read(clientctx, buf, sizeof(buf)-1) == -1) {
			warnx("tls_read: %s", tls_error(clientctx));
			goto clientend;
		}

		handle(buf, clientctx);

	clientend:
		if (tls_close(clientctx) == -1)
			warn("tls_close: client");
		tls_free(clientctx);
		close(fd);
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
	const char *cert = "cert.pem", *key = "key.pem", *dir = "docs";
	struct tls *ctx = NULL;
	struct tls_config *conf;
	int sock, ch;

	while ((ch = getopt(argc, argv, "c:d:hk:")) != -1) {
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

	sock = make_socket(1965);

	if ((dirfd = open(dir, O_RDONLY | O_DIRECTORY)) == -1)
		err(1, "open: %s", dir);

	if (unveil(dir, "r") == -1)
		err(1, "unveil");

	if (pledge("stdio rpath inet", "") == -1)
		err(1, "pledge");

	loop(ctx, sock);

	close(sock);
	tls_free(ctx);
	tls_config_free(conf);
}
