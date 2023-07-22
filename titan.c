/*
 * Copyright (c) 2023 Omar Polo <op@omarpolo.com>
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

#include "config.h"

#include <sys/stat.h>
#include <sys/socket.h>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tls.h>
#include <unistd.h>

#include "iri.h"

#ifndef INFTIM
#define INFTIM -1
#endif

#ifndef __OpenBSD__
#define pledge(a, b) (0)
#endif

static int
dial(const char *hostname, const char *port)
{
	struct addrinfo	 hints, *res, *res0;
	int		 error, save_errno, s;
	const char	*cause = NULL;

	if (port == NULL || *port == '\0')
		port = "1965";

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	error = getaddrinfo(hostname, port, &hints, &res0);
	if (error)
		errx(1, "can't resolve %s: %s", hostname, gai_strerror(error));

	s = -1;
	for (res = res0; res; res = res->ai_next) {
		s = socket(res->ai_family, res->ai_socktype,
		    res->ai_protocol);
		if (s == -1) {
			cause = "socket";
			continue;
		}

		if (connect(s, res->ai_addr, res->ai_addrlen) == -1) {
			cause = "connect";
			save_errno = errno;
			close(s);
			errno = save_errno;
			s = -1;
			continue;
		}

		if (fcntl(s, F_SETFL, O_NONBLOCK) == -1)
			err(1, "fcntl");
		break; /* got one */
	}
	if (s == -1)
		err(1, "%s", cause);
	freeaddrinfo(res0);
	return (s);
}

/* returns read bytes, or -1 on error */
static ssize_t
iomux(struct tls *ctx, int fd, const char *in, size_t inlen, char *out,
    size_t outlen)
{
	struct pollfd	 pfd;
	size_t		 outwrote = 0;
	ssize_t		 ret;

	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLIN|POLLOUT;

	for (;;) {
		if (poll(&pfd, 1, INFTIM) == -1)
			err(1, "poll");
		if (pfd.revents & (POLLERR|POLLNVAL))
			errx(1, "bad fd %d", pfd.fd);

		/* attempt to read */
		if (out != NULL) {
			switch (ret = tls_read(ctx, out, outlen)) {
			case TLS_WANT_POLLIN:
			case TLS_WANT_POLLOUT:
				break;
			case -1:
				return -1;
			case 0:
				return outwrote;
			default:
				outwrote += ret;
				out += ret;
				outlen -= ret;
			}

			/*
			 * don't write if we're reading; titan works
			 * like this.
			 */
			if (outwrote != 0)
				continue;
		}

		if (inlen == 0 && out == NULL)
			break;
		if (inlen == 0)
			continue;

		switch (ret = tls_write(ctx, in, inlen)) {
		case TLS_WANT_POLLIN:
		case TLS_WANT_POLLOUT:
			continue;
		case 0:
		case -1:
			return -1;
		default:
			in += ret;
			inlen -= ret;
		}
	}

	return 0;
}

static void __dead
usage(void)
{
	fprintf(stderr,
	    "usage: %s [-C cert] [-K key] [-m mime] [-t token] url file\n",
	    getprogname());
	exit(1);
}

int
main(int argc, char **argv)
{
	struct tls_config *config;
	struct tls	*ctx;
	struct stat	 sb;
	struct iri	 iri;
	FILE		*in;
	const char	*cert = NULL, *key = NULL, *mime = NULL, *token = NULL;
	const char	*parse_err;
	char		 iribuf[1025];
	char		 resbuf[1025];
	char		*req;
	int		 sock, ch;

	if (pledge("stdio rpath inet dns", NULL) == -1)
		err(1, "pledge");

	while ((ch = getopt(argc, argv, "C:K:m:t:")) != -1) {
		switch (ch) {
		case 'C':
			cert = optarg;
			break;
		case 'K':
			key = optarg;
			break;
		case 'm':
			mime = optarg;
			break;
		case 't':
			token = optarg;
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (cert == NULL && key != NULL)
		usage();
	if (cert != NULL && key == NULL)
		key = cert;

	if (argc != 2)
		usage();

	if ((in = fopen(argv[1], "r")) == NULL)
		err(1, "can't open %s", argv[1]);

	/* drop rpath */
	if (pledge("stdio inet dns", NULL) == -1)
		err(1, "pledge");

	if (fstat(fileno(in), &sb) == -1)
		err(1, "fstat");

	/* prepare the URL */
	if (token && mime) {
		if (asprintf(&req, "%s;size=%lld;token=%s;mime=%s\r\n", argv[0],
		    (long long)sb.st_size, token, mime) == -1)
			err(1, "asprintf");
	} else if (token) {
		if (asprintf(&req, "%s;size=%lld;token=%s\r\n", argv[0],
		    (long long)sb.st_size, token) == -1)
			err(1, "asprintf");
	} else if (mime) {
		if (asprintf(&req, "%s;size=%lld;mime=%s\r\n", argv[0],
		    (long long)sb.st_size, mime) == -1)
			err(1, "asprintf");
	} else {
		if (asprintf(&req, "%s;size=%lld\r\n", argv[0],
		    (long long)sb.st_size) == -1)
			err(1, "asprintf");
	}

	if (strlcpy(iribuf, argv[0], sizeof(iribuf)) >= sizeof(iribuf))
		errx(1, "URL too long");

	if (!parse_iri(iribuf, &iri, &parse_err))
		errx(1, "invalid IRI: %s", parse_err);

	if ((config = tls_config_new()) == NULL)
		err(1, "tls_config_new");
	tls_config_insecure_noverifycert(config);
	tls_config_insecure_noverifyname(config);

	if (cert && tls_config_set_keypair_file(config, cert, key) == -1)
		errx(1, "cant load certificate client %s", cert);

	if ((ctx = tls_client()) == NULL)
		errx(1, "can't create tls context");

	if (tls_configure(ctx, config) == -1)
		errx(1, "tls_configure: %s", tls_error(ctx));

	sock = dial(iri.host, iri.port);
	if (tls_connect_socket(ctx, sock, iri.host) == -1)
		errx(1, "failed to connect to %s:%s: %s", iri.host,
		    *iri.port == '\0' ? "1965" : iri.port, tls_error(ctx));

	/* drop inet tls */
	if (pledge("stdio", NULL) == -1)
		err(1, "pledge");

	/* send request */
	if (iomux(ctx, sock, req, strlen(req), NULL, 0) == -1)
		errx(1, "I/O error: %s", tls_error(ctx));

	for (;;) {
		static char buf[BUFSIZ];
		size_t buflen;
		ssize_t w;
		char *m;

		/* will be zero on EOF */
		buflen = fread(buf, 1, sizeof(buf), in);

		w = iomux(ctx, sock, buf, buflen, resbuf, sizeof(resbuf));
		if (w == -1)
			errx(1, "I/O error: %s", tls_error(ctx));
		if (w != 0) {
			if ((m = memmem(resbuf, w, "\r\n", 2)) == NULL)
				errx(1, "invalid reply");
			*m = '\0';
			/* XXX parse */
			puts(resbuf);
			break;
		}
	}

	/* close connection */
	for (;;) {
		struct pollfd pfd;

		memset(&pfd, 0, sizeof(pfd));
		pfd.fd = sock;
		pfd.events = POLLIN|POLLOUT;

		switch (tls_close(ctx)) {
		case TLS_WANT_POLLIN:
		case TLS_WANT_POLLOUT:
			if (poll(&pfd, 1, INFTIM) == -1)
				err(1, "poll");
			break;
		case -1:
			warnx("tls_close: %s", tls_error(ctx));
			/* fallthrough */
		default:
			tls_free(ctx);
			return (0);
		}
	}
}