/*
 * Copyright (c) 2021 Omar Polo <op@omarpolo.com>
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

#include <sys/socket.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>

enum debug {
	DEBUG_NONE,
	DEBUG_CODE,
	DEBUG_HEADER,
	DEBUG_META,
	DEBUG_ALL,
};

/* flags */
int		 debug;
int		 dont_verify_name;
int		 flag2;
int		 flag3;
int		 nop;
int		 redirects = 5;
int		 timer;
const char	*cert;
const char	*key;
const char	*proxy_host;
const char	*proxy_port;
const char	*sni;

/* state */
struct tls_config *tls_conf;

static void
timeout(int signo)
{
	dprintf(2, "%s: timer expired\n", getprogname());
	exit(1);
}

static void
load_tls_conf(void)
{
	if ((tls_conf = tls_config_new()) == NULL)
		err(1, "tls_config_new");

	tls_config_insecure_noverifycert(tls_conf);
	if (dont_verify_name)
		tls_config_insecure_noverifyname(tls_conf);

	if (flag2 &&
	    tls_config_set_protocols(tls_conf, TLS_PROTOCOL_TLSv1_2) == -1)
		errx(1, "can't set TLSv1.2");
	if (flag3 &&
	    tls_config_set_protocols(tls_conf, TLS_PROTOCOL_TLSv1_3) == -1)
		errx(1, "can't set TLSv1.3");

	if (cert != NULL &&
	    tls_config_set_keypair_file(tls_conf, cert, key) == -1)
		errx(1, "can't load client certificate %s", cert);
}

static void
connectto(struct tls *ctx, const char *host, const char *port)
{
	struct addrinfo hints, *res, *res0;
	int error;
	int saved_errno;
	int s;
	const char *cause = NULL;
	const char *sname;

	if (proxy_host != NULL) {
		host = proxy_host;
		port = proxy_port;
	}

	if ((sname = sni) == NULL)
		sname = host;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	error = getaddrinfo(host, port, &hints, &res0);
	if (error)
		errx(1, "%s", gai_strerror(error));

	s = -1;
	for (res = res0; res != NULL; res = res->ai_next) {
		s = socket(res->ai_family, res->ai_socktype,
		    res->ai_protocol);
		if (s == -1) {
			cause = "socket";
			continue;
		}

		if (connect(s, res->ai_addr, res->ai_addrlen) == -1) {
			cause = "connect";
			saved_errno = errno;
			close(s);
			errno = saved_errno;
			s = -1;
			continue;
		}

		break;
	}

	if (s == -1)
		err(1, "%s: can't connect to %s:%s", cause,
		    host, port);

	freeaddrinfo(res0);

	if (tls_connect_socket(ctx, s, sname) == -1)
		errx(1, "tls_connect_socket: %s", tls_error(ctx));
}

static void
doreq(struct tls *ctx, const char *buf)
{
	size_t	s;
	ssize_t	w;

	s = strlen(buf);
	while (s != 0) {
		switch (w = tls_write(ctx, buf, s)) {
		case 0:
		case -1:
			errx(1, "tls_write: %s", tls_error(ctx));
		case TLS_WANT_POLLIN:
		case TLS_WANT_POLLOUT:
			continue;
		}

		s -= w;
		buf += w;
	}
}

static size_t
dorep(struct tls *ctx, void *buf, size_t len)
{
	ssize_t	w;
	size_t	tot = 0;

	while (len != 0) {
		switch (w = tls_read(ctx, buf, len)) {
		case 0:
			return tot;
		case -1:
			errx(1, "tls_write: %s", tls_error(ctx));
		case TLS_WANT_POLLIN:
		case TLS_WANT_POLLOUT:
			continue;
		}

		len -= w;
		buf += w;
		tot += w;
	}

	return tot;
}

static int
get(const char *r)
{
	struct tls	*ctx;
	struct iri	 iri;
	int		 foundhdr = 0, code = -1, od;
	char		 iribuf[GEMINI_URL_LEN];
	char		 req[GEMINI_URL_LEN];
	char		 buf[2048];
	const char	*parse_err, *host, *port;

	if (strlcpy(iribuf, r, sizeof(iribuf)) >= sizeof(iribuf))
		errx(1, "iri too long: %s", r);

	if (strlcpy(req, r, sizeof(req)) >= sizeof(req))
		errx(1, "iri too long: %s", r);

	if (strlcat(req, "\r\n", sizeof(req)) >= sizeof(req))
		errx(1, "iri too long: %s", r);

	if (!parse_iri(iribuf, &iri, &parse_err))
		errx(1, "invalid IRI: %s", parse_err);

	if (nop)
		errx(0, "IRI OK");

	if ((ctx = tls_client()) == NULL)
		errx(1, "can't create tls context");

	if (tls_configure(ctx, tls_conf) == -1)
		errx(1, "tls_configure: %s", tls_error(ctx));

	host = iri.host;
	port = "1965";
	if (*iri.port != '\0')
		port = iri.port;

	connectto(ctx, host, port);

	od = 0;
	while (!od) {
		switch (tls_handshake(ctx)) {
		case 0:
			od = 1;
			break;
		case -1:
			errx(1, "handshake: %s", tls_error(ctx));
		}
	}

	doreq(ctx, req);

	for (;;) {
		char	*t;
		size_t	 len;

		len = dorep(ctx, buf, sizeof(buf));
		if (len == 0)
			goto close;

		if (foundhdr) {
			write(1, buf, len);
			continue;
		}
		foundhdr = 1;

		if (memmem(buf, len, "\r\n", 2) == NULL)
			errx(1, "invalid reply: no \\r\\n");
		if (!isdigit(buf[0]) || !isdigit(buf[1]) || buf[2] != ' ')
			errx(1, "invalid reply: invalid response format");

		code = (buf[0] - '0') * 10 + buf[1] - '0';

		if (debug == DEBUG_CODE) {
			printf("%d\n", code);
			goto close;
		}

		if (debug == DEBUG_HEADER) {
			t = memmem(buf, len, "\r\n", 2);
			assert(t != NULL);
			*t = '\0';
			printf("%s\n", buf);
			goto close;
		}

		if (debug == DEBUG_META) {
			t = memmem(buf, len, "\r\n", 2);
			assert(t != NULL);
			*t = '\0';
			printf("%s\n", buf+3);
			goto close;
		}

		if (debug == DEBUG_ALL) {
			write(1, buf, len);
			continue;
		}

		/* skip the header */
		t = memmem(buf, len, "\r\n", 2);
		assert(t != NULL);
		t += 2; /* skip \r\n */
		len -= t - buf;
		write(1, t, len);
	}

close:
	od = tls_close(ctx);
	if (od == TLS_WANT_POLLIN || od == TLS_WANT_POLLOUT)
		goto close;

	tls_close(ctx);
	tls_free(ctx);
	return code;
}

static void __attribute__((noreturn))
usage(void)
{
	fprintf(stderr, "usage: %s [-23Nn] [-C cert] [-d mode] [-H sni] "
	    "[-K key] [-P host[:port]]\n",
	    getprogname());
	fprintf(stderr, "          [-T seconds] gemini://...\n");
	exit(1);
}

static int
parse_debug(const char *arg)
{
	if (!strcmp(arg, "none"))
		return DEBUG_NONE;
	if (!strcmp(arg, "code"))
		return DEBUG_CODE;
	if (!strcmp(arg, "header"))
		return DEBUG_HEADER;
	if (!strcmp(arg, "meta"))
		return DEBUG_META;
	if (!strcmp(arg, "all"))
		return DEBUG_ALL;
	usage();
}

static void
parse_proxy(const char *arg)
{
	char *at;

	if ((proxy_host = strdup(arg)) == NULL)
		err(1, "strdup");

	proxy_port = "1965";

	if ((at = strchr(proxy_host, ':')) == NULL)
		return;
	*at = '\0';
	proxy_port = ++at;

	if (strchr(proxy_port, ':') != NULL)
		errx(1, "invalid port %s", proxy_port);
}

int
main(int argc, char **argv)
{
	int		 ch, code;
	const char	*errstr;

	while ((ch = getopt(argc, argv, "23C:d:H:K:NP:T:")) != -1) {
		switch (ch) {
		case '2':
			flag2 = 1;
			break;
		case '3':
			flag3 = 1;
			break;
		case 'C':
			cert = optarg;
			break;
		case 'd':
			debug = parse_debug(optarg);
			break;
		case 'H':
			sni = optarg;
			break;
		case 'K':
			key = optarg;
			break;
		case 'N':
			dont_verify_name = 1;
			break;
		case 'n':
			nop = 1;
			break;
		case 'P':
			parse_proxy(optarg);
			dont_verify_name = 1;
			break;
		case 'T':
			timer = strtonum(optarg, 1, 1000, &errstr);
			if (errstr != NULL)
				errx(1, "timeout is %s: %s",
				    errstr, optarg);
			signal(SIGALRM, timeout);
			alarm(timer);
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (flag2 + flag3 > 1) {
		warnx("only -2 or -3 can be specified at the same time");
		usage();
	}

	if ((cert != NULL && key == NULL) ||
	    (cert == NULL && key != NULL)) {
		warnx("cert or key is missing");
		usage();
	}

	if (argc != 1)
		usage();

	load_tls_conf();

	signal(SIGPIPE, SIG_IGN);

#ifdef __OpenBSD__
	if (pledge("stdio inet dns", NULL) == -1)
		err(1, "pledge");
#endif

	code = get(*argv);

	return code < 20 || code >= 30;
}
