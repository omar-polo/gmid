/*
 * Copyright (c) 2021-2023 Omar Polo <op@omarpolo.com>
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
#include <locale.h>
#include <string.h>
#include <wchar.h>

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
int		 quiet;
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
dorep(struct tls *ctx, uint8_t *buf, size_t len)
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

static void
safeprint(FILE *fp, const char *str)
{
	int		 len;
	wchar_t		 wc;

	for (; *str != '\0'; str += len) {
		if ((len = mbtowc(&wc, str, MB_CUR_MAX)) == -1) {
			mbtowc(NULL, NULL, MB_CUR_MAX);
			fputc('?', fp);
			len = 1;
		} else if (wcwidth(wc) == -1) {
			fputc('?', fp);
		} else if (wc != L'\n')
			putwc(wc, fp);
	}

	fputc('\n', fp);
}

static int
get(const char *r)
{
	struct tls	*ctx;
	struct iri	 iri;
	int		 foundhdr = 0, code = -1, od;
	char		 iribuf[GEMINI_URL_LEN];
	char		 req[GEMINI_URL_LEN];
	uint8_t		 buf[2048];
	const char	*parse_err, *host, *port;
	int		 ret;

	if (strlcpy(iribuf, r, sizeof(iribuf)) >= sizeof(iribuf))
		errx(1, "iri too long: %s", r);

	ret = snprintf(req, sizeof(req), "%s\r\n", r);
	if (ret < 0 || (size_t)ret >= sizeof(req))
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
		uint8_t	*t;
		size_t	 len;

		len = dorep(ctx, buf, sizeof(buf));
		if (len == 0)
			break;

		if (foundhdr) {
			write(1, buf, len);
			continue;
		}
		foundhdr = 1;

		if (memmem(buf, len, "\r\n", 2) == NULL)
			errx(1, "invalid reply: no \\r\\n");
		if (!isdigit((unsigned char)buf[0]) ||
		    !isdigit((unsigned char)buf[1]) ||
		    buf[2] != ' ')
			errx(1, "invalid reply: invalid response format");

		code = (buf[0] - '0') * 10 + buf[1] - '0';

		if (debug == DEBUG_CODE) {
			printf("%d\n", code);
			break;
		}

		if (debug == DEBUG_HEADER) {
			t = memmem(buf, len, "\r\n", 2);
			assert(t != NULL);
			*t = '\0';
			printf("%s\n", buf);
			break;
		}

		if (debug == DEBUG_META) {
			t = memmem(buf, len, "\r\n", 2);
			assert(t != NULL);
			*t = '\0';
			printf("%s\n", buf+3);
			break;
		}

		if (debug == DEBUG_ALL) {
			write(1, buf, len);
			continue;
		}

		/* skip the header */
		t = memmem(buf, len, "\r\n", 2);
		assert(t != NULL);
		if (code < 20 || code >= 30) {
			*t = '\0';
			if (!quiet) {
				fprintf(stderr, "Server says: ");
				/* skip return code */
				safeprint(stderr, buf + 3);
			}
		}
		t += 2; /* skip \r\n */
		len -= t - buf;
		write(1, t, len);
	}

	for (;;) {
		switch (tls_close(ctx)) {
		case TLS_WANT_POLLIN:
		case TLS_WANT_POLLOUT:
			continue;
		case -1:
			warnx("tls_close: %s", tls_error(ctx));
			/* fallthrough */
		default:
			tls_free(ctx);
			return code;
		}
	}
}

static void __attribute__((noreturn))
usage(void)
{
	fprintf(stderr, "version: " GG_STRING "\n");
	fprintf(stderr, "usage: %s [-23Nnq] [-C cert] [-d mode] [-H sni] "
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
parse_proxy(char *arg)
{
	char *at;

	proxy_host = arg;
	proxy_port = "1965";

	if (*proxy_host == '[') {
		if ((at = strchr(proxy_host, ']')) == NULL)
			errx(1, "invalid host: %s", proxy_host);
		proxy_host++;
		*at++ = '\0';
		if (*at == '\0')
			return;
		if (*at != ':')
			errx(1, "invalid port specification: %s", at);
	} else if ((at = strchr(proxy_host, ':')) == NULL)
		return;

	*at++ = '\0';
	proxy_port = at;
}

int
main(int argc, char **argv)
{
	int		 ch, code;
	const char	*errstr;

	setlocale(LC_CTYPE, "");

	while ((ch = getopt(argc, argv, "23C:d:H:K:nNP:qT:")) != -1) {
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
		case 'q':
			quiet = 1;
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
	if (code >= 20 && code < 30)
		return 0;
	return code;
}
