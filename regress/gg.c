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

#include "../gmid.h"

#include <string.h>

int flag2, flag3, bflag, cflag, hflag, Nflag, Oflag, Vflag, vflag;
const char *cert, *key;

static void
timeout(int signo)
{
	dprintf(2, "%s: timer expired\n", getprogname());
	exit(1);
}

int
main(int argc, char **argv)
{
	struct iri iri;
	struct tls_config *conf;
	struct tls *ctx;
	char iribuf[GEMINI_URL_LEN], buf[GEMINI_URL_LEN];
	const char *parse_err = "unknown error", *port = "1965", *errstr;
	const char *hostname;
	char *t;
	int ch, handshake, timer;
	ssize_t len;

	hostname = NULL;
	while ((ch = getopt(argc, argv, "23C:cbH:hK:NOT:Vv")) != -1) {
		switch (ch) {
		case '2':
			flag2 = 1;
			break;
		case '3':
			flag3 = 1;
			break;
		case 'b':
			bflag = 1;
			break;
		case 'C':
			cert = optarg;
			break;
		case 'c':
			cflag = 1;
			break;
		case 'H':
			hostname = optarg;
			break;
		case 'h':
			hflag = 1;
			break;
		case 'K':
			key = optarg;
			break;
		case 'N':
			Nflag = 1;
			break;
		case 'O':
			Oflag = 1;
			break;
		case 'T':
			timer = strtonum(optarg, 1, 1000, &errstr);
			if (errstr != NULL)
				errx(1, "timeout is %s: %s", errstr, optarg);
			signal(SIGALRM, timeout);
			alarm(timer);
			break;
		case 'V':
			Vflag = 1;
			break;
		case 'v':
			vflag = 1;
			break;
		default:
			fprintf(stderr, "USAGE: %s [-23cbhNVv] [-H hostname]\n",
			    *argv);
			return 1;
		}
	}
	argc -= optind;
	argv += optind;

	if ((bflag + cflag + hflag + Vflag) > 1)
		errx(1, "only one of bchr flags can be used.");

	if (flag2 + flag3 > 1)
		errx(1, "only -2 or -3 can be specified at the same time.");

	if ((cert != NULL && key == NULL) || (cert == NULL && key != NULL))
		errx(1, "missing certificate or key");

	if (argc != 1)
		errx(1, "missing IRI");

	if (strlcpy(iribuf, argv[0], sizeof(iribuf)) >= sizeof(iribuf))
		errx(1, "request too long: %s", argv[0]);
	if (strlcpy(buf, argv[0], sizeof(buf)) >= sizeof(iribuf))
		errx(1, "request too long: %s", argv[0]);
	if (strlcat(buf, "\r\n", sizeof(buf)) >= sizeof(buf))
		errx(1, "request too long: %s", argv[0]);

	if (!parse_iri(iribuf, &iri, &parse_err))
		errx(1, "invalid IRI: %s", parse_err);

	if (Vflag)
		errx(0, "IRI: OK");

	if ((conf = tls_config_new()) == NULL)
		errx(1, "tls_config_new");

	tls_config_insecure_noverifycert(conf);
	if (Nflag)
		tls_config_insecure_noverifyname(conf);

	if (Oflag)
		tls_config_ocsp_require_stapling(conf);

	if (flag2 && tls_config_set_protocols(conf, TLS_PROTOCOL_TLSv1_2) == -1)
		errx(1, "cannot set TLSv1.2");
	if (flag3 && tls_config_set_protocols(conf, TLS_PROTOCOL_TLSv1_3) == -1)
		errx(1, "cannot set TLSv1.3");

	if (cert != NULL && tls_config_set_keypair_file(conf, cert, key))
		errx(1, "couldn't load cert: %s", cert);

	if ((ctx = tls_client()) == NULL)
		errx(1, "tls_client creation failed");

	if (tls_configure(ctx, conf) == -1)
		errx(1, "tls_configure: %s", tls_error(ctx));

	if (*iri.port != '\0')
		port = iri.port;

	if (hostname == NULL)
		hostname = iri.host;

	if (tls_connect_servername(ctx, iri.host, port, hostname) == -1)
		errx(1, "tls_connect: %s", tls_error(ctx));

	for (handshake = 0; !handshake;) {
		switch (tls_handshake(ctx)) {
		case 0:
		case -1:
			handshake = 1;
			break;
		}
	}

	if (vflag)
		printf("%s", buf);
	if (tls_write(ctx, buf, strlen(buf)) == -1)
		errx(1, "tls_write: %s", tls_error(ctx));

	for (;;) {
		switch (len = tls_read(ctx, buf, sizeof(buf))) {
		case 0:
		case -1:
			goto end;
		case TLS_WANT_POLLIN:
		case TLS_WANT_POLLOUT:
			continue;
		}

		if (bflag) {
			bflag = 0;
			if ((t = strchr(buf, '\r')) != NULL)
				t += 2;
			else if ((t = strchr(buf, '\n')) != NULL)
				t += 1;
			else
				continue;
			len -= t - buf;
			write(1, t, len);
			continue;
		}

		if (cflag) {
			write(1, buf, 2);
			write(1, "\n", 1);
			break;
		}

		if (hflag) {
			t = strchr(buf, '\r');
			if (t == NULL)
				t = strchr(buf, '\n');
			if (t == NULL)
				t = &buf[len];
                        write(1, buf, t - buf);
			write(1, "\n", 1);
			break;
		}

		write(1, buf, len);
	}
end:

	tls_close(ctx);
	tls_free(ctx);

	return 0;
}
