/*
 * Copyright (c) 2022, 2023 Omar Polo <op@omarpolo.com>
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
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <locale.h>
#include <libgen.h>
#include <signal.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "log.h"

int privsep_process;

static const struct option opts[] = {
	{"help",	no_argument,	NULL,	'h'},
	{"version",	no_argument,	NULL,	'V'},
	{NULL,		0,		NULL,	0},
};

void
log_request(struct client *c, char *meta, size_t l)
{
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV], b[GEMINI_URL_LEN];
	const char *t;
	int ec;

	ec = getnameinfo((struct sockaddr*)&c->raddr, c->raddrlen,
	    hbuf, sizeof(hbuf),
	    sbuf, sizeof(sbuf),
	    NI_NUMERICHOST | NI_NUMERICSERV);
	if (ec != 0)
		fatalx("getnameinfo: %s", gai_strerror(ec));

	if (c->iri.schema != NULL) {
		/* serialize the IRI */
		strlcpy(b, c->iri.schema, sizeof(b));
		strlcat(b, "://", sizeof(b));

		/* log the decoded host name, but if it was invalid
		 * use the raw one. */
		if (*c->domain != '\0')
			strlcat(b, c->domain, sizeof(b));
		else
			strlcat(b, c->iri.host, sizeof(b));

		if (*c->iri.path != '/')
			strlcat(b, "/", sizeof(b));
		strlcat(b, c->iri.path, sizeof(b)); /* TODO: sanitize UTF8 */
		if (*c->iri.query != '\0') {	    /* TODO: sanitize UTF8 */
			strlcat(b, "?", sizeof(b));
			strlcat(b, c->iri.query, sizeof(b));
		}
	} else {
		if ((t = c->req) == NULL)
			t = "";
		strlcpy(b, t, sizeof(b));
	}

	if ((t = memchr(meta, '\r', l)) == NULL)
		t = meta + l;

	fprintf(stderr, "%s:%s GET %s %.*s\n", hbuf, sbuf, b,
	    (int)(t-meta), meta);
}

void
load_local_cert(struct vhost *h, const char *hostname, const char *dir)
{
	char *cert, *key;

	if (asprintf(&cert, "%s/%s.cert.pem", dir, hostname) == -1)
		fatal("asprintf");
	if (asprintf(&key, "%s/%s.key.pem", dir, hostname) == -1)
		fatal("asprintf");

	if (access(cert, R_OK) == -1 || access(key, R_OK) == -1)
		gen_certificate(hostname, cert, key);

	h->cert = tls_load_file(cert, &h->certlen, NULL);
	if (h->cert == NULL)
		fatal("can't load %s", cert);

	h->key = tls_load_file(key, &h->keylen, NULL);
	if (h->key == NULL)
		fatal("can't load %s", key);

	strlcpy(h->domain, hostname, sizeof(h->domain));
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
		fatal("can't mkdir %s", path);
}

/* $XDG_DATA_HOME/gmid */
char *
data_dir(void)
{
	const char *home, *xdg;
	char *t;

	if ((xdg = getenv("XDG_DATA_HOME")) == NULL) {
		if ((home = getenv("HOME")) == NULL)
			fatalx("XDG_DATA_HOME and HOME both empty");
		if (asprintf(&t, "%s/.local/share/gmid", home) == -1)
			fatalx("asprintf");
	} else {
		if (asprintf(&t, "%s/gmid", xdg) == -1)
			fatal("asprintf");
	}

	mkdirs(t, 0755);
	return t;
}

static int
serve(struct conf *conf, const char *host, int port, const char *dir)
{
	struct addrinfo hints, *res, *res0;
	struct vhost *vh = TAILQ_FIRST(&conf->hosts);
	struct address *addr, *acp;
	int r, error, saved_errno, sock = -1;
	const char *cause = NULL;
	char service[32];
	int any = 0;

	event_init();

	r = snprintf(service, sizeof(service), "%d", port);
	if (r < 0 || (size_t)r >= sizeof(service))
		fatal("snprintf");

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	error = getaddrinfo(host, service, &hints, &res0);
	if (error)
		fatalx("%s", gai_strerror(error));
	for (res = res0; res; res = res->ai_next) {
		sock = socket(res->ai_family, res->ai_socktype,
		    res->ai_protocol);
		if (sock == -1) {
			cause = "socket";
			continue;
		}

		if (bind(sock, res->ai_addr, res->ai_addrlen) == -1) {
			cause = "bind";
			saved_errno = errno;
			close(sock);
			errno = saved_errno;
			continue;
		}

		if (listen(sock, 5) == -1)
			fatal("listen");

		any = 1;

		addr = xcalloc(1, sizeof(*addr));
		addr->ai_flags = res->ai_flags;
		addr->ai_family = res->ai_family;
		addr->ai_socktype = res->ai_socktype;
		addr->ai_protocol = res->ai_protocol;
		addr->slen = res->ai_addrlen;
		memcpy(&addr->ss, res->ai_addr, res->ai_addrlen);

		addr->conf = conf;
		addr->sock = sock;
		event_set(&addr->evsock, addr->sock, EV_READ|EV_PERSIST,
		    do_accept, addr);

		if ((addr->ctx = tls_server()) == NULL)
			fatal("tls_server failure");

		TAILQ_INSERT_HEAD(&conf->addrs, addr, addrs);

		acp = xcalloc(1, sizeof(*acp));
		memcpy(acp, addr, sizeof(*acp));
		acp->sock = -1;
		memset(&acp->evsock, 0, sizeof(acp->evsock));
		TAILQ_INSERT_HEAD(&vh->addrs, addr, addrs);
	}

	if (!any)
		fatal("%s", cause);
	freeaddrinfo(res0);

	server_init(NULL, NULL, NULL);
	if (server_configure_done(conf) == -1)
		fatalx("server configuration failed");

	log_info("serving %s on port %d", dir, port);
	event_dispatch();
	log_info("quitting");
	return 0;
}

static __dead void
usage(void)
{
	fprintf(stderr,
	    "Version: " GE_STRING "\n"
	    "Usage: %s [-hVv] [-d certs-dir] [-H hostname] [-p port] [dir]\n",
	    getprogname());
	exit(1);
}

int
main(int argc, char **argv)
{
	struct conf *conf;
	struct vhost *host;
	struct location *loc;
	const char *errstr, *certs_dir = NULL, *hostname = "localhost";
	char path[PATH_MAX];
	int ch, port = 1965;

	setlocale(LC_CTYPE, "");

	log_init(1, LOG_DAEMON);
	log_setverbose(0);
	conf = config_new();

	/* ge doesn't do privsep so no privsep crypto engine. */
	conf->use_privsep_crypto = 0;

	while ((ch = getopt_long(argc, argv, "d:H:hp:Vv", opts, NULL)) != -1) {
		switch (ch) {
		case 'd':
			certs_dir = optarg;
			break;
		case 'H':
			hostname = optarg;
			break;
		case 'h':
			usage();
			break;
		case 'p':
			port = strtonum(optarg, 0, UINT16_MAX, &errstr);
			if (errstr)
				fatalx("port number is %s: %s", errstr,
				    optarg);
			break;
		case 'V':
			puts("Version: " GE_STRING);
			return 0;
		default:
			usage();
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc > 1)
		usage();

	/* prepare the configuration */
	init_mime(&conf->mime);

	if (certs_dir == NULL)
		certs_dir = data_dir();

	/* set up the implicit vhost and location */
	host = xcalloc(1, sizeof(*host));
	TAILQ_INSERT_HEAD(&conf->hosts, host, vhosts);

	loc = xcalloc(1, sizeof(*loc));
	loc->fcgi = -1;
	TAILQ_INSERT_HEAD(&host->locations, loc, locations);

	load_local_cert(host, hostname, certs_dir);

	strlcpy(host->domain, "*", sizeof(host->domain));
	loc->auto_index = 1;
	strlcpy(loc->match, "*", sizeof(loc->match));

	if (*argv == NULL) {
		if (getcwd(path, sizeof(path)) == NULL)
			fatal("getcwd");
		strlcpy(loc->dir, path, sizeof(loc->dir));
	} else {
		char	*tmp;

		tmp = absolutify_path(*argv);
		strlcpy(loc->dir, tmp, sizeof(loc->dir));
		free(tmp);
	}

	/* start the server */
	signal(SIGPIPE, SIG_IGN);
	setproctitle("%s", loc->dir);
	return serve(conf, hostname, port, loc->dir);
}
