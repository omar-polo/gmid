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

#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <limits.h>
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <string.h>

#include <openssl/pem.h>
#include <openssl/x509.h>

#include "gmid.h"

volatile sig_atomic_t hupped;

struct vhost hosts[HOSTSLEN];

int exfd, foreground, verbose, sock4, sock6;

const char *config_path, *certs_dir, *hostname;

struct conf conf;

struct tls_config *tlsconf;
struct tls *ctx;

void
fatal(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	if (foreground) {
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

	if (foreground && !verbose) {
		if (priority == LOG_DEBUG || priority == LOG_INFO)
			return;
	}

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

	if (foreground)
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

		/* log the decoded host name, but if it was invalid
		 * use the raw one. */
		if (*c->domain != '\0')
			strlcat(b, c->domain, sizeof(b));
		else
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

	if (foreground)
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

	hupped = sig == SIGHUP;
}

void
gen_certificate(const char *host, const char *certpath, const char *keypath)
{
	BIGNUM		e;
	EVP_PKEY	*pkey;
	RSA		*rsa;
	X509		*x509;
	X509_NAME	*name;
	FILE		*f;
	const char	*org = "gmid";

	LOGN(NULL, "generating new certificate for %s (it could take a while)",
	    host);

	if ((pkey = EVP_PKEY_new()) == NULL)
                fatal("couldn't create a new private key");

	if ((rsa = RSA_new()) == NULL)
		fatal("could'nt generate rsa");

	BN_init(&e);
	BN_set_word(&e, 17);
	if (!RSA_generate_key_ex(rsa, 4096, &e, NULL))
		fatal("couldn't generate a rsa key");

	if (!EVP_PKEY_assign_RSA(pkey, rsa))
		fatal("couldn't assign the key");

	if ((x509 = X509_new()) == NULL)
		fatal("couldn't generate the X509 certificate");

	ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
	X509_gmtime_adj(X509_get_notBefore(x509), 0);
	X509_gmtime_adj(X509_get_notAfter(x509), 315360000L); /* 10 years */

	if (!X509_set_pubkey(x509, pkey))
		fatal("couldn't set the public key");

	name = X509_get_subject_name(x509);
	if (!X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, org, -1, -1, 0))
		fatal("couldn't add N to cert");
	if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, host, -1, -1, 0))
		fatal("couldn't add CN to cert");
	X509_set_issuer_name(x509, name);

	if (!X509_sign(x509, pkey, EVP_sha256()))
                fatal("couldn't sign the certificate");

	if ((f = fopen(keypath, "w")) == NULL)
		fatal("fopen(%s): %s", keypath, strerror(errno));
	if (!PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL))
		fatal("couldn't write private key");
	fclose(f);

	if ((f = fopen(certpath, "w")) == NULL)
		fatal("fopen(%s): %s", certpath, strerror(errno));
	if (!PEM_write_X509(f, x509))
		fatal("couldn't write cert");
	fclose(f);

	X509_free(x509);
	RSA_free(rsa);
}

/* XXX: create recursively */
void
mkdirs(const char *path)
{
	if (mkdir(path, 0755) == -1 && errno != EEXIST)
		fatal("can't mkdir %s: %s", path, strerror(errno));
}

/* $XDG_DATA_HOME/gmid */
char *
data_dir(void)
{
	const char *home, *xdg;
	char *t;

	if ((xdg = getenv("XDG_DATA_HOME")) == NULL) {
		if ((home = getenv("HOME")) == NULL)
			errx(1, "XDG_DATA_HOME and HOME both empty");
		if (asprintf(&t, "%s/.local/share/gmid", home) == -1)
			err(1, "asprintf");
		mkdirs(t);
		return t;
	}

	if (asprintf(&t, "%s/gmid", xdg) == -1)
		err(1, "asprintf");
	mkdirs(t);
	return t;
}

void
load_local_cert(const char *hostname, const char *dir)
{
	char *cert, *key;

	if (asprintf(&cert, "%s/%s.cert.pem", dir, hostname) == -1)
		errx(1, "asprintf");
	if (asprintf(&key, "%s/%s.key.pem", dir, hostname) == -1)
		errx(1, "asprintf");

	if (access(cert, R_OK) == -1 || access(key, R_OK) == -1)
		gen_certificate(hostname, cert, key);

	hosts[0].cert = cert;
	hosts[0].key = key;
	hosts[0].domain = hostname;
}

void
load_vhosts(void)
{
	struct vhost *h;

	for (h = hosts; h->domain != NULL; ++h) {
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

void
setup_tls(void)
{
	struct vhost *h;

	if ((tlsconf = tls_config_new()) == NULL)
		fatal("tls_config_new");

	/* optionally accept client certs, but don't try to verify them */
	tls_config_verify_client_optional(tlsconf);
	tls_config_insecure_noverifycert(tlsconf);

	if (tls_config_set_protocols(tlsconf, conf.protos) == -1)
		fatal("tls_config_set_protocols");

	if ((ctx = tls_server()) == NULL)
		fatal("tls_server failure");

	/* we need to set something, then we can add how many key we want */
	if (tls_config_set_keypair_file(tlsconf, hosts->cert, hosts->key))
		fatal("tls_config_set_keypair_file failed for (%s, %s)",
		    hosts->cert, hosts->key);

	for (h = &hosts[1]; h->domain != NULL; ++h) {
		if (tls_config_add_keypair_file(tlsconf, h->cert, h->key) == -1)
			fatal("failed to load the keypair (%s, %s)",
			    h->cert, h->key);
	}

	if (tls_configure(ctx, tlsconf) == -1)
		fatal("tls_configure: %s", tls_error(ctx));
}

static int
listener_main(void)
{
	load_default_mime(&conf.mime);
	load_vhosts();
	sandbox();
	loop(ctx, sock4, sock6);
	return 0;
}

void
init_config(void)
{
	size_t i;

	bzero(hosts, sizeof(hosts));
	for (i = 0; i < HOSTSLEN; ++i)
		hosts[i].dirfd = -1;

	conf.port = 1965;
	conf.ipv6 = 0;
	conf.protos = TLS_PROTOCOL_TLSv1_2 | TLS_PROTOCOL_TLSv1_3;

	init_mime(&conf.mime);

	conf.chroot = NULL;
	conf.user = NULL;
}

void
free_config(void)
{
	struct vhost *h;
	struct location *l;

	free(conf.chroot);
	free(conf.user);
	memset(&conf, 0, sizeof(conf));

	for (h = hosts; h->domain != NULL; ++h) {
		free((char*)h->domain);
		free((char*)h->cert);
		free((char*)h->key);
		free((char*)h->dir);
		free((char*)h->cgi);

		for (l = h->locations; l->match != NULL; ++l) {
			free((char*)l->match);
			free((char*)l->lang);
			free((char*)l->default_mime);
			free((char*)l->index);
		}
	}
	memset(hosts, 0, sizeof(hosts));

	tls_free(ctx);
	tls_config_free(tlsconf);
}

static void
wait_sighup(void)
{
	sigset_t mask;
	int signo;

	sigemptyset(&mask);
	sigaddset(&mask, SIGHUP);
	sigwait(&mask, &signo);
}

void
drop_priv(void)
{
	struct passwd *pw = NULL;

	if (conf.chroot != NULL && conf.user == NULL)
		fatal("can't chroot without an user to switch to after.");

	if (conf.user != NULL) {
		if ((pw = getpwnam(conf.user)) == NULL)
			fatal("can't find user %s", conf.user);
	}

	if (conf.chroot != NULL) {
		if (chroot(conf.chroot) != 0 || chdir("/") != 0)
			fatal("%s: %s", conf.chroot, strerror(errno));
	}

	if (pw != NULL) {
		if (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1)
			fatal("setresuid(%d): %s", pw->pw_uid,
			    strerror(errno));
	}

	if (getuid() == 0)
		LOGW(NULL, "%s",
		    "not a good idea to run a network daemon as root");
}

void
usage(const char *me)
{
	fprintf(stderr,
	    "USAGE: %s [-fn] [-c config] | [-6h] [-d certs-dir] [-H host]"
	    "       [-p port] [-x cgi] [dir]",
	    me);
}

static int
serve(int argc, char **argv, int *p)
{
	char path[PATH_MAX];

	if (config_path == NULL) {
		if (hostname == NULL)
			hostname = "localhost";
		if (certs_dir == NULL)
			certs_dir = data_dir();
		load_local_cert(hostname, certs_dir);

		hosts[0].domain = "*";
		hosts[0].locations[0].auto_index = 1;
		hosts[0].locations[0].match = "*";

		switch (argc) {
		case 0:
			hosts[0].dir = getcwd(path, sizeof(path));
			break;
		case 1:
			hosts[0].dir = absolutify_path(argv[0]);
			break;
		default:
			usage(getprogname());
			return 1;
		}

		LOGN(NULL, "serving %s on port %d", hosts[0].dir, conf.port);
	}

	/* setup tls before dropping privileges: we don't want user
	 * to put private certs inside the chroot. */
	setup_tls();

	switch (fork()) {
	case -1:
		fatal("fork: %s", strerror(errno));

	case 0:			/* child */
		setproctitle("listener");
		close(p[0]);
		exfd = p[1];
		drop_priv();
		unblock_signals();
		listener_main();
		_exit(0);

	default:		/* parent */
		setproctitle("executor");
		close(p[1]);
		exfd = p[0];
		drop_priv();
		unblock_signals();
		return executor_main();
	}
}

int
main(int argc, char **argv)
{
	int ch, p[2];
	int conftest = 0, configless = 0;
	int old_ipv6, old_port;

	init_config();

	while ((ch = getopt(argc, argv, "6c:d:fH:hnp:vx:")) != -1) {
		switch (ch) {
		case '6':
			conf.ipv6 = 1;
			configless = 1;
			break;

		case 'c':
			config_path = absolutify_path(optarg);
			break;

		case 'd':
			certs_dir = optarg;
			configless = 1;
			break;

		case 'f':
			foreground = 1;
			break;

		case 'H':
			hostname = optarg;
			configless = 1;
			break;

		case 'h':
			usage(*argv);
			return 0;

		case 'n':
			conftest = 1;
			break;

		case 'p':
			conf.port = parse_portno(optarg);
			configless = 1;
			break;

		case 'v':
			verbose = 1;
			break;

		case 'x':
			/* drop the starting / (if any) */
			if (*optarg == '/')
				optarg++;
			hosts[0].cgi = optarg;
			configless = 1;
			break;

		default:
			usage(*argv);
			return 1;
		}
	}
	argc -= optind;
	argv += optind;

	if (config_path == NULL) {
		configless = 1;
		foreground = 1;
	}

	if (config_path != NULL && (argc > 0 || configless))
		err(1, "can't specify options in config mode.");

	if (conftest) {
		parse_conf(config_path);
		puts("config OK");
		return 0;
	}

	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);

#ifdef SIGINFO
	signal(SIGINFO, sig_handler);
#endif
	signal(SIGUSR2, sig_handler);
	signal(SIGHUP, sig_handler);

	if (!foreground && !configless) {
		if (daemon(1, 1) == -1)
			fatal("daemon: %s", strerror(errno));
	}

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC,
	    PF_UNSPEC, p) == -1)
		fatal("socketpair: %s", strerror(errno));

	if (config_path != NULL)
		parse_conf(config_path);

	sock4 = make_socket(conf.port, AF_INET);
	sock6 = -1;
	if (conf.ipv6)
		sock6 = make_socket(conf.port, AF_INET6);

	if (configless)
		return serve(argc, argv, p);

	/* wait a sighup and reload the daemon */
	for (;;) {
		block_signals();

		hupped = 0;
		switch (fork()) {
		case -1:
			fatal("fork: %s", strerror(errno));
		case 0:
			return serve(argc, argv, p);
		}

		close(p[0]);
		close(p[1]);

		wait_sighup();
		unblock_signals();
		LOGI("reloading configuration %s", config_path);

		old_ipv6 = conf.ipv6;
		old_port = conf.port;

		free_config();
		init_config();
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

		if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC,
		    PF_UNSPEC, p) == -1)
			fatal("socketpair: %s", strerror(errno));
	}
}
