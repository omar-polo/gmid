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

#include "gmid.h"

#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <syslog.h>

#include <openssl/pem.h>

#include "log.h"
#include "proc.h"

struct conf *
config_new(void)
{
	struct conf *conf;

	conf = xcalloc(1, sizeof(*conf));

	TAILQ_INIT(&conf->fcgi);
	TAILQ_INIT(&conf->hosts);
	TAILQ_INIT(&conf->pkis);
	TAILQ_INIT(&conf->addrs);

	conf->protos = TLS_PROTOCOL_TLSv1_2 | TLS_PROTOCOL_TLSv1_3;

	init_mime(&conf->mime);

	conf->prefork = 3;
	conf->log_syslog = 1;
	conf->log_facility = LOG_DAEMON;
	conf->log_format = LOG_FORMAT_LEGACY;

	conf->use_privsep_crypto = 1;

	return conf;
}

void
config_purge(struct conf *conf)
{
	struct privsep *ps;
	struct fcgi *f, *tf;
	struct vhost *h, *th;
	struct location *l, *tl;
	struct proxy *p, *tp;
	struct envlist *e, *te;
	struct alist *a, *ta;
	struct pki *pki, *tpki;
	struct address *addr, *taddr;
	int use_privsep_crypto, log_format;

	ps = conf->ps;
	use_privsep_crypto = conf->use_privsep_crypto;
	log_format = conf->log_format;

	free(conf->log_access);
	free_mime(&conf->mime);
	TAILQ_FOREACH_SAFE(f, &conf->fcgi, fcgi, tf) {
		TAILQ_REMOVE(&conf->fcgi, f, fcgi);
		free(f);
	}

	TAILQ_FOREACH_SAFE(h, &conf->hosts, vhosts, th) {
		free(h->cert_path);
		free(h->key_path);
		free(h->ocsp_path);
		free(h->cert);
		free(h->key);
		free(h->ocsp);

		TAILQ_FOREACH_SAFE(addr, &h->addrs, addrs, taddr) {
			TAILQ_REMOVE(&h->addrs, addr, addrs);
			free(addr);
		}

		TAILQ_FOREACH_SAFE(l, &h->locations, locations, tl) {
			TAILQ_REMOVE(&h->locations, l, locations);

			if (l->dirfd != -1)
				close(l->dirfd);

			free(l->reqca_path);
			X509_STORE_free(l->reqca);

			TAILQ_FOREACH_SAFE(e, &l->params, envs, te) {
				TAILQ_REMOVE(&l->params, e, envs);
				free(e);
			}

			free(l);
		}

		TAILQ_FOREACH_SAFE(a, &h->aliases, aliases, ta) {
			TAILQ_REMOVE(&h->aliases, a, aliases);
			free(a);
		}

		TAILQ_FOREACH_SAFE(p, &h->proxies, proxies, tp) {
			TAILQ_REMOVE(&h->proxies, p, proxies);
			free(p->cert_path);
			free(p->cert);
			free(p->key_path);
			free(p->key);
			free(p->reqca_path);
			X509_STORE_free(p->reqca);
			free(p);
		}

		TAILQ_REMOVE(&conf->hosts, h, vhosts);
		free(h);
	}

	TAILQ_FOREACH_SAFE(pki, &conf->pkis, pkis, tpki) {
		TAILQ_REMOVE(&conf->pkis, pki, pkis);
		free(pki->hash);
		EVP_PKEY_free(pki->pkey);
		free(pki);
	}

	TAILQ_FOREACH_SAFE(addr, &conf->addrs, addrs, taddr) {
		TAILQ_REMOVE(&conf->addrs, addr, addrs);
		if (addr->sock != -1) {
			close(addr->sock);
			event_del(&addr->evsock);
			tls_free(addr->ctx);
		}
		free(addr);
	}

	memset(conf, 0, sizeof(*conf));

	conf->ps = ps;
	conf->use_privsep_crypto = use_privsep_crypto;
	conf->protos = TLS_PROTOCOL_TLSv1_2 | TLS_PROTOCOL_TLSv1_3;
	conf->log_syslog = 1;
	conf->log_facility = LOG_DAEMON;
	conf->log_format = log_format;
	init_mime(&conf->mime);
	TAILQ_INIT(&conf->fcgi);
	TAILQ_INIT(&conf->hosts);
	TAILQ_INIT(&conf->pkis);
}

static int
config_send_file(struct privsep *ps, enum privsep_procid id, int type,
    int fd, void *data, size_t l)
{
	int	 n, m, d;

	n = -1;
	proc_range(ps, id, &n, &m);
	for (n = 0; n < m; ++n) {
		d = -1;
		if (fd != -1 && (d = dup(fd)) == -1)
			fatal("dup %d", fd);
		if (proc_compose_imsg(ps, id, n, type, -1, d, data, l)
		    == -1)
			return -1;
	}

	if (fd != -1)
		close(fd);

	/* avoid fd rampage */
	if (proc_flush_imsg(ps, id, -1) == -1) {
		log_warn("%s: proc_fush_imsg", __func__);
		return -1;
	}

	return 0;
}

static int
config_open_send(struct privsep *ps, enum privsep_procid id, int type,
    const char *path)
{
	int fd;

	log_debug("sending %s", path);

	if ((fd = open(path, O_RDONLY)) == -1)
		fatal("can't open %s", path);

	return config_send_file(ps, id, type, fd, NULL, 0);
}

static int
config_send_kp(struct privsep *ps, int cert_type, int key_type,
    const char *cert, const char *key)
{
	struct conf *conf = ps->ps_env;
	int fd, d, key_target;

	log_debug("sending %s", cert);
	if ((fd = open(cert, O_RDONLY)) == -1)
		fatal("can't open %s", cert);
	if ((d = dup(fd)) == -1)
		fatal("fd");

	if (config_send_file(ps, PROC_SERVER, cert_type, fd, NULL, 0) == -1) {
		close(d);
		return -1;
	}
	if (conf->use_privsep_crypto &&
	    config_send_file(ps, PROC_CRYPTO, cert_type, d, NULL, 0) == -1)
		return -1;

	key_target = PROC_CRYPTO;
	if (!conf->use_privsep_crypto)
		key_target = PROC_SERVER;

	if (config_open_send(ps, key_target, key_type, key) == -1)
		return -1;

	return 0;
}

static int
config_send_socks(struct conf *conf)
{
	struct privsep	*ps = conf->ps;
	struct address	*addr, a;
	int		 sock, v;

	TAILQ_FOREACH(addr, &conf->addrs, addrs) {
		sock = socket(addr->ai_family, addr->ai_socktype,
		    addr->ai_protocol);
		if (sock == -1) {
			if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT)
				continue;
			fatal("socket");
		}

		v = 1;
		if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v))
		    == -1)
			fatal("setsockopt(SO_REUSEADDR)");

		v = 1;
		if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &v, sizeof(v))
		    == -1)
			fatal("setsockopt(SO_REUSEPORT)");

		mark_nonblock(sock);

		if (bind(sock, (struct sockaddr *)&addr->ss, addr->slen)
		    == -1)
			fatal("bind");

		if (listen(sock, 16) == -1)
			fatal("listen");

		memcpy(&a, addr, sizeof(a));
		a.conf = NULL;
		a.sock = -1;
		memset(&a.evsock, 0, sizeof(a.evsock));
		memset(&a.addrs, 0, sizeof(a.addrs));

		if (config_send_file(ps, PROC_SERVER, IMSG_RECONF_SOCK, sock,
		    &a, sizeof(a)) == -1)
			return -1;
	}

	return 0;
}

int
config_send(struct conf *conf)
{
	struct privsep	*ps = conf->ps;
	struct etm	*m;
	struct fcgi	*fcgi;
	struct vhost	*h;
	struct location	*l;
	struct proxy	*p;
	struct envlist	*e;
	struct alist	*a;
	size_t		 i;

	if (proc_compose(ps, PROC_SERVER, IMSG_RECONF_LOG_FMT,
	    &conf->log_format, sizeof(conf->log_format)) == -1)
		return -1;

	for (i = 0; i < conf->mime.len; ++i) {
		m = &conf->mime.t[i];
		if (proc_compose(ps, PROC_SERVER, IMSG_RECONF_MIME,
		    m, sizeof(*m)) == -1)
			return -1;
	}

	if (proc_compose(ps, PROC_SERVER, IMSG_RECONF_PROTOS,
	    &conf->protos, sizeof(conf->protos)) == -1)
		return -1;

	if (config_send_socks(conf) == -1)
		return -1;

	TAILQ_FOREACH(fcgi, &conf->fcgi, fcgi) {
		log_debug("sending fastcgi %s", fcgi->path);
		if (proc_compose(ps, PROC_SERVER, IMSG_RECONF_FCGI,
		    fcgi, sizeof(*fcgi)) == -1)
			return -1;
	}

	TAILQ_FOREACH(h, &conf->hosts, vhosts) {
		struct vhost vcopy;
		struct address *addr, acopy;

		memcpy(&vcopy, h, sizeof(vcopy));
		vcopy.cert_path = NULL;
		vcopy.key_path = NULL;
		vcopy.ocsp_path = NULL;

		log_debug("sending host %s", h->domain);

		if (proc_compose(ps, PROC_SERVER, IMSG_RECONF_HOST,
		    &vcopy, sizeof(vcopy)) == -1)
			return -1;

		if (config_send_kp(ps, IMSG_RECONF_CERT, IMSG_RECONF_KEY,
		    h->cert_path, h->key_path) == -1)
			return -1;

		if (h->ocsp_path != NULL) {
			if (config_open_send(ps, PROC_SERVER, IMSG_RECONF_OCSP,
			    h->ocsp_path) == -1)
				return -1;
		}

		TAILQ_FOREACH(addr, &h->addrs, addrs) {
			memcpy(&acopy, addr, sizeof(acopy));
			memset(&acopy.addrs, 0, sizeof(acopy.addrs));

			if (proc_compose(ps, PROC_SERVER,
			    IMSG_RECONF_HOST_ADDR, &acopy, sizeof(acopy))
			    == -1)
				return -1;
		}

		if (proc_flush_imsg(ps, PROC_SERVER, -1) == -1) {
			log_warn("%s: proc_fush_imsg", __func__);
			return -1;
		}

		TAILQ_FOREACH(l, &h->locations, locations) {
			struct location lcopy;
			int fd = -1;

			memcpy(&lcopy, l, sizeof(lcopy));
			lcopy.reqca_path = NULL;
			lcopy.reqca = NULL;
			lcopy.dirfd = -1;
			memset(&lcopy.locations, 0, sizeof(lcopy.locations));

			if (l->reqca_path != NULL &&
			    (fd = open(l->reqca_path, O_RDONLY)) == -1)
				fatal("can't open %s", l->reqca_path);

			if (config_send_file(ps, PROC_SERVER, IMSG_RECONF_LOC,
			    fd, &lcopy, sizeof(lcopy)) == -1)
				return -1;

			TAILQ_FOREACH(e, &l->params, envs) {
				if (proc_compose(ps, PROC_SERVER,
				    IMSG_RECONF_ENV, e, sizeof(*e)) == -1)
					return -1;
			}
		}

		if (proc_flush_imsg(ps, PROC_SERVER, -1) == -1)
			return -1;

		TAILQ_FOREACH(a, &h->aliases, aliases) {
			if (proc_compose(ps, PROC_SERVER, IMSG_RECONF_ALIAS,
			    a, sizeof(*a)) == -1)
				return -1;
		}

		if (proc_flush_imsg(ps, PROC_SERVER, -1) == -1)
			return -1;

		TAILQ_FOREACH(p, &h->proxies, proxies) {
			struct proxy pcopy;
			int fd = -1;

			memcpy(&pcopy, p, sizeof(pcopy));
			pcopy.cert_path = NULL;
			pcopy.cert = NULL;
			pcopy.certlen = 0;
			pcopy.key_path = NULL;
			pcopy.key = NULL;
			pcopy.keylen = 0;
			pcopy.reqca_path = NULL;
			pcopy.reqca = NULL;

			if (p->reqca_path != NULL) {
				fd = open(p->reqca_path, O_RDONLY);
				if (fd == -1)
					fatal("can't open %s", p->reqca_path);
			}

			if (config_send_file(ps, PROC_SERVER, IMSG_RECONF_PROXY,
			    fd, &pcopy, sizeof(pcopy)) == -1)
				return -1;

			if (p->cert_path == NULL || p->key_path == NULL)
				continue;

			if (config_open_send(ps, PROC_SERVER,
			    IMSG_RECONF_PROXY_CERT, p->cert_path) == -1 ||
			    config_open_send(ps, PROC_SERVER,
			    IMSG_RECONF_PROXY_KEY, p->key_path) == -1)
				return -1;
		}
	}

	return 0;
}

static int
load_file(int fd, uint8_t **data, size_t *len)
{
	struct stat	 sb;
	ssize_t		 r;

	if (fstat(fd, &sb) == -1)
		fatal("fstat");

	if (sb.st_size < 0 /* || sb.st_size > SIZE_MAX */) {
		log_warnx("file too large");
		close(fd);
		return -1;
	}
	*len = sb.st_size;

	if ((*data = malloc(*len)) == NULL)
		fatal("malloc");

	r = pread(fd, *data, *len, 0);
	if (r == -1 || (size_t)r != *len) {
		log_warn("read failed");
		close(fd);
		free(*data);
		return -1;
	}

	close(fd);
	return 0;
}

static int
config_crypto_recv_kp(struct conf *conf, struct imsg *imsg)
{
	static struct pki *pki;
	uint8_t *d;
	size_t len;
	int fd;

	/* XXX: check for duplicates */

	if ((fd = imsg_get_fd(imsg)) == -1)
		fatalx("%s: no fd for imsg %d", __func__, imsg_get_type(imsg));

	switch (imsg_get_type(imsg)) {
	case IMSG_RECONF_CERT:
		if (pki != NULL)
			fatalx("imsg in wrong order; pki is not NULL");
		if ((pki = calloc(1, sizeof(*pki))) == NULL)
			fatal("calloc");
		if (load_file(fd, &d, &len) == -1)
			fatalx("can't load file");
		if ((pki->hash = ssl_pubkey_hash(d, len)) == NULL)
			fatalx("failed to compute cert hash");
		free(d);
		TAILQ_INSERT_TAIL(&conf->pkis, pki, pkis);
		break;

	case IMSG_RECONF_KEY:
		if (pki == NULL)
			fatalx("%s: RECONF_KEY: got key without cert",
			    __func__);
		if (load_file(fd, &d, &len) == -1)
			fatalx("failed to load private key");
		if ((pki->pkey = ssl_load_pkey(d, len)) == NULL)
			fatalx("failed load private key");
		free(d);
		pki = NULL;
		break;

	default:
		return -1;
	}

	return 0;
}

int
config_recv(struct conf *conf, struct imsg *imsg)
{
	static struct vhost *h;
	static struct location *l;
	static struct proxy *p;
	struct privsep	*ps = conf->ps;
	struct etm	 m;
	struct fcgi	*fcgi;
	struct vhost	*vh, vht;
	struct location	*loc;
	struct envlist	*env;
	struct alist	*alias;
	struct proxy	*proxy;
	struct address	*addr;
	uint8_t		*d;
	size_t		 len;
	int		 fd;

	switch (imsg_get_type(imsg)) {
	case IMSG_RECONF_START:
		config_purge(conf);
		h = NULL;
		p = NULL;
		break;

	case IMSG_RECONF_LOG_FMT:
		if (imsg_get_data(imsg, &conf->log_format,
		    sizeof(conf->log_format)) == -1)
			fatalx("bad length imsg LOG_FMT");
		break;

	case IMSG_RECONF_MIME:
		if (imsg_get_data(imsg, &m, sizeof(m)) == -1)
			fatalx("bad length imsg RECONF_MIME");
		if (m.mime[sizeof(m.mime) - 1] != '\0' ||
		    m.ext[sizeof(m.ext) - 1] != '\0')
			fatal("received corrupted IMSG_RECONF_MIME");
		if (add_mime(&conf->mime, m.mime, m.ext) == -1)
			fatal("failed to add mime mapping %s -> %s",
			    m.mime, m.ext);
		break;

	case IMSG_RECONF_PROTOS:
		if (imsg_get_data(imsg, &conf->protos, sizeof(conf->protos))
		    == -1)
			fatalx("bad length imsg RECONF_PROTOS");
		break;

	case IMSG_RECONF_SOCK:
		addr = xcalloc(1, sizeof(*addr));
		if (imsg_get_data(imsg, addr, sizeof(*addr)) == -1)
			fatalx("bad length imsg RECONF_SOCK");
		if ((fd = imsg_get_fd(imsg)) == -1)
			fatalx("missing socket for IMSG_RECONF_SOCK");
		addr->conf = conf;
		addr->sock = fd;
		event_set(&addr->evsock, addr->sock, EV_READ|EV_PERSIST,
		    server_accept, addr);
		if ((addr->ctx = tls_server()) == NULL)
			fatal("tls_server failure");
		TAILQ_INSERT_HEAD(&conf->addrs, addr, addrs);
		break;

	case IMSG_RECONF_FCGI:
		fcgi = xcalloc(1, sizeof(*fcgi));
		if (imsg_get_data(imsg, fcgi, sizeof(*fcgi)) == -1)
			fatalx("bad length imsg RECONF_FCGI");
		log_debug("received fcgi %s", fcgi->path);
		TAILQ_INSERT_TAIL(&conf->fcgi, fcgi, fcgi);
		break;

	case IMSG_RECONF_HOST:
		if (imsg_get_data(imsg, &vht, sizeof(vht)) == -1)
			fatalx("bad length imsg RECONF_HOST");
		vh = new_vhost();
		strlcpy(vh->domain, vht.domain, sizeof(vh->domain));
		h = vh;
		TAILQ_INSERT_TAIL(&conf->hosts, h, vhosts);

		/* reset location and proxy */
		l = NULL;
		p = NULL;
		break;

	case IMSG_RECONF_CERT:
		log_debug("receiving cert");
		if (privsep_process == PROC_CRYPTO)
			return config_crypto_recv_kp(conf, imsg);
		if (h == NULL)
			fatalx("recv'd cert without host");
		if (h->cert != NULL)
			fatalx("cert already received");
		if ((fd = imsg_get_fd(imsg)) == -1)
			fatalx("no fd for IMSG_RECONF_CERT");
		if (load_file(fd, &h->cert, &h->certlen) == -1)
			fatalx("failed to load cert for %s",
			    h->domain);
		break;

	case IMSG_RECONF_KEY:
		log_debug("receiving key");
		if (privsep_process == PROC_CRYPTO)
			return config_crypto_recv_kp(conf, imsg);
		if (h == NULL)
			fatalx("recv'd key without host");
		if (h->key != NULL)
			fatalx("key already received");
		if ((fd = imsg_get_fd(imsg)) == -1)
			fatalx("no fd for IMSG_RECONF_KEY");
		if (load_file(fd, &h->key, &h->keylen) == -1)
			fatalx("failed to load key for %s",
			    h->domain);
		break;

	case IMSG_RECONF_OCSP:
		log_debug("receiving ocsp");
		if (h == NULL)
			fatalx("recv'd ocsp without host");
		if (h->ocsp != NULL)
			fatalx("ocsp already received");
		if ((fd = imsg_get_fd(imsg)) == -1)
			fatalx("no fd for IMSG_RECONF_OCSP");
		if (load_file(fd, &h->ocsp, &h->ocsplen) == -1)
			fatalx("failed to load ocsp for %s",
			    h->domain);
		break;

	case IMSG_RECONF_HOST_ADDR:
		log_debug("receiving host addr");
		if (h == NULL)
			fatalx("recv'd host address withouth host");
		addr = xcalloc(1, sizeof(*addr));
		if (imsg_get_data(imsg, addr, sizeof(*addr)) == -1)
			fatalx("bad length imsg RECONF_HOST_ADDR");
		TAILQ_INSERT_TAIL(&h->addrs, addr, addrs);
		break;

	case IMSG_RECONF_LOC:
		if (h == NULL)
			fatalx("recv'd location without host");
		loc = xcalloc(1, sizeof(*loc));
		if (imsg_get_data(imsg, loc, sizeof(*loc)) == -1)
			fatalx("bad length imsg RECONF_LOC");
		TAILQ_INIT(&loc->params);

		if ((fd = imsg_get_fd(imsg)) != -1) {
			if (load_file(fd, &d, &len) == -1)
				fatal("load_file");
			loc->reqca = load_ca(d, len);
			if (loc->reqca == NULL)
				fatalx("failed to load CA");
			free(d);
		}

		l = loc;
		TAILQ_INSERT_TAIL(&h->locations, loc, locations);
		break;

	case IMSG_RECONF_ENV:
		if (l == NULL)
			fatalx("recv'd env without location");
		env = xcalloc(1, sizeof(*env));
		if (imsg_get_data(imsg, env, sizeof(*env)) == -1)
			fatalx("bad length imsg RECONF_ENV");
		TAILQ_INSERT_TAIL(&l->params, env, envs);
		break;

	case IMSG_RECONF_ALIAS:
		if (h == NULL)
			fatalx("recv'd alias without host");
		alias = xcalloc(1, sizeof(*alias));
		if (imsg_get_data(imsg, alias, sizeof(*alias)) == -1)
			fatalx("bad length imsg RECONF_ALIAS");
		TAILQ_INSERT_TAIL(&h->aliases, alias, aliases);
		break;

	case IMSG_RECONF_PROXY:
		log_debug("receiving proxy");
		if (h == NULL)
			fatalx("recv'd proxy without host");
		proxy = xcalloc(1, sizeof(*proxy));
		if (imsg_get_data(imsg, proxy, sizeof(*proxy)) == -1)
			fatalx("bad length imsg RECONF_PROXY");

		if ((fd = imsg_get_fd(imsg)) != -1) {
			if (load_file(fd, &d, &len) == -1)
				fatal("load_file");
			proxy->reqca = load_ca(d, len);
			if (proxy->reqca == NULL)
				fatal("failed to load CA");
			free(d);
		}

		TAILQ_INSERT_TAIL(&h->proxies, proxy, proxies);
		p = proxy;
		break;

	case IMSG_RECONF_PROXY_CERT:
		log_debug("receiving proxy cert");
		if (p == NULL)
			fatalx("recv'd proxy cert without proxy");
		if (p->cert != NULL)
			fatalx("proxy cert already received");
		if ((fd = imsg_get_fd(imsg)) == -1)
			fatalx("no fd for IMSG_RECONF_PROXY_CERT");
		if (load_file(fd, &p->cert, &p->certlen) == -1)
			fatalx("failed to load cert for proxy %s of %s",
			    p->host, h->domain);
		break;

	case IMSG_RECONF_PROXY_KEY:
		log_debug("receiving proxy key");
		if (p == NULL)
			fatalx("recv'd proxy key without proxy");
		if (p->key != NULL)
			fatalx("proxy key already received");
		if ((fd = imsg_get_fd(imsg)) == -1)
			fatalx("no fd for IMSG_RECONF_PROXY_KEY");
		if (load_file(fd, &p->key, &p->keylen) == -1)
			fatalx("failed to load key for proxy %s of %s",
			    p->host, h->domain);
		break;

	case IMSG_RECONF_END:
		if (proc_compose(ps, PROC_PARENT, IMSG_RECONF_DONE,
		    NULL, 0) == -1)
			return -1;
		break;

	default:
		return -1;
	}

	return 0;
}

int
config_test(struct conf *conf)
{
	struct vhost	*h;
	struct address	*addr;
	int		 fd;

	/*
	 * can't use config_crypto_recv_kp() because not on all platforms
	 * we're using the privsep crypto engine (yet).
	 */
	conf->use_privsep_crypto = 0;

	TAILQ_FOREACH(h, &conf->hosts, vhosts) {
		if ((fd = open(h->cert_path, O_RDONLY)) == -1) {
			log_warn("can't open %s", h->cert_path);
			return -1;
		}
		if (load_file(fd, &h->cert, &h->certlen) == -1) {
			log_warnx("failed to load cert for %s",
			    h->domain);
			return -1;
		}

		if ((fd = open(h->key_path, O_RDONLY)) == -1) {
			log_warn("can't open %s", h->key_path);
			return -1;
		}
		if (load_file(fd, &h->key, &h->keylen) == -1) {
			log_warnx("failed to load key for %s",
			    h->domain);
			return -1;
		}
	}

	TAILQ_FOREACH(addr, &conf->addrs, addrs) {
		if ((addr->ctx = tls_server()) == NULL)
			fatal("tls_server failed");
		addr->sock = -1;
	}

	if (server_configure_done(conf))
		return -1;

	return 0;
}
