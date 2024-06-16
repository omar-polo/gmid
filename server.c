/*
 * Copyright (c) 2021, 2022, 2023 Omar Polo <op@omarpolo.com>
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
#include <sys/un.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <limits.h>
#include <string.h>

#include "log.h"
#include "proc.h"

#define MINIMUM(a, b)	((a) < (b) ? (a) : (b))

#ifndef nitems
#define nitems(_a) (sizeof((_a)) / sizeof((_a)[0]))
#endif

#ifdef SIGINFO
static struct event siginfo;
#endif
static struct event sigusr2;

int connected_clients;

/*
 * This function is not publicy exported because it is a hack until libtls
 * has a proper privsep setup.
 */
void tls_config_use_fake_private_key(struct tls_config *);

static inline int matches(const char*, const char*);

static void	 handle_handshake(int, short, void*);
static void	 fmtbuf(char *, size_t, const char *, struct client *,
		    const char *);
static int	 apply_block_return(struct client*);
static int	 check_matching_certificate(X509_STORE *, struct client *);
static int	 apply_reverse_proxy(struct client *);
static int	 apply_fastcgi(struct client*);
static int	 apply_require_ca(struct client*);
static void	 open_dir(struct client*);
static void	 redirect_canonical_dir(struct client*);

static void	 client_tls_readcb(int, short, void *);
static void	 client_tls_writecb(int, short, void *);

static void	 client_read(struct bufferevent *, void *);
void		 client_write(struct bufferevent *, void *);
static void	 client_error(struct bufferevent *, short, void *);

static void	 client_close_ev(int, short, void *);

static void	 handle_siginfo(int, short, void*);

static int	 server_dispatch_parent(int, struct privsep_proc *, struct imsg *);
static int	 server_dispatch_crypto(int, struct privsep_proc *, struct imsg *);
static int	 server_dispatch_logger(int, struct privsep_proc *, struct imsg *);

static ssize_t read_cb(struct tls *, void *, size_t, void *);
static ssize_t write_cb(struct tls *, const void *, size_t, void *);

static struct privsep_proc procs[] = {
	{ "parent",	PROC_PARENT,	server_dispatch_parent },
	{ "crypto",	PROC_CRYPTO,	server_dispatch_crypto },
	{ "logger",	PROC_LOGGER,	server_dispatch_logger },
};

static uint32_t server_client_id;

struct client_tree_id clients;

static inline int
match_addr(struct address *target, struct address *source)
{
	return (target->ai_flags == source->ai_flags &&
	    target->ai_family == source->ai_family &&
	    target->ai_socktype == source->ai_socktype &&
	    target->ai_protocol == source->ai_protocol &&
	    target->slen == source->slen &&
	    !memcmp(&target->ss, &source->ss, target->slen));
}

static inline int
matches(const char *pattern, const char *path)
{
	if (*path == '/')
		path++;
	return !fnmatch(pattern, path, 0);
}

static inline int
match_host(struct vhost *v, struct client *c)
{
	struct alist *a;
	struct address *addr;

	TAILQ_FOREACH(addr, &v->addrs, addrs)
		if (match_addr(addr, c->addr))
			break;
	if (addr == NULL)
		return 0;

	if (*c->domain == '\0') {
		if (strlcpy(c->domain, addr->pp, sizeof(c->domain))
		    >= sizeof(c->domain)) {
			log_warnx("%s: domain too long: %s", __func__,
			    addr->pp);
			*c->domain = '\0';
		}
	}

	if (matches(v->domain, c->domain))
		return 1;

	TAILQ_FOREACH(a, &v->aliases, aliases)
		if (matches(a->alias, c->domain))
			return 1;

	return 0;
}

const char *
vhost_lang(struct vhost *v, const char *path)
{
	struct location *loc;

	if (v == NULL || path == NULL)
		return NULL;

	loc = TAILQ_FIRST(&v->locations);
	while ((loc = TAILQ_NEXT(loc, locations)) != NULL) {
		if (*loc->lang != '\0') {
			if (matches(loc->match, path))
				return loc->lang;
		}
	}

	loc = TAILQ_FIRST(&v->locations);
	if (*loc->lang == '\0')
		return NULL;
	return loc->lang;
}

const char *
vhost_default_mime(struct vhost *v, const char *path)
{
	struct location *loc;
	const char *default_mime = "application/octet-stream";

	if (v == NULL || path == NULL)
		return default_mime;

	loc = TAILQ_FIRST(&v->locations);
	while ((loc = TAILQ_NEXT(loc, locations)) != NULL) {
		if (*loc->default_mime != '\0') {
			if (matches(loc->match, path))
				return loc->default_mime;
		}
	}

	loc = TAILQ_FIRST(&v->locations);
	if (*loc->default_mime != '\0')
		return loc->default_mime;
	return default_mime;
}

const char *
vhost_index(struct vhost *v, const char *path)
{
	struct location *loc;
	const char *index = "index.gmi";

	if (v == NULL || path == NULL)
		return index;

	loc = TAILQ_FIRST(&v->locations);
	while ((loc = TAILQ_NEXT(loc, locations)) != NULL) {
		if (*loc->index != '\0') {
			if (matches(loc->match, path))
				return loc->index;
		}
	}

	loc = TAILQ_FIRST(&v->locations);
	if (*loc->index != '\0')
		return loc->index;
	return index;
}

int
vhost_auto_index(struct vhost *v, const char *path)
{
	struct location *loc;

	if (v == NULL || path == NULL)
		return 0;

	loc = TAILQ_FIRST(&v->locations);
	while ((loc = TAILQ_NEXT(loc, locations)) != NULL) {
		if (loc->auto_index != 0) {
			if (matches(loc->match, path))
				return loc->auto_index == 1;
		}
	}

	loc = TAILQ_FIRST(&v->locations);
	return loc->auto_index == 1;
}

int
vhost_block_return(struct vhost *v, const char *path, int *code, const char **fmt)
{
	struct location *loc;

	if (v == NULL || path == NULL)
		return 0;

	loc = TAILQ_FIRST(&v->locations);
	while ((loc = TAILQ_NEXT(loc, locations)) != NULL) {
		if (loc->block_code != 0) {
			if (matches(loc->match, path)) {
				*code = loc->block_code;
				*fmt = loc->block_fmt;
				return 1;
			}
		}
	}

	loc = TAILQ_FIRST(&v->locations);
	*code = loc->block_code;
	*fmt = loc->block_fmt;
	return loc->block_code != 0;
}

struct location *
vhost_fastcgi(struct vhost *v, const char *path)
{
	struct location *loc;

	if (v == NULL || path == NULL)
		return NULL;

	loc = TAILQ_FIRST(&v->locations);
	while ((loc = TAILQ_NEXT(loc, locations)) != NULL) {
		if (loc->fcgi != -1)
			if (matches(loc->match, path))
				return loc;
		if (loc->nofcgi && matches(loc->match, path))
			return NULL;
	}

	loc = TAILQ_FIRST(&v->locations);
	return loc->fcgi == -1 ? NULL : loc;
}

int
vhost_dirfd(struct vhost *v, const char *path, size_t *retloc)
{
	struct location *loc;
	size_t		 l = 0;

	if (v == NULL || path == NULL)
		return -1;

	loc = TAILQ_FIRST(&v->locations);
	while ((loc = TAILQ_NEXT(loc, locations)) != NULL) {
		l++;
		if (loc->dirfd != -1)
			if (matches(loc->match, path)) {
				*retloc = l;
				return loc->dirfd;
			}
	}

	*retloc = 0;
	loc = TAILQ_FIRST(&v->locations);
	return loc->dirfd;
}

int
vhost_strip(struct vhost *v, const char *path)
{
	struct location *loc;

	if (v == NULL || path == NULL)
		return 0;

	loc = TAILQ_FIRST(&v->locations);
	while ((loc = TAILQ_NEXT(loc, locations)) != NULL) {
		if (loc->strip != 0) {
			if (matches(loc->match, path))
				return loc->strip;
		}
	}

	loc = TAILQ_FIRST(&v->locations);
	return loc->strip;
}

X509_STORE *
vhost_require_ca(struct vhost *v, const char *path)
{
	struct location *loc;

	if (v == NULL || path == NULL)
		return NULL;

	loc = TAILQ_FIRST(&v->locations);
	while ((loc = TAILQ_NEXT(loc, locations)) != NULL) {
		if (loc->reqca != NULL) {
			if (matches(loc->match, path))
				return loc->reqca;
		}
	}

	loc = TAILQ_FIRST(&v->locations);
	return loc->reqca;
}

int
vhost_disable_log(struct vhost *v, const char *path)
{
	struct location *loc;

	if (v == NULL || path == NULL)
		return 0;

	loc = TAILQ_FIRST(&v->locations);
	while ((loc = TAILQ_NEXT(loc, locations)) != NULL) {
		if (loc->disable_log && matches(loc->match, path))
				return 1;
	}

	loc = TAILQ_FIRST(&v->locations);
	return loc->disable_log;
}

void
mark_nonblock(int fd)
{
	int flags;

	if ((flags = fcntl(fd, F_GETFL)) == -1)
		fatal("fcntl(F_GETFL)");
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
		fatal("fcntl(F_SETFL)");
}

static void
handle_handshake(int fd, short ev, void *d)
{
	struct client *c = d;
	struct conf *conf = c->conf;
	struct vhost *h;
	const char *servname;
	const char *parse_err = "unknown error";

	switch (tls_handshake(c->ctx)) {
	case 0:  /* success */
		break;
	case -1:
		log_warnx("(%s:%s) tls_handshake failed: %s",
		    c->rhost, c->rserv, tls_error(c->ctx));
		client_close(c);
		return;
	case TLS_WANT_POLLIN:
		event_once(c->fd, EV_READ, handle_handshake, c, NULL);
		return;
	case TLS_WANT_POLLOUT:
		event_once(c->fd, EV_WRITE, handle_handshake, c, NULL);
		return;
	default:
		/* unreachable */
		fatalx("unexpected return value from tls_handshake");
	}

	c->bev = bufferevent_new(fd, client_read, client_write,
	    client_error, c);
	if (c->bev == NULL)
		fatal("%s: failed to allocate client buffer", __func__);

	event_set(&c->bev->ev_read, c->fd, EV_READ,
	    client_tls_readcb, c->bev);
	event_set(&c->bev->ev_write, c->fd, EV_WRITE,
	    client_tls_writecb, c->bev);

#if HAVE_LIBEVENT2
	evbuffer_unfreeze(c->bev->input, 0);
	evbuffer_unfreeze(c->bev->output, 1);
#endif

	if ((servname = tls_conn_servername(c->ctx)) == NULL)
		log_debug("handshake: missing SNI");
	if (!puny_decode(servname, c->domain, sizeof(c->domain), &parse_err)) {
		log_info("puny_decode: %s", parse_err);
		start_reply(c, BAD_REQUEST, "Wrong/malformed host");
		return;
	}

	/*
	 * match_addr will serialize the (matching) address if c->domain
	 * is empty, so that we can support requests for raw IPv6 address
	 * that can't have a SNI.
	 */
	TAILQ_FOREACH(h, &conf->hosts, vhosts)
		if (match_host(h, c))
			break;

	log_debug("handshake: SNI: \"%s\"; decoded: \"%s\"; matched: \"%s\"",
	    servname != NULL ? servname : "(null)",
	    c->domain,
	    h != NULL ? h->domain : "(null)");

	if (h != NULL) {
		c->host = h;
		bufferevent_enable(c->bev, EV_READ);
		return;
	}

	start_reply(c, BAD_REQUEST, "Wrong/malformed host");
}

static void
fmtbuf(char *buf, size_t buflen, const char *fmt, struct client *c,
    const char *path)
{
	size_t i;
	char tmp[32];

	*buf = '\0';
	memset(tmp, 0, sizeof(tmp));
	for (i = 0; *fmt; ++fmt) {
		if (i == sizeof(tmp)-1 || *fmt == '%') {
			strlcat(buf, tmp, buflen);
			memset(tmp, 0, sizeof(tmp));
			i = 0;
		}

		if (*fmt != '%') {
			tmp[i++] = *fmt;
			continue;
		}

		switch (*++fmt) {
		case '%':
			strlcat(buf, "%", buflen);
			break;
		case 'p':
			if (*path != '/')
				strlcat(buf, "/", buflen);
			strlcat(buf, path, buflen);
			break;
		case 'q':
			strlcat(buf, c->iri.query, buflen);
			break;
		case 'P':
			snprintf(tmp, sizeof(tmp), "%d", c->addr->port);
			strlcat(buf, tmp, buflen);
			memset(tmp, 0, sizeof(tmp));
			break;
		case 'N':
			strlcat(buf, c->domain, buflen);
			break;
		default:
			log_warnx("%s: unknown fmt specifier %c",
			    __func__, *fmt);
		}
	}

	if (i != 0)
		strlcat(buf, tmp, buflen);
}

/* 1 if a matching `block return' (and apply it), 0 otherwise */
static int
apply_block_return(struct client *c)
{
	char buf[GEMINI_URL_LEN];
	const char *fmt, *path;
	int code;

	if (!vhost_block_return(c->host, c->iri.path, &code, &fmt))
		return 0;

	path = strip_path(c->iri.path, vhost_strip(c->host, c->iri.path));
	fmtbuf(buf, sizeof(buf), fmt, c, path);

	start_reply(c, code, buf);
	return 1;
}

static struct proxy *
matched_proxy(struct client *c)
{
	struct proxy	*p;
	const char	*proto;
	const char	*host;
	const char	*port;

	TAILQ_FOREACH(p, &c->host->proxies, proxies) {
		if (*(proto = p->match_proto) == '\0')
			proto = "gemini";
		if (*(host = p->match_host) == '\0')
			host = "*";
		if (*(port = p->match_port) == '\0')
			port = "*";

		if (matches(proto, c->iri.schema) &&
		    matches(host, c->domain) &&
		    matches(port, c->iri.port))
			return p;
	}

	return NULL;
}

static int
check_matching_certificate(X509_STORE *store, struct client *c)
{
	const uint8_t	*cert;
	size_t		 len;

	if (!tls_peer_cert_provided(c->ctx)) {
		start_reply(c, CLIENT_CERT_REQ, "client certificate required");
		return 1;
	}

	cert = tls_peer_cert_chain_pem(c->ctx, &len);
	if (!validate_against_ca(store, cert, len)) {
		start_reply(c, CERT_NOT_AUTH, "certificate not authorised");
		return 1;
	}

	return 0;
}

static int
proxy_socket(struct client *c, const char *host, const char *port)
{
	struct addrinfo hints, *res, *res0;
	int r, sock, save_errno;
	const char *cause = NULL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	/* XXX: asr_run? :> */
	r = getaddrinfo(host, port, &hints, &res0);
	if (r != 0) {
		log_warnx("getaddrinfo(\"%s\", \"%s\"): %s",
		    host, port, gai_strerror(r));
		return -1;
	}

	for (res = res0; res; res = res->ai_next) {
		sock = socket(res->ai_family, res->ai_socktype,
		    res->ai_protocol);
		if (sock == -1) {
			cause = "socket";
			continue;
		}

		if (connect(sock, res->ai_addr, res->ai_addrlen) == -1) {
			cause = "connect";
			save_errno = errno;
			close(sock);
			errno = save_errno;
			sock = -1;
			continue;
		}

		break;
	}

	if (sock == -1)
		log_warn("can't connect to %s:%s: %s", host, port, cause);

	freeaddrinfo(res0);

	return sock;
}

/* 1 if matching a proxy relay-to (and apply it), 0 otherwise */
static int
apply_reverse_proxy(struct client *c)
{
	struct proxy	*p;

	if ((p = matched_proxy(c)) == NULL)
		return 0;

	c->proxy = p;

	if (p->reqca != NULL && check_matching_certificate(p->reqca, c))
		return 1;

	log_debug("opening proxy connection for %s:%s", p->host, p->port);

	if ((c->pfd = proxy_socket(c, p->host, p->port)) == -1) {
		start_reply(c, PROXY_ERROR, "proxy error");
		return 1;
	}

	mark_nonblock(c->pfd);
	if (proxy_init(c) == -1)
		start_reply(c, PROXY_ERROR, "proxy error");

	return 1;
}

static int
fcgi_open_sock(struct fcgi *f)
{
	struct sockaddr_un	addr;
	int			fd;

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		log_warn("socket");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, f->path, sizeof(addr.sun_path));

	if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
		log_warn("failed to connect to %s", f->path);
		close(fd);
		return -1;
	}

	return fd;
}

static int
fcgi_open_conn(struct fcgi *f)
{
	struct addrinfo	 hints, *servinfo, *p;
	int		 r, sock, save_errno;
	const char	*cause = NULL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_ADDRCONFIG;

	if ((r = getaddrinfo(f->path, f->port, &hints, &servinfo)) != 0) {
		log_warnx("getaddrinfo %s:%s: %s", f->path, f->port,
		    gai_strerror(r));
		return -1;
	}

	for (p = servinfo; p != NULL; p = p->ai_next) {
		sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (sock == -1) {
			cause = "socket";
			continue;
		}
		if (connect(sock, p->ai_addr, p->ai_addrlen) == -1) {
			cause = "connect";
			save_errno = errno;
			close(sock);
			errno = save_errno;
			continue;
		}
		break;
	}

	if (p == NULL) {
		log_warn("couldn't connect to %s:%s: %s", f->path, f->port,
		    cause);
		sock = -1;
	}

	freeaddrinfo(servinfo);
	return sock;
}

/* 1 if matching `fcgi' (and apply it), 0 otherwise */
static int
apply_fastcgi(struct client *c)
{
	int		 i = 0;
	struct fcgi	*f;
	struct location	*loc;

	if ((loc = vhost_fastcgi(c->host, c->iri.path)) == NULL)
		return 0;

	TAILQ_FOREACH(f, &c->conf->fcgi, fcgi) {
		if (i == loc->fcgi)
			break;
		++i;
	}

	if (f == NULL) {
		log_warnx("can't find fcgi #%d", loc->fcgi);
		return 0;
	}

	log_debug("opening fastcgi connection for (%s,%s)", f->path, f->port);

	if (*f->port == '\0')
		c->pfd = fcgi_open_sock(f);
	else
		c->pfd = fcgi_open_conn(f);

	if (c->pfd == -1) {
		start_reply(c, CGI_ERROR, "CGI error");
		return 1;
	}

	mark_nonblock(c->pfd);

	c->cgibev = bufferevent_new(c->pfd, fcgi_read, fcgi_write,
	    fcgi_error, c);
	if (c->cgibev == NULL) {
		start_reply(c, TEMP_FAILURE, "internal server error");
		return 1;
	}

	bufferevent_enable(c->cgibev, EV_READ|EV_WRITE);
	fcgi_req(c, loc);

	return 1;
}

/* 1 if matching `require client ca' fails (and apply it), 0 otherwise */
static int
apply_require_ca(struct client *c)
{
	X509_STORE	*store;

	if ((store = vhost_require_ca(c->host, c->iri.path)) == NULL)
		return 0;
	return check_matching_certificate(store, c);
}

static void
server_dir_listing(struct client *c)
{
	int root;

	root = !strcmp(c->iri.path, "/") || *c->iri.path == '\0';

	if (!vhost_auto_index(c->host, c->iri.path)) {
		start_reply(c, NOT_FOUND, "not found");
		return;
	}

	c->dirlen = scandir_fd(c->pfd, &c->dir,
	    root ? select_non_dotdot : select_non_dot,
	    alphasort);
	if (c->dirlen == -1) {
		log_warn("scandir_fd(%d) (vhost:%s) %s",
		    c->pfd, c->host->domain, c->iri.path);
		start_reply(c, TEMP_FAILURE, "internal server error");
		return;
	}

	c->type = REQUEST_DIR;
	start_reply(c, SUCCESS, "text/gemini");
	evbuffer_add_printf(EVBUFFER_OUTPUT(c->bev),
	    "# Index of /%s\n\n", c->iri.path);
}

static void
open_dir(struct client *c)
{
	struct stat sb;
	const char *index;
	char path[PATH_MAX];
	int fd = -1;

	if (*c->iri.path != '\0' && !ends_with(c->iri.path, "/")) {
		redirect_canonical_dir(c);
		return;
	}

	index = vhost_index(c->host, c->iri.path);
	fd = openat(c->pfd, index, O_RDONLY);
	if (fd == -1) {
		server_dir_listing(c);
		return;
	}

	if (fstat(fd, &sb) == -1) {
		log_warn("fstat");
		close(fd);
		start_reply(c, TEMP_FAILURE, "internal server error");
		return;
	}

	if (!S_ISREG(sb.st_mode)) {
		close(fd);
		server_dir_listing(c);
		return;
	}

	snprintf(path, sizeof(path), "%s%s", c->iri.path, index);

	close(c->pfd);
	c->pfd = fd;
	c->type = REQUEST_FILE;
	start_reply(c, SUCCESS, mime(c->conf, c->host, path));
}

static void
redirect_canonical_dir(struct client *c)
{
	char buf[GEMINI_URL_LEN];
	int r;

	r = snprintf(buf, sizeof(buf), "/%s/", c->iri.path);
	if (r < 0 || (size_t)r >= sizeof(buf)) {
		start_reply(c, TEMP_FAILURE, "internal server error");
		return;
	}

	start_reply(c, TEMP_REDIRECT, buf);
}

static void
client_tls_readcb(int fd, short event, void *d)
{
	struct bufferevent	*bufev = d;
	struct client		*client = bufev->cbarg;
	ssize_t			 ret;
	size_t			 len;
	int			 what = EVBUFFER_READ;
	int			 howmuch = IBUF_READ_SIZE;
	char			 buf[IBUF_READ_SIZE];

	if (event == EV_TIMEOUT) {
		what |= EVBUFFER_TIMEOUT;
		goto err;
	}

	if (bufev->wm_read.high != 0)
		howmuch = MINIMUM(sizeof(buf), bufev->wm_read.high);

	switch (ret = tls_read(client->ctx, buf, howmuch)) {
	case TLS_WANT_POLLIN:
	case TLS_WANT_POLLOUT:
		goto retry;
	case -1:
		what |= EVBUFFER_ERROR;
		goto err;
	}
	len = ret;

	if (len == 0) {
		what |= EVBUFFER_EOF;
		goto err;
	}

	if (evbuffer_add(bufev->input, buf, len) == -1) {
		what |= EVBUFFER_ERROR;
		goto err;
	}

	event_add(&bufev->ev_read, NULL);
	if (bufev->wm_read.low != 0 && len < bufev->wm_read.low)
		return;
	if (bufev->wm_read.high != 0 && len > bufev->wm_read.high) {
		/*
		 * here we could implement a read pressure policy.
		 */
	}

	if (bufev->readcb != NULL)
		(*bufev->readcb)(bufev, bufev->cbarg);

	return;

retry:
	event_add(&bufev->ev_read, NULL);
	return;

err:
	(*bufev->errorcb)(bufev, what, bufev->cbarg);
}

static void
client_tls_writecb(int fd, short event, void *d)
{
	struct bufferevent	*bufev = d;
	struct client		*client = bufev->cbarg;
	ssize_t			 ret;
	size_t			 len;
	short			 what = EVBUFFER_WRITE;

	if (event == EV_TIMEOUT) {
		what |= EVBUFFER_TIMEOUT;
		goto err;
	}

	if (EVBUFFER_LENGTH(bufev->output) != 0) {
		ret = tls_write(client->ctx,
		    EVBUFFER_DATA(bufev->output),
		    EVBUFFER_LENGTH(bufev->output));
		switch (ret) {
		case TLS_WANT_POLLIN:
		case TLS_WANT_POLLOUT:
			goto retry;
		case -1:
			what |= EVBUFFER_ERROR;
			goto err;
		}
		len = ret;
		evbuffer_drain(bufev->output, len);
	}

	if (EVBUFFER_LENGTH(bufev->output) != 0)
		event_add(&bufev->ev_write, NULL);

	if (bufev->writecb != NULL &&
	    EVBUFFER_LENGTH(bufev->output) <= bufev->wm_write.low)
		(*bufev->writecb)(bufev, bufev->cbarg);
	return;

retry:
	event_add(&bufev->ev_write, NULL);
	return;
err:
	log_warnx("tls error: %s", tls_error(client->ctx));
	(*bufev->errorcb)(bufev, what, bufev->cbarg);
}

static void
client_read(struct bufferevent *bev, void *d)
{
	struct stat	 sb;
	struct client	*c = d;
	struct evbuffer	*src = EVBUFFER_INPUT(bev);
	const char	*path, *p, *parse_err = "invalid request";
	char		 decoded[DOMAIN_NAME_LEN];
	char		*nul;
	size_t		 len;

	bufferevent_disable(bev, EVBUFFER_READ);

	/*
	 * libevent2 can still somehow call this function, even
	 * though I never enable EV_READ in the bufferevent.  If
	 * that's the case, bail out.
	 */
	if (c->type != REQUEST_UNDECIDED)
		return;

	/* max url len + \r\n */
	if (EVBUFFER_LENGTH(src) > 1024 + 2) {
		log_debug("too much data received");
		start_reply(c, BAD_REQUEST, "bad request");
		return;
	}

	c->req = evbuffer_readln(src, &c->reqlen, EVBUFFER_EOL_CRLF_STRICT);
	if (c->req == NULL) {
		/* not enough data yet. */
		bufferevent_enable(bev, EVBUFFER_READ);
		return;
	}
	if (c->reqlen > 1024+2) {
		log_debug("URL too long");
		start_reply(c, BAD_REQUEST, "bad request");
		return;
	}

	nul = strchr(c->req, '\0');
	len = nul - c->req;
	if (len != c->reqlen) {
		log_debug("NUL inside the request IRI");
		start_reply(c, BAD_REQUEST, "bad request");
		return;
	}

	if (!parse_iri(c->req, &c->iri, &parse_err) ||
	    !puny_decode(c->iri.host, decoded, sizeof(decoded), &parse_err)) {
		log_debug("IRI parse error: %s", parse_err);
		start_reply(c, BAD_REQUEST, "bad request");
		return;
	}

	if (apply_reverse_proxy(c))
		return;

	/* ignore the port number */
	if (strcmp(c->iri.schema, "gemini") ||
	    strcmp(decoded, c->domain)) {
		start_reply(c, PROXY_REFUSED, "won't proxy request");
		return;
	}

	if (apply_require_ca(c) ||
	    apply_block_return(c)||
	    apply_fastcgi(c))
		return;

	path = c->iri.path;
	p = strip_path(path, vhost_strip(c->host, path));
	while (*p == '/')
		p++;
	if (*p == '\0')
		p = ".";

	c->pfd = openat(vhost_dirfd(c->host, path, &c->loc), p, O_RDONLY);
	if (c->pfd == -1) {
		if (errno == EACCES)
			log_info("can't open %s: %s", p, strerror(errno));
		start_reply(c, NOT_FOUND, "not found");
		return;
	}

	if (fstat(c->pfd, &sb) == -1) {
		log_warnx("fstat %s", path);
		start_reply(c, TEMP_FAILURE, "internal server error");
		return;
	}

	if (S_ISDIR(sb.st_mode)) {
		open_dir(c);
		return;
	}

	c->type = REQUEST_FILE;
	start_reply(c, SUCCESS, mime(c->conf, c->host, p));
}

void
client_write(struct bufferevent *bev, void *d)
{
	struct client	*c = d;
	struct evbuffer	*out = EVBUFFER_OUTPUT(bev);
	char		 nam[PATH_MAX];
	char		 buf[BUFSIZ];
	ssize_t		 r;

	switch (c->type) {
	case REQUEST_UNDECIDED:
		/*
		 * Ignore spurious calls when we still don't have idea
		 * what to do with the request.
		 */
		break;

	case REQUEST_FILE:
		if ((r = read(c->pfd, buf, sizeof(buf))) == -1) {
			log_warn("read");
			client_error(bev, EVBUFFER_ERROR, c);
			return;
		} else if (r == 0) {
			client_close(c);
			return;
		} else if (r != sizeof(buf))
			c->type = REQUEST_DONE;
		bufferevent_write(bev, buf, r);
		break;

	case REQUEST_DIR:
		/* TODO: handle big big directories better */
		for (c->diroff = 0; c->diroff < c->dirlen; ++c->diroff) {
			const char *sufx = "";

			encode_path(nam, sizeof(nam),
			    c->dir[c->diroff]->d_name);
			if (c->dir[c->diroff]->d_type == DT_DIR)
				sufx = "/";
			evbuffer_add_printf(out, "=> ./%s%s\n", nam, sufx);
			free(c->dir[c->diroff]);
		}
		free(c->dir);
		c->dir = NULL;

		c->type = REQUEST_DONE;

		event_add(&c->bev->ev_write, NULL);
		break;

	case REQUEST_FCGI:
	case REQUEST_PROXY:
		/*
		 * Here we depend on fastcgi or proxy connection to
		 * provide data.
		 */
		break;

	case REQUEST_DONE:
		if (EVBUFFER_LENGTH(out) == 0)
			client_close(c);
		break;
	}
}

static void
client_error(struct bufferevent *bev, short error, void *d)
{
	struct client	*c = d;

	c->type = REQUEST_DONE;

	if (error & EVBUFFER_TIMEOUT) {
		log_debug("timeout; forcefully closing the connection");
		if (c->code == 0)
			start_reply(c, BAD_REQUEST, "timeout");
		else
			client_close(c);
		return;
	}

	if (error & EVBUFFER_EOF) {
		client_close(c);
		return;
	}

	log_warnx("unknown bufferevent error 0x%x", error);
	client_close(c);
}

int
start_reply(struct client *c, int code, const char *meta)
{
	struct evbuffer	*evb = EVBUFFER_OUTPUT(c->bev);
	const char	*lang;
	int		 r, rr;

	bufferevent_enable(c->bev, EVBUFFER_WRITE);

	c->code = code;
	c->meta = meta;

	r = evbuffer_add_printf(evb, "%d %s", code, meta);
	if (r == -1)
		goto err;

	/* 2 digit status + space + 1024 max reply */
	if (r > 1027)
		goto overflow;

	if (c->type != REQUEST_FCGI &&
	    c->type != REQUEST_PROXY &&
	    !strcmp(meta, "text/gemini") &&
	    (lang = vhost_lang(c->host, c->iri.path)) != NULL) {
		rr = evbuffer_add_printf(evb, ";lang=%s", lang);
		if (rr == -1)
			goto err;
		if (r + rr > 1027)
			goto overflow;
	}

	bufferevent_write(c->bev, "\r\n", 2);

	if (!vhost_disable_log(c->host, c->iri.path))
		log_request(c, code, meta);

	if (code != 20)
		c->type = REQUEST_DONE;

	return 0;

err:
	log_warnx("evbuffer_add_printf error: no memory");
	evbuffer_drain(evb, EVBUFFER_LENGTH(evb));
	c->type = REQUEST_DONE;
	return -1;

overflow:
	log_warnx("reply header overflow");
	evbuffer_drain(evb, EVBUFFER_LENGTH(evb));
	start_reply(c, TEMP_FAILURE, "internal error");
	return -1;
}

static void
client_close_ev(int fd, short event, void *d)
{
	struct client	*c = d;

	switch (tls_close(c->ctx)) {
	case TLS_WANT_POLLIN:
		event_once(c->fd, EV_READ, client_close_ev, c, NULL);
		return;
	case TLS_WANT_POLLOUT:
		event_once(c->fd, EV_WRITE, client_close_ev, c, NULL);
		return;
	}

	connected_clients--;

	free(c->req);

	tls_free(c->ctx);
	c->ctx = NULL;

	free(c->header);

	if (c->pfd != -1)
		close(c->pfd);

	if (c->dir != NULL)
		free(c->dir);

	close(c->fd);
	c->fd = -1;

	c->should_buffer = 0;

	free(c);
}

static void
client_proxy_close(int fd, short event, void *d)
{
	struct tls *ctx = d;

	if (ctx == NULL) {
		close(fd);
		return;
	}

	switch (tls_close(ctx)) {
	case TLS_WANT_POLLIN:
		event_once(fd, EV_READ, client_proxy_close, d, NULL);
		break;
	case TLS_WANT_POLLOUT:
		event_once(fd, EV_WRITE, client_proxy_close, d, NULL);
		break;
	}

	tls_free(ctx);
	close(fd);
}

void
client_close(struct client *c)
{
	/*
	 * We may end up calling client_close in various situations
	 * and for the most unexpected reasons.  Therefore, we need to
	 * ensure that everything gets properly released once we reach
	 * this point.
	 */

	SPLAY_REMOVE(client_tree_id, &clients, c);

	if (c->cgibev != NULL) {
		bufferevent_disable(c->cgibev, EVBUFFER_READ|EVBUFFER_WRITE);
		bufferevent_free(c->cgibev);
		c->cgibev = NULL;
		close(c->pfd);
		c->pfd = -1;
	}

	if (c->bev != NULL) {
		bufferevent_disable(c->bev, EVBUFFER_READ|EVBUFFER_WRITE);
		bufferevent_free(c->bev);
	}

	if (c->proxyevset &&
	    event_pending(&c->proxyev, EV_READ|EV_WRITE, NULL)) {
		c->proxyevset = 0;
		event_del(&c->proxyev);
	}

	if (c->pfd != -1 && c->proxyctx != NULL) {
		/* shut down the proxy TLS connection */
		client_proxy_close(c->pfd, 0, c->proxyctx);
		c->pfd = -1;
	}

	if (c->proxybev != NULL)
		bufferevent_free(c->proxybev);

	client_close_ev(c->fd, 0, c);
}

static ssize_t
read_cb(struct tls *ctx, void *buf, size_t buflen, void *cb_arg)
{
	struct client *c = cb_arg;

	if (!c->should_buffer) {
		// no buffer to cache into, read into libtls buffer
		ssize_t ret = read(c->fd, buf, buflen);
		if (-1 == ret && errno == EWOULDBLOCK)
			ret = TLS_WANT_POLLIN;
		
		return ret;
	}

	if (c->buf.has_tail) {
		// we have leftover data from a previous call to read_cb
		size_t left = BUFLAYER_MAX - c->buf.read_pos;
		size_t copy_len = MINIMUM(buflen, left);
		memcpy(buf, c->buf.data + c->buf.read_pos, copy_len);

		c->buf.read_pos += copy_len;

		if (left == copy_len) {
			// memset(buflayer, 0, BUFLAYER_MAX);
			c->should_buffer = 0;
			c->buf.has_tail = 0;
		}
		
		return copy_len;
	}

	// buffer layer exists, we expect proxy protocol
	errno = 0;
	ssize_t n_read = read(
		c->fd, 
		c->buf.data + c->buf.len, 
		BUFLAYER_MAX - c->buf.len
	);
	if (-1 == n_read && errno == EWOULDBLOCK)
		return TLS_WANT_POLLIN;

	c->buf.len += n_read;

	struct proxy_protocol_v1 pp1 = {0};
	size_t consumed = 0;
	
	int parse_status = proxy_proto_v1_parse(&pp1, c->buf.data, c->buf.len, &consumed);
	if (PROXY_PROTO_PARSE_SUCCESS != parse_status) {
		close(c->fd);
		return 0;
	}

	switch (pp1.proto) {
		case PROTO_V4: inet_ntop(AF_INET, &pp1.srcaddr.v4, c->rhost, NI_MAXHOST); break;
		case PROTO_V6: inet_ntop(AF_INET6, &pp1.srcaddr.v6, c->rhost, NI_MAXHOST); break;
		case PROTO_UNKNOWN: strncpy(c->rhost, "UNKNOWN", NI_MAXHOST); break;
	}

	if (PROTO_UNKNOWN != pp1.proto) {
		snprintf(c->rserv, NI_MAXSERV, "%u", pp1.srcport);
	}

	char protostr[1024];
	proxy_proto_v1_string(&pp1, protostr, 1024);
	log_debug("proxy-protocol v1: %s", protostr);

	if (consumed < c->buf.len) {
		// we have some leftover
		c->buf.read_pos = consumed;
		c->buf.has_tail = 1;
	} else {
		// we consumed the whole buffer
		c->should_buffer = c->buf.read_pos = 0;
		c->buf.has_tail = 0;
	}
	
	return TLS_WANT_POLLIN;
}

static ssize_t write_cb(struct tls *ctx, const void *buf, size_t buflen, void *cb_arg)
{
	struct client *c = cb_arg;
	
	ssize_t ret = write(c->fd, buf, buflen);
	if (-1 == ret && EAGAIN == errno)
		return TLS_WANT_POLLOUT;

	return ret;
}

void
server_accept(int sock, short et, void *d)
{
	struct address *addr = d;
	struct client *c;
	struct sockaddr_storage raddr;
	struct sockaddr *sraddr;
	socklen_t len;
	int e, fd;

	sraddr = (struct sockaddr *)&raddr;
	len = sizeof(raddr);
	if ((fd = accept(sock, sraddr, &len)) == -1) {
		if (errno == EWOULDBLOCK || errno == EAGAIN ||
		    errno == ECONNABORTED)
			return;
		log_warnx("accept failed");
		return;
	}

	mark_nonblock(fd);

	c = xcalloc(1, sizeof(*c));
	c->conf = addr->conf;
	c->addr = addr;
	c->id = ++server_client_id;
	c->fd = fd;
	c->pfd = -1;
	memcpy(&c->raddr, &raddr, sizeof(raddr));
	c->raddrlen = len;

	e = getnameinfo(sraddr, len, c->rhost, sizeof(c->rhost),
	    c->rserv, sizeof(c->rserv), NI_NUMERICHOST | NI_NUMERICSERV);
	if (e != 0) {
		log_warnx("getnameinfo failed: %s", gai_strerror(e));
		close(c->fd);
		free(c);
		return;
	}

	c->should_buffer = 1; // TODO set if config has proto-v1 enabled
	c->buf.read_pos = 0;

	if (tls_accept_cbs(addr->ctx, &c->ctx, read_cb, write_cb, c) == -1) {
		log_warnx("failed to accept socket: %s", tls_error(c->ctx));
		close(c->fd);
		free(c);
		return;
	}

	SPLAY_INSERT(client_tree_id, &clients, c);
	event_once(c->fd, EV_READ|EV_WRITE, handle_handshake, c, NULL);
	connected_clients++;
}

static void
handle_siginfo(int fd, short ev, void *d)
{
	log_info("%d connected clients", connected_clients);
}

static void
add_matching_kps(struct tls_config *tlsconf, struct address *addr,
    struct conf *conf)
{
	struct address	*vaddr;
	struct vhost	*h;
	int		 r, any = 0;

	TAILQ_FOREACH(h, &conf->hosts, vhosts) {
		TAILQ_FOREACH(vaddr, &h->addrs, addrs) {
			if (!match_addr(addr, vaddr))
				continue;

			if (!any) {
				any = 1;
				r = tls_config_set_keypair_ocsp_mem(tlsconf,
				    h->cert, h->certlen, h->key, h->keylen,
				    h->ocsp, h->ocsplen);
			} else {
				r = tls_config_add_keypair_ocsp_mem(tlsconf,
				    h->cert, h->certlen, h->key, h->keylen,
				    h->ocsp, h->ocsplen);
			}

			if (r == -1)
				fatalx("failed to load keypair"
				    " for host %s: %s", h->domain,
				    tls_config_error(tlsconf));
		}
	}
}

static void
setup_tls(struct conf *conf)
{
	struct tls_config	*tlsconf;
	struct address		*addr;

	TAILQ_FOREACH(addr, &conf->addrs, addrs) {
		if ((tlsconf = tls_config_new()) == NULL)
			fatal("tls_config_new");

		if (conf->use_privsep_crypto)
			tls_config_use_fake_private_key(tlsconf);

		/* optionally accept client certs but don't verify */
		tls_config_verify_client_optional(tlsconf);
		tls_config_insecure_noverifycert(tlsconf);

		if (tls_config_set_protocols(tlsconf, conf->protos) == -1)
			fatalx("tls_config_set_protocols: %s",
			    tls_config_error(tlsconf));

		add_matching_kps(tlsconf, addr, conf);

		tls_reset(addr->ctx);
		if (tls_configure(addr->ctx, tlsconf) == -1)
			fatalx("tls_configure: %s", tls_error(addr->ctx));

		tls_config_free(tlsconf);
	}
}

static void
load_vhosts(struct conf *conf)
{
	struct vhost	*h;
	struct location	*l;
	char		 path[PATH_MAX], *p;
	int		 r;

	TAILQ_FOREACH(h, &conf->hosts, vhosts) {
		TAILQ_FOREACH(l, &h->locations, locations) {
			if (*l->dir == '\0')
				continue;

			p = l->dir;

			if (conf->conftest && *conf->chroot != '\0') {
				r = snprintf(path, sizeof(path), "%s/%s",
				    conf->chroot, l->dir);
				if (r < 0 || (size_t)r >= sizeof(path))
					fatalx("path too long: %s", l->dir);
				p = path;
			}

			l->dirfd = open(p, O_RDONLY | O_DIRECTORY);
			if (l->dirfd == -1)
				fatal("open %s for domain %s", l->dir,
				    h->domain);
		}
	}
}

void
server(struct privsep *ps, struct privsep_proc *p)
{
	proc_run(ps, p, procs, nitems(procs), server_init, NULL);
}

void
server_init(struct privsep *ps, struct privsep_proc *p, void *arg)
{
	struct conf *c;

	SPLAY_INIT(&clients);

#ifdef SIGINFO
	signal_set(&siginfo, SIGINFO, &handle_siginfo, NULL);
	signal_add(&siginfo, NULL);
#endif
	signal_set(&sigusr2, SIGUSR2, &handle_siginfo, NULL);
	signal_add(&sigusr2, NULL);

	sandbox_server_process();

	/*
	 * gemexp doesn't use the privsep crypto engine; it doesn't
	 * use privsep at all so `ps' is NULL.
	 */
	if (ps != NULL) {
		c = ps->ps_env;
		if (c->use_privsep_crypto)
			crypto_engine_init(ps->ps_env);
	}
}

int
server_configure_done(struct conf *conf)
{
	struct address *addr;

	if (load_default_mime(&conf->mime) == -1)
		fatal("can't load default mime");
	sort_mime(&conf->mime);
	setup_tls(conf);
	load_vhosts(conf);

	TAILQ_FOREACH(addr, &conf->addrs, addrs) {
		if (addr->sock != -1)
			event_add(&addr->evsock, NULL);
	}

	return 0;
}

static int
server_dispatch_parent(int fd, struct privsep_proc *p, struct imsg *imsg)
{
	struct privsep	*ps = p->p_ps;
	struct conf	*conf = ps->ps_env;

	switch (imsg_get_type(imsg)) {
	case IMSG_RECONF_START:
	case IMSG_RECONF_LOG_FMT:
	case IMSG_RECONF_MIME:
	case IMSG_RECONF_PROTOS:
	case IMSG_RECONF_SOCK:
	case IMSG_RECONF_FCGI:
	case IMSG_RECONF_HOST:
	case IMSG_RECONF_CERT:
	case IMSG_RECONF_KEY:
	case IMSG_RECONF_OCSP:
	case IMSG_RECONF_HOST_ADDR:
	case IMSG_RECONF_LOC:
	case IMSG_RECONF_ENV:
	case IMSG_RECONF_ALIAS:
	case IMSG_RECONF_PROXY:
	case IMSG_RECONF_PROXY_CERT:
	case IMSG_RECONF_PROXY_KEY:
		return config_recv(conf, imsg);
	case IMSG_RECONF_END:
		if (config_recv(conf, imsg) == -1)
			return -1;
		if (server_configure_done(conf) == -1)
			return -1;
		break;
	default:
		return -1;
	}

	return 0;
}

static int
server_dispatch_crypto(int fd, struct privsep_proc *p, struct imsg *imsg)
{
	return -1;
}

static int
server_dispatch_logger(int fd, struct privsep_proc *p, struct imsg *imsg)
{
	return -1;
}

int
client_tree_cmp(struct client *a, struct client *b)
{
	if (a->id == b->id)
		return 0;
	else if (a->id < b->id)
		return -1;
	else
		return +1;
}

SPLAY_GENERATE(client_tree_id, client, entry, client_tree_cmp)
