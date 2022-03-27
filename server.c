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

#include <sys/stat.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <limits.h>
#include <string.h>

#define MIN(a, b)	((a) < (b) ? (a) : (b))

int shutting_down;

static struct tls	*ctx;

static struct event e4, e6, imsgev, siginfo, sigusr2;
static int has_ipv6, has_siginfo;

int connected_clients;

static inline int matches(const char*, const char*);

static int	 check_path(struct client*, const char*, int*);
static void	 open_file(struct client*);
static void	 check_for_cgi(struct client*);
static void	 handle_handshake(int, short, void*);
static const char *strip_path(const char*, int);
static void	 fmt_sbuf(const char*, struct client*, const char*);
static int	 apply_block_return(struct client*);
static int	 check_matching_certificate(X509_STORE *, struct client *);
static int	 apply_reverse_proxy(struct client *);
static int	 apply_fastcgi(struct client*);
static int	 apply_require_ca(struct client*);
static size_t	 host_nth(struct vhost*);
static void	 start_cgi(const char*, const char*, struct client*);
static void	 open_dir(struct client*);
static void	 redirect_canonical_dir(struct client*);

static void	 client_tls_readcb(int, short, void *);
static void	 client_tls_writecb(int, short, void *);

static void	 client_read(struct bufferevent *, void *);
void		 client_write(struct bufferevent *, void *);
static void	 client_error(struct bufferevent *, short, void *);

static void	 client_close_ev(int, short, void *);

static void	 cgi_read(struct bufferevent *, void *);
static void	 cgi_write(struct bufferevent *, void *);
static void	 cgi_error(struct bufferevent *, short, void *);

static void	 do_accept(int, short, void*);

static void	 handle_imsg_cgi_res(struct imsgbuf*, struct imsg*, size_t);
static void	 handle_imsg_fcgi_fd(struct imsgbuf*, struct imsg*, size_t);
static void	 handle_imsg_conn_fd(struct imsgbuf*, struct imsg*, size_t);
static void	 handle_imsg_quit(struct imsgbuf*, struct imsg*, size_t);
static void	 handle_dispatch_imsg(int, short, void *);
static void	 handle_siginfo(int, short, void*);

static imsg_handlerfn *handlers[] = {
	[IMSG_QUIT] = handle_imsg_quit,
	[IMSG_CGI_RES] = handle_imsg_cgi_res,
	[IMSG_FCGI_FD] = handle_imsg_fcgi_fd,
	[IMSG_CONN_FD] = handle_imsg_conn_fd,
};

static uint32_t server_client_id;

struct client_tree_id clients;

static inline int
matches(const char *pattern, const char *path)
{
	if (*path == '/')
		path++;
	return !fnmatch(pattern, path, 0);
}

const char *
vhost_lang(struct vhost *v, const char *path)
{
	struct location *loc;

	if (v == NULL || path == NULL)
		return NULL;

	loc = TAILQ_FIRST(&v->locations);
	while ((loc = TAILQ_NEXT(loc, locations)) != NULL) {
		if (loc->lang != NULL) {
			if (matches(loc->match, path))
				return loc->lang;
		}
	}

	return TAILQ_FIRST(&v->locations)->lang;
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
		if (loc->default_mime != NULL) {
			if (matches(loc->match, path))
				return loc->default_mime;
		}
	}

	loc = TAILQ_FIRST(&v->locations);
	if (loc->default_mime != NULL)
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
		if (loc->index != NULL) {
			if (matches(loc->match, path))
				return loc->index;
		}
	}

	loc = TAILQ_FIRST(&v->locations);
	if (loc->index != NULL)
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

int
vhost_fastcgi(struct vhost *v, const char *path)
{
	struct location *loc;

	if (v == NULL || path == NULL)
		return -1;

	loc = TAILQ_FIRST(&v->locations);
	while ((loc = TAILQ_NEXT(loc, locations)) != NULL) {
		if (loc->fcgi != -1)
			if (matches(loc->match, path))
				return loc->fcgi;
	}

	loc = TAILQ_FIRST(&v->locations);
	return loc->fcgi;
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

static int
check_path(struct client *c, const char *path, int *fd)
{
	struct stat sb;
	const char *p;
	int dirfd, strip;

	assert(path != NULL);

	/*
	 * in send_dir we add an initial / (to be redirect-friendly),
	 * but here we want to skip it
	 */
	if (*path == '/')
		path++;

	strip = vhost_strip(c->host, path);
	p = strip_path(path, strip);

	if (*p == '/')
		p = p+1;
	if (*p == '\0')
		p = ".";

	dirfd = vhost_dirfd(c->host, path, &c->loc);
	log_debug(c, "check_path: strip=%d path=%s original=%s",
	    strip, p, path);
	if (*fd == -1 && (*fd = openat(dirfd, p, O_RDONLY)) == -1)
		return FILE_MISSING;

	if (fstat(*fd, &sb) == -1) {
		log_notice(c, "failed stat for %s: %s", path, strerror(errno));
		return FILE_MISSING;
	}

	if (S_ISDIR(sb.st_mode))
		return FILE_DIRECTORY;

	if (sb.st_mode & S_IXUSR)
		return FILE_EXECUTABLE;

	return FILE_EXISTS;
}

static void
open_file(struct client *c)
{
	switch (check_path(c, c->iri.path, &c->pfd)) {
	case FILE_EXECUTABLE:
		if (c->host->cgi != NULL && matches(c->host->cgi, c->iri.path)) {
			start_cgi(c->iri.path, "", c);
			return;
		}

		/* fallthrough */

	case FILE_EXISTS:
		c->type = REQUEST_FILE;
		start_reply(c, SUCCESS, mime(c->host, c->iri.path));
		return;

	case FILE_DIRECTORY:
		open_dir(c);
		return;

	case FILE_MISSING:
		if (c->host->cgi != NULL && matches(c->host->cgi, c->iri.path)) {
			check_for_cgi(c);
			return;
		}
		start_reply(c, NOT_FOUND, "not found");
		return;

	default:
		/* unreachable */
		abort();
	}
}

/*
 * the inverse of this algorithm, i.e. starting from the start of the
 * path + strlen(cgi), and checking if each component, should be
 * faster.  But it's tedious to write.  This does the opposite: starts
 * from the end and strip one component at a time, until either an
 * executable is found or we emptied the path.
 */
static void
check_for_cgi(struct client *c)
{
	char path[PATH_MAX];
	char *end;

	strlcpy(path, c->iri.path, sizeof(path));
	end = strchr(path, '\0');

	while (end > path) {
		/*
		 * go up one level.  UNIX paths are simple and POSIX
		 * dirname, with its ambiguities on if the given
		 * pointer is changed or not, gives me headaches.
		 */
		while (*end != '/' && end > path)
			end--;

		if (end == path)
			break;

		*end = '\0';

		switch (check_path(c, path, &c->pfd)) {
		case FILE_EXECUTABLE:
			start_cgi(path, end+1, c);
			return;
		case FILE_MISSING:
			break;
		default:
			goto err;
		}

		*end = '/';
		end--;
	}

err:
	start_reply(c, NOT_FOUND, "not found");
	return;
}

void
mark_nonblock(int fd)
{
	int flags;

	if ((flags = fcntl(fd, F_GETFL)) == -1)
		fatal("fcntl(F_GETFL): %s", strerror(errno));
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
		fatal("fcntl(F_SETFL): %s", strerror(errno));
}

static void
handle_handshake(int fd, short ev, void *d)
{
	struct client *c = d;
	struct vhost *h;
	struct alist *a;
	const char *servname;
	const char *parse_err = "unknown error";

	switch (tls_handshake(c->ctx)) {
	case 0:  /* success */
	case -1: /* already handshaked */
		break;
	case TLS_WANT_POLLIN:
		event_once(c->fd, EV_READ, handle_handshake, c, NULL);
		return;
	case TLS_WANT_POLLOUT:
		event_once(c->fd, EV_WRITE, handle_handshake, c, NULL);
		return;
	default:
		/* unreachable */
		abort();
	}

	c->bev = bufferevent_new(fd, client_read, client_write,
	    client_error, c);
	if (c->bev == NULL)
		fatal("%s: failed to allocate client buffer: %s",
		    __func__, strerror(errno));

	event_set(&c->bev->ev_read, c->fd, EV_READ,
	    client_tls_readcb, c->bev);
	event_set(&c->bev->ev_write, c->fd, EV_WRITE,
	    client_tls_writecb, c->bev);

#if HAVE_LIBEVENT2
	evbuffer_unfreeze(c->bev->input, 0);
	evbuffer_unfreeze(c->bev->output, 1);
#endif

	if ((servname = tls_conn_servername(c->ctx)) == NULL) {
		log_debug(c, "handshake: missing SNI");
		goto err;
	}

	if (!puny_decode(servname, c->domain, sizeof(c->domain), &parse_err)) {
		log_info(c, "puny_decode: %s", parse_err);
		goto err;
	}

	TAILQ_FOREACH(h, &hosts, vhosts) {
		if (matches(h->domain, c->domain))
			goto found;
		TAILQ_FOREACH(a, &h->aliases, aliases) {
			if (matches(a->alias, c->domain))
				goto found;
		}
	}

found:
	log_debug(c, "handshake: SNI: \"%s\"; decoded: \"%s\"; matched: \"%s\"",
	    servname != NULL ? servname : "(null)",
	    c->domain,
	    h != NULL ? h->domain : "(null)");

	if (h != NULL) {
		c->host = h;
		bufferevent_enable(c->bev, EV_READ);
		return;
	}

err:
	start_reply(c, BAD_REQUEST, "Wrong/malformed host or missing SNI");
}

static const char *
strip_path(const char *path, int strip)
{
	char *t;

	while (strip > 0) {
		if ((t = strchr(path, '/')) == NULL) {
			path = strchr(path, '\0');
			break;
		}
		path = t;
		strip--;
	}

	return path;
}

static void
fmt_sbuf(const char *fmt, struct client *c, const char *path)
{
	size_t i;
	char buf[32];

	memset(buf, 0, sizeof(buf));
	for (i = 0; *fmt; ++fmt) {
		if (i == sizeof(buf)-1 || *fmt == '%') {
			strlcat(c->sbuf, buf, sizeof(c->sbuf));
			memset(buf, 0, sizeof(buf));
			i = 0;
		}

		if (*fmt != '%') {
			buf[i++] = *fmt;
			continue;
		}

		switch (*++fmt) {
		case '%':
			strlcat(c->sbuf, "%", sizeof(c->sbuf));
			break;
		case 'p':
			if (*path != '/')
				strlcat(c->sbuf, "/", sizeof(c->sbuf));
			strlcat(c->sbuf, path, sizeof(c->sbuf));
			break;
		case 'q':
			strlcat(c->sbuf, c->iri.query, sizeof(c->sbuf));
			break;
		case 'P':
			snprintf(buf, sizeof(buf), "%d", conf.port);
			strlcat(c->sbuf, buf, sizeof(c->sbuf));
			memset(buf, 0, sizeof(buf));
			break;
		case 'N':
			strlcat(c->sbuf, c->domain, sizeof(c->sbuf));
			break;
		default:
			fatal("%s: unknown fmt specifier %c",
			    __func__, *fmt);
		}
	}

	if (i != 0)
		strlcat(c->sbuf, buf, sizeof(c->sbuf));
}

/* 1 if a matching `block return' (and apply it), 0 otherwise */
static int
apply_block_return(struct client *c)
{
	const char *fmt, *path;
	int code;

	if (!vhost_block_return(c->host, c->iri.path, &code, &fmt))
		return 0;

	path = strip_path(c->iri.path, vhost_strip(c->host, c->iri.path));
	fmt_sbuf(fmt, c, path);

	start_reply(c, code, c->sbuf);
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
		if ((proto = p->match_proto) == NULL)
			proto = "gemini";
		if ((host = p->match_host) == NULL)
			host = "*";
		if ((port = p->match_port) == NULL)
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

/* 1 if matching a proxy relay-to (and apply it), 0 otherwise */
static int
apply_reverse_proxy(struct client *c)
{
	struct proxy	*p;
	struct connreq	 r;

	if ((p = matched_proxy(c)) == NULL)
		return 0;

	c->proxy = p;

	if (p->reqca != NULL && check_matching_certificate(p->reqca, c))
		return 1;

	log_debug(c, "opening proxy connection for %s:%s",
	    p->host, p->port);

	strlcpy(r.host, p->host, sizeof(r.host));
	strlcpy(r.port, p->port, sizeof(r.port));

	imsg_compose(&exibuf, IMSG_CONN_REQ, c->id, 0, -1, &r, sizeof(r));
	imsg_flush(&exibuf);

	return 1;
}

/* 1 if matching `fcgi' (and apply it), 0 otherwise */
static int
apply_fastcgi(struct client *c)
{
	int		 id;
	struct fcgi	*f;

	if ((id = vhost_fastcgi(c->host, c->iri.path)) == -1)
		return 0;

	f = &fcgi[id];

	log_debug(c, "opening fastcgi connection for (%s,%s,%s)",
	    f->path, f->port, f->prog);

	imsg_compose(&exibuf, IMSG_FCGI_REQ, c->id, 0, -1,
	    &id, sizeof(id));
	imsg_flush(&exibuf);
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

static size_t
host_nth(struct vhost *h)
{
	struct vhost	*v;
	size_t		 i = 0;

	TAILQ_FOREACH(v, &hosts, vhosts) {
		if (v == h)
			return i;
		i++;
	}

	abort();
}

static void
start_cgi(const char *spath, const char *relpath, struct client *c)
{
	char addr[NI_MAXHOST];
	const char *t;
	struct cgireq req;
	int e;

	c->type = REQUEST_CGI;

	e = getnameinfo((struct sockaddr*)&c->addr, sizeof(c->addr),
	    addr, sizeof(addr),
	    NULL, 0,
	    NI_NUMERICHOST);
	if (e != 0)
		fatal("getnameinfo failed");

	memset(&req, 0, sizeof(req));

	memcpy(req.buf, c->req, c->reqlen);

	req.iri_schema_off = c->iri.schema - c->req;
	req.iri_host_off = c->iri.host - c->req;
	req.iri_port_off = c->iri.port - c->req;
	req.iri_path_off = c->iri.path - c->req;
	req.iri_query_off = c->iri.query - c->req;
	req.iri_fragment_off = c->iri.fragment - c->req;

	req.iri_portno = c->iri.port_no;

	strlcpy(req.spath, spath, sizeof(req.spath));
	strlcpy(req.relpath, relpath, sizeof(req.relpath));
	strlcpy(req.addr, addr, sizeof(req.addr));

	if ((t = tls_peer_cert_subject(c->ctx)) != NULL)
		strlcpy(req.subject, t, sizeof(req.subject));
	if ((t = tls_peer_cert_issuer(c->ctx)) != NULL)
		strlcpy(req.issuer, t, sizeof(req.issuer));
	if ((t = tls_peer_cert_hash(c->ctx)) != NULL)
		strlcpy(req.hash, t, sizeof(req.hash));
	if ((t = tls_conn_version(c->ctx)) != NULL)
		strlcpy(req.version, t, sizeof(req.version));
	if ((t = tls_conn_cipher(c->ctx)) != NULL)
		strlcpy(req.cipher, t, sizeof(req.cipher));

	req.cipher_strength = tls_conn_cipher_strength(c->ctx);
	req.notbefore = tls_peer_cert_notbefore(c->ctx);
	req.notafter = tls_peer_cert_notafter(c->ctx);

	req.host_off = host_nth(c->host);
	req.loc_off = c->loc;

	imsg_compose(&exibuf, IMSG_CGI_REQ, c->id, 0, -1, &req, sizeof(req));
	imsg_flush(&exibuf);

	close(c->pfd);
}

static void
open_dir(struct client *c)
{
	size_t len;
	int dirfd, root;
	char *before_file;

	root = !strcmp(c->iri.path, "/") || *c->iri.path == '\0';

	len = strlen(c->iri.path);
	if (len > 0 && !ends_with(c->iri.path, "/")) {
		redirect_canonical_dir(c);
		return;
	}

	strlcpy(c->sbuf, "/", sizeof(c->sbuf));
	strlcat(c->sbuf, c->iri.path, sizeof(c->sbuf));
	if (!ends_with(c->sbuf, "/"))
		strlcat(c->sbuf, "/", sizeof(c->sbuf));
	before_file = strchr(c->sbuf, '\0');
	len = strlcat(c->sbuf, vhost_index(c->host, c->iri.path),
	    sizeof(c->sbuf));
	if (len >= sizeof(c->sbuf)) {
		start_reply(c, TEMP_FAILURE, "internal server error");
		return;
	}

	c->iri.path = c->sbuf;

	/* close later unless we have to generate the dir listing */
	dirfd = c->pfd;
	c->pfd = -1;

	switch (check_path(c, c->iri.path, &c->pfd)) {
	case FILE_EXECUTABLE:
		if (c->host->cgi != NULL && matches(c->host->cgi, c->iri.path)) {
			start_cgi(c->iri.path, "", c);
			break;
		}

		/* fallthrough */

	case FILE_EXISTS:
		c->type = REQUEST_FILE;
		start_reply(c, SUCCESS, mime(c->host, c->iri.path));
		break;

	case FILE_DIRECTORY:
		start_reply(c, TEMP_REDIRECT, c->sbuf);
		break;

	case FILE_MISSING:
		*before_file = '\0';

		if (!vhost_auto_index(c->host, c->iri.path)) {
			start_reply(c, NOT_FOUND, "not found");
			break;
		}

		c->type = REQUEST_DIR;

		c->dirlen = scandir_fd(dirfd, &c->dir,
		    root ? select_non_dotdot : select_non_dot,
		    alphasort);
		if (c->dirlen == -1) {
			log_err(c, "scandir_fd(%d) (vhost:%s) %s: %s",
			    c->pfd, c->host->domain, c->iri.path, strerror(errno));
			start_reply(c, TEMP_FAILURE, "internal server error");
			return;
		}
		c->diroff = 0;
		c->off = 0;

		start_reply(c, SUCCESS, "text/gemini");
		evbuffer_add_printf(EVBUFFER_OUTPUT(c->bev),
		    "# Index of %s\n\n", c->iri.path);
		return;

	default:
		/* unreachable */
		abort();
	}

	close(dirfd);
}

static void
redirect_canonical_dir(struct client *c)
{
	size_t len;

	strlcpy(c->sbuf, "/", sizeof(c->sbuf));
	strlcat(c->sbuf, c->iri.path, sizeof(c->sbuf));
	len = strlcat(c->sbuf, "/", sizeof(c->sbuf));

	if (len >= sizeof(c->sbuf)) {
		start_reply(c, TEMP_FAILURE, "internal server error");
		return;
	}

	start_reply(c, TEMP_REDIRECT, c->sbuf);
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
		howmuch = MIN(sizeof(buf), bufev->wm_read.high);

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
	log_err(client, "tls error: %s", tls_error(client->ctx));
	(*bufev->errorcb)(bufev, what, bufev->cbarg);
}

static void
client_read(struct bufferevent *bev, void *d)
{
	struct client	*c = d;
	struct evbuffer	*src = EVBUFFER_INPUT(bev);
	const char	*parse_err = "invalid request";
	char		 decoded[DOMAIN_NAME_LEN];
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
		log_err(c, "too much data received");
		start_reply(c, BAD_REQUEST, "bad request");
		return;
	}

	c->req = evbuffer_readln(src, &len, EVBUFFER_EOL_CRLF_STRICT);
	if (c->req == NULL) {
		/* not enough data yet. */
		bufferevent_enable(bev, EVBUFFER_READ);
		return;
	}
	c->reqlen = strlen(c->req);
	if (c->reqlen > 1024+2) {
		log_err(c, "URL too long");
		start_reply(c, BAD_REQUEST, "bad request");
		return;
	}

	if (!parse_iri(c->req, &c->iri, &parse_err) ||
	    !puny_decode(c->iri.host, decoded, sizeof(decoded), &parse_err)) {
		log_err(c, "IRI parse error: %s", parse_err);
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

	if (c->host->entrypoint != NULL) {
		c->loc = 0;
		start_cgi(c->host->entrypoint, c->iri.path, c);
		return;
	}

	open_file(c);
}

void
client_write(struct bufferevent *bev, void *d)
{
	struct client	*c = d;
	struct evbuffer	*out = EVBUFFER_OUTPUT(bev);
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
			log_warn(c, "read: %s", strerror(errno));
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
			evbuffer_add_printf(out, "=> %s\n",
			    c->dir[c->diroff]->d_name);
			free(c->dir[c->diroff]);
		}
		free(c->dir);
		c->dir = NULL;

		c->type = REQUEST_DONE;

		event_add(&c->bev->ev_write, NULL);
		break;

	case REQUEST_CGI:
	case REQUEST_FCGI:
	case REQUEST_PROXY:
		/*
		 * Here we depend on the cgi/fastcgi or proxy
		 * connection to provide data.
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
		log_warn(c, "timeout reached, "
		    "forcefully closing the connection");
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

	log_err(c, "unknown bufferevent error %x", error);
	client_close(c);
}

void
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

	if (c->type != REQUEST_CGI &&
	    c->type != REQUEST_FCGI &&
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
		log_request(c, EVBUFFER_DATA(evb), EVBUFFER_LENGTH(evb));

	if (code != 20)
		c->type = REQUEST_DONE;

	return;

err:
	log_err(c, "evbuffer_add_printf error: no memory");
	evbuffer_drain(evb, EVBUFFER_LENGTH(evb));
	client_close(c);
	return;

overflow:
	log_warn(c, "reply header overflow");
	evbuffer_drain(evb, EVBUFFER_LENGTH(evb));
	start_reply(c, TEMP_FAILURE, "internal error");
}

static void
client_close_ev(int fd, short event, void *d)
{
	struct client	*c = d;

	switch (tls_close(c->ctx)) {
	case TLS_WANT_POLLIN:
		event_once(c->fd, EV_READ, client_close_ev, c, NULL);
		break;
	case TLS_WANT_POLLOUT:
		event_once(c->fd, EV_WRITE, client_close_ev, c, NULL);
		break;
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

	bufferevent_disable(c->bev, EVBUFFER_READ|EVBUFFER_WRITE);
	bufferevent_free(c->bev);
	c->bev = NULL;

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

static void
cgi_read(struct bufferevent *bev, void *d)
{
	struct client	*client = d;
	struct evbuffer	*src = EVBUFFER_INPUT(bev);
	char		*header;
	size_t		 len;
	int		 code;

	/* intercept the header */
	if (client->code == 0) {
		header = evbuffer_readln(src, &len, EVBUFFER_EOL_CRLF_STRICT);
		if (header == NULL) {
			/* max reply + \r\n */
			if (EVBUFFER_LENGTH(src) > 1029) {
				log_warn(client, "CGI script is trying to "
				    "send a header too long.");
				cgi_error(bev, EVBUFFER_READ, client);
			}

			/* wait a bit */
			return;
		}

		if (len < 3 || len > 1029 ||
		    !isdigit(header[0]) ||
		    !isdigit(header[1]) ||
		    !isspace(header[2])) {
			free(header);
			log_warn(client, "CGI script is trying to send a "
			    "malformed header");
			cgi_error(bev, EVBUFFER_READ, client);
			return;
		}

		client->header = header;
		code = (header[0] - '0') * 10 + (header[1] - '0');

		if (code < 10 || code >= 70) {
			log_warn(client, "CGI script is trying to send an "
			    "invalid reply code (%d)", code);
			cgi_error(bev, EVBUFFER_READ, client);
			return;
		}

		start_reply(client, code, header + 3);

		if (client->code < 20 || client->code > 29) {
			cgi_error(client->cgibev, EVBUFFER_EOF, client);
			return;
		}
	}

	bufferevent_write_buffer(client->bev, src);
}

static void
cgi_write(struct bufferevent *bev, void *d)
{
	/*
	 * Never called.  We don't send data to a CGI script.
	 */
	abort();
}

static void
cgi_error(struct bufferevent *bev, short error, void *d)
{
	struct client	*client = d;

	if (error & EVBUFFER_ERROR)
		log_err(client, "%s: evbuffer error (%x): %s",
		    __func__, error, strerror(errno));

	bufferevent_disable(bev, EVBUFFER_READ|EVBUFFER_WRITE);
	bufferevent_free(bev);
	client->cgibev = NULL;

	close(client->pfd);
	client->pfd = -1;

	client->type = REQUEST_DONE;
	if (client->code != 0)
		client_write(client->bev, client);
	else
		start_reply(client, CGI_ERROR, "CGI error");
}

static void
do_accept(int sock, short et, void *d)
{
	struct client *c;
	struct sockaddr_storage addr;
	struct sockaddr *saddr;
	socklen_t len;
	int fd;

	saddr = (struct sockaddr*)&addr;
	len = sizeof(addr);
	if ((fd = accept(sock, saddr, &len)) == -1) {
		if (errno == EWOULDBLOCK || errno == EAGAIN ||
		    errno == ECONNABORTED)
			return;
		fatal("accept: %s", strerror(errno));
	}

	mark_nonblock(fd);

	c = xcalloc(1, sizeof(*c));
	c->id = ++server_client_id;
	c->fd = fd;
	c->pfd = -1;
	c->addr = addr;

	if (tls_accept_socket(ctx, &c->ctx, fd) == -1) {
		log_warn(c, "failed to accept socket: %s", tls_error(c->ctx));
		close(c->fd);
		free(c);
		return;
	}

	SPLAY_INSERT(client_tree_id, &clients, c);
	event_once(c->fd, EV_READ|EV_WRITE, handle_handshake, c, NULL);
	connected_clients++;
}

struct client *
client_by_id(int id)
{
	struct client find;

	find.id = id;
	return SPLAY_FIND(client_tree_id, &clients, &find);
}

static void
handle_imsg_cgi_res(struct imsgbuf *ibuf, struct imsg *imsg, size_t len)
{
	struct client *c;

	if ((c = client_by_id(imsg->hdr.peerid)) == NULL) {
		if (imsg->fd != -1)
			close(imsg->fd);
		return;
	}

	if ((c->pfd = imsg->fd) == -1) {
		start_reply(c, TEMP_FAILURE, "internal server error");
		return;
	}

	c->type = REQUEST_CGI;

	c->cgibev = bufferevent_new(c->pfd, cgi_read, cgi_write,
	    cgi_error, c);

	bufferevent_enable(c->cgibev, EV_READ);
}

static void
handle_imsg_fcgi_fd(struct imsgbuf *ibuf, struct imsg *imsg, size_t len)
{
	struct client	*c;
	int		 id;

	id = imsg->hdr.peerid;

	if ((c = client_by_id(id)) == NULL) {
		if (imsg->fd != -1)
			close(imsg->fd);
		return;
	}

	if ((c->pfd = imsg->fd) == -1) {
		start_reply(c, CGI_ERROR, "CGI error");
		return;
	}

	mark_nonblock(c->pfd);

	c->cgibev = bufferevent_new(c->pfd, fcgi_read, fcgi_write,
	    fcgi_error, c);
	if (c->cgibev == NULL) {
		start_reply(c, TEMP_FAILURE, "internal server error");
		return;
	}

	bufferevent_enable(c->cgibev, EV_READ|EV_WRITE);
	fcgi_req(c);
}

static void
handle_imsg_conn_fd(struct imsgbuf *ibuf, struct imsg *imsg, size_t len)
{
	struct client	*c;
	int		 id;

	id = imsg->hdr.peerid;
	if ((c = client_by_id(id)) == NULL) {
		if (imsg->fd != -1)
			close(imsg->fd);
		return;
	}

	if ((c->pfd = imsg->fd) == -1) {
		start_reply(c, PROXY_ERROR, "proxy error");
		return;
	}

	mark_nonblock(c->pfd);

	if (proxy_init(c) == -1)
		start_reply(c, PROXY_ERROR, "proxy error");
}

static void
handle_imsg_quit(struct imsgbuf *ibuf, struct imsg *imsg, size_t len)
{
	/*
	 * don't call event_loopbreak since we want to finish to
	 * handle the ongoing connections.
	 */

	shutting_down = 1;

	event_del(&e4);
	if (has_ipv6)
		event_del(&e6);
	if (has_siginfo)
		signal_del(&siginfo);
	event_del(&imsgev);
	signal_del(&sigusr2);
}

static void
handle_dispatch_imsg(int fd, short ev, void *d)
{
	struct imsgbuf *ibuf = d;
	dispatch_imsg(ibuf, handlers, sizeof(handlers));
}

static void
handle_siginfo(int fd, short ev, void *d)
{
	log_info(NULL, "%d connected clients", connected_clients);
}

void
loop(struct tls *ctx_, int sock4, int sock6, struct imsgbuf *ibuf)
{
	ctx = ctx_;

	SPLAY_INIT(&clients);

	event_init();

	event_set(&e4, sock4, EV_READ | EV_PERSIST, &do_accept, NULL);
	event_add(&e4, NULL);

	if (sock6 != -1) {
		has_ipv6 = 1;
		event_set(&e6, sock6, EV_READ | EV_PERSIST, &do_accept, NULL);
		event_add(&e6, NULL);
	}

	event_set(&imsgev, ibuf->fd, EV_READ | EV_PERSIST, handle_dispatch_imsg, ibuf);
	event_add(&imsgev, NULL);

#ifdef SIGINFO
	has_siginfo = 1;
	signal_set(&siginfo, SIGINFO, &handle_siginfo, NULL);
	signal_add(&siginfo, NULL);
#endif
	signal_set(&sigusr2, SIGUSR2, &handle_siginfo, NULL);
	signal_add(&sigusr2, NULL);

	sandbox_server_process();
	event_dispatch();
	_exit(0);
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
