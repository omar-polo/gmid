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

#include <sys/mman.h>
#include <sys/stat.h>

#include <netdb.h>

#include <assert.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <limits.h>
#include <string.h>

#include "gmid.h"

struct server {
	struct client	 clients[MAX_USERS];
	struct tls	*ctx;
};

struct event e4, e6, sighup, siginfo, sigusr2;
int has_ipv6, has_siginfo;

int connected_clients;

static inline int matches(const char*, const char*);

static inline void reschedule_read(int, struct client*, statefn);
static inline void reschedule_write(int, struct client*, statefn);

static int	 check_path(struct client*, const char*, int*);
static void	 open_file(struct client*);
static void	 load_file(struct client*);
static void	 check_for_cgi(struct client*);
static void	 handle_handshake(int, short, void*);
static char	*strip_path(char*, int);
static void	 fmt_sbuf(const char*, struct client*, const char*);
static int	 apply_block_return(struct client*);
static int	 apply_require_ca(struct client*);
static void	 handle_open_conn(int, short, void*);
static void	 start_reply(struct client*, int, const char*);
static void	 handle_start_reply(int, short, void*);
static void	 start_cgi(const char*, const char*, struct client*);
static void	 send_file(int, short, void*);
static void	 open_dir(struct client*);
static void	 redirect_canonical_dir(struct client*);
static void	 enter_handle_dirlist(int, short, void*);
static void	 handle_dirlist(int, short, void*);
static int 	 read_next_dir_entry(struct client*);
static void	 send_directory_listing(int, short, void*);
static void	 handle_cgi_reply(int, short, void*);
static void	 handle_cgi(int, short, void*);
static void	 close_conn(int, short, void*);
static void	 do_accept(int, short, void*);
static void	 handle_sighup(int, short, void*);

static inline int
matches(const char *pattern, const char *path)
{
	if (*path == '/')
		path++;
	return !fnmatch(pattern, path, 0);
}

static inline void
reschedule_read(int fd, struct client *c, statefn fn)
{
	event_once(fd, EV_READ, fn, c, NULL);
}

void
reschedule_write(int fd, struct client *c, statefn fn)
{
	event_once(fd, EV_WRITE, fn, c, NULL);
}

const char *
vhost_lang(struct vhost *v, const char *path)
{
	struct location *loc;

	if (v == NULL || path == NULL)
		return NULL;

	for (loc = &v->locations[1]; loc->match != NULL; ++loc) {
		if (loc->lang != NULL) {
			if (matches(loc->match, path))
				return loc->lang;
		}
	}

	return v->locations[0].lang;
}

const char *
vhost_default_mime(struct vhost *v, const char *path)
{
	struct location *loc;
	const char *default_mime = "application/octet-stream";

	if (v == NULL || path == NULL)
		return default_mime;

	for (loc = &v->locations[1]; loc->match != NULL; ++loc) {
		if (loc->default_mime != NULL) {
			if (matches(loc->match, path))
				return loc->default_mime;
		}
	}

	if (v->locations[0].default_mime != NULL)
		return v->locations[0].default_mime;
	return default_mime;
}

const char *
vhost_index(struct vhost *v, const char *path)
{
	struct location *loc;
	const char *index = "index.gmi";

	if (v == NULL || path == NULL)
		return index;

	for (loc = &v->locations[1]; loc->match != NULL; ++loc) {
		if (loc->index != NULL) {
			if (matches(loc->match, path))
				return loc->index;
		}
	}

	if (v->locations[0].index != NULL)
		return v->locations[0].index;
	return index;
}

int
vhost_auto_index(struct vhost *v, const char *path)
{
	struct location *loc;

	if (v == NULL || path == NULL)
		return 0;

	for (loc = &v->locations[1]; loc->match != NULL; ++loc) {
		if (loc->auto_index != 0) {
			if (matches(loc->match, path))
				return loc->auto_index == 1;
		}
	}

	return v->locations[0].auto_index == 1;
}

int
vhost_block_return(struct vhost *v, const char *path, int *code, const char **fmt)
{
	struct location *loc;

	if (v == NULL || path == NULL)
		return 0;

	for (loc = &v->locations[1]; loc->match != NULL; ++loc) {
		if (loc->block_code != 0) {
			if (matches(loc->match, path)) {
				*code = loc->block_code;
				*fmt = loc->block_fmt;
				return 1;
			}
		}
	}

	*code = v->locations[0].block_code;
	*fmt = v->locations[0].block_fmt;
	return v->locations[0].block_code != 0;
}

int
vhost_strip(struct vhost *v, const char *path)
{
	struct location *loc;

	if (v == NULL || path == NULL)
		return 0;

	for (loc = &v->locations[1]; loc->match != NULL; ++loc) {
		if (loc->strip != 0) {
			if (matches(loc->match, path))
				return loc->strip;
		}
	}

	return v->locations[0].strip;
}

X509_STORE *
vhost_require_ca(struct vhost *v, const char *path)
{
	struct location *loc;

	if (v == NULL || path == NULL)
		return NULL;

	for (loc = &v->locations[1]; loc->match != NULL; ++loc) {
		if (loc->reqca != NULL) {
			if (matches(loc->match, path))
				return loc->reqca;
		}
	}

	return v->locations[0].reqca;
}

static int
check_path(struct client *c, const char *path, int *fd)
{
	struct stat sb;
	const char *p;
	int flags;

	assert(path != NULL);

	if (*path == '\0')
		p = ".";
	else if (*path == '/')
		/* in send_dir we add an initial / (to be
		 * redirect-friendly), but here we want to skip it */
		p = path+1;
	else
		p = path;

	flags = O_RDONLY | O_NOFOLLOW;

	if (*fd == -1 && (*fd = openat(c->host->dirfd, p, flags)) == -1)
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
		if (c->host->cgi != NULL && !fnmatch(c->host->cgi, c->iri.path, 0)) {
			start_cgi(c->iri.path, "", c);
			return;
		}

		/* fallthrough */

	case FILE_EXISTS:
		load_file(c);
		return;

	case FILE_DIRECTORY:
		open_dir(c);
		return;

	case FILE_MISSING:
		if (c->host->cgi != NULL && !fnmatch(c->host->cgi, c->iri.path, 0)) {
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

static void
load_file(struct client *c)
{
	if ((c->len = filesize(c->pfd)) == -1) {
		log_err(c, "failed to get file size for %s: %s",
		    c->iri.path, strerror(errno));
		start_reply(c, TEMP_FAILURE, "internal server error");
		return;
	}

	if ((c->buf = mmap(NULL, c->len, PROT_READ, MAP_PRIVATE,
		    c->pfd, 0)) == MAP_FAILED) {
		log_err(c, "mmap: %s: %s", c->iri.path, strerror(errno));
		start_reply(c, TEMP_FAILURE, "internal server error");
		return;
	}
	c->i = c->buf;
	c->next = send_file;
	start_reply(c, SUCCESS, mime(c->host, c->iri.path));
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
		/* go up one level.  UNIX paths are simple and POSIX
		 * dirname, with its ambiguities on if the given path
		 * is changed or not, gives me headaches. */
		while (*end != '/')
			end--;
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
	const char *servname;
	const char *parse_err = "unknown error";

	switch (tls_handshake(c->ctx)) {
	case 0:  /* success */
	case -1: /* already handshaked */
		break;
	case TLS_WANT_POLLIN:
		reschedule_read(fd, c, &handle_handshake);
		return;
	case TLS_WANT_POLLOUT:
		reschedule_write(fd, c, &handle_handshake);
		return;
	default:
		/* unreachable */
		abort();
	}

	servname = tls_conn_servername(c->ctx);
	if (!puny_decode(servname, c->domain, sizeof(c->domain), &parse_err)) {
		log_info(c, "puny_decode: %s", parse_err);
		goto err;
	}

	for (h = hosts; h->domain != NULL; ++h) {
		if (!fnmatch(h->domain, c->domain, 0))
			break;
	}

	log_debug(c, "handshake: SNI: \"%s\"; decoded: \"%s\"; matched: \"%s\"",
	    servname != NULL ? servname : "(null)",
	    c->domain,
	    h->domain != NULL ? h->domain : "(null)");

	if (h->domain != NULL) {
		c->host = h;
		handle_open_conn(fd, ev, c);
		return;
	}

err:
	if (servname != NULL)
		strncpy(c->req, servname, sizeof(c->req));
	else
		strncpy(c->req, "null", sizeof(c->req));

	start_reply(c, BAD_REQUEST, "Wrong/malformed host or missing SNI");
}

static char *
strip_path(char *path, int strip)
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

/* 1 if matching `require client ca' fails (and apply it), 0 otherwise */
static int
apply_require_ca(struct client *c)
{
	X509_STORE	*store;
	const uint8_t	*cert;
	size_t		 len;

	if ((store = vhost_require_ca(c->host, c->iri.path)) == NULL)
		return 0;

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

static void
handle_open_conn(int fd, short ev, void *d)
{
	struct client *c = d;
	const char *parse_err = "invalid request";
	char decoded[DOMAIN_NAME_LEN];

	bzero(c->req, sizeof(c->req));
	bzero(&c->iri, sizeof(c->iri));

	switch (tls_read(c->ctx, c->req, sizeof(c->req)-1)) {
	case -1:
		log_err(c, "tls_read: %s", tls_error(c->ctx));
		close_conn(fd, ev, c);
		return;

	case TLS_WANT_POLLIN:
		reschedule_read(fd, c, &handle_open_conn);
		return;

	case TLS_WANT_POLLOUT:
		reschedule_write(fd, c, &handle_open_conn);
		return;
	}

	if (!trim_req_iri(c->req, &parse_err)
	    || !parse_iri(c->req, &c->iri, &parse_err)
	    || !puny_decode(c->iri.host, decoded, sizeof(decoded), &parse_err)) {
		log_info(c, "iri parse error: %s", parse_err);
		start_reply(c, BAD_REQUEST, "invalid request");
		return;
	}

	if (c->iri.port_no != conf.port
	    || strcmp(c->iri.schema, "gemini")
	    || strcmp(decoded, c->domain)) {
		start_reply(c, PROXY_REFUSED, "won't proxy request");
		return;
	}

	if (apply_require_ca(c))
		return;

	if (apply_block_return(c))
		return;

	if (c->host->entrypoint != NULL) {
		start_cgi(c->host->entrypoint, c->iri.path, c);
		return;
	}

	open_file(c);
}

static void
start_reply(struct client *c, int code, const char *meta)
{
	c->code = code;
	c->meta = meta;
	handle_start_reply(c->fd, 0, c);
}

static void
handle_start_reply(int fd, short ev, void *d)
{
	struct client *c = d;
	char buf[1030];		/* status + ' ' + max reply len + \r\n\0 */
	const char *lang;
	size_t len;

	lang = vhost_lang(c->host, c->iri.path);

	snprintf(buf, sizeof(buf), "%d ", c->code);
	strlcat(buf, c->meta, sizeof(buf));
	if (!strcmp(c->meta, "text/gemini") && lang != NULL) {
		strlcat(buf, "; lang=", sizeof(buf));
		strlcat(buf, lang, sizeof(buf));
	}

	len = strlcat(buf, "\r\n", sizeof(buf));
	assert(len < sizeof(buf));

	switch (tls_write(c->ctx, buf, len)) {
	case -1:
		close_conn(fd, ev, c);
		return;
	case TLS_WANT_POLLIN:
		reschedule_read(fd, c, &handle_start_reply);
		return;
	case TLS_WANT_POLLOUT:
		reschedule_write(fd, c, &handle_start_reply);
		return;
	}

	log_request(c, buf, sizeof(buf));

	if (c->code != SUCCESS)
		close_conn(fd, ev, c);
	else
		c->next(fd, ev, c);
}

static void
start_cgi(const char *spath, const char *relpath, struct client *c)
{
	char addr[NI_MAXHOST];
	int e;

	e = getnameinfo((struct sockaddr*)&c->addr, sizeof(c->addr),
	    addr, sizeof(addr),
	    NULL, 0,
	    NI_NUMERICHOST);
	if (e != 0)
		goto err;

	if (!send_iri(exfd, &c->iri)
	    || !send_string(exfd, spath)
	    || !send_string(exfd, relpath)
	    || !send_string(exfd, addr)
	    || !send_string(exfd, tls_peer_cert_subject(c->ctx))
	    || !send_string(exfd, tls_peer_cert_issuer(c->ctx))
	    || !send_string(exfd, tls_peer_cert_hash(c->ctx))
	    || !send_time(exfd, tls_peer_cert_notbefore(c->ctx))
	    || !send_time(exfd, tls_peer_cert_notafter(c->ctx))
	    || !send_vhost(exfd, c->host))
		goto err;

	close(c->pfd);
	if ((c->pfd = recv_fd(exfd)) == -1) {
		start_reply(c, TEMP_FAILURE, "internal server error");
		return;
	}

	reschedule_read(c->pfd, c, &handle_cgi_reply);
	return;

err:
	/* fatal("cannot talk to the executor process: %s", strerror(errno)); */
	fatal("cannot talk to the executor process");
}

static void
send_file(int fd, short ev, void *d)
{
	struct client *c = d;
	ssize_t ret, len;

	len = (c->buf + c->len) - c->i;

	while (len > 0) {
		switch (ret = tls_write(c->ctx, c->i, len)) {
		case -1:
			log_err(c, "tls_write: %s", tls_error(c->ctx));
			close_conn(fd, ev, c);
			return;

		case TLS_WANT_POLLIN:
			reschedule_read(fd, c, &send_file);
			return;

		case TLS_WANT_POLLOUT:
			reschedule_write(fd, c, &send_file);
			return;

		default:
			c->i += ret;
			len -= ret;
			break;
		}
	}

	close_conn(fd, ev, c);
}

static void
open_dir(struct client *c)
{
	size_t len;
	int dirfd;
	char *before_file;

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
		if (c->host->cgi != NULL && !fnmatch(c->host->cgi, c->iri.path, 0)) {
			start_cgi(c->iri.path, "", c);
			break;
		}

		/* fallthrough */

	case FILE_EXISTS:
                load_file(c);
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

		c->pfd = dirfd;
		c->next = enter_handle_dirlist;

		if ((c->dir = fdopendir(c->pfd)) == NULL) {
			log_err(c, "fdopendir(%d) (vhost:%s) %s: %s",
			    c->pfd, c->host->domain, c->iri.path, strerror(errno));
			start_reply(c, TEMP_FAILURE, "internal server error");
			return;
		}
		c->off = 0;

                start_reply(c, SUCCESS, "text/gemini");
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
enter_handle_dirlist(int fd, short ev, void *d)
{
	struct client *c = d;
	char b[PATH_MAX];
	size_t l;

	strlcpy(b, c->iri.path, sizeof(b));
	l = snprintf(c->sbuf, sizeof(c->sbuf),
	    "# Index of %s\n\n", b);
	if (l >= sizeof(c->sbuf)) {
		/* this is impossible, given that we have enough space
		 * in c->sbuf to hold the ancilliary string plus the
		 * full path; but it wouldn't read nice without some
		 * error checking, and I'd like to avoid a strlen. */
		close_conn(fd, ev, c);
		return;
	}

	c->len = l;
	handle_dirlist(fd, ev, c);
}

static void
handle_dirlist(int fd, short ev, void *d)
{
	struct client *c = d;
	ssize_t r;

	while (c->len > 0) {
		switch (r = tls_write(c->ctx, c->sbuf + c->off, c->len)) {
		case -1:
			close_conn(fd, ev, c);
			return;
		case TLS_WANT_POLLOUT:
			reschedule_read(fd, c, &handle_dirlist);
			return;
		case TLS_WANT_POLLIN:
			reschedule_write(fd, c, &handle_dirlist);
			return;
		default:
			c->off += r;
			c->len -= r;
		}
	}

	send_directory_listing(fd, ev, c);
}

static int
read_next_dir_entry(struct client *c)
{
	struct dirent *d;

	do {
		errno = 0;
		if ((d = readdir(c->dir)) == NULL) {
			if (errno != 0)
				log_err(c, "readdir: %s", strerror(errno));
			return 0;
		}
	} while (!strcmp(d->d_name, "."));

	/* XXX: url escape */
	snprintf(c->sbuf, sizeof(c->sbuf), "=> %s %s\n",
	    d->d_name, d->d_name);
	c->len = strlen(c->sbuf);
	c->off = 0;

	return 1;
}

static void
send_directory_listing(int fd, short ev, void *d)
{
	struct client *c = d;
	ssize_t r;

	while (1) {
		if (c->len == 0) {
			if (!read_next_dir_entry(c))
				goto end;
		}

		while (c->len > 0) {
			switch (r = tls_write(c->ctx, c->sbuf + c->off, c->len)) {
			case -1:
				goto end;

			case TLS_WANT_POLLOUT:
				reschedule_read(fd, c, &send_directory_listing);
				return;

			case TLS_WANT_POLLIN:
				reschedule_write(fd, c, &send_directory_listing);
				return;

			default:
				c->off += r;
				c->len -= r;
				break;
			}
		}
	}

end:
	close_conn(fd, ev, d);
}

/* accumulate the meta line from the cgi script. */
static void
handle_cgi_reply(int fd, short ev, void *d)
{
	struct client *c = d;
	void	*buf, *e;
	size_t	 len;
	ssize_t	 r;


	buf = c->sbuf + c->len;
	len = sizeof(c->sbuf) - c->len;

	r = read(c->pfd, buf, len);
	if (r == 0 || r == -1) {
		start_reply(c, CGI_ERROR, "CGI error");
		return;
	}

	c->len += r;

	/* TODO: error if the CGI script don't reply correctly */
	e = strchr(c->sbuf, '\n');
	if (e != NULL || c->len == sizeof(c->sbuf)) {
		log_request(c, c->sbuf, c->len);

		c->off = 0;
		handle_cgi(fd, ev, c);
		return;
	}

	reschedule_read(fd, c, &handle_cgi_reply);
}

static void
handle_cgi(int fd, short ev, void *d)
{
	struct client *c = d;
	ssize_t r;

	while (1) {
		if (c->len == 0) {
			switch (r = read(c->pfd, c->sbuf, sizeof(c->sbuf))) {
			case 0:
				goto end;
			case -1:
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					reschedule_read(c->pfd, c, &handle_cgi);
					return;
				}
				goto end;
			default:
				c->len = r;
				c->off = 0;
			}
		}

		while (c->len > 0) {
			switch (r = tls_write(c->ctx, c->sbuf + c->off, c->len)) {
			case -1:
				goto end;

			case TLS_WANT_POLLOUT:
				reschedule_read(c->fd, c, &handle_cgi);
				return;

			case TLS_WANT_POLLIN:
				reschedule_write(c->fd, c, &handle_cgi);
				return;

			default:
                                c->off += r;
				c->len -= r;
				break;
			}
		}
	}

end:
	close_conn(c->fd, ev, d);
}

static void
close_conn(int fd, short ev, void *d)
{
	struct client *c = d;

	switch (tls_close(c->ctx)) {
	case TLS_WANT_POLLIN:
		reschedule_read(fd, c, &close_conn);
		return;
	case TLS_WANT_POLLOUT:
		reschedule_read(fd, c, &close_conn);
		return;
	}

	connected_clients--;

	tls_free(c->ctx);
	c->ctx = NULL;

	if (c->buf != MAP_FAILED)
		munmap(c->buf, c->len);

	if (c->pfd != -1)
		close(c->pfd);

	if (c->dir != NULL)
		closedir(c->dir);

	close(c->fd);
	c->fd = -1;
}

static void
do_accept(int sock, short et, void *d)
{
	struct client *c;
	struct server *s = d;
	struct sockaddr_storage addr;
	struct sockaddr *saddr;
	socklen_t len;
	int i, fd;

	(void)et;


	saddr = (struct sockaddr*)&addr;
	len = sizeof(addr);
	if ((fd = accept4(sock, saddr, &len, SOCK_NONBLOCK)) == -1) {
		if (errno == EWOULDBLOCK || errno == EAGAIN)
			return;
		fatal("accept: %s", strerror(errno));
	}

	for (i = 0; i < MAX_USERS; ++i) {
		c = &s->clients[i];
		if (c->fd == -1) {
			memset(c, 0, sizeof(*c));
			if (tls_accept_socket(s->ctx, &c->ctx, fd) == -1)
				break; /* goodbye fd! */

			c->fd = fd;
			c->pfd = -1;
			c->buf = MAP_FAILED;
			c->dir = NULL;
			c->addr = addr;

			reschedule_read(fd, c, &handle_handshake);
			connected_clients++;
			return;
		}
	}

	close(fd);
}

static void
handle_sighup(int fd, short ev, void *d)
{
	(void)fd;
	(void)ev;

	event_del(&e4);
	if (has_ipv6)
		event_del(&e6);
	if (has_siginfo)
		signal_del(&siginfo);
	signal_del(&sigusr2);
	signal_del(&sighup);
}

static void
handle_siginfo(int fd, short ev, void *d)
{
	(void)fd;
	(void)ev;
	(void)d;

	log_info(NULL, "%d connected clients", connected_clients);
}

void
loop(struct tls *ctx, int sock4, int sock6)
{
	struct server server;
	size_t i;

	event_init();

	memset(&server, 0, sizeof(server));
	for (i = 0; i < MAX_USERS; ++i)
		server.clients[i].fd = -1;

	event_set(&e4, sock4, EV_READ | EV_PERSIST, &do_accept, &server);
	event_add(&e4, NULL);

	if (sock6 != -1) {
		has_ipv6 = 1;
		event_set(&e6, sock6, EV_READ | EV_PERSIST, &do_accept, &server);
		event_add(&e6, NULL);
	}

	signal_set(&sighup, SIGHUP, &handle_sighup, NULL);
	signal_add(&sighup, NULL);

#ifdef SIGINFO
	has_siginfo = 1;
	signal_set(&siginfo, SIGINFO, &handle_siginfo, NULL);
	signal_add(&siginfo, NULL);
#endif
	signal_set(&sigusr2, SIGINFO, &handle_siginfo, NULL);
	signal_add(&sigusr2, NULL);

	server.ctx = ctx;

	sandbox();
	event_dispatch();
	_exit(0);
}
