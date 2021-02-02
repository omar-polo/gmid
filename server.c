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
#include <fcntl.h>
#include <fnmatch.h>
#include <limits.h>
#include <string.h>

#include "gmid.h"

int connected_clients;

const char *
vhost_lang(struct vhost *v, const char *path)
{
	struct location *loc;

	if (v == NULL || path == NULL)
		return NULL;

	for (loc = &v->locations[1]; loc->match != NULL; ++loc) {
		if (!fnmatch(loc->match, path, 0)) {
			if (loc->lang != NULL)
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
		if (!fnmatch(loc->match, path, 0)) {
			if (loc->default_mime != NULL)
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
		if (!fnmatch(loc->match, path, 0)) {
			if (loc->index != NULL)
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

	for (loc = v->locations; loc->match != NULL; ++loc) {
		if (!fnmatch(loc->match, path, 0)) {
			if (loc->auto_index != 0)
				return loc->auto_index == 1;
		}
	}

	return v->locations[0].auto_index == 1;
}

int
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
		LOGN(c, "failed stat for %s: %s", path, strerror(errno));
		return FILE_MISSING;
	}

	if (S_ISDIR(sb.st_mode))
		return FILE_DIRECTORY;

	if (sb.st_mode & S_IXUSR)
		return FILE_EXECUTABLE;

	return FILE_EXISTS;
}

void
open_file(struct pollfd *fds, struct client *c)
{
	switch (check_path(c, c->iri.path, &c->fd)) {
	case FILE_EXECUTABLE:
		if (c->host->cgi != NULL && !fnmatch(c->host->cgi, c->iri.path, 0)) {
			start_cgi(c->iri.path, "", fds, c);
			return;
		}

		/* fallthrough */

	case FILE_EXISTS:
		load_file(fds, c);
		return;

	case FILE_DIRECTORY:
		open_dir(fds, c);
		return;

	case FILE_MISSING:
		if (c->host->cgi != NULL && !fnmatch(c->host->cgi, c->iri.path, 0)) {
			check_for_cgi(fds, c);
			return;
		}
		start_reply(fds, c, NOT_FOUND, "not found");
		return;

	default:
		/* unreachable */
		abort();
	}
}

void
load_file(struct pollfd *fds, struct client *c)
{
	if ((c->len = filesize(c->fd)) == -1) {
		LOGE(c, "failed to get file size for %s: %s",
		    c->iri.path, strerror(errno));
		start_reply(fds, c, TEMP_FAILURE, "internal server error");
		return;
	}

	if ((c->buf = mmap(NULL, c->len, PROT_READ, MAP_PRIVATE,
		    c->fd, 0)) == MAP_FAILED) {
		LOGW(c, "mmap: %s: %s", c->iri.path, strerror(errno));
		start_reply(fds, c, TEMP_FAILURE, "internal server error");
		return;
	}
	c->i = c->buf;
	c->next = send_file;
	start_reply(fds, c, SUCCESS, mime(c->host, c->iri.path));
}

/*
 * the inverse of this algorithm, i.e. starting from the start of the
 * path + strlen(cgi), and checking if each component, should be
 * faster.  But it's tedious to write.  This does the opposite: starts
 * from the end and strip one component at a time, until either an
 * executable is found or we emptied the path.
 */
void
check_for_cgi(struct pollfd *fds, struct client *c)
{
	char path[PATH_MAX];
	char *end;

	strlcpy(path, c->iri.path, sizeof(path));
	end = strchr(path, '\0');

	/* NB: assume CGI is enabled and path matches cgi */

	while (end > path) {
		/* go up one level.  UNIX paths are simple and POSIX
		 * dirname, with its ambiguities on if the given path
		 * is changed or not, gives me headaches. */
		while (*end != '/')
			end--;
		*end = '\0';

		switch (check_path(c, path, &c->fd)) {
		case FILE_EXECUTABLE:
			start_cgi(path, end+1, fds, c);
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
	start_reply(fds, c, NOT_FOUND, "not found");
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

void
handle_handshake(struct pollfd *fds, struct client *c)
{
	struct vhost *h;
	const char *servname;
	const char *parse_err = "unknown error";

	switch (tls_handshake(c->ctx)) {
	case 0:  /* success */
	case -1: /* already handshaked */
		break;
	case TLS_WANT_POLLIN:
		fds->events = POLLIN;
		return;
	case TLS_WANT_POLLOUT:
		fds->events = POLLOUT;
		return;
	default:
		/* unreachable */
		abort();
	}

	servname = tls_conn_servername(c->ctx);
	if (!puny_decode(servname, c->domain, sizeof(c->domain), &parse_err)) {
		LOGI(c, "%s", parse_err);
		goto err;
	}

	for (h = hosts; h->domain != NULL; ++h) {
		if (!fnmatch(h->domain, c->domain, 0))
			break;
	}

	/* LOGD(c, "handshake: SNI: \"%s\"; decoded: \"%s\"; matched: \"%s\"", */
	/*     servname != NULL ? servname : "(null)", */
	/*     c->domain, */
	/*     h->domain != NULL ? h->domain : "(null)"); */

	if (h->domain != NULL) {
		c->host = h;
		c->state = handle_open_conn;
		c->state(fds, c);
		return;
	}

err:
	if (servname != NULL)
		strncpy(c->req, servname, sizeof(c->req));
	else
		strncpy(c->req, "null", sizeof(c->req));

	start_reply(fds, c, BAD_REQUEST, "Wrong/malformed host or missing SNI");
}

void
handle_open_conn(struct pollfd *fds, struct client *c)
{
	const char *parse_err = "invalid request";
	char decoded[DOMAIN_NAME_LEN];

	bzero(c->req, sizeof(c->req));
	bzero(&c->iri, sizeof(c->iri));

	switch (tls_read(c->ctx, c->req, sizeof(c->req)-1)) {
	case -1:
		LOGE(c, "tls_read: %s", tls_error(c->ctx));
		close_conn(fds, c);
		return;

	case TLS_WANT_POLLIN:
		fds->events = POLLIN;
		return;

	case TLS_WANT_POLLOUT:
		fds->events = POLLOUT;
		return;
	}

	if (!trim_req_iri(c->req, &parse_err)
	    || !parse_iri(c->req, &c->iri, &parse_err)
	    || !puny_decode(c->iri.host, decoded, sizeof(decoded), &parse_err)) {
		LOGI(c, "iri parse error: %s", parse_err);
		start_reply(fds, c, BAD_REQUEST, "invalid request");
		return;
	}

	if (c->iri.port_no != conf.port
	    || strcmp(c->iri.schema, "gemini")
	    || strcmp(decoded, c->domain)) {
		start_reply(fds, c, PROXY_REFUSED, "won't proxy request");
		return;
	}

	open_file(fds, c);
}

void
start_reply(struct pollfd *pfd, struct client *c, int code, const char *meta)
{
	c->code = code;
	c->meta = meta;
	c->state = handle_start_reply;
	c->state(pfd, c);
}

void
handle_start_reply(struct pollfd *pfd, struct client *c)
{
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
		close_conn(pfd, c);
		return;
	case TLS_WANT_POLLIN:
		pfd->events = POLLIN;
		return;
	case TLS_WANT_POLLOUT:
		pfd->events = POLLOUT;
		return;
	}

	log_request(c, buf, sizeof(buf));

	/* we don't need a body */
	if (c->code != SUCCESS) {
		close_conn(pfd, c);
		return;
	}

	/* advance the state machine */
	c->state = c->next;
	c->state(pfd, c);
}

void
start_cgi(const char *spath, const char *relpath,
    struct pollfd *fds, struct client *c)
{
	char addr[NI_MAXHOST];
	const char *ruser, *cissuer, *chash;
	int e;

	e = getnameinfo((struct sockaddr*)&c->addr, sizeof(c->addr),
	    addr, sizeof(addr),
	    NULL, 0,
	    NI_NUMERICHOST);
	if (e != 0)
		goto err;

	if (tls_peer_cert_provided(c->ctx)) {
		ruser = tls_peer_cert_subject(c->ctx);
		cissuer = tls_peer_cert_issuer(c->ctx);
		chash = tls_peer_cert_hash(c->ctx);
	} else {
		ruser = NULL;
		cissuer = NULL;
		chash = NULL;
	}

	if (!send_iri(exfd, &c->iri)
	    || !send_string(exfd, spath)
	    || !send_string(exfd, relpath)
	    || !send_string(exfd, addr)
	    || !send_string(exfd, ruser)
	    || !send_string(exfd, cissuer)
	    || !send_string(exfd, chash)
	    || !send_vhost(exfd, c->host))
		goto err;

	close(c->fd);
	if ((c->fd = recv_fd(exfd)) == -1) {
		start_reply(fds, c, TEMP_FAILURE, "internal server error");
		return;
	}

	cgi_poll_on_child(fds, c);
	c->state = handle_cgi_reply;
	return;

err:
	/* fatal("cannot talk to the executor process: %s", strerror(errno)); */
	fatal("cannot talk to the executor process");
}

void
send_file(struct pollfd *fds, struct client *c)
{
	ssize_t ret, len;

	len = (c->buf + c->len) - c->i;

	while (len > 0) {
		switch (ret = tls_write(c->ctx, c->i, len)) {
		case -1:
			LOGE(c, "tls_write: %s", tls_error(c->ctx));
			close_conn(fds, c);
			return;

		case TLS_WANT_POLLIN:
			fds->events = POLLIN;
			return;

		case TLS_WANT_POLLOUT:
			fds->events = POLLOUT;
			return;

		default:
			c->i += ret;
			len -= ret;
			break;
		}
	}

	close_conn(fds, c);
}

void
open_dir(struct pollfd *fds, struct client *c)
{
	size_t len;
	int dirfd;
	char *before_file;

	len = strlen(c->iri.path);
	if (len > 0 && !ends_with(c->iri.path, "/")) {
		redirect_canonical_dir(fds, c);
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
		start_reply(fds, c, TEMP_FAILURE, "internal server error");
		return;
	}

	c->iri.path = c->sbuf;

	/* close later unless we have to generate the dir listing */
	dirfd = c->fd;
	c->fd = -1;

	switch (check_path(c, c->iri.path, &c->fd)) {
	case FILE_EXECUTABLE:
		if (c->host->cgi != NULL && !fnmatch(c->host->cgi, c->iri.path, 0)) {
			start_cgi(c->iri.path, "", fds, c);
			break;
		}

		/* fallthrough */

	case FILE_EXISTS:
                load_file(fds, c);
		break;

	case FILE_DIRECTORY:
		start_reply(fds, c, TEMP_REDIRECT, c->sbuf);
		break;

	case FILE_MISSING:
		*before_file = '\0';

		if (!vhost_auto_index(c->host, c->iri.path)) {
			start_reply(fds, c, NOT_FOUND, "not found");
			break;
		}

		c->fd = dirfd;
		c->next = enter_handle_dirlist;

		if ((c->dir = fdopendir(c->fd)) == NULL) {
			LOGE(c, "can't fdopendir(%d) (vhost:%s) %s: %s",
			    c->fd, c->host->domain, c->iri.path, strerror(errno));
			start_reply(fds, c, TEMP_FAILURE, "internal server error");
			return;
		}
		c->off = 0;

                start_reply(fds, c, SUCCESS, "text/gemini");
		return;

	default:
		/* unreachable */
		abort();
	}

	close(dirfd);
}

void
redirect_canonical_dir(struct pollfd *fds, struct client *c)
{
	size_t len;

	strlcpy(c->sbuf, "/", sizeof(c->sbuf));
	strlcat(c->sbuf, c->iri.path, sizeof(c->sbuf));
	len = strlcat(c->sbuf, "/", sizeof(c->sbuf));

	if (len >= sizeof(c->sbuf)) {
		start_reply(fds, c, TEMP_FAILURE, "internal server error");
		return;
	}

	start_reply(fds, c, TEMP_REDIRECT, c->sbuf);
}

void
enter_handle_dirlist(struct pollfd *fds, struct client *c)
{
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
		close_conn(fds, c);
		return;
	}
	c->len = l;

	c->state = handle_dirlist;
	handle_dirlist(fds, c);
}

void
handle_dirlist(struct pollfd *fds, struct client *c)
{
	ssize_t r;

	while (c->len > 0) {
		switch (r = tls_write(c->ctx, c->sbuf + c->off, c->len)) {
		case -1:
			close_conn(fds, c);
			return;
		case TLS_WANT_POLLOUT:
			fds->events = POLLOUT;
			return;
		case TLS_WANT_POLLIN:
			fds->events = POLLIN;
			return;
		default:
			c->off += r;
			c->len -= r;
		}
	}

	c->state = send_directory_listing;
	send_directory_listing(fds, c);
}

int
read_next_dir_entry(struct client *c)
{
	struct dirent *d;

	do {
		errno = 0;
		if ((d = readdir(c->dir)) == NULL) {
			if (errno != 0)
				LOGE(c, "readdir: %s", strerror(errno));
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

void
send_directory_listing(struct pollfd *fds, struct client *c)
{
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
				fds->events = POLLOUT;
				return;

			case TLS_WANT_POLLIN:
				fds->events = POLLIN;
				return;

			default:
				c->off += r;
				c->len -= r;
				break;
			}
		}
	}

end:
	close_conn(fds, c);
}

void
cgi_poll_on_child(struct pollfd *fds, struct client *c)
{
	int fd;

	if (c->waiting_on_child)
		return;
	c->waiting_on_child = 1;

	fds->events = POLLIN;

	fd = fds->fd;
	fds->fd = c->fd;
	c->fd = fd;
}

void
cgi_poll_on_client(struct pollfd *fds, struct client *c)
{
	int fd;

	if (!c->waiting_on_child)
		return;
	c->waiting_on_child = 0;

	fd = fds->fd;
	fds->fd = c->fd;
	c->fd = fd;
}

/* accumulate the meta line from the cgi script. */
void
handle_cgi_reply(struct pollfd *fds, struct client *c)
{
	void	*buf, *e;
	size_t	 len;
	ssize_t	 r;

	buf = c->sbuf + c->len;
	len = sizeof(c->sbuf) - c->len;

	/* we're polling on the child! */
	r = read(fds->fd, buf, len);
	if (r == 0 || r == -1) {
		cgi_poll_on_client(fds, c);
		start_reply(fds, c, CGI_ERROR, "CGI error");
		return;
	}

	c->len += r;

	/* TODO: error if the CGI script don't reply correctly */
	e = strchr(c->sbuf, '\n');
	if (e != NULL || c->len == sizeof(c->sbuf)) {
		log_request(c, c->sbuf, c->len);

		c->off = 0;
		c->state = handle_cgi;
		c->state(fds, c);
		return;
	}
}

void
handle_cgi(struct pollfd *fds, struct client *c)
{
	ssize_t r;

	/* ensure c->fd is the child and fds->fd the client */
	cgi_poll_on_client(fds, c);

	while (1) {
		if (c->len == 0) {
			switch (r = read(c->fd, c->sbuf, sizeof(c->sbuf))) {
			case 0:
				goto end;
			case -1:
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					cgi_poll_on_child(fds, c);
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
				fds->events = POLLOUT;
				return;

			case TLS_WANT_POLLIN:
				fds->events = POLLIN;
				return;

			default:
                                c->off += r;
				c->len -= r;
				break;
			}
		}
	}

end:
	close_conn(fds, c);
}

void
close_conn(struct pollfd *pfd, struct client *c)
{
	c->state = close_conn;

	switch (tls_close(c->ctx)) {
	case TLS_WANT_POLLIN:
		pfd->events = POLLIN;
		return;
	case TLS_WANT_POLLOUT:
		pfd->events = POLLOUT;
		return;
	}

	connected_clients--;

	tls_free(c->ctx);
	c->ctx = NULL;

	if (c->buf != MAP_FAILED)
		munmap(c->buf, c->len);

	if (c->fd != -1)
		close(c->fd);

	if (c->dir != NULL)
		closedir(c->dir);

	close(pfd->fd);
	pfd->fd = -1;
}

void
do_accept(int sock, struct tls *ctx, struct pollfd *fds, struct client *clients)
{
	int i, fd;
	struct sockaddr_storage addr;
	socklen_t len;

	len = sizeof(addr);
	if ((fd = accept(sock, (struct sockaddr*)&addr, &len)) == -1) {
		if (errno == EWOULDBLOCK)
			return;
		fatal("accept: %s", strerror(errno));
	}

	mark_nonblock(fd);

	for (i = 0; i < MAX_USERS; ++i) {
		if (fds[i].fd == -1) {
			bzero(&clients[i], sizeof(struct client));
			if (tls_accept_socket(ctx, &clients[i].ctx, fd) == -1)
				break; /* goodbye fd! */

			fds[i].fd = fd;
			fds[i].events = POLLIN;

			clients[i].state = handle_handshake;
			clients[i].next = send_file;
			clients[i].fd = -1;
			clients[i].waiting_on_child = 0;
			clients[i].buf = MAP_FAILED;
			clients[i].dir = NULL;
			clients[i].addr = addr;

			connected_clients++;
			return;
		}
	}

	close(fd);
}

void
loop(struct tls *ctx, int sock4, int sock6)
{
	int i;
	struct client clients[MAX_USERS];
	struct pollfd fds[MAX_USERS];

	connected_clients = 0;

	for (i = 0; i < MAX_USERS; ++i) {
		fds[i].fd = -1;
		fds[i].events = POLLIN;
		bzero(&clients[i], sizeof(struct client));
	}

	fds[0].fd = sock4;
	fds[1].fd = sock6;

	for (;;) {
		if (poll(fds, MAX_USERS, INFTIM) == -1) {
			if (errno == EINTR) {
                                fprintf(stderr, "connected clients: %d\n",
				    connected_clients);
				continue;
			}
			fatal("poll: %s", strerror(errno));
		}

		for (i = 0; i < MAX_USERS; i++) {
			if (fds[i].revents == 0)
				continue;

			if (fds[i].revents & (POLLERR|POLLNVAL))
				fatal("bad fd %d: %s", fds[i].fd,
				    strerror(errno));

			if (fds[i].revents & POLLHUP) {
				/* fds[i] may be the fd of the stdin
				 * of a cgi script that has exited. */
				if (!clients[i].waiting_on_child) {
					close_conn(&fds[i], &clients[i]);
					continue;
				}
			}

			if (fds[i].fd == sock4)
				do_accept(sock4, ctx, fds, clients);
			else if (fds[i].fd == sock6)
				do_accept(sock6, ctx, fds, clients);
			else
				clients[i].state(&fds[i], &clients[i]);
		}
	}
}
