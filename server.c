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
#include <string.h>

#include "gmid.h"

int connected_clients;

int
check_path(struct client *c, const char *path, int *fd)
{
	struct stat sb;
	const char *p;

	assert(path != NULL);

	if (*path == '\0')
		p = ".";
	else if (*path == '/')
		/* in send_dir we add an initial / (to be
		 * redirect-friendly), but here we want to skip it */
		p = path+1;
	else
		p = path;

	if ((*fd = openat(c->host->dirfd, p, O_RDONLY | O_NOFOLLOW)) == -1) {
		return FILE_MISSING;
	}

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

int
open_file(struct pollfd *fds, struct client *c)
{
	switch (check_path(c, c->iri.path, &c->fd)) {
	case FILE_EXECUTABLE:
		if (c->host->cgi != NULL && starts_with(c->iri.path, c->host->cgi))
			return start_cgi(c->iri.path, "", c->iri.query, fds, c);

		/* fallthrough */

	case FILE_EXISTS:
		if ((c->len = filesize(c->fd)) == -1) {
			LOGE(c, "failed to get file size for %s", c->iri.path);
			close_conn(fds, c);
			return 0;
		}

		if ((c->buf = mmap(NULL, c->len, PROT_READ, MAP_PRIVATE,
			    c->fd, 0)) == MAP_FAILED) {
			LOGW(c, "mmap: %s: %s", c->iri.path, strerror(errno));
			close_conn(fds, c);
			return 0;
		}
		c->i = c->buf;
		c->next = S_SENDING_FILE;
		start_reply(fds, c, SUCCESS, mime(c->host, c->iri.path));
		return 0;

	case FILE_DIRECTORY:
		close(c->fd);
		c->fd = -1;
		send_dir(fds, c);
		return 0;

	case FILE_MISSING:
		if (c->host->cgi != NULL && starts_with(c->iri.path, c->host->cgi))
			return check_for_cgi(c->iri.path, c->iri.query, fds, c);
		start_reply(fds, c, NOT_FOUND, "not found");
		return 0;

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
int
check_for_cgi(char *path, char *query, struct pollfd *fds, struct client *c)
{
	char *end;
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
			return start_cgi(path, end+1, query, fds,c);
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
	return 0;
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

	for (h = hosts; h->domain != NULL; ++h) {
		if (!strcmp(h->domain, "*"))
			break;

		if (servname != NULL && !fnmatch(h->domain, servname, 0))
			break;
	}

	if (h->domain != NULL) {
		c->state = S_OPEN;
		c->host = h;
		handle_open_conn(fds, c);
		return;
	}

	if (servname != NULL)
		strncpy(c->req, servname, sizeof(c->req));
	else
		strncpy(c->req, "null", sizeof(c->req));

	start_reply(fds, c, BAD_REQUEST, "Wrong host or missing SNI");
}

void
handle_open_conn(struct pollfd *fds, struct client *c)
{
	const char *parse_err = "invalid request";

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

	if (!trim_req_iri(c->req) || !parse_iri(c->req, &c->iri, &parse_err)) {
		start_reply(fds, c, BAD_REQUEST, parse_err);
		return;
	}

	/* XXX: we should check that the SNI matches the requested host */
	if (strcmp(c->iri.schema, "gemini") || c->iri.port_no != conf.port) {
		start_reply(fds, c, PROXY_REFUSED, "won't proxy request");
		return;
	}

	open_file(fds, c);
}

void
start_reply(struct pollfd *pfd, struct client *c, int code, const char *meta)
{
	char buf[1030];		/* status + ' ' + max reply len + \r\n\0 */
	size_t len;

	c->code = code;
	c->meta = meta;
	c->state = S_INITIALIZING;

	snprintf(buf, sizeof(buf), "%d ", code);
	strlcat(buf, meta, sizeof(buf));
	if (!strcmp(meta, "text/gemini") && c->host->lang != NULL) {
		strlcat(buf, "; lang=", sizeof(buf));
		strlcat(buf, c->host->lang, sizeof(buf));
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
	handle(pfd, c);
}

int
start_cgi(const char *spath, const char *relpath, const char *query,
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

	if (!send_string(exfd, spath)
	    || !send_string(exfd, relpath)
	    || !send_string(exfd, query)
	    || !send_string(exfd, addr)
	    || !send_string(exfd, ruser)
	    || !send_string(exfd, cissuer)
	    || !send_string(exfd, chash)
	    || !send_vhost(exfd, c->host))
		goto err;

	close(c->fd);
	if ((c->fd = recv_fd(exfd)) == -1) {
		start_reply(fds, c, TEMP_FAILURE, "internal server error");
		return 0;
	}
	c->state = S_SENDING_CGI;
	cgi_poll_on_child(fds, c);
	c->code = -1;
	/* handle_cgi(fds, c); */
	return 0;

err:
	/* fatal("cannot talk to the executor process: %s", strerror(errno)); */
	fatal("cannot talk to the executor process");
}

void
send_file(struct pollfd *fds, struct client *c)
{
	ssize_t ret, len;

	/* ensure the correct state */
	c->state = S_SENDING_FILE;

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
send_dir(struct pollfd *fds, struct client *c)
{
	size_t len;
	const char *index = "index.gmi";

	/* guard against a re-entrant call: open_file -> send_dir ->
	 * open_file -> send_dir.  This can happen only if:
	 *
	 *  - user requested a dir, say foo/
	 *  - we try to serve foo/$INDEX
	 *  - foo/$INDEX is a directory.
	 */
	if (c->iri.path == c->sbuf) {
		start_reply(fds, c, TEMP_REDIRECT, c->sbuf);
		return;
	}

	strlcpy(c->sbuf, "/", sizeof(c->sbuf));

	len = strlen(c->iri.path);
	if (len > 0 && c->iri.path[len-1] != '/') {
		/* redirect to url with the trailing / */
		strlcat(c->sbuf, c->iri.path, sizeof(c->sbuf));
		strlcat(c->sbuf, "/", sizeof(c->sbuf));
		start_reply(fds, c, TEMP_REDIRECT, c->sbuf);
		return;
	}

	strlcat(c->sbuf, c->iri.path, sizeof(c->sbuf));

	if (!ends_with(c->sbuf, "/"))
		strlcat(c->sbuf, "/", sizeof(c->sbuf));

	if (c->host->index != NULL)
		index = c->host->index;
	len = strlcat(c->sbuf, index, sizeof(c->sbuf));

	if (len >= sizeof(c->sbuf)) {
		start_reply(fds, c, TEMP_FAILURE, "internal server error");
		return;
	}

	close(c->fd);
	c->iri.path = c->sbuf;
	open_file(fds, c);
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

/* handle the read from the child process.  Return like read(2) */
static ssize_t
read_from_cgi(struct client *c)
{
	void	*buf;
	size_t	 len;
	ssize_t	 r;

	/* if we haven't read a whole response line, we want to
	 * continue reading. */

	if (c->code == -1) {
		buf = c->sbuf + c->len;
		len = sizeof(c->sbuf) - c->len;
	} else {
		buf = c->sbuf;
		len = sizeof(c->sbuf);
	}

	r = read(c->fd, buf, len);
	if (r == 0 || r == -1)
		return r;

	c->len += r;
	c->off = 0;

	if (c->code != -1)
		return r;

	if (strchr(c->sbuf, '\n') || c->len == sizeof(c->sbuf)) {
		c->code = 0;
		log_request(c, c->sbuf, c->len);
	}

	return r;
}

void
handle_cgi(struct pollfd *fds, struct client *c)
{
	ssize_t r;

	/* ensure c->fd is the child and fds->fd the client */
	cgi_poll_on_client(fds, c);

	while (1) {
		if (c->code == -1 || c->len == 0) {
			switch (r = read_from_cgi(c)) {
			case 0:
				goto end;

			case -1:
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					cgi_poll_on_child(fds, c);
					return;
				}
				goto end;
			}
		}

		if (c->code == -1) {
			cgi_poll_on_child(fds, c);
			return;
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
	c->state = S_CLOSING;

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

			clients[i].state = S_HANDSHAKE;
			clients[i].next = S_SENDING_FILE;
			clients[i].fd = -1;
			clients[i].waiting_on_child = 0;
			clients[i].buf = MAP_FAILED;
			clients[i].addr = addr;

			connected_clients++;
			return;
		}
	}

	close(fd);
}

void
handle(struct pollfd *fds, struct client *client)
{
	switch (client->state) {
	case S_HANDSHAKE:
		handle_handshake(fds, client);
		break;

	case S_OPEN:
                handle_open_conn(fds, client);
		break;

	case S_INITIALIZING:
		start_reply(fds, client, client->code, client->meta);
                break;

	case S_SENDING_FILE:
		send_file(fds, client);
		break;

	case S_SENDING_CGI:
		handle_cgi(fds, client);
		break;

	case S_CLOSING:
		close_conn(fds, client);
		break;

	default:
		/* unreachable */
		abort();
	}
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
				handle(&fds[i], &clients[i]);
		}
	}
}
