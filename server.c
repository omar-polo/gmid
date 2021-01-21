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

	assert(path != NULL);
	if ((*fd = openat(c->host->dirfd, *path ? path : ".",
	    O_RDONLY | O_NOFOLLOW)) == -1) {
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
			goodbye(fds, c);
			return 0;
		}

		if ((c->buf = mmap(NULL, c->len, PROT_READ, MAP_PRIVATE,
			    c->fd, 0)) == MAP_FAILED) {
			LOGW(c, "mmap: %s: %s", c->iri.path, strerror(errno));
			goodbye(fds, c);
			return 0;
		}
		c->i = c->buf;
		if (!start_reply(fds, c, SUCCESS, mime(c->host, c->iri.path)))
			return 0;
		send_file(fds, c);
		return 0;

	case FILE_DIRECTORY:
		close(c->fd);
		c->fd = -1;
		send_dir(fds, c);
		return 0;

	case FILE_MISSING:
		if (c->host->cgi != NULL && starts_with(c->iri.path, c->host->cgi))
			return check_for_cgi(c->iri.path, c->iri.query, fds, c);

		if (!start_reply(fds, c, NOT_FOUND, "not found"))
			return 0;
		goodbye(fds, c);
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
	if (!start_reply(fds, c, NOT_FOUND, "not found"))
		return 0;
	goodbye(fds, c);
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

	if (!start_reply(fds, c, BAD_REQUEST, "Wrong host or missing SNI"))
		return;
	goodbye(fds, c);
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
		goodbye(fds, c);
		return;

	case TLS_WANT_POLLIN:
		fds->events = POLLIN;
		return;

	case TLS_WANT_POLLOUT:
		fds->events = POLLOUT;
		return;
	}

	if (!trim_req_iri(c->req) || !parse_iri(c->req, &c->iri, &parse_err)) {
		if (!start_reply(fds, c, BAD_REQUEST, parse_err))
			return;
		goodbye(fds, c);
		return;
	}

	/* XXX: we should check that the SNI matches the requested host */
	if (strcmp(c->iri.schema, "gemini") || c->iri.port_no != conf.port) {
		if (!start_reply(fds, c, PROXY_REFUSED, "won't proxy request"))
			return;
		goodbye(fds, c);
		return;
	}

	open_file(fds, c);
}

int
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
	case TLS_WANT_POLLIN:
		pfd->events = POLLIN;
		return 0;
	case TLS_WANT_POLLOUT:
		pfd->events = POLLOUT;
		return 0;
	default:
		log_request(c, buf, sizeof(buf));
		return 1;
	}
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
		if (!start_reply(fds, c, TEMP_FAILURE, "internal server error"))
			return 0;
		goodbye(fds, c);
		return 0;
	}
	c->child = 1;
	c->state = S_SENDING;
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

	len = (c->buf + c->len) - c->i;

	while (len > 0) {
		switch (ret = tls_write(c->ctx, c->i, len)) {
		case -1:
			LOGE(c, "tls_write: %s", tls_error(c->ctx));
			goodbye(fds, c);
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

	goodbye(fds, c);
}

void
send_dir(struct pollfd *fds, struct client *c)
{
	size_t len;

	/* guard against a re-entrant call:
	 *
	 *	open_file -> send_dir -> open_file -> send_dir
	 *
	 * this can happen only if:
	 *
	 *  - user requested a dir, say foo/
	 *  - we try to serve foo/index.gmi
	 *  - foo/index.gmi is a directory.
	 *
	 * It's an unlikely case, but can happen.  We then redirect
	 * to foo/index.gmi
	 */
	if (c->iri.path == c->sbuf) {
		if (!start_reply(fds, c, TEMP_REDIRECT, c->sbuf))
			return;
		goodbye(fds, c);
		return;
	}

	len = strlen(c->iri.path);
	if (len > 0 && c->iri.path[len-1] != '/') {
		/* redirect to url with the trailing / */
		strlcpy(c->sbuf, c->iri.path, sizeof(c->sbuf));
		strlcat(c->sbuf, "/", sizeof(c->sbuf));
		if (!start_reply(fds, c, TEMP_REDIRECT, c->sbuf))
			return;
		goodbye(fds, c);
		return;
	}

        strlcpy(c->sbuf, c->iri.path, sizeof(c->sbuf));
	if (len != 0)
		strlcat(c->sbuf, "/", sizeof(c->sbuf));
	len = strlcat(c->sbuf, "index.gmi", sizeof(c->sbuf));

	if (len >= sizeof(c->sbuf)) {
		if (!start_reply(fds, c, TEMP_FAILURE, "internal server error"))
			return;
		goodbye(fds, c);
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

void
handle_cgi(struct pollfd *fds, struct client *c)
{
	ssize_t r;

	/* ensure c->fd is the child and fds->fd the client */
	cgi_poll_on_client(fds, c);

	while (1) {
		if (c->len == 0) {
			if ((r = read(c->fd, c->sbuf, sizeof(c->sbuf))) == 0)
				goto end;
			if (r == -1) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					cgi_poll_on_child(fds, c);
					return;
				}
                                goto end;
			}
			c->len = r;
			c->off = 0;

			/* XXX: if we haven't still read a whole
			 * reply line, we should go back to poll! */
			if (c->code == -1) {
				c->code = 0;
				log_request(c, c->sbuf, sizeof(c->sbuf));
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
	goodbye(fds, c);
}

void
goodbye(struct pollfd *pfd, struct client *c)
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
			clients[i].fd = -1;
			clients[i].child = 0;
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
		if (!start_reply(fds, client, client->code, client->meta))
			return;

		if (client->code != SUCCESS) {
			/* we don't need a body */
			goodbye(fds, client);
			return;
		}

		client->state = S_SENDING;

		/* fallthrough */

	case S_SENDING:
		if (client->child)
			handle_cgi(fds, client);
		else
			send_file(fds, client);
		break;

	case S_CLOSING:
		goodbye(fds, client);
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
					goodbye(&fds[i], &clients[i]);
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
