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

#include <netdb.h>

#include <err.h>
#include <errno.h>
#include <string.h>

#include "gmid.h"

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
	/* handle_cgi(fds, c); */
	return 0;

err:
	/* fatal("cannot talk to the executor process: %s", strerror(errno)); */
	err(1, "cannot talk to the executor process");
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
