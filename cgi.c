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

#include <errno.h>
#include <string.h>

#include "gmid.h"

static inline void
safe_setenv(const char *name, const char *val)
{
	if (val == NULL)
		val = "";
	setenv(name, val, 1);
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

int
start_cgi(const char *spath, const char *relpath, const char *query,
    struct pollfd *fds, struct client *c)
{
	pid_t pid;
	int p[2];		/* read end, write end */

	if (pipe(p) == -1)
		goto err;

	switch (pid = fork()) {
	case -1:
		goto err;

	case 0: {		/* child */
		char *ex, *requri, *portno;
		char addr[NI_MAXHOST];
		char *argv[] = { NULL, NULL, NULL };
		int ec;

		close(p[0]);
		if (dup2(p[1], 1) == -1)
			goto childerr;

		ec = getnameinfo((struct sockaddr*)&c->addr, sizeof(c->addr),
		    addr, sizeof(addr),
		    NULL, 0,
		    NI_NUMERICHOST | NI_NUMERICSERV);
		if (ec != 0)
			goto childerr;

		if (asprintf(&portno, "%d", conf.port) == -1)
			goto childerr;

		if (asprintf(&ex, "%s/%s", c->host->dir, spath) == -1)
			goto childerr;

		if (asprintf(&requri, "%s%s%s", spath,
		    *relpath == '\0' ? "" : "/", relpath) == -1)
			goto childerr;

		argv[0] = argv[1] = ex;

		/* fix the env */
		safe_setenv("GATEWAY_INTERFACE", "CGI/1.1");
		safe_setenv("SERVER_SOFTWARE", "gmid");
		safe_setenv("SERVER_PORT", portno);
		/* setenv("SERVER_NAME", "", 1); */
		safe_setenv("SCRIPT_NAME", spath);
		safe_setenv("SCRIPT_EXECUTABLE", ex);
		safe_setenv("REQUEST_URI", requri);
		safe_setenv("REQUEST_RELATIVE", relpath);
		safe_setenv("QUERY_STRING", query);
		safe_setenv("REMOTE_HOST", addr);
		safe_setenv("REMOTE_ADDR", addr);
		safe_setenv("DOCUMENT_ROOT", c->host->dir);

		if (tls_peer_cert_provided(c->ctx)) {
			safe_setenv("AUTH_TYPE", "Certificate");
			safe_setenv("REMOTE_USER", tls_peer_cert_subject(c->ctx));
			safe_setenv("TLS_CLIENT_ISSUER", tls_peer_cert_issuer(c->ctx));
			safe_setenv("TLS_CLIENT_HASH", tls_peer_cert_hash(c->ctx));
		}

		execvp(ex, argv);
		goto childerr;
	}

	default:		/* parent */
		close(p[1]);
		close(c->fd);
		c->fd = p[0];
		c->child = pid;
		mark_nonblock(c->fd);
		c->state = S_SENDING;
		handle_cgi(fds, c);
		return 0;
	}

err:
	if (!start_reply(fds, c, TEMP_FAILURE, "internal server error"))
		return 0;
	goodbye(fds, c);
	return 0;

childerr:
	dprintf(p[1], "%d internal server error\r\n", TEMP_FAILURE);
	close(p[1]);
	_exit(1);
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
