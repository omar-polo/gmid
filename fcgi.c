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

#include <assert.h>
#include <errno.h>
#include <string.h>

/*
 * Sometimes it can be useful to inspect the fastcgi traffic as
 * received by gmid.
 *
 * This will make gmid connect to a `debug.sock' socket (that must
 * exists) in the current directory and send there a copy of what gets
 * read.  The socket can be created and monitored e.g. with
 *
 *	rm -f debug.sock ; nc -Ulk ./debug.sock | hexdump -C
 *
 * NB: the sandbox must be disabled for this to work.
 */
#define DEBUG_FCGI 0

#if DEBUG_FCGI
# include <sys/un.h>
static int debug_socket = -1;
#endif

struct fcgi_header {
	unsigned char version;
	unsigned char type;
	unsigned char req_id1;
	unsigned char req_id0;
	unsigned char content_len1;
	unsigned char content_len0;
	unsigned char padding;
	unsigned char reserved;
};

/*
 * number of bytes in a FCGI_HEADER.  Future version of the protocol
 * will not reduce this number.
 */
#define FCGI_HEADER_LEN	8

/*
 * values for the version component
 */
#define FCGI_VERSION_1	1

/*
 * values for the type component
 */
#define FCGI_BEGIN_REQUEST	 1
#define FCGI_ABORT_REQUEST	 2
#define FCGI_END_REQUEST	 3
#define FCGI_PARAMS		 4
#define FCGI_STDIN		 5
#define FCGI_STDOUT		 6
#define FCGI_STDERR		 7
#define FCGI_DATA		 8
#define FCGI_GET_VALUES		 9
#define FCGI_GET_VALUES_RESULT	10
#define FCGI_UNKNOWN_TYPE	11
#define FCGI_MAXTYPE		(FCGI_UNKNOWN_TYPE)

struct fcgi_begin_req {
	unsigned char role1;
	unsigned char role0;
	unsigned char flags;
	unsigned char reserved[5];
};

struct fcgi_begin_req_record {
	struct fcgi_header	header;
	struct fcgi_begin_req	body;
};

/*
 * mask for flags;
 */
#define FCGI_KEEP_CONN		1

/*
 * values for the role
 */
#define FCGI_RESPONDER	1
#define FCGI_AUTHORIZER	2
#define FCGI_FILTER	3

struct fcgi_end_req_body {
	unsigned char app_status3;
	unsigned char app_status2;
	unsigned char app_status1;
	unsigned char app_status0;
	unsigned char proto_status;
	unsigned char reserved[3];
};

/*
 * values for proto_status
 */
#define FCGI_REQUEST_COMPLETE	0
#define FCGI_CANT_MPX_CONN	1
#define FCGI_OVERLOADED		2
#define FCGI_UNKNOWN_ROLE	3

/*
 * Variable names for FCGI_GET_VALUES / FCGI_GET_VALUES_RESULT
 * records.
 */
#define FCGI_MAX_CONNS	"FCGI_MAX_CONNS"
#define FCGI_MAX_REQS	"FCGI_MAX_REQS"
#define FCGI_MPXS_CONNS	"FCGI_MPXS_CONNS"

static int
prepare_header(struct fcgi_header *h, int type, int id, size_t size,
    size_t padding)
{
	memset(h, 0, sizeof(*h));

	/*
	 * id=0 is reserved for status messages.
	 */
	id++;

	h->version = FCGI_VERSION_1;
        h->type = type;
	h->req_id1 = (id >> 8);
	h->req_id0 = (id & 0xFF);
	h->content_len1 = (size >> 8);
	h->content_len0 = (size & 0xFF);
	h->padding = padding;

	return 0;
}

static int
fcgi_begin_request(int sock, int id)
{
	struct fcgi_begin_req_record r;

	if (id > UINT16_MAX)
		return -1;

	memset(&r, 0, sizeof(r));
	prepare_header(&r.header, FCGI_BEGIN_REQUEST, id,
	    sizeof(r.body), 0);
	assert(sizeof(r.body) == FCGI_HEADER_LEN);

	r.body.role1 = 0;
	r.body.role0 = FCGI_RESPONDER;
	r.body.flags = FCGI_KEEP_CONN;

	if (write(sock, &r, sizeof(r)) != sizeof(r))
		return -1;
	return 0;
}

static int
fcgi_send_param(int sock, int id, const char *name, const char *value)
{
	struct fcgi_header	h;
        uint32_t		namlen, vallen, padlen;
	uint8_t			s[8];
	size_t			size;
	char			padding[8] = { 0 };

	namlen = strlen(name);
	vallen = strlen(value);
	size = namlen + vallen + 8; /* 4 for the sizes */
	padlen = (8 - (size & 0x7)) & 0x7;

	s[0] = ( namlen >> 24)         | 0x80;
	s[1] = ((namlen >> 16) & 0xFF);
	s[2] = ((namlen >>  8) & 0xFF);
	s[3] = ( namlen        & 0xFF);

	s[4] = ( vallen >> 24)         | 0x80;
	s[5] = ((vallen >> 16) & 0xFF);
	s[6] = ((vallen >>  8) & 0xFF);
	s[7] = ( vallen        & 0xFF);

	prepare_header(&h, FCGI_PARAMS, id, size, padlen);

	if (write(sock, &h, sizeof(h))   != sizeof(h) ||
	    write(sock, s, sizeof(s))    != sizeof(s) ||
	    write(sock, name, namlen)    != namlen    ||
	    write(sock, value, vallen)   != vallen    ||
	    write(sock, padding, padlen) != padlen)
		return -1;

	return 0;
}

static int
fcgi_end_param(int sock, int id)
{
	struct fcgi_header h;

	prepare_header(&h, FCGI_PARAMS, id, 0, 0);
	if (write(sock, &h, sizeof(h)) != sizeof(h))
		return -1;

	prepare_header(&h, FCGI_STDIN, id, 0, 0);
	if (write(sock, &h, sizeof(h)) != sizeof(h))
		return -1;

	return 0;
}

static int
fcgi_abort_request(int sock, int id)
{
	struct fcgi_header h;

	prepare_header(&h, FCGI_ABORT_REQUEST, id, 0, 0);
	if (write(sock, &h, sizeof(h)) != sizeof(h))
		return -1;

	return 0;
}

static int
must_read(int sock, char *d, size_t len)
{
	ssize_t r;

#if DEBUG_FCGI
	if (debug_socket == -1) {
		struct sockaddr_un addr;

		if ((debug_socket = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
			err(1, "socket");

		memset(&addr, 0, sizeof(addr));
		addr.sun_family = AF_UNIX;
		strlcpy(addr.sun_path, "./debug.sock", sizeof(addr.sun_path));
		if (connect(debug_socket, (struct sockaddr*)&addr, sizeof(addr))
		    == -1)
			err(1, "connect");
	}
#endif

	for (;;) {
		switch (r = read(sock, d, len)) {
		case -1:
		case 0:
			return -1;
		default:
#if DEBUG_FCGI
			write(debug_socket, d, r);
#endif

			if (r == (ssize_t)len)
				return 0;
			len -= r;
			d += r;
		}
	}
}

static int
fcgi_read_header(int sock, struct fcgi_header *h)
{
	if (must_read(sock, (char*)h, sizeof(*h)) == -1)
		return -1;
	if (h->version != FCGI_VERSION_1) {
		errno = EINVAL;
		return -1;
	}
	return 0;
}

static inline int
recid(struct fcgi_header *h)
{
	return h->req_id0 + (h->req_id1 << 8) - 1;
}

static inline int
reclen(struct fcgi_header *h)
{
	return h->content_len0 + (h->content_len1 << 8);
}

static void
copy_mbuf(int fd, short ev, void *d)
{
	struct client	*c = d;
	struct mbuf	*mbuf;
	size_t		 len;
	ssize_t		 r;
	char		*data;

        for (;;) {
		mbuf = TAILQ_FIRST(&c->mbufhead);
		if (mbuf == NULL)
			break;

		len = mbuf->len - mbuf->off;
		data = mbuf->data + mbuf->off;
		switch (r = tls_write(c->ctx, data, len)) {
		case -1:
			/*
			 * Can't close_conn here.  The application
			 * needs to be informed first, otherwise it
			 * can interfere with future connections.
			 * Check also that we're not doing recursion
			 * (copy_mbuf -> handle_fcgi -> copy_mbuf ...)
			 */
			if (c->next != NULL)
				goto end;
			fcgi_abort_request(0, c->id);
			return;
		case TLS_WANT_POLLIN:
			event_once(c->fd, EV_READ, &copy_mbuf, c, NULL);
			return;
		case TLS_WANT_POLLOUT:
			event_once(c->fd, EV_WRITE, &copy_mbuf, c, NULL);
			return;
		}
		mbuf->off += r;

		if (mbuf->off == mbuf->len) {
			TAILQ_REMOVE(&c->mbufhead, mbuf, mbufs);
			free(mbuf);
		}
	}

end:
	if (c->next != NULL)
		c->next(0, 0, c);
}

static int
consume(int fd, size_t len)
{
	size_t	l;
	char	buf[64];

	while (len != 0) {
		if ((l = len) > sizeof(buf))
			l =  sizeof(buf);
		if (must_read(fd, buf, l) == -1)
                        return 0;
		len -= l;
	}

	return 1;
}

static void
close_all(struct fcgi *f)
{
	size_t i;
	struct client *c;

	for (i = 0; i < MAX_USERS; i++) {
		c = &clients[i];

		if (c->fcgi != f->id)
			continue;

		if (c->code != 0)
			close_conn(0, 0, c);
		else
			start_reply(c, CGI_ERROR, "CGI error");
	}

	fcgi_close_backend(f);
}

void
fcgi_close_backend(struct fcgi *f)
{
	event_del(&f->e);
	close(f->fd);
	f->fd = -1;
	f->pending = 0;
	f->s = FCGI_OFF;
}

void
handle_fcgi(int sock, short event, void *d)
{
	struct fcgi		*f = d;
	struct fcgi_header	 h;
	struct fcgi_end_req_body end;
	struct client		*c;
	struct mbuf		*mbuf;
	size_t			 len;

	if (fcgi_read_header(sock, &h) == -1)
		goto err;

	c = try_client_by_id(recid(&h));
	if (c == NULL || c->fcgi != f->id)
		goto err;

	len = reclen(&h);

	switch (h.type) {
	case FCGI_END_REQUEST:
		if (len != sizeof(end))
			goto err;
		if (must_read(sock, (char*)&end, sizeof(end)) == -1)
			goto err;
		/* TODO: do something with the status? */

		f->pending--;
		c->fcgi = -1;
		c->next = close_conn;
		event_once(c->fd, EV_WRITE, &copy_mbuf, c, NULL);
		break;

	case FCGI_STDERR:
		/* discard stderr (for now) */
		if (!consume(sock, len))
			goto err;
		break;

	case FCGI_STDOUT:
		if ((mbuf = calloc(1, sizeof(*mbuf) + len)) == NULL)
			fatal("calloc");
		mbuf->len = len;
                if (must_read(sock, mbuf->data, len) == -1) {
			free(mbuf);
			goto err;
		}

		if (TAILQ_EMPTY(&c->mbufhead)) {
			TAILQ_INSERT_HEAD(&c->mbufhead, mbuf, mbufs);
			event_once(c->fd, EV_WRITE, &copy_mbuf, c, NULL);
		} else
			TAILQ_INSERT_TAIL(&c->mbufhead, mbuf, mbufs);
		break;

	default:
		log_err(NULL, "got invalid fcgi record (type=%d)", h.type);
                goto err;
	}

	if (!consume(sock, h.padding))
		goto err;

	if (f->pending == 0 && shutting_down)
		fcgi_close_backend(f);

	return;

err:
	close_all(f);
}

void
send_fcgi_req(struct fcgi *f, struct client *c)
{
	char		 addr[NI_MAXHOST], buf[22];
	int		 e;
	time_t		 tim;
	struct tm	 tminfo;
	struct envlist	*p;

	f->pending++;

	e = getnameinfo((struct sockaddr*)&c->addr, sizeof(c->addr),
	    addr, sizeof(addr),
	    NULL, 0,
	    NI_NUMERICHOST);
	if (e != 0)
		fatal("getnameinfo failed");

	c->next = NULL;

	fcgi_begin_request(f->fd, c->id);
	fcgi_send_param(f->fd, c->id, "GATEWAY_INTERFACE", "CGI/1.1");
	fcgi_send_param(f->fd, c->id, "GEMINI_URL_PATH", c->iri.path);
	fcgi_send_param(f->fd, c->id, "QUERY_STRING", c->iri.query);
	fcgi_send_param(f->fd, c->id, "REMOTE_ADDR", addr);
	fcgi_send_param(f->fd, c->id, "REMOTE_HOST", addr);
	fcgi_send_param(f->fd, c->id, "REQUEST_METHOD", "");
	fcgi_send_param(f->fd, c->id, "SERVER_NAME", c->iri.host);
	fcgi_send_param(f->fd, c->id, "SERVER_PROTOCOL", "GEMINI");
	fcgi_send_param(f->fd, c->id, "SERVER_SOFTWARE", GMID_VERSION);

	if (tls_peer_cert_provided(c->ctx)) {
		fcgi_send_param(f->fd, c->id, "AUTH_TYPE", "CERTIFICATE");
		fcgi_send_param(f->fd, c->id, "REMOTE_USER",
		    tls_peer_cert_subject(c->ctx));
		fcgi_send_param(f->fd, c->id, "TLS_CLIENT_ISSUER",
		    tls_peer_cert_issuer(c->ctx));
		fcgi_send_param(f->fd, c->id, "TLS_CLIENT_HASH",
		    tls_peer_cert_hash(c->ctx));
		fcgi_send_param(f->fd, c->id, "TLS_VERSION",
		    tls_conn_version(c->ctx));
		fcgi_send_param(f->fd, c->id, "TLS_CIPHER",
		    tls_conn_cipher(c->ctx));

		snprintf(buf, sizeof(buf), "%d",
		    tls_conn_cipher_strength(c->ctx));
		fcgi_send_param(f->fd, c->id, "TLS_CIPHER_STRENGTH", buf);

		tim = tls_peer_cert_notbefore(c->ctx);
		strftime(buf, sizeof(buf), "%FT%TZ",
		    gmtime_r(&tim, &tminfo));
		fcgi_send_param(f->fd, c->id, "TLS_CLIENT_NOT_BEFORE", buf);

		tim = tls_peer_cert_notafter(c->ctx);
		strftime(buf, sizeof(buf), "%FT%TZ",
		    gmtime_r(&tim, &tminfo));
		fcgi_send_param(f->fd, c->id, "TLS_CLIENT_NOT_AFTER", buf);

		TAILQ_FOREACH(p, &c->host->params, envs) {
			fcgi_send_param(f->fd, c->id, p->name, p->value);
		}
	} else
		fcgi_send_param(f->fd, c->id, "AUTH_TYPE", "");

	if (fcgi_end_param(f->fd, c->id) == -1)
		close_all(f);
}
