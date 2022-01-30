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

#include <ctype.h>
#include <errno.h>
#include <string.h>

#define MIN(a, b)	((a) < (b) ? (a) : (b))

static struct timeval handshake_timeout = { 5, 0 };

static void	proxy_tls_readcb(int, short, void *);
static void	proxy_tls_writecb(int, short, void *);
static void	proxy_read(struct bufferevent *, void *);
static void	proxy_write(struct bufferevent *, void *);
static void	proxy_error(struct bufferevent *, short, void *);

static void
proxy_tls_readcb(int fd, short event, void *d)
{
	struct bufferevent	*bufev = d;
	struct client		*c = bufev->cbarg;
	char			 buf[IBUF_READ_SIZE];
	int			 what = EVBUFFER_READ;
	int			 howmuch = IBUF_READ_SIZE;
	int			 res;
	ssize_t			 ret;
	size_t			 len;

	if (event == EV_TIMEOUT) {
		what |= EVBUFFER_TIMEOUT;
		goto err;
	}

	if (bufev->wm_read.high != 0)
		howmuch = MIN(sizeof(buf), bufev->wm_read.high);

	switch (ret = tls_read(c->proxyctx, buf, howmuch)) {
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

	res = evbuffer_add(bufev->input, buf, len);
	if (res == -1) {
		what |= EVBUFFER_ERROR;
		goto err;
	}

	event_add(&bufev->ev_read, NULL);

	len = EVBUFFER_LENGTH(bufev->input);
	if (bufev->wm_read.low != 0 && len < bufev->wm_read.low)
		return;

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
proxy_tls_writecb(int fd, short event, void *d)
{
	struct bufferevent	*bufev = d;
	struct client		*c = bufev->cbarg;
	ssize_t			 ret;
	size_t			 len;
	short			 what = EVBUFFER_WRITE;

	if (event & EV_TIMEOUT) {
		what |= EVBUFFER_TIMEOUT;
		goto err;
	}

	if (EVBUFFER_LENGTH(bufev->output) != 0) {
		ret = tls_write(c->proxyctx, EVBUFFER_DATA(bufev->output),
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
	(*bufev->errorcb)(bufev, what, bufev->cbarg);
}

static void
proxy_read(struct bufferevent *bev, void *d)
{
	struct client	*c = d;
	struct evbuffer	*src = EVBUFFER_INPUT(bev);
	char		*hdr;
	size_t		 len;
	int		 code;

	/* intercept the header */
	if (c->code == 0) {
		hdr = evbuffer_readln(src, &len, EVBUFFER_EOL_CRLF_STRICT);
		if (hdr == NULL) {
			/* max reply + \r\n */
			if (EVBUFFER_LENGTH(src) > 1029) {
				log_warn(c, "upstream server is trying to "
				    "send a header that's too long.");
				proxy_error(bev, EVBUFFER_READ, c);
			}

			/* wait a bit */
			return;
		}

		if (len < 3 || len > 1029 ||
		    !isdigit(hdr[0]) ||
		    !isdigit(hdr[1]) ||
		    !isspace(hdr[2])) {
			free(hdr);
			log_warn(c, "upstream server is trying to send a "
			    "header that's too long.");
			proxy_error(bev, EVBUFFER_READ, c);
			return;
		}

		c->header = hdr;
		code = (hdr[0] - '0') * 10 + (hdr[1] - '0');

		if (code < 10 || code >= 70) {
			log_warn(c, "upstream server is trying to send an "
			    "invalid reply code: %d", code);
			proxy_error(bev, EVBUFFER_READ, c);
			return;
		}

		start_reply(c, code, hdr + 3);

		if (c->code < 20 || c->code > 29) {
			proxy_error(bev, EVBUFFER_EOF, c);
			return;
		}
	}

	bufferevent_write_buffer(c->bev, src);
}

static void
proxy_write(struct bufferevent *bev, void *d)
{
	struct evbuffer	*dst = EVBUFFER_OUTPUT(bev);

	/* request successfully sent */
	if (EVBUFFER_LENGTH(dst) == 0)
		bufferevent_disable(bev, EV_WRITE);
}

static void
proxy_error(struct bufferevent *bev, short error, void *d)
{
	struct client	*c = d;

	/*
	 * If we're here it means that some kind of non-recoverable
	 * error appened.
	 */

	bufferevent_free(bev);
	c->proxybev = NULL;

	tls_free(c->proxyctx);
	c->proxyctx = NULL;

	close(c->pfd);
	c->pfd = -1;

	/* EOF and no header */
	if (c->code == 0) {
		start_reply(c, PROXY_ERROR, "protocol error");
		return;
	}

	c->type = REQUEST_DONE;
	client_write(c->bev, c);
}

static void
proxy_enqueue_req(struct client *c)
{
	struct proxy *p = c->proxy;
	struct evbuffer	*evb;
	char		 iribuf[GEMINI_URL_LEN];

	c->proxybev = bufferevent_new(c->pfd, proxy_read, proxy_write,
	    proxy_error, c);
	if (c->proxybev == NULL)
		fatal("can't allocate bufferevent: %s", strerror(errno));

	if (!p->notls) {
		event_set(&c->proxybev->ev_read, c->pfd, EV_READ,
		    proxy_tls_readcb, c->proxybev);
		event_set(&c->proxybev->ev_write, c->pfd, EV_WRITE,
		    proxy_tls_writecb, c->proxybev);

#if HAVE_LIBEVENT2
		evbuffer_unfreeze(c->proxybev->input, 0);
		evbuffer_unfreeze(c->proxybev->output, 1);
#endif
	}

	serialize_iri(&c->iri, iribuf, sizeof(iribuf));

	evb = EVBUFFER_OUTPUT(c->proxybev);
	evbuffer_add_printf(evb, "%s\r\n", iribuf);

	bufferevent_enable(c->proxybev, EV_READ|EV_WRITE);
}

static void
proxy_handshake(int fd, short event, void *d)
{
	struct client	*c = d;

	if (event == EV_TIMEOUT) {
		start_reply(c, PROXY_ERROR, "timeout");
		return;
	}

	switch (tls_handshake(c->proxyctx)) {
	case TLS_WANT_POLLIN:
		event_set(&c->proxyev, fd, EV_READ, proxy_handshake, c);
		event_add(&c->proxyev, &handshake_timeout);
		return;
	case TLS_WANT_POLLOUT:
		event_set(&c->proxyev, fd, EV_WRITE, proxy_handshake, c);
		event_add(&c->proxyev, &handshake_timeout);
		return;
	case -1:
		log_warn(c, "handshake with proxy failed: %s",
		    tls_error(c->proxyctx));
		start_reply(c, PROXY_ERROR, "handshake failed");
		return;
	}

	c->proxyevset = 0;
	proxy_enqueue_req(c);
}

static int
proxy_setup_tls(struct client *c)
{
	struct proxy *p = c->proxy;
	struct tls_config *conf = NULL;
	const char *hn;

	if ((conf = tls_config_new()) == NULL)
		return -1;

	if (p->noverifyname)
		tls_config_insecure_noverifyname(conf);

	tls_config_insecure_noverifycert(conf);
	tls_config_set_protocols(conf, p->protocols);

	if (p->cert != NULL) {
		int r;

		r = tls_config_set_cert_mem(conf, p->cert, p->certlen);
		if (r == -1)
			goto err;

		r = tls_config_set_key_mem(conf, p->key, p->keylen);
		if (r == -1)
			goto err;
	}

	if ((c->proxyctx = tls_client()) == NULL)
		goto err;

	if (tls_configure(c->proxyctx, conf) == -1)
		goto err;

	if ((hn = p->sni) == NULL)
		hn = p->host;
	if (tls_connect_socket(c->proxyctx, c->pfd, hn) == -1)
		goto err;

	c->proxyevset = 1;
	event_set(&c->proxyev, c->pfd, EV_READ|EV_WRITE, proxy_handshake, c);
	event_add(&c->proxyev, &handshake_timeout);

	tls_config_free(conf);
	return 0;

err:
	tls_config_free(conf);
	if (c->proxyctx != NULL) {
		tls_free(c->proxyctx);
		c->proxyctx = NULL;
	}
	return -1;
}

int
proxy_init(struct client *c)
{
	struct proxy *p = c->proxy;

	if (!p->notls && proxy_setup_tls(c) == -1)
		return -1;
	else if (p->notls)
		proxy_enqueue_req(c);

	c->type = REQUEST_PROXY;

	return 0;
}
