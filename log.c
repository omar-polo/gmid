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

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/uio.h>

#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

struct imsgbuf parent_ibuf, child_ibuf;
struct event sigusr2, inlog;
int logfd;

static void handle_log(int, short, void*);
static int logger_main(int, struct imsgbuf*);

void
fatal(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	if (conf.foreground) {
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
	} else
		vsyslog(LOG_DAEMON | LOG_CRIT, fmt, ap);

	va_end(ap);
	exit(1);
}

static inline int
should_log(int priority)
{
	switch (priority) {
	case LOG_ERR:
		return 1;
	case LOG_WARNING:
		return 1;
	case LOG_NOTICE:
		return conf.verbose >= 1;
	case LOG_INFO:
		return conf.verbose >= 2;
	case LOG_DEBUG:
		return conf.verbose >= 3;
	default:
		return 0;
	}
}

static inline void
send_log(const char *msg, size_t len)
{
	imsg_compose(&parent_ibuf, 0, 0, 0, -1, msg, len);
	/* XXX: use event_once() */
	imsg_flush(&parent_ibuf);
}

static inline void
vlog(int priority, struct client *c,
    const char *fmt, va_list ap)
{
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	char *fmted, *s;
	size_t len;
	int ec;

	if (!should_log(priority))
		return;

	if (c != NULL) {
		len = sizeof(c->addr);
		ec = getnameinfo((struct sockaddr*)&c->addr, len,
		    hbuf, sizeof(hbuf),
		    sbuf, sizeof(sbuf),
		    NI_NUMERICHOST | NI_NUMERICSERV);
		if (ec != 0)
			fatal("getnameinfo: %s", gai_strerror(ec));
	}

	if (vasprintf(&fmted, fmt, ap) == -1)
		fatal("vasprintf: %s", strerror(errno));

        if (c == NULL)
		ec = asprintf(&s, "internal: %s", fmted);
	else
		ec = asprintf(&s, "%s:%s %s", hbuf, sbuf, fmted);

	if (ec < 0)
		fatal("asprintf: %s", strerror(errno));

	send_log(s, ec+1);

	free(fmted);
	free(s);
}

void
log_err(struct client *c, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vlog(LOG_ERR, c, fmt, ap);
	va_end(ap);
}

void
log_warn(struct client *c, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vlog(LOG_WARNING, c, fmt, ap);
	va_end(ap);
}

void
log_notice(struct client *c, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vlog(LOG_NOTICE, c, fmt, ap);
	va_end(ap);
}

void
log_info(struct client *c, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vlog(LOG_INFO, c, fmt, ap);
	va_end(ap);
}

void
log_debug(struct client *c, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vlog(LOG_DEBUG, c, fmt, ap);
	va_end(ap);
}

/* strchr, but with a bound */
static char *
gmid_strnchr(char *s, int c, size_t len)
{
	size_t i;

	for (i = 0; i < len; ++i)
		if (s[i] == c)
			return &s[i];
	return NULL;
}

void
log_request(struct client *c, char *meta, size_t l)
{
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV], b[GEMINI_URL_LEN];
	char *t, *fmted;
	size_t len;
	int ec;

	len = sizeof(c->addr);
	ec = getnameinfo((struct sockaddr*)&c->addr, len,
	    hbuf, sizeof(hbuf),
	    sbuf, sizeof(sbuf),
	    NI_NUMERICHOST | NI_NUMERICSERV);
	if (ec != 0)
		fatal("getnameinfo: %s", gai_strerror(ec));

	if (c->iri.schema != NULL) {
		/* serialize the IRI */
		strlcpy(b, c->iri.schema, sizeof(b));
		strlcat(b, "://", sizeof(b));

		/* log the decoded host name, but if it was invalid
		 * use the raw one. */
		if (*c->domain != '\0')
			strlcat(b, c->domain, sizeof(b));
		else
			strlcat(b, c->iri.host, sizeof(b));

		strlcat(b, "/", sizeof(b));
		strlcat(b, c->iri.path, sizeof(b)); /* TODO: sanitize UTF8 */
		if (*c->iri.query != '\0') {	    /* TODO: sanitize UTF8 */
			strlcat(b, "?", sizeof(b));
			strlcat(b, c->iri.query, sizeof(b));
		}
	} else {
		strlcpy(b, c->req, sizeof(b));
	}

	if ((t = gmid_strnchr(meta, '\r', l)) == NULL)
		t = meta + len;

	ec = asprintf(&fmted, "%s:%s GET %s %.*s", hbuf, sbuf, b,
	    (int)(t-meta), meta);
	if (ec < 0)
		err(1, "asprintf");
	send_log(fmted, ec+1);
	free(fmted);
}



static void
handle_log(int fd, short ev, void *d)
{
	struct imsgbuf	*ibuf = d;
	struct imsg	 imsg;
	ssize_t		 n, datalen;
	char		*msg;

	if ((n = imsg_read(ibuf)) == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return;
                err(1, "imsg_read");
	}
	if (n == 0)
		errx(1, "connection lost?");

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			err(1, "read error");
		if (n == 0)
			return;

		datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
		msg = imsg.data;
		msg[datalen] = '\0';

		/* ignore imsg.hdr.type for now */
		if (conf.foreground)
			fprintf(stderr, "%s\n", msg);
		else
			syslog(LOG_DAEMON, "%s", msg);

		imsg_free(&imsg);
	}
}

static int
logger_main(int fd, struct imsgbuf *ibuf)
{
	event_init();

	event_set(&inlog, fd, EV_READ | EV_PERSIST, &handle_log, ibuf);
	event_add(&inlog, NULL);

#ifdef __OpenBSD__
	if (pledge("stdio", NULL) == -1)
		err(1, "pledge");
#endif

	event_dispatch();

	return 0;
}

void
logger_init(void)
{
	int p[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, p) == -1)
		err(1, "socketpair");

	switch (fork()) {
	case -1:
		err(1, "fork");
	case 0:
		logfd = p[1];
		close(p[0]);
		setproctitle("logger");
		imsg_init(&child_ibuf, p[1]);
		drop_priv();
		_exit(logger_main(p[1], &child_ibuf));
	default:
		logfd = p[0];
		close(p[1]);
		imsg_init(&parent_ibuf, p[0]);
		return;
	}
}
