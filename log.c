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
#include <sys/uio.h>

#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

static struct event imsgev;

static void	handle_imsg_quit(struct imsgbuf*, struct imsg*, size_t);
static void	handle_imsg_log(struct imsgbuf*, struct imsg*, size_t);
static void	handle_dispatch_imsg(int, short, void*);

static imsg_handlerfn *handlers[] = {
	[IMSG_QUIT] = handle_imsg_quit,
	[IMSG_LOG] = handle_imsg_log,
};

static inline void
print_date(void)
{
	struct tm	tminfo;
	time_t		t;
	char		buf[20];

	time(&t);
	strftime(buf, sizeof(buf), "%F %T",
	    localtime_r(&t, &tminfo));
	fprintf(stderr, "[%s] ", buf);
}

void
fatal(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	if (conf.foreground) {
		print_date();
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
	imsg_compose(&logibuf, IMSG_LOG, 0, 0, -1, msg, len);
	/* XXX: use event_once() */
	imsg_flush(&logibuf);
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
handle_imsg_quit(struct imsgbuf *ibuf, struct imsg *imsg, size_t datalen)
{
	event_loopbreak();
}

static void
handle_imsg_log(struct imsgbuf *ibuf, struct imsg *imsg, size_t datalen)
{
	char *msg;

	msg = imsg->data;
	msg[datalen-1] = '\0';

	if (conf.foreground) {
		print_date();
		fprintf(stderr, "%s\n", msg);
	} else
		syslog(LOG_DAEMON, "%s", msg);
}

static void
handle_dispatch_imsg(int fd, short ev, void *d)
{
	struct imsgbuf *ibuf = d;
	dispatch_imsg(ibuf, handlers, sizeof(handlers));
}

int
logger_main(int fd, struct imsgbuf *ibuf)
{
	event_init();

	event_set(&imsgev, fd, EV_READ | EV_PERSIST, &handle_dispatch_imsg, ibuf);
	event_add(&imsgev, NULL);

	sandbox_logger_process();

	event_dispatch();

	return 0;
}
