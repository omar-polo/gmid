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

#include <errno.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

#include "gmid.h"

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

static void
do_log(int priority, struct client *c,
    const char *fmt, va_list ap)
{
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	char *fmted, *s;
	size_t len;
	int ec;

	if (!should_log(priority))
		return;

	if (c == NULL) {
		strncpy(hbuf, "<internal>", sizeof(hbuf));
		sbuf[0] = '\0';
	} else {
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

	if (conf.foreground)
		fprintf(stderr, "%s:%s %s\n", hbuf, sbuf, fmted);
	else {
		if (asprintf(&s, "%s:%s %s", hbuf, sbuf, fmted) == -1)
			fatal("asprintf: %s", strerror(errno));
		syslog(priority | LOG_DAEMON, "%s", s);
		free(s);
	}

	free(fmted);
}

void
log_err(struct client *c, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	do_log(LOG_ERR, c, fmt, ap);
	va_end(ap);
}

void
log_warn(struct client *c, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	do_log(LOG_WARNING, c, fmt, ap);
	va_end(ap);
}

void
log_notice(struct client *c, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	do_log(LOG_NOTICE, c, fmt, ap);
	va_end(ap);
}

void
log_info(struct client *c, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	do_log(LOG_INFO, c, fmt, ap);
	va_end(ap);
}

void
log_debug(struct client *c, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	do_log(LOG_DEBUG, c, fmt, ap);
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
	char *t;
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

	if (conf.foreground)
		fprintf(stderr, "%s:%s GET %s %.*s\n", hbuf, sbuf, b,
		    (int)(t - meta), meta);
	else
		syslog(LOG_INFO | LOG_DAEMON, "%s:%s GET %s %.*s",
		    hbuf, sbuf, b, (int)(t - meta), meta);
}
