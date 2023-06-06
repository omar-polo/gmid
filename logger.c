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
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include "logger.h"
#include "log.h"

static struct event imsgev;

static FILE *log;

static void	handle_imsg_quit(struct imsgbuf*, struct imsg*, size_t);
static void	handle_imsg_log(struct imsgbuf*, struct imsg*, size_t);
static void	handle_imsg_log_type(struct imsgbuf*, struct imsg*, size_t);
static void	handle_dispatch_imsg(int, short, void*);

static imsg_handlerfn *handlers[] = {
	[IMSG_QUIT] = handle_imsg_quit,
	[IMSG_LOG] = handle_imsg_log,
	[IMSG_LOG_REQUEST] = handle_imsg_log,
	[IMSG_LOG_TYPE] = handle_imsg_log_type,
};

void
log_request(struct client *c, char *meta, size_t l)
{
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV], b[GEMINI_URL_LEN];
	char *fmted;
	const char *t;
	size_t len;
	int ec;

	len = sizeof(c->addr);
	ec = getnameinfo((struct sockaddr*)&c->addr, len,
	    hbuf, sizeof(hbuf),
	    sbuf, sizeof(sbuf),
	    NI_NUMERICHOST | NI_NUMERICSERV);
	if (ec != 0)
		fatalx("getnameinfo: %s", gai_strerror(ec));

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

		if (*c->iri.path != '/')
			strlcat(b, "/", sizeof(b));
		strlcat(b, c->iri.path, sizeof(b)); /* TODO: sanitize UTF8 */
		if (*c->iri.query != '\0') {	    /* TODO: sanitize UTF8 */
			strlcat(b, "?", sizeof(b));
			strlcat(b, c->iri.query, sizeof(b));
		}
	} else {
		if ((t = c->req) == NULL)
			t = "";
		strlcpy(b, t, sizeof(b));
	}

	if ((t = memchr(meta, '\r', l)) == NULL)
		t = meta + len;

	ec = asprintf(&fmted, "%s:%s GET %s %.*s", hbuf, sbuf, b,
	    (int)(t-meta), meta);
	if (ec < 0)
		err(1, "asprintf");

	imsg_compose(&logibuf, IMSG_LOG_REQUEST, 0, 0, -1, fmted, ec + 1);
	imsg_flush(&logibuf);

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
	char	*msg;

	msg = imsg->data;
	msg[datalen-1] = '\0';

	if (log != NULL)
		fprintf(log, "%s\n", msg);
	else
		syslog(LOG_DAEMON | LOG_NOTICE, "%s", msg);
}

static void
handle_imsg_log_type(struct imsgbuf *ibuf, struct imsg *imsg, size_t datalen)
{
	if (log != NULL && log != stderr) {
		fflush(log);
		fclose(log);
	}
	log = NULL;

	if (imsg->fd != -1) {
		if ((log = fdopen(imsg->fd, "a")) == NULL) {
			syslog(LOG_DAEMON | LOG_ERR, "fdopen: %s",
			    strerror(errno));
			exit(1);
		}
	}
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
	log = stderr;

	event_init();

	event_set(&imsgev, fd, EV_READ | EV_PERSIST, &handle_dispatch_imsg, ibuf);
	event_add(&imsgev, NULL);

	sandbox_logger_process();

	event_dispatch();

	closelog();

	return 0;
}
