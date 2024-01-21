/*
 * Copyright (c) 2021, 2023 Omar Polo <op@omarpolo.com>
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

#include "log.h"
#include "proc.h"

#ifndef nitems
#define nitems(_a) (sizeof((_a)) / sizeof((_a)[0]))
#endif

static int logfd = -1;
static int log_to_syslog = 1;
static int facility = LOG_DAEMON;

static void logger_init(struct privsep *, struct privsep_proc *, void *);
static void logger_shutdown(void);
static int logger_dispatch_parent(int, struct privsep_proc *, struct imsg *);
static int logger_dispatch_server(int, struct privsep_proc *, struct imsg *);

static struct privsep_proc procs[] = {
	{ "parent",	PROC_PARENT,	logger_dispatch_parent },
	{ "server",	PROC_SERVER,	logger_dispatch_server },
};

void
logger(struct privsep *ps, struct privsep_proc *p)
{
	proc_run(ps, p, procs, nitems(procs), logger_init, NULL);
}

static void
logger_init(struct privsep *ps, struct privsep_proc *p, void *arg)
{
	p->p_shutdown = logger_shutdown;

	openlog(getprogname(), LOG_NDELAY, LOG_DAEMON);
	tzset();

	sandbox_logger_process();
}

static void
logger_shutdown(void)
{
	closelog();
	if (logfd != -1)
		close(logfd);
}

static int
logger_dispatch_parent(int fd, struct privsep_proc *p, struct imsg *imsg)
{
	switch (imsg->hdr.type) {
	case IMSG_LOG_FACILITY:
		if (imsg_get_data(imsg, &facility, sizeof(facility)) == -1)
			fatal("corrupted IMSG_LOG_SYSLOG");
		break;
	case IMSG_LOG_SYSLOG:
		if (imsg_get_data(imsg, &log_to_syslog,
		    sizeof(log_to_syslog)) == -1)
			fatal("corrupted IMSG_LOG_SYSLOG");
		break;
	case IMSG_LOG_ACCESS:
		if (logfd != -1)
			close(logfd);
		logfd = imsg_get_fd(imsg);
		break;
	default:
		return -1;
	}

	return 0;
}

static int
logger_dispatch_server(int fd, struct privsep_proc *p, struct imsg *imsg)
{
	char *msg;
	size_t datalen = 0;
	struct ibuf ibuf;

	switch (imsg->hdr.type) {
	case IMSG_LOG_REQUEST:
		if (imsg_get_ibuf(imsg, &ibuf) == -1 ||
		    (datalen = ibuf_size(&ibuf)) == 0)
			fatal("got invalid IMSG_LOG_REQUEST");
		msg = ibuf_data(&ibuf);
		msg[datalen - 1] = '\0';
		if (logfd != -1)
			dprintf(logfd, "%s\n", msg);
		if (log_to_syslog)
			syslog(facility | LOG_NOTICE, "%s", msg);
		break;
	default:
		return -1;
	}

	return 0;
}
