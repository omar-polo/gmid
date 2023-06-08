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
#include "proc.h"

#ifndef nitems
#define nitems(_a) (sizeof((_a)) / sizeof((_a)[0]))
#endif

static FILE *log;

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
	log = stderr;
	sandbox_logger_process();
}

static void
logger_shutdown(void)
{
	closelog();
	if (log && log != stderr) {
		fflush(log);
		fclose(log);
	}
}

static int
logger_dispatch_parent(int fd, struct privsep_proc *p, struct imsg *imsg)
{
	switch (imsg->hdr.type) {
	case IMSG_LOG_TYPE:
		if (log != NULL && log != stderr) {
			fflush(log);
			fclose(log);
		}
		log = NULL;

		if (imsg->fd != -1) {
			if ((log = fdopen(imsg->fd, "a")) == NULL)
				fatal("fdopen");
		}
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
	size_t datalen;

	switch (imsg->hdr.type) {
	case IMSG_LOG_REQUEST:
		msg = imsg->data;
		datalen = IMSG_DATA_SIZE(imsg);
		if (datalen == 0)
			fatal("got invalid IMSG_LOG_REQUEST");
		msg[datalen - 1] = '\0';
		if (log != NULL)
			fprintf(log, "%s\n", msg);
		else
			syslog(LOG_DAEMON | LOG_NOTICE, "%s", msg);
		break;
	default:
		return -1;
	}

	return 0;
}
