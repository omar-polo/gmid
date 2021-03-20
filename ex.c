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

#include <err.h>
#include <errno.h>

#include <event.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <string.h>

static void	handle_imsg_cgi_req(struct imsgbuf*, struct imsg*, size_t);
static void	handle_imsg_quit(struct imsgbuf*, struct imsg*, size_t);
static void	handle_dispatch_imsg(int, short, void*);

static imsg_handlerfn *handlers[] = {
	[IMSG_CGI_REQ] = handle_imsg_cgi_req,
	[IMSG_QUIT] = handle_imsg_quit,
};

static inline void
safe_setenv(const char *name, const char *val)
{
	if (val == NULL)
		val = "";
	setenv(name, val, 1);
}

static char *
xasprintf(const char *fmt, ...)
{
	va_list ap;
	char *s;

	va_start(ap, fmt);
	if (vasprintf(&s, fmt, ap) == -1)
		s = NULL;
	va_end(ap);

	return s;
}

static void
do_exec(const char *ex, const char *spath, char *query)
{
	char **argv, buf[PATH_MAX], *sname, *t;
	size_t i, n;

	strlcpy(buf, spath, sizeof(buf));
	sname = basename(buf);

	if (query == NULL || strchr(query, '=') != NULL) {
		if ((argv = calloc(2, sizeof(char*))) == NULL)
			err(1, "calloc");
		argv[0] = sname;
		execvp(ex, argv);
		warn("execvp: %s", argv[0]);
		return;
	}

	n = 1;
	for (t = query ;; t++, n++) {
		if ((t = strchr(t, '+')) == NULL)
			break;
	}

	if ((argv = calloc(n+2, sizeof(char*))) == NULL)
		err(1, "calloc");

	argv[0] = sname;
	for (i = 0; i < n; ++i) {
		t = strchr(query, '+');
		if (t != NULL)
			*t = '\0';
		argv[i+1] = pct_decode_str(query);
		query = t+1;
	}

	execvp(ex, argv);
	warn("execvp: %s", argv[0]);
}

static inline void
setenv_time(const char *var, time_t t)
{
	char timebuf[21];
	struct tm tminfo;

	if (t == -1)
		return;

	strftime(timebuf, sizeof(timebuf), "%FT%TZ",
	    gmtime_r(&t, &tminfo));
	setenv(var, timebuf, 1);
}

/* fd or -1 on error */
static int
launch_cgi(struct iri *iri, struct cgireq *req, struct vhost *vhost)
{
	int p[2];		/* read end, write end */

	if (pipe(p) == -1)
		return -1;

	switch (fork()) {
	case -1:
		return -1;

	case 0: {		/* child */
		char *ex, *pwd;
		char iribuf[GEMINI_URL_LEN];
		char path[PATH_MAX];

		close(p[0]);
		if (dup2(p[1], 1) == -1)
			goto childerr;

		ex = xasprintf("%s/%s", vhost->dir, req->spath);

		serialize_iri(iri, iribuf, sizeof(iribuf));

		safe_setenv("GATEWAY_INTERFACE", "CGI/1.1");
		safe_setenv("GEMINI_DOCUMENT_ROOT", vhost->dir);
		safe_setenv("GEMINI_SCRIPT_FILENAME",
		    xasprintf("%s/%s", vhost->dir, req->spath));
		safe_setenv("GEMINI_URL", iribuf);

		strlcpy(path, "/", sizeof(path));
		strlcat(path, req->spath, sizeof(path));
		safe_setenv("GEMINI_URL_PATH", path);

		if (*req->relpath != '\0') {
			strlcpy(path, "/", sizeof(path));
			strlcat(path, req->relpath, sizeof(path));
			safe_setenv("PATH_INFO", path);

			strlcpy(path, vhost->dir, sizeof(path));
			strlcat(path, "/", sizeof(path));
			strlcat(path, req->relpath, sizeof(path));
			safe_setenv("PATH_TRANSLATED", path);
		}

		safe_setenv("QUERY_STRING", iri->query);
		safe_setenv("REMOTE_ADDR", req->addr);
		safe_setenv("REMOTE_HOST", req->addr);
		safe_setenv("REQUEST_METHOD", "");

		strlcpy(path, "/", sizeof(path));
		strlcat(path, req->spath, sizeof(path));
		safe_setenv("SCRIPT_NAME", path);

		safe_setenv("SERVER_NAME", iri->host);

		snprintf(path, sizeof(path), "%d", conf.port);
		safe_setenv("SERVER_PORT", path);

		safe_setenv("SERVER_PROTOCOL", "GEMINI");
		safe_setenv("SERVER_SOFTWARE", "gmid/1.6");

		if (*req->subject != '\0')
			safe_setenv("AUTH_TYPE", "Certificate");
		else
			safe_setenv("AUTH_TYPE", "");

		safe_setenv("REMOTE_USER", req->subject);
		safe_setenv("TLS_CLIENT_ISSUER", req->issuer);
		safe_setenv("TLS_CLIENT_HASH", req->hash);
		setenv_time("TLS_CLIENT_NOT_AFTER", req->notafter);
		setenv_time("TLS_CLIENT_NOT_BEFORE", req->notbefore);

		strlcpy(path, ex, sizeof(path));

		pwd = dirname(path);
		if (chdir(pwd)) {
			warn("chdir");
			goto childerr;
		}

		do_exec(ex, req->spath, iri->query);
		goto childerr;
	}

	default:
		close(p[1]);
		mark_nonblock(p[0]);
		return p[0];
	}

childerr:
	dprintf(p[1], "%d internal server error\r\n", TEMP_FAILURE);
	_exit(1);
}

static void
handle_imsg_cgi_req(struct imsgbuf *ibuf, struct imsg *imsg, size_t datalen)
{
	struct cgireq	req;
	struct iri	iri;
	int		fd;

	if (datalen != sizeof(req))
		abort();

	memcpy(&req, imsg->data, datalen);

	iri.schema = req.iri_schema_off + req.buf;
	iri.host = req.iri_host_off + req.buf;
	iri.port = req.iri_port_off + req.buf;
	iri.path = req.iri_path_off + req.buf;
	iri.query = req.iri_query_off + req.buf;
	iri.fragment = req.iri_fragment_off + req.buf;

	/* patch the query, otherwise do_exec will always pass "" as
	 * first argument to the script. */
	if (*iri.query == '\0')
		iri.query = NULL;

	if (req.host_off > HOSTSLEN || hosts[req.host_off].domain == NULL)
		abort();

	fd = launch_cgi(&iri, &req, &hosts[req.host_off]);
	imsg_compose(ibuf, IMSG_CGI_RES, imsg->hdr.peerid, 0, fd, NULL, 0);
	imsg_flush(ibuf);
}

static void
handle_imsg_quit(struct imsgbuf *ibuf, struct imsg *imsg, size_t datalen)
{
	int i;

	(void)ibuf;
	(void)imsg;
	(void)datalen;

	for (i = 0; i < conf.prefork; ++i) {
		imsg_compose(&servibuf[i], IMSG_QUIT, 0, 0, -1, NULL, 0);
		imsg_flush(&exibuf);
		close(servibuf[i].fd);
	}

	event_loopbreak();
}

static void
handle_dispatch_imsg(int fd, short ev, void *d)
{
	struct imsgbuf *ibuf = d;
	dispatch_imsg(ibuf, handlers, sizeof(handlers));
}

int
executor_main(struct imsgbuf *ibuf)
{
	struct event	 evs[PROC_MAX], imsgev;
	int		 i;

	event_init();

	if (ibuf != NULL) {
		event_set(&imsgev, ibuf->fd, EV_READ | EV_PERSIST,
		    handle_dispatch_imsg, ibuf);
		event_add(&imsgev, NULL);
	}

	for (i = 0; i < conf.prefork; ++i) {
		event_set(&evs[i], servibuf[i].fd, EV_READ | EV_PERSIST,
		    handle_dispatch_imsg, &servibuf[i]);
		event_add(&evs[i], NULL);
	}

	sandbox_executor_process();

	event_dispatch();

	return 1;
}
