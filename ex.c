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

#include <sys/un.h>

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
static void	handle_imsg_fcgi_req(struct imsgbuf*, struct imsg*, size_t);
static void	handle_imsg_quit(struct imsgbuf*, struct imsg*, size_t);
static void	handle_dispatch_imsg(int, short, void*);

static imsg_handlerfn *handlers[] = {
	[IMSG_FCGI_REQ] = handle_imsg_fcgi_req,
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

	/* restore the default handlers */
	signal(SIGPIPE, SIG_DFL);
	signal(SIGCHLD, SIG_DFL);
	signal(SIGHUP,  SIG_DFL);
	signal(SIGINT,  SIG_DFL);
	signal(SIGTERM, SIG_DFL);

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
launch_cgi(struct iri *iri, struct cgireq *req, struct vhost *vhost,
    struct location *loc)
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
		struct envlist *e;

		close(p[0]);
		if (dup2(p[1], 1) == -1)
			goto childerr;

		ex = xasprintf("%s/%s", loc->dir, req->spath);

		serialize_iri(iri, iribuf, sizeof(iribuf));

		safe_setenv("GATEWAY_INTERFACE", "CGI/1.1");
		safe_setenv("GEMINI_DOCUMENT_ROOT", loc->dir);
		safe_setenv("GEMINI_SCRIPT_FILENAME",
		    xasprintf("%s/%s", loc->dir, req->spath));
		safe_setenv("GEMINI_URL", iribuf);

		strlcpy(path, "/", sizeof(path));
		strlcat(path, req->spath, sizeof(path));
		safe_setenv("GEMINI_URL_PATH", path);

		if (*req->relpath != '\0') {
			strlcpy(path, "/", sizeof(path));
			strlcat(path, req->relpath, sizeof(path));
			safe_setenv("PATH_INFO", path);

			strlcpy(path, loc->dir, sizeof(path));
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
		safe_setenv("TLS_VERSION", req->version);
		safe_setenv("TLS_CIPHER", req->cipher);

		snprintf(path, sizeof(path), "%d", req->cipher_strength);
		safe_setenv("TLS_CIPHER_STRENGTH", path);

		setenv_time("TLS_CLIENT_NOT_AFTER", req->notafter);
		setenv_time("TLS_CLIENT_NOT_BEFORE", req->notbefore);

		TAILQ_FOREACH(e, &vhost->env, envs) {
			safe_setenv(e->name, e->value);
		}

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

static struct vhost *
host_nth(size_t n)
{
	struct vhost *h;

	TAILQ_FOREACH(h, &hosts, vhosts) {
		if (n == 0)
			return h;
		n--;
	}

	return NULL;
}

static struct location *
loc_nth(struct vhost *vhost, size_t n)
{
	struct location *loc;

	TAILQ_FOREACH(loc, &vhost->locations, locations) {
		if (n == 0)
			return loc;
		n--;
	}

	return NULL;
}

static void
handle_imsg_cgi_req(struct imsgbuf *ibuf, struct imsg *imsg, size_t datalen)
{
	struct vhost	*h;
	struct location	*l;
	struct cgireq	 req;
	struct iri	 iri;
	int		 fd;

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

	if ((h = host_nth(req.host_off)) == NULL)
		abort();

	if ((l = loc_nth(h, req.loc_off)) == NULL)
		abort();

	fd = launch_cgi(&iri, &req, h, l);
	imsg_compose(ibuf, IMSG_CGI_RES, imsg->hdr.peerid, 0, fd, NULL, 0);
	imsg_flush(ibuf);
}

static int
fcgi_open_prog(struct fcgi *f)
{
	int s[2];
	pid_t p;

	/* XXX! */

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNIX, s) == -1)
		err(1, "socketpair");

	switch (p = fork()) {
	case -1:
		err(1, "fork");
	case 0:
		close(s[0]);
		if (dup2(s[1], 0) == -1)
			err(1, "dup2");
		execl(f->prog, f->prog, NULL);
		err(1, "execl %s", f->prog);
	default:
		close(s[1]);
		return s[0];
	}
}

static int
fcgi_open_sock(struct fcgi *f)
{
	struct sockaddr_un	addr;
	int			fd;

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		log_err(NULL, "socket: %s", strerror(errno));
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, f->path, sizeof(addr.sun_path));

	if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
		log_warn(NULL, "failed to connect to %s: %s", f->path,
		    strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}

static int
fcgi_open_conn(struct fcgi *f)
{
	struct addrinfo	hints, *servinfo, *p;
	int		r, sock;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_ADDRCONFIG;

	if ((r = getaddrinfo(f->path, f->port, &hints, &servinfo)) != 0) {
		log_warn(NULL, "getaddrinfo %s:%s: %s", f->path, f->port,
		    gai_strerror(r));
		return -1;
	}

	for (p = servinfo; p != NULL; p = p->ai_next) {
		sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (sock == -1)
			continue;
		if (connect(sock, p->ai_addr, p->ai_addrlen) == -1) {
			close(sock);
			continue;
		}
		break;
	}

	if (p == NULL) {
		log_warn(NULL, "couldn't connect to %s:%s", f->path, f->port);
		sock = -1;
	}

	freeaddrinfo(servinfo);
	return sock;
}

static void
handle_imsg_fcgi_req(struct imsgbuf *ibuf, struct imsg *imsg, size_t datalen)
{
	struct fcgi	*f;
	int		 id, fd;

	if (datalen != sizeof(id))
		abort();
	memcpy(&id, imsg->data, datalen);

	if (id > FCGI_MAX || (fcgi[id].path == NULL && fcgi[id].prog == NULL))
		abort();

	f = &fcgi[id];
	if (f->prog != NULL)
		fd = fcgi_open_prog(f);
	else if (f->port != NULL)
		fd = fcgi_open_conn(f);
	else
		fd = fcgi_open_sock(f);

	imsg_compose(ibuf, IMSG_FCGI_FD, id, 0, fd, NULL, 0);
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
