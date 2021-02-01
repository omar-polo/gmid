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

#include <err.h>
#include <errno.h>

#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <string.h>

#include "gmid.h"

int
send_string(int fd, const char *str)
{
	ssize_t len;

	if (str == NULL)
		len = 0;
	else
		len = strlen(str);

	if (write(fd, &len, sizeof(len)) != sizeof(len))
		return 0;

	if (len != 0)
		if (write(fd, str, len) != len)
			return 0;

	return 1;
}

int
recv_string(int fd, char **ret)
{
	ssize_t len;

	if (read(fd, &len, sizeof(len)) != sizeof(len))
		return 0;

	if (len == 0) {
		*ret = NULL;
		return 1;
	}

	if ((*ret = calloc(1, len+1)) == NULL)
		return 0;

	if (read(fd, *ret, len) != len)
		return 0;
	return 1;
}

int
send_iri(int fd, struct iri *i)
{
	return send_string(fd, i->schema)
		&& send_string(fd, i->host)
		&& send_string(fd, i->port)
		&& send_string(fd, i->path)
		&& send_string(fd, i->query);
}

int
recv_iri(int fd, struct iri *i)
{
	memset(i, 0, sizeof(*i));

	if (!recv_string(fd, &i->schema)
	    || !recv_string(fd, &i->host)
	    || !recv_string(fd, &i->port)
	    || !recv_string(fd, &i->path)
	    || !recv_string(fd, &i->query))
		return 0;

	return 1;
}

void
free_recvd_iri(struct iri *i)
{
	free(i->schema);
	free(i->host);
	free(i->port);
	free(i->path);
	free(i->query);
}

int
send_vhost(int fd, struct vhost *vhost)
{
	ssize_t n;

	if (vhost < hosts || vhost > hosts + HOSTSLEN)
		return 0;

	n = vhost - hosts;
	return write(fd, &n, sizeof(n)) == sizeof(n);
}

int
recv_vhost(int fd, struct vhost **vhost)
{
	ssize_t n;

	if (read(fd, &n, sizeof(n)) != sizeof(n))
		return 0;

	if (n < 0 || n > HOSTSLEN)
		return 0;

	*vhost = &hosts[n];
	if ((*vhost)->domain == NULL)
		return 0;
	return 1;
}

/* send d though fd. see /usr/src/usr.sbin/syslogd/privsep_fdpass.c
 * for an example */
int
send_fd(int fd, int d)
{
	struct msghdr msg;
	union {
		struct cmsghdr hdr;
		unsigned char buf[CMSG_SPACE(sizeof(int))];
	} cmsgbuf;
	struct cmsghdr *cmsg;
	struct iovec vec;
	int result = 1;
	ssize_t n;

	memset(&msg, 0, sizeof(msg));

	if (d >= 0) {
		msg.msg_control = &cmsgbuf.buf;
		msg.msg_controllen = sizeof(cmsgbuf.buf);
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		*(int*)CMSG_DATA(cmsg) = d;
	} else
		result = 0;

	vec.iov_base = &result;
	vec.iov_len = sizeof(int);
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;

	if ((n = sendmsg(fd, &msg, 0)) == -1 || n != sizeof(int)) {
                fprintf(stderr, "sendmsg: got %zu but wanted %zu: (errno) %s",
		    n, sizeof(int), strerror(errno));
		return 0;
	}
	return 1;
}

/* receive a descriptor via fd */
int
recv_fd(int fd)
{
	struct msghdr msg;
	union {
		struct cmsghdr hdr;
		char buf[CMSG_SPACE(sizeof(int))];
	} cmsgbuf;
	struct cmsghdr *cmsg;
	struct iovec vec;
	ssize_t n;
	int result;

	memset(&msg, 0, sizeof(msg));
	vec.iov_base = &result;
	vec.iov_len = sizeof(int);
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;
	msg.msg_control = &cmsgbuf.buf;
	msg.msg_controllen = sizeof(cmsgbuf.buf);

	if ((n = recvmsg(fd, &msg, 0)) != sizeof(int)) {
		fprintf(stderr, "read %zu bytes bu wanted %zu\n", n, sizeof(int));
		return -1;
	}

	if (result) {
		cmsg = CMSG_FIRSTHDR(&msg);
		if (cmsg == NULL || cmsg->cmsg_type != SCM_RIGHTS)
			return -1;
		return (*(int *)CMSG_DATA(cmsg));
	} else
		return -1;
}

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

/* fd or -1 on error */
static int
launch_cgi(struct iri *iri, const char *spath, char *relpath,
    const char *addr, const char *ruser, const char *cissuer,
    const char *chash, struct vhost *vhost)
{
	int p[2];		/* read end, write end */

	if (pipe2(p, O_NONBLOCK) == -1)
		return -1;

	switch (fork()) {
	case -1:
		return -1;

	case 0: {		/* child */
		char *argv[] = {NULL, NULL, NULL};
		char *ex, *pwd;
		char iribuf[GEMINI_URL_LEN];
		char path[PATH_MAX];

		close(p[0]);
		if (dup2(p[1], 1) == -1)
			goto childerr;

		ex = xasprintf("%s/%s", vhost->dir, spath);
		argv[0] = ex;
		argv[1] = iri->query;

		serialize_iri(iri, iribuf, sizeof(iribuf));

		safe_setenv("GATEWAY_INTERFACE", "CGI/1.1");
		safe_setenv("GEMINI_DOCUMENT_ROOT", vhost->dir);
		safe_setenv("GEMINI_SCRIPT_FILENAME",
		    xasprintf("%s/%s", vhost->dir, spath));
		safe_setenv("GEMINI_URL", iribuf);

		strlcpy(path, "/", sizeof(path));
		strlcat(path, spath, sizeof(path));
		safe_setenv("GEMINI_URL_PATH", path);

		if (relpath != NULL) {
			strlcpy(path, "/", sizeof(path));
			strlcat(path, relpath, sizeof(path));
			safe_setenv("PATH_INFO", path);

			strlcpy(path, vhost->dir, sizeof(path));
			strlcat(path, "/", sizeof(path));
			strlcat(path, relpath, sizeof(path));
			safe_setenv("PATH_TRANSLATED", path);
		}

		safe_setenv("QUERY_STRING", iri->query);
		safe_setenv("REMOTE_ADDR", addr);
		safe_setenv("REMOTE_HOST", addr);
		safe_setenv("REQUEST_METHOD", "");

		strlcpy(path, "/", sizeof(path));
		strlcat(path, spath, sizeof(path));
		safe_setenv("SCRIPT_NAME", path);

		safe_setenv("SERVER_NAME", iri->host);

		snprintf(path, sizeof(path), "%d", conf.port);
		safe_setenv("SERVER_PORT", path);

		safe_setenv("SERVER_PROTOCOL", "GEMINI");
		safe_setenv("SERVER_SOFTWARE", "gmid/1.5");

		if (ruser != NULL) {
			safe_setenv("AUTH_TYPE", "Certificate");
			safe_setenv("REMOTE_USER", ruser);
			safe_setenv("TLS_CLIENT_ISSUER", cissuer);
			safe_setenv("TLS_CLIENT_HASH", chash);
		}

		strlcpy(path, argv[0], sizeof(path));
		pwd = dirname(path);
		if (chdir(pwd)) {
			warn("chdir");
			goto childerr;
		}

		execvp(argv[0], argv);
		warn("execvp: %s", argv[0]);
		goto childerr;
	}

	default:
		close(p[1]);
		return p[0];
	}

childerr:
	dprintf(p[1], "%d internal server error\r\n", TEMP_FAILURE);
	_exit(1);
}

int
executor_main(int fd)
{
	char *spath, *relpath, *addr, *ruser, *cissuer, *chash;
        struct vhost *vhost;
	struct iri iri;
	int d;

#ifdef __OpenBSD__
	for (vhost = hosts; vhost->domain != NULL; ++vhost) {
		/* r so we can chdir into the correct directory */
		if (unveil(vhost->dir, "rx") == -1)
			err(1, "unveil %s for domain %s",
			    vhost->dir, vhost->domain);
	}

	/* rpath to chdir into the correct directory */
	if (pledge("stdio rpath sendfd proc exec", NULL))
		err(1, "pledge");
#endif

	for (;;) {
		if (!recv_iri(fd, &iri)
		    || !recv_string(fd, &spath)
		    || !recv_string(fd, &relpath)
		    || !recv_string(fd, &addr)
		    || !recv_string(fd, &ruser)
		    || !recv_string(fd, &cissuer)
		    || !recv_string(fd, &chash)
		    || !recv_vhost(fd, &vhost))
			break;

		d = launch_cgi(&iri, spath, relpath, addr, ruser, cissuer, chash,
		    vhost);
		if (!send_fd(fd, d))
			break;
		close(d);

		free_recvd_iri(&iri);
		free(spath);
		free(relpath);
		free(addr);
		free(ruser);
		free(cissuer);
		free(chash);
	}

	/* kill all process in my group.  This means the listener and
	 * every pending CGI script. */
	kill(0, SIGINT);
	return 1;
}
