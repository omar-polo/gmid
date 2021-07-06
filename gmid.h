/*
 * Copyright (c) 2020 Omar Polo <op@omarpolo.com>
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

#ifndef GMID_H
#define GMID_H

#include "config.h"

#include <sys/socket.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <dirent.h>
#include <event.h>
#include <limits.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <tls.h>
#include <unistd.h>

#include <openssl/x509.h>

#define GMID_STRING	"gmid 1.7"
#define GMID_VERSION	"gmid/1.7"

#define GEMINI_URL_LEN (1024+3)	/* URL max len + \r\n + \0 */

#define SUCCESS		20
#define TEMP_REDIRECT	30
#define TEMP_FAILURE	40
#define CGI_ERROR	42
#define NOT_FOUND	51
#define PROXY_REFUSED	53
#define BAD_REQUEST	59
#define CLIENT_CERT_REQ	60
#define CERT_NOT_AUTH	61

#define MAX_USERS	64

/* maximum hostname and label length, +1 for the NUL-terminator */
#define DOMAIN_NAME_LEN	(253+1)
#define LABEL_LEN	(63+1)

#define FCGI_MAX	32
#define PROC_MAX	16

struct fcgi {
	int		 id;
	char		*path;
	char		*port;
	char		*prog;
	int		 fd;
	struct event	 e;

	/* number of pending clients */
	int		 pending;

#define FCGI_OFF	0
#define FCGI_INFLIGHT	1
#define FCGI_READY	2
	int		 s;
};
extern struct fcgi fcgi[FCGI_MAX];

TAILQ_HEAD(lochead, location);
struct location {
	const char	*match;
	const char	*lang;
	const char	*default_mime;
	const char	*index;
	int		 auto_index; /* 0 auto, -1 off, 1 on */
	int		 block_code;
	const char	*block_fmt;
	int		 strip;
	X509_STORE	*reqca;
	int		 disable_log;
	int		 fcgi;

	const char	*dir;
	int		 dirfd;

	TAILQ_ENTRY(location) locations;
};

TAILQ_HEAD(envhead, envlist);
struct envlist {
	char		*name;
	char		*value;
	TAILQ_ENTRY(envlist) envs;
};

TAILQ_HEAD(aliashead, alist);
struct alist {
	char		*alias;
	TAILQ_ENTRY(alist) aliases;
};

extern TAILQ_HEAD(vhosthead, vhost) hosts;
struct vhost {
	const char	*domain;
	const char	*cert;
	const char	*key;
	const char	*cgi;
	const char	*entrypoint;

	TAILQ_ENTRY(vhost) vhosts;

	/* the first location rule is always '*' and holds the default
	 * settings for the vhost, then follows the "real" location
	 * rules as specified in the configuration. */
	struct lochead	 locations;

	struct envhead	 env;
	struct envhead	 params;
	struct aliashead aliases;
};

struct etm {			/* extension to mime */
	const char	*mime;
	const char	*ext;
};

struct mime {
	struct etm	*t;
	size_t		len;
	size_t		cap;
};

struct conf {
	/* from command line */
	int		 foreground;
	int		 verbose;

	/* in the config */
	int		 port;
	int		 ipv6;
	uint32_t	 protos;
	struct mime	 mime;
	char		*chroot;
	char		*user;
	int		 prefork;
};

extern const char *config_path;
extern struct conf conf;

extern struct imsgbuf logibuf, exibuf, servibuf[PROC_MAX];

extern int servpipes[PROC_MAX];

struct iri {
	char		*schema;
	char		*host;
	char		*port;
	uint16_t	 port_no;
	char		*path;
	char		*query;
	char		*fragment;
};

struct parser {
	char		*iri;
	struct iri	*parsed;
	const char	*err;
};

struct mbuf {
	size_t			len;
	size_t			off;
	TAILQ_ENTRY(mbuf)	mbufs;
	char			data[];
};
TAILQ_HEAD(mbufhead, mbuf);

typedef void (imsg_handlerfn)(struct imsgbuf*, struct imsg*, size_t);

typedef void (*statefn)(int, short, void*);

/*
 * DFA: handle_handshake is the initial state, close_conn the final.
 * Sometimes we have an enter_* function to handle the state switch.
 *
 * handle_handshake -> handle_open_conn
 * handle_handshake -> close_conn		// on err
 *
 * handle_open_conn -> handle_cgi_reply		// via open_file/dir/...
 * handle_open_conn -> send_fcgi_req		// via apply_fastcgi, IMSG_FCGI_FD
 * handle_open_conn -> handle_dirlist		// ...same
 * handle_open_conn -> send_file		// ...same
 * handle_open_conn -> start_reply		// on error
 *
 * handle_cgi_reply -> handle_cgi	// after logging the CGI reply
 * handle_cgi_reply -> start_reply	// on error
 *
 * handle_cgi -> close_conn
 *
 * send_fcgi_req -> copy_mbuf		// via handle_fcgi
 * handle_fcgi -> close_all		// on error
 * copy_mbuf -> close_conn		// on success/error
 *
 * handle_dirlist -> send_directory_listing
 * handle_dirlist -> close_conn			// on error
 *
 * send_directory_listing -> close_conn
 *
 * send_file -> close_conn
 */
struct client {
	int		 id;
	struct tls	*ctx;
	char		 req[GEMINI_URL_LEN];
	struct iri	 iri;
	char		 domain[DOMAIN_NAME_LEN];

	/*
	 * start_reply uses this to know what function call after the
	 * reply.  It's also used as sentinel value in fastcgi to know
	 * if the server has closed the request.
	 */
	statefn		 next;

	int		 code;
	const char	*meta;
	int		 fd, pfd;
	struct dirent	**dir;
	int		 dirlen, diroff;
	int		 fcgi;

	/* big enough to store STATUS + SPACE + META + CRLF */
	char		 sbuf[1029];
	ssize_t		 len, off;

	struct mbufhead	 mbufhead;

	struct sockaddr_storage	 addr;
	struct vhost	*host;	/* host they're talking to */
	size_t		 loc;	/* location matched */
};

extern struct client clients[MAX_USERS];

struct cgireq {
	char		buf[GEMINI_URL_LEN];

	size_t		iri_schema_off;
	size_t		iri_host_off;
	size_t		iri_port_off;
	size_t		iri_path_off;
	size_t		iri_query_off;
	size_t		iri_fragment_off;
	int		iri_portno;

	char		spath[PATH_MAX+1];
	char		relpath[PATH_MAX+1];
	char		addr[NI_MAXHOST+1];

	/* AFAIK there isn't an upper limit for these two fields. */
	char		subject[64+1];
	char		issuer[64+1];

	char		hash[128+1];
	char		version[8];
	char		cipher[32];
	int		cipher_strength;
	time_t		notbefore;
	time_t		notafter;

	size_t		host_off;
	size_t		loc_off;
};

enum {
	FILE_EXISTS,
	FILE_EXECUTABLE,
	FILE_DIRECTORY,
	FILE_MISSING,
};

enum imsg_type {
	IMSG_CGI_REQ,
	IMSG_CGI_RES,
	IMSG_FCGI_REQ,
	IMSG_FCGI_FD,
	IMSG_LOG,
	IMSG_LOG_TYPE,
	IMSG_QUIT,
};

/* gmid.c */
char		*data_dir(void);
void		 load_local_cert(const char*, const char*);
void		 load_vhosts(void);
int		 make_socket(int, int);
void		 setup_tls(void);
void		 init_config(void);
void		 free_config(void);
void		 drop_priv(void);

void		 yyerror(const char*, ...);
int		 parse_portno(const char*);
void		 parse_conf(const char*);
int		 cmdline_symset(char *);

/* log.c */
void		 fatal(const char*, ...)
	__attribute__((format (printf, 1, 2)))
	__attribute__((__noreturn__));

#define LOG_ATTR_FMT __attribute__((format (printf, 2, 3)))
void		 log_err(struct client*, const char*, ...)	LOG_ATTR_FMT;
void		 log_warn(struct client*, const char*, ...)	LOG_ATTR_FMT;
void		 log_notice(struct client*, const char*, ...)	LOG_ATTR_FMT;
void		 log_info(struct client*, const char*, ...)	LOG_ATTR_FMT;
void		 log_debug(struct client*, const char*, ...)	LOG_ATTR_FMT;
void		 log_request(struct client*, char*, size_t);
int		 logger_main(int, struct imsgbuf*);

/* mime.c */
void		 init_mime(struct mime*);
void		 add_mime(struct mime*, const char*, const char*);
void		 load_default_mime(struct mime*);
const char	*mime(struct vhost*, const char*);

/* server.c */
extern int	shutting_down;
const char	*vhost_lang(struct vhost*, const char*);
const char	*vhost_default_mime(struct vhost*, const char*);
const char	*vhost_index(struct vhost*, const char*);
int		 vhost_auto_index(struct vhost*, const char*);
int		 vhost_block_return(struct vhost*, const char*, int*, const char**);
int		 vhost_fastcgi(struct vhost*, const char*);
int		 vhost_dirfd(struct vhost*, const char*, size_t*);
int		 vhost_strip(struct vhost*, const char*);
X509_STORE	*vhost_require_ca(struct vhost*, const char*);
int		 vhost_disable_log(struct vhost*, const char*);

void		 mark_nonblock(int);
void		 start_reply(struct client*, int, const char*);
void		 close_conn(int, short, void*);
struct client	*try_client_by_id(int);
void		 loop(struct tls*, int, int, struct imsgbuf*);

/* dirs.c */
int		 scandir_fd(int, struct dirent***, int(*)(const struct dirent*),
		    int(*)(const struct dirent**, const struct dirent**));
int		 select_non_dot(const struct dirent*);
int		 select_non_dotdot(const struct dirent*);

/* ex.c */
int		 send_string(int, const char*);
int		 recv_string(int, char**);
int		 send_iri(int, struct iri*);
int		 recv_iri(int, struct iri*);
void		 free_recvd_iri(struct iri*);
int		 send_vhost(int, struct vhost*);
int		 recv_vhost(int, struct vhost**);
int		 send_time(int, time_t);
int		 recv_time(int, time_t*);
int		 send_fd(int, int);
int		 recv_fd(int);
int		 executor_main(struct imsgbuf*);

/* fcgi.c */
void		 fcgi_close_backend(struct fcgi *);
void		 handle_fcgi(int, short, void*);
void		 send_fcgi_req(struct fcgi*, struct client*);

/* sandbox.c */
void		 sandbox_server_process(void);
void		 sandbox_executor_process(void);
void		 sandbox_logger_process(void);

/* utf8.c */
int		 valid_multibyte_utf8(struct parser*);
char		*utf8_nth(char*, size_t);

/* iri.c */
int		 parse_iri(char*, struct iri*, const char**);
int		 trim_req_iri(char*, const char **);
int		 serialize_iri(struct iri*, char*, size_t);
char		*pct_decode_str(char *);

/* puny.c */
int		 puny_decode(const char*, char*, size_t, const char**);

/* utils.c */
void		 block_signals(void);
void		 unblock_signals(void);
int		 starts_with(const char*, const char*);
int		 ends_with(const char*, const char*);
ssize_t		 filesize(int);
char		*absolutify_path(const char*);
char		*xstrdup(const char*);
void		*xcalloc(size_t, size_t);
void		 gen_certificate(const char*, const char*, const char*);
X509_STORE	*load_ca(const char*);
int		 validate_against_ca(X509_STORE*, const uint8_t*, size_t);
void		 dispatch_imsg(struct imsgbuf*, imsg_handlerfn**, size_t);

#endif
