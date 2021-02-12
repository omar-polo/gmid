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

#include <sys/socket.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <dirent.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <tls.h>
#include <unistd.h>

#include <openssl/x509.h>

#include "config.h"

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

#define HOSTSLEN	64
#define LOCLEN		32

/* maximum hostname and label length, +1 for the NUL-terminator */
#define DOMAIN_NAME_LEN	(253+1)
#define LABEL_LEN	(63+1)

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
};

struct vhost {
	const char	*domain;
	const char	*cert;
	const char	*key;
	const char	*dir;
	const char	*cgi;
	const char	*entrypoint;
	int		 dirfd;

	/* the first location rule is always '*' and holds the default
	 * settings for the vhost, from locations[1] onwards there are
	 * the "real" location rules specified in the configuration. */
	struct location	 locations[LOCLEN];
};

extern struct vhost hosts[HOSTSLEN];

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
extern int exfd;

extern volatile sig_atomic_t hupped;

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

struct client;

typedef void (*statefn)(int, short, void*);

/*
 * DFA: handle_handshake is the initial state, close_conn the final.
 * Sometimes we have an enter_* function to handle the state switch.
 *
 * handle_handshake -> handle_open_conn
 * handle_handshake -> close_conn		// on err
 *
 * handle_open_conn -> handle_cgi_reply		// via open_file/dir/...
 * handle_open_conn -> handle_dirlist		// ...same
 * handle_open_conn -> send_file		// ...same
 * handle_open_conn -> start_reply		// on error
 *
 * handle_cgi_reply -> handle_cgi	// after logging the CGI reply
 * handle_cgi_reply -> start_reply	// on error
 *
 * handle_cgi -> close_conn
 *
 * handle_dirlist -> send_directory_listing
 * handle_dirlist -> close_conn			// on error
 *
 * send_directory_listing -> close_conn
 *
 * send_file -> close_conn
 */
struct client {
	struct tls	*ctx;
	char		 req[GEMINI_URL_LEN];
	struct iri	 iri;
	char		 domain[DOMAIN_NAME_LEN];
	statefn		 next;
	int		 code;
	const char	*meta;
	int		 fd, pfd;
	DIR		*dir;
	char		 sbuf[1024];
	ssize_t		 len, off;
	struct sockaddr_storage	 addr;
	struct vhost	*host;	/* host she's talking to */
};

enum {
	FILE_EXISTS,
	FILE_EXECUTABLE,
	FILE_DIRECTORY,
	FILE_MISSING,
};

/* gmid.c */
void		 sig_handler(int);
void		 mkdirs(const char*);
char		*data_dir(void);
void		 load_local_cert(const char*, const char*);
void		 load_vhosts(void);
int		 make_socket(int, int);
void		 setup_tls(void);
void		 init_config(void);
void		 free_config(void);
void		 drop_priv(void);

/* provided by lex/yacc */
extern FILE *yyin;
extern int yylineno;
extern int yyparse(void);
extern int yylex(void);

void		 yyerror(const char*, ...);
int		 parse_portno(const char*);
void		 parse_conf(const char*);

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

/* mime.c */
void		 init_mime(struct mime*);
void		 add_mime(struct mime*, const char*, const char*);
void		 load_default_mime(struct mime*);
const char	*mime(struct vhost*, const char*);

/* server.c */
const char	*vhost_lang(struct vhost*, const char*);
const char	*vhost_default_mime(struct vhost*, const char*);
const char	*vhost_index(struct vhost*, const char*);
int		 vhost_auto_index(struct vhost*, const char*);
int		 vhost_block_return(struct vhost*, const char*, int*, const char**);
int		 vhost_strip(struct vhost*, const char*);
X509_STORE	*vhost_require_ca(struct vhost*, const char*);
void		 mark_nonblock(int);
void		 loop(struct tls*, int, int);

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
int		 executor_main(void);

/* sandbox.c */
void		 sandbox(void);

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
void		 gen_certificate(const char*, const char*, const char*);
X509_STORE	*load_ca(const char*);
int		 validate_against_ca(X509_STORE*, const uint8_t*, size_t);

#endif
