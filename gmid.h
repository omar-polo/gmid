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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <tls.h>
#include <unistd.h>

#include "config.h"

#ifndef INFTIM
# define INFTIM -1
#endif

#define GEMINI_URL_LEN (1024+3)	/* URL max len + \r\n + \0 */

/* large enough to hold a copy of a gemini URL and still have extra room */
#define PATHBUF		2048

#define SUCCESS		20
#define TEMP_REDIRECT	30
#define TEMP_FAILURE	40
#define NOT_FOUND	51
#define PROXY_REFUSED	53
#define BAD_REQUEST	59

#define MAX_USERS	64

#define HOSTSLEN	64

#define LOGE(c, fmt, ...) logs(LOG_ERR,     c, fmt, __VA_ARGS__)
#define LOGW(c, fmt, ...) logs(LOG_WARNING, c, fmt, __VA_ARGS__)
#define LOGN(c, fmt, ...) logs(LOG_NOTICE,  c, fmt, __VA_ARGS__)
#define LOGI(c, fmt, ...) logs(LOG_INFO,    c, fmt, __VA_ARGS__)
#define LOGD(c, fmt, ...) logs(LOG_DEBUG,   c, fmt, __VA_ARGS__)

struct vhost {
	const char	*domain;
	const char	*cert;
	const char	*key;
	const char	*dir;
	const char	*cgi;
	char		*lang;
	int		 dirfd;
	char		*default_mime;
};

extern struct vhost hosts[HOSTSLEN];

struct etm {			/* extension to mime */
	const char	*mime;
	const char	*ext;
};

struct mimes {
	struct etm	*t;
	size_t		len;
	size_t		cap;
};

struct conf {
	int		foreground;
	int		port;
	int		ipv6;
	uint32_t	protos;
	struct mimes	mimes;
};

extern struct conf conf;
extern int exfd;

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

enum {
	S_HANDSHAKE,
	S_OPEN,
	S_INITIALIZING,
	S_SENDING,
	S_CLOSING,
};

struct client {
	struct tls	*ctx;
	char		 req[GEMINI_URL_LEN];
	struct iri	 iri;
	int		 state;
	int		 code;
	const char	*meta;
	int		 fd, waiting_on_child;
	int		 child;
	char		 sbuf[1024];	  /* static buffer */
	void		*buf, *i;	  /* mmap buffer */
	ssize_t		 len, off;	  /* mmap/static buffer  */
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

__attribute__((format (printf, 1, 2)))
__attribute__((__noreturn__))
void fatal(const char*, ...);

__attribute__((format (printf, 3, 4)))
void logs(int, struct client*, const char*, ...);
void log_request(struct client*, char*, size_t);

void		 sig_handler(int);
int		 starts_with(const char*, const char*);
ssize_t		 filesize(int);
char		*absolutify_path(const char*);
void		 yyerror(const char*);
int		 parse_portno(const char*);
void		 parse_conf(const char*);
void		 load_vhosts(struct tls_config*);
int		 make_soket(int);
int		 listener_main();
void		 usage(const char*);

/* provided by lex/yacc */
extern FILE *yyin;
extern int yylineno;
extern int yyparse(void);
extern int yylex(void);

/* mime.c */
void		 init_mime(void);
void		 add_mime(const char*, const char*);
void		 load_default_mime(void);
int		 load_mime_file(const char*);
const char	*mime(struct vhost*, const char*);

/* server.c */
int		 check_path(struct client*, const char*, int*);
int		 open_file(struct pollfd*, struct client*);
int		 check_for_cgi(char *, char*, struct pollfd*, struct client*);
void		 mark_nonblock(int);
void		 handle_handshake(struct pollfd*, struct client*);
void		 handle_open_conn(struct pollfd*, struct client*);
int		 start_reply(struct pollfd*, struct client*, int, const char*);
int		 start_cgi(const char*, const char*, const char*, struct pollfd*, struct client*);
void		 send_file(struct pollfd*, struct client*);
void		 send_dir(struct pollfd*, struct client*);
void		 cgi_poll_on_child(struct pollfd*, struct client*);
void		 cgi_poll_on_client(struct pollfd*, struct client*);
void		 handle_cgi(struct pollfd*, struct client*);
void		 goodbye(struct pollfd*, struct client*);
void		 do_accept(int, struct tls*, struct pollfd*, struct client*);
void		 handle(struct pollfd*, struct client*);
void		 loop(struct tls*, int, int);

/* ex.c */
int		 send_string(int, const char*);
int		 recv_string(int, char**);
int		 send_vhost(int, struct vhost*);
int		 recv_vhost(int, struct vhost**);
int		 send_fd(int, int);
int		 recv_fd(int);
int		 executor_main(int);

/* sandbox.c */
void		 sandbox();

/* utf8.c */
int		 valid_multibyte_utf8(struct parser*);

/* iri.c */
int		 parse_iri(char*, struct iri*, const char**);
int		 trim_req_iri(char*);

#endif
