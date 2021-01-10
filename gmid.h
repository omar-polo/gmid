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

#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <tls.h>
#include <unistd.h>

#ifndef __OpenBSD__
# define pledge(a, b) 0
# define unveil(a, b) 0
#endif

#ifndef INFTIM
# define INFTIM -1
#endif

#define GEMINI_URL_LEN (1024+3)	/* URL max len + \r\n + \0 */

/* large enough to hold a copy of a gemini URL and still have extra room */
#define PATHBUF		2048

#define SUCCESS		20
#define TEMP_FAILURE	40
#define NOT_FOUND	51
#define BAD_REQUEST	59

#define MAX_USERS	64

enum {
	S_OPEN,
	S_INITIALIZING,
	S_SENDING,
	S_CLOSING,
};

struct client {
	struct tls	*ctx;
	int		 state;
	int		 code;
	const char	*meta;
	int		 fd, waiting_on_child;
	pid_t		 child;
	char		 sbuf[1024];	  /* static buffer */
	void		*buf, *i;	  /* mmap buffer */
	ssize_t		 len, off;	  /* mmap/static buffer  */
	int		 af;
	struct in_addr	 addr;
};

struct uri {
	char		*schema;
	char		*host;
	char		*port;
	uint16_t	 port_no;
	char		*path;
	char		*query;
	char		*fragment;
};

struct parser {
	char		*uri;
	struct uri	*parsed;
	const char	*err;
};

enum {
	FILE_EXISTS,
	FILE_EXECUTABLE,
	FILE_DIRECTORY,
	FILE_MISSING,
};

/* gmid.c */
void		 sig_handler(int);
int		 starts_with(const char*, const char*);

int		 start_reply(struct pollfd*, struct client*, int, const char*);
ssize_t		 filesize(int);
const char	*path_ext(const char*);
const char	*mime(const char*);
int		 check_path(struct client*, const char*, int*);
int		 check_for_cgi(char *, char*, struct pollfd*, struct client*);
int		 open_file(char*, char*, struct pollfd*, struct client*);
int		 start_cgi(const char*, const char*, const char*, struct pollfd*, struct client*);
void		 cgi_poll_on_child(struct pollfd*, struct client*);
void		 cgi_poll_on_client(struct pollfd*, struct client*);
void		 handle_cgi(struct pollfd*, struct client*);
void		 send_file(char*, char*, struct pollfd*, struct client*);
void		 send_dir(char*, struct pollfd*, struct client*);
void		 handle(struct pollfd*, struct client*);

void		 mark_nonblock(int);
int		 make_soket(int);
void		 do_accept(int, struct tls*, struct pollfd*, struct client*);
void		 goodbye(struct pollfd*, struct client*);
void		 loop(struct tls*, int);

void		 usage(const char*);

/* utf8.c */
int		 valid_multibyte_utf8(struct parser*);

/* uri.c */
int		 parse_uri(char*, struct uri*, const char**);
int		 trim_req_uri(char*);

#endif
