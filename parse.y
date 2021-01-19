/* -*- mode: fundamental; indent-tabs-mode: t; -*- */
%{

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
#include <stdio.h>

#include "gmid.h"

/*
 * #define YYDEBUG 1
 * int yydebug = 1;
 */

struct vhost *host = &hosts[0];
size_t ihost = 0;

extern void yyerror(const char*);

%}

/* for bison: */
/* %define parse.error verbose */

%union {
	char		*str;
	int		 num;
}

%token TDAEMON TIPV6 TPORT TPROTOCOLS TMIME TDEFAULT TTYPE TSERVER
%token TCERT TKEY TROOT TCGI TLANG
%token TERR

%token <str>	TSTRING
%token <num>	TNUM
%token <num>	TBOOL

%%

conf		: options vhosts ;

options		: /* empty */
		| options option
		;

option		: TDAEMON TBOOL		{ conf.foreground = !$2; }
		| TIPV6 TBOOL		{ conf.ipv6 = $2; }
		| TPORT TNUM		{ conf.port = $2; }
		| TPROTOCOLS TSTRING {
			if (tls_config_parse_protocols(&conf.protos, $2) == -1)
				errx(1, "invalid protocols string \"%s\"", $2);
		}
		| TMIME TSTRING TSTRING	{ add_mime($2, $3); }
		;

vhosts		: /* empty */
		| vhosts vhost
		;

vhost		: TSERVER TSTRING '{' servopts '}' {
			host->domain = $2;

			if (host->cert == NULL || host->key == NULL ||
			    host->dir == NULL)
				errx(1, "invalid vhost definition: %s", $2);
			if (++ihost == HOSTSLEN)
				errx(1, "too much vhosts defined");
                        host++;
		}
		| error '}'		{ yyerror("error in server directive"); }
		;

servopts	: /* empty */
		| servopts servopt
		;

servopt		: TCERT TSTRING		{ host->cert = $2; }
		| TKEY TSTRING		{ host->key = $2; }
		| TROOT TSTRING		{ host->dir = $2; }
		| TCGI TSTRING		{
			host->cgi = $2;
			/* drop the starting '/', if any */
			if (*host->cgi == '/')
				host->cgi++;
		}
		| TDEFAULT TTYPE TSTRING {
			free(host->default_mime);
			host->default_mime = $3;
		}
		| TLANG TSTRING {
			free(host->lang);
			host->lang = $2;
		}
		;
