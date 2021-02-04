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
#include <string.h>

#include "gmid.h"

/*
 * #define YYDEBUG 1
 * int yydebug = 1;
 */

struct vhost *host;
size_t ihost;
struct location *loc;
size_t iloc;

int goterror = 0;
const char *config_path;

void		 yyerror(const char*);
int		 parse_portno(const char*);
void		 parse_conf(const char*);
char		*ensure_absolute_path(char*);

%}

/* for bison: */
/* %define parse.error verbose */

%union {
	char		*str;
	int		 num;
}

%token TIPV6 TPORT TPROTOCOLS TMIME TDEFAULT TTYPE
%token TCHROOT TUSER TSERVER
%token TLOCATION TCERT TKEY TROOT TCGI TLANG TINDEX TAUTO
%token TERR

%token <str>	TSTRING
%token <num>	TNUM
%token <num>	TBOOL

%%

conf		: options vhosts ;

options		: /* empty */
		| options option
		;

option		: TIPV6 TBOOL		{ conf.ipv6 = $2; }
		| TPORT TNUM		{ conf.port = $2; }
		| TPROTOCOLS TSTRING {
			if (tls_config_parse_protocols(&conf.protos, $2) == -1)
				errx(1, "invalid protocols string \"%s\"", $2);
		}
		| TMIME TSTRING TSTRING	{ add_mime(&conf.mime, $2, $3); }
		| TCHROOT TSTRING	{ conf.chroot = $2; }
		| TUSER TSTRING		{ conf.user = $2; }
		;

vhosts		: /* empty */
		| vhosts vhost
		;

vhost		: TSERVER TSTRING '{' servopts locations '}' {
			host->locations[0].match = xstrdup("*");
			host->domain = $2;

			if (strstr($2, "xn--") != NULL) {
				warnx("%s:%d \"%s\" looks like punycode: "
				    "you should use the decoded hostname.",
				    config_path, yylineno, $2);
			}

			if (host->cert == NULL || host->key == NULL ||
			    host->dir == NULL)
				errx(1, "invalid vhost definition: %s", $2);

			if (++ihost == HOSTSLEN)
				errx(1, "too much vhosts defined");

			host++;
			loc = &host->locations[0];
			iloc = 0;
		}
		| error '}'		{ yyerror("error in server directive"); }
		;

servopts	: /* empty */
		| servopts servopt
		;

servopt		: TCERT TSTRING		{ host->cert = ensure_absolute_path($2); }
		| TKEY TSTRING		{ host->key  = ensure_absolute_path($2); }
		| TROOT TSTRING		{ host->dir  = ensure_absolute_path($2); }
		| TCGI TSTRING		{
			/* drop the starting '/', if any */
			if (*$2 == '/')
				memmove($2, $2+1, strlen($2));
			host->cgi = $2;
		}
		| locopt
		;

locations	: /* empty */
		| locations location
		;

location	: TLOCATION TSTRING '{' locopts '}' {
			loc->match = $2;
			if (++iloc == LOCLEN)
				errx(1, "too much location rules defined");
			loc++;
		}
		| error '}'
		;

locopts		: /* empty */
		| locopts locopt
		;

locopt		: TDEFAULT TTYPE TSTRING {
			if (loc->default_mime != NULL)
				yyerror("`default type' specified more than once");
			loc->default_mime = $3;
		}
		| TLANG TSTRING {
			if (loc->lang != NULL)
				yyerror("`lang' specified more than once");
			loc->lang = $2;
		}
		| TINDEX TSTRING {
			if (loc->index != NULL)
				yyerror("`index' specified more than once");
			loc->index = $2;
		}
		| TAUTO TINDEX TBOOL	{ loc->auto_index = $3 ? 1 : -1; }
		;

%%

void
yyerror(const char *msg)
{
	goterror = 1;
	fprintf(stderr, "%s:%d: %s\n", config_path, yylineno, msg);
}

int
parse_portno(const char *p)
{
	const char *errstr;
	int n;

	n = strtonum(p, 0, UINT16_MAX, &errstr);
	if (errstr != NULL)
		errx(1, "port number is %s: %s", errstr, p);
	return n;
}

void
parse_conf(const char *path)
{
	host = &hosts[0];
	ihost = 0;
	loc = &hosts[0].locations[0];
	iloc = 0;

	config_path = path;
	if ((yyin = fopen(path, "r")) == NULL)
		fatal("cannot open config %s", path);
	yyparse();
	fclose(yyin);

	if (goterror)
		exit(1);
}

char *
ensure_absolute_path(char *path)
{
	if (path == NULL || *path != '/')
		yyerror("not an absolute path");
	return path;
}
