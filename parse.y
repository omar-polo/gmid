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

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "gmid.h"

/*
 * #define YYDEBUG 1
 * int yydebug = 1;
 */

struct vhost *host;
struct location *loc;

int goterror = 0;

static struct vhost	*new_vhost(void);
static struct location	*new_location(void);

void		 yyerror(const char*, ...);
int		 parse_portno(const char*);
void		 parse_conf(const char*);
char		*ensure_absolute_path(char*);
int		 check_block_code(int);
char		*check_block_fmt(char*);
int		 check_strip_no(int);
int		 check_prefork_num(int);
void		 advance_loc(void);

%}

/* for bison: */
/* %define parse.error verbose */

%union {
	char		*str;
	int		 num;
}

%token TIPV6 TPORT TPROTOCOLS TMIME TDEFAULT TTYPE TCHROOT TUSER TSERVER
%token TPREFORK TLOCATION TCERT TKEY TROOT TCGI TENV TLANG TLOG TINDEX TAUTO
%token TSTRIP TBLOCK TRETURN TENTRYPOINT TREQUIRE TCLIENT TCA TALIAS

%token TERR

%token <str>	TSTRING
%token <num>	TNUM
%token <num>	TBOOL

%%

conf		: options vhosts ;

options		: /* empty */
		| options option
		;

option		: TCHROOT TSTRING	{ conf.chroot = $2; }
		| TIPV6 TBOOL		{ conf.ipv6 = $2; }
		| TMIME TSTRING TSTRING	{ add_mime(&conf.mime, $2, $3); }
		| TPORT TNUM		{ conf.port = $2; }
		| TPREFORK TNUM		{ conf.prefork = check_prefork_num($2); }
		| TPROTOCOLS TSTRING {
			if (tls_config_parse_protocols(&conf.protos, $2) == -1)
				yyerror("invalid protocols string \"%s\"", $2);
		}
		| TUSER TSTRING		{ conf.user = $2; }
		;

vhosts		: /* empty */
		| vhosts vhost
		;

vhost		: TSERVER TSTRING {
			host = new_vhost();
			TAILQ_INSERT_HEAD(&hosts, host, vhosts);

			loc = new_location();
			TAILQ_INSERT_HEAD(&host->locations, loc, locations);

			loc->match = xstrdup("*");
			host->domain = $2;

			if (strstr($2, "xn--") != NULL) {
				warnx("%s:%d \"%s\" looks like punycode: "
				    "you should use the decoded hostname.",
				    config_path, yylineno, $2);
			}
		} '{' servopts locations '}' {

			if (host->cert == NULL || host->key == NULL)
				yyerror("invalid vhost definition: %s", $2);
		}
		| error '}'		{ yyerror("error in server directive"); }
		;

servopts	: /* empty */
		| servopts servopt
		;

servopt		: TALIAS TSTRING {
			struct alist *a;

			a = xcalloc(1, sizeof(*a));
			a->alias = $2;
			if (TAILQ_EMPTY(&host->aliases))
				TAILQ_INSERT_HEAD(&host->aliases, a, aliases);
			else
				TAILQ_INSERT_TAIL(&host->aliases, a, aliases);
		}
		| TCERT TSTRING		{ host->cert = ensure_absolute_path($2); }
		| TCGI TSTRING		{
			/* drop the starting '/', if any */
			if (*$2 == '/')
				memmove($2, $2+1, strlen($2));
			host->cgi = $2;
		}
		| TENTRYPOINT TSTRING {
			if (host->entrypoint != NULL)
				yyerror("`entrypoint' specified more than once");
			while (*$2 == '/')
				memmove($2, $2+1, strlen($2));
			host->entrypoint = $2;
		}
		| TENV TSTRING TSTRING {
			struct envlist *e;

			e = xcalloc(1, sizeof(*e));
			e->name = $2;
			e->value = $3;
			if (TAILQ_EMPTY(&host->env))
				TAILQ_INSERT_HEAD(&host->env, e, envs);
			else
				TAILQ_INSERT_TAIL(&host->env, e, envs);
		}
		| TKEY TSTRING		{ host->key  = ensure_absolute_path($2); }
		| locopt
		;

locations	: /* empty */
		| locations location
		;

location	: TLOCATION { advance_loc(); } TSTRING '{' locopts '}'	{
			/* drop the starting '/' if any */
			if (*$3 == '/')
				memmove($3, $3+1, strlen($3));
			loc->match = $3;
		}
		| error '}'
		;

locopts		: /* empty */
		| locopts locopt
		;

locopt		: TAUTO TINDEX TBOOL	{ loc->auto_index = $3 ? 1 : -1; }
		| TBLOCK TRETURN TNUM TSTRING {
			if (loc->block_fmt != NULL)
				yyerror("`block' rule specified more than once");
			loc->block_fmt = check_block_fmt($4);
			loc->block_code = check_block_code($3);
		}
		| TBLOCK TRETURN TNUM {
			if (loc->block_fmt != NULL)
				yyerror("`block' rule specified more than once");
			loc->block_fmt = xstrdup("temporary failure");
			loc->block_code = check_block_code($3);
			if ($3 >= 30 && $3 < 40)
				yyerror("missing `meta' for block return %d", $3);
		}
		| TBLOCK {
			if (loc->block_fmt != NULL)
				yyerror("`block' rule specified more than once");
			loc->block_fmt = xstrdup("temporary failure");
			loc->block_code = 40;
		}
		| TDEFAULT TTYPE TSTRING {
			if (loc->default_mime != NULL)
				yyerror("`default type' specified more than once");
			loc->default_mime = $3;
		}
		| TINDEX TSTRING {
			if (loc->index != NULL)
				yyerror("`index' specified more than once");
			loc->index = $2;
		}
		| TLANG TSTRING {
			if (loc->lang != NULL)
				yyerror("`lang' specified more than once");
			loc->lang = $2;
		}
		| TLOG TBOOL	{ loc->disable_log = !$2; }
		| TREQUIRE TCLIENT TCA TSTRING {
			if (loc->reqca != NULL)
				yyerror("`require client ca' specified more than once");

			ensure_absolute_path($4);
			if ((loc->reqca = load_ca($4)) == NULL)
				yyerror("couldn't load ca cert: %s", $4);
			free($4);
		}
		| TROOT TSTRING		{
			if (loc->dir != NULL)
				yyerror("`root' specified more than once");

			loc->dir  = ensure_absolute_path($2);
		}
		| TSTRIP TNUM		{ loc->strip = check_strip_no($2); }
		;

%%

static struct vhost *
new_vhost(void)
{
	return xcalloc(1, sizeof(struct vhost));
}

static struct location *
new_location(void)
{
	struct location *l;

	l = xcalloc(1, sizeof(*l));
	l->dirfd = -1;
	return l;
}

void
yyerror(const char *msg, ...)
{
	va_list ap;

	goterror = 1;

	va_start(ap, msg);
	fprintf(stderr, "%s:%d: ", config_path, yylineno);
	vfprintf(stderr, msg, ap);
	fprintf(stderr, "\n");
	va_end(ap);
}

int
parse_portno(const char *p)
{
	const char *errstr;
	int n;

	n = strtonum(p, 0, UINT16_MAX, &errstr);
	if (errstr != NULL)
		yyerror("port number is %s: %s", errstr, p);
	return n;
}

void
parse_conf(const char *path)
{
	config_path = path;
	if ((yyin = fopen(path, "r")) == NULL)
		err(1, "cannot open config: %s", path);
	yyparse();
	fclose(yyin);

	if (goterror)
		exit(1);

	if (TAILQ_FIRST(&hosts)->domain == NULL)
		errx(1, "no vhost defined in %s", path);
}

char *
ensure_absolute_path(char *path)
{
	if (path == NULL || *path != '/')
		yyerror("not an absolute path: %s", path);
	return path;
}

int
check_block_code(int n)
{
	if (n < 10 || n >= 70 || (n >= 20 && n <= 29))
		yyerror("invalid block code %d", n);
	return n;
}

char *
check_block_fmt(char *fmt)
{
	char *s;

	for (s = fmt; *s; ++s) {
		if (*s != '%')
			continue;
		switch (*++s) {
		case '%':
		case 'p':
		case 'q':
		case 'P':
		case 'N':
			break;
		default:
			yyerror("invalid format specifier %%%c", *s);
		}
	}

	return fmt;
}

int
check_strip_no(int n)
{
	if (n <= 0)
		yyerror("invalid strip number %d", n);
	return n;
}

int
check_prefork_num(int n)
{
	if (n <= 0 || n >= PROC_MAX)
		yyerror("invalid prefork number %d", n);
	return n;
}

void
advance_loc(void)
{
	loc = new_location();
	TAILQ_INSERT_TAIL(&host->locations, loc, locations);
}
