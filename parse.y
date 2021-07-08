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

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gmid.h"

FILE *yyfp;

typedef struct {
	union {
		char	*str;
		int	 num;
	} v;
	int lineno;
	int colno;
} yystype;
#define YYSTYPE yystype

/*
 * #define YYDEBUG 1
 * int yydebug = 1;
 */

/*
 * The idea behind this implementation of macros is from rad/parse.y
 */
TAILQ_HEAD(symhead, sym) symhead = TAILQ_HEAD_INITIALIZER(symhead);
struct sym {
	TAILQ_ENTRY(sym)	 entry;
	int			 used;
	int			 persist;
	char			*name;
	char			*val;
};

struct vhost *host;
struct location *loc;

static int goterror;

static struct vhost	*new_vhost(void);
static struct location	*new_location(void);

void		 yyerror(const char*, ...);
int		 kw_cmp(const void *, const void *);
static int	 yylex(void);
int		 parse_portno(const char*);
void		 parse_conf(const char*);
char		*ensure_absolute_path(char*);
int		 check_block_code(int);
char		*check_block_fmt(char*);
int		 check_strip_no(int);
int		 check_prefork_num(int);
void		 advance_loc(void);
void		 only_once(const void*, const char*);
void		 only_oncei(int, const char*);
int		 fastcgi_conf(char *, char *, char *);
void		 add_param(char *, char *, int);
int		 symset(const char *, const char *, int);
char		*symget(const char *);

%}

/* for bison: */
/* %define parse.error verbose */

%token	TIPV6 TPORT TPROTOCOLS TMIME TDEFAULT TTYPE TCHROOT TUSER TSERVER
%token	TPREFORK TLOCATION TCERT TKEY TROOT TCGI TENV TLANG TLOG TINDEX TAUTO
%token	TSTRIP TBLOCK TRETURN TENTRYPOINT TREQUIRE TCLIENT TCA TALIAS TTCP
%token	TFASTCGI TSPAWN TPARAM TMAP TTOEXT TARROW

%token	TERR

%token	<v.str>	TSTRING
%token	<v.num>	TNUM
%token	<v.num>	TBOOL

%type	<v.str>	string

%%

conf		: /* empty */
		| conf var
		| conf option
		| conf vhost
		;

string		: string TSTRING {
			if (asprintf(&$$, "%s%s", $1, $2) == -1) {
				free($1);
				free($2);
				yyerror("string: asprintf: %s", strerror(errno));
				YYERROR;
			}
			free($1);
			free($2);
		}
		| TSTRING
		;

var		: TSTRING '=' string {
			char *s = $1;
			while (*s++) {
				if (isspace(*s)) {
					yyerror("macro name cannot contain "
					    "whitespaces");
					free($1);
					free($3);
					YYERROR;
				}
			}
			symset($1, $3, 0);
			free($1);
			free($3);
		}
		;

option		: TCHROOT string	{ conf.chroot = $2; }
		| TIPV6 TBOOL		{ conf.ipv6 = $2; }
		| TMIME TSTRING string	{
			fprintf(stderr, "%s:%d: `mime MIME EXT' is deprecated and "
			    "will be removed in a future version, "
			    "please use the new syntax: `map MIME to-ext EXT'",
			    config_path, yylval.lineno+1);
			add_mime(&conf.mime, $2, $3);
		}
		| TMAP string TTOEXT string { add_mime(&conf.mime, $2, $4); }
		| TPORT TNUM		{ conf.port = $2; }
		| TPREFORK TNUM		{ conf.prefork = check_prefork_num($2); }
		| TPROTOCOLS string {
			if (tls_config_parse_protocols(&conf.protos, $2) == -1)
				yyerror("invalid protocols string \"%s\"", $2);
		}
		| TUSER string		{ conf.user = $2; }
		;

vhost		: TSERVER string {
			host = new_vhost();
			TAILQ_INSERT_HEAD(&hosts, host, vhosts);

			loc = new_location();
			TAILQ_INSERT_HEAD(&host->locations, loc, locations);

			loc->match = xstrdup("*");
			host->domain = $2;

			if (strstr($2, "xn--") != NULL) {
				warnx("%s:%d:%d \"%s\" looks like punycode: "
				    "you should use the decoded hostname.",
				    config_path, yylval.lineno+1, yylval.colno,
				    $2);
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

servopt		: TALIAS string {
			struct alist *a;

			a = xcalloc(1, sizeof(*a));
			a->alias = $2;
			if (TAILQ_EMPTY(&host->aliases))
				TAILQ_INSERT_HEAD(&host->aliases, a, aliases);
			else
				TAILQ_INSERT_TAIL(&host->aliases, a, aliases);
		}
		| TCERT string		{
			only_once(host->cert, "cert");
			host->cert = ensure_absolute_path($2);
		}
		| TCGI string		{
			only_once(host->cgi, "cgi");
			/* drop the starting '/', if any */
			if (*$2 == '/')
				memmove($2, $2+1, strlen($2));
			host->cgi = $2;
		}
		| TENTRYPOINT string {
			only_once(host->entrypoint, "entrypoint");
			while (*$2 == '/')
				memmove($2, $2+1, strlen($2));
			host->entrypoint = $2;
		}
		| TENV string TARROW string {
			add_param($2, $4, 1);
		}
		| TKEY string		{
			only_once(host->key, "key");
			host->key  = ensure_absolute_path($2);
		}
		| TPARAM string TARROW string {
			add_param($2, $4, 0);
		}
		| locopt
		;

locations	: /* empty */
		| locations location
		;

location	: TLOCATION { advance_loc(); } string '{' locopts '}'	{
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
		| TBLOCK TRETURN TNUM string {
			only_once(loc->block_fmt, "block");
			loc->block_fmt = check_block_fmt($4);
			loc->block_code = check_block_code($3);
		}
		| TBLOCK TRETURN TNUM {
			only_once(loc->block_fmt, "block");
			loc->block_fmt = xstrdup("temporary failure");
			loc->block_code = check_block_code($3);
			if ($3 >= 30 && $3 < 40)
				yyerror("missing `meta' for block return %d", $3);
		}
		| TBLOCK {
			only_once(loc->block_fmt, "block");
			loc->block_fmt = xstrdup("temporary failure");
			loc->block_code = 40;
		}
		| TDEFAULT TTYPE string {
			only_once(loc->default_mime, "default type");
			loc->default_mime = $3;
		}
		| TFASTCGI fastcgi
		| TINDEX string {
			only_once(loc->index, "index");
			loc->index = $2;
		}
		| TLANG string {
			only_once(loc->lang, "lang");
			loc->lang = $2;
		}
		| TLOG TBOOL	{ loc->disable_log = !$2; }
		| TREQUIRE TCLIENT TCA string {
			only_once(loc->reqca, "require client ca");
			ensure_absolute_path($4);
			if ((loc->reqca = load_ca($4)) == NULL)
				yyerror("couldn't load ca cert: %s", $4);
			free($4);
		}
		| TROOT string		{
			only_once(loc->dir, "root");
			loc->dir  = ensure_absolute_path($2);
		}
		| TSTRIP TNUM		{ loc->strip = check_strip_no($2); }
		;

fastcgi		: TSPAWN string {
			only_oncei(loc->fcgi, "fastcgi");
			loc->fcgi = fastcgi_conf(NULL, NULL, $2);
		}
		| string {
			only_oncei(loc->fcgi, "fastcgi");
			loc->fcgi = fastcgi_conf($1, NULL, NULL);
		}
		| TTCP string TPORT TNUM {
			char *c;
			if (asprintf(&c, "%d", $4) == -1)
				err(1, "asprintf");
			only_oncei(loc->fcgi, "fastcgi");
			loc->fcgi = fastcgi_conf($2, c, NULL);
		}
		| TTCP string {
			only_oncei(loc->fcgi, "fastcgi");
			loc->fcgi = fastcgi_conf($2, xstrdup("9000"), NULL);
		}
		| TTCP string TPORT string {
			only_oncei(loc->fcgi, "fastcgi");
			loc->fcgi = fastcgi_conf($2, $4, NULL);
		}
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
	l->fcgi = -1;
	return l;
}

void
yyerror(const char *msg, ...)
{
	va_list ap;

	goterror = 1;

	va_start(ap, msg);
	fprintf(stderr, "%s:%d: ", config_path, yylval.lineno);
	vfprintf(stderr, msg, ap);
	fprintf(stderr, "\n");
	va_end(ap);
}

static struct keyword {
	const char *word;
	int token;
} keywords[] = {
	/* these MUST be sorted */
	{"alias", TALIAS},
	{"auto", TAUTO},
	{"block", TBLOCK},
	{"ca", TCA},
	{"cert", TCERT},
	{"cgi", TCGI},
	{"chroot", TCHROOT},
	{"client", TCLIENT},
	{"default", TDEFAULT},
	{"entrypoint", TENTRYPOINT},
	{"env", TENV},
	{"fastcgi", TFASTCGI},
	{"index", TINDEX},
	{"ipv6", TIPV6},
	{"key", TKEY},
	{"lang", TLANG},
	{"location", TLOCATION},
	{"log", TLOG},
	{"map", TMAP},
	{"mime", TMIME},
	{"param", TPARAM},
	{"port", TPORT},
	{"prefork", TPREFORK},
	{"protocols", TPROTOCOLS},
	{"require", TREQUIRE},
	{"return", TRETURN},
	{"root", TROOT},
	{"server", TSERVER},
	{"spawn", TSPAWN},
	{"strip", TSTRIP},
	{"tcp", TTCP},
	{"to-ext", TTOEXT},
	{"type", TTYPE},
	{"user", TUSER},
};

int
kw_cmp(const void *k, const void *e)
{
	return strcmp(k, ((struct keyword *)e)->word);
}

/*
 * Taken an adapted from doas' parse.y
 */
static int
yylex(void)
{
	struct keyword *kw;
	char buf[8096], *ebuf, *p, *str, *v, *val;
	int c, quotes = 0, escape = 0, qpos = -1, nonkw = 0;
	size_t len;

	p = buf;
	ebuf = buf + sizeof(buf);

repeat:
	/* skip whitespace first */
	for (c = getc(yyfp); isspace(c); c = getc(yyfp)) {
		yylval.colno++;
		if (c == '\n') {
			yylval.lineno++;
			yylval.colno = 0;
		}
	}

	/* check for special one-character constructions */
	switch (c) {
	case '{':
	case '}':
		return c;
	case '#':
		/* skip comments; NUL is allowed; no continuation */
		while ((c = getc(yyfp)) != '\n')
			if (c == EOF)
				goto eof;
		yylval.colno = 0;
		yylval.lineno++;
		goto repeat;
	case '=':
		if ((c = getc(yyfp)) == '>')
			return TARROW;
		ungetc(c, yyfp);
		return '=';
	case EOF:
		goto eof;
	}

	/* parsing next word */
	for (;; c = getc(yyfp), yylval.colno++) {
		switch (c) {
		case '\0':
			yyerror("unallowed character NULL in column %d",
			    yylval.colno+1);
			escape = 0;
			continue;
		case '\\':
			escape = !escape;
			if (escape)
				continue;
			break;

		/* expand macros in-place */
		case '$':
			if (!escape && !quotes) {
				v = p;
				while (1) {
					if ((c = getc(yyfp)) == EOF) {
						yyerror("EOF during macro expansion");
                                                return 0;
					}
					if (p + 1 >= ebuf - 1) {
						yyerror("string too long");
						return 0;
					}
					if (isalnum(c) || c == '_') {
						*p++ = c;
						continue;
					}
					*p = 0;
					break;
				}
				p = v;
				if ((val = symget(p)) == NULL) {
					yyerror("macro '%s' not defined", v);
					return TERR;
				}
				len = strlen(val);
				if (p + len >= ebuf - 1) {
					yyerror("after macro-expansion, "
					    "string too long");
					return TERR;
				}
				*p = '\0';
				strlcat(p, val, ebuf - p);
				p += len;
				nonkw = 1;
				goto eow;
			}
			break;
		case '\n':
			if (quotes)
				yyerror("unterminated quotes in column %d",
				    yylval.colno+1);
			if (escape) {
				nonkw = 1;
				escape = 0;
				yylval.colno = 0;
				yylval.lineno++;
			}
			goto eow;
		case EOF:
			if (escape)
				yyerror("unterminated escape in column %d",
				    yylval.colno);
			if (quotes)
				yyerror("unterminated quotes in column %d",
				    qpos+1);
			goto eow;
		case '{':
		case '}':
		case '#':
		case ' ':
		case '\t':
                        if (!escape && !quotes)
				goto eow;
			break;
		case '"':
			if (!escape) {
				quotes = !quotes;
				if (quotes) {
					nonkw = 1;
					qpos = yylval.colno;
				}
				continue;
			}
		}
		*p++ = c;
		if (p == ebuf) {
			yyerror("line too long");
			p = buf;
		}
		escape = 0;
	}

eow:
	*p = 0;
	if (c != EOF)
		ungetc(c, yyfp);
	if (p == buf) {
		/*
		 * There could be a number of reason for empty buffer,
		 * and we handle all of them here, to avoid cluttering
		 * the main loop.
		 */
		if (c == EOF)
			goto eof;
		else if (qpos == -1) /* accept, e.g., empty args: cmd foo args "" */
			goto repeat;
	}
	if (!nonkw) {
		kw = bsearch(buf, keywords, sizeof(keywords)/sizeof(keywords[0]),
		    sizeof(keywords[0]), kw_cmp);
		if (kw != NULL)
			return kw->token;
	}
	c = *buf;
	if (!nonkw && (c == '-' || isdigit(c))) {
		yylval.v.num = parse_portno(buf);
		return TNUM;
	}
	if (!nonkw && !strcmp(buf, "on")) {
		yylval.v.num = 1;
		return TBOOL;
	}
	if (!nonkw && !strcmp(buf, "off")) {
		yylval.v.num = 0;
		return TBOOL;
	}
	if ((str = strdup(buf)) == NULL)
		err(1, "%s", __func__);
	yylval.v.str = str;
	return TSTRING;

eof:
	if (ferror(yyfp))
		yyerror("input error reading config");
	return 0;
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
	struct sym	*sym, *next;

	config_path = path;
	if ((yyfp = fopen(path, "r")) == NULL)
		err(1, "cannot open config: %s", path);
	yyparse();
	fclose(yyfp);

	if (goterror)
		exit(1);

	if (TAILQ_FIRST(&hosts)->domain == NULL)
		errx(1, "no vhost defined in %s", path);

	/* free unused macros */
	TAILQ_FOREACH_SAFE(sym, &symhead, entry, next) {
		/* TODO: warn if !sym->used */
		if (!sym->persist) {
			free(sym->name);
			free(sym->val);
			TAILQ_REMOVE(&symhead, sym, entry);
			free(sym);
		}
	}
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

void
only_once(const void *ptr, const char *name)
{
	if (ptr != NULL)
		yyerror("`%s' specified more than once", name);
}

void
only_oncei(int i, const char *name)
{
	if (i != -1)
		yyerror("`%s' specified more than once", name);
}

int
fastcgi_conf(char *path, char *port, char *prog)
{
	struct fcgi	*f;
	int		i;

	for (i = 0; i < FCGI_MAX; ++i) {
		f = &fcgi[i];

		if (f->path == NULL) {
			f->id = i;
			f->path = path;
			f->port = port;
			f->prog = prog;
			return i;
		}

		/* XXX: what to do with prog? */
		if (!strcmp(f->path, path) &&
		    ((port == NULL && f->port == NULL) ||
		     !strcmp(f->port, port))) {
			free(path);
			free(port);
			return i;
		}
	}

	yyerror("too much `fastcgi' rules defined.");
	return -1;
}

void
add_param(char *name, char *val, int env)
{
	struct envlist *e;
	struct envhead *h;

	if (env)
		h = &host->env;
	else
		h = &host->params;

	e = xcalloc(1, sizeof(*e));
	e->name = name;
	e->value = val;
	if (TAILQ_EMPTY(h))
		TAILQ_INSERT_HEAD(h, e, envs);
	else
		TAILQ_INSERT_TAIL(h, e, envs);
}

int
symset(const char *name, const char *val, int persist)
{
	struct sym *sym;

	TAILQ_FOREACH(sym, &symhead, entry) {
		if (!strcmp(name, sym->name))
			break;
	}

	if (sym != NULL) {
		if (sym->persist)
			return 0;
		else {
			free(sym->name);
			free(sym->val);
			TAILQ_REMOVE(&symhead, sym, entry);
			free(sym);
		}
	}

        sym = xcalloc(1, sizeof(*sym));
	sym->name = xstrdup(name);
	sym->val = xstrdup(val);
	sym->used = 0;
	sym->persist = persist;

	TAILQ_INSERT_TAIL(&symhead, sym, entry);
	return 0;
}

int
cmdline_symset(char *s)
{
	char	*sym, *val;
	int	 ret;

	if ((val = strrchr(s, '=')) == NULL)
		return -1;
	sym = xcalloc(1, val - s + 1);
	memcpy(sym, s, val - s);
	ret = symset(sym, val + 1, 1);
	free(sym);
	return ret;
}

char *
symget(const char *name)
{
	struct sym	*sym;

	TAILQ_FOREACH(sym, &symhead, entry) {
		if (!strcmp(name, sym->name)) {
			sym->used = 1;
			return sym->val;
		}
	}

	return NULL;
}
