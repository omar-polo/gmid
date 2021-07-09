%{

/*
 * Copyright (c) 2021 Omar Polo <op@omarpolo.com>
 * Copyright (c) 2018 Florian Obser <florian@openbsd.org>
 * Copyright (c) 2004, 2005 Esben Norby <norby@openbsd.org>
 * Copyright (c) 2004 Ryan McBride <mcbride@openbsd.org>
 * Copyright (c) 2002, 2003, 2004 Henning Brauer <henning@openbsd.org>
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2001 Daniel Hartmeier.  All rights reserved.
 * Copyright (c) 2001 Theo de Raadt.  All rights reserved.
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

TAILQ_HEAD(files, file)		 files = TAILQ_HEAD_INITIALIZER(files);
static struct file {
	TAILQ_ENTRY(file)	 entry;
	FILE			*stream;
	char			*name;
	size_t	 		 ungetpos;
	size_t			 ungetsize;
	u_char			*ungetbuf;
	int			 eof_reached;
	int			 lineno;
	int			 errors;
} *file, *topfile;

struct file	*pushfile(const char *, int);
int		 popfile(void);
int		 yyparse(void);
int		 yylex(void);
void		 yyerror(const char *, ...)
    __attribute__((__format__ (printf, 1, 2)))
    __attribute__((__nonnull__ (1)));
int		 kw_cmp(const void *, const void *);
int		 lookup(char *);
int		 igetc(void);
int		 lgetc(int);
void		 lungetc(int);
int		 findeol(void);

/*
 * #define YYDEBUG 1
 * int yydebug = 1;
 */

TAILQ_HEAD(symhead, sym) symhead = TAILQ_HEAD_INITIALIZER(symhead);
struct sym {
	TAILQ_ENTRY(sym)	 entry;
	int			 used;
	int			 persist;
	char			*name;
	char			*val;
};

int	 symset(const char *, const char *, int);
char	*symget(const char *);

struct vhost	*new_vhost(void);
struct location	*new_location(void);
int		 parse_portno(const char*);
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

static struct vhost		*host;
static struct location		*loc;
static int			 errors;

typedef struct {
	union {
		char	*string;
		int	 number;
	} v;
	int lineno;
} YYSTYPE;

%}

/* for bison: */
/* %define parse.error verbose */

%token	TIPV6 TPORT TPROTOCOLS TMIME TDEFAULT TTYPE TCHROOT TUSER TSERVER
%token	TPREFORK TLOCATION TCERT TKEY TROOT TCGI TENV TLANG TLOG TINDEX TAUTO
%token	TSTRIP TBLOCK TRETURN TENTRYPOINT TREQUIRE TCLIENT TCA TALIAS TTCP
%token	TFASTCGI TSPAWN TPARAM TMAP TTOEXT INCLUDE TON TOFF

%token	ERROR

%token	<v.string>	STRING
%token	<v.number>	NUM

%type	<v.number>	bool
%type	<v.string>	string

%%

conf		: /* empty */
		| conf include '\n'
		| conf '\n'
		| conf varset '\n'
		| conf option '\n'
		| conf vhost '\n'
		| conf error '\n'		{ file->errors++; }
		;

include		: INCLUDE STRING		{
			struct file	*nfile;

			if ((nfile = pushfile($2, 0)) == NULL) {
				yyerror("failed to include file %s", $2);
				free($2);
				YYERROR;
			}
			free($2);

			file = nfile;
			lungetc('\n');
		}
		;

bool		: TON	{ $$ = 1; }
		| TOFF	{ $$ = 0; }
		;

string		: string STRING	{
			if (asprintf(&$$, "%s%s", $1, $2) == -1) {
				free($1);
				free($2);
				yyerror("string: asprintf: %s", strerror(errno));
				YYERROR;
			}
			free($1);
			free($2);
		}
		| STRING
		;

varset		: STRING '=' string		{
			char *s = $1;
			while (*s++) {
				if (isspace((unsigned char)*s)) {
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
		| TIPV6 bool		{ conf.ipv6 = $2; }
		| TMIME STRING string	{
			fprintf(stderr, "%s:%d: `mime MIME EXT' is deprecated and "
			    "will be removed in a future version, "
			    "please use the new syntax: `map MIME to-ext EXT'",
			    config_path, yylval.lineno+1);
			add_mime(&conf.mime, $2, $3);
		}
		| TMAP string TTOEXT string { add_mime(&conf.mime, $2, $4); }
		| TPORT NUM		{ conf.port = $2; }
		| TPREFORK NUM		{ conf.prefork = check_prefork_num($2); }
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
				warnx("%s:%d \"%s\" looks like punycode: "
				    "you should use the decoded hostname.",
				    config_path, yylval.lineno+1, $2);
			}
		} '{' optnl servopts locations '}' {
			if (host->cert == NULL || host->key == NULL)
				yyerror("invalid vhost definition: %s", $2);
		}
		| error '}'		{ yyerror("error in server directive"); }
		;

servopts	: /* empty */
		| servopts servopt optnl
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
		| TENV string '=' string {
			add_param($2, $4, 1);
		}
		| TKEY string		{
			only_once(host->key, "key");
			host->key  = ensure_absolute_path($2);
		}
		| TPARAM string '=' string {
			add_param($2, $4, 0);
		}
		| locopt
		;

locations	: /* empty */
		| locations location optnl
		;

location	: TLOCATION { advance_loc(); } string '{' optnl locopts '}' {
			/* drop the starting '/' if any */
			if (*$3 == '/')
				memmove($3, $3+1, strlen($3));
			loc->match = $3;
		}
		| error '}'
		;

locopts		: /* empty */
		| locopts locopt optnl
		;

locopt		: TAUTO TINDEX bool	{ loc->auto_index = $3 ? 1 : -1; }
		| TBLOCK TRETURN NUM string {
			only_once(loc->block_fmt, "block");
			loc->block_fmt = check_block_fmt($4);
			loc->block_code = check_block_code($3);
		}
		| TBLOCK TRETURN NUM {
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
		| TLOG bool	{ loc->disable_log = !$2; }
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
		| TSTRIP NUM		{ loc->strip = check_strip_no($2); }
		;

fastcgi		: TSPAWN string {
			only_oncei(loc->fcgi, "fastcgi");
			loc->fcgi = fastcgi_conf(NULL, NULL, $2);
		}
		| string {
			only_oncei(loc->fcgi, "fastcgi");
			loc->fcgi = fastcgi_conf($1, NULL, NULL);
		}
		| TTCP string TPORT NUM {
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

optnl		: '\n' optnl		/* zero or more newlines */
		| ';' optnl		/* semicolons too */
		| /*empty*/
		;

%%

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
	{"off", TOFF},
	{"on", TON},
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

void
yyerror(const char *msg, ...)
{
	va_list ap;

	file->errors++;

	va_start(ap, msg);
	fprintf(stderr, "%s:%d: ", config_path, yylval.lineno);
	vfprintf(stderr, msg, ap);
	fprintf(stderr, "\n");
	va_end(ap);
}

int
kw_cmp(const void *k, const void *e)
{
	return strcmp(k, ((struct keyword *)e)->word);
}

int
lookup(char *s)
{
	const struct keyword	*p;

	p = bsearch(s, keywords, sizeof(keywords)/sizeof(keywords[0]),
	    sizeof(keywords[0]), kw_cmp);

	if (p)
		return p->token;
	else
		return STRING;
}

#define START_EXPAND	1
#define DONE_EXPAND	2

static int	expanding;

int
igetc(void)
{
	int	c;

	while (1) {
		if (file->ungetpos > 0)
			c = file->ungetbuf[--file->ungetpos];
		else
			c = getc(file->stream);

		if (c == START_EXPAND)
			expanding = 1;
		else if (c == DONE_EXPAND)
			expanding = 0;
		else
			break;
	}
	return c;
}

int
lgetc(int quotec)
{
	int		c, next;

	if (quotec) {
		if ((c = igetc()) == EOF) {
			yyerror("reached end of file while parsing "
			    "quoted string");
			if (file == topfile || popfile() == EOF)
				return EOF;
			return quotec;
		}
		return c;
	}

	while ((c = igetc()) == '\\') {
		next = igetc();
		if (next != '\n') {
			c = next;
			break;
		}
		yylval.lineno = file->lineno;
		file->lineno++;
	}

	if (c == EOF) {
		/*
		 * Fake EOL when hit EOF for the first time. This gets line
		 * count right if last line in included file is syntactically
		 * invalid and has no newline.
		 */
		if (file->eof_reached == 0) {
			file->eof_reached = 1;
			return '\n';
		}
		while (c == EOF) {
			if (file == topfile || popfile() == EOF)
				return EOF;
			c = igetc();
		}
	}
	return c;
}

void
lungetc(int c)
{
	if (c == EOF)
		return;

	if (file->ungetpos >= file->ungetsize) {
		void *p = reallocarray(file->ungetbuf, file->ungetsize, 2);
		if (p == NULL)
			err(1, "lungetc");
		file->ungetbuf = p;
		file->ungetsize *= 2;
	}
	file->ungetbuf[file->ungetpos++] = c;
}

int
findeol(void)
{
	int	c;

	/* Skip to either EOF or the first real EOL. */
	while (1) {
		c = lgetc(0);
		if (c == '\n') {
			file->lineno++;
			break;
		}
		if (c == EOF)
			break;
	}
	return ERROR;
}

int
yylex(void)
{
	unsigned char	 buf[8096];
	unsigned char	*p, *val;
	int		 quotec, next, c;
	int		 token;

top:
	p = buf;
	while ((c = lgetc(0)) == ' ' || c == '\t')
		; /* nothing */

	yylval.lineno = file->lineno;
	if (c == '#')
		while ((c = lgetc(0)) != '\n' && c != EOF)
			; /* nothing */
	if (c == '$' && !expanding) {
		while (1) {
			if ((c = lgetc(0)) == EOF)
				return 0;
			if (p + 1 >= buf + sizeof(buf) -1) {
				yyerror("string too long");
				return findeol();
			}
			if (isalnum(c) || c == '_') {
				*p++ = c;
				continue;
			}
			*p = '\0';
			lungetc(c);
			break;
		}
		val = symget(buf);
		if (val == NULL) {
			yyerror("macro `%s' not defined", buf);
			return findeol();
		}
		yylval.v.string = xstrdup(val);
		return STRING;
	}
	if (c == '@' && !expanding) {
		while (1) {
			if ((c = lgetc(0)) == EOF)
				return 0;

			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return findeol();
			}
			if (isalnum(c) || c == '_') {
				*p++ = c;
				continue;
			}
			*p = '\0';
			lungetc(c);
			break;
		}
		val = symget(buf);
		if (val == NULL) {
			yyerror("macro '%s' not defined", buf);
			return findeol();
		}
		p = val + strlen(val) - 1;
		lungetc(DONE_EXPAND);
		while (p >= val) {
			lungetc(*p);
			p--;
		}
		lungetc(START_EXPAND);
		goto top;
	}

	switch (c) {
	case '\'':
	case '"':
		quotec = c;
		while (1) {
			if ((c = lgetc(quotec)) == EOF)
				return 0;
			if (c == '\n') {
				file->lineno++;
				continue;
			} else if (c == '\\') {
				if ((next = lgetc(quotec)) == EOF)
					return (0);
				if (next == quotec || next == ' ' ||
				    next == '\t')
					c = next;
				else if (next == '\n') {
					file->lineno++;
					continue;
				} else
					lungetc(next);
			} else if (c == quotec) {
				*p = '\0';
				break;
			} else if (c == '\0') {
				yyerror("syntax error");
				return findeol();
			}
			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return findeol();
			}
			*p++ = c;
		}
		yylval.v.string = strdup(buf);
		if (yylval.v.string == NULL)
			err(1, "yylex: strdup");
		return STRING;
	}

#define allowed_to_end_number(x) \
	(isspace(x) || x == ')' || x ==',' || x == '/' || x == '}' || x == '=')

	if (c == '-' || isdigit(c)) {
		do {
			*p++ = c;
			if ((size_t)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return findeol();
			}
		} while ((c = lgetc(0)) != EOF && isdigit(c));
		lungetc(c);
		if (p == buf + 1 && buf[0] == '-')
			goto nodigits;
		if (c == EOF || allowed_to_end_number(c)) {
			const char *errstr = NULL;

			*p = '\0';
			yylval.v.number = strtonum(buf, LLONG_MIN,
			    LLONG_MAX, &errstr);
			if (errstr) {
				yyerror("\"%s\" invalid number: %s",
				    buf, errstr);
				return findeol();
			}
			return NUM;
		} else {
nodigits:
			while (p > buf + 1)
				lungetc(*--p);
			c = *--p;
			if (c == '-')
				return c;
		}
	}

#define allowed_in_string(x) \
	(isalnum(x) || (ispunct(x) && x != '(' && x != ')' && \
	x != '{' && x != '}' && \
	x != '!' && x != '=' && x != '#' && \
	x != ',' && x != ';'))

	if (isalnum(c) || c == ':' || c == '_') {
		do {
			*p++ = c;
			if ((size_t)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return findeol();
			}
		} while ((c = lgetc(0)) != EOF && (allowed_in_string(c)));
		lungetc(c);
		*p = '\0';
		if ((token = lookup(buf)) == STRING)
			yylval.v.string = xstrdup(buf);
		return token;
	}
	if (c == '\n') {
		yylval.lineno = file->lineno;
		file->lineno++;
	}
	if (c == EOF)
		return 0;
	return c;
}

struct file *
pushfile(const char *name, int secret)
{
	struct file	*nfile;

	nfile = xcalloc(1, sizeof(*nfile));
	nfile->name = xstrdup(name);
	if ((nfile->stream = fopen(nfile->name, "r")) == NULL) {
		yyerror("can't open %s: %s", nfile->name,
		    strerror(errno));
		free(nfile->name);
		free(nfile);
		return NULL;
	}
	nfile->lineno = TAILQ_EMPTY(&files) ? 1 : 0;
	nfile->ungetsize = 16;
	nfile->ungetbuf = xcalloc(1, nfile->ungetsize);
	TAILQ_INSERT_TAIL(&files, nfile, entry);
	return nfile;
}

int
popfile(void)
{
	struct file	*prev;

	if ((prev = TAILQ_PREV(file, files, entry)) != NULL)
		prev->errors += file->errors;

	TAILQ_REMOVE(&files, file, entry);
	fclose(file->stream);
	free(file->name);
	free(file->ungetbuf);
	free(file);
	file = prev;
	return file ? 0 : EOF;
}

void
parse_conf(const char *filename)
{
	struct sym		*sym, *next;

	file = pushfile(filename, 0);
	if (file == NULL)
		return;
	topfile = file;

	yyparse();
	errors = file->errors;
	popfile();

	/* Free macros and check which have not been used. */
	TAILQ_FOREACH_SAFE(sym, &symhead, entry, next) {
		/* TODO: warn if !sym->used */
		if (!sym->persist) {
			free(sym->name);
			free(sym->val);
			TAILQ_REMOVE(&symhead, sym, entry);
			free(sym);
		}
	}

	if (errors)
		exit(1);
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
symget(const char *nam)
{
	struct sym	*sym;

	TAILQ_FOREACH(sym, &symhead, entry) {
		if (strcmp(nam, sym->name) == 0) {
			sym->used = 1;
			return sym->val;
		}
	}
	return NULL;
}

struct vhost *
new_vhost(void)
{
	return xcalloc(1, sizeof(struct vhost));
}

struct location *
new_location(void)
{
	struct location *l;

	l = xcalloc(1, sizeof(*l));
	l->dirfd = -1;
	l->fcgi = -1;
	return l;
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
