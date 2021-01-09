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

#include <ctype.h>
#include <string.h>

#include "gmid.h"

/*
 * Notes from RFC3986
 *
 * => gemini://tanso.net/rfc/rfc3986.txt
 *
 *
 * ABNF
 * ====
 *
 * pct-encoded	"%" HEXDIG HEXDIG
 *
 * reserved	= gen-delims / sub-delimis
 * gen-delims	= ":" / "/" / "?" / "#" / "[" / "]" / "@"
 * sub-delims	= "!" / "$" / "&" / "'" / "(" / ")"
 * 		/ "*" / "+" / "," / ";" / "="
 *
 * unreserved	= ALPHA / DIGIT / "-" / "." / "_" / "~"
 *
 * URI		= scheme ":" hier-part [ "?" query ] [ "#" fragment ]
 *
 * hier-part	= "//" authority path-abempty
 * 		/ path-absolute
 * 		/ path-rootless
 * 		/ path-empty
 *
 * scheme	= ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
 *
 * authority	= [ userinfo "@" ] host [ ":" port ]
 *
 * (note that userinfo isn't used for Gemini URL)
 *
 * host		= IP-literal / IPv4address / reg-name
 * reg-name	= *( unreserved / pct-encoded / sub-delims )
 *
 * port		= *DIGIT
 *
 * path		= path-abemty	; begins with "/" or is empty
 * 		/ path-absolute	; begins with "/" but not "//"
 * 		/ path-noscheme	; begins with a non-colon segment
 * 		/ path-rootless ; begins with a segment
 * 		/ path-empty	; zero characters
 *
 * path-abemty		= *( "/" segment )
 * path-absolute	= "/" [ segment-nz *( "/" segment ) ]
 * path-noscheme	= ; not used
 * path-rootless	= ; not used
 * path-empty		= ; not used
 *
 * segment		= *pchar
 * segment-nz	= 1*pchar
 * segment-nz-nc	= 1*( unreserved / pct-encoded / sub-delims / "@" )
 * pchar		= unreserved / pct-encoded / sub-delims / ":" / "@"
 *
 * query		= *( pchar / "/" / "?" )
 *
 * fragment		= *( pchar / "/" / "?" )
 *
 *
 * EXAMPLE
 * =======
 *
 *    foo://example.com:8042/over/there?name=ferret#nose
 *    \_/   \______________/\_________/ \_________/ \__/
 *     |           |            |            |        |
 *  scheme     authority       path        query   fragment
 *
 */

/* XXX: these macros will expand multiple times their argument */

#define UNRESERVED(p)				\
	(isalnum(p)				\
	    || p == '-'				\
	    || p == '.'				\
	    || p == '_'				\
	    || p == '~')

#define SUB_DELIMITERS(p)			\
	(p == '!'				\
	    || p == '$'				\
	    || p == '&'				\
	    || p == '\''			\
	    || p == '('				\
	    || p == ')'				\
	    || p == '*'				\
	    || p == '+'				\
	    || p == ','				\
	    || p == ';'				\
	    || p == '=')

static int
parse_pct_encoded(struct parser *p)
{
	if (*p->uri != '%')
		return 0;

	if (!isxdigit(*(p->uri+1)) || !isxdigit(*(p->uri+2))) {
		p->err = "illegal percent-encoding";
		return 0;
	}

	sscanf(p->uri+1, "%2hhx", p->uri);
	memmove(p->uri+1, p->uri+3, strlen(p->uri+3)+1);
	if (*p->uri == '\0') {
		p->err = "illegal percent-encoding";
		return 0;
	}

	return 1;
}

/* ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) "://" */
static int
parse_scheme(struct parser *p)
{
	p->parsed->schema = p->uri;

	if (!isalpha(*p->uri)) {
		p->err = "illegal character in scheme";
		return 0;
	}

	p->uri++;
	while (isalnum(*p->uri)
	    || *p->uri == '+'
	    || *p->uri == '-'
	    || *p->uri == '.')
		p->uri++;

	if (*p->uri != ':') {
		p->err = "illegal character in scheme";
		return 0;
	}

	*p->uri = '\0';
	if (*(++p->uri) != '/' || *(++p->uri) != '/') {
		p->err = "invalid marker after scheme";
		return 0;
	}

	p->uri++;
	return 1;
}

/* *DIGIT */
static int
parse_port(struct parser *p)
{
	uint32_t i = 0;

	p->parsed->port = p->uri;

	for (; isdigit(*p->uri); p->uri++) {
		i = i * 10 + *p->uri - '0';
		if (i > UINT16_MAX) {
			p->err = "port number too large";
			return 0;
		}
	}

	if (*p->uri != '/' && *p->uri != '\0') {
		p->err = "illegal character in port number";
		return 0;
	}

	p->parsed->port_no = i;

	if (*p->uri != '\0') {
		*p->uri = '\0';
		p->uri++;
	}

	return 1;
}

/* TODO: add support for ip-literal and ipv4addr ? */
/* *( unreserved / sub-delims / pct-encoded ) */
static int
parse_authority(struct parser *p)
{
	p->parsed->host = p->uri;

	while (UNRESERVED(*p->uri)
	    || SUB_DELIMITERS(*p->uri)
	    || parse_pct_encoded(p))
		p->uri++;

	if (p->err != NULL)
		return 0;

	if (*p->uri == ':') {
		*p->uri = '\0';
		p->uri++;
		return parse_port(p);
	}

	if (*p->uri == '/') {
		*p->uri = '\0';
		p->uri++;
		return 1;
	}

	if (*p->uri == '\0')
		return 1;

	p->err = "illegal character in authority section";
	return 0;
}

/* Routine for path_clean.  Elide the pointed .. with the preceding
 * element.  Return 0 if it's not possible.  incr is the length of
 * the increment, 3 for ../ and 2 for .. */
static int
path_elide_dotdot(char *path, char *i, int incr)
{
	char *j;

	if (i == path)
		return 0;
	for (j = i-2; j != path && *j != '/'; j--)
                /* noop */ ;
	if (*j == '/')
		j++;
	i += incr;
	memmove(j, i, strlen(i)+1);
	return 1;
}

/*
 * Use an algorithm similar to the one implemented in go' path.Clean:
 *
 * 1. Replace multiple slashes with a single slash
 * 2. Eliminate each . path name element
 * 3. Eliminate each inner .. along with the non-.. element that precedes it
 * 4. Eliminate trailing .. if possible or error (go would only discard)
 *
 * Unlike path.Clean, this function return the empty string if the
 * original path is equivalent to "/".
 */
static int
path_clean(char *path)
{
	char *i;

	/* 1. replace multiple slashes with a single one */
	for (i = path; *i; ++i) {
		if (*i == '/' && *(i+1) == '/') {
			memmove(i, i+1, strlen(i)); /* move also the \0 */
			i--;
		}
	}

	/* 2. eliminate each . path name element */
	for (i = path; *i; ++i) {
		if ((i == path || *i == '/') && *(i+1) == '.' &&
		    *(i+2) == '/') {
			/* move also the \0 */
			memmove(i, i+2, strlen(i)-1);
			i--;
		}
	}
	if (!strcmp(path, ".") || !strcmp(path, "/.")) {
		*path = '\0';
		return 1;
	}

	/* 3. eliminate each inner .. along with the preceding non-.. */
	for (i = strstr(path, "../"); i != NULL; i = strstr(path, ".."))
		if (!path_elide_dotdot(path, i, 3))
			return 0;

	/* 4. eliminate trailing ..*/
	if ((i = strstr(path, "..")) != NULL)
		if (!path_elide_dotdot(path, i, 2))
			return 0;

	return 1;
}

static int
parse_query(struct parser *p)
{
	p->parsed->query = p->uri;
	if (*p->uri == '\0')
		return 1;

	while (UNRESERVED(*p->uri)
	    || SUB_DELIMITERS(*p->uri)
	    || *p->uri == '/'
	    || *p->uri == '?'
	    || parse_pct_encoded(p)
	    || valid_multibyte_utf8(p))
		p->uri++;

	if (p->err != NULL)
		return 0;

	if (*p->uri != '\0' && *p->uri != '#') {
		p->err = "illegal character in query";
		return 0;
	}

	if (*p->uri != '\0') {
		*p->uri = '\0';
		p->uri++;
	}

	return 1;
}

/* don't even bother */
static int
parse_fragment(struct parser *p)
{
	p->parsed->fragment = p->uri;
	return 1;
}

/* XXX: is it too broad? */
/* *(pchar / "/") */
static int
parse_path(struct parser *p)
{
	char c;

	p->parsed->path = p->uri;
	if (*p->uri == '\0') {
		p->parsed->query = p->parsed->fragment = p->uri;
		return 1;
	}

	while (UNRESERVED(*p->uri)
	    || SUB_DELIMITERS(*p->uri)
	    || *p->uri == '/'
	    || parse_pct_encoded(p)
	    || valid_multibyte_utf8(p))
		p->uri++;

	if (p->err != NULL)
		return 0;

	if (*p->uri != '\0' && *p->uri != '?' && *p->uri != '#') {
		p->err = "illegal character in path";
		return 0;
	}

	if (*p->uri != '\0') {
		c = *p->uri;
		*p->uri = '\0';
		p->uri++;

		if (c == '#') {
			if (!parse_fragment(p))
				return 0;
		} else
			if (!parse_query(p) || !parse_fragment(p))
				return 0;
	}

	if (!path_clean(p->parsed->path)) {
		p->err = "illegal path";
		return 0;
	}

	return 1;
}

int
parse_uri(char *uri, struct uri *ret, const char **err_ret)
{
	char *end;
	struct parser p = {uri, ret, NULL};

	bzero(ret, sizeof(*ret));

	/* initialize optional stuff to the empty string */
	end = uri + strlen(uri);
	p.parsed->port = end;
	p.parsed->path = end;
	p.parsed->query = end;
	p.parsed->fragment = end;

	if (!parse_scheme(&p) || !parse_authority(&p) || !parse_path(&p)) {
		*err_ret = p.err;
		return 0;
	}

	*err_ret = NULL;
	return 1;
}

int
trim_req_uri(char *uri)
{
	char *i;

	if ((i = strstr(uri, "\r\n")) == NULL)
		return 0;
	*i = '\0';
	return 1;
}
