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
#include <errno.h>

#include "gmid.h"

#include "y.tab.h"

%}

%x COMMENT
%x STRING

%%

<INITIAL>#	BEGIN(COMMENT);
<COMMENT>.*\n	yylineno++; BEGIN(INITIAL);

<INITIAL>\"	BEGIN(STRING);
<STRING>[^"]*\"	{
	if ((yylval.str = strdup(yytext)) == NULL)
		err(1, "strdup");
	yylval.str[strlen(yylval.str)-1] = '\0'; /* remove the closing quote */
	BEGIN(INITIAL);
	return TSTRING;
}

[0-9]+		{
	yylval.num = parse_portno(yytext);
	return TNUM;
}

off		yylval.num = 0; return TBOOL;
on		yylval.num = 1; return TBOOL;

auto		return TAUTO;
block		return TBLOCK;
ca		return TCA;
cert		return TCERT;
cgi		return TCGI;
chroot		return TCHROOT;
client		return TCLIENT;
default		return TDEFAULT;
entrypoint	return TENTRYPOINT;
index		return TINDEX;
ipv6		return TIPV6;
key		return TKEY;
lang		return TLANG;
location	return TLOCATION;
log		return TLOG;
mime		return TMIME;
port		return TPORT;
prefork		return TPREFORK;
protocols	return TPROTOCOLS;
require		return TREQUIRE;
return		return TRETURN;
root		return TROOT;
server		return TSERVER;
strip		return TSTRIP;
type		return TTYPE;
user		return TUSER;

[{}]		return *yytext;

\n		yylineno++;

[ \f\r\t\v]+	;

.		yyerror("unexpected character: %c", *yytext); exit(1);

%%

int
yywrap(void)
{
	return 1;
}
