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

#include <stdio.h>
#include <string.h>

#include "../gmid.h"

struct suite {
	const char	*src;
	const char	*res;
} t[] = {
	{"foo",			"foo"},
	{"h.n",			"h.n"},
	{"xn-invalid",		"xn-invalid"},
	{"naïve",		"naïve"},
	{"xn--8ca",		"è"},
	{"xn--caff-8oa",	"caffè"},
	{"xn--nave-6pa",	"naïve"},
	{"xn--e-0mbbc",		"τeστ"},
	{"xn--8ca67lbac",	"τèστ"},
	{"xn--28j2a3ar1p",	"こんにちは"},
	{"xn--hello--ur7iy09x",	"hello-世界"},
	{"xn--hi--hi-rr7iy09x",	"hi-世界-hi"},
	{"xn--caf-8la.foo.org",	"cafè.foo.org"},
	/* 3 bytes */
	{"xn--j6h",		"♨"},
	/* 4 bytes */
	{"xn--x73l",		"𩸽"},
	{"xn--x73laaa",		"𩸽𩸽𩸽𩸽"},
	{NULL, NULL}
};

int
main(int argc, char **argv)
{
	struct suite *i;
	int failed;
	char buf[64];		/* name len */

	failed = 0;
	for (i = t; i->src != NULL; ++i) {
		memset(buf, 0, sizeof(buf));
		if (!puny_decode(i->src, buf, sizeof(buf))) {
                        printf("decode: failure with %s\n", i->src);
                        failed = 1;
			continue;
		}

		if (strcmp(buf, i->res)) {
			printf("ERR: expected \"%s\", got \"%s\"\n",
			    i->res, buf);
			failed = 1;
			continue;
		} else
			printf("OK:  %s => %s\n", i->src, buf);
	}

	return failed;
}
