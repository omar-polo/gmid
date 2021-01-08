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

#include <err.h>
#include <stdio.h>
#include <string.h>

#include "gmid.h"

#define TEST(uri, fail, exp, descr)				\
	if (!run_test(uri, fail, exp)) {			\
		fprintf(stderr, "%s:%d: error: %s\n",		\
		    __FILE__, __LINE__, descr);			\
		exit(1);					\
	}

#define URI(schema, host, port, path, query, frag)		\
	((struct uri){schema, host, port, 0, path, query, frag})

#define DIFF(wanted, got, field)					\
	if (wanted->field == NULL || got->field == NULL ||		\
	    strcmp(wanted->field, got->field)) {			\
		fprintf(stderr, #field ":\n\tgot: %s\n\twanted: %s\n",	\
		    got->field, wanted->field);				\
		return 0;						\
	}

#define PASS 0
#define FAIL 1

int
diff_uri(struct uri *p, struct uri *exp)
{
        DIFF(p, exp, schema);
        DIFF(p, exp, host);
        DIFF(p, exp, port);
        DIFF(p, exp, path);
        DIFF(p, exp, query);
        DIFF(p, exp, fragment);
	return 1;
}

int
run_test(const char *uri, int should_fail, struct uri expected)
{
	int failed, ok = 1;
	char *uri_copy;
	struct uri parsed;
	const char *error;

	if ((uri_copy = strdup(uri)) == NULL)
		err(1, "strdup");

	fprintf(stderr, "=> %s\n", uri);
	failed = !parse_uri(uri_copy, &parsed, &error);

	if (failed && should_fail)
		goto done;

	if (error != NULL)
		fprintf(stderr, "> %s\n", error);

	ok = !failed && !should_fail;
	if (ok)
		ok = diff_uri(&expected, &parsed);

done:
	free(uri_copy);
	return ok;
}

int
main(void)
{
	struct uri empty = {"", "", "", PASS, "", "", ""};

	TEST("http://omarpolo.com",
	    PASS,
	    URI("http", "omarpolo.com", "", "", "", ""),
	    "can parse uri with empty path");

	/* schema */
	TEST("omarpolo.com", FAIL, empty, "FAIL when the schema is missing");
	TEST("gemini:/omarpolo.com", FAIL, empty, "FAIL with invalid marker");
	TEST("gemini//omarpolo.com", FAIL, empty, "FAIL with invalid marker");
	TEST("h!!p://omarpolo.com", FAIL, empty, "FAIL with invalid schema");

	/* authority */
	TEST("gemini://omarpolo.com",
	    PASS,
	    URI("gemini", "omarpolo.com", "", "", "", ""),
	    "can parse authority with empty path");
	TEST("gemini://omarpolo.com/",
	    PASS,
	    URI("gemini", "omarpolo.com", "", "", "", ""),
	    "can parse authority with empty path (alt)")
	TEST("gemini://omarpolo.com:1965",
	    PASS,
	    URI("gemini", "omarpolo.com", "1965", "", "", ""),
	    "can parse with port and empty path");
	TEST("gemini://omarpolo.com:1965/",
	    PASS,
	    URI("gemini", "omarpolo.com", "1965", "", "", ""),
	    "can parse with port and empty path")
	TEST("gemini://omarpolo.com:196s",
	    FAIL,
	    empty,
	    "FAIL with invalid port number");

	/* path */
	TEST("gemini://omarpolo.com/foo/bar/baz",
	    PASS,
	    URI("gemini", "omarpolo.com", "", "foo/bar/baz", "", ""),
	    "parse simple paths");
	TEST("gemini://omarpolo.com/foo//bar///baz",
	    PASS,
	    URI("gemini", "omarpolo.com", "", "foo/bar/baz", "", ""),
	    "parse paths with multiple slashes");
	TEST("gemini://omarpolo.com/foo/./bar/./././baz",
	    PASS,
	    URI("gemini", "omarpolo.com", "", "foo/bar/baz", "", ""),
	    "parse paths with . elements");
	TEST("gemini://omarpolo.com/foo/bar/../bar/baz",
	    PASS,
	    URI("gemini", "omarpolo.com", "", "foo/bar/baz", "", ""),
	    "parse paths with .. elements");
	TEST("gemini://omarpolo.com/foo/../foo/bar/../bar/baz/../baz",
	    PASS,
	    URI("gemini", "omarpolo.com", "", "foo/bar/baz", "", ""),
	    "parse paths with multiple .. elements");
	TEST("gemini://omarpolo.com/foo/..",
	    PASS,
            URI("gemini", "omarpolo.com", "", "", "", ""),
	    "parse paths with a trailing ..");
	TEST("gemini://omarpolo.com/foo/../",
	    PASS,
            URI("gemini", "omarpolo.com", "", "", "", ""),
	    "parse paths with a trailing ..");
	TEST("gemini://omarpolo.com/foo/../..",
	    FAIL,
            empty,
	    "reject paths that would escape the root");
	TEST("gemini://omarpolo.com/foo/../foo/../././/bar/baz/.././.././/",
	    PASS,
            URI("gemini", "omarpolo.com", "", "", "", ""),
	    "parse path with lots of cleaning available");

	/* query */
	TEST("foo://example.com/foo/?gne",
	    PASS,
	    URI("foo", "example.com", "", "foo/", "gne", ""),
	    "parse query strings");
	TEST("foo://example.com/foo/?gne&foo",
	    PASS,
	    URI("foo", "example.com", "", "foo/", "gne&foo", ""),
	    "parse query strings");
	TEST("foo://example.com/foo/?gne%2F",
	    PASS,
	    URI("foo", "example.com", "", "foo/", "gne/", ""),
	    "parse query strings");

	/* fragment */
	TEST("foo://bar.co/#foo",
	    PASS,
	    URI("foo", "bar.co", "", "", "", "foo"),
	    "can recognize fragments");

	/* percent encoding */
	TEST("foo://bar.com/caf%C3%A8.gmi",
	    PASS,
	    URI("foo", "bar.com", "", "cafè.gmi", "", ""),
	    "can decode");
	TEST("foo://bar.com/caff%C3%A8%20macchiato.gmi",
	    PASS,
	    URI("foo", "bar.com", "", "caffè macchiato.gmi", "", ""),
	    "can decode");
	TEST("foo://bar.com/caff%C3%A8+macchiato.gmi",
	    PASS,
	    URI("foo", "bar.com", "", "caffè+macchiato.gmi", "", ""),
	    "can decode");
	TEST("foo://bar.com/foo%2F..%2F..",
	    FAIL,
	    empty,
	    "conversion and checking are done in the correct order");
	TEST("foo://bar.com/foo%00?baz",
	    FAIL,
	    empty,
	    "rejects %00");

	/* IRI */
        TEST("foo://bar.com/cafè.gmi",
	    PASS,
	    URI("foo", "bar.com", "", "cafè.gmi", "" , ""),
	    "decode IRI (with a 2-byte utf8 seq)");
	TEST("foo://bar.com/世界.gmi",
	    PASS,
	    URI("foo", "bar.com", "", "世界.gmi", "" , ""),
	    "decode IRI");
	TEST("foo://bar.com/😼.gmi",
	    PASS,
	    URI("foo", "bar.com", "", "😼.gmi", "" , ""),
	    "decode IRI (with a 3-byte utf8 seq)");
	TEST("foo://bar.com/😼/𤭢.gmi",
	    PASS,
	    URI("foo", "bar.com", "", "😼/𤭢.gmi", "" , ""),
	    "decode IRI (with a 3-byte and a 4-byte utf8 seq)");
	TEST("foo://bar.com/世界/\xC0\x80",
	    FAIL,
	    empty,
	    "reject invalid sequence (overlong NUL)");

	return 0;
}
