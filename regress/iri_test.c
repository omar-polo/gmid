/*
 * Copyright (c) 2020, 2022 Omar Polo <op@omarpolo.com>
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

#include "../gmid.h"

#define ENCTEST(buf, len, raw, exp)				\
	if (encode_path(buf, len, raw) == -1) {			\
		fprintf(stderr, "%s:%d: failed to encode: %s\n", \
		    __FILE__, __LINE__, raw);			\
		exit(1);					\
	}							\
	if (strcmp(buf, exp) != 0) {				\
		fprintf(stderr, "%s:%d: error: "		\
		    "unexpected encoding: got %s, want %s\n",	\
		    __FILE__, __LINE__, buf, exp);		\
		exit(1);					\
	}

#define TEST(iri, fail, exp, descr)				\
	if (!run_test(iri, fail, exp)) {			\
		fprintf(stderr, "%s:%d: error: %s\n",		\
		    __FILE__, __LINE__, descr);			\
		exit(1);					\
	}

#define IRI(schema, host, port, path, query, frag)		\
	((struct iri){(char*)schema, (char*)host, (char*)port,	\
		 0, (char*)path, (char*)query,			\
		 (char*)frag})

#define DIFF(wanted, got, field)					\
	if (wanted->field == NULL || got->field == NULL ||		\
	    strcmp(wanted->field, got->field)) {			\
		fprintf(stderr, #field ":\n\tgot: %s\n\twanted: %s\n",	\
		    got->field, wanted->field);				\
		return 0;						\
	}

#define PASS 0
#define FAIL 1

int	diff_iri(struct iri*, struct iri*);
int	run_test(const char*, int, struct iri);

int
diff_iri(struct iri *p, struct iri *exp)
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
run_test(const char *iri, int should_fail, struct iri expected)
{
	int failed, ok = 1;
	char *iri_copy;
	struct iri parsed;
	const char *error;

	if ((iri_copy = strdup(iri)) == NULL)
		err(1, "strdup");

	fprintf(stderr, "=> %s\n", iri);
	failed = !parse_iri(iri_copy, &parsed, &error);

	if (failed && should_fail)
		goto done;

	if (error != NULL)
		fprintf(stderr, "> %s\n", error);

	ok = !failed && !should_fail;
	if (ok)
		ok = diff_iri(&expected, &parsed);

done:
	free(iri_copy);
	return ok;
}

int
main(void)
{
	char buf[32];
	struct iri empty = IRI("", "", "", "", "", "");

	ENCTEST(buf, sizeof(buf), "hello world", "hello%20world");
	ENCTEST(buf, sizeof(buf), "hello\nworld", "hello%0Aworld");
	ENCTEST(buf, sizeof(buf), "hello\r\nworld", "hello%0D%0Aworld");

	TEST("http://omarpolo.com",
	    PASS,
	    IRI("http", "omarpolo.com", "", "", "", ""),
	    "can parse iri with empty path");

	/* schema */
	TEST("omarpolo.com", FAIL, empty, "FAIL when the schema is missing");
	TEST("gemini:/omarpolo.com", FAIL, empty, "FAIL with invalid marker");
	TEST("gemini//omarpolo.com", FAIL, empty, "FAIL with invalid marker");
	TEST("h!!p://omarpolo.com", FAIL, empty, "FAIL with invalid schema");
	TEST("GEMINI://omarpolo.com",
	    PASS,
	    IRI("gemini", "omarpolo.com", "", "", "", ""),
	    "Schemas are case insensitive.");

	/* authority */
	TEST("gemini://omarpolo.com",
	    PASS,
	    IRI("gemini", "omarpolo.com", "", "", "", ""),
	    "can parse authority with empty path");
	TEST("gemini://omarpolo.com/",
	    PASS,
	    IRI("gemini", "omarpolo.com", "", "", "", ""),
	    "can parse authority with empty path (alt)")
	TEST("gemini://omarpolo.com:1965",
	    PASS,
	    IRI("gemini", "omarpolo.com", "1965", "", "", ""),
	    "can parse with port and empty path");
	TEST("gemini://omarpolo.com:1965/",
	    PASS,
	    IRI("gemini", "omarpolo.com", "1965", "", "", ""),
	    "can parse with port and empty path")
	TEST("gemini://omarpolo.com:196s",
	    FAIL,
	    empty,
	    "FAIL with invalid port number");
	TEST("gemini://OmArPoLo.CoM",
	    PASS,
	    IRI("gemini", "omarpolo.com", "", "", "", ""),
	    "host is case-insensitive");
	TEST("gemini://xn--nave-6pa.omarpolo.com",
	    PASS,
	    IRI("gemini", "xn--nave-6pa.omarpolo.com", "", "", "", ""),
	    "Can parse punycode-encoded hostnames");
	TEST("gemini://naïve.omarpolo.com",
	    PASS,
	    IRI("gemini", "naïve.omarpolo.com", "", "", "", ""),
	    "Accept non punycode-encoded hostnames");
	TEST("gemini://na%c3%afve.omarpolo.com",
	    PASS,
	    IRI("gemini", "naïve.omarpolo.com", "", "", "", ""),
	    "Can percent decode hostnames");
	TEST("gemini://100.64.3.27/",
	    PASS,
	    IRI("gemini", "100.64.3.27", "", "", "", ""),
	    "Accepts IPv4 addresses");
	TEST("gemini://[::1]/",
	    PASS,
	    IRI("gemini", "::1", "", "", "", ""),
	    "Accepts IPv6 addresses");

	/* path */
	TEST("gemini://omarpolo.com/foo/bar/baz",
	    PASS,
	    IRI("gemini", "omarpolo.com", "", "foo/bar/baz", "", ""),
	    "parse simple paths");
	TEST("gemini://omarpolo.com/foo//bar///baz",
	    PASS,
	    IRI("gemini", "omarpolo.com", "", "foo/bar/baz", "", ""),
	    "parse paths with multiple slashes");
	TEST("gemini://omarpolo.com/foo/./bar/./././baz",
	    PASS,
	    IRI("gemini", "omarpolo.com", "", "foo/bar/baz", "", ""),
	    "parse paths with . elements");
	TEST("gemini://omarpolo.com/foo/bar/../bar/baz",
	    PASS,
	    IRI("gemini", "omarpolo.com", "", "foo/bar/baz", "", ""),
	    "parse paths with .. elements");
	TEST("gemini://omarpolo.com/foo/../foo/bar/../bar/baz/../baz",
	    PASS,
	    IRI("gemini", "omarpolo.com", "", "foo/bar/baz", "", ""),
	    "parse paths with multiple .. elements");
	TEST("gemini://omarpolo.com/foo/..",
	    PASS,
	    IRI("gemini", "omarpolo.com", "", "", "", ""),
	    "parse paths with a trailing ..");
	TEST("gemini://omarpolo.com/foo/../",
	    PASS,
	    IRI("gemini", "omarpolo.com", "", "", "", ""),
	    "parse paths with a trailing ..");
	TEST("gemini://omarpolo.com/foo/../..",
	    PASS,
	    IRI("gemini", "omarpolo.com", "", "", "", ""),
	    "parse paths that would escape the root");
	TEST("gemini://omarpolo.com/foo/../../",
	    PASS,
	    IRI("gemini", "omarpolo.com", "", "", "", ""),
	    "parse paths that would escape the root")
	TEST("gemini://omarpolo.com/foo/../foo/../././/bar/baz/.././.././/",
	    PASS,
	    IRI("gemini", "omarpolo.com", "", "", "", ""),
	    "parse path with lots of cleaning available");
	TEST("gemini://omarpolo.com//foo",
	    PASS,
	    IRI("gemini", "omarpolo.com", "", "foo", "", ""),
	    "Trim initial slashes");
	TEST("gemini://omarpolo.com/////foo",
	    PASS,
	    IRI("gemini", "omarpolo.com", "", "foo", "", ""),
	    "Trim initial slashes (pt. 2)");
	TEST("http://a/b/c/../..",
	    PASS,
	    IRI("http", "a", "", "", "", ""),
	    "avoid infinite loops (see v1.6.1)");
	TEST("gemini://example.com/@f:b!(z$&)/baz",
	    PASS,
	    IRI("gemini", "example.com", "", "@f:b!(z$&)/baz", "", ""),
	    "allow @, :, !, (), $ and & in paths");

	/* query */
	TEST("foo://example.com/foo/?gne",
	    PASS,
	    IRI("foo", "example.com", "", "foo/", "gne", ""),
	    "parse query strings");
	TEST("foo://example.com/foo/?gne&foo",
	    PASS,
	    IRI("foo", "example.com", "", "foo/", "gne&foo", ""),
	    "parse query strings");
	/* TEST("foo://example.com/foo/?gne%2F", */
	/*     PASS, */
	/*     IRI("foo", "example.com", "", "foo/", "gne/", ""), */
	/*     "parse query strings"); */
	TEST("foo://ex.com/robots.txt?name=foobar&url=https://foo.com",
	    PASS,
	    IRI("foo", "ex.com", "", "robots.txt", "name=foobar&url=https://foo.com", ""),
	    "Accepts : in queries");
	TEST("foo://ex.com/foo?email=foo@bar.com#quuz",
	    PASS,
	    IRI("foo", "ex.com", "", "foo", "email=foo@bar.com", "quuz"),
	    "Accepts @ in queries");

	/* fragment */
	TEST("foo://bar.co/#foo",
	    PASS,
	    IRI("foo", "bar.co", "", "", "", "foo"),
	    "can recognize fragments");

	/* percent encoding */
	TEST("foo://bar.com/caf%C3%A8.gmi",
	    PASS,
	    IRI("foo", "bar.com", "", "cafè.gmi", "", ""),
	    "can decode");
	TEST("foo://bar.com/caff%C3%A8%20macchiato.gmi",
	    PASS,
	    IRI("foo", "bar.com", "", "caffè macchiato.gmi", "", ""),
	    "can decode");
	TEST("foo://bar.com/caff%C3%A8+macchiato.gmi",
	    PASS,
	    IRI("foo", "bar.com", "", "caffè+macchiato.gmi", "", ""),
	    "can decode");
	TEST("foo://bar.com/foo%2F..%2F..",
	    PASS,
	    IRI("foo", "bar.com", "", "", "", ""),
	    "conversion and checking are done in the correct order");
	TEST("foo://bar.com/foo%00?baz",
	    FAIL,
	    empty,
	    "rejects %00");

	/* IRI */
	TEST("foo://bar.com/cafè.gmi",
	    PASS,
	    IRI("foo", "bar.com", "", "cafè.gmi", "" , ""),
	    "decode IRI (with a 2-byte utf8 seq)");
	TEST("foo://bar.com/世界.gmi",
	    PASS,
	    IRI("foo", "bar.com", "", "世界.gmi", "" , ""),
	    "decode IRI");
	TEST("foo://bar.com/😼.gmi",
	    PASS,
	    IRI("foo", "bar.com", "", "😼.gmi", "" , ""),
	    "decode IRI (with a 3-byte utf8 seq)");
	TEST("foo://bar.com/😼/𤭢.gmi",
	    PASS,
	    IRI("foo", "bar.com", "", "😼/𤭢.gmi", "" , ""),
	    "decode IRI (with a 3-byte and a 4-byte utf8 seq)");
	TEST("foo://bar.com/世界/\xC0\x80",
	    FAIL,
	    empty,
	    "reject invalid sequence (overlong NUL)");

	return 0;
}
