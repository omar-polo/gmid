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

#include "gmid.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define BASE	36
#define TMIN	1
#define TMAX	26
#define SKEW	38
#define DAMP	700
#define IBIAS	72
#define IN	128

static int
adapt(int delta, int numpoints, int firsttime)
{
	int k;

	if (firsttime)
		delta = delta / DAMP;
	else
		delta = delta / 2;

	delta += (delta / numpoints);

	k = 0;
	while (delta > ((BASE - TMIN) * TMAX) / 2) {
		delta = delta / (BASE - TMIN);
		k += BASE;
	}
	return k + (((BASE - TMIN + 1) * delta) / (delta + SKEW));
}

static const char *
copy_label(const char *s, char *out, size_t len)
{
	char *end, *t;
	size_t l;

	end = strchr(s, '\0');
	l = end - s;
	if (l > len)
		return NULL;

	for (t = end; t >= s; --t)
		if (*t == '-')
			break;

	if (t < s)
		t = end;

	for (; s < t; ++s, ++out) {
		if (*s > 'z')
			return NULL;
		*out = *s;
	}

	return s;
}

static unsigned int
digit_value(char c)
{
	if ('A' <= c && c <= 'Z')
		return c - 'A';

	if ('a' <= c && c <= 'z')
		return c - 'a';

	if ('0' <= c && c <= '9')
		return 26 + c - '0';

	return c;
}

static int
insert(char *out, size_t len, int codepoint, size_t i, const char **err)
{
	int l;
	char *t;

	if (codepoint <= 0x7F) {
		*err = "puny: invalid decoded character (ASCII range)";
		return 0;
	} else if (codepoint <= 0x7FF) {
		l = 2;
	} else if (codepoint <= 0xFFFF) {
		l = 3;
	} else if (codepoint <= 0x10FFFF) {
		l = 4;
	} else {
		*err = "puny: invalid decoded character";
		return 0;
	}

	if ((t = utf8_nth(out, i)) == NULL) {
		*err = "puny: invalid insert position";
		return 0;
	}

	if (t + l >= out + len) {
		*err = "puny: insert would overflow";
		return 0;
	}

	memmove(t + l, t, strlen(t));

	switch (l) {
	case 2:
		t[1] = ( codepoint        & 0x3F) + 0x80;
		t[0] = ((codepoint >>  6) & 0x1F) + 0xC0;
		break;
	case 3:
		t[2] = ( codepoint        & 0x3F) + 0x80;
		t[1] = ((codepoint >>  6) & 0x3F) + 0x80;
		t[0] = ((codepoint >> 12) & 0x0F) + 0xE0;
		break;
	case 4:
		t[3] = ( codepoint        & 0x3F) + 0x80;
		t[2] = ((codepoint >>  6) & 0x3F) + 0x80;
		t[1] = ((codepoint >> 12) & 0x3F) + 0x80;
		t[0] = ((codepoint >> 18) & 0x07) + 0xF0;
		break;
	}
	return 1;
}

static int
decode(const char *str, char *out, size_t len, const char **err)
{
	size_t i;
	uint32_t n;
	unsigned int oldi, bias, w, k, digit, t;
	unsigned int numpoints;
	const char *s;

	if (!starts_with(str, "xn--")) {
		strncpy(out, str, len);
		return 1;
	}

	/* skip the xn-- */
	str += 4;

	if (strchr(str, '-') != NULL) {
		if ((s = copy_label(str, out, len)) == NULL) {
			*err = "puny: invalid label";
			return 0;
		}
		if (*s == '-')
			s++;
	} else
		s = str;

	numpoints = strlen(out);

	n = IN;
	i = 0;
	bias = IBIAS;

	while (*s != '\0') {
		oldi = i;
		w = 1;

		for (k = BASE; ; k += BASE) {
			if (*s == '\0') {
				*err = "puny: label truncated?";
				return 0;
			}
			/* fail eventually? */
			digit = digit_value(*s);
			s++;

			/* fail on overflow */
			i += digit * w;

			if (k <= bias)
				t = TMIN;
			else if (k >= bias + TMAX)
				t = TMAX;
			else
				t = k - bias;

			if (digit < t)
				break;
			w *= (BASE - t);
		}

		bias = adapt(i - oldi, numpoints+1, oldi == 0);
		n += i / (numpoints+1); /* fail on overflow */
		i = i % (numpoints+1);

		if (!insert(out, len, n, i, err))
			return 0;
		numpoints++;
		++i;
	}

	return 1;
}

static const char *
end_of_label(const char *hostname)
{
	for (; *hostname != '\0' && *hostname != '.'; ++hostname)
		;		/* nop */
	return hostname;
}

int
puny_decode(const char *hostname, char *out, size_t len, const char **err)
{
	char label[LABEL_LEN];
	const char *s, *end;
	size_t l;

	memset(out, 0, len);
	if (hostname == NULL)
		return 1;

	s = hostname;
	for (;;) {
		end = end_of_label(s);
		l = end - s;
		if (l >= sizeof(label)) {
			*err = "label too long";
			return 0;
		}

		memcpy(label, s, l);
		label[l] = '\0';

		if (!decode(label, out, len, err))
			return 0;

		if (*end == '\0')
			return 1;

		if (strlcat(out, ".", len) >= len) {
			*err = "domain name too long";
			return 0;
		}

		l = strlen(out);
		if (l >= len) {
			*err = "domain name too long";
			return 0;
		}
		out += l;
		len -= l;

		s = end+1;
	}
}
