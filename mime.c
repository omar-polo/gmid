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
#include <stdlib.h>
#include <string.h>

#include "gmid.h"

struct etm {			/* extension to mime */
	const char	*mime;
	const char	*ext;
};

struct mimes {
	char		*def;
	struct etm	*t;
	size_t		len;
	size_t		cap;
};

struct mimes mimes;

void
init_mime(void)
{
	mimes.len = 0;
	mimes.cap = 2;

	if ((mimes.t = calloc(mimes.cap, sizeof(struct etm))) == NULL)
		fatal("calloc: %s", strerror(errno));

	mimes.def = strdup("application/octet-stream");
	if (mimes.def == NULL)
		fatal("strdup: %s", strerror(errno));

}

void
set_default_mime(const char *m)
{
	free(mimes.def);
	if ((mimes.def = strdup(m)) == NULL)
		fatal("strdup: %s", strerror(errno));
}

/* register mime for the given extension */
void
add_mime(const char *mime, const char *ext)
{
	if (mimes.len == mimes.cap) {
		mimes.cap *= 1.5;
		mimes.t = realloc(mimes.t, mimes.cap * sizeof(struct etm));
		if (mimes.t == NULL)
			fatal("realloc: %s", strerror(errno));
	}

	mimes.t[mimes.len].mime = mime;
	mimes.t[mimes.len].ext  = ext;
	mimes.len++;
}

/* load a default set of common mime-extension associations */
void
load_default_mime()
{
	struct etm *i, m[] = {
		{"application/pdf",	"pdf"},
		{"image/gif",		"gif"},
		{"image/jpeg",		"jpg"},
		{"image/jpeg",		"jpeg"},
		{"image/png",		"png"},
		{"image/svg+xml",	"svg"},
		{"text/gemini",		"gemini"},
		{"text/gemini",		"gmi"},
		{"text/markdown",	"markdown"},
		{"text/markdown",	"md"},
		{"text/plain",		"txt"},
		{"text/xml",		"xml"},
		{NULL, NULL}
	};

	for (i = m; i->mime != NULL; ++i)
		add_mime(i->mime, i->ext);
}

static const char *
path_ext(const char *path)
{
	const char *end;

	end = path + strlen(path)-1;
	for (; end != path; --end) {
		if (*end == '.')
			return end+1;
		if (*end == '/')
			break;
	}

	return NULL;
}

const char *
mime(const char *path)
{
	const char *ext;
	struct etm *t;

	if ((ext = path_ext(path)) == NULL)
		return mimes.def;

	for (t = mimes.t; t->mime != NULL; ++t)
		if (!strcmp(ext, t->ext))
			return t->mime;

	return mimes.def;
}
