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

void
init_mime(void)
{
	conf.mimes.len = 0;
	conf.mimes.cap = 16;

	conf.mimes.t = calloc(conf.mimes.cap, sizeof(struct etm));
	if (conf.mimes.t == NULL)
		fatal("calloc: %s", strerror(errno));
}

/* register mime for the given extension */
void
add_mime(const char *mime, const char *ext)
{
	if (conf.mimes.len == conf.mimes.cap) {
		conf.mimes.cap *= 1.5;
		conf.mimes.t = realloc(conf.mimes.t,
		    conf.mimes.cap * sizeof(struct etm));
		if (conf.mimes.t == NULL)
			fatal("realloc: %s", strerror(errno));
	}

	conf.mimes.t[conf.mimes.len].mime = mime;
	conf.mimes.t[conf.mimes.len].ext  = ext;
	conf.mimes.len++;
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
mime(struct vhost *host, const char *path)
{
	const char *def, *ext;
	struct etm *t;

	if ((def = host->default_mime) == NULL)
		def = "application/octet-stream";

	if ((ext = path_ext(path)) == NULL)
		return def;

	for (t = conf.mimes.t; t->mime != NULL; ++t)
		if (!strcmp(ext, t->ext))
			return t->mime;

	return def;
}
