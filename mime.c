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

#include <errno.h>
#include <stdlib.h>
#include <string.h>

void
init_mime(struct mime *mime)
{
	mime->len = 0;
	mime->cap = 16;

	mime->t = calloc(mime->cap, sizeof(struct etm));
	if (mime->t == NULL)
		fatal("calloc: %s", strerror(errno));
}

/* register mime for the given extension */
void
add_mime(struct mime *mime, const char *mt, const char *ext)
{
	size_t oldcap;

	if (mime->len == mime->cap) {
		oldcap = mime->cap;
		mime->cap *= 1.5;
		mime->t = recallocarray(mime->t, oldcap, mime->cap,
		    sizeof(struct etm));
		if (mime->t == NULL)
			err(1, "recallocarray");
	}

	mime->t[mime->len].mime = mt;
	mime->t[mime->len].ext  = ext;
	mime->len++;
}

/* load a default set of common mime-extension associations */
void
load_default_mime(struct mime *mime)
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
		{"text/x-patch",	"diff"}
		{"text/x-patch",	"patch"},
		{"text/xml",		"xml"},
		{NULL, NULL}
	};

	for (i = m; i->mime != NULL; ++i)
		add_mime(mime, i->mime, i->ext);
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

	def = vhost_default_mime(host, path);

	if ((ext = path_ext(path)) == NULL)
		return def;

	for (t = conf.mime.t; t->mime != NULL; ++t)
		if (!strcmp(ext, t->ext))
			return t->mime;

	return def;
}
