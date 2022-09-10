/*
 * Copyright (c) 2021, 2022 Omar Polo <op@omarpolo.com>
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
int
add_mime(struct mime *mime, const char *mt, const char *ext)
{
	struct etm *t;
	size_t newcap;

	if (mime->len == mime->cap) {
		newcap = mime->cap * 1.5;
		t = recallocarray(mime->t, mime->cap, newcap,
		    sizeof(struct etm));
		if (t == NULL)
			return -1;
		mime->t = t;
		mime->cap = newcap;
	}

	t = &mime->t[mime->len];
	if (strlcpy(t->mime, mt, sizeof(t->mime)) >= sizeof(t->mime))
		return -1;
	if (strlcpy(t->ext, ext, sizeof(t->ext)) >= sizeof(t->ext))
		return -1;
	mime->len++;
	return 0;
}

/* load a default set of common mime-extension associations */
int
load_default_mime(struct mime *mime)
{
	const struct mapping {
		const char *mime;
		const char *ext;
	} m[] = {
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
		{"text/x-patch",	"diff"},
		{"text/x-patch",	"patch"},
		{"text/xml",		"xml"},
		{NULL, NULL}
	}, *i;

	/* don't load the default if `types' was used. */
	if (mime->len != 0)
		return 0;

	for (i = m; i->mime != NULL; ++i) {
		if (add_mime(mime, i->mime, i->ext) == -1)
			return -1;
	}

	return 0;
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

static int
mime_comp(const void *a, const void *b)
{
	const struct etm *x = a, *y = b;

	return strcmp(x->ext, y->ext);
}

void
sort_mime(struct mime *m)
{
	qsort(m->t, m->len, sizeof(*m->t), mime_comp);
}

static int
mime_find(const void *a, const void *b)
{
	const char *ext = a;
	const struct etm *x = b;

	return strcmp(ext, x->ext);
}

const char *
mime(struct vhost *host, const char *path)
{
	const char *def, *ext;
	struct etm *t;

	def = vhost_default_mime(host, path);

	if ((ext = path_ext(path)) == NULL)
		return def;

	t = bsearch(ext, conf.mime.t, conf.mime.len, sizeof(*conf.mime.t),
	    mime_find);
	if (t != NULL)
		return t->mime;
	if (!strcmp(ext, "gmi") || !strcmp(ext, "gemini"))
		return "text/gemini";
	return def;
}

void
free_mime(struct mime *m)
{
	free(m->t);
}
