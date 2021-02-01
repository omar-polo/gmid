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
#include <string.h>

#include "gmid.h"

int
starts_with(const char *str, const char *prefix)
{
	size_t i;

	if (prefix == NULL)
		return 0;

	for (i = 0; prefix[i] != '\0'; ++i)
		if (str[i] != prefix[i])
			return 0;
	return 1;
}

int
ends_with(const char *str, const char *sufx)
{
	size_t i, j;

	i = strlen(str);
	j = strlen(sufx);

	if (j > i)
		return 0;

	i -= j;
	for (j = 0; str[i] != '\0'; i++, j++)
		if (str[i] != sufx[j])
			return 0;
	return 1;
}

ssize_t
filesize(int fd)
{
	ssize_t len;

	if ((len = lseek(fd, 0, SEEK_END)) == -1)
		return -1;
	if (lseek(fd, 0, SEEK_SET) == -1)
		return -1;
	return len;
}

char *
absolutify_path(const char *path)
{
	char *wd, *r;

	if (*path == '/') {
		if ((r = strdup(path)) == NULL)
			err(1, "strdup");
		return r;
	}

	wd = getcwd(NULL, 0);
	if (asprintf(&r, "%s/%s", wd, path) == -1)
		err(1, "asprintf");
	free(wd);
	return r;
}
