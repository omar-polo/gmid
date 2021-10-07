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

#include <sys/tree.h>

#include <stdio.h>

struct tree {
	int i;
	SPLAY_ENTRY(tree) entry;
};
SPLAY_HEAD(tree_id, tree);

static int
tree_cmp(struct tree *a, struct tree *b)
{
	if (a->i == b->i)
		return 0;
	else if (a->i < b->i)
		return -1;
	else
		return +1;
}

SPLAY_PROTOTYPE(tree_id, tree, entry, tree_cmp);
SPLAY_GENERATE(tree_id, tree, entry, tree_cmp);

int
main(void)
{
	return 0;
}
