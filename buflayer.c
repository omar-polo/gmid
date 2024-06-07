#include <string.h>

#include "gmid.h"

struct buflayer *buflayer_create(size_t n_bytes)
{
	struct buflayer *b;
	b = xcalloc(1, sizeof(*b));
	b->data = xcalloc(n_bytes, 1);
	b->capacity = n_bytes;
	return b;
}

void buflayer_expand(struct buflayer *b, size_t n_bytes)
{
	size_t new_cap = b->capacity + n_bytes;
	void *newbuf = xcalloc(new_cap, 1);
	memcpy(newbuf, b->data, b->len);
	free(b->data);
	b->data = newbuf;
	b->capacity = new_cap;
}

void buflayer_free(struct buflayer *b) 
{
	if (b) {
		if (b->data) free(b->data);
		free(b);
	}
}