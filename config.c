/*
 * Copyright (c) 2023 Omar Polo <op@omarpolo.com>
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

#include <string.h>

void
config_init(void)
{
	TAILQ_INIT(&hosts);

	conf.port = 1965;
	conf.ipv6 = 0;
	conf.protos = TLS_PROTOCOL_TLSv1_2 | TLS_PROTOCOL_TLSv1_3;

	init_mime(&conf.mime);

	conf.prefork = 3;
}

void
config_free(void)
{
	struct vhost *h, *th;
	struct location *l, *tl;
	struct proxy *p, *tp;
	struct envlist *e, *te;
	struct alist *a, *ta;
	int v;

	v = conf.verbose;

	free_mime(&conf.mime);
	memset(&conf, 0, sizeof(conf));

	conf.verbose = v;

	TAILQ_FOREACH_SAFE(h, &hosts, vhosts, th) {
		TAILQ_FOREACH_SAFE(l, &h->locations, locations, tl) {
			TAILQ_REMOVE(&h->locations, l, locations);

			if (l->dirfd != -1)
				close(l->dirfd);

			free(l);
		}

		TAILQ_FOREACH_SAFE(e, &h->params, envs, te) {
			TAILQ_REMOVE(&h->params, e, envs);
			free(e);
		}

		TAILQ_FOREACH_SAFE(a, &h->aliases, aliases, ta) {
			TAILQ_REMOVE(&h->aliases, a, aliases);
			free(a);
		}

		TAILQ_FOREACH_SAFE(p, &h->proxies, proxies, tp) {
			TAILQ_REMOVE(&h->proxies, p, proxies);
			tls_unload_file(p->cert, p->certlen);
			tls_unload_file(p->key, p->keylen);
			free(p);
		}

		TAILQ_REMOVE(&hosts, h, vhosts);
		free(h);
	}

	memset(fcgi, 0, sizeof(fcgi));
}
