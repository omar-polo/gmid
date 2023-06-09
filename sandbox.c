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
#include "log.h"

#if defined(__OpenBSD__)

#include <unistd.h>

void
sandbox_main_process(void)
{
	if (pledge("stdio rpath inet dns sendfd proc", NULL) == -1)
		fatal("pledge");
}

void
sandbox_server_process(void)
{
	if (pledge("stdio recvfd rpath unix inet dns", NULL) == -1)
		fatal("pledge");
}

void
sandbox_logger_process(void)
{
	if (pledge("stdio recvfd", NULL) == -1)
		fatal("pledge");
}

#else

#warning "No sandbox method known for this OS"

void
sandbox_main_process(void)
{
	return;
}

void
sandbox_server_process(void)
{
	return;
}

void
sandbox_logger_process(void)
{
	return;
}

#endif
