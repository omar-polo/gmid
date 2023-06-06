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

void		 fatal(const char *, ...)
	__attribute__((format (printf, 1, 2)))
	__attribute__((__noreturn__));
void		 fatalx(const char *, ...)
	__attribute__((format (printf, 1, 2)))
	__attribute__((__noreturn__));

struct client;

#define LOG_ATTR_FMT __attribute__((format (printf, 2, 3)))
void		 log_err(struct client *, const char *, ...)	LOG_ATTR_FMT;
void		 log_warn(struct client *, const char *, ...)	LOG_ATTR_FMT;
void		 log_warnx(struct client *, const char *, ...)	LOG_ATTR_FMT;
void		 log_notice(struct client *, const char *, ...)	LOG_ATTR_FMT;
void		 log_info(struct client *, const char *, ...)	LOG_ATTR_FMT;
void		 log_debug(struct client *, const char *, ...)	LOG_ATTR_FMT;
void		 log_request(struct client *, char *, size_t);
int		 logger_main(int, struct imsgbuf *);
