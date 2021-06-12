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

/*
 * Test program for fastcgi.  It speaks the protocol over stdin.
 * Can't handle more than one request at the same time.
 */

#include "../config.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define FCGI_VERSION_1	1

/* subset of records that matters to us */
#define FCGI_BEGIN_REQUEST	 1
#define FCGI_END_REQUEST	 3
#define FCGI_PARAMS		 4
#define FCGI_STDIN		 5
#define FCGI_STDOUT		 6

#define SUM(a, b) (((a) << 8) + (b))

struct fcgi_header {
	uint8_t version;
	uint8_t type;
	uint8_t req_id1;
	uint8_t req_id0;
	uint8_t content_len1;
	uint8_t content_len0;
	uint8_t padding;
	uint8_t reserved;
};

struct fcgi_end_req_body {
	unsigned char app_status3;
	unsigned char app_status2;
	unsigned char app_status1;
	unsigned char app_status0;
	unsigned char proto_status;
	unsigned char reserved[3];
};

static int
prepare_header(struct fcgi_header *h, int type, int id, size_t size,
    size_t padding)
{
	memset(h, 0, sizeof(*h));

	h->version = FCGI_VERSION_1;
        h->type = type;
	h->req_id1 = (id >> 8);
	h->req_id0 = (id & 0xFF);
	h->content_len1 = (size >> 8);
	h->content_len0 = (size & 0xFF);
	h->padding = padding;

	return 0;
}

static int
must_read(int sock, void *d, size_t len)
{
	ssize_t r;

	for (;;) {
		switch (r = read(sock, d, len)) {
		case -1:
		case 0:
			return -1;
		default:
			if (r == (ssize_t)len)
				return 0;
			len -= r;
			d += r;
		}
	}
}

static int
consume(int fd, size_t len)
{
	size_t	l;
	char	buf[64];

	while (len != 0) {
		if ((l = len) > sizeof(buf))
			l =  sizeof(buf);
		if (must_read(fd, buf, l) == -1)
                        return 0;
		len -= l;
	}

	return 1;
}

static void
read_header(struct fcgi_header *hdr)
{
	if (must_read(0, hdr, sizeof(*hdr)) == -1)
		errx(1, "must_read failed");
}

/* read and consume a record of the given type */
static void
assert_record(int type)
{
	struct fcgi_header hdr;

	read_header(&hdr);

	if (hdr.type != type)
		errx(1, "expected record type %d; got %d",
		    type, hdr.type);

	consume(0, SUM(hdr.content_len1, hdr.content_len0));
	consume(0, hdr.padding);
}

int
main(void)
{
	struct fcgi_header	 hdr;
	struct fcgi_end_req_body end;
	const char		*msg;
	size_t			 len;

	msg = "20 text/gemini\r\n# Hello, world!\n";
	len = strlen(msg);

	for (;;) {
		warnx("waiting for a request");
		assert_record(FCGI_BEGIN_REQUEST);

		/* read params */
		for (;;) {
			read_header(&hdr);

			consume(0, SUM(hdr.content_len1, hdr.content_len0));
			consume(0, hdr.padding);

			if (hdr.type != FCGI_PARAMS)
				errx(1, "got %d; expecting PARAMS", hdr.type);

			if (hdr.content_len0 == 0 &&
			    hdr.content_len1 == 0 &&
			    hdr.padding == 0)
				break;
		}

		assert_record(FCGI_STDIN);

		warnx("sending the response");

		prepare_header(&hdr, FCGI_STDOUT, 1, len, 0);
		write(0, &hdr, sizeof(hdr));
		write(0, msg, len);

		warnx("closing the request");

		prepare_header(&hdr, FCGI_END_REQUEST, 1, sizeof(end), 0);
		write(0, &hdr, sizeof(hdr));
		memset(&end, 0, sizeof(end));
		write(0, &end, sizeof(end));
	}
}
