/*
 * Copyright (c) 2024 github.com/Sir-Photch <sir-photch@posteo.me>
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

#include <stdint.h>
#include <string.h>

#define MIN(a, b) (a) < (b) ? (a) : (b)

static int
check_prefix_v1(char **buf)
{
	static const char PROXY[6] = "PROXY ";

	if (strncmp(*buf, PROXY, sizeof(PROXY)) != 0)
		return PROXY_PROTO_PARSE_FAIL;

	*buf += sizeof(PROXY);

	return PROXY_PROTO_PARSE_SUCCESS;
}

static int
check_proto_v1(char **buf)
{
	static const char TCP[3] = "TCP";

	if (strncmp(*buf, TCP, sizeof(TCP)) != 0)
		return PROXY_PROTO_PARSE_FAIL;

	*buf += sizeof(TCP);

	int type;
	switch ((*buf)[0]) {
	case '4': type = 4; break;
	case '6': type = 6; break;
	default: return PROXY_PROTO_PARSE_FAIL;
	}

	// '4' / '6' + ' '
	*buf += 2;

	return type;
}

static int
check_unknown_v1(char **buf)
{
	static const char UNKNOWN[7] = "UNKNOWN";

	if (strncmp(*buf, UNKNOWN, sizeof(UNKNOWN)) != 0)
		return PROXY_PROTO_PARSE_FAIL;

	*buf += sizeof(UNKNOWN);

	return PROXY_PROTO_PARSE_SUCCESS;
}

static int
check_crlf_v1(char *const *buf, size_t buflen)
{
	static const char CRLF[2] = "\r\n";

	if (buflen < sizeof(CRLF))
		return PROXY_PROTO_PARSE_FAIL;

	if (!memmem(*buf, buflen, CRLF, sizeof(CRLF)))
		return PROXY_PROTO_PARSE_FAIL;

	return PROXY_PROTO_PARSE_SUCCESS;
}

static int
check_ip_v1(int af, void *addr, char **buf)
{
	char *spc;

	if ((spc = strchr(*buf, ' ')) == NULL)
		return PROXY_PROTO_PARSE_FAIL;

	*spc++ = '\0';

	if (inet_pton(af, *buf, addr) != 1)
		return PROXY_PROTO_PARSE_FAIL;

	*buf = spc;

	return PROXY_PROTO_PARSE_SUCCESS;
}

static int
check_port_v1(uint16_t *port, char **buf, size_t *buflen)
{
	size_t wspc_idx = strcspn(*buf, " \r");
	char *wspc = *buf + wspc_idx;

	if (!(*wspc == ' ' || *wspc == '\r'))
		return PROXY_PROTO_PARSE_FAIL;

	*wspc++ = '\0';

	const char *errstr;
	long long num = strtonum(*buf, 0, UINT16_MAX, &errstr);
	if (errstr)
		return PROXY_PROTO_PARSE_FAIL;

	*buf = wspc;
	*port = num;

	return PROXY_PROTO_PARSE_SUCCESS;
}

#define EXPECT_SUCCESS(call) do { \
    ret = (call); \
    if (PROXY_PROTO_PARSE_SUCCESS != ret) \
        return ret; \
} while (0)

int
proxy_proto_v1_parse(struct proxy_protocol_v1 *s, char *buf, size_t buflen,
    size_t *consumed)
{
	const char *begin = buf;
	int ret;

	EXPECT_SUCCESS(check_crlf_v1(&buf, buflen));
	EXPECT_SUCCESS(check_prefix_v1(&buf));

	ret = check_proto_v1(&buf);
	switch (ret) {
	case 4: s->proto = PROTO_V4; break;
	case 6: s->proto = PROTO_V6; break;
	case PROXY_PROTO_PARSE_FAIL:
		EXPECT_SUCCESS(check_unknown_v1(&buf));

		s->proto = PROTO_UNKNOWN;
		return PROXY_PROTO_PARSE_SUCCESS;
	default:
		return ret;
	}

	switch (s->proto) {
	case PROTO_V4:
		EXPECT_SUCCESS(check_ip_v1(AF_INET, &s->srcaddr.v4, &buf));
		EXPECT_SUCCESS(check_ip_v1(AF_INET, &s->dstaddr.v4, &buf));
		break;

	case PROTO_V6:
		EXPECT_SUCCESS(check_ip_v1(AF_INET6, &s->srcaddr.v6, &buf));
		EXPECT_SUCCESS(check_ip_v1(AF_INET6, &s->dstaddr.v6, &buf));
		break;

	default: 
		ASSERT_MSG(0, "unimplemented");
	}

	EXPECT_SUCCESS(check_port_v1(&s->srcport, &buf, &buflen));
	EXPECT_SUCCESS(check_port_v1(&s->dstport, &buf, &buflen));

	assert('\n' == *buf);
	buf += 1;

	*consumed = buf - begin;
	return PROXY_PROTO_PARSE_SUCCESS;
}

int
proxy_proto_v1_string(const struct proxy_protocol_v1 *s, char *buf,
    size_t buflen)
{
	// "0000:0000:0000:0000:0000:0000:0000:0000\0"
	char srcaddrbuf[40], dstaddrbuf[40];
	int ret;
	switch (s->proto) {
	case PROTO_UNKNOWN:
		ret = snprintf(buf, buflen, "unknown");
		goto fin;
	case PROTO_V4:
		inet_ntop(AF_INET, &s->srcaddr.v4, srcaddrbuf,
		    sizeof(srcaddrbuf));
		inet_ntop(AF_INET, &s->dstaddr.v4, dstaddrbuf,
		    sizeof(dstaddrbuf));
		break;
	case PROTO_V6:
		inet_ntop(AF_INET6, &s->srcaddr.v6, srcaddrbuf,
		    sizeof(srcaddrbuf));
		inet_ntop(AF_INET6, &s->dstaddr.v6, dstaddrbuf,
		    sizeof(dstaddrbuf));
		break;
	}

	ret = snprintf(
	    buf,
	    buflen,
	    "from %s port %u via %s port %u",
	    srcaddrbuf,
	    s->srcport,
	    dstaddrbuf,
	    s->dstport);

fin:
	return ret;
}
