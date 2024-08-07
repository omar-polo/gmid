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

#include "log.h"

#define MIN(a, b) (a) < (b) ? (a) : (b)

static int
check_prefix_v1(char **buf)
{
	static const char PROXY[6] = "PROXY ";

	if (strncmp(*buf, PROXY, sizeof(PROXY)) != 0)
		return (-1);

	*buf += sizeof(PROXY);

	return (0);
}

static int
check_proto_v1(char **buf)
{
	static const char TCP[3] = "TCP";

	if (strncmp(*buf, TCP, sizeof(TCP)) != 0)
		return (-1);

	*buf += sizeof(TCP);

	int type;
	switch ((*buf)[0]) {
	case '4': type = 4; break;
	case '6': type = 6; break;
	default: return (-1);
	}

	if ((*buf)[1] != ' ')
		return (-1);

	// '4' / '6' + ' '
	*buf += 2;

	return type;
}

static int
check_unknown_v1(char **buf)
{
	static const char UNKNOWN[7] = "UNKNOWN";

	if (strncmp(*buf, UNKNOWN, sizeof(UNKNOWN)) != 0)
		return (-1);

	*buf += sizeof(UNKNOWN);

	return (0);
}

static int
check_crlf_v1(char *const *buf, size_t buflen)
{
	static const char CRLF[2] = "\r\n";

	if (buflen < sizeof(CRLF))
		return (-1);

	if (!memmem(*buf, buflen, CRLF, sizeof(CRLF)))
		return (-1);

	return (0);
}

static int
check_ip_v1(int af, char **buf, struct sockaddr_storage *addr, socklen_t *len)
{
	struct addrinfo	 hints, *res;
	char		*spc;
	int		 err;

	if ((spc = strchr(*buf, ' ')) == NULL)
		return (-1);

	*spc++ = '\0';

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = af;
	hints.ai_flags = AI_NUMERICHOST;
	err = getaddrinfo(*buf, NULL, &hints, &res);
	if (err) {
		log_warnx("getaddrinfo(%s): %s", *buf, gai_strerror(err));
		return (-1);
	}

	memcpy(addr, res->ai_addr, res->ai_addrlen);
	*len = res->ai_addrlen;
	freeaddrinfo(res);

	*buf = spc;

	return (0);
}

static int
check_port_v1(uint16_t *port, char **buf)
{
	size_t wspc_idx = strcspn(*buf, " \r");
	char *wspc = *buf + wspc_idx;

	if (!(*wspc == ' ' || *wspc == '\r'))
		return (-1);

	*wspc++ = '\0';

	const char *errstr;
	long long num = strtonum(*buf, 0, UINT16_MAX, &errstr);
	if (errstr)
		return (-1);

	*buf = wspc;
	*port = num;

	return (0);
}

int
proxy_proto_v1_parse(struct proxy_protocol_v1 *s, char *buf, size_t buflen,
    size_t *consumed)
{
	const char *begin = buf;
	int af;

	if (check_crlf_v1(&buf, buflen) == -1 ||
	    check_prefix_v1(&buf) == -1)
		return (-1);

	switch (check_proto_v1(&buf)) {
	case 4: s->proto = PROTO_V4; break;
	case 6: s->proto = PROTO_V6; break;
	case -1:
		if (check_unknown_v1(&buf) == -1)
			return (-1);
		s->proto = PROTO_UNKNOWN;
		return (0);
	default:
		return (-1);
	}

	af = AF_INET;
	if (s->proto == PROTO_V6)
		af = AF_INET6;

	if (check_ip_v1(af, &buf, &s->srcaddr, &s->srclen) == -1 ||
	    check_ip_v1(AF_UNSPEC, &buf, &s->dstaddr, &s->dstlen) == -1 ||
	    check_port_v1(&s->srcport, &buf) == -1 ||
	    check_port_v1(&s->dstport, &buf) == -1)
		return (-1);

	if (*buf != '\n')
		return (-1);
	buf += 1;

	*consumed = buf - begin;
	return (0);
}

int
proxy_proto_v1_string(const struct proxy_protocol_v1 *s, char *buf,
    size_t buflen)
{
	char srcaddr[NI_MAXHOST], dstaddr[NI_MAXHOST];
	int ret;

	if (s->proto == PROTO_UNKNOWN)
		return strlcpy(buf, "unknown", buflen);

	ret = getnameinfo((struct sockaddr *)&s->srcaddr, s->srclen,
	    srcaddr, sizeof(srcaddr), NULL, 0,
	    NI_NUMERICHOST);
	if (ret) {
		log_warnx("getnameinfo: %s", gai_strerror(ret));
		return (-1);
	}

	ret = getnameinfo((struct sockaddr *)&s->dstaddr, s->dstlen,
	    dstaddr, sizeof(dstaddr), NULL, 0,
	    NI_NUMERICHOST);
	if (ret) {
		log_warnx("getnameinfo: %s", gai_strerror(ret));
		return (-1);
	}

	ret = snprintf(buf, buflen, "from %s port %u via %s port %u",
	    srcaddr, s->srcport, dstaddr, s->dstport);
	if (ret < 0 || (size_t)ret >= buflen)
		return (-1);
	return (ret);
}
