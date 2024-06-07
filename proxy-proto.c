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

#include <ctype.h>
#include <string.h>

#define MIN(a, b) (a) < (b) ? (a) : (b)

static const char* 
consume_token(
    const char *buf, 
    size_t buflen, 
    const char *token, 
    size_t tokenlen, 
    size_t *consumed_len
) {
    // buflen may be smaller than tokenlen
    // in that case, compare until end of buf
    size_t checklen = MIN(buflen, tokenlen);
    if (NULL != consumed_len)
        *consumed_len = checklen;

    return memmem(buf, buflen, token, checklen);
}

static int 
check_prefix_v1(const char **buf, size_t *buflen)
{
    static const char PROXY[6] = "PROXY ";

    size_t consumed;
    const char *found = consume_token(*buf, *buflen, PROXY, 6, &consumed);
    if (NULL == found)
        return 0 == consumed ? PROXY_PROTO_PARSE_AGAIN : PROXY_PROTO_PARSE_FAIL;

    if (consumed < 6)
        return PROXY_PROTO_PARSE_AGAIN;

    *buf += consumed;
    *buflen -= consumed;

    return PROXY_PROTO_PARSE_SUCCESS;
}

static int
check_proto_v1(const char **buf, size_t *buflen)
{
    static const char TCP[3] = "TCP";

    size_t consumed;
    const char *found = consume_token(*buf, *buflen, TCP, 3, &consumed);
    if (NULL == found)
        return 0 == consumed ? PROXY_PROTO_PARSE_AGAIN : PROXY_PROTO_PARSE_FAIL;
    
    if (consumed < 3)
        return PROXY_PROTO_PARSE_AGAIN;

    if (*buflen - consumed < 2)
        return PROXY_PROTO_PARSE_AGAIN;

    if (' ' != (*buf)[4])
        return PROXY_PROTO_PARSE_FAIL;

    *buf += consumed;
    *buflen -= consumed;

    int type;
    switch ((*buf)[0]) {
        case '4': type = 4; break;
        case '6': type = 6; break;
        default: return PROXY_PROTO_PARSE_FAIL;
    }

    // '4' / '6' + ' '
    *buf += 2;
    *buflen -= 2;

    return type;
}

static int
check_unknown_v1(const char **buf, size_t *buflen)
{
    static const char UNKNOWN[7] = "UNKNOWN";

    size_t consumed;
    const char *found = consume_token(*buf, *buflen, UNKNOWN, 7, &consumed);
    if (NULL == found) {
        return 0 == consumed ? PROXY_PROTO_PARSE_AGAIN : PROXY_PROTO_PARSE_FAIL;
    }

    if (consumed < 7)
        return PROXY_PROTO_PARSE_AGAIN;

    *buf += consumed;
    *buflen -= consumed;

    return PROXY_PROTO_PARSE_SUCCESS;
}

static int
check_crlf_v1(const char **buf, size_t buflen)
{
    static const char CRLF[2] = "\r\n";

    size_t consumed = 0;
    const char *found = consume_token(*buf, buflen, CRLF, 2, &consumed);
    if (NULL == found)
        return PROXY_PROTO_PARSE_AGAIN;

    if (consumed < 2)
        return PROXY_PROTO_PARSE_AGAIN;

    if (buflen < consumed)
        return PROXY_PROTO_PARSE_FAIL;

    *buf += consumed;

    return PROXY_PROTO_PARSE_SUCCESS;
}

static int
check_ipv4_v1(struct in_addr *addr, const char **buf, size_t *buflen)
{
    size_t n_dots = 0, digits_after_last_dot = 0;
    ssize_t addrlen = -1;
    for (size_t i = 0; i < *buflen && i < 15; ++i)
    {
        if ('.' == (*buf)[i]) {
            n_dots++;
        } else if (3 == n_dots && isdigit((*buf)[i])) {
            digits_after_last_dot++;
        } else if (3 < n_dots) {
            return PROXY_PROTO_PARSE_FAIL;
        } else if (0 < digits_after_last_dot && ' ' == (*buf)[i]) {
            addrlen = i;
            break;
        }
    }

    if (3 != n_dots || digits_after_last_dot < 1)
        return PROXY_PROTO_PARSE_AGAIN;

    if (3 < digits_after_last_dot || addrlen < 7)
        return PROXY_PROTO_PARSE_FAIL;

    char addrbuf[addrlen + 1];
    memcpy(addrbuf, *buf, addrlen);
    addrbuf[addrlen] = '\0'; 

    if (1 != inet_pton(AF_INET, addrbuf, addr))
        return PROXY_PROTO_PARSE_FAIL;

    *buf += addrlen + 1;
    *buflen -= addrlen + 1;

    return PROXY_PROTO_PARSE_SUCCESS;
}

static int
check_ipv6_v1(struct in6_addr *addr, const char **buf, size_t *buflen)
{
    size_t n_colons = 0;
    ssize_t addrlen = -1;
    for (size_t i = 0; i < *buflen && i < 39; ++i)
    {
        if (':' == (*buf)[i]) {
            n_colons++;
        } else if (2 <= n_colons && ' ' == (*buf)[i]) {
            addrlen = i;
            break;
        }
    }

    if (addrlen < 2)
        return PROXY_PROTO_PARSE_AGAIN;

    char addrbuf[addrlen + 1];
    memcpy(addrbuf, *buf, addrlen);
    addrbuf[addrlen] = '\0';

    if (1 != inet_pton(AF_INET6, addrbuf, addr))
        return PROXY_PROTO_PARSE_FAIL;

    *buf += addrlen + 1;
    *buflen -= addrlen + 1;

    return PROXY_PROTO_PARSE_SUCCESS;
}

static int
check_port_v1(uint16_t *port, const char **buf, size_t *buflen)
{
    char *end;
    errno = 0;
    unsigned long num = strtoul(*buf, &end, 10);
    if (errno == ERANGE || errno == EINVAL || UINT16_MAX < num)
        return PROXY_PROTO_PARSE_FAIL;

    *port = (uint16_t)num;
    *buflen -= end - *buf;
    *buf = end;
    return PROXY_PROTO_PARSE_SUCCESS;
}

int proxy_proto_v1_parse(struct proxy_protocol_v1 *s, const char *buf, size_t buflen, size_t *consumed)
{
    const char *begin = buf;
    int proxy = check_prefix_v1(&buf, &buflen);
    if (PROXY_PROTO_PARSE_SUCCESS != proxy)
        return proxy;
    
    int proto = check_proto_v1(&buf, &buflen);
    switch (proto) 
    {
        case 4: s->proto = PROTO_V4; break;
        case 6: s->proto = PROTO_V6; break;
        case PROXY_PROTO_PARSE_FAIL: {
            int unknown = check_unknown_v1(&buf, &buflen);
            if (PROXY_PROTO_PARSE_SUCCESS != unknown)
                return unknown;

            int crlf = check_crlf_v1(&buf, buflen);
            if (PROXY_PROTO_PARSE_SUCCESS == crlf) {
                *consumed = buf - begin;
                s->proto = PROTO_UNKNOWN;
            }
            return crlf;
        } break;
        default: return proto;
    }

    switch (s->proto)
    {
        case PROTO_V4: {
            
            int srcaddr = check_ipv4_v1(&s->srcaddr.v4, &buf, &buflen);
            if (PROXY_PROTO_PARSE_SUCCESS != srcaddr)
                return srcaddr;

            int dstaddr = check_ipv4_v1(&s->dstaddr.v4, &buf, &buflen);
            if (PROXY_PROTO_PARSE_SUCCESS != dstaddr)
                return dstaddr;

        } break;

        case PROTO_V6: {

            int srcaddr = check_ipv6_v1(&s->srcaddr.v6, &buf, &buflen);
            if (PROXY_PROTO_PARSE_SUCCESS != srcaddr)
                return srcaddr;

            int dstaddr = check_ipv6_v1(&s->dstaddr.v6, &buf, &buflen);
            if (PROXY_PROTO_PARSE_SUCCESS != dstaddr)
                return dstaddr;

        } break;

        default: ASSERT_MSG(0, "unimplemented");
    }

    int srcport = check_port_v1(&s->srcport, &buf, &buflen);
    if (PROXY_PROTO_PARSE_SUCCESS != srcport)
        return srcport;

    if (' ' != *buf)
        return PROXY_PROTO_PARSE_AGAIN;
    buf += 1;

    int dstport = check_port_v1(&s->dstport, &buf, &buflen);
    if (PROXY_PROTO_PARSE_SUCCESS != dstport)
        return dstport;

    int crlf = check_crlf_v1(&buf, buflen);
    if (PROXY_PROTO_PARSE_SUCCESS != crlf)
        return crlf;

    *consumed = buf - begin;
    return PROXY_PROTO_PARSE_SUCCESS;
}

int 
proxy_proto_v1_string(const struct proxy_protocol_v1 *s, char* buf, size_t buflen)
{
    // "0000:0000:0000:0000:0000:0000:0000:0000\0"
    char srcaddrbuf[40], dstaddrbuf[40];
    int ret;
    switch (s->proto)
    {
        case PROTO_UNKNOWN: ret = snprintf(buf, buflen, "unknown"); goto fin;
        case PROTO_V4: {
            inet_ntop(AF_INET, &s->srcaddr.v4, srcaddrbuf, 39);
            inet_ntop(AF_INET, &s->dstaddr.v4, dstaddrbuf, 39);
        } break;
        case PROTO_V6: {
            inet_ntop(AF_INET6, &s->srcaddr.v6, srcaddrbuf, 39);
            inet_ntop(AF_INET6, &s->dstaddr.v6, dstaddrbuf, 39);
        } break;
    }

    srcaddrbuf[39] = dstaddrbuf[39] = '\0';

    ret = snprintf(
        buf,
        buflen,
        "from %s port %u via %s port %u",
        srcaddrbuf,
        s->srcport,
        dstaddrbuf,
        s->dstport
    );

fin:
    return ret;
}
