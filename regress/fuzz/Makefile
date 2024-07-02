DISTFILES =	Makefile \
		iri.c

include ../../config.mk

CC = afl-clang

COBJS =		${COMPATS:.c=.o}
REG_COMPATS =	${COBJS:%=../../%}

IRI_SRCS =	iri.c ../../iri.c ../../utf8.c ../../log.c
IRI_OBJS =	${IRI_SRCS:.c=.o} ${REG_COMPATS}

PROXY_SRCS =	proxy.c ../../proxy-proto.c
PROXY_OBJS =	${PROXY_SRCS:.c=.o} ${REG_COMPATS}

.PHONY: all data clean dist

all:
	@echo run ${MAKE} fuzz-iri   to fuzz the IRI parser
	@echo run ${MAKE} fuzz-proxy to fuzz the proxy v1 protocol parser

fuzz-iri: iri
	rm -rf in out
	mkdir -p in out
	echo 'gemini://omarpolo.com/'		> in/simple
	echo 'https://op:123@omarpolo.com/'	> in/auth
	echo 'ftp://op@omarpolo.com/a/bb/c'	> in/path
	echo 'gemini://omarpolo.com/?some=val'	> in/query
	echo 'gemini://omarpolo.com/b/#xyz'	> in/fragment
	echo 'gemini://omarpolo.com/b/?x=y#xyz'	> in/qf
	echo 'ssh://omarpolo.com/%2F/'		> in/enc
	echo 'http://omarpolo.com/foo/.././'	> in/dots
	echo 'http://omarpolo.com/////././'	> in/slash
	afl-fuzz -i in -o out -- ./iri

fuzz-proxy: proxy
	rm -rf in out
	mkdir -p in out
	printf 'PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n' >in/ipv4
	printf 'PROXY TCP6 fe80::1 fd4b:b287:5c6f:1f4::2 65535 65535\r\n' >in/ipv6
	printf 'PROXY UNKNOWN\r\n' > in/unknown
	afl-fuzz -i in -o out -- ./proxy

iri: ${IRI_OBJS}
	${CC} ${IRI_OBJS} -o $@ ${LIBS} ${LDFLAGS}

proxy: ${PROXY_OBJS}
	${CC} ${PROXY_OBJS} -o $@ ${LIBS} ${LDFLAGS}

.c.o:
	${CC} -I../.. ${CFLAGS} -c $< -o $@

clean:
	rm -f *.o iri
