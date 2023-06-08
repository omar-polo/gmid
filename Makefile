# Copyright (c) 2022 Omar Polo <op@omarpolo.com>
# Copyright (c) 2011, 2013-2022 Ingo Schwarze <schwarze@openbsd.org>
# Copyright (c) 2010, 2011, 2012 Kristaps Dzonsons <kristaps@bsd.lv>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# tests to run as a port of the regression suite.  Leave empty to run
# all.
TESTS=

GMID_SRCS =	config.c \
		dirs.c \
		fcgi.c \
		gmid.c \
		iri.c \
		log.c \
		logger.c \
		mime.c \
		proc.c \
		proxy.c \
		puny.c \
		sandbox.c \
		server.c \
		utf8.c \
		utils.c \
		y.tab.c \

GMID_OBJS =	${GMID_SRCS:.c=.o} ${COBJS}

GE_SRCS =	config.c \
		dirs.c \
		fcgi.c \
		ge.c \
		iri.c \
		log.c \
		logger.c \
		mime.c \
		proxy.c \
		puny.c \
		sandbox.c \
		server.c \
		utf8.c \
		utils.c

GE_OBJS =	${GE_SRCS:.c=.o} ${COBJS}

GG_SRCS =	gg.c \
		iri.c \
		utf8.c

GG_OBJS =	${GG_SRCS:.c=.o} ${COBJS}

SRCS =		gmid.h \
		log.h \
		logger.h \
		parse.y \
		proc.h \
		${GMID_SRCS} \
		${GE_SRCS} \
		${GG_SRCS}

DISTNAME =	gmid-${VERSION}

all: Makefile.local gmid ge gg
.PHONY: all tags static clean cleanall test regress install

Makefile.local config.h: configure
	@echo "$@ is out of date; please run ./configure"
	@exit 1

include Makefile.local
include Makefile.depend

tags:
	ctags ${SRCS}

y.tab.c: parse.y
	${YACC} -b y parse.y

gmid: ${GMID_OBJS}
	${CC} ${GMID_OBJS} -o $@ ${LDFLAGS}

#ge: ${GE_OBJS}
#	${CC} ${GE_OBJS} -o $@ ${LDFLAGS}
ge:
	:

gg: ${GG_OBJS}
	${CC} ${GG_OBJS} -o $@ ${LDFLAGS}

static: ${GMID_OBJS} ${GE_OBJS} ${GG_OBJS}
	${CC} ${GMID_OBJS} -o gmid ${LDFLAGS} ${STATIC}
	${CC} ${GG_OBJS} -o ge ${LDFLAGS} ${STATIC}
	${CC} ${GG_OBJS} -o gg ${LDFLAGS} ${STATIC}

clean:
	rm -f *.o compat/*.o y.tab.c y.tab.h y.output gmid ge gg
	rm -f compile_flags.txt
	${MAKE} -C regress clean

distclean: clean
	rm -f Makefile.local config.h config.h.old config.log config.log.old

test: regress
regress: all
	${MAKE} 'TESTS=${TESTS}' -C regress all

install: gmid gg ge
	mkdir -p ${DESTDIR}${BINDIR}
	mkdir -p ${DESTDIR}${MANDIR}/man1
	mkdir -p ${DESTDIR}${MANDIR}/man5
	mkdir -p ${DESTDIR}${MANDIR}/man8
	${INSTALL_PROGRAM} gmid ${DESTDIR}${BINDIR}
	${INSTALL_PROGRAM} gg ${DESTDIR}${BINDIR}
	${INSTALL_PROGRAM} ge ${DESTDIR}${BINDIR}
	${INSTALL_MAN} gmid.8 ${DESTDIR}${MANDIR}/man8
	${INSTALL_MAN} gmid.conf.5 ${DESTDIR}${MANDIR}/man5
	${INSTALL_MAN} ge.1 ${DESTDIR}${MANDIR}/man1
	${INSTALL_MAN} gg.1 ${DESTDIR}${MANDIR}/man1

uninstall:
	rm ${DESTDIR}${BINDIR}/ge
	rm ${DESTDIR}${BINDIR}/gg
	rm ${DESTDIR}${BINDIR}/gmid
	rm ${DESTDIR}${MANDIR}/man1/ge.1
	rm ${DESTDIR}${MANDIR}/man1/gg.1
	rm ${DESTDIR}${MANDIR}/man5/gmid.conf.5
	rm ${DESTDIR}${MANDIR}/man8/gmid.8

# make sure we pass -o to ${CC}.  OpenBSD default suffix rule doesn't
.SUFFIXES: .c .o
.c.o:
	${CC} ${CFLAGS} -c $< -o $@

# -- maintainer targets --

DISTFILES =	.cirrus.yml \
		.dockerignore \
		.gitignore \
		ChangeLog \
		LICENSE \
		Makefile \
		Makefile.depend \
		README.md \
		configure \
		configure.local.example \
		dirs.c \
		fcgi.c \
		ge.1 \
		ge.c \
		gg.1 \
		gg.c \
		gmid.8 \
		gmid.c \
		gmid.conf.5 \
		gmid.h \
		iri.c \
		log.c \
		log.h \
		logger.c \
		mime.c \
		parse.y \
		proxy.c \
		puny.c \
		sandbox.c \
		server.c \
		utf8.c \
		utils.c \
		y.tab.c

depend: config.h y.tab.c
	mkdep -f Makefile.tmp1 ${CFLAGS} ${GE_SRCS} ${GG_SRCS} ${GMID_SRCS} \
		${COBJSx:.o=.c}
	perl -e 'undef $$/; $$_ = <>; s|/usr/include/\S+||g; \
		s|\\\n||g; s|  +| |g; s| $$||mg; print;' \
		Makefile.tmp1 > Makefile.tmp2
	rm Makefile.tmp1
	mv Makefile.tmp2 Makefile.depend

dist: ${DISTNAME}.sha256

${DISTNAME}.sha256: ${DISTNAME}.tar.gz

${DISTNAME}.tar.gz: ${DISTFILES}
	mkdir -p .dist/${DISTNAME}/
	${INSTALL} -m 0644 ${DISTFILES} .dist/${DISTNAME}/
	cd .dist/${DISTNAME} && chmod 755 configure
	${MAKE} -C compat	DESTDIR=${PWD}/.dist/${DISTNAME}/compat dist
	${MAKE} -C contrib	DESTDIR=${PWD}/.dist/${DISTNAME}/contrib dist
	${MAKE} -C have		DESTDIR=${PWD}/.dist/${DISTNAME}/have dist
	${MAKE} -C regress	DESTDIR=${PWD}/.dist/${DISTNAME}/regress dist
	cd .dist/ && tar zcf ../$@ ${DISTNAME}
	rm -rf .dist/
