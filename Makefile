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

# host to bind to during regress
REGRESS_HOST =	localhost

# -- build-related variables --

COBJS =		${COMPATS:.c=.o}

GMID_SRCS =	gmid.c config.c crypto.c dirs.c fcgi.c iri.c log.c \
		logger.c mime.c proc.c proxy.c puny.c sandbox.c \
		server.c utf8.c utils.c y.tab.c

GMID_OBJS =	${GMID_SRCS:.c=.o} ${COBJS}

GEMEXP_SRCS =	ge.c config.c crypto.c dirs.c fcgi.c iri.c log.c mime.c \
		proc.c proxy.c puny.c sandbox.c server.c utf8.c utils.c

GEMEXP_OBJS =	${GEMEXP_SRCS:.c=.o} ${COBJS}

GG_SRCS =	gg.c iri.c utf8.c

GG_OBJS =	${GG_SRCS:.c=.o} ${COBJS}

TITAN_SRCS =	titan.c iri.c utf8.c
TITAN_OBJS =	${TITAN_SRCS:.c=.o} ${COBJS}

SRCS =		gmid.h log.h parse.y proc.h \
		${GMID_SRCS} ${GEMEXP_SRCS} ${GG_SRCS} ${TITAN_SRCS}

DISTNAME =	gmid-${VERSION}

# -- public targets --

all: config.mk gmid gemexp gg titan
.PHONY: all tags clean cleanall test regress install

config.mk config.h: configure
	@echo "$@ is out of date; please run ./configure"
	@exit 1

include config.mk

clean:
	rm -f *.[do] compat/*.[do] y.tab.c y.tab.h y.output gmid gemexp gg
	rm -f compile_flags.txt
	${MAKE} -C regress clean

distclean: clean
	rm -f config.h config.h.old config.log config.log.old config.mk

test: regress
regress: all
	${MAKE} 'TESTS=${TESTS}' -C regress all

install: gmid gg gemexp
	mkdir -p ${DESTDIR}${BINDIR}
	mkdir -p ${DESTDIR}${MANDIR}/man1
	mkdir -p ${DESTDIR}${MANDIR}/man5
	mkdir -p ${DESTDIR}${MANDIR}/man8
	${INSTALL_PROGRAM} gmid ${DESTDIR}${BINDIR}
	${INSTALL_PROGRAM} gg ${DESTDIR}${BINDIR}
	${INSTALL_PROGRAM} gemexp ${DESTDIR}${BINDIR}
	${INSTALL_MAN} gmid.8 ${DESTDIR}${MANDIR}/man8
	${INSTALL_MAN} gmid.conf.5 ${DESTDIR}${MANDIR}/man5
	${INSTALL_MAN} gemexp.1 ${DESTDIR}${MANDIR}/man1
	${INSTALL_MAN} gg.1 ${DESTDIR}${MANDIR}/man1

uninstall:
	rm ${DESTDIR}${BINDIR}/gemexp
	rm ${DESTDIR}${BINDIR}/gg
	rm ${DESTDIR}${BINDIR}/gmid
	rm ${DESTDIR}${MANDIR}/man1/gemexp.1
	rm ${DESTDIR}${MANDIR}/man1/gg.1
	rm ${DESTDIR}${MANDIR}/man5/gmid.conf.5
	rm ${DESTDIR}${MANDIR}/man8/gmid.8

tags:
	ctags ${SRCS}

# --internal build targets --

gmid: ${GMID_OBJS}
	${CC} ${GMID_OBJS} -o $@ ${LIBS} ${LDFLAGS}

gemexp: ${GEMEXP_OBJS}
	${CC} ${GEMEXP_OBJS} -o $@ ${LIBS} ${LDFLAGS}

gg: ${GG_OBJS}
	${CC} ${GG_OBJS} -o $@ ${LIBS} ${LDFLAGS}

titan: ${TITAN_OBJS}
	${CC} ${TITAN_OBJS} -o $@ ${LIBS} ${LDFLAGS}

y.tab.c: parse.y
	${YACC} -b y parse.y

# make sure we pass -o to ${CC}.  OpenBSD default suffix rule doesn't
.SUFFIXES: .c .o
.c.o:
	${CC} ${CFLAGS} -c $< -o $@

# -- maintainer targets --

.PHONY: lint release dist

lint:
	man -Tlint -Wstyle -l gmid.8 gmid.conf.5 ge.1 gg.1

DISTFILES =	.cirrus.yml .dockerignore .gitignore ChangeLog LICENSE \
		Makefile README.md config.c configure configure.local.example \
		crypto.c dirs.c fcgi.c ge.1 ge.c gg.1 gg.c gmid.8 gmid.c \
		gmid.conf.5 gmid.h iri.c log.c log.h logger.c mime.c \
		parse.y proxy.c puny.c sandbox.c server.c utf8.c utils.c \
		y.tab.c

release:
	sed -i -e '/^RELEASE=/s/no/yes' configure
	${MAKE} dist
	sed -i -e '/^RELEASE=/s/yes/no' configure

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

# -- dependencies --

-include config.d
-include crypto.d
-include dirs.d
-include fcgi.d
-include ge.d
-include gg.d
-include gmid.d
-include iri.d
-include log.d
-include logger.d
-include mime.d
-include proc.d
-include proxy.d
-include puny.d
-include sandbox.d
-include server.d
-include titan.d
-include utf8.d
-include utils.d
-include y.tab.d
