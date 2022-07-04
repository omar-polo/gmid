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

TESTSRCS =	have/err.c \
		have/explicit_bzero.c \
		have/freezero.c \
		have/getdtablecount.c \
		have/getdtablesize.c \
		have/getprogname.c \
		have/imsg.c \
		have/landlock.c \
		have/libevent.c \
		have/libevent2.c \
		have/libtls.c \
		have/noop.c \
		have/openssl.c \
		have/pr_set_name.c \
		have/program_invocation_short_name.c \
		have/queue_h.c \
		have/reallocarray.c \
		have/recallocarray.c \
		have/setproctitle.c \
		have/strlcat.c \
		have/strlcpy.c \
		have/strtonum.c \
		have/tree_h.c \
		have/vasprintf.c

COMPATS =	compat/err.c \
		compat/explicit_bzero.c \
		compat/freezero.c \
		compat/getdtablecount.c \
		compat/getdtablesize.c \
		compat/getprogname.c \
		compat/imsg-buffer.c \
		compat/imsg.c \
		compat/imsg.h \
		compat/queue.h \
		compat/reallocarray.c \
		compat/recallocarray.c \
		compat/setproctitle.c \
		compat/strlcat.c \
		compat/strlcpy.c \
		compat/strtonum.c \
		compat/tree.h \
		compat/vasprintf.c

GMID_SRCS =	dirs.c \
		ex.c \
		fcgi.c \
		gmid.c \
		iri.c \
		log.c \
		mime.c \
		proxy.c \
		puny.c \
		sandbox.c \
		server.c \
		utf8.c \
		utils.c \
		y.tab.c \

GMID_OBJS =	${GMID_SRCS:.c=.o} ${COBJS}

GG_SRCS =	gg.c \
		iri.c \
		utf8.c

GG_OBJS =	${GG_SRCS:.c=.o} ${COBJS}

SRCS =		gmid.h \
		landlock_shim.h \
		parse.y \
		${GMID_SRCS} \
		${GG_SRCS}

REGRESSFILES =	regress/Makefile \
		regress/env \
		regress/err \
		regress/example.mime.types \
		regress/fcgi-test.c \
		regress/fill-file.c \
		regress/hello \
		regress/invalid \
		regress/iri_test.c \
		regress/lib.sh \
		regress/max-length-reply \
		regress/puny-test.c \
		regress/regress \
		regress/serve-bigfile \
		regress/sha \
		regress/slow \
		regress/tests.sh \
		regress/valid.ext

EXTRAS =	ChangeLog \
		LICENSE \
		Makefile \
		Makefile.depend \
		README.md \
		configure \
		configure.local.example \
		gg.1 \
		gmid.1 \
		gmid.conf.5

DISTFILES =	${EXTRAS} \
		${COMPATS} \
		${REGRESSFILES} \
		${SRCS} \
		${TESTSRCS}

DISTNAME =	gmid-${VERSION}

all: Makefile.local gmid gg
.PHONY: all static clean cleanall test regress install

Makefile.local config.h: configure ${TESTSRCS}
	@echo "$@ is out of date; please run ./configure"
	@exit 1

include Makefile.local
include Makefile.depend

y.tab.c: parse.y
	${YACC} -b y parse.y

gmid: ${GMID_OBJS}
	${CC} ${GMID_OBJS} -o $@ ${LDFLAGS}

gg: ${GG_OBJS}
	${CC} ${GG_OBJS} -o $@ ${LDFLAGS}

static: ${GMID_OBJS} ${GG_OBJS}
	${CC} ${GMID_OBJS} -o gmid ${LDFLAGS} ${STATIC}
	${CC} ${GG_OBJS} -o gg ${LDFLAGS} ${STATIC}

clean:
	rm -f *.o compat/*.o y.tab.c y.tab.h y.output gmid gg
	rm -f compile_flags.txt
	${MAKE} -C regress clean

distclean: clean
	rm -f Makefile.local config.h config.h.old config.log config.log.old

test: regress
regress: all
	${MAKE} 'TESTS=${TESTS}' -C regress all

install: gmid gg
	mkdir -p ${DESTDIR}${BINDIR}
	mkdir -p ${DESTDIR}${MANDIR}/man1
	mkdir -p ${DESTDIR}${MANDIR}/man5
	${INSTALL_PROGRAM} gmid ${DESTDIR}${BINDIR}
	${INSTALL_PROGRAM} gg ${DESTDIR}${BINDIR}
	${INSTALL_MAN} gmid.1 ${DESTDIR}${MANDIR}/man1
	${INSTALL_MAN} gmid.conf.5 ${DESTDIR}${MANDIR}/man5
	${INSTALL_MAN} gg.1 ${DESTDIR}${MANDIR}/man1

uninstall:
	rm ${DESTDIR}${BINDIR}/gg
	rm ${DESTDIR}${BINDIR}/gmid
	rm ${DESTDIR}${MANDIR}/man1/gg.1
	rm ${DESTDIR}${MANDIR}/man1/gmid.1
	rm ${DESTDIR}${MANDIR}/man5/gmid.conf.5

# make sure we pass -o to ${CC}.  OpenBSD default suffix rule doesn't
.SUFFIXES: .c .o
.c.o:
	${CC} ${CFLAGS} -c $< -o $@

depend: config.h y.tab.c
	mkdep -f Makefile.tmp1 ${CFLAGS} ${GMID_SRCS} ${GG_SRCS} ${COBJSx:.o=.c}
	perl -e 'undef $$/; $$_ = <>; s|/usr/include/\S+||g; \
		s|\\\n||g; s|  +| |g; s| $$||mg; print;' \
		Makefile.tmp1 > Makefile.tmp2
	rm Makefile.tmp1
	mv Makefile.tmp2 Makefile.depend

dist: ${DISTNAME}.sha256

${DISTNAME}.sha256: ${DISTNAME}.tar.gz

${DISTNAME}.tar.gz: ${DISTFILES}
	mkdir -p .dist/${DISTNAME}/
	${INSTALL} -m 0644 ${SRCS} ${EXTRAS} .dist/${DISTNAME}
	cd .dist/${DISTNAME} && chmod 755 configure
	mkdir -p .dist/${DISTNAME}/compat
	${INSTALL} -m 0644 ${COMPATS} .dist/${DISTNAME}/compat
	mkdir -p .dist/${DISTNAME}/have
	${INSTALL} -m 0644 ${TESTSRCS} .dist/${DISTNAME}/have
	mkdir -p .dist/${DISTNAME}/regress
	${INSTALL} -m 0644 ${REGRESSFILES} .dist/${DISTNAME}/regress
	cd .dist/${DISTNAME}/regress && chmod 755 env err hello invalid \
	    max-length-reply regress sha slow
	cd .dist/ && tar zcf ../$@ ${DISTNAME}
	rm -rf .dist/
