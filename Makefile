# tests to run as a port of the regression suite.  Leave empty to run
# all.
TESTS=

.PHONY: all static clean cleanall regress install

all: Makefile.local gmid gg TAGS compile_flags.txt

Makefile.local: configure
	./configure

include Makefile.local

y.tab.c: parse.y
	${YACC} -b y parse.y

SRCS = gmid.c iri.c utf8.c ex.c server.c sandbox.c mime.c puny.c \
	utils.c log.c dirs.c fcgi.c proxy.c
OBJS = ${SRCS:.c=.o} y.tab.o ${COMPAT}

gmid: ${OBJS}
	${CC} ${OBJS} -o gmid ${LDFLAGS}

gg: gg.o iri.o utf8.o ${COMPAT}
	${CC} gg.o iri.o utf8.o ${COMPAT} -o $@ ${LDFLAGS}

static: ${OBJS}
	${CC} ${OBJS} -o gmid ${LDFLAGS} ${STATIC}

TAGS: ${SRCS}
	@(etags ${SRCS} || true) 2>/dev/null

clean:
	rm -f *.o compat/*.o y.tab.c y.tab.h y.output gmid
	rm -f compile_flags.txt

cleanall: clean
	${MAKE} -C regress clean

regress: gmid
	${MAKE} 'TESTS=${TESTS}' -C regress all

install: gmid
	mkdir -p ${DESTDIR}${BINDIR}
	mkdir -p ${DESTDIR}${MANDIR}/man1
	${INSTALL_PROGRAM} gmid ${DESTDIR}${BINDIR}
	${INSTALL_MAN} gmid.1 ${DESTDIR}${MANDIR}/man1

compile_flags.txt:
	printf "%s\n" ${CFLAGS} > compile_flags.txt

# make sure we pass -o to ${CC}.  OpenBSD default suffix rule doesn't
.SUFFIXES: .c .o
.c.o:
	${CC} ${CFLAGS} -c $< -o $@
