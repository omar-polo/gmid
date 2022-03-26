# tests to run as a port of the regression suite.  Leave empty to run
# all.
TESTS=

.PHONY: all static clean cleanall test regress install

all: Makefile.local gmid gg

Makefile.local: configure
	./configure

include Makefile.local

y.tab.c: parse.y
	${YACC} -b y parse.y

gmid: ${GMID_OBJS}
	${CC} ${GMID_OBJS} -o $@ ${LDFLAGS}

gg: ${GG_OBJS}
	${CC} ${GG_OBJS} -o $@ ${LDFLAGS}

static: ${GMID_OBJS}
	${CC} ${GMID_OBJS} -o gmid ${LDFLAGS} ${STATIC}

clean:
	rm -f *.o compat/*.o y.tab.c y.tab.h y.output gmid gg
	rm -f compile_flags.txt

cleanall: clean
	${MAKE} -C regress clean

test: regress
regress: all
	${MAKE} 'TESTS=${TESTS}' -C regress all

install: gmid
	mkdir -p ${DESTDIR}${BINDIR}
	mkdir -p ${DESTDIR}${MANDIR}/man1
	${INSTALL_PROGRAM} gmid ${DESTDIR}${BINDIR}
	${INSTALL_PROGRAM} gg ${DESTDIR}${BINDIR}
	${INSTALL_MAN} gmid.1 ${DESTDIR}${MANDIR}/man1
	${INSTALL_MAN} gg.1 ${DESTDIR}${MANDIR}/man1

compile_flags.txt:
	printf "%s\n" ${CFLAGS} > compile_flags.txt

# make sure we pass -o to ${CC}.  OpenBSD default suffix rule doesn't
.SUFFIXES: .c .o
.c.o:
	${CC} ${CFLAGS} -c $< -o $@
