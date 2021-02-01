.PHONY: all static clean regress install

all: Makefile.local gmid TAGS compile_flags.txt

Makefile.local: configure
	./configure

include Makefile.local

lex.yy.c: lex.l y.tab.c
	${LEX} lex.l

y.tab.c: parse.y
	${YACC} -b y -d parse.y

SRCS = gmid.c iri.c utf8.c ex.c server.c sandbox.c mime.c puny.c utils.c
OBJS = ${SRCS:.c=.o} lex.yy.o y.tab.o ${COMPAT}

gmid: ${OBJS}
	${CC} ${OBJS} -o gmid ${LDFLAGS}

gg: gg.o iri.o utf8.o ${COMPAT}
	${CC} gg.o iri.o utf8.o ${COMPAT} -o $@ ${LDFLAGS}

static: ${OBJS}
	${CC} -static ${OBJS} \
		${LIBDIR}/libcrypto.a ${LIBDIR}/libtls.a ${LIBDIR}/libssl.a \
		-o gmid
	strip gmid

TAGS: ${SRCS}
	-etags ${SRCS} || true

clean:
	rm -f *.o lex.yy.c y.tab.c y.tab.h y.output gmid gg
	rm -f compile_flags.txt
	make -C regress clean

iri_test: iri_test.o iri.o utf8.o
	${CC} iri_test.o iri.o utf8.o -o iri_test ${LDFLAGS}

regress: gmid gg
	make -C regress all

install: gmid
	mkdir -p ${DESTDIR}${BINDIR}
	mkdir -p ${DESTDIR}${MANDIR}/man1
	${INSTALL_PROGRAM} gmid ${DESTDIR}${BINDIR}
	${INSTALL_MAN} gmid.1 ${DESTDIR}${MANDIR}/man1

compile_flags.txt:
	printf "%s\n" ${CFLAGS} > compile_flags.txt
