CC =		cc
CFLAGS =	-Wall -Wextra -g
LDFLAGS =	-ltls
LEX =		lex
YACC =		yacc

PREFIX =	/usr/local

# /usr/local/lib on FreeBSD
LIBDIR =	/usr/lib/

.PHONY: all static clean test install

all: gmid TAGS README.md

lex.yy.c: lex.l y.tab.c
	${LEX} lex.l

y.tab.c: parse.y
	${YACC} -b y -d parse.y

OBJS = gmid.o iri.o utf8.o lex.yy.o y.tab.o ex.o server.o sandbox.o
gmid: ${OBJS}
	${CC} ${OBJS} -o gmid ${LDFLAGS}

static: ${OBJS}
	${CC} -static ${OBJS} \
		${LIBDIR}/libcrypto.a ${LIBDIR}/libtls.a ${LIBDIR}/libssl.a \
		-o gmid
	strip gmid

TAGS: gmid.c iri.c utf8.c ex.c server.c sandbox.c
	-etags gmid.c iri.c utf8.c ex.c server.c sandbox.c || true

clean:
	rm -f *.o lex.yy.c y.tab.c y.tab.h y.output gmid iri_test

iri_test: iri_test.o iri.o utf8.o
	${CC} iri_test.o iri.o utf8.o -o iri_test ${LDFLAGS}

test: gmid iri_test
	@echo "IRI tests"
	@echo "=============================="
	./iri_test
	@echo
	@echo "server tests"
	@echo "=============================="
	cd test && ./test.sh

install: gmid
	install -o root -g wheel -m 0755 gmid   ${PREFIX}/bin/
	install -o root -g wheel -m 0644 gmid.1 ${PREFIX}/man/man1
