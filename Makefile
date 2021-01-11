CC =		cc
CFLAGS =	-Wall -Wextra -g
LDFLAGS =	-ltls

.PHONY: all clean test

all: gmid TAGS README.md

gmid: gmid.o iri.o utf8.o
	${CC} gmid.o iri.o utf8.o -o gmid ${LDFLAGS}

TAGS: gmid.c iri.c utf8.c
	-etags gmid.c iri.c utf8.c || true

clean:
	rm -f *.o gmid iri_test

iri_test: iri_test.o iri.o utf8.o
	${CC} iri_test.o iri.o utf8.o -o iri_test ${LDFLAGS}

test: iri_test
	./iri_test
