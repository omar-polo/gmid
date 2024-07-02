DISTFILES =	Makefile \
		iri.c

include ../../config.mk

CC = afl-clang

COBJS =		${COMPATS:.c=.o}
REG_COMPATS =	${COBJS:%=../../%}

IRI_SRCS =	iri.c ../../iri.c ../../utf8.c ../../log.c
IRI_OBJS =	${IRI_SRCS:.c=.o} ${REG_COMPATS}

.PHONY: all data clean dist

all: fuzz

fuzz: iri
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

iri: ${IRI_OBJS}
	${CC} ${IRI_OBJS} -o $@ ${LIBS} ${LDFLAGS}

.c.o:
	${CC} -I../.. ${CFLAGS} -c $< -o $@

clean:
	rm -f *.o iri
