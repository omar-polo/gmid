CC =		cc
CFLAGS =	-Wall -Wextra -g
LDFLAGS =	-ltls

.PHONY: all clean test

all: gmid TAGS README.md

gmid: gmid.o uri.o utf8.o
	${CC} gmid.o uri.o utf8.o -o gmid ${LDFLAGS}

TAGS: gmid.c uri.c utf8.c
	-etags gmid.c uri.c utf8.c || true

README.md: gmid.1
	mandoc -Tmarkdown gmid.1 | sed -e '1d' -e '$$d' > README.md

clean:
	rm -f *.o gmid

uri_test: uri_test.o uri.o utf8.o
	${CC} uri_test.o uri.o utf8.o -o uri_test ${LDFLAGS}

test: uri_test
	./uri_test
