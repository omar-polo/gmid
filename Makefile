CC =		cc
CFLAGS =	-Wall -Wextra -g
LDFLAGS =	-ltls

.PHONY: all clean

all: gmid TAGS README.md

gmid: gmid.o
	${CC} gmid.o -o gmid ${LDFLAGS}

TAGS: gmid.c
	-etags gmid.c

README.md: gmid.1
	mandoc -Tmarkdown gmid.1 | sed -e '1d' -e '$d' > README.md

clean:
	rm -f gmid.o gmid
