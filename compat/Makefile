DISTFILES =	Makefile \
		err.c \
		explicit_bzero.c \
		freezero.c \
		getdtablecount.c \
		getdtablesize.c \
		getprogname.c \
		imsg-buffer.c \
		imsg.c \
		imsg.h \
		queue.h \
		reallocarray.c \
		recallocarray.c \
		setproctitle.c \
		strlcat.c \
		strlcpy.c \
		strtonum.c \
		tree.h \
		vasprintf.c

all:
	false

dist: ${DISTFILES}
	mkdir -p ${DESTDIR}/
	${INSTALL} -m 0644 ${DISTFILES} ${DESTDIR}/

.PHONY: all dist
include ../Makefile.local
