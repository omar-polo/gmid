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
		memmem.c \
		queue.h \
		reallocarray.c \
		recallocarray.c \
		setproctitle.c \
		setresgid.c \
		setresuid.c \
		strlcat.c \
		strlcpy.c \
		strtonum.c \
		tree.h \
		vasprintf.c \
		vis.c

all:
	false

dist: ${DISTFILES}
	mkdir -p ${DESTDIR}/
	${INSTALL} -m 0644 ${DISTFILES} ${DESTDIR}/
	mkdir -p ${DESTDIR}/vis
	${INSTALL} -m 0644 vis/vis.h ${DESTDIR}/vis

.PHONY: all dist
include ../config.mk
