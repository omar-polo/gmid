DISTFILES =	Makefile \
		arc4random.c \
		arc4random.h \
		chacha_private.h \
		err.c \
		explicit_bzero.c \
		freezero.c \
		getdtablecount.c \
		getdtablesize.c \
		getentropy.c \
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
		timingsafe_memcmp.c \
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
	${MAKE} -C libtls DESTDIR=${DESTDIR}/libtls dist

.PHONY: all dist
include ../config.mk
