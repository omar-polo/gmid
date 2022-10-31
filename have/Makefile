DISTFILES =	Makefile \
		err.c \
		explicit_bzero.c \
		freezero.c \
		getdtablecount.c \
		getdtablesize.c \
		getprogname.c \
		imsg.c \
		landlock.c \
		libevent.c \
		libevent2.c \
		libtls.c \
		noop.c \
		openssl.c \
		pr_set_name.c \
		program_invocation_short_name.c \
		queue_h.c \
		reallocarray.c \
		recallocarray.c \
		setproctitle.c \
		strlcat.c \
		strlcpy.c \
		strtonum.c \
		tree_h.c \
		vasprintf.c

all:
	false

dist: ${DISTFILES}
	mkdir -p ${DESTDIR}/
	${INSTALL} -m 0644 ${DISTFILES} ${DESTDIR}/

.PHONY: all dist
include ../Makefile.local
