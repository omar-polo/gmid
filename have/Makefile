DISTFILES =	ASN1_time_parse.c \
		ASN1_time_tm_clamp_notafter.c \
		ASN1_time_tm_cmp.c \
		Makefile \
		SSL_CTX_load_verify_mem.c \
		SSL_CTX_use_certificate_chain_mem.c \
		X509_LOOKUP_mem.c \
		arc4random.c \
		endian_h.c \
		err.c \
		explicit_bzero.c \
		freezero.c \
		getdtablecount.c \
		getdtablesize.c \
		getentropy.c \
		getprogname.c \
		imsg.c \
		landlock.c \
		libevent.c \
		libevent2.c \
		libtls.c \
		memmem.c \
		noop.c \
		openssl.c \
		pr_set_name.c \
		program_invocation_short_name.c \
		queue_h.c \
		reallocarray.c \
		recallocarray.c \
		setproctitle.c \
		setresgid.c \
		setresuid.c \
		strlcat.c \
		strlcpy.c \
		strtonum.c \
		timingsafe_memcmp.c \
		tree_h.c \
		vasprintf.c \
		vis.c \
		wait_any.c

all:
	false

dist: ${DISTFILES}
	mkdir -p ${DESTDIR}/
	${INSTALL} -m 0644 ${DISTFILES} ${DESTDIR}/

.PHONY: all dist
include ../config.mk
