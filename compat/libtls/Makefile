DISTFILES =	Makefile \
		asn.c \
		by_mem.c \
		openssl.c \
		tls.c \
		tls.h \
		tls_bio_cb.c \
		tls_client.c \
		tls_config.c \
		tls_conninfo.c \
		tls_internal.h \
		tls_keypair.c \
		tls_ocsp.c \
		tls_peer.c \
		tls_server.c \
		tls_signer.c \
		tls_util.c \
		tls_verify.c

all:
	false

dist: ${DISTFILES}
	mkdir -p ${DESTDIR}/
	${INSTALL} -m 0644 ${DISTFILES} ${DESTDIR}/

.PHONY: all dist
include ../../config.mk
