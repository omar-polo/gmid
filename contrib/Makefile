DISTFILES =	Makefile \
		Dockerfile \
		README \
		gencert \
		gmid.service \
		gmid.sysusers \
		mime.types \
		renew-certs

all:
	false

dist: ${DISTFILES}
	mkdir -p ${DESTDIR}/
	${INSTALL} -m 0644 ${DISTFILES} ${DESTDIR}/
	cd ${DESTDIR} && chmod 755 gencert renew-certs
	cp -R vim ${DESTDIR}/vim

.PHONY: all dist
include ../config.mk
