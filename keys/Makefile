DISTFILES =	Makefile gmid-1.7.pub gmid-1.8.pub gmid-2.0.pub gmid-2.1.pub

all: false

dist: ${DISTFILES}
	mkdir -p ${DESTDIR}
	${INSTALL} -m 0644 ${DISTFILES} ${DESTDIR}/

.PHONY: all dist
include ../config.mk
