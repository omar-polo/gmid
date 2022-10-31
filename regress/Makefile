# tests to run as a port of the regression suite.  Leave empty to run
# all.
TESTS=

DISTFILES =	Makefile \
		env \
		err \
		example.mime.types \
		fcgi-test.c \
		fill-file.c \
		hello \
		invalid \
		iri_test.c \
		lib.sh \
		max-length-reply \
		puny-test.c \
		regress \
		serve-bigfile \
		sha \
		slow \
		tests.sh \
		valid.ext

include ../Makefile.local

COMPAT= ${COBJS:%=../%}

.PHONY: all data clean dist

all: data puny-test iri_test fcgi-test
	./regress ${TESTS}

data: testdata cert.pem testca.pem valid.crt invalid.cert.pem

puny-test: puny-test.o ../puny.o ../utf8.o ../utils.o ../log.o ${COMPAT}
	${CC} puny-test.o ../puny.o ../utf8.o ../utils.o ../log.o ${COMPAT} \
		-o puny-test ${LDFLAGS}

iri_test: iri_test.o ../iri.o ../utf8.o ${COMPAT}
	${CC} iri_test.o ../iri.o ../utf8.o ${COMPAT} -o $@ ${LDFLAGS}

fill-file: fill-file.o
	${CC} fill-file.o -o $@ ${LDFLAGS}

fcgi-test: fcgi-test.o
	${CC} fcgi-test.o ${COMPAT} -o fcgi-test ${LDFLAGS}

key.pem: cert.pem

# XXX: key size is NOT GOOD.  This is only for testing.  Smaller keys
# are quicker to generate.  DON'T DO THIS AT HOME.
cert.pem:
	openssl req -x509 -newkey rsa:2048	\
		-keyout key.pem			\
		-out cert.pem			\
		-days 365 -nodes		\
		-subj "/CN=localhost"
	ln -s cert.pem localhost.cert.pem
	ln -s key.pem localhost.key.pem
	@echo

testca.pem:
	openssl genrsa -out testca.key 2048
	openssl req -x509 -new -sha256		\
		-key testca.key			\
		-days 365 -nodes		\
		-out testca.pem			\
		-subj "/CN=testca"
	@echo

valid.crt: testca.pem
	openssl genrsa -out valid.key 2048
	openssl req -new -key valid.key	\
		-out valid.csr		\
		-subj "/CN=valid"
	@echo
	openssl x509 -req -in valid.csr		\
		-CA testca.pem			\
		-CAkey testca.key		\
		-CAcreateserial			\
		-out valid.crt			\
		-days 365			\
		-sha256 -extfile valid.ext

invalid.cert.pem: cert.pem
	cp cert.pem invalid.cert.pem
	cp key.pem invalid.key.pem

clean:
	rm -f *.o iri_test cert.pem key.pem
	rm -f localhost.cert.pem localhost.key.pem
	rm -f testca.* valid.csr valid.key valid.crt invalid.*pem
	rm -rf testdata fill-file puny-test fcgi-test
	rm -f gmid.pid

testdata: fill-file
	mkdir testdata
	./fill-file testdata/bigfile
	./sha testdata/bigfile testdata/bigfile.sha
	printf "# hello world\n" > testdata/index.gmi
	./sha testdata/index.gmi testdata/index.gmi.sha
	cp hello slow err invalid serve-bigfile env testdata/
	cp max-length-reply testdata
	mkdir testdata/dir
	date > 'testdata/dir/current date'
	cp hello testdata/dir
	cp testdata/index.gmi testdata/dir/foo.gmi
	touch testdata/test.m3u8 testdata/foo.1

dist: ${DISTFILES}
	mkdir -p ${DESTDIR}/
	${INSTALL} -m 0644 ${DISTFILES} ${DESTDIR}/
	cd ${DESTDIR}/ && chmod +x env err hello invalid \
		max-length-reply regress sha slow
