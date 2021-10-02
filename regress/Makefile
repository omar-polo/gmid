include ../Makefile.local

.PHONY: all data clean runtime

all: data gg puny-test fcgi-test
	./puny-test
	./iri_test
	./runtime

data: testdata iri_test cert.pem testca.pem valid.crt invalid.cert.pem

gg: gg.o ../iri.o ../utf8.o ${COMPAT}
	${CC} gg.o ../iri.o ../utf8.o ${COMPAT} -o $@ ${LDFLAGS}

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
	rm -rf testdata fill-file puny-test gg fcgi-test

testdata: fill-file
	mkdir testdata
	./fill-file testdata/bigfile
	./sha testdata/bigfile testdata/bigfile.sha
	printf "# hello world\n" > testdata/index.gmi
	./sha testdata/index.gmi testdata/index.gmi.sha
	cp hello slow err invalid serve-bigfile env testdata/
	cp max-length-reply testdata
	mkdir testdata/dir
	cp hello testdata/dir
	cp testdata/index.gmi testdata/dir/foo.gmi

runtime: testdata
	./runtime
