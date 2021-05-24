include ../Makefile.local

.PHONY: all clean runtime

all: gg puny-test testdata iri_test cert.pem testca.pem valid.crt invalid.cert.pem
	./puny-test
	./runtime
	./iri_test

gg: gg.o ../iri.o ../utf8.o ${COMPAT}
	${CC} gg.o ../iri.o ../utf8.o ${COMPAT} -o $@ ${LDFLAGS}

puny-test: puny-test.o ../puny.o ../utf8.o ../utils.o ../log.o ${COMPAT}
	${CC} puny-test.o ../puny.o ../utf8.o ../utils.o ../log.o ${COMPAT} \
		-o puny-test ${LDFLAGS}

iri_test: iri_test.o ../iri.o ../utf8.o ${COMPAT}
	${CC} iri_test.o ../iri.o ../utf8.o ${COMPAT} -o iri_test

fill-file: fill-file.o
	${CC} fill-file.o -o fill-file

key.pem: cert.pem

# XXX: key size is NOT GOOD.  This is only for testing.  Smaller keys
# are quicker to generate.  DON'T DO THIS AT HOME.
cert.pem:
	printf ".\n.\n.\n.\n.\nlocalhost\n.\n" |	\
		openssl req -x509 -newkey rsa:2048	\
			-keyout key.pem			\
			-out cert.pem			\
			-days 365 -nodes
	@echo

testca.pem:
	openssl genrsa -out testca.key 2048
	printf ".\n.\n.\n.\n.\ntestca\n.\n" |	\
		openssl req -x509 -new -sha256		\
			-key testca.key			\
			-days 365 -nodes		\
			-out testca.pem
	@echo

valid.crt: testca.pem
	openssl genrsa -out valid.key 2048
	printf ".\n.\n.\n.\n.\nvalid\n.\n\n\n"|	\
		openssl req -new -key valid.key	\
			-out valid.csr
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
	rm -f testca.* valid.csr valid.key invalid.*pem
	rm -rf testdata fill-file puny-test gg

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
