include ../Makefile.local

.PHONY: all clean runtime

all: iri_test runtime
	./iri_test

iri_test: iri_test.o ../iri.o ../utf8.o
	${CC} iri_test.o ../iri.o ../utf8.o -o iri_test ${LDFLAGS}

fill-file: fill-file.o
	${CC} fill-file.o -o fill-file

key.pem: cert.pem

# XXX: key size is NOT GOOD.  This is only for testing.  Smaller keys
# are quicker to generate.  DON'T DO THIS AT HOME.
cert.pem:
	printf ".\n.\n.\n.\n.\nlocalhost\n.\n" |	\
		openssl req -x509 -newkey rsa:1024	\
			-keyout key.pem			\
			-out cert.pem			\
			-days 365 -nodes
	@echo

clean:
	rm -f *.o iri_test cert.pem key.pem
	rm -rf testdata

testdata: fill-file
	mkdir testdata
	./fill-file testdata/bigfile
	./sha testdata/bigfile testdata/bigfile.sha
	printf "# hello world\n" > testdata/index.gmi
	./sha testdata/index.gmi testdata/index.gmi.sha
	cp hello slow err testdata/
	mkdir testdata/dir
	cp testdata/index.gmi testdata/dir/foo.gmi

runtime: testdata cert.pem
	./runtime