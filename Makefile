all: test
test: test.c
	${CC} -o test test.c

.PHONY: regress
regress: test
	./test
