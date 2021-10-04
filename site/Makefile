.PHONY: all serve-www serve-gemini

all: gmid.1.html gmid.1.txt

gmid.1.html: ../gmid.1
	./mdoc2html.sh $? $@

gmid.1.txt: ../gmid.1
	MANWIDTH=72 man -Tutf8 -l $? | col -b > $@

serve-www:
	python3 -m http.server 8888

serve-gemini:
	gmid -p 1966 .
