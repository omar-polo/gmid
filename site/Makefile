MANPAGES =	gemexp.1 \
		gg.1 \
		gmid.conf.5 \
		gmid.8 \
		titan.1

PAGES =		index.gmi \
		changelog.gmi \
		contrib.gmi \
		quickstart.gmi \
		faq.gmi

TITLE_index.gmi =	home
TITLE_changelog.gmi =	changelog
TITLE_contrib.gmi =	contrib
TITLE_quickstart.gmi =	guide
TITLE_faq.gmi =		faq

REPOLOGY_BANNER =	https://repology.org/badge/vertical-allrepos/gmid.svg
REPOLOGY_URL =		https://repology.org/project/gmid/versions

SUBST =		./subst GITHUB=https://github.com/omar-polo/gmid \
			SITE=https://ftp.omarpolo.com \
			VERS=2.0.5 \
			PUBKEY=gmid-2.0.pub \
			TREE=https://github.com/omar-polo/gmid/blob/master

SUBST_GEM =	${SUBST} MANEXT=txt  EXT=gmi  REPOLOGY=${REPOLOGY_URL}
SUBST_WWW =	${SUBST} MANEXT=html EXT=html REPOLOGY=${REPOLOGY_BANNER}

.PHONY: all dirs manpages serve-www serve-gemini upload clean titles

all: dirs manpages pages
	cp style.css mandoc.css www/
	cp vim-screenshot.png www/
	cp vim-screenshot.png gemini/

dirs:
	mkdir -p gemini www

MANOPTS = -Oman='%N.%S.html;https://man.openbsd.org/%N.%S',style=mandoc.css

manpages:
.for m in ${MANPAGES}
	@echo generating www/${m:T}.html
	cd .. && man -Thtml ${MANOPTS} -l $m > site/www/${m:T}.html
	man -O width=65 -Tutf8 -l $m | col -b > gemini/${m:T}.txt
.endfor

pages:
.for p in ${PAGES}
	${MAKE} titles-gem | ./menu.pl $p gemini > gemini/$p
	${SUBST_GEM} $p >> gemini/$p

	${SUBST_WWW} TITLE=${TITLE_${p}:Q} header.html > www/${p:.gmi=.html}
	${MAKE} titles-www | ./menu.pl "${p:.gmi=.html}" html >> www/${p:.gmi=.html}
	${SUBST_WWW} $p | ./gem2html >> www/${p:.gmi=.html}
	cat footer.html >> www/${p:.gmi=.html}
.endfor

serve-www:
	python3 -m http.server --directory www 8888

serve-gemini:
	./../gemexp ./gemini

upload:
	openrsync --rsync-path=openrsync --del -a www/ antartica:/var/www/gmid.omarpolo.com
	openrsync --rsync-path=openrsync --del -a gemini/ antartica:/var/gemini/gmid.omarpolo.com

titles-gem:
.for p in ${PAGES}
	@printf "%s %s\n" "${p}" ${TITLE_${p}:Q}
.endfor

titles-www:
.for p in ${PAGES}
	@printf "%s %s\n" "${p:.gmi=.html}" ${TITLE_${p}:Q}
.endfor
