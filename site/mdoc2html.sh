#!/bin/sh
#
# usage: mdoc2html.sh src out
#
# converts the manpage `src' to the HTML file `out', tweaking the
# style

set -e

: ${1:?missing input file}
: ${2:?missing output file}

man -Thtml -l "$1" > "$2"

exec ed "$2" <<EOF
/<style>
a
    body { max-width: 960px; margin: 0 auto; }
.
wq
EOF
