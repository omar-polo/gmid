#!/bin/sh

# sha256 of "20 text/gemini\r\n# hello world\n"
ok_res=6989d9b0e082c79edb8f625ebb77ddcb07764d3dd0c7c5ae60a27a50a33f6a15

# sha256 of docs/script
script_res=00bf8349336a4a1896f9e98dda67c8264f70b767343351247db96b4546f8d872

get() {
	./gg.py "$1" 10965
}

# check "path" "expected-sha256"
check() {
	got=`get "$1" | $sha | awk '{print \$1}'`
	if [ "$got" '!=' "$2" ]; then
		echo "FAIL $1 (with_cgi: $with_cgi)"
		quit
	else
		echo "PASS $1"
	fi
}

quit() {
	pkill gmid
	exit ${1:-1}
}

# check for sha256sum (linux) or sha256 (OpenBSD)
if which sha256sum >/dev/null; then
	sha=sha256sum
elif which sha256 >/dev/null; then
	sha=sha256
else
	echo "No sha256/sha256sum binary available"
	exit 1
fi

with_cgi="no"
./../gmid -c no-cgi.conf 2>/dev/null &

check "/" $ok_res
check "/index.gmi" $ok_res
check "/script" $script_res

if ! pkill gmid; then
	echo "Is gmid still running?"
	exit 1
fi

wait

with_cgi="yes"
./../gmid -c cgi.conf 2>/dev/null &

check "/" $ok_res
check "/index.gmi" $ok_res
check "/script" $ok_res

quit 0
