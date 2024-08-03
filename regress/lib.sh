ran_no=0
failed_no=0
failed=

gemexp="./../gemexp"
gg="./../gg"
gmid="./../gmid"
current_test=
server_name=
gghost=

run_test() {
	ggflags=
	host="$REGRESS_HOST"
	port=10965
	proxy_port=10966
	proxy=
	config_common="log syslog off"
	hdr=
	body=
	dont_check_server_alive=no

	ran_no=$((ran_no + 1))

	current_test=$1
	server_name=localhost
	gghost=localhost

	rm -f reg.conf

	if [ "$2" = "need_ipv6" -a "$HAVE_IPV6" != "yes" ]; then
		echo "$1 skipped (needs HAVE_IPV6='yes')"
		return
	elif ! $1; then
		echo "$1 failed"
		failed="$failed $1"
		failed_no=$((failed_no + 1))
		return
	else
		echo "$1 passed"
	fi

	if [ "$dont_check_server_alive" != 'no' ]; then
		return
	fi

	if ! check; then
		echo "gmid crashed?"
		failed="$failed $1"
		failed_no=$((failed_no + 1))
	fi
}

tests_done() {
	ok=$((ran_no - failed_no))
	echo
	echo "tests: $ran_no / passed: $ok / failed: $failed_no"
	if [ "$failed" != "" ]; then
		echo
		echo "failed tests:$failed"
		exit 1
	fi
	exit 0
}

# usage: gen_config <global config> <server config>
# generates a configuration file reg.conf
gen_config() {
	cat <<EOF > reg.conf
$config_common
$1
server "$server_name" {
	cert "$PWD/localhost.pem"
	key  "$PWD/localhost.key"
	root "$PWD/testdata"
	listen on $host port $port $proxy
	$2
}
EOF
	if ! checkconf; then
		echo "failed to parse the config" >&2
		return 1
	fi
}

set_proxy() {
	cat <<EOF >>reg.conf
server "localhost.local" {
	cert "$PWD/localhost.pem"
	key "$PWD/localhost.key"
	listen on $host port $proxy_port
	proxy {
		relay-to localhost port $port
		$1
	}
}
EOF

	if ! checkconf; then
		echo "failed to parse the config" >&2
		return 1
	fi
}

checkconf() {
	if ! $gmid -n -c reg.conf >/dev/null 2>&1; then
		$gmid -n -c reg.conf
	fi
}

# usage: setup_simple_test <global config> <server config>
# generates a configuration file with `gen_config', validates it and
# launches the daemon
setup_simple_test() {
	gen_config "$1" "$2"
	run
}

# usage: get <path>
# return the body of the request on stdout
get() {
	$gg -q -T10 $ggflags "gemini://$gghost:$port/$1" || true
}

# usage: head <path>
# return the meta response line on stdout
head() {
	$gg -q -T10 -d header $ggflags "gemini://$gghost:$port/$1" || true
}

# usage: fetch <path>
# fetches the header and the body.  They're returned in $hdr and
# $body.
fetch() {
	if ! hdr="$(head $1)" || ! body="$(get $1)"; then
		return 1
	fi
}

# usage: fetch_hdr <path>
# fetches the header into $hdr
fetch_hdr() {
	hdr="$(head $1)"
	body=""
}

# usage: check_reply header body
# checks that $hdr and $body are equal to the given strings
check_reply() {
	if [ "$hdr" != "$1" ]; then
		echo "Header mismatch" >&2
		echo "wants : $1"      >&2
		echo "got   : $hdr"    >&2
		return 1
	fi

	if [ "$body" != "$2" ]; then
		echo "Body mismatch" >&2
		echo "wants : $2"    >&2
		echo "got   : $body" >&2
		return 1
	fi
}

run() {
	if check; then
		kill -HUP "$(cat gmid.pid)"
		sleep 1
		return
	fi

	$gmid -P $PWD/gmid.pid -c reg.conf

	# give gmid time to bind the port, otherwise we end up
	# executing gg when gmid isn't ready yet.
	sleep 1
}

check() {
	if [ ! -f gmid.pid ]; then
		return 1
	fi

	pid="$(cat gmid.pid || true)"
	if [ "$pid" = "" ]; then
		return 1
	fi

	ps $pid >/dev/null
}

count() {
	wc -l | xargs
}

quit() {
	pid="$(cat gmid.pid || true)"
	if [ "$pid" != "" ]; then
		kill $pid || true
		wait || true
	fi
}

onexit() {
	rm -f bigfile bigfile.sha
	quit
}
