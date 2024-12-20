test_punycode() {
	dont_check_server_alive=yes
	./puny-test
}

test_iri() {
	dont_check_server_alive=yes
	./iri_test
}

test_gg_n_flag() {
	dont_check_server_alive=yes
	$gg -n gemini://omarpolo.com/ || return 1

	# XXX this fails on macos in the CI, while in
	# test_iri passes successfully.  Unfortunately,
	# I can't debug stuff on darwin (lacking hardware.)
	#$gg -n "foo://bar.com/cafè.gmi" || return 1

	$gg -n gemini://omarpolo.com/../ || return 1
}

test_parse_comments_at_start() {
	dont_check_server_alive=yes

	cat <<EOF >reg.conf
# a comment

server "$server_name" {
	cert "$PWD/localhost.pem"
	key  "$PWD/localhost.key"
	root "$PWD/testdata"
	listen on $host port $port
}
EOF

	$gmid -n -c reg.conf >/dev/null
}

test_dump_config() {
	dont_check_server_alive=yes
	gen_config '' ''

        exp="$(mktemp)"
	got="$(mktemp)"
	cat <<EOF >$exp
prefork 3

server "localhost" {
	cert "$PWD/localhost.pem"
	key "$PWD/localhost.key"
}
EOF

	$gmid -nn -c reg.conf > $got 2>/dev/null

	ret=0
	if ! cmp -s "$exp" "$got"; then
    		echo "config differs!" >&2
    		diff -u "$exp" "$got" >&2
    		ret=1
	fi

	rm "$exp" "$got"
	return $ret
}

test_gemexp() {
	dont_check_server_alive=yes

	$gemexp -p $port -d . testdata &
	pid=$!
	sleep 1

	fetch /
	kill $pid
	check_reply "20 text/gemini" "# hello world" || return 1
}

test_static_files() {
	setup_simple_test

	fetch /
	check_reply "20 text/gemini" "# hello world" || return 1

	fetch /foo
	check_reply "51 not found" || return 1

	fetch /dir/foo.gmi
	check_reply "20 text/gemini" "# hello world" || return 1
}

test_alias() {
	alias="foo.example"
	setup_simple_test '' "alias '$alias'"
	gghost="$alias"
	ggflags="-P localhost:$port -H $alias"

	fetch /
	check_reply "20 text/gemini" "# hello world" || return 1
}

test_alias_long_hostname() {
	# longer than 64 chars to detect issues with glibc
	# posix-violating tiny HOST_NAME_MAX.
	alias=foo.jjijhrngx5ZxWY0p3o9jag3fOEuZQ64Iuler243oAkkCCqq8pFufw43DBLgVX.test

	setup_simple_test '' "alias '$alias'"

	fetch /
	check_reply "20 text/gemini" "# hello world" || return 1

	# now the same but against the alias

	gghost=$alias
	ggflags="-P localhost:$port -H $alias"

	fetch /
	check_reply "20 text/gemini" "# hello world" || return 1
}

test_directory_redirect() {
	setup_simple_test

	fetch /dir
	check_reply "30 /dir/" || return 1

	fetch /dir/
	check_reply "51 not found" || return 1
}

test_serve_big_files() {
	setup_simple_test

	hdr="$(head /bigfile)"
	get /bigfile > bigfile

	want="20 application/octet-stream"
	if [ "$hdr" != "$want" ]; then
		echo "Header mismatch" >&2
		echo "wants : $want"   >&2
		echo "got   : $hdr"    >&2
		return 1
	fi

	if ! cmp -s bigfile testdata/bigfile; then
		echo "received bigfile is not as expected"
		cmp bigfile testdata/bigfile
		return 1
	fi
}

test_dont_execute_scripts() {
	setup_simple_test

	fetch_hdr /hello
	check_reply "20 application/octet-stream" "" || return 1
}

test_custom_mime() {
	setup_simple_test '
types {
	text/x-funny gmi
}
' ''

	fetch_hdr /
	check_reply "20 text/x-funny"
}

test_default_type() {
	setup_simple_test '' 'default type "application/x-foo"'

	fetch_hdr /hello
	check_reply "20 application/x-foo"
}

test_custom_lang() {
	setup_simple_test '' 'lang it'

	fetch_hdr /
	check_reply "20 text/gemini;lang=it"
}

test_parse_custom_lang_per_location() {
	setup_simple_test '' \
	    'lang it location "/en/*" {lang en} location "/de/*" {lang de}'
	# can parse multiple locations
}

test_custom_index() {
	setup_simple_test '' 'index "foo.gmi"'

	fetch /dir/
	check_reply "20 text/gemini" "# hello world"
}

test_custom_index_default_type_per_location() {
	setup_simple_test '' 'location "/dir/*" { default type "text/plain" index "hello" }'

	fetch /dir/
	check_reply "20 text/plain" "$(cat hello)"
}

test_auto_index() {
	setup_simple_test '' 'location "/dir/*" { auto index on }'

	fetch /
	check_reply "20 text/gemini" "# hello world" || return 1

	fetch_hdr /dir
	check_reply "30 /dir/" || return 1

	fetch_hdr /dir/
	check_reply "20 text/gemini" || return 1

	get /dir/ > listing || return 1
	cat <<EOF > listing.expected
# Index of /dir/

=> ./../
=> ./current%20date
=> ./foo.gmi
=> ./hello
EOF

	cmp -s listing.expected listing
	ret=$?
	if [ $ret -ne 0 ]; then
		echo 'unexpected dir content:'
		diff -u listing.expected listing
	fi
	rm listing listing.expected

	return $ret
}

test_block() {
	setup_simple_test '' 'location "*" { block }'

	fetch /
	check_reply "40 temporary failure" || return 1

	fetch /nonexists
	check_reply "40 temporary failure" || return 1
}

test_block_return_fmt() {
	setup_simple_test '' '
location "/dir" {
	strip 1
	block return 40 "%% %p %q %P %N test"
}
location "*" {
	strip 99
	block return 40 "%% %p %q %P %N test"
}'

	fetch_hdr /dir/foo.gmi
	check_reply "40 % /foo.gmi  10965 localhost test" || return 1

	fetch_hdr /bigfile
	check_reply "40 % /  10965 localhost test" || return 1
}

test_require_client_ca() {
	setup_simple_test '' 'require client ca "'$PWD'/testca.pem"'

	fetch /
	check_reply "60 client certificate required" || return 1

	ggflags="-C valid.crt -K valid.key"
	fetch_hdr /
	check_reply "20 text/gemini" || return 1

	ggflags="-C invalid.pem -K invalid.key"
	fetch_hdr /
	check_reply "61 certificate not authorised" || return 1
}

test_root_inside_location() {
	setup_simple_test '' 'location "/foo/*" { root "'$PWD'/testdata" strip 1 }'

	fetch /foo
	check_reply "51 not found" || return 1

	fetch_hdr /foo/
	check_reply "20 text/gemini"
}

test_root_inside_location_with_redirect() {
	setup_simple_test '' '
location "/foo"   { block return 31 "%p/" }
location "/foo/*" { root "'$PWD'/testdata" strip 1 }'

	fetch /foo
	check_reply "31 /foo/" || return 1

	fetch_hdr /foo/
	check_reply "20 text/gemini"
}

test_fastcgi() {
	./fcgi-test fcgi.sock &
	fcgi_pid=$!

	setup_simple_test 'prefork 1' 'fastcgi socket "'$PWD'/fcgi.sock"'

	i=0
	while [ $i -lt 10 ]; do
		fetch /
		check_reply "20 text/gemini" "$(fcgi_content)"
		if [ $? -ne 0 ]; then
			kill $fcgi_pid
			return 1
		fi

		i=$(($i + 1))
	done

	kill $fcgi_pid
	return 0
}

test_fastcgi_inside_location() {
	./fcgi-test fcgi.sock &
	fcgi_pid=$!
	fcgi_path_info="/foo"
	fcgi_path="$PWD/testdata/foo"

	setup_simple_test 'prefork 1' 'fastcgi socket "'$PWD'/fcgi.sock"
	location "/dir/*" {
		fastcgi off
	}'

	fetch /foo
	if ! check_reply "20 text/gemini" "$(fcgi_content)"; then
		kill $fcgi_pid
		return 1
	fi

	fetch /dir/foo.gmi
	if ! check_reply "20 text/gemini" "# hello world"; then
		kill $fcgi_pid
		return 1
	fi

	kill $fcgi_pid
	return 0
}

test_fastcgi_location_match() {
	./fcgi-test fcgi.sock &
	fcgi_pid=$!
	fcgi_path_info="/foo"
	fcgi_path="$PWD/testdata/foo"

	setup_simple_test 'prefork 1' '
	location "/dir/*" {
		fastcgi off
	}
	location "/*" {
		fastcgi socket "'$PWD'/fcgi.sock"
	}'

	fetch /foo
	if ! check_reply "20 text/gemini" "$(fcgi_content)"; then
		kill $fcgi_pid
		return 1
	fi

	fetch /dir/foo.gmi
	if ! check_reply "20 text/gemini" "# hello world"; then
		kill $fcgi_pid
		return 1
	fi

	kill $fcgi_pid
	return 0
}

test_fastcgi_deprecated_syntax() {
	./fcgi-test fcgi.sock &
	fcgi_pid=$!

	# the old syntax will eventually go away, but check that the
	# backward compatibility works.
	setup_simple_test 'prefork 1' 'fastcgi "'$PWD'/fcgi.sock"'

	fetch /
	check_reply "20 text/gemini" "$(fcgi_content)"
	if [ $? -ne 0 ]; then
		kill $fcgi_pid
		return 1
	fi

	kill $fcgi_pid
	return 0
}

test_macro_expansion() {
	cat <<EOF > reg.conf
pwd = "$PWD"
common = "lang it; auto index on"

server "localhost" {
	# the quoting of \$ is for sh
	cert \$pwd "/localhost.pem"
	key  \$pwd "/localhost.key"
	root \$pwd "/testdata"
	listen on $host port $port
	@common
}
EOF

	if ! checkconf; then
		echo "failed to parse the config"
		return 1
	fi

	run

	fetch /
	check_reply "20 text/gemini;lang=it" "# hello world"
}

test_proxy_relay_to() {
	gen_config '' ''
	set_proxy ''

	run

	ggflags="-P localhost:$proxy_port -H localhost.local"

	fetch /
	check_reply "20 text/gemini" "# hello world"
}

test_proxy_with_certs() {
	ggflags="-P localhost:$proxy_port -H localhost.local"

	# first test using the valid keys

	gen_config '' 'require client ca "'$PWD'/testca.pem"'
	set_proxy "
		cert \"$PWD/valid.crt\"
		key \"$PWD/valid.key\"
	"
	run

	fetch /
	check_reply "20 text/gemini" "# hello world" || return 1

	# then using some invalid keys

	gen_config '' 'require client ca "'$PWD'/testca.pem"'
	set_proxy "
		cert \"$PWD/invalid.pem\"
		key \"$PWD/invalid.key\"
	"
	run

	fetch /
	check_reply "61 certificate not authorised" || return 1

	# and finally without keys

	gen_config '' 'require client ca "'$PWD'/testca.pem"'
	set_proxy ''
	run

	fetch /
	check_reply "60 client certificate required" || return 1
}

test_unknown_host() {
	setup_simple_test '' ''

	ggflags="-N -H foobar"
	fetch /
	check_reply '59 Wrong/malformed host or missing SNI'
}

test_include_mime() {
	setup_simple_test "types { include '$PWD/example.mime.types' }" ""

	fetch_hdr /
	check_reply '20 text/gemini' || return 1

	fetch_hdr /test.m3u8
	check_reply '20 application/vnd.apple.mpegurl' || return 1

	fetch_hdr /foo.1
	check_reply '20 text/x-mandoc' || return 1
}

test_log_file() {
	rm -f log log.edited
	setup_simple_test '
log access "'$PWD'/log"
log style legacy'

	fetch_hdr /
	check_reply '20 text/gemini'

	# remove the ip
	awk '{$1 = ""; print substr($0, 2)}' log > log.edited

	printf '%s\n' 'GET gemini://localhost/ 20 text/gemini' > log.exp
	if ! cmp -s log.edited log.exp; then
		diff -u log.edited log.exp
		# keep the log for post-mortem analysis
		return 1
	fi

	rm -f log log.edited
	return 0
}

test_log_common() {
	rm -f log log.edited
	setup_simple_test '
log access "'$PWD'/log"
log style common'

	fetch_hdr /
	check_reply '20 text/gemini'

	# remove the ip and timestamp
	awk '{$2 = ""; $5 = "timestamp"; $6 = "tz"; print $0}' log > log.edited

	printf '%s\n' 'localhost  - - timestamp tz "gemini://localhost/" 20 0' \
		> log.exp
	if ! cmp -s log.edited log.exp; then
		diff -u log.edited log.exp
		# keep the log for post-mortem analysis
		return 1
	fi

	rm -f log log.edited
	return 0
}

test_log_combined() {
	rm -f log log.edited
	setup_simple_test '
log access "'$PWD'/log"
log style combined'

	fetch_hdr /
	check_reply '20 text/gemini'

	# remove the ip and timestamp
	awk '{$1 = ""; print gensub("\\[.*\\]", "[timestamp]", 1)}' log > log.edited

	printf '%s\n' ' - - [timestamp] "gemini://localhost/" 20 0 "-" ""' > log.exp
	if ! cmp -s log.edited log.exp; then
		diff -u log.edited log.exp
		# keep the log for post-mortem analysis
		return 1
	fi

	rm -f log log.edited
	return 0
}

test_ipv4_addr() {
	server_name="*"
	host="127.0.0.1"
	gghost=127.0.0.1
	ggflags=-N
	setup_simple_test

	fetch /
	check_reply "20 text/gemini" "# hello world" || return 1
}

test_ipv6_addr() {
	server_name="*"
	host="::1"
	gghost="[::1]"
	ggflags=-N
	setup_simple_test

	fetch /
	check_reply "20 text/gemini" "# hello world" || return 1
}

test_ipv6_server() {
	server_name="::1"
	host="::1"
	gghost="[::1]"
	ggflags=-N
	setup_simple_test

	fetch /
	check_reply "20 text/gemini" "# hello world" || return 1
}

test_high_prefork() {
	quit

	setup_simple_test 'prefork 12'

	fetch /
	check_reply "20 text/gemini" "# hello world" || return 1

	dont_check_server_alive=yes
	quit
}

test_proxy_protocol_v1() {
	rm -f log
	proxy=proxy-v1
	gen_config '
log access "'$PWD'/log"
log style legacy' ''
	set_proxy 'proxy-v1'
	run

	ggflags="-P localhost:$proxy_port -H localhost.local"

	# This will generate two log entry: one for the "frontend"
	# and one for the proxied request.  Both should have exactly
	# the same IP and port.
	fetch_hdr /
	check_reply '20 text/gemini'

	n=$(awk '{print $1}' log | uniq | wc -l)
	if [ "$n" -ne 1 ]; then
		# keep the log for post-mortem analysis
		echo
		echo "n is $n"
		return 1
	fi

	rm -f log
	return 0
}
