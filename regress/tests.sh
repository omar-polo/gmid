test_punycode() {
	dont_check_server_alive=yes
	./puny-test
}

test_iri() {
	dont_check_server_alive=yes
	./iri_test
}

test_ge() {
	dont_check_server_alive=yes

	$ge -p $port -d . testdata &
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
	./sha bigfile bigfile.sha
	body="$(cat bigfile.sha)"

	check_reply "20 application/octet-stream" "$(cat testdata/bigfile.sha)"
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

	ggflags="-C invalid.cert.pem -K invalid.key.pem"
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
	# XXX: prefork 1 for testing
	setup_simple_test 'prefork 1' 'fastcgi spawn "'$PWD'/fcgi-test"'

	fetch /
	check_reply "20 text/gemini" "# Hello, world!"
}

test_macro_expansion() {
	cat <<EOF > reg.conf
pwd = "$PWD"
$config_common

server "localhost" {
	# the quoting of \$ is for sh
	cert \$pwd "/cert.pem"
	key  \$pwd "/key.pem"
	root \$pwd "/testdata"
}
EOF

	if ! checkconf; then
		echo "failed to parse the config"
		return 1
	fi

	run

	fetch /
	check_reply "20 text/gemini" "# hello world"
}

test_proxy_relay_to() {
	gen_config '' ''
	set_proxy ''

	run

	ggflags="-P localhost:$port -H localhost.local"

	fetch /
	check_reply "20 text/gemini" "# hello world"
}

test_proxy_with_certs() {
	ggflags="-P localhost:$port -H localhost.local"

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
		cert \"$PWD/invalid.cert.pem\"
		key \"$PWD/invalid.key.pem\"
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
