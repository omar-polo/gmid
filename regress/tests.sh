test_punycode() {
	dont_check_server_alive=yes
	./puny-test
}

test_iri() {
	dont_check_server_alive=yes
	./iri_test
}

test_configless_mode() {
	dont_check_server_alive=yes

	$gmid -p $port -H localhost -d . testdata &
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
	setup_simple_test 'map "text/x-funny" to-ext "gmi"' ''

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

test_cgi_scripts() {
	setup_simple_test '' 'cgi "*"'

	fetch /hello
	check_reply "20 text/gemini" "# hello world" || return 1

	fetch /slow
	check_reply "20 text/gemini" "# hello world" || return 1

	fetch /err
	check_reply "42 CGI error" || return 1

	fetch /invalid
	check_reply "42 CGI error" || return 1
}

test_cgi_big_replies() {
	setup_simple_test '' 'cgi "*"'

	hdr="$(head /serve-bigfile)"
	get /bigfile > bigfile
	./sha bigfile bigfile.sha
	body="$(cat bigfile.sha)"
	check_reply "20 application/octet-stream" "$(cat testdata/bigfile.sha)"
}

test_cgi_split_query() {
	setup_simple_test '' 'cgi "*"'

	for s in "1" "2 ?foo" "3 ?foo+bar" "1 ?foo+bar=5" "3 ?foo+bar%3d5"; do
		exp="$(echo $s | sed 's/ .*//')"
		qry="$(echo $s | sed 's/^..//')"

		if [ "$exp" = "$qry" ]; then
			# the "1" case yields exp == qry
			qry=''
		fi

		url="/env$qry"

		n="$(get "$url" | awk /^-/ | count)"
		if [ $? -ne 0 ]; then
			echo "failed to get /$url"
			return 1
		fi

		if [ "$n" -ne $exp ]; then
			echo "Unexpected number of args"
			echo "want : $exp"
			echo "got  : $n"
			return 1
		fi
	done
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
	check_reply "20 text/gemini"

	# we expect 5 lines from the auto index

	body="$(get /dir/ | count)"
	if [ $? -ne 0 ]; then
		echo 'failed to get /dir/'
		return 1
	fi

	if [ "$body" -ne 5 ]; then
		echo "expected five lines from the auto index, got $body"
		return 1
	fi
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

test_entrypoint() {
	setup_simple_test '' 'entrypoint "/env"'

	fetch_hdr /foo/bar
	check_reply "20 text/plain; lang=en" || return 1

	# TODO: test something similar with plain cgi too

	body="$(get /foo/bar|grep PATH_INFO)"
	if [ $? -ne 0 ]; then
		echo "failed to get /foo/bar"
		return 1
	fi

	if [ "$body" != "PATH_INFO=/foo/bar" ]; then
		echo "Invalid PATH_INFO generated"
		echo "want : PATH_INFO=/foo/bar"
		echo "got  : $body"
		return 1
	fi
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

# 1.7.4 bugfix: check_for_cgi goes out-of-bound processing a string
# that doesn't contain a '/'
test_174_bugfix() {
	setup_simple_test '' 'cgi "*"'

	# thanks cage :)
	for i in 0 1 2 3 4 5 6 7 8 9; do
		fetch /favicon.txt
		check_reply "51 not found" || return 1
	done
}
