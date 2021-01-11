
# NAME

**gmid** - dead simple zero configuration gemini server

# SYNOPSIS

**gmid**
\[**-6fh**]
\[**-c**&nbsp;*cert.pem*]
\[**-d**&nbsp;*docs*]
\[**-k**&nbsp;*key.pem*]
\[**-p**&nbsp;*port*]
\[**-x**&nbsp;*cgi-bin*]

# DESCRIPTION

**gmid**
is a very simple and minimal gemini server that can serve static files
and execute CGI scripts.

**gmid**
won't serve files outside the given directory and won't follow
symlinks.
Furthermore, on
OpenBSD,
pledge(2)
and
unveil(2)
are used to ensure that
**gmid**
dosen't do anything else than read files from the given directory,
accept network connections and, optionally, execute CGI scripts.

**gmid**
fully supports IRIs (Internationalized Resource Identifiers, see
RFC3987).

It should be noted that
**gmid**
is very simple in its implementation, and so it may not be appropriate
for serving sites with lots of users.
After all, the code is single threaded and use a single process,
although it can handle multiple clients at the same time.

If a user request path is a directory,
**gmid**
will try to serve a
*index.gmi*
file inside that directory.

The options are as follows:

**-6**

> Enable IPv6.

**-c** *cert.pem*

> The certificate to use, by default is
> *cert.pem*.

**-d** *docs*

> The root directory to serve.
> **gmid**
> won't serve any file that is outside that directory.
> By default is
> *docs*.

**-f**

> stays and log in the foreground, do not daemonize the process.

**-h**

> Print the usage and exit.

**-k** *key.pem*

> The key for the certificate, by default is
> *key.pem*.

**-p** *port*

> The port to bind to, by default 1965.

**-x** *dir*

> Enable execution of CGI scripts inside the given directory (relative
> to the document root.)  Cannot be provided more than once.

# CGI

When CGI scripts are enabled for a directory, a request for an
executable file will execute it and fed its output to the client.

The CGI scripts will inherit the environment from
**gmid**
with these additional variables set:

`SERVER_SOFTWARE`

> "gmid"

`SERVER_PORT`

> "1965"

`SCRIPT_NAME`

> The (public) path to the script.

`SCRIPT_EXECUTABLE`

> The full path to the executable.

`REQUEST_URI`

> The user request (without the query parameters.)

`REQUEST_RELATIVE`

> The request relative to the script.

`QUERY_STRING`

> The query parameters.

`REMOTE_HOST`

> The remote IP address.

`REMOTE_ADDR`

> The remote IP address.

`DOCUMENT_ROOT`

> The root directory being served, the one provided with the
> *d*
> parameter to
> **gmid**

`AUTH_TYPE`

> The string "Certificate" if the client used a certificate, otherwise unset.

`REMOTE_USER`

> The subject of the client certificate if provided, otherwise unset.

`TLS_CLIENT_ISSUER`

> The is the issuer of the client certificate if provided, otherwise unset.

`TLS_CLIENT_HASH`

> The hash of the client certificate if provided, otherwise unset.
> The format is "ALGO:HASH".

Let's say you have a script in
*/cgi-bin/script*
and the user request is
*/cgi-bin/script/foo/bar?quux*.
Then
`SCRIPT_NAME`
will be
*/cgi-bin/script*,
`SCRIPT_EXECUTABLE`
will be
*$DOCUMENT\_ROOT/cgi-bin/script*,
`REQUEST_URI`
will be
*/cgi-bin/script/foo/bar*,
`REQUEST_RELATIVE`
will be
*foo/bar and*
`QUERY_STRING`
will be
*quux*.

# EXAMPLES

To quickly getting started

	$ # generate a cert and a key
	$ openssl req -x509 -newkey rsa:4096 -keyout key.pem \
	        -out cert.pem -days 365 -nodes
	$ mkdir docs
	$ cat <<EOF > docs/index.gmi
	# Hello world
	test paragraph...
	EOF
	$ gmid -c cert.pem -k key.pem -d docs

Now you can visit gemini://localhost/ with your preferred gemini
client.

To add some CGI scripts, assuming a setup similar to the previous
example, you can

	$ mkdir docs/cgi-bin
	$ cat <<EOF > docs/cgi-bin/hello-world
	#!/bin/sh
	printf "20 text/plain\r\n"
	echo "hello world!"
	EOF
	$ gmid -x cgi-bin

Note that the argument to the
**-x**
option is
*cgi-bin*
and not
*docs/cgi-bin*,
since it's relative to the document root.

# ACKNOWLEDGEMENTS

**gmid**
uses the "Flexible and Economical" UTF-8 decoder written by
Bjoern Hoehrmann.

# CAVEATS

*	it doesn't support virtual hosts: the host part of the request URL is
	completely ignored.

*	a %2F sequence in the path part is indistinguishable from a literal
	slash: this is not RFC3986-compliant.

*	a %00 sequence either in the path or in the query part is treated as
	invalid character and thus rejected.

