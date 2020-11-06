
# NAME

**gmid** - dead simple zero configuration gemini server

# SYNOPSIS

**gmid**
\[**-h**]
\[**-c**&nbsp;*cert.pem*]
\[**-d**&nbsp;*docs*]
\[**-k**&nbsp;*key.pem*]
\[**-l**&nbsp;*logfile*]
\[**-x**&nbsp;*cgi-bin*]

# DESCRIPTION

**gmid**
is a very simple and minimal gemini server that can serve static files
and execute CGI scripts.

**gmid**
will strip any sequence of
*../*
or trailing
*..*
in the requests made by clients, so it's impossible to serve content
outside the
*docs*
directory by mistake, and will also refuse to follow symlinks.
Furthermore, on
OpenBSD,
pledge(2)
and
unveil(2)
are used to ensure that
**gmid**
dosen't do anything else than read files from the given directory,
accept network connections and, optionally, execute CGI scripts.

It should be noted that
**gmid**
is very simple in its implementation, and so it may not be appropriate
for serving sites with lots of users.
After all, the code is single threaded and use a single process,
although it can handle multiple requests concurrently.

If a user request path is a directory,
**gmid**
will try to serve a
*index.gmi*
file inside that directory.
If not found, it will return an error 51 (not found) to the user.

The options are as follows:

**-c** *cert.pem*

> The certificate to use, by default is
> *cert.pem*.

**-d** *docs*

> The root directory to serve.
> **gmid**
> won't serve any file that is outside that directory, by default
> *docs*.

**-h**

> Print the usage and exit.

**-k** *key.pem*

> The key for the certificate, by default is
> *key.pem*.

**-l** *logfile*

> log to the given file instead of the standard error.

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

`SERVER_PROTOCOL`

> "gemini"

`SERVER_PORT`

> "1965"

`PATH_INFO`

> the request path

`PATH_TRANSLATED`

> the full path: the concatenation of the document root and the request
> path

`QUERY_STRING`

> the query string if present in the request URL, otherwise it
> won't be set.

`REMOTE_ADDR`

> the IP address of the client in dot notation

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
since it&#8217;s relative to the document root.

# CAVEATS

*	it doesn't support virtual hosts: the host part of the request URL is
	completely ignored.

*	it doesn't fork in the background or anything like that.

