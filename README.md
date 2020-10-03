
# NAME

**gmid** - dead simple zero configuration gemini server

# SYNOPSIS

**gmid**
\[**-h**]
\[**-c**&nbsp;*cert.pem*]
\[**-d**&nbsp;*docs*]
\[**-k**&nbsp;*key.pem*]

# DESCRIPTION

**gmid**
is a very simple and minimal gemini server.
It only supports serving static content, and strive to be as simple as
possible.

**gmid**
will strip any sequence of
*../*
or trailing
*..*
in the requests made by clients, so it's impossible to serve content
outside the
*docs*
directory by mistake, and will also refuse to follow symlink.
Furthermore, on
OpenBSD,
pledge(2)
and
unveil(2)
are used to ensure that
**gmid**
dosen't do anything else than read files from the given directory and
accept network connections.

It should be noted that
**gmid**
is very simple in its implementation, and so it may not be appropriate
for serving site with lots of users.
After all, the code is single threaded and use a single process.

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
> won't serve any file that is outside that directory.

**-h**

> Print the usage and exit.

**-k** *key.pem*

> The key for the certificate, by default is
> *key.pem*.

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

now you can visit gemini://localhost/ with your preferred gemini client.

# CAVEATS

*	it doesn't support virtual hosts: the host part of the request URL is
	completely ignored.

*	it doesn't fork in the background or anything like that.

