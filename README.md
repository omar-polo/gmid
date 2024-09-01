# gmid

gmid is a full-featured Gemini server written with security in mind.
It can serve static files, has optional FastCGI and proxying support,
and a rich configuration syntax.

A few helper programs are shipped as part of gmid:

 - `gg` is a simple command-line Gemini client.

 - `gemexp` is a stripped-down config-less version of gmid to quickly
   serve a directory from the command line.

 - `titan` is a command-line titan client.


## Internationalisation (IRIs, IDN, UNICODE)

Even thought the current Gemini specification doesn't mention anything
in this regard, I think it's important to make as easy as possible to
use non-ASCII characters in domain names and URL paths.

For starters, gmid has full support for IRIs (RFC3987 —
Internationalized Resource Identifiers).  IRIs are a superset of URIs
that allow UNICODE characters, so there aren't incompatibilities with
URI-only clients.

There is full support also for IDNs (Internationalized Domain Names).
There's no need to fiddle with punycode, or even know what it is: the
hostname in the configuration file can (and must be) in the decoded
form (e.g. `naïve` and not `xn--nave-6pa`), gmid will do the rest.

The only missing piece is UNICODE normalisation of the IRI path: gmid
doesn't do that (yet).


## Configuration

[httpd]: https://man.openbsd.org/httpd.8

gmid has a rich configuration file, heavily inspired by OpenBSD'
[httpd(8)][httpd], with every detail carefully documented in the
manpage.  Here's a minimal example of a config file:

```conf
# /etc/gmid.conf
server "example.com" {
	listen on * port 1965
	cert "/path/to/cert.pem"
	key  "/path/to/key.pem"
	root "/var/gemini/example.com"
}
```

and a slightly more complex one

```conf
# /etc/gmid.conf
cert_root = "/path/to/keys"

server "example.com" {
	listen on * port 1965

	alias "foobar.com"

	cert $cert_root "/example.com.crt"
	key  $cert_root "/example.com.pem"
	root "/var/gemini/example.com"

	# lang for text/gemini files
	lang "en"

	# only for locations that matches /files/*
	location "/files/*" {
		# generate directory listings
		auto index on
	}

	location "/repo/*" {
		# change the index file name
		index "README.gmi"
		lang "it"
	}
}
```


## Building

gmid depends on libevent2, LibreSSL or OpenSSL, and yacc or GNU bison.

The build is as simple as

	$ ./configure
	$ make

If the configure scripts fails to pick up something, please open an
issue or notify me via email.

To install execute:

	# make install


### Testing

Execute

	$ make regress

to start the suite.  Keep in mind that the regression tests needs to
create a few file inside the `regress` directory and bind the 10965 and
10966 ports.


## Contributing

Any form of contribution is welcome, not only patches or bug reports.
If you have a sample configuration for some specific use-case, a
script or anything that could be useful to others, consider adding it
to the `contrib` directory.


## Architecture/Security considerations

gmid has a privsep design, where the operations done by the daemon are
split into multiple processes:

 - main: the main process is the only one that keeps the original
   privileges.  It opens the TLS certificates on the behalf of the
   `server` and `crypto` processes, reloads the configuration upon
   `SIGHUP` and re-opens the log files upon `SIGUSR1`.

 - logger: handles the logging with syslog and/or local files.

 - server: listens for connections and handles the requests.  It also
   speaks FastCGI and do the proxying.

 - crypto: holds the TLS private keys to avoid a compromised `server`
   process to disclose them.
