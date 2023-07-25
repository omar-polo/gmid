# gmid

> **Warning**
> The `master` branch is WIP: it's what gmid 2.0 will be, with
> breaking changes et al.  Please use the latest release from the 1.8
> branch for a stable and documented experience, thank you.

gmid is a full-featured Gemini server written with security in mind.
It can serve static files, has optional FastCGI and proxying support,
and a rich configuration syntax.

gg is a simple command-line Gemini client, and gemexp a stripped-down
config-less gmid version used to quickly serve a directory locally
over Gemini.


## Internationalisation (IRIs, UNICODE, punycode, all that stuff)

Even thought the current Gemini specification doesn't mention anything
in this regard, I do think these are important things and so I tried
to implement them in the most user-friendly way I could think of.

For starters, gmid has full support for IRI (RFC3987 —
Internationalized Resource Identifiers).  IRIs are a superset of URIs,
so there aren't incompatibilities with URI-only clients.

There is full support also for punycode.  In theory, the user doesn't
even need to know that punycode is a thing.  The hostname in the
configuration file can (and must be) in the decoded form (e.g. `naïve`
and not `xn--nave-6pa`), gmid will do the rest.

The only missing piece is UNICODE normalisation of the IRI path: gmid
doesn't do that (yet).


## Configuration

[httpd]: https://man.openbsd.org/httpd.8

gmid has a rich configuration file, heavily inspired by OpenBSD'
[httpd(8)][httpd], with every detail carefully documented in the
manpage.  Here's a minimal example of a config file:

```conf
server "example.com" {
	listen on * port 1965
	cert "/path/to/cert.pem"
	key  "/path/to/key.pem"
	root "/var/gemini/example.com"
}
```

and a slightly more complex one

```conf
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

gmid depends on libevent2, OpenSSL/LibreSSL and libtls (provided
either by LibreSSL or libretls).  At build time, yacc (or GNU bison)
is also needed.

The build is as simple as

	$ ./configure
	$ make

If the configure scripts fails to pick up something, please open an
issue or notify me via email.

To install execute:

	# make install

Please keep in mind that the master branch, from time to time, may be
accidentally broken on some platforms.  gmid is developed primarily on
OpenBSD/amd64 and commits on the master branch don't get always tested
in other OSes.  Before tagging a release however, a comprehensive
testing on various platform is done to ensure that everything is
working as intended.


### Testing

Execute

	$ make regress

to start the suite.  Keep in mind that the regression tests needs to
create a few file inside the `regress` directory and bind the 10965
port.


## Contributing

Any form of contribution is welcome, not only patches or bug reports.
If you have a sample configuration for some specific use-case, a
script or anything that could be useful to others, consider adding it
to the `contrib` directory.


## Architecture/Security considerations

The internal architecture was revisited for the 2.0 release.  For
previous releases, please refer to previous revision of this file.

gmid has a privsep design, where the operations done by the daemon are
splitted into multiple processes:

 - main: the main process is the only one that keeps the original
   privileges.  It opens the TLS certificates on the behalf of the
   `server` and `crypto` processes and reloads the configuration upon
   `SIGHUP`.

 - logger: logs the requests.

 - server: listen on the binded ports and serves the request.  This
   also include speaking FastCGI and proxying requests.

 - crypto: (used only on OpenBSD at the time of writing.)  Holds the
   TLS private keys to avoid a compromised `server` process to
   disclose them.
