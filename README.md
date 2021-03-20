# gmid

gmid is a fast Gemini server written with security in mind.  I
initially wrote it to serve static files, but it has grown into a
featureful server.


## Features

(random order)

 - reconfiguration: reload the running configuration without
   interruption
 - sandboxed by default on OpenBSD, Linux and FreeBSD
 - automatic redirect/error pages (see `block return`)
 - IRI support (RFC3987)
 - punycode support
 - dual stack (IPv4 and IPv6)
 - automatic certificate generation for config-less mode
 - CGI scripts
 - low memory footprint
 - event-based asynchronous I/O model
 - small codebase, easily hackable
 - virtual hosts
 - per-location rules
 - optional directory listings
 - configurable mime types
 - chroot support


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

gmid has a rich configuration file, heavily inspired by OpenBSD'
httpd.  While you should definitely check the manpage because it
documents every option in depth, here's a small example of how a
configuration file looks like.

```conf
ipv6 on     # enable ipv6

server "example.com" {
    cert "/path/to/cert.pem"
    key  "/path/to/key.pem"
    root "/var/gemini/example.com"
    lang "it"
    cgi  "/cgi/*"

    location "/files/*" {
        auto index on
    }

    location "/repo/*" {
        # change the index file name
        index "README.gmi"
    }
}
```


## Building

gmid depends on a POSIX libc, libevent2, OpenSSL/LibreSSL and libtls
(provided either by LibreSSL or libretls).  At build time, flex and
yacc (or GNU bison) are also needed.

The build is as simple as

    ./configure
    make

If the configure scripts fails to pick up something, please open an
issue or notify me via email.

To install execute:

    make install

### Docker

If you have trouble installing LibreSSL or libretls, you can use
Docker to build a `gmid` image with:

    docker build -t gmid .

and then run it with something along the lines of

    docker run --rm -it -p 1965:1965 \
        -v /path/to/gmid.conf:...:ro \
        -v /path/to/docs:/var/gemini \
        gmid -c .../gmid.conf

(ellipses used for brevity)

### Local libretls

This is **NOT** recommended, please try to port LibreSSL/LibreTLS to
your distribution of choice or use docker instead.

However, it's possible to statically-link `gmid` to locally-installed
libretls quite easily.  (It's how I test gmid on Fedora, for instance)

Let's say you have compiled and installed libretls in `$LIBRETLS`,
then you can build `gmid` with

    ./configure CFLAGS="-I$LIBRETLS/include" \
                LDFLAGS="$LIBRETLS/lib/libtls.a -lssl -lcrypto -lpthread -levent"
    make

### Testing

Execute

    make regress

to start the suite.  Keep in mind that the regression tests will
create files inside the `regress` directory and bind the 10965 port.


## Architecture/Security considerations

gmid is composed by four processes: the parent process, the logger,
the listener and the executor.  The parent process is the only one
that doesn't drop privileges, but all it does is to wait for a SIGHUP
to reload the configuration and spawn a new generation of children
process.  The logger processes gather the logs and prints 'em to
stderr or syslog (for the time being.)  The listener process is the
only one that needs internet access and is sandboxed by default.  The
executor process exists only to fork and execute CGI scripts.

On OpenBSD, the listener runs with the `stdio recvfd rpath inet`
pledges, while the executor has `stdio sendfd proc exec`; both have
unveiled only the served directories.  The logger process has pledge
`stdio`.

On FreeBSD, the listener and logger process are sandboxed with `capsicum(4)`.

On Linux, a `seccomp(2)` filter is installed in the listener to allow
only certain syscalls, see [sandbox.c](sandbox.c) for more information
on the BPF program.

In any case, you are invited to run gmid inside some sort of
container/jail/chroot.
