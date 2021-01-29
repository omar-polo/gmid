# gmid

> dead simple, zero configuration Gemini server

gmid is a simple and minimal Gemini server.  It can run without
configuration, so it's well suited for local development, but at the
same time has a configuration file flexible enough to meet the
requirements of most capsules.

It was initially written to serve static files, but can also
optionally execute CGI scripts.  It was also written with security in
mind: on Linux, FreeBSD and OpenBSD is sandboxed via `seccomp(2)`,
`capsicum(4)`and `pledge(2)`+`unveil(2)` respectively.

gmid can be used from the command line to serve local directories

    # serve the directory docs
    gmid docs

or you can pass a configuration file and have access to all the
features

    gmid -c /etc/gmid.conf

Please consult the [manpage](gmid.1) for more information.


## Features

 - IRI support (RFC3987)
 - punycode support
 - dual stack: can serve over both IPv4 and IPv6
 - automatic certificate generation (in config-less mode)
 - CGI scripts
 - (very) low memory footprint
 - small codebase, easily hackable
 - virtual hosts
 - per-location rules
 - optional directory listings
 - configurable mime types
 - sandboxed by default on OpenBSD, Linux and FreeBSD
 - chroot support


## Drawbacks

 - not suited for very busy hosts.  If you receive an high number of
   connection per-second you'd probably want to run multiple gmid
   instances behind relayd/haproxy or a different server.


## Internationalisation (IRIs, UNICODE, punycode, all that stuff)

Even thought the current Gemini specification doesn't mention anything
in this regard, I do think these are important things, so I tried to
implement them in the most user-friendly way I could think of.

For starters, gmid has full support for IRI (RFC3987 --
Internationalized Resource Identifiers).  IRIs are a superset of URIs,
so there aren't incompatibilities with URI-only clients.

There is full support also for punycode.  In theory, the users doesn't
even need to know that punycode is a thing.  The hostname in the
configuration file can (and must be) written with proper UNICODE, gmid
will do the rest.

The only missing piece is UNICODE normalisation.  gmid doesn't
do that (yet).


## Building

gmid depends on a POSIX libc, OpenSSL/LibreSSL and libtls (provided
either by LibreSSL or libretls).  At build time, flex and yacc (or GNU
bison) are also needed.

The build is as simple as

    make

If the configure scripts fails to pick up something, please open an
issue or notify me via email.

To install execute:

    make install

If you have trouble installing LibreSSL or libretls, as they aren't
available as package on various Linux distribution, you can use Docker
to build a `gmid` image with:

    docker build -t gmid .

and then run it with something along the lines of

    docker run --rm -it -p 1965:1965 \
        -v /path/to/gmid.conf:...:ro \
        -v /path/to/docs:/var/gemini \
        gmid -c .../gmid.conf

ellipses for brevity.

### Local libretls

This is **NOT** recommended, please try to port LibreSSL/LibreTLS to
your distribution of choice or use docker instead.

However, it's possible to link `gmid` to locally-installed libtls
quite easily.  (It's how I test gmid on Fedora, for instance)

Let's say you have compiled and installed libretls in `$LIBRETLS`,
then you can build `gmid` with

    ./configure CFLAGS="-I$LIBRETLS/include" \
                LDFLAGS="$LIBRETLS/lib/libtls.a -lssl -lcrypto -lpthread"
    make

### Testing

Execute

    make regress

to start the suite.  Keep in mind that the suite will create files
inside the `regress` directory and bind the 10965 port.


## Architecture/Security considerations

gmid is composed by two processes: a listener and an executor.  The
listener process is the only one that needs internet access and is
sandboxed.  When a CGI script needs to be executed, the executor
(outside of the sandbox) sets up a pipe and gives one end to the
listener, while the other is bound to the CGI script standard output.
This way, is still possible to execute CGI scripts without
restrictions even in the presence of a sandbox.

On OpenBSD, the listener process runs with the `stdio recvfd rpath
inet` pledges, the executor has `stdio sendfd proc exec` as pledges;
both have unveiled only the served directories.

On FreeBSD, the executor process is sandboxed with `capsicum(4)`.

On Linux, a `seccomp(2)` filter is installed to allow only certain
syscalls, see [sandbox.c](sandbox.c) for more information on the BPF
program.

In any case, you are invited to run gmid inside some sort of
container/jail/chroot.
