# gmid

> dead simple, zero configuration Gemini server

gmid is a simple and minimal Gemini server.  It can run without
configuration, so it's well suited for local development, but at the
same time has a configuration file flexible enough to meet the
requirements of most capsules.

gmid was initially written to serve static files, but can also
optionally execute CGI scripts.  It was also written with security in
mind: on Linux, FreeBSD and OpenBSD is sandboxed via `seccomp(2)`,
`capsicum(4)`and `pledge(2)`+`unveil(2)` respectively.


## Features

 - IRI support (RFC3987)
 - dual stack: can serve over both IPv4 and IPv6
 - CGI scripts
 - (very) low memory footprint
 - small codebase, easily hackable
 - virtual hosts
 - sandboxed by default on OpenBSD, Linux and FreeBSD


## Drawbacks

 - not suited for very busy hosts.  If you receive an high number of
   connection per-second you'd probably want to run multiple gmid
   instances behind relayd/haproxy or a different server.

## Building

gmid depends a POSIX libc and libtls.  It can probably be linked
against libretls, but I've never tried.

See [INSTALL.gmi](INSTALL.gmi) for more info, but the build is as
simple as

    make

The Makefile isn't able to produce a statically linked executable
(yet), so for that you have to execute by hand

    make
    cc -static *.o /usr/lib/lib{crypto,tls,ssl}.a -o gmid
    strip gmid

to enjoy your ~2.3M statically-linked gmid.


## Architecture/Security considerations

gmid is composed by two processes: a listener and an executor.  The
listener process is the only one that needs internet access and is
sandboxed.  When a CGI script needs to be executed, the executor
(outside of the sandbox) sets up a pipe and gives one end to the
listener, while the other is bound to the CGI script standard output.
This way, is still possible to execute CGI scripts without restriction
even if the presence of a sandbox.

On OpenBSD, the listener process runs with the `stdio recvfd rpath
inet` pledges and has `unveil(2)`ed only the directories that it
serves; the executor has `stdio sendfd proc exec` as pledges.

On FreeBSD, the executor process is sandboxed with `capsicum(4)`.

On Linux, a `seccomp(2)` filter is installed to filter the syscalls
allowed, see [sandbox.c](sandbox.c) for more information on the BPF
program.

In any case, you are invited to run gmid inside some sort of
container/jail.
