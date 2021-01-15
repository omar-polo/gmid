# gmid

> dead simple, zero configuration Gemini server

gmid is a simple and minimal Gemini server.  It requires no
configuration whatsoever so it's well suited for local development
machines.

Care has been taken to assure that gmid doesn't serve files outside
the given directory, and it won't follow symlinks.  Furthermore, on
OpenBSD, gmid is also `pledge(2)`ed and `unveil(2)`ed: the set of
pledges are `stdio rpath inet`, with the addition of `proc exec` if
CGI scripts are enabled, while the given directory is unveiled with
`rx`.


## Features

 - IRI support (RFC3987)
 - dual stack: can serve over both IPv4 and IPv6
 - CGI scripts
 - (very) low memory footprint
 - small codebase, easily hackable
 - virtual hosts
 - sandboxed on OpenBSD and FreeBSD


## Drawbacks

 - not suited for very busy hosts.  If you receive an high number of
   connection per-second you'd probably want to run multiple gmid
   instances behind relayd/haproxy or a different server.

 - the sandbox on FreeBSD is **NOT** activated if CGI scripts are
   enabled: CGI script cannot be used with the way `capsicum(4)` works


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
