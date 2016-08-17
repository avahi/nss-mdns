# News

## Sat May 12 2007:

[Version 0.10](http://0pointer.de/lennart/projects/nss-mdns/nss-mdns-0.10.tar.gz)
released. Changes include: Ported to FreeBSD; alignment fixes for SPARC.

## Mon Jan 1 2007:

[Version 0.9](http://0pointer.de/lennart/projects/nss-mdns/nss-mdns-0.9.tar.gz)
released. Changes include: Make most shared library symbols private to
not conflict with any symbols of the program we're loaded into. Fix a
potential endless loop in the mDNS packet parsing code.

**Please note that due to security reasons from this release on the
minimal mDNS stack included in `nss-mdns` (dubbed "legacy") is no
longer built by default. Thus, `nss-mdns` will not work unless
[Avahi](http://avahi.org/) is running! That makes Avahi essentially a
hard dependency of `nss-mdns`. Pass `--enable-legacy` to reenable the
mini mDNS stack again. Please note as well that this release does not
honour `/etc/resolv.conf` domain search lists by default anymore. It
created a lot of problems and was never recommended anyway. You may
reenable this functionality by passing `--enable-search-domains`.**

## Sat Apr 29 2006:

[Version 0.8](http://0pointer.de/lennart/projects/nss-mdns/nss-mdns-0.8.tar.gz)
released. Changes include: Build time option to disable "legacy unicast" mDNS
requests, i.e. resolve exclusively with Avahi; build a special
`_minimal` flavour of the shared objects to minimize
unnecessary name lookup timeouts; fix IPv6 resolving when using
Avahi.

**Please note that starting with nss-mdns 0.8 we encourage you to use
a different `/etc/nsswitch.conf` configuration line. See below
for more information!**

## Sat Nov 19 2005:

[Version
0.7](http://0pointer.de/lennart/projects/nss-mdns/nss-mdns-0.7.tar.gz)
released. Changes include: Portability patch for ARM from Philipp
Zabel; make sure not to print any messages to STDERR; deal with OOM
situations properly; if multiple addresses are assigned to the same
interface make sure to send a query packet only once; other cleanups

## Sun Aug 21 2005:

[Version 0.6](http://0pointer.de/lennart/projects/nss-mdns/nss-mdns-0.6.tar.gz)
released. Changes include: honour search list in
`/etc/resolv.conf`; try to contact [Avahi](http://avahi.org/) for
resolving.

## Sat Jun 4 2005:

[Version 0.5](http://0pointer.de/lennart/projects/nss-mdns/nss-mdns-0.5.tar.gz)
released. Changes include: only lookup hostnames ending in
`.local`; add support for a configuration file
(`/etc/mdns.allow`) to allow lookups for other names.

## Sun May 15 2005:

[Version 0.4](http://0pointer.de/lennart/projects/nss-mdns/nss-mdns-0.4.tar.gz)
released. Changes include: small portability fix for big endian
architectures; send "legacy unicast" packets instead of normal mDNS
packets (this should reduce traffic and improve response time)

## Jan Sun 16 2005:

[Version
0.3](http://0pointer.de/lennart/projects/nss-mdns/nss-mdns-0.3.tar.gz)
released. Changes include: add Debianization; use `ip6.arpa` instead
of `ip6.int` for reverse IPv6 lookups.

## Fri Dec 17 2004:

[Version 0.2](http://0pointer.de/lennart/projects/nss-mdns/nss-mdns-0.2.tar.gz)
released. Changes include: send mDNS queries on every interface that
supports multicasts, instead of only the one with the default route,
making `nss-mdns` more robust on multi-homed hosts; gcc 2.95
compatiblity.

## Mon Dec 6 2004:

[Version 0.1](http://0pointer.de/lennart/projects/nss-mdns/nss-mdns-0.1.tar.gz)
