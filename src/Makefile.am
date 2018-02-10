# This file is part of nss-mdns.
#
# nss-mdns is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
#
# nss-mdns is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with nss-mdns; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

EXTRA_DIST = map-file

AM_CFLAGS = \
	-DMDNS_ALLOW_FILE=\"$(sysconfdir)/mdns.allow\" \
	-DAVAHI_SOCKET=\"$(localstatedir)/run/avahi-daemon/socket\"

AM_LDFLAGS=-avoid-version -module -export-dynamic

lib_LTLIBRARIES = \
	libnss_mdns.la \
	libnss_mdns4.la \
	libnss_mdns6.la \
	libnss_mdns_minimal.la \
	libnss_mdns4_minimal.la \
	libnss_mdns6_minimal.la

check_PROGRAMS = nss-test avahi-test
sources = util.c util.h avahi.c avahi.h

# GNU Libc
libnss_mdns_la_SOURCES= $(sources) nss.c
libnss_mdns_la_CFLAGS=$(AM_CFLAGS)
libnss_mdns_la_LDFLAGS=$(AM_LDFLAGS) -shrext .so.2 -Wl,-version-script=$(srcdir)/map-file

libnss_mdns_minimal_la_SOURCES=$(libnss_mdns_la_SOURCES)
libnss_mdns_minimal_la_CFLAGS=$(libnss_mdns_la_CFLAGS) -DMDNS_MINIMAL
libnss_mdns_minimal_la_LDFLAGS=$(libnss_mdns_la_LDFLAGS)

libnss_mdns4_la_SOURCES=$(libnss_mdns_la_SOURCES)
libnss_mdns4_la_CFLAGS=$(libnss_mdns_la_CFLAGS) -DNSS_IPV4_ONLY=1
libnss_mdns4_la_LDFLAGS=$(libnss_mdns_la_LDFLAGS)

libnss_mdns4_minimal_la_SOURCES=$(libnss_mdns_la_SOURCES)
libnss_mdns4_minimal_la_CFLAGS=$(libnss_mdns_la_CFLAGS) -DNSS_IPV4_ONLY=1 -DMDNS_MINIMAL
libnss_mdns4_minimal_la_LDFLAGS=$(libnss_mdns_la_LDFLAGS)

libnss_mdns6_la_SOURCES=$(libnss_mdns_la_SOURCES)
libnss_mdns6_la_CFLAGS=$(libnss_mdns_la_CFLAGS) -DNSS_IPV6_ONLY=1
libnss_mdns6_la_LDFLAGS=$(libnss_mdns_la_LDFLAGS)

libnss_mdns6_minimal_la_SOURCES=$(libnss_mdns_la_SOURCES)
libnss_mdns6_minimal_la_CFLAGS=$(libnss_mdns_la_CFLAGS) -DNSS_IPV6_ONLY=1 -DMDNS_MINIMAL
libnss_mdns6_minimal_la_LDFLAGS=$(libnss_mdns_la_LDFLAGS)

avahi_test_SOURCES = \
	avahi.c avahi.h \
	util.c util.h \
	avahi-test.c

nss_test_SOURCES = \
	nss-test.c

install-exec-hook:
	rm -f $(DESTDIR)$(libdir)/libnss_mdns.la
	rm -f $(DESTDIR)$(libdir)/libnss_mdns_minimal.la
	rm -f $(DESTDIR)$(libdir)/libnss_mdns4.la
	rm -f $(DESTDIR)$(libdir)/libnss_mdns4_minimal.la
	rm -f $(DESTDIR)$(libdir)/libnss_mdns6.la
	rm -f $(DESTDIR)$(libdir)/libnss_mdns6_minimal.la

uninstall-hook:
	rm -f $(DESTDIR)$(libdir)/libnss_mdns.so.2
	rm -f $(DESTDIR)$(libdir)/libnss_mdns_minimal.so.2
	rm -f $(DESTDIR)$(libdir)/libnss_mdns4.so.2
	rm -f $(DESTDIR)$(libdir)/libnss_mdns4_minimal.so.2
	rm -f $(DESTDIR)$(libdir)/libnss_mdns6.so.2
	rm -f $(DESTDIR)$(libdir)/libnss_mdns6_minimal.so.2
