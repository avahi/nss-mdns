Name: nss-mdns
Version: 0.15.1
Release: %autorelease
Summary: glibc plugin for .local name resolution

License: LGPL-2.1+
URL: https://github.com/avahi/nss-mdns
Source0: %{url}/releases/download/v%{version}/%{name}-%{version}.tar.gz

BuildRequires: make
BuildRequires: gcc
BuildRequires: pkgconfig(check)
BuildRequires: autoconf
BuildRequires: automake
BuildRequires: libtool
Requires: avahi
Requires(preun,posttrans): authselect

%description
nss-mdns is a plugin for the GNU Name Service Switch (NSS) functionality of
the GNU C Library (glibc) providing host name resolution via Multicast DNS
(aka Zeroconf, aka Apple Rendezvous, aka Apple Bonjour), effectively allowing
name resolution by common Unix/Linux programs in the ad-hoc mDNS domain .local.

nss-mdns provides client functionality only, which means that you have to
run a mDNS responder daemon separately from nss-mdns if you want to register
the local host name via mDNS (e.g. Avahi).


%prep
%autosetup -p1

%build
autoreconf -fiv
%configure
%make_build

%check
%make_build check || (R=$?; cat ./test-suite.log; exit $R)

%install
%make_install


%posttrans
authselect enable-feature with-mdns4 > /dev/null || :

%preun
authselect disable-feature with-mdns4 > /dev/null || :

%{?ldconfig_scriptlets}


%files
%license LICENSE
%doc README.md NEWS.md ACKNOWLEDGEMENTS.md
%{_libdir}/libnss_mdns*.so.2*


%changelog
%autochangelog
