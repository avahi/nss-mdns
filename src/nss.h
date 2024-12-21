#ifndef src_nss_h
#define src_nss_h

/*
  nss-mdns is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, see <https://www.gnu.org/licenses/>.

SPDX-License-Identifier: LGPL-2.1-or-later
*/

#if defined(NSS_IPV4_ONLY) && !defined(MDNS_MINIMAL)
#define _nss_mdns_gethostbyname4_r _nss_mdns4_gethostbyname4_r
#define _nss_mdns_gethostbyname3_r _nss_mdns4_gethostbyname3_r
#define _nss_mdns_gethostbyname2_r _nss_mdns4_gethostbyname2_r
#define _nss_mdns_gethostbyname_r _nss_mdns4_gethostbyname_r
#define _nss_mdns_gethostbyaddr_r _nss_mdns4_gethostbyaddr_r
#elif defined(NSS_IPV4_ONLY) && defined(MDNS_MINIMAL)
#define _nss_mdns_gethostbyname4_r _nss_mdns4_minimal_gethostbyname4_r
#define _nss_mdns_gethostbyname3_r _nss_mdns4_minimal_gethostbyname3_r
#define _nss_mdns_gethostbyname2_r _nss_mdns4_minimal_gethostbyname2_r
#define _nss_mdns_gethostbyname_r _nss_mdns4_minimal_gethostbyname_r
#define _nss_mdns_gethostbyaddr_r _nss_mdns4_minimal_gethostbyaddr_r
#elif defined(NSS_IPV6_ONLY) && !defined(MDNS_MINIMAL)
#define _nss_mdns_gethostbyname4_r _nss_mdns6_gethostbyname4_r
#define _nss_mdns_gethostbyname3_r _nss_mdns6_gethostbyname3_r
#define _nss_mdns_gethostbyname2_r _nss_mdns6_gethostbyname2_r
#define _nss_mdns_gethostbyname_r _nss_mdns6_gethostbyname_r
#define _nss_mdns_gethostbyaddr_r _nss_mdns6_gethostbyaddr_r
#elif defined(NSS_IPV6_ONLY) && defined(MDNS_MINIMAL)
#define _nss_mdns_gethostbyname4_r _nss_mdns6_minimal_gethostbyname4_r
#define _nss_mdns_gethostbyname3_r _nss_mdns6_minimal_gethostbyname3_r
#define _nss_mdns_gethostbyname2_r _nss_mdns6_minimal_gethostbyname2_r
#define _nss_mdns_gethostbyname_r _nss_mdns6_minimal_gethostbyname_r
#define _nss_mdns_gethostbyaddr_r _nss_mdns6_minimal_gethostbyaddr_r
#elif defined(MDNS_MINIMAL)
#define _nss_mdns_gethostbyname4_r _nss_mdns_minimal_gethostbyname4_r
#define _nss_mdns_gethostbyname3_r _nss_mdns_minimal_gethostbyname3_r
#define _nss_mdns_gethostbyname2_r _nss_mdns_minimal_gethostbyname2_r
#define _nss_mdns_gethostbyname_r _nss_mdns_minimal_gethostbyname_r
#define _nss_mdns_gethostbyaddr_r _nss_mdns_minimal_gethostbyaddr_r
#endif

// Define prototypes for nss function we're going to export (fixes GCC warnings)
#ifndef __FreeBSD__
enum nss_status _nss_mdns_gethostbyname4_r(const char*, struct gaih_addrtuple**,
                                           char*, size_t, int*, int*, int32_t*);
#endif
enum nss_status _nss_mdns_gethostbyname3_r(const char*, int, struct hostent*,
                                           char*, size_t, int*, int*, int32_t*,
                                           char**);
enum nss_status _nss_mdns_gethostbyname2_r(const char*, int, struct hostent*,
                                           char*, size_t, int*, int*);
enum nss_status _nss_mdns_gethostbyname_r(const char*, struct hostent*, char*,
                                          size_t, int*, int*);
enum nss_status _nss_mdns_gethostbyaddr_r(const void*, int, int,
                                          struct hostent*, char*, size_t, int*,
                                          int*);

typedef struct {
    int minimal;
    int ipv4_only;
    int ipv6_only;
} nss_mdns_config_t;

#endif
