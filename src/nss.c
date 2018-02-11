/*
  This file is part of nss-mdns.

  nss-mdns is free software; you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as published
  by the Free Software Foundation; either version 2 of the License,
  or (at your option) any later version.

  nss-mdns is distributed in the hope that it will be useful, but1
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with nss-mdns; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <netdb.h>
#include <sys/socket.h>
#include <nss.h>
#include <stdio.h>
#include <stdlib.h>

#include "avahi.h"
#include "util.h"

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
enum nss_status _nss_mdns_gethostbyname4_r(const char*, struct gaih_addrtuple**, char*, size_t, int*, int*, int32_t*);
enum nss_status _nss_mdns_gethostbyname3_r(const char*, int, struct hostent*, char*, size_t, int*, int*, int32_t*, char**);
enum nss_status _nss_mdns_gethostbyname2_r(const char*, int, struct hostent*, char*, size_t, int*, int*);
enum nss_status _nss_mdns_gethostbyname_r(const char*, struct hostent*, char*, size_t, int*, int*);
enum nss_status _nss_mdns_gethostbyaddr_r(const void*, int, int, struct hostent*, char*, size_t, int*, int*);

static void address_callback(const query_address_result_t* result, void* userdata) {
    userdata_t* u = userdata;
    assert(result && u);

    if (u->count >= MAX_ENTRIES)
        return;

    memcpy(&(u->data.result[u->count]), result, sizeof(*result));
    u->data_len += sizeof(*result);
    u->count++;
}

static void name_callback(const char* name, void* userdata) {
    userdata_t* u = userdata;
    assert(name && userdata);

    if (u->count >= MAX_ENTRIES)
        return;

    u->data.name[u->count++] = strdup(name);
    u->data_len += strlen(name) + 1;
}

static int do_avahi_resolve_name(int af, const char* name, void* userdata, int* avahi_works) {
    query_address_result_t address_result;
    int r;
    int found = 0;

    if (af == AF_INET || af == AF_UNSPEC) {
        if ((r = avahi_resolve_name(AF_INET, name, &address_result)) < 0) {
            /* Lookup failed */
            *avahi_works = 0;
        } else if (r == 0) {
            /* Lookup succeeded */
            address_callback(&address_result, userdata);
            found = 1;
        }
    }

    if (af == AF_INET6 || af == AF_UNSPEC) {
        if ((r = avahi_resolve_name(AF_INET6, name, &address_result)) < 0) {
            /* Lookup failed */
            *avahi_works = 0;
        } else if (r == 0) {
            /* Lookup succeeded */
            address_callback(&address_result, userdata);
            found = 1;
        }
    }

    return found;
}

static enum nss_status gethostbyname_impl(
    const char* name, int af,
    userdata_t* u,
    int* errnop,
    int* h_errnop) {

    enum nss_status status = NSS_STATUS_UNAVAIL;

    int avahi_works = 1;
    int name_allowed;
    FILE* mdns_allow_file = NULL;

#ifdef NSS_IPV4_ONLY
    if (af == AF_UNSPEC) {
        af = AF_INET;
    }
#endif

#ifdef NSS_IPV6_ONLY
    if (af == AF_UNSPEC) {
        af = AF_INET6;
    }
#endif

#ifdef NSS_IPV4_ONLY
    if (af != AF_INET)
#elif NSS_IPV6_ONLY
    if (af != AF_INET6)
#else
    if (af != AF_INET && af != AF_INET6 && af != AF_UNSPEC)
#endif
    {
        *errnop = EINVAL;
        *h_errnop = NO_RECOVERY;

        return status;
    }

    u->count = 0;
    u->data_len = 0;

#ifndef MDNS_MINIMAL
    mdns_allow_file = fopen(MDNS_ALLOW_FILE, "r");
#endif
    name_allowed = verify_name_allowed_with_soa(name, mdns_allow_file);
#ifndef MDNS_MINIMAL
    if (mdns_allow_file)
        fclose(mdns_allow_file);
#endif

    if (avahi_works && name_allowed) {
        if (!do_avahi_resolve_name(af, name, u, &avahi_works)) {
            status = NSS_STATUS_NOTFOUND;
        }
    }

    if (u->count == 0) {
        *errnop = ETIMEDOUT;
        *h_errnop = HOST_NOT_FOUND;
        return status;
    }

    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_mdns_gethostbyname4_r(
    const char* name,
    struct gaih_addrtuple** pat,
    char* buffer, size_t buflen,
    int* errnop, int* h_errnop,
    int32_t* ttlp) {

    userdata_t u;

    enum nss_status status = gethostbyname_impl(name, AF_UNSPEC, &u, errnop, h_errnop);
    if (status != NSS_STATUS_SUCCESS) {
        return status;
    }
    return convert_userdata_to_addrtuple(&u, name, pat, buffer, buflen,
                                         errnop, h_errnop);
}

enum nss_status _nss_mdns_gethostbyname3_r(
    const char* name,
    int af,
    struct hostent* result,
    char* buffer, size_t buflen,
    int* errnop, int* h_errnop,
    int32_t* ttlp,
    char** canonp) {

    userdata_t u;

    // The interfaces for gethostbyname3_r and below do not actually support returning results
    // for more than one address family
    if (af == AF_UNSPEC) {
#ifdef NSS_IPV6_ONLY
        af = AF_INET6;
#else
        af = AF_INET;
#endif
    }

    enum nss_status status = gethostbyname_impl(name, af, &u, errnop, h_errnop);
    if (status != NSS_STATUS_SUCCESS) {
        return status;
    }
    return convert_userdata_for_name_to_hostent(&u, name, af, result, buffer,
                                                buflen, errnop, h_errnop);
}

enum nss_status _nss_mdns_gethostbyname2_r(
    const char* name,
    int af,
    struct hostent* result,
    char* buffer, size_t buflen,
    int* errnop, int* h_errnop) {

    return _nss_mdns_gethostbyname3_r(
        name,
        af,
        result,
        buffer, buflen,
        errnop, h_errnop,
        NULL, NULL);
}

enum nss_status _nss_mdns_gethostbyname_r(
    const char* name,
    struct hostent* result,
    char* buffer,
    size_t buflen,
    int* errnop,
    int* h_errnop) {

    return _nss_mdns_gethostbyname2_r(
        name,
        AF_UNSPEC,
        result,
        buffer,
        buflen,
        errnop,
        h_errnop);
}

enum nss_status _nss_mdns_gethostbyaddr_r(
    const void* addr,
    int len,
    int af,
    struct hostent* result,
    char* buffer,
    size_t buflen,
    int* errnop,
    int* h_errnop) {

    userdata_t u;
    int r;
    size_t address_length;
    char t[256];
    *errnop = EINVAL;
    *h_errnop = NO_RECOVERY;

    u.count = 0;
    u.data_len = 0;

    /* Check for address types */
    address_length = af == AF_INET ? sizeof(ipv4_address_t) : sizeof(ipv6_address_t);

    if (len < (int)address_length ||
#ifdef NSS_IPV4_ONLY
        af != AF_INET
#elif NSS_IPV6_ONLY
        af != AF_INET6
#else
        (af != AF_INET && af != AF_INET6)
#endif
    ) {
        *errnop = EINVAL;
        *h_errnop = NO_RECOVERY;
        return NSS_STATUS_UNAVAIL;
    }

#ifdef MDNS_MINIMAL
    /* Only query for 169.254.0.0/16 IPv4 in minimal mode */
    if ((af == AF_INET && ((ntohl(*(const uint32_t*)addr) & 0xFFFF0000UL) != 0xA9FE0000UL)) ||
        (af == AF_INET6 && !(((const uint8_t*)addr)[0] == 0xFE && (((const uint8_t*)addr)[1] >> 6) == 2))) {

        *errnop = EINVAL;
        *h_errnop = NO_RECOVERY;
        return NSS_STATUS_UNAVAIL;
    }
#endif

    /* Lookup using Avahi */
    if ((r = avahi_resolve_address(af, addr, t, sizeof(t))) == 0) {
        name_callback(t, &u);
    } else if (r > 0) {
        *errnop = ETIMEDOUT;
        *h_errnop = HOST_NOT_FOUND;
        return NSS_STATUS_NOTFOUND;
    }

    return convert_userdata_for_addr_to_hostent(&u, addr, address_length, af, result,
                                                buffer, buflen, errnop, h_errnop);
}
