/* $Id$ */

/***
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
***/

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

#if defined(NSS_IPV4_ONLY) && ! defined(MDNS_MINIMAL)
#define _nss_mdns_gethostbyname4_r _nss_mdns4_gethostbyname4_r
#define _nss_mdns_gethostbyname3_r _nss_mdns4_gethostbyname3_r
#define _nss_mdns_gethostbyname2_r _nss_mdns4_gethostbyname2_r
#define _nss_mdns_gethostbyname_r  _nss_mdns4_gethostbyname_r
#define _nss_mdns_gethostbyaddr_r  _nss_mdns4_gethostbyaddr_r
#elif defined(NSS_IPV4_ONLY) && defined(MDNS_MINIMAL)
#define _nss_mdns_gethostbyname4_r _nss_mdns4_minimal_gethostbyname4_r
#define _nss_mdns_gethostbyname3_r _nss_mdns4_minimal_gethostbyname3_r
#define _nss_mdns_gethostbyname2_r _nss_mdns4_minimal_gethostbyname2_r
#define _nss_mdns_gethostbyname_r  _nss_mdns4_minimal_gethostbyname_r
#define _nss_mdns_gethostbyaddr_r  _nss_mdns4_minimal_gethostbyaddr_r
#elif defined(NSS_IPV6_ONLY) && ! defined(MDNS_MINIMAL)
#define _nss_mdns_gethostbyname4_r _nss_mdns6_gethostbyname4_r
#define _nss_mdns_gethostbyname3_r _nss_mdns6_gethostbyname3_r
#define _nss_mdns_gethostbyname2_r _nss_mdns6_gethostbyname2_r
#define _nss_mdns_gethostbyname_r  _nss_mdns6_gethostbyname_r
#define _nss_mdns_gethostbyaddr_r  _nss_mdns6_gethostbyaddr_r
#elif defined(NSS_IPV6_ONLY) && defined(MDNS_MINIMAL)
#define _nss_mdns_gethostbyname4_r _nss_mdns6_minimal_gethostbyname4_r
#define _nss_mdns_gethostbyname3_r _nss_mdns6_minimal_gethostbyname3_r
#define _nss_mdns_gethostbyname2_r _nss_mdns6_minimal_gethostbyname2_r
#define _nss_mdns_gethostbyname_r  _nss_mdns6_minimal_gethostbyname_r
#define _nss_mdns_gethostbyaddr_r  _nss_mdns6_minimal_gethostbyaddr_r
#elif defined(MDNS_MINIMAL)
#define _nss_mdns_gethostbyname4_r _nss_mdns_minimal_gethostbyname4_r
#define _nss_mdns_gethostbyname3_r _nss_mdns_minimal_gethostbyname3_r
#define _nss_mdns_gethostbyname2_r _nss_mdns_minimal_gethostbyname2_r
#define _nss_mdns_gethostbyname_r  _nss_mdns_minimal_gethostbyname_r
#define _nss_mdns_gethostbyaddr_r  _nss_mdns_minimal_gethostbyaddr_r
#endif

// Define prototypes for nss function we're going to export (fixes GCC warnings)
enum nss_status _nss_mdns_gethostbyname4_r(const char*, struct gaih_addrtuple**, char*, size_t, int*, int*, int32_t*);
enum nss_status _nss_mdns_gethostbyname3_r(const char*, int, struct hostent*, char*, size_t, int*, int*, int32_t*, char**);
enum nss_status _nss_mdns_gethostbyname2_r(const char*, int, struct hostent*, char*, size_t, int*, int*);
enum nss_status _nss_mdns_gethostbyname_r (const char*, struct hostent*, char*, size_t, int*, int*);
enum nss_status _nss_mdns_gethostbyaddr_r (const void*, int, int, struct hostent*, char *, size_t, int *, int *);

/* Maximum number of entries to return */
#define MAX_ENTRIES 16

#define ALIGN(idx) do { \
  if (idx % sizeof(void*)) \
    idx += (sizeof(void*) - idx % sizeof(void*)); /* Align on word boundary */ \
} while(0)

struct userdata {
    int count;
    int data_len; /* only valid when doing reverse lookup */
    union  {
        query_address_result_t result[MAX_ENTRIES];
        char *name[MAX_ENTRIES];
    } data;
};

static void address_callback(const query_address_result_t *result, void *userdata) {
    struct userdata *u = (struct userdata*) userdata;
    assert(result && u);

    if (u->count >= MAX_ENTRIES)
        return;

    memcpy(&(u->data.result[u->count]), result, sizeof(*result));
    u->data_len += sizeof(*result);
    u->count++;
}

static void name_callback(const char*name, void *userdata) {
    struct userdata *u = userdata;
    assert(name && userdata);

    if (u->count >= MAX_ENTRIES)
        return;

    u->data.name[u->count++] = strdup(name);
    u->data_len += strlen(name)+1;
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
        const char *name, int af,
        struct userdata *u,
        int *errnop,
        int *h_errnop
    ) {

    enum nss_status status = NSS_STATUS_UNAVAIL;

    int avahi_works = 1;
    int name_allowed;
    FILE *mdns_allow_file = NULL;

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
        if(!do_avahi_resolve_name(af, name, u, &avahi_works)) {
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
        const char *name,
        struct gaih_addrtuple **pat,
        char *buffer, size_t buflen,
        int *errnop, int *h_errnop,
        int32_t *ttlp
    ) {

    int i;
    size_t idx;
    char *buffer_name;
    struct gaih_addrtuple *tuple_prev;
    struct userdata u;

    // Since populating the buffer works differently in `gethostbyname[23]?` than in
    // `gethostbyname4`, we delegate the actual information gathering to a subroutine.
    enum nss_status status = gethostbyname_impl(name, AF_UNSPEC, &u, errnop, h_errnop);
    if(status != NSS_STATUS_SUCCESS) {
        return status;
    }

    /* Check if there's enough space for the addresses */
    // strlen(name)+1                        - Host name string
    // sizeof(struct gaih_addrtuple)*u.count - All address result structures
    // 3*(1+u.count)                         - Theoretical alignment byte maximum
    if (buflen < (strlen(name)+1 + sizeof(struct gaih_addrtuple)*u.count + 3*(1+u.count))) {
        *errnop = ERANGE;
        *h_errnop = NO_RECOVERY;
        return NSS_STATUS_TRYAGAIN;
    }

    idx = 0;

    // Copy name to buffer (referenced in every result address tuple)
    buffer_name = buffer + idx;
    strcpy(buffer_name, name);
    idx += strlen(buffer_name) + 1;
    ALIGN(idx);

    tuple_prev = NULL;
    for (i = 0; i < u.count; i++) {
        struct gaih_addrtuple *tuple = (struct gaih_addrtuple*) (buffer+idx);

        size_t address_length = sizeof(ipv4_address_t);
        if(u.data.result[i].af == AF_INET6) {
            address_length = sizeof(ipv6_address_t);
        }

        // Will be overwritten by next address assignment (if there is one)
        tuple->next = NULL;

        // Assign the (always same) name
        tuple->name = buffer_name;

        // Assign actual address family of address
        tuple->family = u.data.result[i].af;

        // Copy address
        memset(&(tuple->addr), 0, sizeof(tuple->addr));
        memcpy(&(tuple->addr), &(u.data.result[i].address), address_length);

        // Assign interface scope id
        tuple->scopeid = u.data.result[i].scopeid;

        if (tuple_prev == NULL) {
            // This is the first tuple.

            // If the caller has provided a valid initial location in *pat,
            // then put a copy of the first result there as well. Without this,
            // nscd will segfault because it assumes that the buffer is only
            // used as an overflow.
            // See https://lists.freedesktop.org/archives/systemd-devel/2013-February/008606.html
            //
            // Unfortunately, it is probably not worth redoing all the buffer
            // allocation code above to remove this small duplication.
            if (*pat) {
                **pat = *tuple;
            }

            // Return the start of the list in *pat.
            *pat = tuple;
        } else {
            // Link the new tuple into the previous tuple.
            tuple_prev->next = tuple;
        }

        idx += sizeof(*tuple);
        ALIGN(idx);

        tuple_prev = tuple;
    }

    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_mdns_gethostbyname3_r(
        const char *name,
        int af,
        struct hostent *result,
        char *buffer, size_t buflen,
        int *errnop, int *h_errnop,
        int32_t *ttlp,
        char **canonp
    ) {

    int i;
    size_t address_length, idx, astart;

    struct userdata u;
    enum nss_status status;

    // The interfaces for gethostbyname3_r and below do not actually support returning results
    // for more than one address family
    if(af == AF_UNSPEC) {
#ifdef NSS_IPV6_ONLY
        af = AF_INET6;
#else
        af = AF_INET;
#endif
    }

    status = gethostbyname_impl(name, af, &u, errnop, h_errnop);
    if(status != NSS_STATUS_SUCCESS) {
        return status;
    }

    if (buflen <
        sizeof(char*)+    // alias names
        strlen(name)+1)  {   // official name

        *errnop = ERANGE;
        *h_errnop = NO_RECOVERY;
        return NSS_STATUS_TRYAGAIN;
    }
    
    address_length = (af == AF_INET ? sizeof(ipv4_address_t) : sizeof(ipv6_address_t));
    
    /* Alias names */
    *((char**) buffer) = NULL;
    result->h_aliases = (char**) buffer;
    idx = sizeof(char*);
    
    /* Official name */
    strcpy(buffer+idx, name); 
    result->h_name = buffer+idx;
    idx += strlen(name)+1;

    ALIGN(idx);
    
    result->h_addrtype = af;
    result->h_length = address_length;
    
    /* Check if there's enough space for the addresses */
    if (buflen < idx+u.data_len+sizeof(char*)*(u.count+1)+sizeof(void*)) {
        *errnop = ERANGE;
        *h_errnop = NO_RECOVERY;
        return NSS_STATUS_TRYAGAIN;
    }

    /* Addresses */
    astart = idx;
    for(i = 0; i < u.count; i++) {
        memcpy(buffer+idx, &u.data.result[i].address, address_length);
        idx += address_length;
    }

    /* realign, whilst the address is a multiple of 32bits, we
     * frequently lose alignment for 64bit systems */
    ALIGN(idx);

    /* Address array address_length is always a multiple of 32bits */
    for (i = 0; i < u.count; i++) {
        ((char**) (buffer+idx))[i] = buffer + astart + address_length*i;
    }
    ((char**) (buffer+idx))[i] = NULL;
    result->h_addr_list = (char**) (buffer+idx);

    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_mdns_gethostbyname2_r(
        const char *name,
        int af,
        struct hostent *result,
        char *buffer, size_t buflen,
        int *errnop, int *h_errnop
    ) {

    return _nss_mdns_gethostbyname3_r(
        name,
        af,
        result,
        buffer, buflen,
        errnop, h_errnop,
        NULL, NULL);
}

enum nss_status _nss_mdns_gethostbyname_r (
    const char *name,
    struct hostent *result,
    char *buffer,
    size_t buflen,
    int *errnop,
    int *h_errnop) {

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
    struct hostent *result,
    char *buffer,
    size_t buflen,
    int *errnop,
    int *h_errnop) {
    
    struct userdata u;
    enum nss_status status = NSS_STATUS_UNAVAIL;
    int r;
    size_t address_length, idx, astart;
    char t[256];
    *errnop = EINVAL;
    *h_errnop = NO_RECOVERY;

    u.count = 0;
    u.data_len = 0;

    /* Check for address types */
    address_length = af == AF_INET ? sizeof(ipv4_address_t) : sizeof(ipv6_address_t);

    if (len < (int) address_length ||
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

        goto finish;
    }

    /* Check for buffer space */
    if (buflen <
        sizeof(char*)+      /* alias names */
        address_length) {   /* address */
        
        *errnop = ERANGE;
        *h_errnop = NO_RECOVERY;
        status = NSS_STATUS_TRYAGAIN;

        goto finish;
    }

#ifdef MDNS_MINIMAL

    /* Only query for 169.254.0.0/16 IPv4 in minimal mode */
    if ((af == AF_INET && ((ntohl(*(const uint32_t*)  addr) & 0xFFFF0000UL) != 0xA9FE0000UL)) ||
        (af == AF_INET6 && !(((const uint8_t*) addr)[0] == 0xFE && (((const uint8_t*) addr)[1] >> 6) == 2))) {

        *errnop = EINVAL;
        *h_errnop = NO_RECOVERY;

        goto finish;
    }
#endif
    
    /* Lookup using Avahi */
    if ((r = avahi_resolve_address(af, addr, t, sizeof(t))) == 0) {
        name_callback(t, &u);
    } else if (r > 0) {
        *errnop = ETIMEDOUT;
        *h_errnop = HOST_NOT_FOUND;
        status = NSS_STATUS_NOTFOUND;
        goto finish;
    } 

    if (u.count == 0) {
        *errnop = ETIMEDOUT;
        *h_errnop = NO_RECOVERY;
        goto finish;
    }

    /* Alias names, assuming buffer starts a nicely aligned offset */
    *((char**) buffer) = NULL;
    result->h_aliases = (char**) buffer;
    idx = sizeof(char*);

    assert(u.count > 0);
    assert(u.data.name[0]);
    
    if (buflen <
        strlen(u.data.name[0])+1+ /* official names */
        sizeof(char*)+ /* alias names */
        address_length+  /* address */
        sizeof(void*)*2 + /* address list */
        sizeof(void*)) {  /* padding to get the alignment right */

        *errnop = ERANGE;
        *h_errnop = NO_RECOVERY;
        status = NSS_STATUS_TRYAGAIN;
        goto finish;
    }
    
    /* Official name */
    strcpy(buffer+idx, u.data.name[0]); 
    result->h_name = buffer+idx;
    idx += strlen(u.data.name[0])+1;
    
    result->h_addrtype = af;
    result->h_length = address_length;

    /* Address */
    astart = idx;
    memcpy(buffer+astart, addr, address_length);
    idx += address_length;

    /* Address array, idx might not be at pointer alignment anymore, so we need
     * to ensure it is*/
    ALIGN(idx);

    ((char**) (buffer+idx))[0] = buffer+astart;
    ((char**) (buffer+idx))[1] = NULL;
    result->h_addr_list = (char**) (buffer+idx);

    status = NSS_STATUS_SUCCESS;
    
finish:
    return status;
}
