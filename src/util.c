/*
  This file is part of nss-mdns.

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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/select.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <fcntl.h>
#include <netdb.h>

#include "util.h"

typedef enum {
    LR_OK = 0,
    LR_BREAK,
    LR_CONTINUE,
} loop_result_t;

int set_cloexec(int fd) {
    int n;
    assert(fd >= 0);

    if ((n = fcntl(fd, F_GETFD)) < 0)
        return -1;

    if (n & FD_CLOEXEC)
        return 0;

    return fcntl(fd, F_SETFD, n | FD_CLOEXEC);
}

int ends_with(const char* name, size_t namelen,
                     const char* suffix, size_t slen) {
    assert(name);
    assert(suffix);

    if (slen > namelen)
        return 0;

    return strcasecmp(name + namelen - slen, suffix) == 0;
}

use_name_result_t verify_name_allowed_with_soa(const char* name,
                                               FILE* mdns_allow_file,
                                               userdata_t *u,
                                               test_local_soa_t test) {
    switch (verify_name_allowed(name, mdns_allow_file, u)) {
    case VERIFY_NAME_RESULT_NOT_ALLOWED:
        return USE_NAME_RESULT_SKIP;
    case VERIFY_NAME_RESULT_ALLOWED:
        return USE_NAME_RESULT_AUTHORITATIVE;
    case VERIFY_NAME_RESULT_ALLOWED_IF_NO_LOCAL_SOA:
	if (test == TEST_LOCAL_SOA_YES ||
	    (test == TEST_LOCAL_SOA_AUTO && local_soa()) )
		/* Make multicast resolution not authoritative for .local zone.
		 * Allow continuing to unicast resolution after multicast had not worked. */
		return USE_NAME_RESULT_OPTIONAL;
	else
		return USE_NAME_RESULT_AUTHORITATIVE;
    default:
        return USE_NAME_RESULT_SKIP;
    }
}

static verify_name_result_t verify_name_minimal(const char *name, size_t namelen) {
    if ((ends_with(name, namelen, ".local", 6) ||
         ends_with(name, namelen, ".local.", 7)) &&
        (label_count(name, namelen) == 2))
        return VERIFY_NAME_RESULT_ALLOWED_IF_NO_LOCAL_SOA;
    else
        return VERIFY_NAME_RESULT_NOT_ALLOWED;
}

static loop_result_t _verify_read_line(char *ln, size_t lnlen,
                         userdata_t *u,
                         FILE *file) {
    if (!fgets(ln, lnlen, file))
        return LR_BREAK;

    ln[strcspn(ln, "#\t\n\r ")] = 0;

    if (ln[0] == 0)
        return LR_CONTINUE;

    if (ln[0] == '%') {
        if (strcmp(ln, "%minimal") == 0)
            u->minimal = 1;
        /* If multiple statements are present, latest wins. */
        else if (strcmp(ln, "%ipv4") == 0)
            u->ipv4_only = 1;
        else if (strcmp(ln, "%ipv6") == 0)
            u->ipv6_only = 1;
        else if (strcmp(ln, "%any") == 0)
            u->ipv4_only = u->ipv6_only = 0;
        return LR_CONTINUE;
    }
    return LR_OK;
}

verify_name_result_t verify_name_allowed(const char* name,
                                         FILE* mdns_allow_file,
                                         userdata_t *u) {
    size_t namelen;

    assert(name);
    assert(u);
    namelen = strlen(name);

    if (mdns_allow_file) {
        int valid = 0;
        size_t slen;
        char ln[129];

        while (!feof(mdns_allow_file)) {
            loop_result_t r;

            r = _verify_read_line(ln, sizeof(ln)-1, u, mdns_allow_file);
            if (r == LR_BREAK)
                    break;
            else if (r == LR_CONTINUE)
                    continue;

            if (strcmp(ln, "*") == 0) {
                valid = 1;
                break;
            }

            slen = strlen(ln);
            if (ln[0] != '.')
                memmove(ln+1, ln, slen+1);

            if (ends_with(name, namelen, ln, slen)) {
                valid = 1;
                break;
            }
        }

        if (valid)
            return VERIFY_NAME_RESULT_ALLOWED;
        else if (u->minimal)
            return verify_name_minimal(name, namelen);
        else
            return VERIFY_NAME_RESULT_NOT_ALLOWED;
    } else {
        return verify_name_minimal(name, namelen);
    }
}

void userdata_config(FILE* mdns_allow_file, userdata_t *u) {
    loop_result_t r;
    char ln[128];
    while (!feof(mdns_allow_file)) {
        r = _verify_read_line(ln, sizeof(ln), u, mdns_allow_file);
        if (r == LR_BREAK)
            break;
    }
}


int local_soa(void) {
    /* FreeBSD requires the state to be zeroed before calling res_ninit() */
    struct __res_state state = {
        0,
    };
    int result;
    unsigned char answer[NS_MAXMSG];

    result = res_ninit(&state);
    if (result == -1)
        return 0;
    result =
        res_nquery(&state, "local", ns_c_in, ns_t_soa, answer, sizeof answer);
    res_nclose(&state);
    return result > 0;
}

int label_count(const char* name, size_t len) {
    // Start with single label.
    int count = 1;
    size_t i;
    assert(name);
    if (len > 0)
        len--;

    // Count all dots not in the last place.
    for (i = 0; i < len; i++) {
        if (name[i] == '.')
            count++;
    }

    return count;
}

enum nss_status convert_name_and_addr_to_hostent(const char* name,
                                                 const void* addr, int len,
                                                 int af, struct hostent* result,
                                                 buffer_t* buf, int* errnop,
                                                 int* h_errnop) {
    // Set empty list of aliases.
    result->h_aliases = (char**)buffer_alloc(buf, sizeof(char**));
    RETURN_IF_FAILED_ALLOC(result->h_aliases);

    // Set official name.
    result->h_name = buffer_strdup(buf, name);
    RETURN_IF_FAILED_ALLOC(result->h_name);

    // Set addrtype and length.
    result->h_addrtype = af;
    result->h_length = len;

    // Initialize address list of length 1, NULL terminated.
    result->h_addr_list = buffer_alloc(buf, 2 * sizeof(char**));
    RETURN_IF_FAILED_ALLOC(result->h_addr_list);

    // Copy the address.
    result->h_addr_list[0] = buffer_alloc(buf, len);
    RETURN_IF_FAILED_ALLOC(result->h_addr_list[0]);
    memcpy(result->h_addr_list[0], addr, len);

    return NSS_STATUS_SUCCESS;
}

enum nss_status convert_userdata_for_name_to_hostent(const userdata_t* u,
                                                     const char* name, int af,
                                                     struct hostent* result,
                                                     buffer_t* buf, int* errnop,
                                                     int* h_errnop) {
    size_t address_length =
        af == AF_INET ? sizeof(ipv4_address_t) : sizeof(ipv6_address_t);

    // Set empty list of aliases.
    result->h_aliases = (char**)buffer_alloc(buf, sizeof(char**));
    RETURN_IF_FAILED_ALLOC(result->h_aliases);

    // Set official name.
    result->h_name = buffer_strdup(buf, name);
    RETURN_IF_FAILED_ALLOC(result->h_name);

    // Set addrtype and length.
    result->h_addrtype = af;
    result->h_length = address_length;

    // Initialize address list, NULL terminated.
    result->h_addr_list = buffer_alloc(buf, (u->count + 1) * sizeof(char**));
    RETURN_IF_FAILED_ALLOC(result->h_addr_list);

    // Copy the addresses.
    for (int i = 0; i < u->count; i++) {
        char* addr = buffer_alloc(buf, address_length);
        RETURN_IF_FAILED_ALLOC(addr);
        memcpy(addr, &u->result[i].address, address_length);
        result->h_addr_list[i] = addr;
    }

    return NSS_STATUS_SUCCESS;
}

#ifndef __FreeBSD__
enum nss_status convert_userdata_to_addrtuple(const userdata_t* u,
                                              const char* name,
                                              struct gaih_addrtuple** pat,
                                              buffer_t* buf, int* errnop,
                                              int* h_errnop) {

    // Copy name to buffer (referenced in every result address tuple).
    char* buffer_name = buffer_strdup(buf, name);
    RETURN_IF_FAILED_ALLOC(buffer_name);

    struct gaih_addrtuple* tuple_prev = NULL;
    for (int i = 0; i < u->count; i++) {
        const query_address_result_t* result = &u->result[i];
        struct gaih_addrtuple* tuple;
        if (tuple_prev == NULL && *pat) {
            // The caller has provided a valid initial location in *pat,
            // so use that as the first result. Without this, nscd will
            // segfault because it assumes that the buffer is only used as
            // an overflow.
            // See
            // https://lists.freedesktop.org/archives/systemd-devel/2013-February/008606.html
            tuple = *pat;
            memset(tuple, 0, sizeof(*tuple));
        } else {
            // Allocate a new tuple from the buffer.
            tuple = buffer_alloc(buf, sizeof(struct gaih_addrtuple));
            RETURN_IF_FAILED_ALLOC(tuple);
        }

        size_t address_length = result->af == AF_INET ? sizeof(ipv4_address_t)
                                                      : sizeof(ipv6_address_t);

        // Assign the (always same) name.
        tuple->name = buffer_name;

        // Assign actual address family of address.
        tuple->family = result->af;

        // Copy address.
        memcpy(&(tuple->addr), &(result->address), address_length);

        // Assign interface scope id
        tuple->scopeid = result->scopeid;

        if (tuple_prev == NULL) {
            // This is the first tuple.
            // Return the start of the list in *pat.
            *pat = tuple;
        } else {
            // Link the new tuple into the previous tuple.
            tuple_prev->next = tuple;
        }

        tuple_prev = tuple;
    }

    return NSS_STATUS_SUCCESS;
}
#endif

static char* aligned_ptr(char* p) {
    uintptr_t ptr = (uintptr_t)p;
    if (ptr % sizeof(void*)) {
        p += sizeof(void*) - (ptr % sizeof(void*));
    }
    return p;
}

void buffer_init(buffer_t* buf, char* buffer, size_t buflen) {
    // next always points to an aligned location.
    buf->next = aligned_ptr(buffer);
    // end is one past the buffer.
    buf->end = buffer + buflen;
}

void* buffer_alloc(buffer_t* buf, size_t size) {
    // Zero-length allocations always succeed with non-NULL.
    if (size == 0) {
        return buf; // Just a convenient non-NULL pointer.
    }

    char* alloc_end = buf->next + size;
    if (alloc_end > buf->end) {
        // No more memory in the buffer.
        return NULL;
    }

    // We have enough space. Set up the next aligned pointer and return
    // the current one, zeroed.
    char* current = buf->next;
    buf->next = aligned_ptr(alloc_end);
    memset(current, 0, size);
    return current;
}

char* buffer_strdup(buffer_t* buf, const char* str) {
    char* result = buffer_alloc(buf, strlen(str) + 1);
    if (result == NULL) {
        return NULL;
    }
    strcpy(result, str);
    return result;
}

void append_address_to_userdata(const query_address_result_t* result,
                                userdata_t* u) {
    assert(result && u);

    if (u->count >= MAX_ENTRIES)
        return;

    memcpy(&(u->result[u->count]), result, sizeof(*result));
    u->count++;
}

/** Initializes defaults from build-time defines.
 *
 * It set minimal from libnss_mdns_minimal plugin etc.
 */
void userdata_init(userdata_t *u) {
    memset(u, 0, sizeof(*u));
#ifdef NSS_IPV4_ONLY
    u->ipv4_only = 1;
#endif
#if NSS_IPV6_ONLY
    u->ipv6_only = 1;
#endif
#ifdef MDNS_MINIMAL
    u->minimal = 1;
#endif
}

