/*
  This file is part of nss-mdns.

  nss-mdns is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as
  published by the Free Software Foundation; either version 2 of the
  License, or (at your option) any later version.

  nss-mdns is distributed in the hope that it will be useful, but
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

#include <sys/select.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <fcntl.h>
#include <netdb.h>

#include "util.h"

int set_cloexec(int fd) {
    int n;
    assert(fd >= 0);

    if ((n = fcntl(fd, F_GETFD)) < 0)
        return -1;

    if (n & FD_CLOEXEC)
        return 0;

    return fcntl(fd, F_SETFD, n | FD_CLOEXEC);
}

int ends_with(const char* name, const char* suffix) {
    size_t ln, ls;
    assert(name);
    assert(suffix);

    if ((ls = strlen(suffix)) > (ln = strlen(name)))
        return 0;

    return strcasecmp(name + ln - ls, suffix) == 0;
}

int verify_name_allowed_with_soa(const char* name, FILE* mdns_allow_file) {
    switch (verify_name_allowed(name, mdns_allow_file)) {
    case VERIFY_NAME_RESULT_NOT_ALLOWED:
        return 0;
    case VERIFY_NAME_RESULT_ALLOWED:
        return 1;
    case VERIFY_NAME_RESULT_ALLOWED_IF_NO_LOCAL_SOA:
        return !local_soa();
    default:
        return 0;
    }
}

enum verify_name_result verify_name_allowed(const char* name,
                                            FILE* mdns_allow_file) {
    assert(name);

    if (mdns_allow_file) {
        int valid = 0;

        while (!feof(mdns_allow_file)) {
            char ln[128], ln2[128], *t;

            if (!fgets(ln, sizeof(ln), mdns_allow_file))
                break;

            ln[strcspn(ln, "#\t\n\r ")] = 0;

            if (ln[0] == 0)
                continue;

            if (strcmp(ln, "*") == 0) {
                valid = 1;
                break;
            }

            if (ln[0] != '.')
                snprintf(t = ln2, sizeof(ln2), ".%s", ln);
            else
                t = ln;

            if (ends_with(name, t)) {
                valid = 1;
                break;
            }
        }
        if (valid)
            return VERIFY_NAME_RESULT_ALLOWED;
        else
            return VERIFY_NAME_RESULT_NOT_ALLOWED;
    } else {
        if ((ends_with(name, ".local") || ends_with(name, ".local.")) &&
            (label_count(name) == 2))
            return VERIFY_NAME_RESULT_ALLOWED_IF_NO_LOCAL_SOA;
        else
            return VERIFY_NAME_RESULT_NOT_ALLOWED;
    }
}

int local_soa(void) {
    struct __res_state state;
    int result;
    unsigned char answer[NS_MAXMSG];

    result = res_ninit(&state);
    if (result == -1)
        return 0;
    result = res_nquery(&state, "local", ns_c_in, ns_t_soa,
                        answer, sizeof answer);
    res_nclose(&state);
    return result > 0;
}

int label_count(const char* name) {
    // Start with single label.
    int count = 1;
    size_t i, len;
    assert(name);

    len = strlen(name);
    // Count all dots not in the last place.
    for (i = 0; i < len; i++) {
        if ((name[i] == '.') && (i != (len - 1)))
            count++;
    }

    return count;
}

// Converts from the userdata struct into the hostent format, used by
// gethostbyaddr_r.
enum nss_status convert_userdata_for_addr_to_hostent(const userdata_t* u,
                                                     const void* addr, int len,
                                                     int af,
                                                     struct hostent* result,
                                                     char* buffer, size_t buflen,
                                                     int* errnop, int* h_errnop) {

    size_t idx, astart;

    if (u->count == 0) {
        *errnop = ETIMEDOUT;
        *h_errnop = NO_RECOVERY;
        return NSS_STATUS_UNAVAIL;
    }

    /* Check for buffer space */
    if (buflen <
        sizeof(char*) + /* alias names */
            len) {      /* address */

        *errnop = ERANGE;
        *h_errnop = NO_RECOVERY;
        return NSS_STATUS_TRYAGAIN;
    }

    /* Alias names, assuming buffer starts a nicely aligned offset */
    *((char**)buffer) = NULL;
    result->h_aliases = (char**)buffer;
    idx = sizeof(char*);

    assert(u->count > 0);
    assert(u->data.name[0]);

    if (buflen <
        strlen(u->data.name[0]) + 1 + /* official names */
            sizeof(char*) +           /* alias names */
            len +                     /* address */
            sizeof(void*) * 2 +       /* address list */
            sizeof(void*)) {          /* padding to get the alignment right */

        *errnop = ERANGE;
        *h_errnop = NO_RECOVERY;
        return NSS_STATUS_TRYAGAIN;
    }

    /* Official name */
    strcpy(buffer + idx, u->data.name[0]);
    result->h_name = buffer + idx;
    idx += strlen(u->data.name[0]) + 1;

    result->h_addrtype = af;
    result->h_length = len;

    /* Address */
    astart = idx;
    memcpy(buffer + astart, addr, len);
    idx += len;

    /* Address array, idx might not be at pointer alignment anymore, so we need
     * to ensure it is */
    ALIGN(idx);

    ((char**)(buffer + idx))[0] = buffer + astart;
    ((char**)(buffer + idx))[1] = NULL;
    result->h_addr_list = (char**)(buffer + idx);

    return NSS_STATUS_SUCCESS;
}

// Converts from the userdata struct into the hostent format, used by
// gethostbyaddr3_r.
enum nss_status convert_userdata_for_name_to_hostent(const userdata_t* u,
                                                     const char* name, int af,
                                                     struct hostent* result,
                                                     char* buffer, size_t buflen,
                                                     int* errnop, int* h_errnop) {

    int i;
    size_t address_length, idx, astart;

    if (buflen <
        sizeof(char*) +         // alias names
            strlen(name) + 1) { // official name

        *errnop = ERANGE;
        *h_errnop = NO_RECOVERY;
        return NSS_STATUS_TRYAGAIN;
    }

    address_length = (af == AF_INET ? sizeof(ipv4_address_t) : sizeof(ipv6_address_t));

    /* Alias names */
    *((char**)buffer) = NULL;
    result->h_aliases = (char**)buffer;
    idx = sizeof(char*);

    /* Official name */
    strcpy(buffer + idx, name);
    result->h_name = buffer + idx;
    idx += strlen(name) + 1;

    ALIGN(idx);

    result->h_addrtype = af;
    result->h_length = address_length;

    /* Check if there's enough space for the addresses */
    if (buflen < idx + u->data_len + sizeof(char*) * (u->count + 1) + sizeof(void*)) {
        *errnop = ERANGE;
        *h_errnop = NO_RECOVERY;
        return NSS_STATUS_TRYAGAIN;
    }

    /* Addresses */
    astart = idx;
    for (i = 0; i < u->count; i++) {
        memcpy(buffer + idx, &u->data.result[i].address, address_length);
        idx += address_length;
    }

    /* realign, whilst the address is a multiple of 32bits, we
     * frequently lose alignment for 64bit systems */
    ALIGN(idx);

    /* Address array address_length is always a multiple of 32bits */
    for (i = 0; i < u->count; i++) {
        ((char**)(buffer + idx))[i] = buffer + astart + address_length * i;
    }
    ((char**)(buffer + idx))[i] = NULL;
    result->h_addr_list = (char**)(buffer + idx);

    return NSS_STATUS_SUCCESS;
}

enum nss_status convert_userdata_to_addrtuple(const userdata_t* u,
                                              const char* name,
                                              struct gaih_addrtuple** pat,
                                              char* buffer, size_t buflen,
                                              int* errnop, int* h_errnop) {

    /* Check if there's enough space for the addresses */
    // strlen(name)+1                         - Host name string
    // sizeof(struct gaih_addrtuple)*u->count - All address result structures
    // 3*(1+u->count)                         - Theoretical alignment byte maximum
    if (buflen < (strlen(name) + 1 + sizeof(struct gaih_addrtuple) * u->count + 3 * (1 + u->count))) {
        *errnop = ERANGE;
        *h_errnop = NO_RECOVERY;
        return NSS_STATUS_TRYAGAIN;
    }

    size_t idx = 0;

    // Copy name to buffer (referenced in every result address tuple)
    char* buffer_name = buffer + idx;
    strcpy(buffer_name, name);
    idx += strlen(buffer_name) + 1;
    ALIGN(idx);

    struct gaih_addrtuple* tuple_prev = NULL;
    for (int i = 0; i < u->count; i++) {
        struct gaih_addrtuple* tuple;
        if (tuple_prev == NULL && *pat) {
            // The caller has provided a valid initial location in *pat,
            // so use that as the first result. Without this, nscd will
            // segfault because it assumes that the buffer is only used as
            // an overflow.
            // See
            // https://lists.freedesktop.org/archives/systemd-devel/2013-February/008606.html
            tuple = *pat;
        } else {
            // Allocate a new tuple from the buffer.
            tuple = (struct gaih_addrtuple*)(buffer + idx);
            idx += sizeof(*tuple);
            ALIGN(idx);
        }

        size_t address_length = sizeof(ipv4_address_t);
        if (u->data.result[i].af == AF_INET6) {
            address_length = sizeof(ipv6_address_t);
        }

        // Will be overwritten by next address assignment (if there is one)
        tuple->next = NULL;

        // Assign the (always same) name
        tuple->name = buffer_name;

        // Assign actual address family of address
        tuple->family = u->data.result[i].af;

        // Copy address
        memset(&(tuple->addr), 0, sizeof(tuple->addr));
        memcpy(&(tuple->addr), &(u->data.result[i].address), address_length);

        // Assign interface scope id
        tuple->scopeid = u->data.result[i].scopeid;

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
