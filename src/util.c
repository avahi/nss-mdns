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
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <fcntl.h>

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
