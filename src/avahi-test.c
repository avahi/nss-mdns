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

#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>

#include "avahi.h"

int main(int argc, char* argv[]) {
    query_address_result_t result;
    char t[256];
    int r;

    if ((r = avahi_resolve_name(AF_INET, argc >= 2 ? argv[1] : "cocaine.local",
                                &result)) == 0)
        printf("AF_INET: %s\n",
               inet_ntop(AF_INET, &(result.address.ipv4), t, sizeof(t)));
    else
        printf("AF_INET: failed (%i).\n", r);

    if ((r = avahi_resolve_name(AF_UNSPEC, argc >= 2 ? argv[1] : "cocaine.local",
                                &result)) == 0)
        printf("AF_UNSPEC: %s\n",
               inet_ntop(result.af, &result.address, t, sizeof(t)));
    else
        printf("AF_UNSPEC: failed (%i).\n", r);

    if ((r = avahi_resolve_address(AF_INET, &(result.address.ipv4), t,
                                   sizeof(t))) == 0)
        printf("REVERSE: %s\n", t);
    else
        printf("REVERSE: failed (%i).\n", r);

    if ((r = avahi_resolve_name(AF_INET6, argc >= 2 ? argv[1] : "cocaine.local",
                                &result)) == 0)
        printf("AF_INET6: %s\n",
               inet_ntop(AF_INET6, &(result.address.ipv6), t, sizeof(t)));
    else
        printf("AF_INET6: failed (%i).\n", r);

    return 0;
}
