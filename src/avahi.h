#ifndef fooavahihfoo
#define fooavahihfoo

/***
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
***/

#include <inttypes.h>
#include <sys/types.h>

typedef struct {
    uint32_t address;
} ipv4_address_t;

typedef struct {
    uint8_t address[16];
} ipv6_address_t;

typedef struct {
    int af;
    union {
        ipv4_address_t ipv4;
        ipv6_address_t ipv6;
    } address;
    uint32_t scopeid;
} query_address_result_t;

int avahi_resolve_name(int af, const char* name, query_address_result_t* result);

int avahi_resolve_address(int af, const void *data, char* name, size_t name_len);

#endif
