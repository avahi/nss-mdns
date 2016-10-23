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
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
  USA.
***/

#define _POSIX_C_SOURCE 200809L

#include <check.h>
#include <stdlib.h>
#include <stdio.h>
#include "../src/util.h"

// Tests that verify_name_allowed works in MINIMAL mode, or with no config file.
// Only names with TLD "local" are allowed.
START_TEST(test_verify_name_allowed_minimal) {
    ck_assert(verify_name_allowed("example.local", NULL));
    ck_assert(verify_name_allowed("example.local.", NULL));
    ck_assert(verify_name_allowed("com.example.local", NULL));
    ck_assert(verify_name_allowed("com.example.local.", NULL));
    ck_assert(!verify_name_allowed("example.com", NULL));
    ck_assert(!verify_name_allowed("example.com.", NULL));
    ck_assert(!verify_name_allowed("example.local.com", NULL));
    ck_assert(!verify_name_allowed("example.local.com.", NULL));
    ck_assert(!verify_name_allowed("", NULL));
    ck_assert(!verify_name_allowed(".", NULL));
}
END_TEST


// Calls verify_name_allowed by first creating a memfile to read from.
static int verify_name_allowed_from_string(const char *name,
                                           const char *file_contents) {
    FILE *f = fmemopen((void *) file_contents, strlen(file_contents), "r");
    int result = verify_name_allowed(name, f);
    fclose(f);
    return result;
}

// Tests verify_name_allowed with empty config.
// Nothing is permitted.
START_TEST(test_verify_name_allowed_empty) {
    const char allow_file[] = "";

    ck_assert(!verify_name_allowed_from_string("example.local", allow_file));
    ck_assert(!verify_name_allowed_from_string("example.local.", allow_file));
    ck_assert(!verify_name_allowed_from_string("com.example.local", allow_file));
    ck_assert(!verify_name_allowed_from_string("com.example.local.",
                                               allow_file));
    ck_assert(!verify_name_allowed_from_string("example.com", allow_file));
    ck_assert(!verify_name_allowed_from_string("example.com.", allow_file));
    ck_assert(!verify_name_allowed_from_string("example.local.com",
                                               allow_file));
    ck_assert(!verify_name_allowed_from_string("example.local.com.",
                                               allow_file));
    ck_assert(!verify_name_allowed_from_string("", allow_file));
    ck_assert(!verify_name_allowed_from_string(".", allow_file));
}
END_TEST

// Tests verify_name_allowed with the standard config.
START_TEST(test_verify_name_allowed_default) {
    const char allow_file[] =
        "# /etc/mdns.allow\n"
        ".local.\n"
        ".local\n";

    ck_assert(verify_name_allowed_from_string("example.local", allow_file));
    ck_assert(verify_name_allowed_from_string("example.local.", allow_file));
    ck_assert(verify_name_allowed_from_string("com.example.local", allow_file));
    ck_assert(verify_name_allowed_from_string("com.example.local.", allow_file));
    ck_assert(!verify_name_allowed_from_string("example.com", allow_file));
    ck_assert(!verify_name_allowed_from_string("example.com.", allow_file));
    ck_assert(!verify_name_allowed_from_string("example.local.com",
                                               allow_file));
    ck_assert(!verify_name_allowed_from_string("example.local.com.",
                                               allow_file));
    ck_assert(!verify_name_allowed_from_string("", allow_file));
    ck_assert(!verify_name_allowed_from_string(".", allow_file));
}
END_TEST

// Tests verify_name_allowed with wildcard.
START_TEST(test_verify_name_allowed_wildcard) {
    const char allow_file[] = "*\n";

    ck_assert(verify_name_allowed_from_string("example.local", allow_file));
    ck_assert(verify_name_allowed_from_string("example.local.", allow_file));
    ck_assert(verify_name_allowed_from_string("com.example.local", allow_file));
    ck_assert(verify_name_allowed_from_string("com.example.local.", allow_file));
    ck_assert(verify_name_allowed_from_string("example.com", allow_file));
    ck_assert(verify_name_allowed_from_string("example.com.", allow_file));
    ck_assert(verify_name_allowed_from_string("example.local.com",
                                              allow_file));
    ck_assert(verify_name_allowed_from_string("example.local.com.",
                                              allow_file));
    ck_assert(verify_name_allowed_from_string("", allow_file));
    ck_assert(verify_name_allowed_from_string(".", allow_file));
}
END_TEST

// Tests verify_name_allowed with too-long lines.
START_TEST(test_verify_name_allowed_too_long) {
    const char allow_file[] =
        "# /etc/mdns.allow\n"
        ".local."
        "                                                  " // 50 spaces
        "                                                  " // 50 spaces
        "                                                  " // 50 spaces
        "\n"
        ".local\n";

    ck_assert(verify_name_allowed_from_string("example.local", allow_file));
    ck_assert(verify_name_allowed_from_string("example.local.", allow_file));
    ck_assert(verify_name_allowed_from_string("com.example.local", allow_file));
    ck_assert(verify_name_allowed_from_string("com.example.local.", allow_file));
    ck_assert(!verify_name_allowed_from_string("example.com", allow_file));
    ck_assert(!verify_name_allowed_from_string("example.com.", allow_file));
    ck_assert(!verify_name_allowed_from_string("example.local.com",
                                               allow_file));
    ck_assert(!verify_name_allowed_from_string("example.local.com.",
                                               allow_file));
    ck_assert(!verify_name_allowed_from_string("", allow_file));
    ck_assert(!verify_name_allowed_from_string(".", allow_file));
}
END_TEST

// Tests verify_name_allowed with too-long non-empty lines.
START_TEST(test_verify_name_allowed_too_long2) {
    const char allow_file[] =
        "# /etc/mdns.allow\n"
        ".aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 50 characters
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 50 characters
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 50 characters
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 50 characters
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 50 characters
        "\n"
        ".local.\n"
        ".local\n";

    // The input is truncated at 127 bytes, so we allow this string.
    ck_assert(verify_name_allowed_from_string(
        "example"
        ".aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 50 characters
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 50 characters
        "aaaaaaaaaaaaaaaaaaaaaaaaaaa",                       // 27 characters
        allow_file));

    // Even though this exactly matches the item in the allow file,
    // it is too long.
    ck_assert(!verify_name_allowed_from_string(
        "example"
        ".aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 50 characters
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 50 characters
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 50 characters
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 50 characters
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // 50 characters
        allow_file));

    ck_assert(verify_name_allowed_from_string("example.local", allow_file));
    ck_assert(verify_name_allowed_from_string("example.local.", allow_file));
    ck_assert(verify_name_allowed_from_string("com.example.local", allow_file));
    ck_assert(verify_name_allowed_from_string("com.example.local.", allow_file));
    ck_assert(!verify_name_allowed_from_string("example.com", allow_file));
    ck_assert(!verify_name_allowed_from_string("example.com.", allow_file));
    ck_assert(!verify_name_allowed_from_string("example.local.com",
                                               allow_file));
    ck_assert(!verify_name_allowed_from_string("example.local.com.",
                                               allow_file));
    ck_assert(!verify_name_allowed_from_string("", allow_file));
    ck_assert(!verify_name_allowed_from_string(".", allow_file));
}
END_TEST

// Tests verify_name_allowed with a custom config.
START_TEST(test_verify_name_allowed_com_and_local) {
    const char allow_file[] =
        "# /etc/mdns.allow\n"
        ".com.\n"
        ".com\n"
        ".local.\n"
        ".local\n";

    ck_assert(verify_name_allowed_from_string("example.local", allow_file));
    ck_assert(verify_name_allowed_from_string("example.local.", allow_file));
    ck_assert(verify_name_allowed_from_string("com.example.local", allow_file));
    ck_assert(verify_name_allowed_from_string("com.example.local.", allow_file));
    ck_assert(verify_name_allowed_from_string("example.com", allow_file));
    ck_assert(verify_name_allowed_from_string("example.com.", allow_file));
    ck_assert(verify_name_allowed_from_string("example.local.com",
                                              allow_file));
    ck_assert(verify_name_allowed_from_string("example.local.com.",
                                              allow_file));
    ck_assert(!verify_name_allowed_from_string("", allow_file));
    ck_assert(!verify_name_allowed_from_string(".", allow_file));
}
END_TEST

// Boilerplate from https://libcheck.github.io/check/doc/check_html/check_3.html
static Suite *util_suite(void) {
    Suite *s;
    TCase *tc_core;

    s = suite_create("util");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_verify_name_allowed_minimal);
    tcase_add_test(tc_core, test_verify_name_allowed_default);
    tcase_add_test(tc_core, test_verify_name_allowed_empty);
    tcase_add_test(tc_core, test_verify_name_allowed_wildcard);
    tcase_add_test(tc_core, test_verify_name_allowed_too_long);
    tcase_add_test(tc_core, test_verify_name_allowed_too_long2);
    tcase_add_test(tc_core, test_verify_name_allowed_com_and_local);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void) {
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = util_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
