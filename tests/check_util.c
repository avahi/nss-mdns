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

#include <check.h>
#include <stdlib.h>
#include "../src/util.h"

// Tests that verify_name_allowed works in MINIMAL mode.
// Only names with TLD "local" are allowed.
START_TEST(test_verify_name_minimal) {
    // Positive results.
    ck_assert(verify_name_allowed("foo.local", NULL));
    ck_assert(verify_name_allowed("foo.local.", NULL));

    // Negative results.
    ck_assert(!verify_name_allowed("foo.com", NULL));
    ck_assert(!verify_name_allowed("foo.com.", NULL));

    ck_assert(!verify_name_allowed("foo.local.com", NULL));
    ck_assert(!verify_name_allowed("foo.local.com.", NULL));

    ck_assert(!verify_name_allowed("", NULL));
    ck_assert(!verify_name_allowed(".", NULL));
}
END_TEST


// Boilerplate from https://libcheck.github.io/check/doc/check_html/check_3.html
static Suite *util_suite(void) {
    Suite *s;
    TCase *tc_core;

    s = suite_create("util");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_verify_name_minimal);
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
