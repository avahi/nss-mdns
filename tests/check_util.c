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

#define _DEFAULT_SOURCE

#include <check.h>
#include <stdlib.h>
#include <stdio.h>
#include "../src/util.h"

// Tests that verify_name_allowed works in MINIMAL mode, or with no config file.
// Only names with TLD "local" are allowed.
// Only 2-label names are allowed.
// SOA check is required.
START_TEST(test_verify_name_allowed_minimal) {
    ck_assert_int_eq(verify_name_allowed("example.local", NULL),
                     VERIFY_NAME_RESULT_ALLOWED_IF_NO_LOCAL_SOA);
    ck_assert_int_eq(verify_name_allowed("example.local.", NULL),
                     VERIFY_NAME_RESULT_ALLOWED_IF_NO_LOCAL_SOA);
    ck_assert_int_eq(verify_name_allowed("com.example.local", NULL),
                     VERIFY_NAME_RESULT_NOT_ALLOWED);
    ck_assert_int_eq(verify_name_allowed("com.example.local.", NULL),
                     VERIFY_NAME_RESULT_NOT_ALLOWED);
    ck_assert_int_eq(verify_name_allowed("example.com", NULL),
                     VERIFY_NAME_RESULT_NOT_ALLOWED);
    ck_assert_int_eq(verify_name_allowed("example.com.", NULL),
                     VERIFY_NAME_RESULT_NOT_ALLOWED);
    ck_assert_int_eq(verify_name_allowed("example.local.com", NULL),
                     VERIFY_NAME_RESULT_NOT_ALLOWED);
    ck_assert_int_eq(verify_name_allowed("example.local.com.", NULL),
                     VERIFY_NAME_RESULT_NOT_ALLOWED);
    ck_assert_int_eq(verify_name_allowed("", NULL),
                     VERIFY_NAME_RESULT_NOT_ALLOWED);
    ck_assert_int_eq(verify_name_allowed(".", NULL),
                     VERIFY_NAME_RESULT_NOT_ALLOWED);
}
END_TEST

// Calls verify_name_allowed by first creating a memfile to read from.
static int verify_name_allowed_from_string(const char* name,
                                           const char* file_contents) {
    FILE* f = fmemopen((void*)file_contents, strlen(file_contents), "r");
    int result = verify_name_allowed(name, f);
    fclose(f);
    return result;
}

// Tests verify_name_allowed with empty config.
// Nothing is permitted.
START_TEST(test_verify_name_allowed_empty) {
    const char allow_file[] = "";

    ck_assert_int_eq(
        verify_name_allowed_from_string("example.local", allow_file),
        VERIFY_NAME_RESULT_NOT_ALLOWED);
    ck_assert_int_eq(
        verify_name_allowed_from_string("example.local.", allow_file),
        VERIFY_NAME_RESULT_NOT_ALLOWED);
    ck_assert_int_eq(
        verify_name_allowed_from_string("com.example.local", allow_file),
        VERIFY_NAME_RESULT_NOT_ALLOWED);
    ck_assert_int_eq(
        verify_name_allowed_from_string("com.example.local.", allow_file),
        VERIFY_NAME_RESULT_NOT_ALLOWED);
    ck_assert_int_eq(
        verify_name_allowed_from_string("example.com", allow_file),
        VERIFY_NAME_RESULT_NOT_ALLOWED);
    ck_assert_int_eq(
        verify_name_allowed_from_string("example.com.", allow_file),
        VERIFY_NAME_RESULT_NOT_ALLOWED);
    ck_assert_int_eq(
        verify_name_allowed_from_string("example.local.com", allow_file),
        VERIFY_NAME_RESULT_NOT_ALLOWED);
    ck_assert_int_eq(
        verify_name_allowed_from_string("example.local.com.", allow_file),
        VERIFY_NAME_RESULT_NOT_ALLOWED);
    ck_assert_int_eq(
        verify_name_allowed_from_string("", allow_file),
        VERIFY_NAME_RESULT_NOT_ALLOWED);
    ck_assert_int_eq(
        verify_name_allowed_from_string(".", allow_file),
        VERIFY_NAME_RESULT_NOT_ALLOWED);
}
END_TEST

// Tests verify_name_allowed with the standard config.
// .local is unconditionally permitted, without SOA check.
// Multi-label names are allowed.
START_TEST(test_verify_name_allowed_default) {
    const char allow_file[] =
        "# /etc/mdns.allow\n"
        ".local.\n"
        ".local\n";

    ck_assert_int_eq(
        verify_name_allowed_from_string("example.local", allow_file),
        VERIFY_NAME_RESULT_ALLOWED);
    ck_assert_int_eq(
        verify_name_allowed_from_string("example.local.", allow_file),
        VERIFY_NAME_RESULT_ALLOWED);
    ck_assert_int_eq(
        verify_name_allowed_from_string("com.example.local", allow_file),
        VERIFY_NAME_RESULT_ALLOWED);
    ck_assert_int_eq(
        verify_name_allowed_from_string("com.example.local.", allow_file),
        VERIFY_NAME_RESULT_ALLOWED);
    ck_assert_int_eq(
        verify_name_allowed_from_string("example.com", allow_file),
        VERIFY_NAME_RESULT_NOT_ALLOWED);
    ck_assert_int_eq(
        verify_name_allowed_from_string("example.com.", allow_file),
        VERIFY_NAME_RESULT_NOT_ALLOWED);
    ck_assert_int_eq(
        verify_name_allowed_from_string("example.local.com", allow_file),
        VERIFY_NAME_RESULT_NOT_ALLOWED);
    ck_assert_int_eq(
        verify_name_allowed_from_string("example.local.com.", allow_file),
        VERIFY_NAME_RESULT_NOT_ALLOWED);
    ck_assert_int_eq(verify_name_allowed_from_string("", allow_file),
                     VERIFY_NAME_RESULT_NOT_ALLOWED);
    ck_assert_int_eq(verify_name_allowed_from_string(".", allow_file),
                     VERIFY_NAME_RESULT_NOT_ALLOWED);
}
END_TEST

// Tests verify_name_allowed with wildcard.
// Everything is permitted, with no SOA check.
// Multi-label names are allowed.
START_TEST(test_verify_name_allowed_wildcard) {
    const char allow_file[] = "*\n";

    ck_assert_int_eq(
        verify_name_allowed_from_string("example.local", allow_file),
        VERIFY_NAME_RESULT_ALLOWED);
    ck_assert_int_eq(
        verify_name_allowed_from_string("example.local.", allow_file),
        VERIFY_NAME_RESULT_ALLOWED);
    ck_assert_int_eq(
        verify_name_allowed_from_string("com.example.local", allow_file),
        VERIFY_NAME_RESULT_ALLOWED);
    ck_assert_int_eq(
        verify_name_allowed_from_string("com.example.local.", allow_file),
        VERIFY_NAME_RESULT_ALLOWED);
    ck_assert_int_eq(
        verify_name_allowed_from_string("example.com", allow_file),
        VERIFY_NAME_RESULT_ALLOWED);
    ck_assert_int_eq(
        verify_name_allowed_from_string("example.com.", allow_file),
        VERIFY_NAME_RESULT_ALLOWED);
    ck_assert_int_eq(
        verify_name_allowed_from_string("example.local.com", allow_file),
        VERIFY_NAME_RESULT_ALLOWED);
    ck_assert_int_eq(
        verify_name_allowed_from_string("example.local.com.", allow_file),
        VERIFY_NAME_RESULT_ALLOWED);
    ck_assert_int_eq(
        verify_name_allowed_from_string("", allow_file),
        VERIFY_NAME_RESULT_ALLOWED);
    ck_assert_int_eq(
        verify_name_allowed_from_string(".", allow_file),
        VERIFY_NAME_RESULT_ALLOWED);
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

    ck_assert_int_eq(
        verify_name_allowed_from_string("example.local", allow_file),
        VERIFY_NAME_RESULT_ALLOWED);
    ck_assert_int_eq(
        verify_name_allowed_from_string("example.local.", allow_file),
        VERIFY_NAME_RESULT_ALLOWED);
    ck_assert_int_eq(
        verify_name_allowed_from_string("com.example.local", allow_file),
        VERIFY_NAME_RESULT_ALLOWED);
    ck_assert_int_eq(
        verify_name_allowed_from_string("com.example.local.", allow_file),
        VERIFY_NAME_RESULT_ALLOWED);
    ck_assert_int_eq(verify_name_allowed_from_string("example.com", allow_file),
                     VERIFY_NAME_RESULT_NOT_ALLOWED);
    ck_assert_int_eq(verify_name_allowed_from_string("example.com.", allow_file),
                     VERIFY_NAME_RESULT_NOT_ALLOWED);
    ck_assert_int_eq(
        verify_name_allowed_from_string("example.local.com", allow_file),
        VERIFY_NAME_RESULT_NOT_ALLOWED);
    ck_assert_int_eq(
        verify_name_allowed_from_string("example.local.com.", allow_file),
        VERIFY_NAME_RESULT_NOT_ALLOWED);
    ck_assert_int_eq(verify_name_allowed_from_string("", allow_file),
                     VERIFY_NAME_RESULT_NOT_ALLOWED);
    ck_assert_int_eq(verify_name_allowed_from_string(".", allow_file),
                     VERIFY_NAME_RESULT_NOT_ALLOWED);
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
    ck_assert_int_eq(verify_name_allowed_from_string(
                         "example"
                         ".aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 50 characters
                         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 50 characters
                         "aaaaaaaaaaaaaaaaaaaaaaaaaaa",                       // 27 characters
                         allow_file),
                     VERIFY_NAME_RESULT_ALLOWED);

    // Even though this exactly matches the item in the allow file,
    // it is too long.
    ck_assert_int_eq(verify_name_allowed_from_string(
                         "example"
                         ".aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"  // 50 characters
                         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"  // 50 characters
                         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"  // 50 characters
                         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"  // 50 characters
                         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // 50 characters
                         allow_file),
                     VERIFY_NAME_RESULT_NOT_ALLOWED);

    ck_assert_int_eq(
        verify_name_allowed_from_string("example.local", allow_file),
        VERIFY_NAME_RESULT_ALLOWED);
    ck_assert_int_eq(
        verify_name_allowed_from_string("example.local.", allow_file),
        VERIFY_NAME_RESULT_ALLOWED);
    ck_assert_int_eq(
        verify_name_allowed_from_string("com.example.local", allow_file),
        VERIFY_NAME_RESULT_ALLOWED);
    ck_assert_int_eq(
        verify_name_allowed_from_string("com.example.local.", allow_file),
        VERIFY_NAME_RESULT_ALLOWED);
    ck_assert_int_eq(verify_name_allowed_from_string("example.com", allow_file),
                     VERIFY_NAME_RESULT_NOT_ALLOWED);
    ck_assert_int_eq(verify_name_allowed_from_string("example.com.", allow_file),
                     VERIFY_NAME_RESULT_NOT_ALLOWED);
    ck_assert_int_eq(
        verify_name_allowed_from_string("example.local.com", allow_file),
        VERIFY_NAME_RESULT_NOT_ALLOWED);
    ck_assert_int_eq(
        verify_name_allowed_from_string("example.local.com.", allow_file),
        VERIFY_NAME_RESULT_NOT_ALLOWED);
    ck_assert_int_eq(verify_name_allowed_from_string("", allow_file),
                     VERIFY_NAME_RESULT_NOT_ALLOWED);
    ck_assert_int_eq(verify_name_allowed_from_string(".", allow_file),
                     VERIFY_NAME_RESULT_NOT_ALLOWED);
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

    ck_assert_int_eq(
        verify_name_allowed_from_string("example.local", allow_file),
        VERIFY_NAME_RESULT_ALLOWED);
    ck_assert_int_eq(
        verify_name_allowed_from_string("example.local.", allow_file),
        VERIFY_NAME_RESULT_ALLOWED);
    ck_assert_int_eq(
        verify_name_allowed_from_string("com.example.local", allow_file),
        VERIFY_NAME_RESULT_ALLOWED);
    ck_assert_int_eq(
        verify_name_allowed_from_string("com.example.local.", allow_file),
        VERIFY_NAME_RESULT_ALLOWED);
    ck_assert_int_eq(
        verify_name_allowed_from_string("example.com", allow_file),
        VERIFY_NAME_RESULT_ALLOWED);
    ck_assert_int_eq(
        verify_name_allowed_from_string("example.com.", allow_file),
        VERIFY_NAME_RESULT_ALLOWED);
    ck_assert_int_eq(
        verify_name_allowed_from_string("example.local.com", allow_file),
        VERIFY_NAME_RESULT_ALLOWED);
    ck_assert_int_eq(
        verify_name_allowed_from_string("example.local.com.", allow_file),
        VERIFY_NAME_RESULT_ALLOWED);
    ck_assert_int_eq(verify_name_allowed_from_string("example.net", allow_file),
                     VERIFY_NAME_RESULT_NOT_ALLOWED);
    ck_assert_int_eq(verify_name_allowed_from_string("example.net.", allow_file),
                     VERIFY_NAME_RESULT_NOT_ALLOWED);
    ck_assert_int_eq(verify_name_allowed_from_string("", allow_file),
                     VERIFY_NAME_RESULT_NOT_ALLOWED);
    ck_assert_int_eq(verify_name_allowed_from_string(".", allow_file),
                     VERIFY_NAME_RESULT_NOT_ALLOWED);
}
END_TEST

// Tests ends_with.
START_TEST(test_ends_with) {
    ck_assert(ends_with("", ""));
    ck_assert(!ends_with("", " "));
    ck_assert(!ends_with("", "z"));
    ck_assert(ends_with("z", ""));
    ck_assert(ends_with("z", "z"));
    ck_assert(!ends_with("z", "zz"));
    ck_assert(ends_with("example.local", ".local"));
    ck_assert(ends_with("example.local.", ".local."));
    ck_assert(!ends_with("example.local.", ".local"));
    ck_assert(!ends_with("example.local.", ".local"));
}
END_TEST

// Tests label_count.
START_TEST(test_label_count) {
    ck_assert_int_eq(label_count(""), 1);
    ck_assert_int_eq(label_count("."), 1);
    ck_assert_int_eq(label_count("local"), 1);
    ck_assert_int_eq(label_count("local."), 1);
    ck_assert_int_eq(label_count("foo.local"), 2);
    ck_assert_int_eq(label_count("foo.local."), 2);
    ck_assert_int_eq(label_count("bar.foo.local"), 3);
    ck_assert_int_eq(label_count("bar.foo.local."), 3);
    ck_assert_int_eq(label_count("my-foo.local"), 2);
    ck_assert_int_eq(label_count("my-foo.local."), 2);
}
END_TEST

// Tests for buffer_t functions.

START_TEST(test_buffer_alloc_too_large_returns_null) {
    char buffer[100];
    buffer_t buf;
    buffer_init(&buf, buffer, sizeof(buffer));

    ck_assert_ptr_null(buffer_alloc(&buf, 101));
}
END_TEST

START_TEST(test_buffer_alloc_just_right_returns_nonnull) {
    char buffer[100];
    buffer_t buf;
    buffer_init(&buf, buffer, sizeof(buffer));

    ck_assert_ptr_nonnull(buffer_alloc(&buf, 100));
}
END_TEST

START_TEST(test_unaligned_buffer_alloc_returns_aligned) {
    char buffer[1000];
    buffer_t buf;

    for (size_t i = 0; i < 32; i++) {
        buffer_init(&buf, buffer + i, sizeof(buffer) - i);
        char* ptr = buffer_alloc(&buf, 10);
        ck_assert_uint_eq((uintptr_t)ptr % sizeof(void*), 0);
    }
}
END_TEST

START_TEST(test_buffer_alloc_returns_aligned) {
    char buffer[1000];
    buffer_t buf;
    buffer_init(&buf, buffer, sizeof(buffer));

    for (size_t i = 0; i < 32; i++) {
        char* ptr = buffer_alloc(&buf, i);
        ck_assert_ptr_nonnull(ptr);
        ck_assert_uint_eq((uintptr_t)ptr % sizeof(void*), 0);
    }
}
END_TEST

START_TEST(test_null_buffer_zero_alloc_returns_nonnull) {
    buffer_t buf;
    buffer_init(&buf, NULL, 0);

    ck_assert_ptr_nonnull(buffer_alloc(&buf, 0));
}
END_TEST

START_TEST(test_zero_buffer_zero_alloc_returns_nonnull) {
    char buffer[1];
    buffer_t buf;
    buffer_init(&buf, buffer, 0);

    ck_assert_ptr_nonnull(buffer_alloc(&buf, 0));
}
END_TEST

START_TEST(test_nonzero_buffer_zero_alloc_returns_nonnull) {
    char buffer[100];
    buffer_t buf;
    buffer_init(&buf, buffer, sizeof(buffer));

    ck_assert_ptr_nonnull(buffer_alloc(&buf, 0));
}
END_TEST

START_TEST(test_null_buffer_nonzero_alloc_returns_null) {
    buffer_t buf;
    buffer_init(&buf, NULL, 0);

    ck_assert_ptr_null(buffer_alloc(&buf, 1));
}
END_TEST

START_TEST(test_zero_buffer_nonzero_alloc_returns_null) {
    char buffer[1];
    buffer_t buf;
    buffer_init(&buf, buffer, 0);

    ck_assert_ptr_null(buffer_alloc(&buf, 1));
}
END_TEST

START_TEST(test_buffer_tiny_alloc_returns_nonnull) {
    char buffer[100];
    buffer_t buf;
    buffer_init(&buf, buffer, sizeof(buffer));

    ck_assert_ptr_nonnull(buffer_alloc(&buf, 1));
}
END_TEST

START_TEST(test_tiny_buffer_tiny_alloc_returns_nonnull) {
    char* buffer = malloc(1); // Need to malloc to get pre-aligned buffer.
    buffer_t buf;
    buffer_init(&buf, buffer, 1);

    ck_assert_ptr_nonnull(buffer_alloc(&buf, 1));
    free(buffer);
}
END_TEST

START_TEST(test_tiny_unaligned_buffer_tiny_alloc_returns_null) {
    char* buffer = malloc(2); // Need to malloc to get pre-aligned buffer.
    buffer_t buf;
    buffer_init(&buf, buffer + 1, 1);

    ck_assert_ptr_null(buffer_alloc(&buf, 1));
    free(buffer);
}
END_TEST

START_TEST(test_tiny_buffer_second_alloc_returns_null) {
    char* buffer = malloc(2); // Need to malloc to get pre-aligned buffer.
    buffer_t buf;
    buffer_init(&buf, buffer, 2);

    ck_assert_ptr_nonnull(buffer_alloc(&buf, 1));
    ck_assert_ptr_null(buffer_alloc(&buf, 1)); // With alignment, out of room.
    free(buffer);
}
END_TEST

START_TEST(test_tiny_buffer_one_too_big_alloc_returns_null) {
    char* buffer = malloc(1); // Need to malloc to get pre-aligned buffer.
    buffer_t buf;
    buffer_init(&buf, buffer, 1);

    ck_assert_ptr_null(buffer_alloc(&buf, 2));
    free(buffer);
}
END_TEST

START_TEST(test_buffer_alloc_returns_zeroed_memory) {
    char buffer[100];
    memset(buffer, 0xFF, sizeof(buffer));

    char zero[100];
    memset(zero, 0, sizeof(zero));

    buffer_t buf;
    buffer_init(&buf, buffer, sizeof(buffer));
    ck_assert_mem_eq(buffer_alloc(&buf, 50), zero, 50);
}
END_TEST

// Boilerplate from https://libcheck.github.io/check/doc/check_html/check_3.html
static Suite* util_suite(void) {
    Suite* s = suite_create("util");

    TCase* tc_verify_name = tcase_create("verify_name");
    tcase_add_test(tc_verify_name, test_verify_name_allowed_minimal);
    tcase_add_test(tc_verify_name, test_verify_name_allowed_default);
    tcase_add_test(tc_verify_name, test_verify_name_allowed_empty);
    tcase_add_test(tc_verify_name, test_verify_name_allowed_wildcard);
    tcase_add_test(tc_verify_name, test_verify_name_allowed_too_long);
    tcase_add_test(tc_verify_name, test_verify_name_allowed_too_long2);
    tcase_add_test(tc_verify_name, test_verify_name_allowed_com_and_local);
    suite_add_tcase(s, tc_verify_name);

    TCase* tc_ends_with = tcase_create("ends_with");
    tcase_add_test(tc_ends_with, test_ends_with);
    suite_add_tcase(s, tc_ends_with);

    TCase* tc_label_count = tcase_create("label_count");
    tcase_add_test(tc_label_count, test_label_count);
    suite_add_tcase(s, tc_label_count);

    TCase* tc_buffer = tcase_create("buffer");
    tcase_add_test(tc_buffer, test_buffer_alloc_too_large_returns_null);
    tcase_add_test(tc_buffer, test_buffer_alloc_just_right_returns_nonnull);
    tcase_add_test(tc_buffer, test_unaligned_buffer_alloc_returns_aligned);
    tcase_add_test(tc_buffer, test_buffer_alloc_returns_aligned);
    tcase_add_test(tc_buffer, test_null_buffer_zero_alloc_returns_nonnull);
    tcase_add_test(tc_buffer, test_zero_buffer_zero_alloc_returns_nonnull);
    tcase_add_test(tc_buffer, test_nonzero_buffer_zero_alloc_returns_nonnull);
    tcase_add_test(tc_buffer, test_null_buffer_nonzero_alloc_returns_null);
    tcase_add_test(tc_buffer, test_zero_buffer_nonzero_alloc_returns_null);
    tcase_add_test(tc_buffer, test_buffer_tiny_alloc_returns_nonnull);
    tcase_add_test(tc_buffer, test_tiny_buffer_tiny_alloc_returns_nonnull);
    tcase_add_test(tc_buffer, test_tiny_unaligned_buffer_tiny_alloc_returns_null);
    tcase_add_test(tc_buffer, test_tiny_buffer_second_alloc_returns_null);
    tcase_add_test(tc_buffer, test_tiny_buffer_one_too_big_alloc_returns_null);
    tcase_add_test(tc_buffer, test_buffer_alloc_returns_zeroed_memory);
    suite_add_tcase(s, tc_buffer);

    return s;
}

int main(void) {
    int number_failed;
    Suite* s;
    SRunner* sr;

    s = util_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
