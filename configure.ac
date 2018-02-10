# -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

# This file is part of nss-mdns.
#
# nss-mdns is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
#
# nss-mdns is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with nss-mdns; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

AC_PREREQ([2.69])
AC_INIT([nss-mdns],[0.11],[https://github.com/lathiat/nss-mdns/issues])
AC_CONFIG_SRCDIR([src/nss.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([foreign 1.9 -Wall])
AC_CONFIG_MACRO_DIRS([m4])

AC_SUBST(PACKAGE_URL, [https://github.com/lathiat/nss-mdns])

ac_default_prefix="/"

AC_USE_SYSTEM_EXTENSIONS

PKG_CHECK_MODULES([CHECK], [check], [have_check=yes], [have_check=no])
AM_CONDITIONAL([HAVE_CHECK], [test "x$have_check" = "xyes"])

if test "x$have_check" = "xno" ; then
    AC_MSG_WARN([$CHECK_PKG_ERRORS])
    AC_MSG_WARN([Unit tests will be disabled])
fi

# Checks for programs.
AM_PROG_AR
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET

test_gcc_flag() {
    AC_LANG_CONFTEST([AC_LANG_SOURCE([int main() {}])])
    $CC -c conftest.c $CFLAGS $@ > /dev/null 2> /dev/null
    ret=$?
    rm -f conftest.o
    return $ret
}

# If using GCC specify some additional parameters
if test "x$GCC" = "xyes" ; then

    # We use gnu99 instead of c99 because many have interpreted the standard
    # in a way that int64_t isn't defined on non-64 bit platforms.
    DESIRED_FLAGS="-std=gnu99 -Wall -W -Wextra -pedantic -pipe -Wformat -Wold-style-definition -Wdeclaration-after-statement -Wfloat-equal -Wmissing-declarations -Wmissing-prototypes -Wstrict-prototypes -Wredundant-decls -Wmissing-noreturn -Wshadow -Wendif-labels -Wpointer-arith -Wbad-function-cast -Wcast-qual -Wcast-align -Wwrite-strings -Winline -Wno-unused-parameter"

    for flag in $DESIRED_FLAGS ; do
        AC_MSG_CHECKING([whether $CC accepts $flag])
        if test_gcc_flag $flag ; then 
           CFLAGS="$CFLAGS $flag"
           AC_MSG_RESULT([yes])
        else
           AC_MSG_RESULT([no])
        fi
    done 
fi

# libtool stuff
AC_DISABLE_STATIC
LT_INIT

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h sys/time.h unistd.h nss.h sys/ioctl.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_HEADER_TIME

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_SELECT_ARGTYPES
AC_SEARCH_LIBS([__res_nquery], [resolv])
AC_CHECK_FUNCS([gethostbyaddr gethostbyname gettimeofday inet_ntoa memset select socket strcspn strdup strerror strncasecmp strcasecmp strspn])

# FreeBSD has a slightly different NSS interface
case ${host} in
     *-freebsd*) freebsd="yes" ;;
esac

AM_CONDITIONAL([FREEBSD_NSS], [test "x$freebsd" = "xyes"])

# If using GCC specify some additional parameters
if test "x$GCC" = "xyes" ; then
   CFLAGS="$CFLAGS -pipe -W -Wall -pedantic"

   AC_LANG_CONFTEST([AC_LANG_SOURCE([int main() {}])])
   $CC -c conftest.c -std=c99 -Wno-unused-parameter $CFLAGS > /dev/null 2> /dev/null && CFLAGS="$CFLAGS -std=c99 -Wno-unused-parameter"
   rm -f conftest.o
fi

AC_CONFIG_FILES([Makefile src/Makefile tests/Makefile])
AC_OUTPUT
