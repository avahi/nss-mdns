if ENABLE_TESTS

TESTS = check_util
check_PROGRAMS = check_util
check_util_SOURCES = check_util.c $(top_builddir)/src/util.h
check_util_CFLAGS = @CHECK_CFLAGS@
check_util_LDADD = $(top_builddir)/src/util.o @CHECK_LIBS@

endif

EXTRA_DIST = check_util.c
