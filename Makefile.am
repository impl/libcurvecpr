ACLOCAL_AMFLAGS = -I m4

LIBCURVECPR_API_VERSION = 1:0:0

lib_LTLIBRARIES = libcurvecpr.la

libcurvecpr_la_CPPFLAGS = -I$(top_srcdir)/include
libcurvecpr_la_CFLAGS = \
    -Wall -W -Wcast-qual -Wcast-align -Winline -Wmissing-prototypes -Wwrite-strings \
    -Wredundant-decls -Wpointer-arith -Wchar-subscripts -Wshadow -Wstrict-prototypes -Werror
libcurvecpr_la_LDFLAGS = -version-info $(LIBCURVECPR_API_VERSION)

AUTOMAKE_OPTIONS = subdir-objects
libcurvecpr_la_SOURCES = \
    lib/bytes.c \
    lib/chicago.c \
    lib/client.c \
    lib/client_recv.c \
    lib/client_send.c \
    lib/messager.c \
    lib/server.c \
    lib/server_recv.c \
    lib/server_send.c \
    lib/session.c \
    lib/util.c

curvecprincludedir = $(includedir)/curvecpr
curvecprinclude_HEADERS = \
    include/block.h \
    include/bytes.h \
    include/chicago.h \
    include/client.h \
    include/messager.h \
    include/packet.h \
    include/server.h \
    include/session.h \
    include/util.h

check_PROGRAMS =

check_PROGRAMS += t/test_messager
t_test_messager_SOURCES = t/test_messager.c
t_test_messager_CPPFLAGS = -I$(top_srcdir)/include
t_test_messager_CFLAGS = @CHECK_CFLAGS@
t_test_messager_LDADD = $(top_builddir)/libcurvecpr.la @CHECK_LIBS@

TESTS = $(check_PROGRAMS)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libcurvecpr.pc
