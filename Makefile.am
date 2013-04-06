ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = libcurvecpr.la

libcurvecpr_la_CPPFLAGS = -I$(top_srcdir)/include
libcurvecpr_la_LDFLAGS = -version-info $(CURVECPR_LIBRARY_VERSION)

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
