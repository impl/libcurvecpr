lib_LTLIBRARIES = libcurvecpr-glib.la

libcurvecpr_glib_la_CPPFLAGS = -I$(top_srcdir)/libcurvecpr/include -I$(top_srcdir)/libcurvecpr-glib/include
libcurvecpr_glib_la_CFLAGS = @GLIB_CFLAGS@
libcurvecpr_glib_la_LDFLAGS = -version-info $(CURVECPR_LIBRARY_VERSION) @GLIB_LIBS@ -L$(top_srcdir)/libcurvecpr/lib -lcurvecpr
libcurvecpr_glib_la_SOURCES = \
    client_messager_glib.c \
    messager_glib.c
