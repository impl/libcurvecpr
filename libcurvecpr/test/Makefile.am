EXTRA_DIST = check_extras.h

AM_CPPFLAGS = -I$(top_srcdir)/libcurvecpr/include -I$(top_srcdir)/libcurvecpr/test
AM_CFLAGS = @CHECK_CFLAGS@ @LIBSODIUM_CFLAGS@
LDADD = $(top_builddir)/libcurvecpr/lib/libcurvecpr.la @CHECK_LIBS@ @LIBSODIUM_LIBS@

check_PROGRAMS =

check_PROGRAMS += messager/test_new_configures_object
messager_test_new_configures_object_SOURCES = messager/test_new_configures_object.c

check_PROGRAMS += messager/test_recv_requests_removal_from_sendmarkq
messager_test_recv_requests_removal_from_sendmarkq_SOURCES = messager/test_recv_requests_removal_from_sendmarkq.c

check_PROGRAMS += messager/test_send_with_1_failure_moves_message_from_sendq
messager_test_send_with_1_failure_moves_message_from_sendq_SOURCES = messager/test_send_with_1_failure_moves_message_from_sendq.c

check_PROGRAMS += messager/test_timeout_callback_fires
messager_test_timeout_callback_fires_SOURCES = messager/test_timeout_callback_fires.c

check_PROGRAMS += util/test_nanoseconds
util_test_nanoseconds_SOURCES = util/test_nanoseconds.c

TESTS = $(check_PROGRAMS)
