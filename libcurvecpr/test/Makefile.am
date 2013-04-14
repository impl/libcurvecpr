AM_CPPFLAGS = -I$(top_srcdir)/libcurvecpr/include -I$(top_srcdir)/libcurvecpr/test
AM_CFLAGS = @CHECK_CFLAGS@
LDADD = $(top_builddir)/libcurvecpr/lib/libcurvecpr.la @CHECK_LIBS@

check_PROGRAMS =

check_PROGRAMS += messager/test_new_configures_object
messager_test_new_configures_object_SOURCES = messager/test_new_configures_object.c

check_PROGRAMS += messager/test_recv_requests_removal_from_sendmarkq
messager_test_recv_requests_removal_from_sendmarkq_SOURCES = messager/test_recv_requests_removal_from_sendmarkq.c

check_PROGRAMS += messager/test_send_with_1_failure_moves_message_from_sendq
messager_test_send_with_1_failure_moves_message_from_sendq_SOURCES = messager/test_send_with_1_failure_moves_message_from_sendq.c

TESTS = $(check_PROGRAMS)
