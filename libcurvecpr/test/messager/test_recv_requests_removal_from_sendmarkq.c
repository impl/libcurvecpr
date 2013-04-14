#include <check.h>
#include <check_extras.h>

#include "bytes.h"
#include "messager.h"

static int t_sendmarkq_remove_range (struct curvecpr_messager *messager, unsigned long long start, unsigned long long end)
{
    fail_unless(start == 0);
    fail_unless(end == 1234);

    return 0;
}

START_TEST (test_recv_requests_removal_from_sendmarkq)
{
    struct curvecpr_messager messager;
    struct curvecpr_messager_cf cf = {
        .ops = {
            .sendmarkq_remove_range = t_sendmarkq_remove_range
        }
    };
    unsigned char buf[1024] = { 0 };
    size_t len = 128;

    curvecpr_bytes_pack_uint64(buf + 8, 1234L);

    curvecpr_messager_new(&messager, &cf, 1);
    curvecpr_messager_recv(&messager, buf, len);
}
END_TEST

RUN_TEST (test_recv_requests_removal_from_sendmarkq)
