#include <check.h>

#include "bytes.h"
#include "messager.h"

static char PRIV[] = "Hello!";

START_TEST (test_new_configures_object)
{
    struct curvecpr_messager messager;
    struct curvecpr_messager_cf cf = { .priv = PRIV };

    curvecpr_messager_new(&messager, &cf, 1);

    fail_unless(memcmp(PRIV, messager.cf.priv, sizeof(PRIV)) == 0);
    fail_unless(messager.my_maximum_send_bytes == 512);
}
END_TEST

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

int main (void)
{
    int failed;

    Suite *s = suite_create("messager");

    TCase *tc_new = tcase_create("new");
    tcase_add_test(tc_new, test_new_configures_object);
    suite_add_tcase(s, tc_new);

    TCase *tc_recv = tcase_create("recv");
    tcase_add_test(tc_recv, test_recv_requests_removal_from_sendmarkq);
    suite_add_tcase(s, tc_recv);

    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return failed ? 1 : 0;
}
