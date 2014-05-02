#include <check.h>
#include <check_extras.h>

#include <curvecpr/messager.h>
#include <curvecpr/util.h>

static char static_priv[] = "Hello!";

static unsigned char t_sendmarkq_is_full (struct curvecpr_messager *messager)
{
    return 0;
}

static unsigned char t_sendq_is_empty (struct curvecpr_messager *messager)
{
    return 1;
}

static int t_sendmarkq_head (struct curvecpr_messager *messager, struct curvecpr_block **block_stored)
{
    return 1;
}

START_TEST (test_new_configures_object)
{
    struct curvecpr_messager messager;
    struct curvecpr_messager_cf cf = {
        .ops = {
            .sendmarkq_is_full = t_sendmarkq_is_full,
            .sendq_is_empty = t_sendq_is_empty,
            .sendmarkq_head = t_sendmarkq_head,
            .get_nanoseconds = curvecpr_util_nanoseconds
        },
        .priv = static_priv
    };

    curvecpr_messager_new(&messager, &cf, 1);

    fail_unless(memcmp(static_priv, messager.cf.priv, sizeof(static_priv)) == 0);
    fail_unless(messager.my_maximum_send_bytes == 512);
}
END_TEST

RUN_TEST (test_new_configures_object)
