#include <check.h>
#include <check_extras.h>

#include "messager.h"

static char static_priv[] = "Hello!";

START_TEST (test_new_configures_object)
{
    struct curvecpr_messager messager;
    struct curvecpr_messager_cf cf = { .priv = static_priv };

    curvecpr_messager_new(&messager, &cf, 1);

    fail_unless(memcmp(static_priv, messager.cf.priv, sizeof(static_priv)) == 0);
    fail_unless(messager.my_maximum_send_bytes == 512);
}
END_TEST

RUN_TEST (test_new_configures_object)
