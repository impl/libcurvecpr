#include <check.h>
#include <check_extras.h>

#include <curvecpr/util.h>

START_TEST (test_nanoseconds)
{
    long long nanoseconds = curvecpr_util_nanoseconds();

    fail_if(nanoseconds < 0);
    fail_unless(nanoseconds > 0);

    /* On OS X, we may cache the kernel clock reference. Make sure it still
       works. */
    long long nanoseconds1 = curvecpr_util_nanoseconds();

    fail_if(nanoseconds1 < 0);
    fail_unless(nanoseconds1 > nanoseconds);
}
END_TEST

RUN_TEST (test_nanoseconds)
