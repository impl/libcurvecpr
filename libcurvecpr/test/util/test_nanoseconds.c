#include <check.h>
#include <check_extras.h>

#include <curvecpr/util.h>

START_TEST (test_nanoseconds)
{
    long long nanoseconds = curvecpr_util_nanoseconds();

    fail_if(nanoseconds < 0);
    fail_unless(nanoseconds > 1374047000000000000LL);

    /* On OS X, we may cache the kernel clock reference. Make sure it still
       works. */
    nanoseconds = curvecpr_util_nanoseconds();

    fail_if(nanoseconds < 0);
    fail_unless(nanoseconds > 1374047000000000000LL);
}
END_TEST

RUN_TEST (test_nanoseconds)
