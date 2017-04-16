#include "config.h"

#include <curvecpr/util.h>

#include <curvecpr/bytes.h>

#include <time.h>
#ifdef HAVE_HOST_GET_CLOCK_SERVICE
#include <libkern/OSAtomic.h>
#include <mach/clock.h>
#include <mach/mach.h>
#include <mach/mach_error.h>
#include <stdint.h>
#endif

#include <sodium/randombytes.h>

/* XXX: Current implementation is limited to n < 2^55. */
long long curvecpr_util_random_mod_n (long long n)
{
    long long result = 0;
    long long i;
    unsigned char bytes[32];

    if (n <= 1)
        return 0;

    randombytes(bytes, sizeof(bytes));
    for (i = 0; i < 32; ++i)
        result = (result * 256 + (unsigned long long)bytes[i]) % n;

    return result;
}

/* XXX: Y2036 problems; should upgrade to a 128-bit type for this. */
/* XXX: Nanosecond granularity limits users to 1 terabyte per second. */
long long curvecpr_util_nanoseconds (void *priv)
{
    /* XXX: host_get_clock_service() has been officially deprecated for years;
       this may need to be updated in the future. */
#ifdef HAVE_HOST_GET_CLOCK_SERVICE
    static int32_t cclock_registered = 0;
    static volatile clock_serv_t cclock = 0;
    mach_timespec_t t;

    if (!cclock) {
        if (OSAtomicCompareAndSwap32Barrier(0, 1, &cclock_registered) == 1) {
            clock_serv_t cclock_actual;

            if (host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &cclock_actual) != KERN_SUCCESS) {
                cclock_registered = 0;
                return -1;
            }

            cclock = cclock_actual;
        } else {
            while (!cclock)
                /* Wait for clock to become available */;
        }
    }

    if (clock_get_time(cclock, &t) != KERN_SUCCESS)
        return -1;
#else
    struct timespec t;

    if (clock_gettime(CLOCK_REALTIME, &t) != 0)
        return -1;
#endif

    return t.tv_sec * 1000000000LL + t.tv_nsec;
}

int curvecpr_util_encode_domain_name (unsigned char *destination, const char *source)
{
    int position = 0;

    if (source == NULL)
        return 0;

    /* The destination must be 256 bytes in size. */
    curvecpr_bytes_zero(destination, 256);

    while (*source != '\0') {
        int i;

        /* Skip segment separators. */
        if (*source == '.') {
            ++source;
            continue;
        }

        /* Count the size of the next segment. */
        for (i = 0; source[i] != '\0' && source[i] != '.'; ++i) {}

        /* Each segment of the server name is limited to 63 characters. */
        if (i >= 64)
            return 0;

        /* Write the length of the next segment. */
        if (position >= 256)
            return 0;
        destination[position] = i;
        ++position;

        /* Write the segment. */
        while (i > 0) {
            if (position >= 256)
                return 0;

            destination[position] = *source;
            ++source;
            ++position;
            --i;
        }
    }

    if (position >= 256)
        return 0;

    return 1;
}
