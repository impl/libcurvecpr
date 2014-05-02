#ifndef __CURVECPR_CHICAGO_H
#define __CURVECPR_CHICAGO_H

#ifdef __cplusplus
extern "C" {
#endif

struct curvecpr_chicago_ops {
    /* Get current time in nanoseconds. The time 0 can be any time as long
       as present time is not too close to it (>100 seconds should be ok) and
       it doesn't change during the lifetime of this chicago instance (i.e.
       it doesn't have to be for example 1970-01-01, but can be the number of
       nanoseconds since the computer booted+100s or whatever).
       You can pass in curvecpr_util_nanoseconds() here if you want. */
    long long (*get_nanoseconds)(void *priv);
};

struct curvecpr_chicago_cf {
    struct curvecpr_chicago_ops ops;
    void *priv;
};

struct curvecpr_chicago {
    long long clock;

    long long rtt_latest;
    long long rtt_average;
    long long rtt_deviation;
    long long rtt_highwater;
    long long rtt_lowwater;
    long long rtt_timeout;

    unsigned char seen_recent_high;
    unsigned char seen_recent_low;
    unsigned char seen_older_high;
    unsigned char seen_older_low;

    unsigned char rtt_phase;

    long long wr_rate;

    long long ns_last_update;
    long long ns_last_edge;
    long long ns_last_doubling;
    long long ns_last_panic;

    struct curvecpr_chicago_cf cf;
};

void curvecpr_chicago_new (struct curvecpr_chicago *chicago, const struct curvecpr_chicago_cf *cf);
void curvecpr_chicago_refresh_clock (struct curvecpr_chicago *chicago);
void curvecpr_chicago_on_timeout (struct curvecpr_chicago *chicago);
void curvecpr_chicago_on_recv (struct curvecpr_chicago *chicago, long long ns_sent);

#ifdef __cplusplus
}
#endif

#endif
