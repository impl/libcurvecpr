#ifndef __CURVECPR_CHICAGO_H
#define __CURVECPR_CHICAGO_H

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
};

void curvecpr_chicago_new (struct curvecpr_chicago *chicago);
void curvecpr_chicago_refresh_clock (struct curvecpr_chicago *chicago);
void curvecpr_chicago_on_timeout (struct curvecpr_chicago *chicago);
void curvecpr_chicago_on_recv (struct curvecpr_chicago *chicago, long long ns_sent);

#endif
