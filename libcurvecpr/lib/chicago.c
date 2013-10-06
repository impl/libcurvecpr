#include "config.h"

#include <curvecpr/chicago.h>

#include <curvecpr/bytes.h>
#include <curvecpr/util.h>

static void _try_update_rates (struct curvecpr_chicago *chicago)
{
    if (chicago->clock - chicago->ns_last_edge < 60000000000LL) {
        if (chicago->clock < chicago->ns_last_doubling + 4 * chicago->wr_rate + 64 * chicago->rtt_timeout + 5000000000LL)
            return;
    } else {
        if (chicago->clock < chicago->ns_last_doubling + 4 * chicago->wr_rate + 2 * chicago->rtt_timeout)
            return;
    }

    if (chicago->wr_rate <= 65535)
        return;

    chicago->wr_rate /= 2;
    chicago->ns_last_doubling = chicago->clock;
    if (chicago->ns_last_edge)
        chicago->ns_last_edge = chicago->clock;
}

static void _update (struct curvecpr_chicago *chicago, long long rtt_ns)
{
    chicago->rtt_latest = rtt_ns;

    /* Initialization. */
    if (!chicago->rtt_average) {
        chicago->wr_rate = chicago->rtt_latest;

        chicago->rtt_average = chicago->rtt_latest;
        chicago->rtt_deviation = chicago->rtt_latest / 2;
        chicago->rtt_highwater = chicago->rtt_latest;
        chicago->rtt_lowwater = chicago->rtt_latest;
    }

    /* Jacobson's retransmission timeout calculation. */
    long long rtt_delta = chicago->rtt_latest - chicago->rtt_average;
    chicago->rtt_average += rtt_delta / 8;
    if (rtt_delta < 0)
        rtt_delta = -rtt_delta;
    rtt_delta -= chicago->rtt_deviation;
    chicago->rtt_deviation += rtt_delta / 4;
    chicago->rtt_timeout = chicago->rtt_average + 4 * chicago->rtt_deviation;

    /* Adjust for delayed acknowledgements with anti-spiking. */
    chicago->rtt_timeout += 8 * chicago->wr_rate;

    /* Recognize top and bottom of congestion cycle. */
    rtt_delta = chicago->rtt_latest - chicago->rtt_highwater;
    chicago->rtt_highwater += rtt_delta / 1024;

    rtt_delta = chicago->rtt_latest - chicago->rtt_lowwater;
    if (rtt_delta > 0)
        chicago->rtt_lowwater += rtt_delta / 8192;
    else
        chicago->rtt_lowwater += rtt_delta / 256;

    if (chicago->rtt_average > chicago->rtt_highwater + 5000000)
        chicago->seen_recent_high = 1;
    else if (chicago->rtt_average < chicago->rtt_lowwater)
        chicago->seen_recent_low = 1;

    /* Should we update? Only after we've seen ~16 packets. */
    if (chicago->clock >= chicago->ns_last_update + 16 * chicago->wr_rate) {
        /* Maybe it's been too long (bad timeout -- 10 seconds)... */
        if (chicago->clock - chicago->ns_last_update > 10000000000LL) {
            chicago->wr_rate = 1000000000;
            chicago->wr_rate += curvecpr_util_random_mod_n(chicago->wr_rate / 8);
        }

        chicago->ns_last_update = chicago->clock;

        if (chicago->wr_rate >= 131072) {
            /* Additive increase: adjust 1/N by a constant c.
             * 
             * RTT-fair additive increase: adjust 1/N by a constant c every N
             * nanoseconds.
             *
             * Approximation: adjust 1/N by cN every N nanoseconds (i.e.,
             * N <- 1/(1/N + cN) = N/(1 + cN^2) every N nanoseconds).
             */
            if (chicago->wr_rate < 16777216) {
                /* N/(1 + cN^2) ~= N - cN^3 */
                long long u = chicago->wr_rate / 131072;
                chicago->wr_rate -= u * u * u;
            } else {
                double d = chicago->wr_rate;
                chicago->wr_rate = d / (1 + d * d / 2251799813685248.0);
            }
        }

        if (chicago->rtt_phase == 0) {
            if (chicago->seen_older_high) {
                chicago->rtt_phase = 1;
                chicago->ns_last_edge = chicago->clock;
                chicago->wr_rate += curvecpr_util_random_mod_n(chicago->wr_rate / 4);
            }
        } else {
            if (chicago->seen_older_low)
                chicago->rtt_phase = 0;
        }

        chicago->seen_older_high = chicago->seen_recent_high;
        chicago->seen_older_low = chicago->seen_recent_low;
        chicago->seen_recent_high = 0;
        chicago->seen_recent_low = 0;

        _try_update_rates(chicago);
    }
}

static void _update_on_timeout (struct curvecpr_chicago *chicago)
{
    if (chicago->clock > chicago->ns_last_panic + 4 * chicago->rtt_timeout) {
        chicago->wr_rate *= 2;
        chicago->ns_last_panic = chicago->clock;
        chicago->ns_last_edge = chicago->clock;
    }
}

void curvecpr_chicago_new (struct curvecpr_chicago *chicago)
{
    curvecpr_bytes_zero(chicago, sizeof(struct curvecpr_chicago));

    curvecpr_chicago_refresh_clock(chicago);

    chicago->rtt_latest = 0;
    chicago->rtt_average = 0;
    chicago->rtt_deviation = 0;
    chicago->rtt_lowwater = 0;
    chicago->rtt_highwater = 0;
    chicago->rtt_timeout = 1000000000;

    chicago->seen_recent_high = 0;
    chicago->seen_recent_low = 0;
    chicago->seen_older_high = 0;
    chicago->seen_older_low = 0;

    chicago->rtt_phase = 0;

    /* FIXME: This should be 1 second? */
    chicago->wr_rate = 0;

    chicago->ns_last_update = 0;
    chicago->ns_last_edge = 0;
    chicago->ns_last_doubling = 0;
    chicago->ns_last_panic = 0;
}

void curvecpr_chicago_refresh_clock (struct curvecpr_chicago *chicago)
{
    chicago->clock = curvecpr_util_nanoseconds();
}

void curvecpr_chicago_on_timeout (struct curvecpr_chicago *chicago)
{
    _update_on_timeout(chicago);
}

void curvecpr_chicago_on_recv (struct curvecpr_chicago *chicago, long long ns_sent)
{
    _update(chicago, chicago->clock - ns_sent);
}
