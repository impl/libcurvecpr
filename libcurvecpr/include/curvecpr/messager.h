#ifndef __CURVECPR_MESSAGER_H
#define __CURVECPR_MESSAGER_H

#include "block.h"
#include "chicago.h"

#include <string.h>

#include <sodium/crypto_uint32.h>

struct curvecpr_messager;

struct curvecpr_messager_ops {
    int (*sendq_head)(struct curvecpr_messager *messager, struct curvecpr_block **block_stored);
    int (*sendq_move_to_sendmarkq)(struct curvecpr_messager *messager, const struct curvecpr_block *block, struct curvecpr_block **block_stored);
    unsigned char (*sendq_is_empty)(struct curvecpr_messager *messager);

    /* The sent-to-be-marked queue (sendmarkq) is a priority queue of blocks ordered by
       the time at which they were last sent. */
    int (*sendmarkq_head)(struct curvecpr_messager *messager, struct curvecpr_block **block_stored);
    int (*sendmarkq_get)(struct curvecpr_messager *messager, crypto_uint32 acknowledging_id, struct curvecpr_block **block_stored);
    int (*sendmarkq_remove_range)(struct curvecpr_messager *messager, unsigned long long start, unsigned long long end);
    unsigned char (*sendmarkq_is_full)(struct curvecpr_messager *messager);

    int (*recvmarkq_put)(struct curvecpr_messager *messager, const struct curvecpr_block *block, struct curvecpr_block **block_stored);
    int (*recvmarkq_get_nth_unacknowledged)(struct curvecpr_messager *messager, unsigned int n, struct curvecpr_block **block_stored);
    unsigned char (*recvmarkq_is_empty)(struct curvecpr_messager *messager);
    int (*recvmarkq_remove_range)(struct curvecpr_messager *messager, unsigned long long start, unsigned long long end);

    int (*send)(struct curvecpr_messager *messager, const unsigned char *buf, size_t num);
};

struct curvecpr_messager_cf {
    struct curvecpr_messager_ops ops;

    void *priv;
};

struct curvecpr_messager {
    struct curvecpr_messager_cf cf;

    /* CurveCP-Chicago decongestion algorithm stats. */
    struct curvecpr_chicago chicago;

    /* State tracking (local). */
    crypto_uint32 my_id;

    unsigned char my_eof;
    unsigned char my_final;

    size_t my_maximum_send_bytes;

    crypto_uint64 my_sent_bytes;
    long long my_sent_clock;

    /* State tracking (remote). */
    crypto_uint32 their_sent_id;

    unsigned char their_eof;
    unsigned char their_final;

    crypto_uint64 their_contiguous_sent_bytes;

    size_t their_total_bytes;
};

void curvecpr_messager_new (struct curvecpr_messager *messager, const struct curvecpr_messager_cf *cf, unsigned char client);
int curvecpr_messager_recv (struct curvecpr_messager *messager, const unsigned char *buf, size_t num);
int curvecpr_messager_process_sendq (struct curvecpr_messager *messager);
long long curvecpr_messager_next_timeout (struct curvecpr_messager *messager);

#endif
