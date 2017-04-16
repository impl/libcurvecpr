#ifndef __CURVECPR_MESSAGER_H
#define __CURVECPR_MESSAGER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "block.h"
#include "chicago.h"

#include <string.h>

#include <sodium/crypto_uint32.h>

struct curvecpr_messager;


/* The callbacks you need to implement to get a reliable stream transport.
   You need to implement the three data structures mentioned below.
   Terminology:
        sendq (send queue): The data waiting to get sent. When you want to send 
            something, you divide it into curvecpr_block:s (each at most 
            messager->my_maximum_send_bytes in size) and put it in this
            queue (you have to do this yourself). When you call 
            curvecpr_messager_process_sendq() it will check
            this queue for data ready to be sent. It might not happen
            immediately, but at a later invocation depending on the 
            decongestion algorithm and packets waiting to be resent etc.
        sendmarkq (sent-to-be-marked queue): When a curvecpr_block is sent
            (using the send() callback function), it is moved from sendq to
            sendmarkq (if it wasn't moved earlier and this is just a resend). 
            It waits here until it has been acknowledged by the recipient.
        recvmarkq (received-to-be-marked): Received curvecpr_block:s are stored
            here until we have sent an ACK (which happens right after they are
            stored actually). You need to assemble the stream data from this 
            data structure yourself.
 
*/
struct curvecpr_messager_ops {
    int (*sendq_head)(struct curvecpr_messager *messager, struct curvecpr_block **block_stored);
    int (*sendq_move_to_sendmarkq)(struct curvecpr_messager *messager, const struct curvecpr_block *block, struct curvecpr_block **block_stored);
    unsigned char (*sendq_is_empty)(struct curvecpr_messager *messager);

    /* The sent-to-be-marked queue (sendmarkq) is a priority queue of blocks ordered by
       the time at which they were last sent. */
    int (*sendmarkq_head)(struct curvecpr_messager *messager, struct curvecpr_block **block_stored);
    int (*sendmarkq_get)(struct curvecpr_messager *messager, crypto_uint32 acknowledging_id, struct curvecpr_block **block_stored);
    
    /* This is called for all ranges in incoming messages's acknowledge structure */
    int (*sendmarkq_remove_range)(struct curvecpr_messager *messager, unsigned long long start, unsigned long long end);
    unsigned char (*sendmarkq_is_full)(struct curvecpr_messager *messager);

    /* This is called once for each message coming in that is not a pure acknowledgement */
    int (*recvmarkq_put)(struct curvecpr_messager *messager, const struct curvecpr_block *block, struct curvecpr_block **block_stored);
    
    int (*recvmarkq_get_nth_unacknowledged)(struct curvecpr_messager *messager, unsigned int n, struct curvecpr_block **block_stored);
    unsigned char (*recvmarkq_is_empty)(struct curvecpr_messager *messager);
    int (*recvmarkq_remove_range)(struct curvecpr_messager *messager, unsigned long long start, unsigned long long end);

    int (*send)(struct curvecpr_messager *messager, const unsigned char *buf, size_t num);

    void (*put_next_timeout)(struct curvecpr_messager *messager, const long long timeout_ns);
    long long (*get_nanoseconds)(void *priv);
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

    /* The client can only send 512 bytes/message until we know that an 
        initiation packet has reached the server. Then this variable is raised 
        to 1024 bytes. The server can send 1024 bytes/message from the start. */
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
/* Call this function on timeout and when you have added things to sendq if it was empty. */
int curvecpr_messager_process_sendq (struct curvecpr_messager *messager);
long long curvecpr_messager_next_timeout (struct curvecpr_messager *messager);

#ifdef __cplusplus
}
#endif

#endif
