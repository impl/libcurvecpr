#include "config.h"

#include <curvecpr/messager.h>

#include <curvecpr/block.h>
#include <curvecpr/bytes.h>
#include <curvecpr/chicago.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <sodium/crypto_uint16.h>
#include <sodium/crypto_uint32.h>
#include <sodium/crypto_uint64.h>

#define _STOP_SUCCESS 2048
#define _STOP_FAILURE 4096

#define _STOP (_STOP_SUCCESS + _STOP_FAILURE)

/* This is the wire format for a message. It's only used internally here. */
struct _message {
    unsigned char id[4];
    unsigned char acknowledging_id[4];
    unsigned char acknowledging_range_1_size[8];
    unsigned char acknowledging_range_12_gap[4];
    unsigned char acknowledging_range_2_size[2];
    unsigned char acknowledging_range_23_gap[2];
    unsigned char acknowledging_range_3_size[2];
    unsigned char acknowledging_range_34_gap[2];
    unsigned char acknowledging_range_4_size[2];
    unsigned char acknowledging_range_45_gap[2];
    unsigned char acknowledging_range_5_size[2];
    unsigned char acknowledging_range_56_gap[2];
    unsigned char acknowledging_range_6_size[2];
    unsigned char flags[2];
    unsigned char offset[8];
    /* Data follows. */
};

static crypto_uint32 _next_id (struct curvecpr_messager *messager)
{
    if (!++messager->my_id)
        ++messager->my_id;

    return messager->my_id;
}

void curvecpr_messager_new (struct curvecpr_messager *messager, const struct curvecpr_messager_cf *cf, unsigned char client)
{
    curvecpr_bytes_zero(messager, sizeof(struct curvecpr_messager));

    /* Initialize configuration. */
    if (cf)
        curvecpr_bytes_copy(&messager->cf, cf, sizeof(struct curvecpr_messager_cf));

    /* Initialize congestion handling. */
    curvecpr_chicago_new(&messager->chicago);

    /* If we're in client mode, initiate packets have a maximum size of 512 bytes.
       Otherwise, we're in server mode, and we can start at 1024. */
    messager->my_maximum_send_bytes = client ? 512 : 1024;
}

int curvecpr_messager_recv (struct curvecpr_messager *messager, const unsigned char *buf, size_t num)
{
    const struct curvecpr_messager_cf *cf = &messager->cf;

    const struct _message *message;
    const unsigned char *data;

    crypto_uint32 id, acknowledging_id;

    /* Minimum message length is 48 (which might be different than what we got from the
       server). The other two conditions shouldn't apply, but we'll check them anyway. */
    if (num < 48 || num > 1088 || num & 15)
        return -EINVAL;

    curvecpr_chicago_refresh_clock(&messager->chicago);

    message = (const struct _message *)buf;
    data = buf + sizeof(struct _message);

    id = curvecpr_bytes_unpack_uint32(message->id);
    acknowledging_id = curvecpr_bytes_unpack_uint32(message->acknowledging_id);

    /* Update decongestion. */
    if (acknowledging_id) {
        struct curvecpr_block *block = NULL;

        if (cf->ops.sendmarkq_get(messager, acknowledging_id, &block)) {
            /* The message couldn't be acknowledged (maybe out of range?). Only real
               consequence is we can't use it for timing data. */
        } else {
            if (block->clock)
                curvecpr_chicago_on_recv(&messager->chicago, block->clock);
        }
    }

    /* Try acknowledging ranges. */
    {
        unsigned long long start, end;

        /* Range 1. */
        start = 0;
        end = curvecpr_bytes_unpack_uint64(message->acknowledging_range_1_size);
        if (start - end > 0) {
            cf->ops.sendmarkq_remove_range(messager, start, end);

            /* If we're at EOF, see if we can move to a final state. */
            if (messager->my_eof && end >= messager->my_sent_bytes)
                messager->my_final = 1;
        }

        /* Range 2. */
        start = end + (unsigned long long)curvecpr_bytes_unpack_uint32(message->acknowledging_range_12_gap);
        end = start + (unsigned long long)curvecpr_bytes_unpack_uint16(message->acknowledging_range_2_size);
        if (start - end > 0)
            cf->ops.sendmarkq_remove_range(messager, start, end);

        /* Range 3. */
        start = end + (unsigned long long)curvecpr_bytes_unpack_uint16(message->acknowledging_range_23_gap);
        end = start + (unsigned long long)curvecpr_bytes_unpack_uint16(message->acknowledging_range_3_size);
        if (start - end > 0)
            cf->ops.sendmarkq_remove_range(messager, start, end);

        /* Range 4. */
        start = end + (unsigned long long)curvecpr_bytes_unpack_uint16(message->acknowledging_range_34_gap);
        end = start + (unsigned long long)curvecpr_bytes_unpack_uint16(message->acknowledging_range_4_size);
        if (start - end > 0)
            cf->ops.sendmarkq_remove_range(messager, start, end);

        /* Range 5. */
        start = end + (unsigned long long)curvecpr_bytes_unpack_uint16(message->acknowledging_range_45_gap);
        end = start + (unsigned long long)curvecpr_bytes_unpack_uint16(message->acknowledging_range_5_size);
        if (start - end > 0)
            cf->ops.sendmarkq_remove_range(messager, start, end);

        /* Range 6. */
        start = end + (unsigned long long)curvecpr_bytes_unpack_uint16(message->acknowledging_range_56_gap);
        end = start + (unsigned long long)curvecpr_bytes_unpack_uint16(message->acknowledging_range_6_size);
        if (start - end > 0)
            cf->ops.sendmarkq_remove_range(messager, start, end);
    }

    /* Read size and flags and dispatch data to delegate. */
    {
        struct curvecpr_block block, *stored_block;
        curvecpr_bytes_zero(&block, sizeof(struct curvecpr_block));

        unsigned short flags = curvecpr_bytes_unpack_uint16(message->flags);
        unsigned short stop = flags & _STOP;
        block.data_len = flags - stop;

        /* Sanity check. */
        if (block.data_len > 1024 || num < sizeof(struct _message) + block.data_len)
            return -EINVAL;

        /* Copy over flags. This might be the last item we'll ever receive. */
        if (stop & _STOP_FAILURE) block.eof = CURVECPR_BLOCK_EOF_FAILURE;
        else if (stop & _STOP_SUCCESS) block.eof = CURVECPR_BLOCK_EOF_SUCCESS;

        /* Range insertion point. */
        block.offset = curvecpr_bytes_unpack_uint64(message->offset);

        if (messager->their_eof && block.offset > messager->their_total_bytes)
            /* Ooh, naughty. Shouldn't be trying to send more data. */
            return -EINVAL;

        /* Since we've now received a valid packet, the maximum send size will be 1024
           (no more initiates). */
        messager->my_maximum_send_bytes = 1024;

        /* Copy data into the block. Because we zero-pad the message, we want to copy
           only the last bytes. */
        curvecpr_bytes_copy(block.data, data + (num - sizeof(struct _message) - block.data_len), block.data_len);

        /* Should we enqueue this block? Only if it isn't a pure acknowledgment. */
        if (id) {
            /* Keep track of the timestamp and ID for good measure. */
            block.id = id;
            block.clock = messager->chicago.clock;

            /* Enqueue the data if possible. This would fail if the queue being used to
               store the data is full. */
            if (cf->ops.recvmarkq_put(messager, &block, &stored_block))
                return -EAGAIN;
        } else {
            stored_block = &block;
        }

        /* Successfully enqueued; update statistics. */
        if (stored_block->eof != CURVECPR_BLOCK_STREAM) {
            messager->their_eof = 1;
            messager->their_total_bytes = stored_block->offset + stored_block->data_len;
        }
    }

    /* Update acknowledgment information (but only if this isn't a pure
       acknowledgment). */
    if (id) {
        int r;

        /* Next acknowledgment should be to this message ID, regardless of what ranges we
           acknowledge (for decongestion purposes). */
        messager->their_sent_id = id;

        /* We might have just filled up the outgoing acknowledgment (recvmark) queue, so
           go ahead and process outgoing messages. */
        r = curvecpr_messager_process_sendq(messager);

        if (r && r != -EAGAIN)
            /* XXX: Is this really the behavior we want? */
            return r;
    }

    return 0;
}

static int _send_block (struct curvecpr_messager *messager, struct curvecpr_block *block)
{
    const struct curvecpr_messager_cf *cf = &messager->cf;

    unsigned char data[1088];
    struct _message *message = (struct _message *)data;

    size_t num;

    crypto_uint32 id = 0;

    struct { unsigned char exists; crypto_uint64 start; crypto_uint64 end; } acknowledgment_ranges[6] = { { .exists = 0, .start = 0, .end = 0 } };

    /* NB: It is perfectly acceptable for block to be null in this function. */

    /* Verify block length is acceptable. */
    if (block && block->data_len > messager->my_maximum_send_bytes)
        return -EINVAL;

    /* How long should this message be? */
    num = sizeof(struct _message) + (block ? block->data_len : 0);
    if (num <= 192) num = 192;
    else if (num <= 320) num = 320;
    else if (num <= 576) num = 576;
    else if (num <= 1088) num = 1088;

    curvecpr_bytes_zero(data, num);

    /* Write message ID unless this is purely an acknowledgment. */
    if (block) {
        id = _next_id(messager);
        curvecpr_bytes_pack_uint32(message->id, id);
    }

    /* Write decongestion (message ID) acknowledgment. */
    if (messager->their_sent_id)
        curvecpr_bytes_pack_uint32(message->acknowledging_id, messager->their_sent_id);

    /* Write range acknowledgments. */
    {
        struct curvecpr_block *received_block = NULL;
        int block_num = 0, i = 0;

        crypto_uint64 check = messager->their_contiguous_sent_bytes;
        unsigned long long maximum_gap = UINT32_MAX;

        for (;;) {
            if (cf->ops.recvmarkq_get_nth_unacknowledged(messager, block_num++, &received_block))
                break;

            acknowledgment_ranges[i].exists = 1;

            if (received_block->offset > check) {
                acknowledgment_ranges[i].end = check;

                if (!(i < 5))
                    /* Can't fit any more acknowledgments in this message. */
                    break;
                else if (received_block->offset - check > maximum_gap)
                    /* Gap is too large... need more packets! */
                    break;

                i++;
                acknowledgment_ranges[i].exists = 1;
                acknowledgment_ranges[i].start = received_block->offset;
                acknowledgment_ranges[i].end = received_block->offset + received_block->data_len;

                maximum_gap = UINT16_MAX;
            } else {
                crypto_uint64 received_block_end = received_block->offset + received_block->data_len;

                acknowledgment_ranges[i].end = check > received_block_end ? check : received_block_end;
            }

            check = acknowledgment_ranges[i].end;
        }

        if (acknowledgment_ranges[0].exists) {
            /* Sanity check: if we're at EOF and the first range completely covers the total
               number of bytes sent, then it must be the only range. */
            if (messager->their_eof && acknowledgment_ranges[0].end >= messager->their_total_bytes) {
                if (i != 0)
                    return -EPROTO; /* Should never happen! */

                /* Include their EOF in the range size (total stream size). */
                ++acknowledgment_ranges[0].end;
            }

            curvecpr_bytes_pack_uint64(message->acknowledging_range_1_size, (crypto_uint64)acknowledgment_ranges[0].end);
        }

        if (acknowledgment_ranges[1].exists) {
            curvecpr_bytes_pack_uint32(message->acknowledging_range_12_gap, (crypto_uint32)(acknowledgment_ranges[1].start - acknowledgment_ranges[0].end));
            curvecpr_bytes_pack_uint16(message->acknowledging_range_2_size, (crypto_uint16)(acknowledgment_ranges[1].end - acknowledgment_ranges[1].start));
        }

        if (acknowledgment_ranges[2].exists) {
            curvecpr_bytes_pack_uint16(message->acknowledging_range_23_gap, (crypto_uint16)(acknowledgment_ranges[2].start - acknowledgment_ranges[1].end));
            curvecpr_bytes_pack_uint16(message->acknowledging_range_3_size, (crypto_uint16)(acknowledgment_ranges[2].end - acknowledgment_ranges[2].start));
        }

        if (acknowledgment_ranges[3].exists) {
            curvecpr_bytes_pack_uint16(message->acknowledging_range_34_gap, (crypto_uint16)(acknowledgment_ranges[3].start - acknowledgment_ranges[2].end));
            curvecpr_bytes_pack_uint16(message->acknowledging_range_4_size, (crypto_uint16)(acknowledgment_ranges[3].end - acknowledgment_ranges[3].start));
        }

        if (acknowledgment_ranges[4].exists) {
            curvecpr_bytes_pack_uint16(message->acknowledging_range_45_gap, (crypto_uint16)(acknowledgment_ranges[4].start - acknowledgment_ranges[3].end));
            curvecpr_bytes_pack_uint16(message->acknowledging_range_5_size, (crypto_uint16)(acknowledgment_ranges[4].end - acknowledgment_ranges[4].start));
        }

        if (acknowledgment_ranges[5].exists) {
            curvecpr_bytes_pack_uint16(message->acknowledging_range_56_gap, (crypto_uint16)(acknowledgment_ranges[5].start - acknowledgment_ranges[4].end));
            curvecpr_bytes_pack_uint16(message->acknowledging_range_6_size, (crypto_uint16)(acknowledgment_ranges[5].end - acknowledgment_ranges[5].start));
        }
    }

    if (block) {
        /* Write flags and size. */
        crypto_uint16 flags = (crypto_uint16)block->data_len;

        if (block->eof == CURVECPR_BLOCK_EOF_FAILURE) flags |= _STOP_FAILURE;
        else if (block->eof == CURVECPR_BLOCK_EOF_SUCCESS) flags |= _STOP_SUCCESS;

        curvecpr_bytes_pack_uint16(message->flags, flags);

        /* Write block position. */
        if (block->clock) {
            /* Block has already been sent. */
            curvecpr_bytes_pack_uint64(message->offset, block->offset);
        } else {
            /* Block hasn't been sent yet; give it the next available offset. */
            curvecpr_bytes_pack_uint64(message->offset, messager->my_sent_bytes);
        }

        /* Copy the block into the message. */
        curvecpr_bytes_copy(data + num - block->data_len, block->data, block->data_len);
    } else if (!messager->their_sent_id && !acknowledgment_ranges[0].exists) {
        /* We have absolutely nothing to send... */
        return -EAGAIN;
    }

    if (cf->ops.send(messager, data, num))
        return -EINVAL;

    if (block) {
        /* We only want to move the message to the pending-acknowledgment queue if this
           isn't a retry. */
        unsigned char resend = block->clock > 0;

        /* Set the ID. */
        block->id = id;

        /* Set the block clock to the current time. */
        block->clock = messager->chicago.clock;

        if (!resend) {
            /* Pass along the offset as well if this is a new message. */
            block->offset = messager->my_sent_bytes;

            if (block->eof != CURVECPR_BLOCK_STREAM)
                messager->my_eof = 1;

            messager->my_sent_bytes += block->data_len;
        } else {
            /* This is a retransmission, meaning we didn't receive an acknowledgment in
               quite some time. */
            curvecpr_chicago_on_timeout(&messager->chicago);
        }

        if (cf->ops.sendq_move_to_sendmarkq(messager, block, NULL)) {
            /* This could fail if the message has already been sent (i.e., it was already
               moved to the to-be-marked queue), but we must call it any time block is
               sent because it could fail for any other arbitrary reason as well and need
               to be reinvoked. */
        }
    }

    /* Remove all the acknowledged ranges from the pending queue. */
    {
        int i;

        for (i = 0; i < 6 && acknowledgment_ranges[i].exists; ++i)
            cf->ops.recvmarkq_remove_range(messager, acknowledgment_ranges[i].start, acknowledgment_ranges[i].end);

    }

    if (acknowledgment_ranges[0].exists)
        messager->their_contiguous_sent_bytes = acknowledgment_ranges[0].end;

    /* The remote side is in a final state if we've acknowledged their EOF. */
    if (messager->their_eof && messager->their_contiguous_sent_bytes >= messager->their_total_bytes)
        messager->their_final = 1;

    /* Update the last sent time for timeout calcuations. */
    messager->my_sent_clock = messager->chicago.clock;

    /* Reset last received ID so we don't acknowledge an old message. */
    messager->their_sent_id = 0;

    return 0;
}

int curvecpr_messager_process_sendq (struct curvecpr_messager *messager)
{
    const struct curvecpr_messager_cf *cf = &messager->cf;
    struct curvecpr_chicago *chicago = &messager->chicago;

    unsigned char acknowledge = 0, bytes = 0;
    struct curvecpr_block *block = NULL;

    curvecpr_chicago_refresh_clock(chicago);

    /* Should we send a block? */
    if (!cf->ops.recvmarkq_is_empty(messager))
        /* Always acknowledge any received data immediately -- not doing so messes up the
           RTT calculations for flow control. */
        acknowledge = 1;

    if (chicago->clock >= messager->my_sent_clock + chicago->wr_rate)
        /* Clock time is up! */
        bytes = 1;
    if (cf->ops.sendmarkq_is_full(messager))
        /* But the pending-acknowledgment queue is full, so we have to wait for the other
           side to reply before we send anything else. */
        bytes = 0;

    if (!acknowledge && !bytes)
        return -EAGAIN;

    /* OK, we should. Maybe we have a block that needs to be resent? */
    if (cf->ops.sendmarkq_head(messager, &block)) {
        /* No block to send here. */
    } else {
        if (chicago->clock >= block->clock + chicago->rtt_timeout)
            /* Timeout! Resend this block. */
            return _send_block(messager, block);
    }

    /* Do we have a new block that we can send instead? (If we're at EOF, we won't even
       bother checking). */
    if (bytes && !messager->my_eof) {
        if (cf->ops.sendq_head(messager, &block)) {
            /* No block to send here, either. */
        } else {
            /* New block! */
            return _send_block(messager, block);
        }
    }

    /* We've got nothing, so just send acknowledgments. */
    return _send_block(messager, NULL);
}

long long curvecpr_messager_next_timeout (struct curvecpr_messager *messager)
{
    const struct curvecpr_messager_cf *cf = &messager->cf;
    struct curvecpr_chicago *chicago = &messager->chicago;

    struct curvecpr_block *block = NULL;

    long long at;

    curvecpr_chicago_refresh_clock(chicago);

    at = chicago->clock + 60000000000LL; /* 60 seconds. */

    if (!cf->ops.sendmarkq_is_full(messager)) {
        /* If we have pending data, we might write it. */
        if (!cf->ops.sendq_is_empty(messager)) {
            /* Write at the write rate. */
            if (at > messager->my_sent_clock + chicago->wr_rate)
                at = messager->my_sent_clock + chicago->wr_rate;
        }
    }

    /* If we have a sent block, we might trigger too. */
    if (cf->ops.sendmarkq_head(messager, &block)) {
        /* No earliest block. */
    } else {
        if (at > block->clock + chicago->rtt_timeout)
            at = block->clock + chicago->rtt_timeout;
    }

    /* If the current time is after the next action time, the timeout is 0. However, we
       always have at least a 1 millisecond timeout to prevent the CPU from spinning. */
    if (chicago->clock > at)
        return 1000000;
    else
        return at - chicago->clock + 1000000;
}
