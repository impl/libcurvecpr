#include "config.h"

#include "bytes.h"
#include "messager.h"
#include "messager_glib.h"

#include <errno.h>
#include <string.h>

#include <sodium/crypto_uint32.h>

#include <glib.h>

#define RECVMARKQ_ELEMENT_NONE 0
#define RECVMARKQ_ELEMENT_DISTRIBUTED (1 << 0)
#define RECVMARKQ_ELEMENT_ACKNOWLEDGED (1 << 1)
#define RECVMARKQ_ELEMENT_DONE (RECVMARKQ_ELEMENT_DISTRIBUTED | RECVMARKQ_ELEMENT_ACKNOWLEDGED)

struct _recvmarkq_element {
    struct curvecpr_block block;
    unsigned char status;
};

static gint _gs_compare_clock (gconstpointer a, gconstpointer b, gpointer unused)
{
    const struct curvecpr_block *block_a = a;
    const struct curvecpr_block *block_b = b;

    if (block_a->clock == block_b->clock)
        return 0;
    else
        return block_a->clock < block_b->clock ? -1 : 1;
}

static unsigned char _sendmarkq_is_full (struct curvecpr_messager *messager)
{
    struct curvecpr_messager_glib *mg = messager->cf.priv;

    gint len = g_sequence_get_length(mg->sendmarkq);

    return len >= 0 && (guint)len >= mg->cf.sendmarkq_maximum;
}

static int _sendq_head (struct curvecpr_messager *messager, struct curvecpr_block **block_stored)
{
    struct curvecpr_messager_glib *mg = messager->cf.priv;

    if (mg->sendq_head_exists) {
        *block_stored = &mg->sendq_head;
        return 0;
    }

    if (mg->pending_used || mg->pending_eof) {
        curvecpr_bytes_zero(&mg->sendq_head, sizeof(struct curvecpr_block));

        mg->sendq_head.eof = mg->pending_eof ? CURVECPR_BLOCK_EOF_SUCCESS : CURVECPR_BLOCK_STREAM;

        if (mg->pending) {
            int requested = mg->pending_used > mg->messager.my_maximum_send_bytes ? mg->messager.my_maximum_send_bytes : mg->pending_used;

            mg->sendq_head.data_len = requested;
            if (mg->pending_current + requested > mg->cf.pending_maximum) {
                /* Two reads, one from the end and one from the beginning. */
                int avail = mg->cf.pending_maximum - mg->pending_current;

                curvecpr_bytes_copy(mg->sendq_head.data, mg->pending + mg->pending_current, avail);
                curvecpr_bytes_copy(mg->sendq_head.data + avail, mg->pending, requested - avail);

                mg->pending_current = requested - avail;
            } else {
                /* Just one read at the end. */
                curvecpr_bytes_copy(mg->sendq_head.data, mg->pending + mg->pending_current, requested);

                mg->pending_current += requested;
            }

            mg->pending_used -= requested;
        }

        mg->sendq_head_exists = 1;
    }

    return -1;
}

static int _sendq_move_to_sendmarkq (struct curvecpr_messager *messager, const struct curvecpr_block *block, struct curvecpr_block **block_stored)
{
    struct curvecpr_messager_glib *mg = messager->cf.priv;

    struct curvecpr_block *new_block;

    if (!mg->sendq_head_exists || block != &mg->sendq_head) {
        /* NB: This is slow, but the clock has likely updated for this block. Good news
           is we should run into it as the first element of the sendmarkq or so. */
        GSequenceIter *it = g_sequence_get_begin_iter(mg->sendmarkq);
        for (; !g_sequence_iter_is_end(it); it = g_sequence_iter_next(it)) {
            if (g_sequence_get(it) == block) {
                g_sequence_sort_changed(it, _gs_compare_clock, NULL);
                break;
            }
        }

        return -1;
    }

    if (_sendmarkq_is_full(messager))
        return -1;

    new_block = g_slice_new(struct curvecpr_block);
    curvecpr_bytes_copy(new_block, block, sizeof(struct curvecpr_block));

    g_sequence_insert_sorted(mg->sendmarkq, new_block, _gs_compare_clock, NULL);

    mg->sendq_head_exists = 0;

    if (block_stored)
        *block_stored = new_block;

    return 0;
}

static int _sendmarkq_head (struct curvecpr_messager *messager, struct curvecpr_block **block_stored)
{
    struct curvecpr_messager_glib *mg = messager->cf.priv;

    GSequenceIter *it = g_sequence_get_begin_iter(mg->sendmarkq);
    if (g_sequence_iter_is_end(it))
        return -1;

    *block_stored = g_sequence_get(it);
    return 0;
}

static int _sendmarkq_get (struct curvecpr_messager *messager, crypto_uint32 acknowledging_id, struct curvecpr_block **block_stored)
{
    struct curvecpr_messager_glib *mg = messager->cf.priv;

    GSequenceIter *it = g_sequence_get_begin_iter(mg->sendmarkq);
    for (; !g_sequence_iter_is_end(it); it = g_sequence_iter_next(it)) {
        struct curvecpr_block *block = g_sequence_get(it);

        if (block->id == acknowledging_id) {
            *block_stored = block;
            return 0;
        }
    }

    return -1;
}

static int _sendmarkq_remove_range (struct curvecpr_messager *messager, unsigned long long start, unsigned long long end)
{
    struct curvecpr_messager_glib *mg = messager->cf.priv;

    GSequenceIter *it = g_sequence_get_begin_iter(mg->sendmarkq);
    while (!g_sequence_iter_is_end(it)) {
        struct curvecpr_block *block = g_sequence_get(it);
        GSequenceIter *candidate = it;

        /* Avoid any issues with g_sequence_remove() by updating the iterator
           beforehand. */
        it = g_sequence_iter_next(it);

        if (block->offset >= start && block->offset + block->data_len <= end)
            g_sequence_remove(candidate);
    }

    return 0;
}

static gint _gs_compare_range (gconstpointer a, gconstpointer b, gpointer unused)
{
    const struct _recvmarkq_element *element_a = a;
    const struct _recvmarkq_element *element_b = b;

    if (element_a->block.offset == element_b->block.offset) {
        if (element_a->block.data_len == element_b->block.data_len)
            return 0;
        else
            return element_a->block.data_len < element_b->block.data_len ? -1 : 1;
    } else {
        return element_a->block.offset < element_b->block.offset ? -1 : 1;
    }
}

static unsigned char _recvmarkq_is_full (struct curvecpr_messager *messager)
{
    struct curvecpr_messager_glib *mg = messager->cf.priv;

    gint len = g_sequence_get_length(mg->recvmarkq);

    return len >= 0 && (guint)len >= mg->cf.recvmarkq_maximum;
}

static int _recvmarkq_put (struct curvecpr_messager *messager, const struct curvecpr_block *block, struct curvecpr_block **block_stored)
{
    struct curvecpr_messager_glib *mg = messager->cf.priv;

    struct _recvmarkq_element *new_element;

    if (_recvmarkq_is_full(messager))
        return -1;

    new_element = g_slice_new(struct _recvmarkq_element);
    new_element->status = RECVMARKQ_ELEMENT_NONE;
    curvecpr_bytes_copy(&new_element->block, block, sizeof(struct curvecpr_block));

    g_sequence_insert_sorted(mg->recvmarkq, new_element, _gs_compare_range, NULL);

    /* Publish any received messages in sequential blocks. */
    {
        GSequenceIter *it = g_sequence_get_begin_iter(mg->recvmarkq);
        while (!g_sequence_iter_is_end(it)) {
            struct _recvmarkq_element *element = g_sequence_get(it);
            GSequenceIter *candidate = it;

            /* Avoid any issues with g_sequence_remove() by updating the iterator
               beforehand. */
            it = g_sequence_iter_next(it);

            if (element->block.offset <= mg->recvmarkq_distributed) {
                if (element->block.data_len > 0 && element->block.offset + element->block.data_len > mg->recvmarkq_distributed) {
                    crypto_uint64 idx = mg->recvmarkq_distributed - element->block.offset;
                    size_t len = element->block.data_len - idx;

                    mg->cf.ops.recv(mg, element->block.data + idx, len);
                    mg->recvmarkq_distributed += len;
                }

                if (element->block.eof != CURVECPR_BLOCK_STREAM) {
                    if (mg->cf.ops.finished)
                        mg->cf.ops.finished(mg, element->block.eof);
                }

                element->status |= RECVMARKQ_ELEMENT_DISTRIBUTED;

                /* If this element has been acknowledged and distributed, remove it. */
                if (element->status == RECVMARKQ_ELEMENT_DONE)
                    g_sequence_remove(candidate);
            } else {
                /* Since the blocks are sorted, nothing else will match after this. */
                break;
            }
        }
    }

    if (block_stored)
        *block_stored = &new_element->block;

    return 0;
}

static int _recvmarkq_get (struct curvecpr_messager *messager, unsigned int n, struct curvecpr_block **block_stored)
{
    struct curvecpr_messager_glib *mg = messager->cf.priv;

    unsigned int i = 0;

    GSequenceIter *it = g_sequence_get_begin_iter(mg->recvmarkq);
    for (;;) {
        struct _recvmarkq_element *element;

        if (g_sequence_iter_is_end(it))
            break;

        element = g_sequence_get(it);
        if (!(element->status & RECVMARKQ_ELEMENT_ACKNOWLEDGED)) {
            if (i == n) {
                *block_stored = &element->block;
                return 0;
            } else {
                ++i;
            }
        }

        it = g_sequence_iter_next(it);
    }

    return -1;
}

static int _recvmarkq_move_range_to_recvq (struct curvecpr_messager *messager, unsigned long long start, unsigned long long end)
{
    struct curvecpr_messager_glib *mg = messager->cf.priv;

    GSequenceIter *it = g_sequence_get_begin_iter(mg->recvmarkq);
    while (!g_sequence_iter_is_end(it)) {
        struct _recvmarkq_element *element = g_sequence_get(it);
        GSequenceIter *candidate = it;

        /* Avoid any issues with g_sequence_remove() by updating the iterator
           beforehand. */
        it = g_sequence_iter_next(it);

        if (element->block.offset >= start && element->block.offset + element->block.data_len <= end) {
            element->status |= RECVMARKQ_ELEMENT_ACKNOWLEDGED;

            if (element->status == RECVMARKQ_ELEMENT_DONE)
                g_sequence_remove(candidate);
        }
    }

    return 0;
}

static int _send (struct curvecpr_messager *messager, const unsigned char *buf, size_t num)
{
    struct curvecpr_messager_glib *mg = messager->cf.priv;

    return mg->cf.ops.send(mg, buf, num);
}

void curvecpr_messager_glib_new (struct curvecpr_messager_glib *mg, struct curvecpr_messager_glib_cf *cf, unsigned char client)
{
    struct curvecpr_messager_cf messager_cf = {
        .ops = {
            .sendq_head = _sendq_head,
            .sendq_move_to_sendmarkq = _sendq_move_to_sendmarkq,
     
            .sendmarkq_head = _sendmarkq_head,
            .sendmarkq_get = _sendmarkq_get,
            .sendmarkq_remove_range = _sendmarkq_remove_range,
            .sendmarkq_is_full = _sendmarkq_is_full,
     
            .recvmarkq_put = _recvmarkq_put,
            .recvmarkq_get = _recvmarkq_get,
            .recvmarkq_is_full = _recvmarkq_is_full,
            .recvmarkq_move_range_to_recvq = _recvmarkq_move_range_to_recvq,
     
            .send = _send
        },
        .priv = mg
    };

    curvecpr_bytes_zero(mg, sizeof(struct curvecpr_messager_glib));

    if (cf)
        curvecpr_bytes_copy(&mg->cf, cf, sizeof(struct curvecpr_messager_glib_cf));

    /* Initialize messager. */
    curvecpr_messager_new(&mg->messager, &messager_cf, client);

    /* Set up queues. */
    mg->pending_eof = CURVECPR_BLOCK_STREAM;
    mg->pending = NULL;
    mg->pending_current = mg->pending_next = mg->pending_used = 0;

    mg->sendq_head_exists = 0;

    mg->sendmarkq = g_sequence_new(g_free);

    mg->recvmarkq = g_sequence_new(g_free);
    mg->recvmarkq_distributed = 0;
}

void curvecpr_messager_glib_dealloc (struct curvecpr_messager_glib *mg)
{
    g_free(mg->pending);

    g_sequence_free(mg->sendmarkq);
    g_sequence_free(mg->recvmarkq);
}

int curvecpr_messager_glib_close (struct curvecpr_messager_glib *mg)
{
    if (mg->pending_eof)
        return -EINVAL;

    mg->pending_eof = 1;
    return 0;
}

int curvecpr_messager_glib_send (struct curvecpr_messager_glib *mg, const unsigned char *buf, size_t num)
{
    if (num == 0)
        return -EINVAL;
    if (mg->pending_eof)
        return -EINVAL;
    if (num > mg->cf.pending_maximum - mg->pending_used)
        return -ENOBUFS;

    if (!mg->pending)
        mg->pending = g_malloc(mg->cf.pending_maximum);

    if (mg->pending_next + num > mg->cf.pending_maximum) {
        /* Two writes; one at the end and one at the beginning. */
        int avail = mg->cf.pending_maximum - mg->pending_next;

        curvecpr_bytes_copy(mg->pending + mg->pending_next, buf, avail);
        curvecpr_bytes_copy(mg->pending, buf + avail, num - avail);

        mg->pending_next = num - avail;
    } else {
        /* Just one write at the end. */
        curvecpr_bytes_copy(mg->pending + mg->pending_next, buf, num);

        mg->pending_next += num;
    }

    mg->pending_used += num;

    return 0;
}

int curvecpr_messager_glib_recv (struct curvecpr_messager_glib *mg, const unsigned char *buf, size_t num)
{
    return curvecpr_messager_recv(&mg->messager, buf, num);
}

int curvecpr_messager_glib_process_sendq (struct curvecpr_messager_glib *mg)
{
    return curvecpr_messager_process_sendq(&mg->messager);
}

long long curvecpr_messager_glib_next_timeout (struct curvecpr_messager_glib *mg)
{
    return curvecpr_messager_next_timeout(&mg->messager);
}
