#include <check.h>
#include <check_extras.h>

#include <curvecpr/messager.h>

static struct curvecpr_block static_block = {
    .id = 0,
    .clock = 0,
    .eof = CURVECPR_BLOCK_STREAM,
    .data_len = 7,
    .data = "Hello!"
};

static unsigned char t_q_is_full (struct curvecpr_messager *messager)
{
    return 0;
}

static unsigned char t_q_is_empty (struct curvecpr_messager *messager)
{
    return 1;
}

static int t_recvmarkq_get_nth_unacknowledged (struct curvecpr_messager *messager, unsigned int n, struct curvecpr_block **block_stored)
{
    return 1;
}

static int t_sendmarkq_head (struct curvecpr_messager *messager, struct curvecpr_block **block_stored)
{
    return 1;
}

static int t_sendq_head (struct curvecpr_messager *messager, struct curvecpr_block **block_stored)
{
    int *send_counter = (int *) messager->cf.priv;
    if (*send_counter < 2) {
        *block_stored = &static_block;
        return 0;
    }

    return 1;
}

static int t_send (struct curvecpr_messager *messager, const unsigned char *buf, size_t num)
{
    return 0;
}

static int t_sendq_move_to_sendmarkq (struct curvecpr_messager *messager, const struct curvecpr_block *block, struct curvecpr_block **block_stored)
{
    int *send_counter = (int *) messager->cf.priv;
    (*send_counter)++;

    if (*send_counter < 2) {
        return 1;
    } else {
        *send_counter = -1;
        return 0;
    }
}

START_TEST (test_send_with_1_failure_moves_message_from_sendq)
{
    int send_counter = 0;

    struct curvecpr_messager messager;
    struct curvecpr_messager_cf cf = {
        .ops = {
            .sendmarkq_is_full = t_q_is_full,
            .recvmarkq_is_empty = t_q_is_empty,
            .recvmarkq_get_nth_unacknowledged = t_recvmarkq_get_nth_unacknowledged,
            .sendmarkq_head = t_sendmarkq_head,
            .sendq_head = t_sendq_head,
            .send = t_send,
            .sendq_move_to_sendmarkq = t_sendq_move_to_sendmarkq
        },
        .priv = &send_counter
    };

    curvecpr_messager_new(&messager, &cf, 1);

    /* Try sending once. */
    curvecpr_messager_process_sendq(&messager);

    fail_unless(send_counter == 1);
    messager.my_sent_clock = 0;

    /* Try sending again. */
    curvecpr_messager_process_sendq(&messager);

    fail_unless(send_counter == -1);
}
END_TEST

RUN_TEST (test_send_with_1_failure_moves_message_from_sendq)
