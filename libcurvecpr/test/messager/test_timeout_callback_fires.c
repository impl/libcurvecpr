#include <check.h>
#include <check_extras.h>

#include <curvecpr/messager.h>

long long test_timeout = -1LL;

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
    *block_stored = &static_block;
    return 0;
}

static int t_send (struct curvecpr_messager *messager, const unsigned char *buf, size_t num)
{
    return 0;
}

static int t_sendq_move_to_sendmarkq (struct curvecpr_messager *messager, const struct curvecpr_block *block, struct curvecpr_block **block_stored)
{
    return 0;
}

static void t_put_next_timeout (struct curvecpr_messager *messager, long long timeout)
{
    test_timeout = timeout;
}

START_TEST (test_timeout_callback_fires)
{
    struct curvecpr_messager messager;
    struct curvecpr_messager_cf cf = {
        .ops = {
            .sendq_is_empty = t_q_is_empty,
            .sendmarkq_is_full = t_q_is_full,
            .recvmarkq_is_empty = t_q_is_empty,
            .recvmarkq_get_nth_unacknowledged = t_recvmarkq_get_nth_unacknowledged,
            .sendmarkq_head = t_sendmarkq_head,
            .sendq_head = t_sendq_head,
            .send = t_send,
            .sendq_move_to_sendmarkq = t_sendq_move_to_sendmarkq,
            .put_next_timeout = t_put_next_timeout
        }
    };

    curvecpr_messager_new(&messager, &cf, 1);

    fail_unless(test_timeout >= 0);
    test_timeout = -1LL;

    curvecpr_messager_process_sendq(&messager);

    fail_unless(test_timeout >= 0);
}
END_TEST

RUN_TEST (test_timeout_callback_fires)
