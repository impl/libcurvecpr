#include <check.h>
#include <check_extras.h>

#include <curvecpr/messager.h>
#include <curvecpr/bytes.h>

#include <stdlib.h>


#define ARRAY_LENGTH(x)  (sizeof(x) / sizeof((x)[0]))



struct block_container {
    size_t size;
    struct curvecpr_block blocks[500];
};

struct packet {
    long long delivery_time;
    char delivered;
    size_t data_len;
    unsigned char data[1088+96];
};

struct packet_container {
    size_t size;
    struct packet packets[500];
};

struct test_helper {
    /* Sorted by offset */
    struct block_container sendq;
    
    /* These are not sorted. */
    struct block_container sendmarkq;
    struct block_container recvmarkq;
    
    size_t send_offset;
    
    /* Used to assemble the stream, all received packets are stored in here */
    struct block_container allrecv;
    
    /* The data coming in through the send() callback are temporarily stored 
       here before being delivered to the other party. Sorted by the time they
       should be delivered. */
    struct packet_container sent;
    
    /* When a packet is sent it is delayed by this many seconds. Wraps around
       when reaching the last entry. Non-positive means dropped packet. */
    double delivery_latencies[10];
    size_t next_index;
    size_t num_delivery_latencies;
    
    /* bool, is it client or server */
    char client;
    
    /* A pointer to the current time in milliseconds. */
    long long* now;
};


/************ Comparator functions *********/

static int order_by_clock (const void *aa, const void *bb)
{
    const struct curvecpr_block *a = aa;
    const struct curvecpr_block *b = bb;
    if (a->clock < b->clock)
        return -1;
    else if (a->clock > b->clock)
        return 1;
    else
        return 0;
}

static int order_by_offset (const void *aa, const void *bb)
{
    const struct curvecpr_block *a = aa;
    const struct curvecpr_block *b = bb;
    if (a->offset < b->offset)
        return -1;
    else if (a->offset > b->offset)
        return 1;
    else
        return 0;
}

static int order_by_delivery_time (const void *aa, const void *bb)
{
    long long a = ((const struct packet *)aa)->delivery_time;
    long long b = ((const struct packet *)bb)->delivery_time;
    if (a < b)
        return -1;
    else if (a > b)
        return 1;
    else
        return 0;
}

/************* Utility functions ***********/

static int remove_range (struct block_container *c, unsigned long long start, unsigned long long end)
{
    size_t i;
    for (i = 0; i < c->size; i++)
    {
        struct curvecpr_block *b = &c->blocks[i];
        if (start <= b->offset && b->offset < end)
        {
            unsigned long long offset = b->offset;
            size_t data_len = b->data_len;
            
            fail_if(end < start + data_len);

            *b = c->blocks[--c->size];

            if (start < offset) {
                remove_range(c, start, offset);
            }
            if (offset+data_len < end) {
                remove_range(c, offset+data_len, end);
            }
            return 0;
        }
    }
    return 1;
}

static void add_to_send_queue (struct curvecpr_messager *messager, const unsigned char *buf, size_t num)
{
    size_t data_len;
    size_t i;
    struct test_helper *helper = (struct test_helper*)messager->cf.priv;
    
    for (i = 0; i < num; i += messager->my_maximum_send_bytes)
    {
        fail_if(helper->sendq.size >= ARRAY_LENGTH(helper->sendq.blocks));
    
        struct curvecpr_block *b = &helper->sendq.blocks[helper->sendq.size++];
        data_len = num-i <= messager->my_maximum_send_bytes ? num-i : messager->my_maximum_send_bytes;
        helper->send_offset += data_len;

        b->offset = helper->send_offset;
        b->data_len = data_len;
        curvecpr_bytes_copy(b->data, buf+i, data_len);
    }
}

static size_t get_received_size (struct test_helper *helper)
{
    size_t i, size = 0;
    crypto_uint64 offset = 0;
    qsort(helper->allrecv.blocks, helper->allrecv.size, sizeof(struct curvecpr_block), &order_by_offset);
    for (i = 0; i < helper->allrecv.size; i++)
    {
        struct curvecpr_block *b = &helper->allrecv.blocks[i];
        fail_if(offset > b->offset);
        if (offset == b->offset) {
            size += b->data_len;
            offset += b->data_len;
        }
        else
            break;
    }
    return size;
}

/* buf must be able to hold size get_received_size() */
static void get_received_data (struct test_helper *helper, unsigned char *buf)
{
    size_t i;
    crypto_uint64 offset = 0;
    qsort(helper->allrecv.blocks, helper->allrecv.size, sizeof(struct curvecpr_block), &order_by_offset);
    for (i = 0; i < helper->allrecv.size; i++)
    {
        struct curvecpr_block *b = &helper->allrecv.blocks[i];
        fail_if(offset > b->offset);
        if (offset == b->offset)
        {
            curvecpr_bytes_copy(buf + offset, b->data, b->data_len);
            offset += b->data_len;
        }
        else
            break;
    }
}

/*************** Init functions ************/

static void test_helper_new (struct test_helper *helper, char client, long long *time_variable)
{
    curvecpr_bytes_zero(helper, sizeof(struct test_helper));
    helper->client = client;
    helper->now = time_variable;
}





/*************** Callbacks *****************/

static int sendq_head (struct curvecpr_messager *messager, struct curvecpr_block **block_stored)
{
    struct test_helper *helper = (struct test_helper*)messager->cf.priv;
    if (helper->sendq.size == 0)
        return 1;
    else
    {
        fail_if(block_stored == NULL);
        *block_stored = &helper->sendq.blocks[0];
        return 0;
    }
}

static int sendq_move_to_sendmarkq (struct curvecpr_messager *messager, const struct curvecpr_block *block, struct curvecpr_block **block_stored)
{
    struct test_helper *helper = (struct test_helper*)messager->cf.priv;
    size_t index;
    size_t num_after;
    
    if (block < &helper->sendq.blocks[0] || block >= &helper->sendq.blocks[helper->sendq.size])
        return 1;
    
    fail_if(helper->sendmarkq.size >= ARRAY_LENGTH(helper->sendmarkq.blocks));
    
    index = block - &helper->sendq.blocks[0];

    memcpy(&helper->sendmarkq.blocks[helper->sendmarkq.size++], block, sizeof(struct curvecpr_block));
    
    num_after = helper->sendq.size - index - 1;
    
    if (num_after > 0)
        memcpy(&helper->sendq.blocks[index], &helper->sendq.blocks[index+1], sizeof(struct curvecpr_block)*num_after);
    
    helper->sendq.size--;

    return 0;
}

static unsigned char sendq_is_empty (struct curvecpr_messager *messager)
{
    struct test_helper *helper = (struct test_helper*)messager->cf.priv;
    return helper->sendq.size == 0 ? 1 : 0;
}

static int sendmarkq_head (struct curvecpr_messager *messager, struct curvecpr_block **block_stored)
{
    struct test_helper *helper = (struct test_helper*)messager->cf.priv;
    if (helper->sendmarkq.size == 0)
        return 1;
    else {
        qsort(helper->sendmarkq.blocks, helper->sendmarkq.size, sizeof(struct curvecpr_block), &order_by_clock);
        fail_if(block_stored == NULL);
        *block_stored = &helper->sendmarkq.blocks[0];
        return 0;
    }
}

static int sendmarkq_get (struct curvecpr_messager *messager, crypto_uint32 acknowledging_id, struct curvecpr_block **block_stored)
{
    struct test_helper *helper = (struct test_helper*)messager->cf.priv;
    size_t i;
    for (i = 0; i < helper->sendmarkq.size; i++)
    {
        struct curvecpr_block *b = &helper->sendmarkq.blocks[i];
        if (b->id == acknowledging_id)
        {
            fail_if(block_stored == NULL);
            *block_stored = b;
            return 0;
        }
    }
    return 1;
}
    
static int sendmarkq_remove_range (struct curvecpr_messager *messager, unsigned long long start, unsigned long long end)
{
    struct test_helper *helper = (struct test_helper*)messager->cf.priv;
    return remove_range(&helper->sendmarkq, start, end);
}

static unsigned char sendmarkq_is_full (struct curvecpr_messager *messager)
{
    struct test_helper *helper = (struct test_helper*)messager->cf.priv;
    return helper->sendmarkq.size == ARRAY_LENGTH(helper->sendmarkq.blocks);
}

static int recvmarkq_put (struct curvecpr_messager *messager, const struct curvecpr_block *block, struct curvecpr_block **block_stored)
{
    struct test_helper *helper = (struct test_helper*)messager->cf.priv;
    if (helper->recvmarkq.size == ARRAY_LENGTH(helper->recvmarkq.blocks))
        return 1;
    else
    {
        size_t i;
        fail_if(helper->recvmarkq.size >= ARRAY_LENGTH(helper->recvmarkq.blocks));
        int already_received = 0;
        helper->recvmarkq.blocks[helper->recvmarkq.size] = *block;
        fail_if(block_stored == NULL);
        *block_stored = &helper->recvmarkq.blocks[helper->recvmarkq.size++];
        
        for (i = 0; i < helper->allrecv.size; i++)
        {
            if (helper->allrecv.blocks[i].offset == block->offset)
            {
                already_received = 1;
                break;
            }
        }
        if (!already_received)
        {
            fail_if(helper->allrecv.size >= ARRAY_LENGTH(helper->allrecv.blocks));
            helper->allrecv.blocks[helper->allrecv.size++] = *block;
        }
        
        return 0;
    }
}

static int recvmarkq_get_nth_unacknowledged (struct curvecpr_messager *messager, unsigned int n, struct curvecpr_block **block_stored)
{
    struct test_helper *helper = (struct test_helper*)messager->cf.priv;
    if (n >= helper->recvmarkq.size)
        return 1;
    else
    {
        qsort(helper->recvmarkq.blocks, helper->recvmarkq.size, sizeof(struct curvecpr_block), &order_by_offset);
        fail_if(block_stored == NULL);
        *block_stored = &helper->recvmarkq.blocks[n];
        return 0;
    }
}

static unsigned char recvmarkq_is_empty (struct curvecpr_messager *messager)
{
    struct test_helper *helper = (struct test_helper*)messager->cf.priv;
    if (helper->recvmarkq.size == 0)
        return 1;
    else
        return 0;
}

static int recvmarkq_remove_range (struct curvecpr_messager *messager, unsigned long long start, unsigned long long end)
{
    struct test_helper *helper = (struct test_helper*)messager->cf.priv;
    return remove_range(&helper->recvmarkq, start, end);
}

static int send (struct curvecpr_messager *messager, const unsigned char *buf, size_t num)
{
    struct test_helper *helper = (struct test_helper*)messager->cf.priv;
    struct packet* p = &helper->sent.packets[helper->sent.size];
    double latency = helper->delivery_latencies[helper->next_index++];
    helper->next_index %= helper->num_delivery_latencies;
    fail_if(helper->sent.size >= ARRAY_LENGTH(helper->sent.packets));
    
    if (latency >= 0)
    {
        p->delivery_time = *helper->now + (long long)(latency * 1000*1000*1000);
        p->data_len = num;
        curvecpr_bytes_copy(p->data, buf, num);
        helper->sent.size++;
        
        qsort(helper->sent.packets, helper->sent.size, sizeof(struct packet), order_by_delivery_time);
    }
    
    return 0;
}

static void put_next_timeout(struct curvecpr_messager *messager, const long long timeout_ns)
{
    // Not used
}

static long long get_nanoseconds(void *priv)
{
    struct test_helper *helper = (struct test_helper*)priv;
    return *helper->now;
}


/*************** test *****************/


struct curvecpr_messager_ops ops = {
        .sendq_head = &sendq_head,
        .sendq_move_to_sendmarkq = &sendq_move_to_sendmarkq,
        .sendq_is_empty = &sendq_is_empty,
        .sendmarkq_head = &sendmarkq_head,
        .sendmarkq_get = &sendmarkq_get,
        .sendmarkq_remove_range = &sendmarkq_remove_range,
        .sendmarkq_is_full = &sendmarkq_is_full,
        .recvmarkq_put = &recvmarkq_put,
        .recvmarkq_get_nth_unacknowledged = &recvmarkq_get_nth_unacknowledged,
        .recvmarkq_is_empty = &recvmarkq_is_empty,
        .recvmarkq_remove_range = &recvmarkq_remove_range,
        .send = &send,
        .put_next_timeout = &put_next_timeout,
        .get_nanoseconds = &get_nanoseconds
    };



static int are_all_queues_empty (const struct test_helper *helper)
{
    if (helper->sendq.size > 0 || helper->sendmarkq.size > 0 || helper->recvmarkq.size > 0 || helper->sent.size > 0)
        return 0;
    else
        return 1;
}

static long long min (long long a, long long b, long long c, long long d)
{
    long long ab = a < b ? a : b;
    long long cd = c < d ? c : d;
    return ab < cd ? ab : cd;
}

static void deliver_packet (struct test_helper *from, struct curvecpr_messager *recipient)
{
    struct packet *p;
    fail_if(from->sent.size == 0);
    from->sent.size--;
    p = &from->sent.packets[0];
    curvecpr_messager_recv(recipient, p->data, p->data_len);
    if (from->sent.size > 0)
        curvecpr_bytes_copy(&from->sent.packets[0], &from->sent.packets[0], from->sent.size * sizeof(struct packet));
}


#define DECLARE(name)                                                                         \
    struct test_helper *name ## _helper = malloc(sizeof(struct test_helper));                 \
    struct curvecpr_messager_cf name ## _cf = {                                               \
            .ops = ops,                                                                       \
            .priv = name ## _helper                                                           \
        };                                                                                    \
    struct curvecpr_messager name                                                             \
    
#define DELIVERY_LATENCY(name, values)                                                        \
    long long name ## _latencies[] = values;
    
#define INITIALIZE(name, client, latencies)                                                   \
    test_helper_new(name ## _helper, client, &now);                                           \
    fail_if(ARRAY_LENGTH(latencies) > ARRAY_LENGTH(name ## _helper->delivery_latencies));     \
    curvecpr_bytes_copy(name ## _helper->delivery_latencies, latencies, sizeof(latencies));   \
    name ## _helper->num_delivery_latencies = ARRAY_LENGTH(latencies);                        \
    curvecpr_messager_new(& name, & name ## _cf, client)                                      \

#define INFINITY 999999999999999999LL


START_TEST (test_delivery)
{
    DECLARE(server);
    DECLARE(client);
    
    long long now = 1000*1000*1000*1000LL;
    
    /* Non-positive means drop packet */
    double server_delivery_latencies[] = {0.1, 0.2, 0.4, 0.01, -1};
    double client_delivery_latencies[] = {0.5, 0.55, 0.1, -1, 0.1, 0.1, 0.2, 5};
 
    const int SEND_SIZE = 75*1000;
    unsigned char *send_data = malloc(SEND_SIZE);
    unsigned char *recv_data = malloc(SEND_SIZE);
    size_t i;
    
    INITIALIZE(server, 0, server_delivery_latencies);
    INITIALIZE(client, 1, client_delivery_latencies);
    
    for (i = 0; i < SEND_SIZE; i++)
        /* send_data = "aBcDeFgH..." */
        send_data[i] = 'a' + (char)(i%26) + (char)(('A'-'a') * (i%2));

    curvecpr_bytes_zero(recv_data, SEND_SIZE);
    
    add_to_send_queue(&client, send_data, sizeof(send_data));
    
    while (!(are_all_queues_empty(server_helper) && are_all_queues_empty(client_helper)))
    {
        long long server_timeout = now + curvecpr_messager_next_timeout(&server);
        long long client_timeout = now + curvecpr_messager_next_timeout(&client);
        long long server_delivery_timeout = server_helper->sent.size > 0 ?
                server_helper->sent.packets[0].delivery_time : INFINITY;
        long long client_delivery_timeout = client_helper->sent.size > 0 ?
                client_helper->sent.packets[0].delivery_time : INFINITY;
        
        long long timeout = min(server_timeout, client_timeout, server_delivery_timeout, client_delivery_timeout);
        fail_if(timeout < now);
        now = timeout;
        fail_if(now == INFINITY);
        
        if (now == server_timeout)
            curvecpr_messager_process_sendq(&server);
        else if (now == client_timeout)
            curvecpr_messager_process_sendq(&client);
        else if (now == server_delivery_timeout)
            deliver_packet(server_helper, &client);
        else if (now == client_delivery_timeout)
            deliver_packet(client_helper, &server);
    }
    
    fail_unless(get_received_size(server_helper) == sizeof(recv_data));
    get_received_data(server_helper, recv_data);
    fail_unless(curvecpr_bytes_equal(send_data, recv_data, sizeof(send_data)));
    
    free(server_helper);
    free(client_helper);
    free(send_data);
    free(recv_data);
}
END_TEST

RUN_TEST(test_delivery)
