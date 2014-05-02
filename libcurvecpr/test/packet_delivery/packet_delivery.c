#include <check.h>
#include <check_extras.h>

#include <curvecpr/client.h>
#include <curvecpr/server.h>
#include <curvecpr/bytes.h>
#include <curvecpr/util.h>

#include <sodium/crypto_box.h>
#include <sodium/randombytes.h>
#include <sodium/crypto_hash_sha512.h>


const unsigned char server_extension[16] = {16,16,16,16,17,17,17,17,18,18,18,18,19,19,19,19};
const unsigned char client_extension[16] = {20,20,20,20,21,21,21,21,22,22,22,22,23,23,23,23};
const char domain_name[] = "www.example.com";



/* Holds client, server, and data set and read by the ops callbacks in curvecpr_client_cf and curvecpr_server_cf */
struct test_helper {

    struct curvecpr_server server;
    struct curvecpr_client client;


    /* Last decrypted message received by server and client, respectively. */
    unsigned char server_recv[1088];
    size_t server_recv_size;
    int num_server_recv;
    
    unsigned char client_recv[1088];
    size_t client_recv_size;
    int num_client_recv;


    /* Encrypted packet on route between server and client or vice versa. */
    unsigned char transmission[1184];
    size_t transmission_size;

    /* Increased each time server or client sends a packet */
    int num_server_sent;
    int num_client_sent;

    
    struct curvecpr_session sessions[2];
    int num_sessions;
};



/********* Client callbacks ***********/


static int client_send (struct curvecpr_client *client, const unsigned char *buf, size_t num)
{
    struct test_helper *t;

    fail_unless(client);
    fail_unless(buf);

    t = client->cf.priv;
    fail_unless(t);

    fail_if(num > sizeof(t->transmission));
    fail_if(num > 96 + 1088);
    fail_if(num < 96 + 16);
    fail_unless(num % 16 == 0);
    
    curvecpr_bytes_copy(t->transmission, buf, num);
    t->transmission_size = num;
    t->num_client_sent++;
    
    return 0;
}

static int client_recv (struct curvecpr_client *client, const unsigned char *buf, size_t num)
{
    struct test_helper *t;
    
    fail_unless(client);
    fail_unless(buf);

    t = client->cf.priv;
    fail_if(num > sizeof(t->client_recv));

    curvecpr_bytes_copy(t->client_recv, buf, num);
    t->client_recv_size = num;
    t->num_client_recv++;
    
    return 0;
}

static int client_next_nonce (struct curvecpr_client *client, unsigned char *destination, size_t num)
{
    fail_if(num != 16);
    randombytes(destination, num);
    return 0;
}


/********* Server callbacks ***********/

static int server_put_session (struct curvecpr_server *server, const struct curvecpr_session *s, void *priv, struct curvecpr_session **s_stored)
{
    struct test_helper *t;

    fail_unless(server);
    fail_unless(s);
    fail_unless(s_stored);
    
    t = server->cf.priv;
    fail_unless(t);
    
    for (int i = 0; i < t->num_sessions; i++)
    {
        fail_if(curvecpr_bytes_equal(t->sessions[i].their_session_pk, s->their_session_pk, 32));
    }
    
    fail_unless(t->num_sessions < (int)(sizeof(t->sessions)/sizeof(t->sessions[0])));
    
    curvecpr_bytes_copy(&t->sessions[t->num_sessions], s, sizeof(struct curvecpr_session));
    *s_stored = &t->sessions[t->num_sessions];
    t->num_sessions++;
    
    return 0;
}

static int server_get_session(struct curvecpr_server *server, const unsigned char their_session_pk[32], struct curvecpr_session **s_stored)
{
    struct test_helper *t;

    fail_unless(server);
    fail_unless(s_stored);
    
    t = server->cf.priv;
    fail_unless(t);

    for (int i = 0; i < t->num_sessions; i++)
    {
        if (curvecpr_bytes_equal(t->sessions[i].their_session_pk, their_session_pk, 32))
        {
            *s_stored = &t->sessions[i];
            return 0;
        }
    }
    
    return 1;
}

static int server_send (struct curvecpr_server *server, struct curvecpr_session *s, void *priv, const unsigned char *buf, size_t num)
{
    struct test_helper *t;

    fail_unless(server);
    fail_unless(buf);

    t = server->cf.priv;
    fail_unless(t);

    fail_if(num > sizeof(t->transmission));
    fail_if(num > 64 + 1088);
    fail_if(num < 64 + 16);
    fail_unless(num == 200 /* cookie packet is special case */ || num % 16 == 0);

    curvecpr_bytes_copy(t->transmission, buf, num);
    t->transmission_size = num;
    t->num_server_sent++;

    return 0;
}

static int server_recv (struct curvecpr_server *server, struct curvecpr_session *s, void *priv, const unsigned char *buf, size_t num)
{
    struct test_helper *t;
    
    fail_unless(server);
    fail_unless(s);
    fail_unless(buf);

    t = server->cf.priv;
    fail_if(num > sizeof(t->server_recv));

    curvecpr_bytes_copy(t->server_recv, buf, num);
    t->server_recv_size = num;
    t->num_server_recv++;
    
    return 0;

}

static int server_next_nonce (struct curvecpr_server *server, unsigned char *destination, size_t num)
{
    fail_if(num != 16);
    randombytes(destination, num);
    return 0;
}



/********* Initialization functions ************/

static void new_client (struct curvecpr_client *client, const unsigned char server_pk[32], void *priv)
{
    unsigned char client_pk[32];
    unsigned char client_sk[32];
    crypto_box_keypair(client_pk, client_sk);

    struct curvecpr_client_cf client_cf = {
            .ops = {
                    .send = &client_send,
                    .recv = &client_recv,
                    .next_nonce = &client_next_nonce
                },
            .priv = priv
        };
    curvecpr_bytes_copy(client_cf.my_extension, client_extension, 16);
    curvecpr_bytes_copy(client_cf.my_global_pk, client_pk, 32);
    curvecpr_bytes_copy(client_cf.my_global_sk, client_sk, 32);
    curvecpr_bytes_copy(client_cf.their_extension, server_extension, 16);
    curvecpr_bytes_copy(client_cf.their_global_pk, server_pk, 32);
    curvecpr_util_encode_domain_name(client_cf.their_domain_name, domain_name);

    curvecpr_client_new(client, &client_cf);
}


static void new_server (struct curvecpr_server *server, void *priv)
{
    unsigned char server_pk[32];
    unsigned char server_sk[32];
    crypto_box_keypair(server_pk, server_sk);

    struct curvecpr_server_cf server_cf = {
            .ops = {
                    .put_session = &server_put_session,
                    .get_session = &server_get_session,
                    .send = &server_send,
                    .recv = &server_recv,
                    .next_nonce = &server_next_nonce
                },
            .priv = priv
        };
    curvecpr_bytes_copy(server_cf.my_extension, server_extension, 16);
    curvecpr_bytes_copy(server_cf.my_global_pk, server_pk, 32);
    curvecpr_bytes_copy(server_cf.my_global_sk, server_sk, 32);
    
    curvecpr_server_new(server, &server_cf);
}



static void new_test_helper (struct test_helper *t)
{
    new_server(&t->server, t);
    new_client(&t->client, t->server.cf.my_global_pk, t);

    curvecpr_bytes_zero(t->server_recv, sizeof(t->server_recv));
    t->server_recv_size = 0;
    t->num_server_recv = 0;

    curvecpr_bytes_zero(t->client_recv, sizeof(t->client_recv));
    t->client_recv_size = 0;
    t->num_client_recv = 0;

    curvecpr_bytes_zero(t->transmission, sizeof(t->transmission));
    t->transmission_size = 0;
    t->num_server_sent = 0;
    t->num_client_sent = 0;
    
    curvecpr_bytes_zero(t->sessions, sizeof(t->sessions));
    t->num_sessions = 0;
}



/********** Tests functions *********/

static size_t client_create_hello (struct test_helper *helper, unsigned char packet[2000])
{
    int num_client_sent = helper->num_client_sent;
    
    fail_unless(curvecpr_client_connected(&helper->client) == 0);
    fail_unless(helper->num_client_sent == num_client_sent+1);
    fail_unless(helper->transmission_size == 224);

    curvecpr_bytes_copy(packet, helper->transmission, helper->transmission_size);
    
    return helper->transmission_size;
}

static size_t server_receive_hello_and_create_cookie (struct test_helper *helper, unsigned char packet[2000], size_t size)
{
    int num_server_sent = helper->num_server_sent;
    int num_server_recv = helper->num_server_recv;
    int num_sessions = helper->num_sessions;

    fail_unless(size == 224);
    fail_unless(curvecpr_server_recv(&helper->server, 0, packet, size, 0) == 0);
    fail_unless(helper->num_server_recv == num_server_recv);
    fail_unless(helper->num_server_sent == num_server_sent+1);
    fail_unless(helper->transmission_size == 200);
    fail_unless(helper->num_sessions == num_sessions);
    
    curvecpr_bytes_copy(packet, helper->transmission, helper->transmission_size);
    
    return helper->transmission_size;
}

static void client_receive_cookie (struct test_helper *helper, unsigned char packet[2000], size_t size)
{
    fail_unless(size == 200);
    fail_unless(curvecpr_client_recv(&helper->client, packet, size) == 0);
    fail_unless(helper->num_client_recv == 0);
    fail_unless(helper->num_client_sent > 0);
}

static size_t client_send_initiate (struct test_helper* helper, unsigned char packet[2000], const void *message, size_t message_size)
{
    int num_client_sent = helper->num_client_sent;
    fail_unless(curvecpr_client_send(&helper->client, message, message_size) == 0);
    fail_unless(helper->num_client_sent == num_client_sent+1);
    fail_unless(helper->transmission_size == 544+message_size);

    curvecpr_bytes_copy(packet, helper->transmission, helper->transmission_size);

    return helper->transmission_size;
}

static void server_receive_initiate (struct test_helper *helper, unsigned char packet[2000], size_t size, const void *expected_message, size_t message_size)
{
    int num_server_recv = helper->num_server_recv;

    fail_unless(curvecpr_server_recv(&helper->server, 0, packet, size, 0) == 0);
    fail_unless(helper->num_server_recv == num_server_recv+1);
    fail_unless(helper->server_recv_size == message_size);
    fail_unless(curvecpr_bytes_equal(helper->server_recv, expected_message, message_size));
    fail_unless(helper->num_sessions == 1);
}

static size_t server_send_message (struct test_helper *helper, unsigned char packet[2000], const void *message, size_t message_size)
{
    int num_server_sent = helper->num_server_sent;
    fail_unless(num_server_sent >= 1);
    
    fail_unless(curvecpr_server_send(&helper->server, &helper->sessions[0], 0, (const unsigned char*)message, message_size) == 0);
    fail_unless(helper->num_server_sent = num_server_sent+1);
    fail_unless(helper->transmission_size == 64+message_size);
    
    curvecpr_bytes_copy(packet, helper->transmission, helper->transmission_size);

    return helper->transmission_size;
}

static void client_receive_message(struct test_helper *helper, unsigned char packet[2000], size_t size, const void *expected_message, size_t message_size) {
    fail_unless(curvecpr_client_recv(&helper->client, packet, size) == 0);
    fail_unless(helper->num_client_recv == 1);
    fail_unless(helper->client_recv_size == message_size);
    fail_unless(curvecpr_bytes_equal(helper->client_recv, expected_message, message_size));
}

static size_t client_send_message (struct test_helper *helper, unsigned char packet[2000], const void *message, size_t message_size)
{
    int packets_sent_before = helper->num_client_sent;
    
    /* Test code must send hello and initiate before sending normal message */
    fail_unless(packets_sent_before >= 2);

    fail_unless(curvecpr_client_send(&helper->client, message, message_size) == 0);

    fail_unless(helper->num_client_sent == packets_sent_before+1);
    fail_unless(helper->transmission_size == 96+message_size);

    curvecpr_bytes_copy(packet, helper->transmission, helper->transmission_size);

    return helper->transmission_size;
}

static void server_receive_message (struct test_helper *helper, unsigned char packet[2000], size_t size, const void *expected_message, size_t message_size)
{
    int packets_recv_before = helper->num_server_recv;
    
    fail_unless(curvecpr_server_recv(&helper->server, 0, packet, size, 0) == 0);
    fail_unless(helper->num_server_recv == packets_recv_before+1);
    fail_unless(helper->server_recv_size+96 == size);
}


/* Because of lazyness I rely on the inner workings of libcurvecpr here. Right
   now, nothing changes in the client nor server structs when receiving invalid
   messages. The code wouldn't necessarily be broken just because something 
   changed in those structs though, one could imagein adding a counter
   of invalid received packets or a last_error or something, which would 
   brake this code.
   Also note that the comparison is shallow, which works fine right now, but
   might brake if the structs get more complicated. */
static void server_fail_receive (struct test_helper *helper, unsigned char packet[2000], size_t size) {
    struct test_helper helper_copy;
    curvecpr_bytes_copy(&helper_copy, helper, sizeof(struct test_helper));

    fail_if(curvecpr_server_recv(&helper->server, 0, packet, size, 0) == 0);
    fail_unless(curvecpr_bytes_equal(&helper_copy, helper, sizeof(struct test_helper)));
}

static void client_fail_receive (struct test_helper *helper, unsigned char packet[2000], size_t size)
{
    struct test_helper helper_copy;
    curvecpr_bytes_copy(&helper_copy, helper, sizeof(struct test_helper));

    fail_if(curvecpr_client_recv(&helper->client, packet, size) == 0);
    fail_unless(curvecpr_bytes_equal(&helper_copy, helper, sizeof(struct test_helper)));
}



/********** Tests ************/


#define TEST_SETUP                           \
    unsigned char packet[2000];              \
    size_t size;                             \
    struct test_helper helper;               \
    new_test_helper(&helper);

#define TEST_MODIFY_SETUP                    \
    unsigned char modified_packet[2000];     \
    TEST_SETUP


START_TEST (test_normal_run)
{
    TEST_SETUP

    size = client_create_hello(&helper, packet);
    size = server_receive_hello_and_create_cookie(&helper, packet, size);
    client_receive_cookie(&helper, packet, size);

    size = client_send_initiate(&helper, packet, "Hello world!!!!", 16);
    server_receive_initiate(&helper, packet, size, "Hello world!!!!", 16);
    
    size = server_send_message(&helper, packet, "Hello world too", 16);
    client_receive_message(&helper, packet, size, "Hello world too", 16);

    size = client_send_message(&helper, packet, "Hello world 2!!", 16);
    server_receive_message(&helper, packet, size, "Hello world 2!!", 16);
}
END_TEST


START_TEST (test_all_initiate_message_sizes)
{
    unsigned char message[640];
    TEST_SETUP

    randombytes(message, sizeof(message));
    
    for (size_t i = 16; i <= 640; i += 16) {
        new_test_helper(&helper);
        size = client_create_hello(&helper, packet);
        size = server_receive_hello_and_create_cookie(&helper, packet, size);
        client_receive_cookie(&helper, packet, size);

        size = client_send_initiate(&helper, packet, message, i);
        server_receive_initiate(&helper, packet, size, message, i);
    }
}
END_TEST


START_TEST (test_all_server_message_sizes)
{
    unsigned char message[1088];
    TEST_SETUP
    
    randombytes(message, sizeof(message));
    
    for (size_t i = 16; i <= 1088; i += 16) {
        new_test_helper(&helper);
        size = client_create_hello(&helper, packet);
        size = server_receive_hello_and_create_cookie(&helper, packet, size);
        client_receive_cookie(&helper, packet, size);

        size = client_send_initiate(&helper, packet, message, 16);
        server_receive_initiate(&helper, packet, size, message, 16);

        size = server_send_message(&helper, packet, message, i);
        client_receive_message(&helper, packet, size, message, i);
    }
}
END_TEST


START_TEST (test_all_client_message_sizes)
{
    unsigned char message[1088];
    TEST_SETUP
    
    randombytes(message, sizeof(message));
    
    for (size_t i = 16; i <= 1088; i += 16) {
        new_test_helper(&helper);

        size = client_create_hello(&helper, packet);
        size = server_receive_hello_and_create_cookie(&helper, packet, size);
        client_receive_cookie(&helper, packet, size);

        size = client_send_initiate(&helper, packet, "Hello world!!!!", 16);
        server_receive_initiate(&helper, packet, size, "Hello world!!!!", 16);
        
        size = server_send_message(&helper, packet, "Hello world too", 16);
        client_receive_message(&helper, packet, size, "Hello world too", 16);

        size = client_send_message(&helper, packet, message, i);
        server_receive_message(&helper, packet, size, message, i);
    }
}
END_TEST


START_TEST (test_can_do_several_handshake_packets)
{
    /* Test lost packets during initial hand shaking */
    TEST_SETUP

    /* Hello gets lost */
    size = client_create_hello(&helper, packet);
    
    /* Hello gets through but cookie packet reply gets lost */
    size = client_create_hello(&helper, packet);
    size = server_receive_hello_and_create_cookie(&helper, packet, size);
    
    /* Hello and cookie get through */
    size = client_create_hello(&helper, packet);
    size = server_receive_hello_and_create_cookie(&helper, packet, size);
    client_receive_cookie(&helper, packet, size);

    /* First message reply from server gets lost */
    size = client_send_initiate(&helper, packet, "Hello world!!!!", 16);
    server_receive_initiate(&helper, packet, size, "Hello world!!!!", 16);
    size = server_send_message(&helper, packet, "abcdefghijklmno", 16);
    
    /* Second initiate from client gets lost */
    size = client_send_initiate(&helper, packet, "Hello world 2!!", 16);
    
    /* Third time all packets get through */
    size = client_send_initiate(&helper, packet, "Hello world too", 16);
    server_receive_initiate(&helper, packet, size, "Hello world too", 16);
    size = server_send_message(&helper, packet, "Something else.", 16);
    client_receive_message(&helper, packet, size, "Something else.", 16);
}
END_TEST


START_TEST (test_reject_modified_hello_packet)
{
    TEST_MODIFY_SETUP
    
    size = client_create_hello(&helper, packet);
    
    /* Test modifying one byte */
    for (size_t i = 0; i < size; i++)
    {
        if (i >= 24 && i < 24+16)
            /* Client extension */
            continue;

        if (i >= 72 && i < 72+64)
            /* Non-verified zeros */
            continue;
        
        curvecpr_bytes_copy(modified_packet, packet, sizeof(modified_packet));
        modified_packet[i] ^= (i+1);
        server_fail_receive(&helper, modified_packet, size);
    }

    /* Test different message sizes */
    for (size_t i = 0; i < sizeof(modified_packet); i++)
    {
        if (i == 224)
            continue;
    
        server_fail_receive(&helper, packet, i);
    }

    
    server_receive_hello_and_create_cookie(&helper, packet, size);
}
END_TEST


START_TEST (test_reject_modified_cookie_packet)
{
    TEST_MODIFY_SETUP

    size = client_create_hello(&helper, packet);
    size = server_receive_hello_and_create_cookie(&helper, packet, size);

    /* Test modify one byte */
    for (size_t i = 0; i < size; i++)
    {
        curvecpr_bytes_copy(modified_packet, packet, sizeof(modified_packet));
        modified_packet[i] ^= (i+1);
        client_fail_receive(&helper, modified_packet, size);
    }
    
    /* Test different message sizes */
    for (size_t i = 0; i < sizeof(modified_packet); i++)
    {
        if (i == size)
            continue;

        client_fail_receive(&helper, packet, i);
    }
    
    client_receive_cookie(&helper, packet, size);
}
END_TEST


START_TEST (test_reject_modified_init_packet)
{
    TEST_MODIFY_SETUP

    size = client_create_hello(&helper, packet);
    size = server_receive_hello_and_create_cookie(&helper, packet, size);
    client_receive_cookie(&helper, packet, size);
    size = client_send_initiate(&helper, packet, "Hello world!!!!", 16);

    /* Test modify one byte */
    for (size_t i = 0; i < 544+16; i++)
    {
        if (i >= 24 && i < 40)
            /* Client extension */
            continue;
        
        curvecpr_bytes_copy(modified_packet, packet, sizeof(modified_packet));
        /* Do i/4 because i=255 or 511 would not change the packet otherwise. */
        modified_packet[i] ^= (i/4+1);
        server_fail_receive(&helper, modified_packet, size);
    }
    
    /* Test different message sizes */
    for (size_t i = 0; i < sizeof(modified_packet); i++)
    {
        if (i == 544+16)
            continue;
    
        server_fail_receive(&helper, packet, i);
    }
    
    server_receive_initiate(&helper, packet, size, "Hello world!!!!", 16);
}
END_TEST


START_TEST (test_client_reject_modified_message_packet)
{
    TEST_MODIFY_SETUP

    size = client_create_hello(&helper, packet);
    size = server_receive_hello_and_create_cookie(&helper, packet, size);
    client_receive_cookie(&helper, packet, size);
    size = client_send_initiate(&helper, packet, "Hello world!!!!", 16);
    server_receive_initiate(&helper, packet, size, "Hello world!!!!", 16);
    size = server_send_message(&helper, packet, "Hello world too", 16);
   
    /* Test modify one byte */
    for (size_t i = 0; i < 64+16; i++)
    {
        curvecpr_bytes_copy(modified_packet, packet, sizeof(modified_packet));
        modified_packet[i] ^= (i+1);
        client_fail_receive(&helper, modified_packet, size);
    }
    
    /* Test different message sizes */
    for (size_t i = 0; i < sizeof(modified_packet); i++)
    {
        if (i == 64+16)
            continue;
        
        client_fail_receive(&helper, packet, i);
    }
    
    client_receive_message(&helper, packet, size, "Hello world too", 16);
}
END_TEST


START_TEST (test_server_reject_modified_message_packet)
{
    TEST_MODIFY_SETUP

    size = client_create_hello(&helper, packet);
    size = server_receive_hello_and_create_cookie(&helper, packet, size);
    client_receive_cookie(&helper, packet, size);
    size = client_send_initiate(&helper, packet, "Hello world!!!!", 16);
    server_receive_initiate(&helper, packet, size, "Hello world!!!!", 16);
    size = server_send_message(&helper, packet, "Hello world too", 16);
    client_receive_message(&helper, packet, size, "Hello world too", 16);
    size = client_send_message(&helper, packet, "Hello world 2!!", 16);
    
    /* Test modify one byte */
    for (size_t i = 0; i < size; i++)
    {
        if (i >= 24 && i < 24+16)
            /* Client extension */
            continue;
    
        curvecpr_bytes_copy(modified_packet, packet, sizeof(modified_packet));
        modified_packet[i] ^= (i+1);
        server_fail_receive(&helper, modified_packet, size);
    }
    
    /* Test different message sizes */
    for (size_t i = 0; i < sizeof(modified_packet); i++)
    {
        if (i == size)
            continue;
        
        server_fail_receive(&helper, packet, i);
    }
    
    server_receive_message(&helper, packet, size, "Hello world 2!!", 16);
}
END_TEST


START_TEST (test_reject_modified_cookie)
{
    TEST_SETUP
    
    for (size_t i = 0; i < sizeof(helper.client.negotiated_cookie); i++)
    {
        new_test_helper(&helper);

        size = client_create_hello(&helper, packet);
        size = server_receive_hello_and_create_cookie(&helper, packet, size);
        client_receive_cookie(&helper, packet, size);

        helper.client.negotiated_cookie[i] ^= (unsigned char)(i+1);

        size = client_send_initiate(&helper, packet, "Hello world!!!!", 16);
        server_fail_receive(&helper, packet, size);
    }
}
END_TEST


START_TEST (test_reject_randomly_modified_vouch)
{
    TEST_SETUP
    
    for (size_t i = 0; i < sizeof(helper.client.negotiated_vouch); i++)
    {
        new_test_helper(&helper);

        size = client_create_hello(&helper, packet);
        size = server_receive_hello_and_create_cookie(&helper, packet, size);
        client_receive_cookie(&helper, packet, size);

        helper.client.negotiated_vouch[i] ^= (unsigned char)(i+1);

        size = client_send_initiate(&helper, packet, "Hello world!!!!", 16);
        server_fail_receive(&helper, packet, size);
    }
}
END_TEST


START_TEST (test_reject_vouch_containing_wrong_key)
{
    TEST_SETUP
    
    unsigned char nonce[24];
    
    unsigned char other_pk[32];
    unsigned char other_sk[32];
    
    unsigned char irrelevant_pk[32];
    unsigned char irrelevant_sk[32];

    unsigned char my_irrelevant_their_global_key[32];
    
    /* Generate another keypair and pretend we only know public key */
    crypto_box_keypair(other_pk, other_sk);
    curvecpr_bytes_zero(other_sk, sizeof(other_sk));

    /* This doesn't really matter, I just need a random secret key to do encryption */
    crypto_box_keypair(irrelevant_pk, irrelevant_sk);
    
    /* Do hello and cookie packets */
    size = client_create_hello(&helper, packet);
    size = server_receive_hello_and_create_cookie(&helper, packet, size);
    client_receive_cookie(&helper, packet, size);


    /* Replace the vouch with the session key encrypted and authenticated to 
       server's global key from irrelevant private key. */
    
    crypto_box_beforenm(my_irrelevant_their_global_key, helper.client.session.their_global_pk, irrelevant_sk);
    
    curvecpr_bytes_zero(helper.client.negotiated_vouch, 32);

    curvecpr_bytes_copy(helper.client.negotiated_vouch + 32, helper.client.session.my_session_pk, 32);

    curvecpr_bytes_copy(nonce, "CurveCPV", 8);
    randombytes(nonce+8, 16);
    
    crypto_box_afternm(helper.client.negotiated_vouch, helper.client.negotiated_vouch, 64, nonce, my_irrelevant_their_global_key);
    curvecpr_bytes_copy(helper.client.negotiated_vouch, nonce+8, 16);
    
    curvecpr_bytes_copy(helper.client.cf.my_global_pk, other_pk, 32);


    /* Send the packet with modified vouch and verify that the server won't accept it. */
    size = client_send_initiate(&helper, packet, "Hello world!!!!", 16);
    server_fail_receive(&helper, packet, size);
}
END_TEST


START_TEST (test_reject_replays)
{
    TEST_SETUP

    size = client_create_hello(&helper, packet);
    
    size = server_receive_hello_and_create_cookie(&helper, packet, size);
    
    client_receive_cookie(&helper, packet, size);
    client_fail_receive(&helper, packet, size);
    
    size = client_send_initiate(&helper, packet, "Hello world!!!!", 16);
    server_receive_initiate(&helper, packet, size, "Hello world!!!!", 16);
    server_fail_receive(&helper, packet, size);
    
    size = server_send_message(&helper, packet, "Hello world too", 16);
    client_receive_message(&helper, packet, size, "Hello world too", 16);
    client_fail_receive(&helper, packet, size);

    size = client_send_message(&helper, packet, "Hello world 2!!", 16);
    server_receive_message(&helper, packet, size, "Hello world 2!!", 16);
    server_fail_receive(&helper, packet, size);
}
END_TEST


START_TEST (test_1_minute_cookie_accepted)
{
    TEST_SETUP
    
    size = client_create_hello(&helper, packet);
    size = server_receive_hello_and_create_cookie(&helper, packet, size);
    client_receive_cookie(&helper, packet, size);
    size = client_send_initiate(&helper, packet, "Hello world!!!!", 16);

    /* "1 minute"... */
    curvecpr_server_refresh_temporal_keys(&helper.server);

    server_receive_initiate(&helper, packet, size, "Hello world!!!!", 16);
}
END_TEST


START_TEST (test_2_minute_cookie_rejected)
{
    TEST_SETUP
    
    size = client_create_hello(&helper, packet);
    size = server_receive_hello_and_create_cookie(&helper, packet, size);
    client_receive_cookie(&helper, packet, size);
    size = client_send_initiate(&helper, packet, "Hello world!!!!", 16);

    /* "2 minutes"... */
    curvecpr_server_refresh_temporal_keys(&helper.server);
    curvecpr_server_refresh_temporal_keys(&helper.server);

    server_fail_receive(&helper, packet, size);
}
END_TEST


/****************** Deterministic RNG ********************/
/* Use a deterministic random number generator during tests so we always test
   the same thing. UNDER NO CIRCUMSTANCES USE IN PRODUCTION */


static uint32_t seed = 0;

static const char *deterministic_rng_implementation_name (void)
{
    return "DeterministicTestRNG";
}

static void deterministic_rng_buf (void * const buf, const size_t size)
{
    unsigned char temp[64];
    size_t bytes_to_copy_this_iteration;
    size_t bytes_left = size;
    unsigned char *output = (unsigned char*)buf;


    /* Hopefully generates compiler error if this function ever ends up outside test code. */
    fail_unless(1);


    while (bytes_left > 0)
    {
        crypto_hash_sha512(temp, (const unsigned char*)&seed, sizeof(seed));
        seed++;
    
        bytes_to_copy_this_iteration = bytes_left < sizeof(temp) ? bytes_left : sizeof(temp);
        curvecpr_bytes_copy(output, temp, bytes_to_copy_this_iteration);
        bytes_left -= bytes_to_copy_this_iteration;
        output += bytes_to_copy_this_iteration;
    }
}

static uint32_t deterministic_rng_random (void)
{
    uint32_t r;
    deterministic_rng_buf(&r, sizeof(r));
    return r;
}

static void deterministic_rng_stir (void)
{
}

/* Copied from libsodium randombytes_sysrandom_uniform, which in turn
   is derived from OpenBSD */
static uint32_t deterministic_rng_uniform (const uint32_t upper_bound)
{
    uint32_t min;
    uint32_t r;

    if (upper_bound < 2) {
        return 0;
    }
    min = (uint32_t) (-upper_bound % upper_bound);
    for (;;) {
        r = deterministic_rng_random();
        if (r >= min) {
            break;
        }
    }
    return r % upper_bound;
}

static int deterministic_rng_close(void) {
    return 0;
}




/******************* main *****************/

#define ADD_TEST(fn) \
    TCase *tc_ ## fn = tcase_create(#fn);    \
    tcase_add_test(tc_ ## fn, (fn));         \
    suite_add_tcase(s, tc_ ## fn)

int main (void)                             
{
    struct randombytes_implementation rand_impl = {
        .implementation_name = &deterministic_rng_implementation_name,
        .random = &deterministic_rng_random,
        .stir = deterministic_rng_stir,
        .uniform = deterministic_rng_uniform,
        .buf = deterministic_rng_buf,
        .close = deterministic_rng_close
    };

    randombytes_set_implementation(&rand_impl);


    Suite *s = suite_create("packet_delivery");
                                            
    ADD_TEST(test_normal_run);
    
    ADD_TEST(test_all_initiate_message_sizes);
    ADD_TEST(test_all_server_message_sizes);
    ADD_TEST(test_all_client_message_sizes);
    
    ADD_TEST(test_can_do_several_handshake_packets);
    
    ADD_TEST(test_reject_modified_hello_packet);
    ADD_TEST(test_reject_modified_cookie_packet);
    ADD_TEST(test_reject_modified_init_packet);
    ADD_TEST(test_client_reject_modified_message_packet);
    ADD_TEST(test_server_reject_modified_message_packet);
    
    ADD_TEST(test_reject_modified_cookie);
    ADD_TEST(test_reject_randomly_modified_vouch);
    ADD_TEST(test_reject_vouch_containing_wrong_key);
    
    ADD_TEST(test_reject_replays);
    
    ADD_TEST(test_1_minute_cookie_accepted);
    ADD_TEST(test_2_minute_cookie_rejected);
    
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);         
    int failed = srunner_ntests_failed(sr); 
    srunner_free(sr);                       
                                            
    return failed ? 1 : 0;
}
