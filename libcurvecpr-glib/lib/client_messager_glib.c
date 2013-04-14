#include "config.h"

#include "bytes.h"
#include "client.h"
#include "client_messager_glib.h"
#include "messager_glib.h"

static int _client_send (struct curvecpr_client *client, const unsigned char *buf, size_t num)
{
    struct curvecpr_client_messager_glib *cmg = client->cf.priv;

    return cmg->cf.ops.send(cmg, buf, num);
}

static int _client_recv (struct curvecpr_client *client, const unsigned char *buf, size_t num)
{
    struct curvecpr_client_messager_glib *cmg = client->cf.priv;

    return curvecpr_messager_glib_recv(&cmg->mg, buf, num);
}

static int _client_next_nonce(struct curvecpr_client *client, unsigned char *destination, size_t num)
{
    struct curvecpr_client_messager_glib *cmg = client->cf.priv;

    return cmg->cf.ops.next_nonce(cmg, destination, num);
}

static int _messager_glib_send (struct curvecpr_messager_glib *mg, const unsigned char *buf, size_t num)
{
    struct curvecpr_client_messager_glib *cmg = mg->cf.priv;

    return curvecpr_client_send(&cmg->client, buf, num);
}

static int _messager_glib_recv (struct curvecpr_messager_glib *mg, const unsigned char *buf, size_t num)
{
    struct curvecpr_client_messager_glib *cmg = mg->cf.priv;

    return cmg->cf.ops.recv(cmg, buf, num);
}

static void _messager_glib_finished (struct curvecpr_messager_glib *mg, enum curvecpr_block_eofflag flag)
{
    struct curvecpr_client_messager_glib *cmg = mg->cf.priv;

    if (cmg->cf.ops.finished)
        cmg->cf.ops.finished(cmg, flag);
}

void curvecpr_client_messager_glib_new (struct curvecpr_client_messager_glib *cmg, struct curvecpr_client_messager_glib_cf *cf)
{
    struct curvecpr_client_cf client_cf = {
        .ops = {
            .send = _client_send,
            .recv = _client_recv,

            .next_nonce = _client_next_nonce
        },
        .priv = cmg
    };

    struct curvecpr_messager_glib_cf mg_cf = {
        .ops = {
            .send = _messager_glib_send,
            .recv = _messager_glib_recv,
            .finished = _messager_glib_finished
        },
        .priv = cmg
    };

    curvecpr_bytes_zero(cmg, sizeof(struct curvecpr_client_messager_glib));

    if (cf)
        curvecpr_bytes_copy(&cmg->cf, cf, sizeof(struct curvecpr_client_messager_glib_cf));

    /* Client configuration. */
    curvecpr_bytes_copy(client_cf.my_extension, cmg->cf.my_extension, 16);

    curvecpr_bytes_copy(client_cf.my_global_pk, cmg->cf.my_global_pk, 32);
    curvecpr_bytes_copy(client_cf.my_global_sk, cmg->cf.my_global_sk, 32);

    curvecpr_bytes_copy(client_cf.their_extension, cmg->cf.their_extension, 16);
    curvecpr_bytes_copy(client_cf.their_global_pk, cmg->cf.their_global_pk, 32);
    curvecpr_bytes_copy(client_cf.their_domain_name, cmg->cf.their_domain_name, 256);

    /* Messager configuration. */
    mg_cf.pending_maximum = cmg->cf.pending_maximum;
    mg_cf.sendmarkq_maximum = cmg->cf.sendmarkq_maximum;
    mg_cf.recvmarkq_maximum = cmg->cf.recvmarkq_maximum;

    /* Initialize client and messager. */
    curvecpr_client_new(&cmg->client, &client_cf);
    curvecpr_messager_glib_new(&cmg->mg, &mg_cf, 1);
}

void curvecpr_client_messager_glib_dealloc (struct curvecpr_client_messager_glib *cmg)
{
    curvecpr_messager_glib_dealloc(&cmg->mg);
}

int curvecpr_client_messager_glib_connected (struct curvecpr_client_messager_glib *cmg)
{
    return curvecpr_client_connected(&cmg->client);
}

int curvecpr_client_messager_glib_send (struct curvecpr_client_messager_glib *cmg, const unsigned char *buf, size_t num)
{
    return curvecpr_messager_glib_send(&cmg->mg, buf, num);
}

int curvecpr_client_messager_glib_close (struct curvecpr_client_messager_glib *cmg)
{
    return curvecpr_messager_glib_close(&cmg->mg);
}

int curvecpr_client_messager_glib_recv (struct curvecpr_client_messager_glib *cmg, const unsigned char *buf, size_t num)
{
    return curvecpr_client_recv(&cmg->client, buf, num);
}

int curvecpr_client_messager_glib_process_sendq (struct curvecpr_client_messager_glib *cmg)
{
    return curvecpr_messager_glib_process_sendq(&cmg->mg);
}

long long curvecpr_client_messager_glib_next_timeout (struct curvecpr_client_messager_glib *cmg)
{
    return curvecpr_messager_glib_next_timeout(&cmg->mg);
}
