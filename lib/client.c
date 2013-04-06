#include "config.h"

#include "client.h"

#include "bytes.h"
#include "packet.h"
#include "session.h"
#include "util.h"

#include <sodium/crypto_box.h>

static const struct curvecpr_session_cf _default_session_cf = { .priv = NULL };
static const unsigned char _zeros[128] = { 0 };

void curvecpr_client_new (struct curvecpr_client *client, const struct curvecpr_client_cf *cf)
{
    curvecpr_bytes_zero(client, sizeof(struct curvecpr_client));

    /* Copy in the configuration. */
    if (cf)
        curvecpr_bytes_copy(&client->cf, cf, sizeof(struct curvecpr_client_cf));

    /* We use a default session configuration because it's never exposed to the user. */
    curvecpr_session_new(&client->session, &_default_session_cf);

    client->negotiated = CURVECPR_CLIENT_PENDING;
}

int curvecpr_client_connected (struct curvecpr_client *client)
{
    struct curvecpr_client_cf *cf = &client->cf;
    struct curvecpr_session *s = &client->session;
    struct curvecpr_packet_hello p;

    /* Copy some data into the session. */
    curvecpr_bytes_copy(s->their_extension, cf->their_extension, 16);
    curvecpr_bytes_copy(s->their_global_pk, cf->their_global_pk, 32);

    /* Generate keys. */
    s->my_session_nonce = curvecpr_util_random_mod_n(281474976710656LL);
    crypto_box_keypair(s->my_session_pk, s->my_session_sk);
    crypto_box_beforenm(s->my_session_their_global_key, s->their_global_pk, s->my_session_sk);
    crypto_box_beforenm(s->my_global_their_global_key, s->their_global_pk, cf->my_global_sk);

    /* Packet identifier. */
    curvecpr_bytes_copy(p.id, "QvnQ5XlH", 8);

    /* Extensions. */
    curvecpr_bytes_copy(p.server_extension, s->their_extension, 16);
    curvecpr_bytes_copy(p.client_extension, cf->my_extension, 16);

    /* The client's session-specific public key. */
    curvecpr_bytes_copy(p.client_session_pk, s->my_session_pk, 32);

    /* A series of zero bytes for padding. */
    curvecpr_bytes_copy(p._, _zeros, 64);

    /* The encrypted data (again, all zeros). Nonce generation is included. */
    {
        unsigned char nonce[24];
        unsigned char data[96] = { 0 };

        /* The nonce for the upcoming encrypted data. */
        curvecpr_bytes_copy(nonce, "CurveCP-client-H", 16);
        curvecpr_session_next_nonce(s, nonce + 16);

        curvecpr_bytes_copy(p.nonce, nonce + 16, 8);

        /* Actual encryption. */
        crypto_box_afternm(data, _zeros, 96, nonce, s->my_session_their_global_key);
        curvecpr_bytes_copy(p.box, data + 16, 80);
    }

    cf->ops.send(client, (const unsigned char *)&p, sizeof(struct curvecpr_packet_hello));

    return 0;
}
