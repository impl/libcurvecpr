#include "config.h"

#include <curvecpr/client.h>

#include <curvecpr/bytes.h>
#include <curvecpr/packet.h>
#include <curvecpr/session.h>

#include <errno.h>
#include <string.h>

#include <sodium/crypto_box.h>
#include <sodium/randombytes.h>

static int _handle_cookie (struct curvecpr_client *client, const struct curvecpr_packet_cookie *p)
{
    const struct curvecpr_client_cf *cf = &client->cf;
    struct curvecpr_session *s = &client->session;

    unsigned char nonce[24];
    unsigned char data[160] = { 0 };

    struct curvecpr_packet_cookie_box *p_box;

    /* Decrypt the box. */
    curvecpr_bytes_copy(nonce, "CurveCPK", 8);
    curvecpr_bytes_copy(nonce + 8, p->nonce, 16);

    curvecpr_bytes_copy(data + 16, p->box, 144);
    if (crypto_box_open_afternm(data, data, 160, nonce, s->my_session_their_global_key))
        return -EINVAL;

    p_box = (struct curvecpr_packet_cookie_box *)data;

    /* Register the server's session key. */
    curvecpr_bytes_copy(s->their_session_pk, p_box->server_session_pk, 32);

    /* Set up remaining keys. */
    crypto_box_beforenm(s->my_session_their_session_key, s->their_session_pk, s->my_session_sk);

    /* Prepare to send an initiate packet. We won't send the actual packet until we
       handle a message, though. */

    /* Build the vouch. */
    curvecpr_bytes_zero(client->negotiated_vouch, 32);
    curvecpr_bytes_copy(client->negotiated_vouch + 32, s->my_session_pk, 32);

    /* Encrypt the vouch and store it into the box. */
    curvecpr_bytes_copy(nonce, "CurveCPV", 8);
    if (cf->ops.next_nonce(client, nonce + 8, 16))
        return -EINVAL;

    crypto_box_afternm(client->negotiated_vouch, client->negotiated_vouch, 64, nonce, s->my_global_their_global_key);
    curvecpr_bytes_copy(client->negotiated_vouch, nonce + 8, 16);

    /* Store the cookie. */
    curvecpr_bytes_copy(client->negotiated_cookie, p_box->cookie, 96);

    client->negotiated = CURVECPR_CLIENT_INITIATING;

    return 0;
}

static int _handle_server_message (struct curvecpr_client *client, const struct curvecpr_packet_server_message *p, const unsigned char *buf, size_t num)
{
    const struct curvecpr_client_cf *cf = &client->cf;
    struct curvecpr_session *s = &client->session;

    unsigned char nonce[24];
    unsigned char data[1120];

    crypto_uint64 unpacked_nonce = curvecpr_bytes_unpack_uint64(p->nonce);
    if (client->negotiated == CURVECPR_CLIENT_NEGOTIATED && unpacked_nonce <= s->their_session_nonce)
        return -EINVAL;

    curvecpr_bytes_copy(nonce, "CurveCP-server-M", 16);
    curvecpr_bytes_copy(nonce + 16, p->nonce, 8);

    curvecpr_bytes_zero(data, 16);
    curvecpr_bytes_copy(data + 16, buf, num);

    if (crypto_box_open_afternm(data, data, num + 16, nonce, s->my_session_their_session_key))
        return -EINVAL;

    if (client->negotiated == CURVECPR_CLIENT_INITIATING) {
        client->negotiated = CURVECPR_CLIENT_NEGOTIATED;

        randombytes(s->their_global_pk, sizeof(s->their_global_pk));

        randombytes(client->negotiated_vouch, sizeof(client->negotiated_vouch));
        randombytes(client->negotiated_cookie, sizeof(client->negotiated_cookie));
    }

    s->their_session_nonce = unpacked_nonce;

    if (cf->ops.recv(client, data + 32, num - 16))
        return -EINVAL;

    return 0;
}

int curvecpr_client_recv (struct curvecpr_client *client, const unsigned char *buf, size_t num)
{
    const struct curvecpr_client_cf *cf = &client->cf;
    const struct curvecpr_session *s = &client->session;

    if (client->negotiated == CURVECPR_CLIENT_PENDING) {
        /* Try to read a cookie packet. */
        const struct curvecpr_packet_cookie *p;

        if (num != sizeof(struct curvecpr_packet_cookie))
            return -EINVAL;

        p = (const struct curvecpr_packet_cookie *)buf;

        if (!(curvecpr_bytes_equal(p->id, "RL3aNMXK", 8) & curvecpr_bytes_equal(p->client_extension, cf->my_extension, 16) & curvecpr_bytes_equal(p->server_extension, s->their_extension, 16)))
            return -EINVAL;

        return _handle_cookie(client, p);
    } else {
        /* Read a server message. */
        const struct curvecpr_packet_server_message *p;

        if (num < 80 || num > 1152 || num & 15)
            return -EINVAL;

        p = (const struct curvecpr_packet_server_message *)buf;

        if (!(curvecpr_bytes_equal(p->id, "RL3aNMXM", 8) & curvecpr_bytes_equal(p->client_extension, cf->my_extension, 16) & curvecpr_bytes_equal(p->server_extension, s->their_extension, 16)))
            return -EINVAL;

        return _handle_server_message(client, p,
            buf + sizeof(struct curvecpr_packet_server_message),
            num - sizeof(struct curvecpr_packet_server_message));
    }

    return -EINVAL;
}
