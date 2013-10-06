#include "config.h"

#include <curvecpr/server.h>

#include <curvecpr/bytes.h>
#include <curvecpr/session.h>
#include <curvecpr/packet.h>

#include <errno.h>
#include <string.h>

#include <sodium/crypto_box.h>
#include <sodium/crypto_secretbox.h>

static int _handle_hello (struct curvecpr_server *server, void *priv, const struct curvecpr_packet_hello *p)
{
    const struct curvecpr_server_cf *cf = &server->cf;
    struct curvecpr_session s; /* Used only as a temporary store to make what we're doing
                                  more clear. */

    unsigned char nonce[24];
    unsigned char data[96] = { 0 };

    /* Dummy initialization. */
    curvecpr_session_new(&s);

    /* Verify initial connection parameters. */
    curvecpr_bytes_copy(s.their_session_pk, p->client_session_pk, 32);
    crypto_box_beforenm(s.my_global_their_session_key, s.their_session_pk, cf->my_global_sk);

    curvecpr_bytes_copy(nonce, "CurveCP-client-H", 16);
    curvecpr_bytes_copy(nonce + 16, p->nonce, 8);

    curvecpr_bytes_copy(data + 16, p->box, 80);
    if (crypto_box_open_afternm(data, data, 96, nonce, s.my_global_their_session_key))
        return -EINVAL;

    /* Set up session keys. */
    crypto_box_keypair(s.my_session_pk, s.my_session_sk);

    /* Prepare to send a cookie packet. */
    {
        struct curvecpr_packet_cookie po;
        struct curvecpr_packet_cookie_box po_box;

        curvecpr_bytes_zero(po_box._, 32);
        curvecpr_bytes_copy(po_box.server_session_pk, s.my_session_pk, 32);

        /* Generate the cookie. */
        curvecpr_bytes_zero(po_box.cookie, 32);
        curvecpr_bytes_copy(po_box.cookie + 32, s.their_session_pk, 32);
        curvecpr_bytes_copy(po_box.cookie + 64, s.my_session_sk, 32);

        /* Encrypt the cookie with our global nonce and temporary key. */
        curvecpr_bytes_copy(nonce, "minute-k", 8);
        if (cf->ops.next_nonce(server, nonce + 8, 16))
            return -EINVAL;

        crypto_secretbox(po_box.cookie, po_box.cookie, 96, nonce, server->my_temporal_key);
        curvecpr_bytes_copy(po_box.cookie, nonce + 8, 16);

        /* Now encrypt the whole box. */
        curvecpr_bytes_copy(nonce, "CurveCPK", 8);

        crypto_box_afternm((unsigned char *)&po_box, (const unsigned char *)&po_box, sizeof(struct curvecpr_packet_cookie_box), nonce, s.my_global_their_session_key);

        /* Build the rest of the packet. */
        curvecpr_bytes_copy(po.id, "RL3aNMXK", 8);
        curvecpr_bytes_copy(po.client_extension, p->client_extension, 16);
        curvecpr_bytes_copy(po.server_extension, cf->my_extension, 16);
        curvecpr_bytes_copy(po.nonce, nonce + 8, 16);
        curvecpr_bytes_copy(po.box, (const unsigned char *)&po_box + 16, 144);

        if (cf->ops.send(server, &s, priv, (const unsigned char *)&po, sizeof(struct curvecpr_packet_cookie)))
            return -EINVAL;
    }

    return 0;
}

static int _handle_initiate (struct curvecpr_server *server, struct curvecpr_session *s, void *priv, const struct curvecpr_packet_initiate *p, const unsigned char *buf, size_t num, struct curvecpr_session **s_stored)
{
    const struct curvecpr_server_cf *cf = &server->cf;

    unsigned char nonce[24];
    unsigned char data[sizeof(struct curvecpr_packet_initiate_box) + 640];

    if (s != NULL) {
        /* Update existing client. */
        crypto_uint64 unpacked_nonce = curvecpr_bytes_unpack_uint64(p->nonce);
        if (unpacked_nonce <= s->their_session_nonce)
            return -EINVAL;

        curvecpr_bytes_copy(nonce, "CurveCP-client-I", 16);
        curvecpr_bytes_copy(nonce + 16, p->nonce, 8);

        curvecpr_bytes_zero(data, 16);
        curvecpr_bytes_copy(data + 16, buf, num);

        if (crypto_box_open_afternm(data, data, num + 16, nonce, s->my_session_their_session_key))
            return -EINVAL;

        s->their_session_nonce = unpacked_nonce;

        if (cf->ops.recv(server, s, priv, data + sizeof(struct curvecpr_packet_initiate_box), num + 16 - sizeof(struct curvecpr_packet_initiate_box)))
            return -EINVAL;

        return 0;
    } else {
        struct curvecpr_session s_new, *s_new_stored;
        const struct curvecpr_packet_initiate_box *p_box;

        /* Register new client. */
        curvecpr_bytes_copy(nonce, "minute-k", 8);
        curvecpr_bytes_copy(nonce + 8, p->cookie, 16);

        /* We can reuse data; the cookie will fit into it. */
        curvecpr_bytes_zero(data, 16);
        curvecpr_bytes_copy(data + 16, p->cookie + 16, 80);

        /* Validate cookie. */
        if (crypto_secretbox_open(data, data, 96, nonce, server->my_temporal_key)) {
            curvecpr_bytes_zero(data, 16);
            curvecpr_bytes_copy(data + 16, p->cookie + 16, 80);
            if (crypto_secretbox_open(data, data, 96, nonce, server->my_last_temporal_key))
                return -EINVAL;
        }

        if (!curvecpr_bytes_equal(p->client_session_pk, data + 32, 32))
            return -EINVAL;

        /* Cookie is valid; set up keys. */
        curvecpr_session_new(&s_new);

        curvecpr_bytes_copy(s_new.their_session_pk, data + 32, 32);
        curvecpr_bytes_copy(s_new.my_session_sk, data + 64, 32);

        crypto_box_beforenm(s_new.my_session_their_session_key, s_new.their_session_pk, s_new.my_session_sk);

        curvecpr_bytes_copy(nonce, "CurveCP-client-I", 16);
        curvecpr_bytes_copy(nonce + 16, p->nonce, 8);

        curvecpr_bytes_zero(data, 16);
        curvecpr_bytes_copy(data + 16, buf, num);

        if (crypto_box_open_afternm(data, data, num + 16, nonce, s_new.my_session_their_session_key))
            return -EINVAL;

        p_box = (struct curvecpr_packet_initiate_box *)data;

        /* Attempt to validate this client. */
        {
            unsigned char vouch[64];

            curvecpr_bytes_copy(s_new.their_global_pk, p_box->client_global_pk, 32);
            crypto_box_beforenm(s_new.my_global_their_global_key, s_new.their_global_pk, cf->my_global_sk);

            curvecpr_bytes_copy(nonce, "CurveCPV", 8);
            curvecpr_bytes_copy(nonce + 8, p_box->nonce, 16);

            curvecpr_bytes_zero(vouch, 16);
            curvecpr_bytes_copy(vouch + 16, p_box->vouch, 48);

            if (crypto_box_afternm(vouch, vouch, 64, nonce, s_new.my_global_their_global_key))
                return -EINVAL;

            if (!curvecpr_bytes_equal(vouch + 32, s_new.their_session_pk, 32))
                return -EINVAL;
        }

        /* All good, we can go ahead and submit the client for registration. */
        s_new.their_session_nonce = curvecpr_bytes_unpack_uint64(p->nonce);
        curvecpr_bytes_copy(s_new.my_domain_name, p_box->server_domain_name, 256);

        if (cf->ops.put_session(server, &s_new, priv, &s_new_stored))
            return -EINVAL; /* This can fail for a variety of reasons that are up to
                               the delegate to determine, but two typical ones will be
                               too many connections or an invalid domain name. */

        /* Now the session is registered; we can send the encapsulated message. */
        if (cf->ops.recv(server, s_new_stored, priv, data + sizeof(struct curvecpr_packet_initiate_box), num + 16 - sizeof(struct curvecpr_packet_initiate_box)))
            return -EINVAL;

        if (s_stored)
            *s_stored = s_new_stored;

        return 0;
    }
}

static int _handle_client_message (struct curvecpr_server *server, struct curvecpr_session *s, void *priv, const struct curvecpr_packet_client_message *p, const unsigned char *buf, size_t num)
{
    const struct curvecpr_server_cf *cf = &server->cf;

    unsigned char nonce[24];
    unsigned char data[1120];

    crypto_uint64 unpacked_nonce = curvecpr_bytes_unpack_uint64(p->nonce);
    if (unpacked_nonce <= s->their_session_nonce)
        return -EINVAL;

    curvecpr_bytes_copy(nonce, "CurveCP-client-M", 16);
    curvecpr_bytes_copy(nonce + 16, p->nonce, 8);

    curvecpr_bytes_zero(data, 16);
    curvecpr_bytes_copy(data + 16, buf, num);

    if (crypto_box_open_afternm(data, data, num + 16, nonce, s->my_session_their_session_key))
        return -EINVAL;

    s->their_session_nonce = unpacked_nonce;

    if (cf->ops.recv(server, s, priv, data + 32, num - 16))
        return -EINVAL;

    return 0;
}

int curvecpr_server_recv (struct curvecpr_server *server, void *priv, const unsigned char *buf, size_t num, struct curvecpr_session **s_stored)
{
    const struct curvecpr_server_cf *cf = &server->cf;

    const struct curvecpr_packet_any *p;

    if (num < 80 || num > 1184 || num & 15)
        return -EINVAL;

    p = (const struct curvecpr_packet_any *)buf;

    if (!(curvecpr_bytes_equal(p->id, "QvnQ5Xl", 7) & curvecpr_bytes_equal(p->server_extension, cf->my_extension, 16)))
        return -EINVAL;

    if (p->id[7] == 'H') {
        /* Hello packet. */
        if (num != sizeof(struct curvecpr_packet_hello))
            return -EINVAL;

        return _handle_hello(server, priv, (const struct curvecpr_packet_hello *)buf);
    } else if (p->id[7] == 'I') {
        /* Initiate packet. */
        struct curvecpr_session *s = NULL;
        const struct curvecpr_packet_initiate *p_initiate;

        if (num < 560)
            return -EINVAL;

        p_initiate = (const struct curvecpr_packet_initiate *)buf;

        /* Try to get session. */
        cf->ops.get_session(server, p_initiate->client_session_pk, &s);

        {
            struct curvecpr_session *s_return = NULL;
            int result = _handle_initiate(server, s, priv, p_initiate, buf + sizeof(struct curvecpr_packet_initiate), num - sizeof(struct curvecpr_packet_initiate), &s_return);

            if (result == 0 && s_stored)
                *s_stored = s_return;

            return result;
        }
    } else if (p->id[7] == 'M') {
        /* Client message packet. */
        struct curvecpr_session *s = NULL;
        const struct curvecpr_packet_client_message *p_message;

        if (num < 112)
            return -EINVAL;

        p_message = (const struct curvecpr_packet_client_message *)buf;

        if (cf->ops.get_session(server, p_message->client_session_pk, &s))
            return -EINVAL;

        {
            int result = _handle_client_message(server, s, priv, p_message, buf + sizeof(struct curvecpr_packet_client_message), num - sizeof(struct curvecpr_packet_client_message));

            if (result == 0 && s_stored)
                *s_stored = s;

            return result;
        }
    }

    return -EINVAL;
}
