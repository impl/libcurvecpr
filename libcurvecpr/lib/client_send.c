#include "config.h"

#include <curvecpr/client.h>

#include <curvecpr/bytes.h>
#include <curvecpr/session.h>
#include <curvecpr/packet.h>

#include <string.h>
#include <errno.h>

#include <sodium/crypto_box.h>

static int _do_initiate (struct curvecpr_client *client, const unsigned char *buf, size_t num)
{
    const struct curvecpr_client_cf *cf = &client->cf;
    struct curvecpr_session *s = &client->session;

    unsigned char nonce[24];

    unsigned char raw_p[sizeof(struct curvecpr_packet_initiate) + 1008];
    unsigned char raw_p_box[sizeof(struct curvecpr_packet_initiate_box) + 640];

    struct curvecpr_packet_initiate *p = (struct curvecpr_packet_initiate *)raw_p;
    struct curvecpr_packet_initiate_box *p_box = (struct curvecpr_packet_initiate_box *)raw_p_box;

    /* Build out the box. */
    curvecpr_bytes_zero(p_box->_, 32);
    curvecpr_bytes_copy(p_box->client_global_pk, cf->my_global_pk, 32);
    curvecpr_bytes_copy(p_box->nonce, client->negotiated_vouch, 16);
    curvecpr_bytes_copy(p_box->vouch, client->negotiated_vouch + 16, 48);
    curvecpr_bytes_copy(p_box->server_domain_name, cf->their_domain_name, 256);

    /* Copy in the message. */
    curvecpr_bytes_copy(raw_p_box + sizeof(struct curvecpr_packet_initiate_box), buf, num);

    /* Encrypt the message. */
    curvecpr_bytes_copy(nonce, "CurveCP-client-I", 16);
    curvecpr_session_next_nonce(s, nonce + 16);

    crypto_box_afternm(raw_p_box, raw_p_box, sizeof(struct curvecpr_packet_initiate_box) + num, nonce, s->my_session_their_session_key);

    /* Build out the packet. */
    curvecpr_bytes_copy(p->id, "QvnQ5XlI", 8);
    curvecpr_bytes_copy(p->server_extension, s->their_extension, 16);
    curvecpr_bytes_copy(p->client_extension, cf->my_extension, 16);
    curvecpr_bytes_copy(p->client_session_pk, s->my_session_pk, 32);
    curvecpr_bytes_copy(p->cookie, client->negotiated_cookie, 96);
    curvecpr_bytes_copy(p->nonce, nonce + 16, 8);

    /* Copy in the box. */
    curvecpr_bytes_copy(raw_p + sizeof(struct curvecpr_packet_initiate), raw_p_box + 16, sizeof(struct curvecpr_packet_initiate_box) - 16 + num);

    /* Send it out! */
    if (cf->ops.send(client, raw_p, sizeof(struct curvecpr_packet_initiate) + (sizeof(struct curvecpr_packet_initiate_box) - 16) + num))
        return -EINVAL;

    return 0;
}

static int _do_client_message (struct curvecpr_client *client, const unsigned char *buf, size_t num)
{
    const struct curvecpr_client_cf *cf = &client->cf;
    struct curvecpr_session *s = &client->session;

    unsigned char nonce[24];
    unsigned char p_raw[sizeof(struct curvecpr_packet_client_message) + 1104];
    unsigned char data[1120];

    struct curvecpr_packet_client_message *p;

    if (num < 16 || num > 1088 || num & 15)
        return -EMSGSIZE;

    /* Build the box. */
    curvecpr_bytes_copy(nonce, "CurveCP-client-M", 16);
    curvecpr_session_next_nonce(s, nonce + 16);

    curvecpr_bytes_zero(data, 32);
    curvecpr_bytes_copy(data + 32, buf, num);

    crypto_box_afternm(data, data, num + 32, nonce, s->my_session_their_session_key);

    /* Build the rest of the packet. */
    p = (struct curvecpr_packet_client_message *)p_raw;

    curvecpr_bytes_copy(p->id, "QvnQ5XlM", 8);
    curvecpr_bytes_copy(p->server_extension, s->their_extension, 16);
    curvecpr_bytes_copy(p->client_extension, cf->my_extension, 16);
    curvecpr_bytes_copy(p->client_session_pk, s->my_session_pk, 32);
    curvecpr_bytes_copy(p->nonce, nonce + 16, 8);

    curvecpr_bytes_copy(p_raw + sizeof(struct curvecpr_packet_client_message), data + 16, num + 16);

    /* Fire away! */
    if (cf->ops.send(client, p_raw, sizeof(struct curvecpr_packet_client_message) + 16 + num))
        return -EINVAL;

    return 0;
}

int curvecpr_client_send (struct curvecpr_client *client, const unsigned char *buf, size_t num)
{
    if (client->negotiated == CURVECPR_CLIENT_NEGOTIATED) {
        if (num < 16 || num > 1088 || num & 15)
            return -EMSGSIZE;

        return _do_client_message(client, buf, num);
    } else if (client->negotiated == CURVECPR_CLIENT_INITIATING) {
        if (num < 16 || num > 640 || num & 15)
            return -EMSGSIZE;

        return _do_initiate(client, buf, num);
    }

    return -EINVAL;
}
