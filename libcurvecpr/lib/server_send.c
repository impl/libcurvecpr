#include "config.h"

#include <curvecpr/server.h>

#include <curvecpr/bytes.h>
#include <curvecpr/packet.h>
#include <curvecpr/session.h>

#include <errno.h>
#include <string.h>

#include <sodium/crypto_box.h>

int curvecpr_server_send (struct curvecpr_server *server, struct curvecpr_session *s, void *priv, const unsigned char *buf, size_t num)
{
    const struct curvecpr_server_cf *cf = &server->cf;

    unsigned char nonce[24];
    unsigned char p_raw[sizeof(struct curvecpr_packet_server_message) + 1104];
    unsigned char data[1120];

    struct curvecpr_packet_server_message *p;

    if (num < 16 || num > 1088 || num & 15)
        return -EMSGSIZE;

    /* Build the box. */
    curvecpr_bytes_copy(nonce, "CurveCP-server-M", 16);
    curvecpr_session_next_nonce(s, nonce + 16);

    curvecpr_bytes_zero(data, 32);
    curvecpr_bytes_copy(data + 32, buf, num);

    crypto_box_afternm(data, data, num + 32, nonce, s->my_session_their_session_key);

    /* Build the rest of the packet. */
    p = (struct curvecpr_packet_server_message *)p_raw;

    curvecpr_bytes_copy(p->id, "RL3aNMXM", 8);
    curvecpr_bytes_copy(p->client_extension, s->their_extension, 16);
    curvecpr_bytes_copy(p->server_extension, cf->my_extension, 16);
    curvecpr_bytes_copy(p->nonce, nonce + 16, 8);

    curvecpr_bytes_copy(p_raw + sizeof(struct curvecpr_packet_server_message), data + 16, num + 16);

    /* Fire away! */
    if (cf->ops.send(server, s, priv, p_raw, sizeof(struct curvecpr_packet_server_message) + num + 16))
        return -EINVAL;

    return 0;
}
