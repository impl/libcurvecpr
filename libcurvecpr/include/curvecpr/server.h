#ifndef __CURVECPR_SERVER_H
#define __CURVECPR_SERVER_H

#include "session.h"

#include <string.h>

struct curvecpr_server;

struct curvecpr_server_ops {
    int (*put_session)(struct curvecpr_server *server, const struct curvecpr_session *s, void *priv, struct curvecpr_session **s_stored);
    int (*get_session)(struct curvecpr_server *server, const unsigned char their_session_pk[32], struct curvecpr_session **s_stored);

    int (*send)(struct curvecpr_server *server, struct curvecpr_session *s, void *priv, const unsigned char *buf, size_t num);
    int (*recv)(struct curvecpr_server *server, struct curvecpr_session *s, void *priv, const unsigned char *buf, size_t num);

    int (*next_nonce)(struct curvecpr_server *server, unsigned char *destination, size_t num);
};

struct curvecpr_server_cf {
    /* Any extensions. */
    unsigned char my_extension[16];

    /* Curve25519 public/private keypairs. */
    unsigned char my_global_pk[32];
    unsigned char my_global_sk[32];

    struct curvecpr_server_ops ops;

    void *priv;
};

struct curvecpr_server {
    struct curvecpr_server_cf cf;

    unsigned char my_temporal_key[32];
    unsigned char my_last_temporal_key[32];
};

void curvecpr_server_new (struct curvecpr_server *server, const struct curvecpr_server_cf *cf);
void curvecpr_server_refresh_temporal_keys (struct curvecpr_server *server);
int curvecpr_server_recv (struct curvecpr_server *server, void *priv, const unsigned char *buf, size_t num, struct curvecpr_session **s_stored);
int curvecpr_server_send (struct curvecpr_server *server, struct curvecpr_session *s, void *priv, const unsigned char *buf, size_t num);

#endif
