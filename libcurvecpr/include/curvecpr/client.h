#ifndef __CURVECPR_CLIENT_H
#define __CURVECPR_CLIENT_H

#ifdef __cplusplus
extern "C" {
#endif

#include "session.h"

#include <string.h>

struct curvecpr_client;

struct curvecpr_client_ops {
    int (*send)(struct curvecpr_client *client, const unsigned char *buf, size_t num);
    int (*recv)(struct curvecpr_client *client, const unsigned char *buf, size_t num);

    int (*next_nonce)(struct curvecpr_client *client, unsigned char *destination, size_t num);
};

struct curvecpr_client_cf {
    /* Any extensions. */
    unsigned char my_extension[16];

    /* Curve25519 public/private keypairs. */
    unsigned char my_global_pk[32];
    unsigned char my_global_sk[32];

    /* Server configuration. */
    unsigned char their_extension[16];
    unsigned char their_global_pk[32];
    unsigned char their_domain_name[256];

    struct curvecpr_client_ops ops;

    void *priv;
};

struct curvecpr_client {
    struct curvecpr_client_cf cf;
    struct curvecpr_session session;

    enum {
        CURVECPR_CLIENT_PENDING,
        CURVECPR_CLIENT_INITIATING,
        CURVECPR_CLIENT_NEGOTIATED
    } negotiated;
    unsigned char negotiated_vouch[64];
    unsigned char negotiated_cookie[96];
};

void curvecpr_client_new (struct curvecpr_client *client, const struct curvecpr_client_cf *cf);
int curvecpr_client_connected (struct curvecpr_client *client);
int curvecpr_client_recv (struct curvecpr_client *client, const unsigned char *buf, size_t num);
int curvecpr_client_send (struct curvecpr_client *client, const unsigned char *buf, size_t num);

#ifdef __cplusplus
}
#endif

#endif
