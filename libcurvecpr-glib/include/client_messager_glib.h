#ifndef __CURVECPR_GLIB_CLIENT_MESSAGER_GLIB_H
#define __CURVECPR_GLIB_CLIENT_MESSAGER_GLIB_H

#include "block.h"
#include "client.h"
#include "messager_glib.h"

#include <string.h>

#include <sodium/crypto_uint64.h>

struct curvecpr_client_messager_glib;

struct curvecpr_client_messager_glib_ops {
    int (*send)(struct curvecpr_client_messager_glib *cmg, const unsigned char *buf, size_t num);
    int (*recv)(struct curvecpr_client_messager_glib *cmg, const unsigned char *buf, size_t num);
    void (*finished)(struct curvecpr_client_messager_glib *cmg, enum curvecpr_block_eofflag flag);

    int (*next_nonce)(struct curvecpr_client_messager_glib *cmg, unsigned char *destination, size_t num);
};

struct curvecpr_client_messager_glib_cf {
    /* Any extensions. */
    unsigned char my_extension[16];

    /* Curve25519 public/private keypairs. */
    unsigned char my_global_pk[32];
    unsigned char my_global_sk[32];

    /* Server configuration. */
    unsigned char their_extension[16];
    unsigned char their_global_pk[32];
    unsigned char their_domain_name[256];

    /* Messager configuration. */
    crypto_uint64 pending_maximum;
    unsigned int sendmarkq_maximum;
    unsigned int recvmarkq_maximum;

    struct curvecpr_client_messager_glib_ops ops;

    void *priv;
};

struct curvecpr_client_messager_glib {
    struct curvecpr_client_messager_glib_cf cf;

    struct curvecpr_client client;
    struct curvecpr_messager_glib mg;
};

void curvecpr_client_messager_glib_new (struct curvecpr_client_messager_glib *cmg, struct curvecpr_client_messager_glib_cf *cf);
void curvecpr_client_messager_glib_dealloc (struct curvecpr_client_messager_glib *cmg);
int curvecpr_client_messager_glib_connected (struct curvecpr_client_messager_glib *cmg);
int curvecpr_client_messager_glib_send (struct curvecpr_client_messager_glib *cmg, const unsigned char *buf, size_t num);
int curvecpr_client_messager_glib_close (struct curvecpr_client_messager_glib *cmg);
int curvecpr_client_messager_glib_recv (struct curvecpr_client_messager_glib *cmg, const unsigned char *buf, size_t num);
int curvecpr_client_messager_glib_process_sendq (struct curvecpr_client_messager_glib *cmg);
long long curvecpr_client_messager_glib_next_timeout (struct curvecpr_client_messager_glib *cmg);

#endif
