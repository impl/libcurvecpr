#ifndef __CURVECPR_GLIB_MESSAGER_GLIB_H
#define __CURVECPR_GLIB_MESSAGER_GLIB_H

#include <curvecpr/block.h>
#include <curvecpr/messager.h>

#include <string.h>

#include <sodium/crypto_uint64.h>

#include <glib.h>

struct curvecpr_messager_glib;

struct curvecpr_messager_glib_ops {
    int (*send)(struct curvecpr_messager_glib *mg, const unsigned char *buf, size_t num);
    int (*recv)(struct curvecpr_messager_glib *mg, const unsigned char *buf, size_t num);
    void (*finished)(struct curvecpr_messager_glib *mg, enum curvecpr_block_eofflag flag);
};

struct curvecpr_messager_glib_cf {
    crypto_uint64 pending_maximum;
    unsigned int sendmarkq_maximum;
    unsigned int recvmarkq_maximum;

    struct curvecpr_messager_glib_ops ops;

    void *priv;
};

struct curvecpr_messager_glib {
    struct curvecpr_messager_glib_cf cf;

    struct curvecpr_messager messager;

    unsigned char sendq_head_exists;
    struct curvecpr_block sendq_head;

    unsigned char *pending;
    crypto_uint64 pending_used;
    unsigned char pending_eof;
    crypto_uint64 pending_current;
    crypto_uint64 pending_next;

    GSequence *sendmarkq;
    GSequence *recvmarkq;
    crypto_uint64 recvmarkq_distributed;
};

void curvecpr_messager_glib_new (struct curvecpr_messager_glib *mg, struct curvecpr_messager_glib_cf *cf, unsigned char client);
void curvecpr_messager_glib_dealloc (struct curvecpr_messager_glib *mg);
unsigned char curvecpr_messager_glib_is_finished (struct curvecpr_messager_glib *mg);
int curvecpr_messager_glib_finish (struct curvecpr_messager_glib *mg);
int curvecpr_messager_glib_send (struct curvecpr_messager_glib *mg, const unsigned char *buf, size_t num);
int curvecpr_messager_glib_recv (struct curvecpr_messager_glib *mg, const unsigned char *buf, size_t num);
int curvecpr_messager_glib_process_sendq (struct curvecpr_messager_glib *mg);
long long curvecpr_messager_glib_next_timeout (struct curvecpr_messager_glib *mg);

#endif
