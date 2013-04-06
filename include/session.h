#ifndef __CURVECPR_SESSION_H
#define __CURVECPR_SESSION_H

#include <sodium/crypto_uint64.h>

struct curvecpr_session_cf {
    void *priv;
};

struct curvecpr_session {
    struct curvecpr_session_cf cf;

    /* Any extensions. */
    unsigned char their_extension[16];

    /* Curve25519 public/private keypairs. */
    unsigned char their_global_pk[32];

    /* These will be automatically generated and/or filled as needed. */

    /* Curve25519 public/private keypairs. */
    unsigned char my_session_pk[32];
    unsigned char my_session_sk[32];
    crypto_uint64 my_session_nonce;

    unsigned char their_session_pk[32];
    crypto_uint64 their_session_nonce;

    /* Calculated encryption keys. */
    unsigned char my_global_their_global_key[32];
    unsigned char my_global_their_session_key[32];
    unsigned char my_session_their_global_key[32];
    unsigned char my_session_their_session_key[32];

    /* Server-specific data. */
    unsigned char my_domain_name[256];
};

void curvecpr_session_new (struct curvecpr_session *s, const struct curvecpr_session_cf *cf);
void curvecpr_session_next_nonce (struct curvecpr_session *s, unsigned char *destination);

#endif
