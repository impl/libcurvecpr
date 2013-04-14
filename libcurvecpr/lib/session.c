#include "config.h"

#include <curvecpr/session.h>

#include <curvecpr/bytes.h>

void curvecpr_session_new (struct curvecpr_session *s)
{
    curvecpr_bytes_zero(s, sizeof(struct curvecpr_session));
}

void curvecpr_session_next_nonce (struct curvecpr_session *s, unsigned char *destination)
{
    curvecpr_bytes_pack_uint64(destination, ++s->my_session_nonce);
}

void curvecpr_session_set_priv (struct curvecpr_session *s, void *priv)
{
    s->priv = priv;
}
