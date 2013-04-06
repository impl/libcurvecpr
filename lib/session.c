#include "config.h"

#include "session.h"

#include "bytes.h"

void curvecpr_session_new (struct curvecpr_session *s, const struct curvecpr_session_cf *cf)
{
    curvecpr_bytes_zero(s, sizeof(struct curvecpr_session));

    /* Copy in the configuration. */
    if (cf)
        curvecpr_bytes_copy(&s->cf, cf, sizeof(struct curvecpr_session_cf));
}

void curvecpr_session_next_nonce (struct curvecpr_session *s, unsigned char *destination)
{
    curvecpr_bytes_pack_uint64(destination, ++s->my_session_nonce);
}
