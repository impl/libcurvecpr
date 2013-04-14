#include "config.h"

#include <curvecpr/server.h>

#include <curvecpr/bytes.h>

#include <sodium/randombytes.h>

void curvecpr_server_new (struct curvecpr_server *server, const struct curvecpr_server_cf *cf)
{
    curvecpr_bytes_zero(server, sizeof(struct curvecpr_server));

    /* Copy in the configuration. */
    if (cf)
        curvecpr_bytes_copy(&server->cf, cf, sizeof(struct curvecpr_server_cf));

    /* Generate brand new temporal keys. */
    randombytes(server->my_temporal_key, sizeof(server->my_temporal_key));
    randombytes(server->my_last_temporal_key, sizeof(server->my_last_temporal_key));
}

void curvecpr_server_refresh_temporal_keys (struct curvecpr_server *server)
{
    curvecpr_bytes_copy(server->my_last_temporal_key, server->my_temporal_key, sizeof(server->my_last_temporal_key));
    randombytes(server->my_temporal_key, sizeof(server->my_temporal_key));
}
