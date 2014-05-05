#ifndef __CURVECPR_BLOCK_H
#define __CURVECPR_BLOCK_H

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>

#include <sodium/crypto_uint32.h>
#include <sodium/crypto_uint64.h>

enum curvecpr_block_eofflag {
    CURVECPR_BLOCK_STREAM,
    CURVECPR_BLOCK_EOF_FAILURE,
    CURVECPR_BLOCK_EOF_SUCCESS
};

struct curvecpr_block {
    /* This message's ID. */
    crypto_uint32 id;

    /* When this message was actually sent/received. (0 means not sent.) */
    long long clock;

    /* The position of this block in the stream. */
    crypto_uint64 offset;

    /* Is this block an EOF indicator? */
    enum curvecpr_block_eofflag eof;

    /* The actual data. */
    size_t data_len;
    unsigned char data[1024];
};

#ifdef __cplusplus
}
#endif

#endif
