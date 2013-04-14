#include "config.h"

#include "bytes.h"

#include <string.h>

#include <sodium/crypto_uint16.h>
#include <sodium/crypto_uint32.h>
#include <sodium/crypto_uint64.h>

void curvecpr_bytes_copy (void *destination, const void *source, size_t num)
{
    char *destination_copier = destination;
    const char *source_copier = source;
    while (num > 0) {
        *destination_copier++ = *source_copier++;
        --num;
    }
}

void curvecpr_bytes_zero (void *destination, size_t num)
{
    char *destination_copier = destination;
    while (num > 0) {
        *destination_copier++ = 0;
        --num;
    }
}

int curvecpr_bytes_equal (const void *ptr1, const void *ptr2, size_t num)
{
    const unsigned char *ptr1_comparator = ptr1;
    const unsigned char *ptr2_comparator = ptr2;
    unsigned char diff = 0;
    while (num > 0) {
        diff |= *ptr1_comparator++ ^ *ptr2_comparator++;
        --num;
    }
    return (256 - (unsigned int) diff) >> 8;
}

void curvecpr_bytes_pack_uint16 (unsigned char *destination, crypto_uint16 source)
{
    *destination++ = source; source >>= 8;
    *destination++ = source; source >>= 8;
}

crypto_uint16 curvecpr_bytes_unpack_uint16 (const unsigned char *source)
{
    crypto_uint16 result;
    result = source[1];
    result <<= 8; result |= source[0];
    return result;
}

void curvecpr_bytes_pack_uint32 (unsigned char *destination, crypto_uint32 source)
{
    *destination++ = source; source >>= 8;
    *destination++ = source; source >>= 8;
    *destination++ = source; source >>= 8;
    *destination++ = source; source >>= 8;
}

crypto_uint32 curvecpr_bytes_unpack_uint32 (const unsigned char *source)
{
    crypto_uint32 result;
    result = source[3];
    result <<= 8; result |= source[2];
    result <<= 8; result |= source[1];
    result <<= 8; result |= source[0];
    return result;
}

void curvecpr_bytes_pack_uint64 (unsigned char *destination, crypto_uint64 source)
{
    *destination++ = source; source >>= 8;
    *destination++ = source; source >>= 8;
    *destination++ = source; source >>= 8;
    *destination++ = source; source >>= 8;
    *destination++ = source; source >>= 8;
    *destination++ = source; source >>= 8;
    *destination++ = source; source >>= 8;
    *destination++ = source; source >>= 8;
}

crypto_uint64 curvecpr_bytes_unpack_uint64 (const unsigned char *source)
{
    crypto_uint64 result;
    result = source[7];
    result <<= 8; result |= source[6];
    result <<= 8; result |= source[5];
    result <<= 8; result |= source[4];
    result <<= 8; result |= source[3];
    result <<= 8; result |= source[2];
    result <<= 8; result |= source[1];
    result <<= 8; result |= source[0];
    return result;
}
