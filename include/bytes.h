#ifndef __LIBCURVECPR_BYTES_H
#define __LIBCURVECPR_BYTES_H

#include <string.h>

#include <sodium/crypto_uint16.h>
#include <sodium/crypto_uint32.h>
#include <sodium/crypto_uint64.h>

void curvecpr_bytes_copy (void *destination, const void *source, size_t num);
void curvecpr_bytes_zero (void *destination, size_t num);
int curvecpr_bytes_equal (const void *ptr1, const void *ptr2, size_t num);

void curvecpr_bytes_pack_uint16 (unsigned char *destination, crypto_uint16 source);
crypto_uint16 curvecpr_bytes_unpack_uint16 (const unsigned char *source);
void curvecpr_bytes_pack_uint32 (unsigned char *destination, crypto_uint32 source);
crypto_uint32 curvecpr_bytes_unpack_uint32 (const unsigned char *source);
void curvecpr_bytes_pack_uint64 (unsigned char *destination, crypto_uint64 source);
crypto_uint64 curvecpr_bytes_unpack_uint64 (const unsigned char *source);

#endif
