#ifndef __CURVECPR_UTIL_H
#define __CURVECPR_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

long long curvecpr_util_random_mod_n (long long n);
long long curvecpr_util_nanoseconds (void);
int curvecpr_util_encode_domain_name (unsigned char *destination, const char *source);

#ifdef __cplusplus
}
#endif

#endif
