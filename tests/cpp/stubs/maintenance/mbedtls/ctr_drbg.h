#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif
typedef struct mbedtls_ctr_drbg_context {
  int seeded;
} mbedtls_ctr_drbg_context;
void mbedtls_ctr_drbg_init(mbedtls_ctr_drbg_context* context);
void mbedtls_ctr_drbg_free(mbedtls_ctr_drbg_context* context);
int mbedtls_ctr_drbg_seed(mbedtls_ctr_drbg_context* context,
                          int (*entropy)(void*, unsigned char*, size_t),
                          void* data, const unsigned char* personalization,
                          size_t personalization_length);
int mbedtls_ctr_drbg_random(void* context, unsigned char* output, size_t length);
#ifdef __cplusplus
}
#endif
