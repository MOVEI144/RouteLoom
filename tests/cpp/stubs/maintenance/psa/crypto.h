#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int32_t psa_status_t;
#define PSA_SUCCESS ((psa_status_t)0)
#define PSA_ERROR_GENERIC_ERROR ((psa_status_t)-132)

psa_status_t psa_crypto_init(void);
psa_status_t psa_generate_random(uint8_t* output, size_t output_size);

#ifdef __cplusplus
}
#endif
