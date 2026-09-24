#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "routeloom/espnow_sdkv1_entropy.hpp"

namespace {
int failures = 0;
#define CHECK(expr) do { if (!(expr)) { \
  std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__, #expr); \
  ++failures; \
} } while (false)

bool source_enabled = false;
bool seed_fails = false;
bool random_fails = false;
int entropy_reads = 0;
int random_reads = 0;
int disables = 0;
}

extern "C" void bootloader_random_enable(void) { source_enabled = true; }
extern "C" void bootloader_random_disable(void) {
  source_enabled = false;
  ++disables;
}
extern "C" void esp_fill_random(void* buffer, const size_t length) {
  CHECK(source_enabled);
  ++entropy_reads;
  std::memset(buffer, 0x5a, length);
}
extern "C" void mbedtls_ctr_drbg_init(mbedtls_ctr_drbg_context* context) {
  context->seeded = 0;
}
extern "C" void mbedtls_ctr_drbg_free(mbedtls_ctr_drbg_context* context) {
  context->seeded = 0;
}
extern "C" int mbedtls_ctr_drbg_seed(mbedtls_ctr_drbg_context* context,
                                       int (*entropy)(void*, unsigned char*, size_t),
                                       void* data, const unsigned char*, size_t) {
  unsigned char seed[32]{};
  if (entropy(data, seed, sizeof(seed)) != 0 || seed_fails) return -1;
  context->seeded = 1;
  return 0;
}
extern "C" int mbedtls_ctr_drbg_random(void* context, unsigned char* output,
                                         const size_t length) {
  CHECK(static_cast<mbedtls_ctr_drbg_context*>(context)->seeded == 1);
  ++random_reads;
  if (random_fails) return -1;
  std::memset(output, 0xa5, length);
  return 0;
}

int main() {
  std::uint8_t key[32]{};
  using routeloom::MutableByteView;
  using routeloom::espnow::EspMaintenanceEntropy;
  {
    EspMaintenanceEntropy entropy;
    CHECK(!entropy.fill(MutableByteView{key, sizeof(key)}).ok());
    CHECK(entropy_reads == 0 && random_reads == 0);
    CHECK(entropy.begin().ok());
    CHECK(source_enabled && entropy_reads == 1);
    CHECK(entropy.fill(MutableByteView{key, sizeof(key)}).ok());
    CHECK(random_reads == 1);
    for (const auto byte : key) CHECK(byte == 0xa5);
    random_fails = true;
    CHECK(!entropy.fill(MutableByteView{key, sizeof(key)}).ok());
    CHECK(!source_enabled);
    CHECK(!entropy.fill(MutableByteView{key, sizeof(key)}).ok());
    CHECK(random_reads == 2);
    random_fails = false;
  }
  {
    seed_fails = true;
    EspMaintenanceEntropy entropy;
    CHECK(!entropy.begin().ok());
    CHECK(!source_enabled);
    CHECK(!entropy.fill(MutableByteView{key, sizeof(key)}).ok());
    CHECK(!entropy.begin().ok());
    seed_fails = false;
  }
  {
    EspMaintenanceEntropy entropy;
    CHECK(entropy.begin().ok());
    CHECK(source_enabled);
  }
  CHECK(!source_enabled && disables == 3);
  return failures == 0 ? 0 : 1;
}
