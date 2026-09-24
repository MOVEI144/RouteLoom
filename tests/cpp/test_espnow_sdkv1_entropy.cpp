#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "psa/crypto.h"
#include "routeloom/espnow_sdkv1_entropy.hpp"

namespace {
int failures = 0;
#define CHECK(expr) do { if (!(expr)) { \
  std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__, #expr); \
  ++failures; \
} } while (false)

bool source_enabled = false;
bool init_fails = false;
bool random_fails = false;
int init_calls = 0;
int random_reads = 0;
int disables = 0;
}

extern "C" void bootloader_random_enable(void) { source_enabled = true; }
extern "C" void bootloader_random_disable(void) {
  source_enabled = false;
  ++disables;
}
extern "C" psa_status_t psa_crypto_init(void) {
  CHECK(source_enabled);
  ++init_calls;
  return init_fails ? PSA_ERROR_GENERIC_ERROR : PSA_SUCCESS;
}
extern "C" psa_status_t psa_generate_random(std::uint8_t* output,
                                              const std::size_t length) {
  CHECK(source_enabled);
  ++random_reads;
  std::memset(output, 0xa5, length);
  return random_fails ? PSA_ERROR_GENERIC_ERROR : PSA_SUCCESS;
}

int main() {
  std::uint8_t key[32]{};
  using routeloom::MutableByteView;
  using routeloom::espnow::EspMaintenanceEntropy;
  {
    EspMaintenanceEntropy entropy;
    CHECK(!entropy.fill(MutableByteView{key, sizeof(key)}).ok());
    CHECK(init_calls == 0 && random_reads == 0);
    CHECK(entropy.begin().ok());
    CHECK(source_enabled && init_calls == 1 && random_reads == 1);
    CHECK(!entropy.begin().ok());
    CHECK(entropy.fill(MutableByteView{key, sizeof(key)}).ok());
    CHECK(random_reads == 2);
    for (const auto byte : key) CHECK(byte == 0xa5);
    random_fails = true;
    CHECK(!entropy.fill(MutableByteView{key, sizeof(key)}).ok());
    for (const auto byte : key) CHECK(byte == 0);
    CHECK(!source_enabled);
    CHECK(!entropy.fill(MutableByteView{key, sizeof(key)}).ok());
    CHECK(random_reads == 3);
    random_fails = false;
  }
  {
    init_fails = true;
    EspMaintenanceEntropy entropy;
    CHECK(!entropy.begin().ok());
    CHECK(!source_enabled);
    CHECK(!entropy.fill(MutableByteView{key, sizeof(key)}).ok());
    CHECK(!entropy.begin().ok());
    init_fails = false;
  }
  {
    random_fails = true;
    EspMaintenanceEntropy entropy;
    CHECK(!entropy.begin().ok());
    CHECK(!source_enabled);
    CHECK(!entropy.fill(MutableByteView{key, sizeof(key)}).ok());
    random_fails = false;
  }
  {
    EspMaintenanceEntropy entropy;
    CHECK(entropy.begin().ok());
    CHECK(source_enabled);
    CHECK(!entropy.fill(MutableByteView{nullptr, 1}).ok());
    CHECK(entropy.fill(MutableByteView{nullptr, 0}).ok());
  }
  CHECK(!source_enabled && disables == 4);
  return failures == 0 ? 0 : 1;
}
