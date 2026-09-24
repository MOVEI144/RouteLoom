#include "routeloom/sdkv1_legacy_purge.hpp"

namespace routeloom::sdkv1 {
namespace {
constexpr std::size_t kBatch = 16;
constexpr std::size_t kMaxScan = 4096;

bool name_is(const char* actual, const char* expected) noexcept {
  if (!actual || !expected) return false;
  for (std::size_t i = 0; i < 16; ++i) {
    if (actual[i] != expected[i]) return false;
    if (actual[i] == '\0') return true;
  }
  return false;
}

bool hex(char c) noexcept {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
         (c >= 'A' && c <= 'F');
}
}  // namespace

bool is_legacy_peer_key(const LegacyKey& key) noexcept {
  const bool counter = name_is(key.name_space, "rlcounter");
  const bool replay = name_is(key.name_space, "rlreplay");
  if ((!counter && !replay) || !key.key) return false;
  if (counter ? key.key[0] != 'c' : (key.key[0] != 'f' && key.key[0] != 'r')) return false;
  for (std::size_t i = 1; i <= 8; ++i) {
    if (!hex(key.key[i])) return false;
  }
  return key.key[9] == '\0';
}

Status purge_legacy_state(LegacyPurgePort& port, const bool stopped,
                          const bool ram_only_build, LegacyPurgeResult& result) noexcept {
  if (!stopped || !ram_only_build) {
    return Status::error(StatusCode::InvalidState, "legacy purge requires stopped RAM-only build");
  }
  bool marker = false;
  Status status = port.migration(marker);
  if (!status) return status;
  if (!marker) {
    status = port.commit_migration();
    if (!status) return status;
    status = port.migration(marker);
    if (!status) return status;
    if (!marker) return Status::error(StatusCode::StorageFailure, "migration readback");
  }
  LegacyPurgeResult observed{};
  std::size_t cursor = 0;
  std::size_t scanned = 0;
  while (scanned < kMaxScan) {
    LegacyKey key{};
    bool found = false;
    status = port.next(cursor, key, found);
    if (!status) return status;
    if (!found) break;
    ++scanned;
    if (!is_legacy_peer_key(key)) continue;
    if (observed.erased < kBatch) {
      status = port.erase(key);
      if (!status) return status;
      ++observed.erased;
    }
  }
  if (scanned == kMaxScan) return Status::error(StatusCode::NoCapacity, "legacy scan limit");
  // Erase acknowledgment is not evidence of durability. Start a fresh
  // enumeration and report completion only when no matching keys survive.
  cursor = 0;
  scanned = 0;
  while (scanned < kMaxScan) {
    LegacyKey key{};
    bool found = false;
    status = port.next(cursor, key, found);
    if (!status) return status;
    if (!found) { result = observed; return Status::success(); }
    ++scanned;
    if (is_legacy_peer_key(key)) ++observed.remaining;
  }
  return Status::error(StatusCode::NoCapacity, "legacy scan limit");
}

}  // namespace routeloom::sdkv1
