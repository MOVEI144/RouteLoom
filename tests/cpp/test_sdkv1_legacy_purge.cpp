#include <array>
#include <cstdint>
#include <cstring>
#include <cstdio>

#include "routeloom/sdkv1_legacy_purge.hpp"
#define CHECK(x) do { if (!(x)) { std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); return 1; } } while (false)

using namespace routeloom;
using namespace routeloom::sdkv1;

namespace {
struct MemoryPort final : LegacyPurgePort {
  struct Entry { const char* space; const char* key; bool live; };
  std::array<Entry, 10> entries{{
      {"rlcounter", "c12345678", true}, {"rlreplay", "fABCDEF01", true},
      {"rlreplay", "r00000000", true}, {"rlcounter", "cmax", true},
      {"rlrevo", "r00000000", true}, {"rlres", "s00", true},
      {"rlcounter", "c1234567g", true}, {"rlreplay", "r000000000", true},
      {"rlreplay", "f00000000", true}, {"rlcounter", "c00000000", true}}};
  bool marker{false};
  bool fail_erase{false};
  unsigned erased{0};
  Status migration(bool& present) noexcept override { present = marker; return Status::success(); }
  Status commit_migration() noexcept override { marker = true; return Status::success(); }
  Status next(std::size_t& cursor, LegacyKey& key, bool& found) noexcept override {
    while (cursor < entries.size() && !entries[cursor].live) ++cursor;
    found = cursor < entries.size();
    if (found) { key = {entries[cursor].space, entries[cursor].key}; ++cursor; }
    return Status::success();
  }
  Status erase(const LegacyKey& key) noexcept override {
    if (fail_erase) { fail_erase = false; return Status::error(StatusCode::StorageFailure, "injected"); }
    for (auto& e : entries) {
      if (e.live && std::strcmp(e.space, key.name_space) == 0 &&
          std::strcmp(e.key, key.key) == 0) { e.live = false; ++erased; return Status::success(); }
    }
    return Status::error(StatusCode::NotFound, "gone");
  }
};
}  // namespace

int main() {
  MemoryPort port;
  LegacyPurgeResult result{};
  CHECK(!purge_legacy_state(port, false, true, result).ok());  // live radio
  CHECK(!port.marker && port.erased == 0);
  CHECK(!purge_legacy_state(port, true, false, result).ok());  // legacy build
  CHECK(!port.marker && port.erased == 0);
  port.fail_erase = true;
  CHECK(!purge_legacy_state(port, true, true, result).ok());
  CHECK(port.marker && port.erased == 0);  // marker before any erase
  CHECK(purge_legacy_state(port, true, true, result).ok());
  CHECK(port.erased == 5 && result.remaining == 0);
  for (std::size_t i = 3; i < 8; ++i) CHECK(port.entries[i].live);
  CHECK(purge_legacy_state(port, true, true, result).ok());
  CHECK(port.erased == 5 && result.erased == 0);
  return 0;
}
