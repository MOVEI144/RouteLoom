#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "routeloom/sdkv1_legacy_purge.hpp"
#define CHECK(x) do { if (!(x)) { std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); return 1; } } while (false)

using namespace routeloom;
using namespace routeloom::sdkv1;

namespace {
struct MemoryPort final : LegacyPurgePort {
  struct Entry { const char* space; const char* key; bool live; };
  std::array<Entry, 4> entries{{
      {"rlcounter", "c12345678", true}, {"rlreplay", "fABCDEF01", true},
      {"rlreplay", "r00000000", true}, {"rlcounter", "cmax", true}}};
  bool marker{false};
  unsigned erased{0};
  Status migration(bool& present) noexcept override { present = marker; return Status::success(); }
  Status commit_migration() noexcept override { marker = true; return Status::success(); }
  Status next(std::size_t& cursor, LegacyKey& key, bool& found) noexcept override {
    found = cursor < entries.size();
    if (found) { key = {entries[cursor].space, entries[cursor].key}; ++cursor; }
    return Status::success();
  }
  Status erase(const LegacyKey& key) noexcept override {
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
  // Old PSK binaries ignore the marker and would accept the recorded frame
  // again if its floor/window were removed by a direct API call.
  for (bool stopped : {false, true}) {
    for (bool ram_only : {false, true}) {
      CHECK(purge_legacy_state(port, stopped, ram_only, result).code ==
            StatusCode::RecoveryRequired);
      CHECK(!port.marker && port.erased == 0);
      CHECK(port.entries[1].live && port.entries[2].live);
    }
  }
  port.marker = true;  // even an existing marker cannot fence an older binary
  CHECK(purge_legacy_state(port, true, true, result).code == StatusCode::RecoveryRequired);
  CHECK(port.erased == 0 && port.entries[1].live && port.entries[2].live);

  auto line = [](const char* text) {
    return ByteView{reinterpret_cast<const std::uint8_t*>(text), std::strlen(text)};
  };
  const std::array<std::uint8_t, 16> domain{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
  constexpr char kPurge[] = "purge --domain 000102030405060708090a0b0c0d0e0f --confirm";
  MemoryPort verb_port;
  LegacyStateConsole verb(verb_port, domain, true);
  char response[LegacyStateConsole::kResponseMax];
  std::size_t size = 0;
  CHECK(verb.process_line(line("status"), true, response, sizeof(response), size).ok());
  CHECK(std::strcmp(response, "OK legacy=3 marker=0") == 0);
  CHECK(verb.process_line(line("purge --domain 000102030405060708090a0b0c0d0e0e --confirm"),
                          true, response, sizeof(response), size).ok());
  CHECK(std::strcmp(response, "ERR domain") == 0);
  CHECK(verb.process_line(line("purge --confirm"), true, response, sizeof(response), size).ok());
  CHECK(std::strcmp(response, "ERR invalid_argument") == 0);
  CHECK(verb.process_line(line(kPurge), false, response, sizeof(response), size).ok());
  CHECK(std::strcmp(response, "ERR busy") == 0);
  CHECK(verb.process_line(line(kPurge), true, response, sizeof(response), size).ok());
  CHECK(std::strcmp(response, "ERR rollback_unsafe") == 0);
  CHECK(!verb_port.marker && verb_port.erased == 0 && verb_port.entries[1].live);
  char small[8];
  CHECK(verb.process_line(line("status"), true, small, sizeof(small), size).code ==
        StatusCode::InvalidArgument);
  MemoryPort legacy_port;
  LegacyStateConsole legacy_verb(legacy_port, domain, false);
  CHECK(legacy_verb.process_line(line(kPurge), true, response, sizeof(response), size).ok());
  CHECK(std::strcmp(response, "ERR refused") == 0);

  ByteView rest{};
  CHECK(strip_legacy_state_prefix(line("security legacy-state status"), rest).ok());
  CHECK(rest.size == 6 && std::memcmp(rest.data, "status", 6) == 0);
  CHECK(strip_legacy_state_prefix(line("security legacy-state"), rest).ok());
  CHECK(rest.size == 0);
  CHECK(strip_legacy_state_prefix(line("security legacy-stateX"), rest).code ==
        StatusCode::NotFound);
  CHECK(strip_legacy_state_prefix(line("status"), rest).code == StatusCode::NotFound);
  return 0;
}
