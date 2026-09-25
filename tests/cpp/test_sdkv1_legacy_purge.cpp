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
  bool lost_erase{false};
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
    if (lost_erase) return Status::success();
    for (auto& e : entries) {
      if (e.live && std::strcmp(e.space, key.name_space) == 0 &&
          std::strcmp(e.key, key.key) == 0) { e.live = false; ++erased; return Status::success(); }
    }
    return Status::error(StatusCode::NotFound, "gone");
  }
};
struct ChurnPort final : LegacyPurgePort {
  std::array<std::array<char, 10>, 200> names{};
  std::array<bool, 200> live{};
  bool marker{false};
  ChurnPort() {
    for (unsigned i = 0; i < names.size(); ++i) {
      std::snprintf(names[i].data(), names[i].size(), "f%08x", i);
      live[i] = true;
    }
  }
  Status migration(bool& present) noexcept override { present = marker; return Status::success(); }
  Status commit_migration() noexcept override { marker = true; return Status::success(); }
  Status next(std::size_t& cursor, LegacyKey& key, bool& found) noexcept override {
    while (cursor < live.size() && !live[cursor]) ++cursor;
    found = cursor < live.size();
    if (found) key = {"rlreplay", names[cursor++].data()};
    return Status::success();
  }
  Status erase(const LegacyKey& key) noexcept override {
    for (std::size_t i = 0; i < names.size(); ++i) {
      if (live[i] && std::strcmp(names[i].data(), key.key) == 0) {
        live[i] = false;
        return Status::success();
      }
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

  // N01: an NVS adapter may acknowledge an erase without persisting it.
  // The next pass must never report completion while old peer state remains.
  MemoryPort dropped;
  dropped.lost_erase = true;
  result = {};
  const Status lost = purge_legacy_state(dropped, true, true, result);
  CHECK(!lost.ok() || result.remaining != 0);
  CHECK(dropped.entries[0].live);

  ChurnPort churn;
  std::uint32_t total = 0;
  for (unsigned pass = 0; pass < 14; ++pass) {
    CHECK(purge_legacy_state(churn, true, true, result).ok());
    CHECK(result.erased <= 16);
    total += result.erased;
    if (result.remaining == 0) break;
  }
  CHECK(total == 200 && result.remaining == 0);
  for (bool live : churn.live) CHECK(!live);

  // The physical-maintenance console: status counts survivors, purge needs
  // the full domain fingerprint plus a stopped radio. Every refusal leaves
  // the store untouched — no marker, no erase.
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
  CHECK(std::strcmp(response, "OK legacy=5 marker=0") == 0);
  CHECK(verb.process_line(line("purge --domain 000102030405060708090a0b0c0d0e0e --confirm"),
                          true, response, sizeof(response), size).ok());
  CHECK(std::strcmp(response, "ERR domain") == 0);  // one nibble off
  CHECK(!verb_port.marker && verb_port.erased == 0);
  CHECK(verb.process_line(line("purge --confirm"), true, response, sizeof(response), size).ok());
  CHECK(std::strcmp(response, "ERR invalid_argument") == 0);
  CHECK(verb.process_line(line("purge"), true, response, sizeof(response), size).ok());
  CHECK(std::strcmp(response, "ERR invalid_argument") == 0);
  CHECK(verb.process_line(line(""), true, response, sizeof(response), size).ok());
  CHECK(std::strcmp(response, "ERR invalid_argument") == 0);
  CHECK(verb.process_line(line("status now"), true, response, sizeof(response), size).ok());
  CHECK(std::strcmp(response, "ERR invalid_argument") == 0);
  CHECK(!verb_port.marker && verb_port.erased == 0);
  CHECK(verb.process_line(line(kPurge), false, response, sizeof(response), size).ok());
  CHECK(std::strcmp(response, "ERR busy") == 0);  // live radio refuses first
  CHECK(!verb_port.marker && verb_port.erased == 0);
  CHECK(verb.process_line(line(kPurge), true, response, sizeof(response), size).ok());
  CHECK(std::strcmp(response, "OK erased=5 remaining=0") == 0);
  CHECK(verb_port.marker && verb_port.erased == 5);
  CHECK(verb.process_line(line(kPurge), true, response, sizeof(response), size).ok());
  CHECK(std::strcmp(response, "OK erased=0 remaining=0") == 0);  // idempotent
  CHECK(verb.process_line(line("status"), true, response, sizeof(response), size).ok());
  CHECK(std::strcmp(response, "OK legacy=0 marker=1") == 0);
  char small[8];
  CHECK(verb.process_line(line("status"), true, small, sizeof(small), size).code ==
        StatusCode::InvalidArgument);
  MemoryPort legacy_port;
  LegacyStateConsole legacy_verb(legacy_port, domain, false);
  CHECK(legacy_verb.process_line(line(kPurge), true, response, sizeof(response), size).ok());
  CHECK(std::strcmp(response, "ERR refused") == 0);  // legacy build keeps its keys
  CHECK(!legacy_port.marker && legacy_port.erased == 0);
  return 0;
}
