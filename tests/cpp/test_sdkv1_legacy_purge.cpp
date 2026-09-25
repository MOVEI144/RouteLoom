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

struct CutBacking {
  static constexpr std::size_t kLegacy = 40;
  static constexpr std::size_t kOther = 5;
  std::array<std::array<char, 10>, kLegacy> legacy{};
  std::array<bool, kLegacy> legacy_live{};
  std::array<std::array<char, 10>, kOther> other{};
  std::array<bool, kOther> other_live{};
  bool marker{false};          // committed (durable)
  bool pending_marker{false};  // staged set, uncommitted (lost on cut)
  CutBacking() {
    for (unsigned i = 0; i < kLegacy; ++i) {
      std::snprintf(legacy[i].data(), legacy[i].size(), "f%08x", i);
      legacy_live[i] = true;
    }
    for (unsigned i = 0; i < kOther; ++i) {
      std::snprintf(other[i].data(), other[i].size(), "x%08x", i);
      other_live[i] = true;
    }
  }
  std::size_t live_legacy() const {
    std::size_t count = 0;
    for (bool live : legacy_live) count += live ? 1 : 0;
    return count;
  }
};

// Power-cut injector over a shared durable backing: every mutating NVS
// op (marker set, marker commit, each erase) is one charged op, and the
// cut fires before op `cut_after` (reads never cut — a torn read changes
// no durability). A fresh port over the same backing is the reboot.
struct CutPort final : LegacyPurgePort {
  CutBacking* backing;
  std::size_t cut_after;
  std::size_t ops{0};
  bool cut{false};
  CutPort(CutBacking* backing_in, std::size_t cut_after_in) noexcept
      : backing(backing_in), cut_after(cut_after_in) {}
  bool charge() noexcept {
    if (cut) return false;
    if (ops == cut_after) {
      cut = true;
      backing->pending_marker = false;  // the staged set never committed
      return false;
    }
    ++ops;
    return true;
  }
  Status migration(bool& present) noexcept override {
    present = backing->marker;
    return Status::success();
  }
  Status commit_migration() noexcept override {
    if (backing->marker) return Status::success();
    if (!charge()) return Status::error(StatusCode::StorageFailure, "power cut");
    backing->pending_marker = true;  // the set stages...
    if (!charge()) return Status::error(StatusCode::StorageFailure, "power cut");
    backing->marker = true;  // ...the commit persists it
    backing->pending_marker = false;
    return Status::success();
  }
  Status next(std::size_t& cursor, LegacyKey& key, bool& found) noexcept override {
    // Fixed-index cursor (erased entries skip, never shift): legacy keys
    // first, then the untouched non-legacy shapes.
    while (cursor < CutBacking::kLegacy && !backing->legacy_live[cursor]) ++cursor;
    if (cursor < CutBacking::kLegacy) {
      key = {"rlreplay", backing->legacy[cursor].data()};
      found = true;
      ++cursor;
      return Status::success();
    }
    std::size_t other = cursor - CutBacking::kLegacy;
    while (other < CutBacking::kOther && !backing->other_live[other]) {
      ++other;
      ++cursor;
    }
    if (other >= CutBacking::kOther) {
      found = false;
      return Status::success();
    }
    key = {"rlcounter", backing->other[other].data()};
    found = true;
    ++cursor;
    return Status::success();
  }
  Status erase(const LegacyKey& key) noexcept override {
    if (!charge()) return Status::error(StatusCode::StorageFailure, "power cut");
    for (std::size_t i = 0; i < CutBacking::kLegacy; ++i) {
      if (backing->legacy_live[i] && std::strcmp(backing->legacy[i].data(), key.key) == 0) {
        backing->legacy_live[i] = false;
        return Status::success();
      }
    }
    return Status::error(StatusCode::NotFound, "gone");
  }
};

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

  // The firmware runner routes `security legacy-state <verb>` lines here;
  // anything else stays with the factory console (NotFound, no match).
  ByteView rest{};
  CHECK(strip_legacy_state_prefix(line("security legacy-state status"), rest).ok());
  CHECK(rest.size == 6 && std::memcmp(rest.data, "status", 6) == 0);
  CHECK(strip_legacy_state_prefix(line("security legacy-state"), rest).ok());
  CHECK(rest.size == 0);  // bare prefix feeds an empty line (invalid_argument)
  CHECK(strip_legacy_state_prefix(line("security legacy-stateX"), rest).code ==
        StatusCode::NotFound);
  CHECK(strip_legacy_state_prefix(line("security legacy-stat"), rest).code ==
        StatusCode::NotFound);
  CHECK(strip_legacy_state_prefix(line("security"), rest).code == StatusCode::NotFound);
  CHECK(strip_legacy_state_prefix(line("status"), rest).code == StatusCode::NotFound);
  CHECK(strip_legacy_state_prefix(line(""), rest).code == StatusCode::NotFound);

  // Power-cut matrix (#37): the cut fires before every mutating op of a
  // 40-key purge (marker set, marker commit, each erase), then a fresh
  // port over the same backing ("reboot") reruns to completion. Every
  // row must converge: all legacy keys gone, the marker committed, the
  // non-legacy shapes untouched, and no pass ever reporting completion
  // while survivors remain.
  constexpr std::size_t kCutOps = 2 + CutBacking::kLegacy;
  for (std::size_t cut = 0; cut <= kCutOps; ++cut) {
    CutBacking backing;
    // The cut port runs pass after pass (16 erases each) until the cut
    // fires; the last row never cuts (a clean run inside the matrix).
    CutPort first(&backing, cut);
    LegacyPurgeResult cut_result{};
    bool fired = false;
    for (unsigned pass = 0; pass < 10; ++pass) {
      if (!purge_legacy_state(first, true, true, cut_result).ok()) {
        fired = true;
        break;
      }
      if (cut_result.remaining == 0) break;
    }
    CHECK(fired == (cut < kCutOps));
    CHECK(!backing.pending_marker);  // a staged set never looks committed
    LegacyPurgeResult rerun{};
    bool complete = false;
    for (unsigned pass = 0; pass < 10 && !complete; ++pass) {
      CutPort reboot(&backing, kCutOps + 1);  // no further cuts
      CHECK(purge_legacy_state(reboot, true, true, rerun).ok());
      CHECK(rerun.remaining == backing.live_legacy());
      complete = rerun.remaining == 0;
    }
    CHECK(complete);
    CHECK(backing.marker);
    CHECK(backing.live_legacy() == 0);
    for (bool live : backing.other_live) CHECK(live);
    // Past completion the purge is a stable no-op (marker readback only).
    CutPort settled(&backing, kCutOps + 1);
    LegacyPurgeResult noop{};
    CHECK(purge_legacy_state(settled, true, true, noop).ok());
    CHECK(noop.erased == 0 && noop.remaining == 0);
  }
  return 0;
}
