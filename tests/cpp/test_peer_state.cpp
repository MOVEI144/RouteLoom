// Bounded persistent peer state (issue #37, docs/design/sdk-v1/05-nvs-state-37.md
// §4, plan P0-2): the TX counter sweep behind a durable witness (D2-b), the
// per-peer caps (D2-c), "RX state is never deleted" (D2-d), the NVS entry
// budget arithmetic mirrored by tools/nvs_budget.py (V1-N07), and a churn
// run of 200 cumulative peers against a fixed-capacity NVS model that must
// never exceed the cap, never reuse a (key, counter) and never re-accept an
// old frame (V1-N03..N05).
//
// The NVS model charges entries exactly like ESP-IDF NVS v2 (a blob costs
// 2 + ceil(size / 32) entries, a u32 one entry, a namespace one entry) and
// refuses a write that would not fit, as nvs_set_* does when the partition
// is full. A separate model plays the default "nvs" partition holding the
// boot session, which peer churn must never be able to block.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <map>
#include <set>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "routeloom/counter_store.hpp"
#include "routeloom/crc32.hpp"
#include "routeloom/peer_state.hpp"
#include "routeloom/replay.hpp"

namespace {

int failures = 0;
#define CHECK(expr)                                                        \
  do {                                                                     \
    if (!(expr)) {                                                         \
      std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__, \
                   #expr);                                                 \
      ++failures;                                                          \
    }                                                                      \
  } while (false)
#define CHECK_OK(expr)                                                     \
  do {                                                                     \
    const auto _status = (expr);                                           \
    if (!_status.ok()) {                                                   \
      std::fprintf(stderr, "STATUS failed %s:%d: %s (%s)\n", __FILE__,     \
                   __LINE__, #expr, _status.detail);                       \
      ++failures;                                                          \
    }                                                                      \
  } while (false)

using namespace routeloom;

constexpr NetworkId kNet = 0x5a;
constexpr NodeId kSelf = 1000;

bool same_detail(const Status& status, const char* detail) {
  return std::strcmp(status.detail, detail) == 0;
}

// --- Fixed-capacity NVS model -------------------------------------------------

class NvsModel {
 public:
  explicit NvsModel(const std::uint32_t capacity_entries)
      : capacity_(capacity_entries) {}

  // Writes fail (nothing persists) once `writes_left` reaches zero: a power
  // cut at a chosen write. Negative means unlimited.
  int writes_left{-1};
  // Operation log for ordering assertions ("W:<key>", "E:<key>").
  std::vector<std::string> log;

  bool put(const std::string& ns, const std::string& key, const void* data,
           const std::size_t size, const std::uint32_t cost) {
    if (!consume_write()) return false;
    const std::string full = ns + "/" + key;
    const auto it = values_.find(full);
    const std::uint32_t old_cost = it == values_.end() ? 0U : it->second.cost;
    const std::uint32_t ns_cost = namespace_cost(ns, it == values_.end());
    if (used_ - old_cost + cost + ns_cost > capacity_) {
      ++full_refusals;  // ESP_ERR_NVS_NOT_ENOUGH_SPACE
      return false;
    }
    Value value{};
    value.bytes.assign(static_cast<const std::uint8_t*>(data),
                       static_cast<const std::uint8_t*>(data) + size);
    value.cost = cost;
    values_[full] = value;
    used_ = used_ - old_cost + cost + ns_cost;
    if (ns_cost != 0) namespaces_.insert(ns);
    peak_ = std::max(peak_, used_);
    log.push_back("W:" + key);
    return true;
  }

  bool get(const std::string& ns, const std::string& key, void* data,
           const std::size_t size, bool& found) const {
    found = false;
    const auto it = values_.find(ns + "/" + key);
    if (it == values_.end()) return true;
    if (it->second.bytes.size() != size) return false;  // size mismatch
    std::memcpy(data, it->second.bytes.data(), size);
    found = true;
    return true;
  }

  bool erase(const std::string& ns, const std::string& key) {
    if (iterating_) {
      ++erase_while_iterating;
      return false;
    }
    if (!consume_write()) return false;
    const auto it = values_.find(ns + "/" + key);
    if (it == values_.end()) return true;
    used_ -= it->second.cost;
    values_.erase(it);
    log.push_back("E:" + key);
    return true;
  }

  // Visits keys of `ns` starting with `prefix` (sorted, like a scan).
  template <typename Visit>
  void scan(const std::string& ns, const char prefix, Visit visit) {
    iterating_ = true;
    const std::string head = ns + "/";
    for (const auto& [full, value] : values_) {
      if (full.compare(0, head.size(), head) != 0) continue;
      const std::string key = full.substr(head.size());
      if (key.size() != 9 || key[0] != prefix) continue;
      if (!visit(static_cast<std::uint32_t>(
              std::stoul(key.substr(1), nullptr, 16)))) {
        break;
      }
    }
    iterating_ = false;
  }

  std::size_t count(const std::string& ns, const char prefix) {
    std::size_t result = 0;
    scan(ns, prefix, [&](std::uint32_t) {
      ++result;
      return true;
    });
    return result;
  }

  std::uint32_t used() const { return used_; }
  std::uint32_t peak() const { return peak_; }
  std::uint32_t capacity() const { return capacity_; }
  std::uint32_t full_refusals{0};
  std::uint32_t erase_while_iterating{0};

  // Test hook: overwrite raw bytes (corruption injection).
  void poke(const std::string& ns, const std::string& key, const void* data,
            const std::size_t size) {
    auto& value = values_[ns + "/" + key];
    value.bytes.assign(static_cast<const std::uint8_t*>(data),
                       static_cast<const std::uint8_t*>(data) + size);
    if (value.cost == 0) {
      value.cost = nvs_blob_entries(size);
      used_ += value.cost;
    }
  }

 private:
  struct Value {
    std::vector<std::uint8_t> bytes;
    std::uint32_t cost{0};
  };

  bool consume_write() {
    if (writes_left == 0) return false;
    if (writes_left > 0) --writes_left;
    return true;
  }
  std::uint32_t namespace_cost(const std::string& ns, const bool new_key) const {
    return new_key && namespaces_.count(ns) == 0 ? 1U : 0U;
  }

  std::uint32_t capacity_{0};
  std::uint32_t used_{0};
  std::uint32_t peak_{0};
  bool iterating_{false};
  std::map<std::string, Value> values_;
  std::set<std::string> namespaces_;
};

std::string slot_key(const char prefix, const std::uint32_t slot) {
  char key[12]{};
  std::snprintf(key, sizeof(key), "%c%08lx", prefix,
                static_cast<unsigned long>(slot));
  return key;
}

Status storage_failure() {
  return Status::error(StatusCode::StorageFailure, "model write failed");
}

class ModelCounterInventory final : public CounterInventory {
 public:
  explicit ModelCounterInventory(NvsModel& nvs) : nvs_(nvs) {}

  Status load(std::uint32_t slot, CounterRecord& record,
              bool& found) noexcept override {
    if (!nvs_.get(kNs, slot_key('c', slot), &record, sizeof(record), found)) {
      return Status::error(StatusCode::IntegrityError, "NVS blob size mismatch");
    }
    return Status::success();
  }
  Status commit(std::uint32_t slot, const CounterRecord& record) noexcept override {
    return nvs_.put(kNs, slot_key('c', slot), &record, sizeof(record),
                    nvs_blob_entries(sizeof(record)))
               ? Status::success()
               : storage_failure();
  }
  Status for_each_slot(SlotVisitor& visitor) noexcept override {
    nvs_.scan(kNs, 'c', [&](std::uint32_t slot) { return visitor.visit(slot); });
    return Status::success();
  }
  Status erase(std::uint32_t slot) noexcept override {
    return nvs_.erase(kNs, slot_key('c', slot)) ? Status::success()
                                                 : storage_failure();
  }
  Status load_witness(std::uint32_t& witness, bool& found) noexcept override {
    witness = 0;
    nvs_.get(kNs, "cmax", &witness, sizeof(witness), found);
    return Status::success();
  }
  Status commit_witness(std::uint32_t witness) noexcept override {
    return nvs_.put(kNs, "cmax", &witness, sizeof(witness), 1U)
               ? Status::success()
               : storage_failure();
  }

  static constexpr char kNs[] = "rlcounter";

 private:
  NvsModel& nvs_;
};

class ModelReplayInventory final : public ReplayInventory {
 public:
  explicit ModelReplayInventory(NvsModel& nvs) : nvs_(nvs) {}

  Status load_window(std::uint32_t slot, ReplayWindowRecord& record,
                     bool& found) noexcept override {
    return load(slot_key('r', slot), &record, sizeof(record), found);
  }
  Status commit_window(std::uint32_t slot,
                       const ReplayWindowRecord& record) noexcept override {
    return put(slot_key('r', slot), &record, sizeof(record));
  }
  Status load_floor(std::uint32_t slot, ReplayFloorRecord& record,
                    bool& found) noexcept override {
    return load(slot_key('f', slot), &record, sizeof(record), found);
  }
  Status commit_floor(std::uint32_t slot,
                      const ReplayFloorRecord& record) noexcept override {
    return put(slot_key('f', slot), &record, sizeof(record));
  }
  Status for_each_floor_slot(SlotVisitor& visitor) noexcept override {
    nvs_.scan(kNs, 'f', [&](std::uint32_t slot) { return visitor.visit(slot); });
    return Status::success();
  }

  static constexpr char kNs[] = "rlreplay";

 private:
  Status load(const std::string& key, void* data, std::size_t size, bool& found) {
    return nvs_.get(kNs, key, data, size, found)
               ? Status::success()
               : Status::error(StatusCode::IntegrityError, "NVS blob size mismatch");
  }
  Status put(const std::string& key, const void* data, std::size_t size) {
    return nvs_.put(kNs, key, data, size, nvs_blob_entries(size))
               ? Status::success()
               : storage_failure();
  }

  NvsModel& nvs_;
};

// The default "nvs" partition: only the boot session here.
class BootPartition {
 public:
  explicit BootPartition(const std::uint32_t capacity) : nvs_(capacity) {}
  bool next_session(std::uint32_t& session) {
    std::uint32_t stored = 0;
    bool found = false;
    nvs_.get("rlboot", "session", &stored, sizeof(stored), found);
    session = stored + 1U;
    return nvs_.put("rlboot", "session", &session, sizeof(session), 1U);
  }
  void wipe() { nvs_ = NvsModel(nvs_.capacity()); }

 private:
  NvsModel nvs_;
};

// --- TX / RX identities, mirroring DevelopmentPskSecurityProvider -------------

SecurityContext tx_context(const SecurityScope scope, const NodeId peer,
                           const std::uint32_t epoch) {
  SecurityContext context{};
  context.scope = scope;
  context.network = kNet;
  context.sender = kSelf;
  context.receiver = peer;
  context.epoch = epoch;
  return context;
}

SecurityContext rx_context(const SecurityScope scope, const NodeId peer,
                           const std::uint32_t epoch) {
  SecurityContext context = tx_context(scope, peer, epoch);
  context.sender = peer;
  context.receiver = kSelf;
  return context;
}

CounterLease make_lease(CounterStore& store, const SecurityContext& context) {
  const std::uint64_t fingerprint = replay_peer_fingerprint(context);
  const auto direction = static_cast<std::uint8_t>(
      (context.scope == SecurityScope::EndToEnd ? 2U : 0U) |
      (context.sender < context.receiver ? 0U : 1U));
  return CounterLease(store, ReplayGuard::floor_slot(context),
                      static_cast<std::uint32_t>(fingerprint ^ (fingerprint >> 32U)),
                      context.epoch, direction, 16);
}

CounterRecord counter_record(const std::uint32_t epoch, const std::uint64_t high_water) {
  CounterRecord record{};
  record.context_id = 7;
  record.key_epoch = epoch;
  record.direction = 0;
  record.layout = kCounterRecordLayout;
  record.high_water_exclusive = high_water;
  record.generation = 1;
  record.crc = crc32_iso_hdlc(ByteView{reinterpret_cast<const std::uint8_t*>(&record),
                                       offsetof(CounterRecord, crc)});
  return record;
}

// --- Budget arithmetic (V1-N07, mirrored by tools/nvs_budget.py) ---------------

void test_budget_arithmetic() {
  CHECK(nvs_blob_entries(sizeof(CounterRecord)) == 3);
  CHECK(nvs_blob_entries(sizeof(ReplayFloorRecord)) == 3);
  CHECK(nvs_blob_entries(sizeof(ReplayWindowRecord)) == 4);
  CHECK(kPeerStateEntriesPerPeer == 20);
  // 64 KiB = 16 pages: (15 * 126) * 80% = 1512 entries -> 75 peers >= 64.
  CHECK(max_persisted_peers_for_entries(16 * kNvsEntriesPerPage) == 75);
  // 128 KiB = 32 pages: (31 * 126) * 80% = 3124 entries -> 156 peers >= 128.
  CHECK(max_persisted_peers_for_entries(32 * kNvsEntriesPerPage) == 156);
  // The default 24 KiB NVS could not host a meaningful cap next to system data.
  CHECK(max_persisted_peers_for_entries(kNvsEntriesPerPage) == 0);
  CHECK(max_persisted_peers_for_entries(0) == 0);
  const PeerStateLimits limits = peer_state_limits(64);
  CHECK(limits.max_counter_records == 128 && limits.max_replay_peers == 128);
  CHECK(peer_state_limits(0xFFFFFFFFU).max_counter_records == 0xFFFFFFFFU);
  // Worst case of the caps stays within 80% of the usable entries.
  CHECK(64U * kPeerStateEntriesPerPeer + kPeerStateFixedEntries <=
        (15U * kNvsEntriesPerPage) * kPeerStateBudgetPercent / 100U);
  CHECK(128U * kPeerStateEntriesPerPeer + kPeerStateFixedEntries <=
        (31U * kNvsEntriesPerPage) * kPeerStateBudgetPercent / 100U);
}

// --- D2-b: sweep behind the witness ---------------------------------------------

void test_sweep_erases_only_dead_records_after_witness() {
  NvsModel nvs(10000);
  ModelCounterInventory inventory(nvs);
  CHECK_OK(inventory.commit(0x10, counter_record(3, 256)));
  CHECK_OK(inventory.commit(0x11, counter_record(5, 512)));
  CHECK_OK(inventory.commit(0x12, counter_record(9, 256)));   // current epoch
  CHECK_OK(inventory.commit(0x13, counter_record(12, 256)));  // newer: regression evidence
  CounterRecord corrupt = counter_record(2, 256);
  corrupt.high_water_exclusive = 1;  // CRC no longer matches
  CHECK_OK(inventory.commit(0x14, corrupt));
  CounterRecord legacy = counter_record(1, 256);
  legacy.layout = 1;  // pre-Wire-v2 layout, CRC recomputed
  legacy.crc = crc32_iso_hdlc(ByteView{reinterpret_cast<const std::uint8_t*>(&legacy),
                                       offsetof(CounterRecord, crc)});
  CHECK_OK(inventory.commit(0x15, legacy));
  const std::uint8_t short_blob[8]{};
  nvs.poke(ModelCounterInventory::kNs, slot_key('c', 0x16), short_blob,
           sizeof(short_blob));
  nvs.log.clear();

  BoundedCounterStore store;
  CHECK_OK(store.open(inventory, 64, 9));
  CHECK_OK(store.sweep_status());
  CHECK(store.witness_present() && store.witness() == 5);
  CHECK(store.sweep_report().erased == 2);
  CHECK(store.sweep_report().retained_current == 1);
  CHECK(store.sweep_report().retained_future == 1);
  CHECK(store.sweep_report().retained_unreadable == 3);
  CHECK(store.records() == 5 && store.records_known());
  CHECK(nvs.erase_while_iterating == 0);
  // C1 ordering: the witness write precedes every erase.
  CHECK(!nvs.log.empty() && nvs.log.front() == "W:cmax");
  CHECK(std::count(nvs.log.begin(), nvs.log.end(), std::string("E:c00000010")) == 1);
  CHECK(std::count(nvs.log.begin(), nvs.log.end(), std::string("E:c00000011")) == 1);
  bool found = false;
  CounterRecord record{};
  CHECK_OK(inventory.load(0x12, record, found));
  CHECK(found);
  CHECK_OK(inventory.load(0x14, record, found));
  CHECK(found);  // corrupt records are never swept (their epoch is unknown)
}

void test_sweep_in_batches_and_witness_monotonic() {
  NvsModel nvs(10000);
  ModelCounterInventory inventory(nvs);
  for (std::uint32_t slot = 0; slot < 50; ++slot) {
    CHECK_OK(inventory.commit(slot, counter_record(1 + slot % 7, 256)));
  }
  CHECK_OK(inventory.commit_witness(40));  // an older, larger witness stays
  BoundedCounterStore store;
  CHECK_OK(store.open(inventory, 64, 41));
  CHECK(store.sweep_report().erased == 50);
  CHECK(store.sweep_report().passes >= 4);  // 16 per pass + census pass
  CHECK(store.records() == 0);
  CHECK(store.witness() == 40);  // never lowered
  CHECK(nvs.count(ModelCounterInventory::kNs, 'c') == 0);
}

void test_witness_refuses_old_epochs() {
  // V1-N04: swept epochs never issue again (cmax commits before erasure).
  NvsModel nvs(10000);
  ModelCounterInventory inventory(nvs);
  CHECK_OK(inventory.commit(0x20, counter_record(5, 256)));
  {
    BoundedCounterStore store;
    CHECK_OK(store.open(inventory, 64, 6));
    CHECK(store.witness() == 5);
    // A lease on the dead epoch cannot reserve, so it never issues.
    CounterLease dead(store, 0x20, 7, 5, 0, 16);
    CHECK_OK(dead.initialize());
    std::uint64_t value = 0;
    const Status status = dead.next(value);
    CHECK(status.code == StatusCode::Conflict &&
          same_detail(status, kTxEpochWitnessDetail));
    CounterLease older(store, 0x21, 7, 2, 0, 16);
    CHECK_OK(older.initialize());
    CHECK(!older.next(value).ok());
    CHECK(store.witness_rejects() == 2);
    CounterLease live(store, 0x20, 7, 6, 0, 16);
    CHECK_OK(live.initialize());
    CHECK_OK(live.next(value));
    CHECK(value == 0);  // fresh key: counters restart safely
  }
  // A boot session at or below the witness (e.g. system NVS erased while
  // rlsec survived) fails closed before anything is swept or committed.
  BoundedCounterStore store;
  const Status regressed = store.open(inventory, 64, 5);
  CHECK(regressed.code == StatusCode::Conflict &&
        same_detail(regressed, kTxEpochWitnessDetail));
  CHECK(!store.is_open());
  CHECK(store.open(inventory, 64, 0).code == StatusCode::InvalidArgument);
  CHECK_OK(store.open(inventory, 64, 7));
}

void test_sweep_power_cuts_never_lose_the_witness() {
  // Cut at every write of the sweep: whatever lands, a record whose epoch
  // is not covered by a durable witness is never erased, and a later boot
  // finishes the job.
  for (int cut = 0; cut < 8; ++cut) {
    NvsModel nvs(10000);
    ModelCounterInventory inventory(nvs);
    for (std::uint32_t slot = 0; slot < 20; ++slot) {
      CHECK_OK(inventory.commit(slot, counter_record(1 + slot, 256)));
    }
    nvs.log.clear();
    nvs.writes_left = cut;
    BoundedCounterStore store;
    CHECK_OK(store.open(inventory, 64, 30));  // a failed sweep is not fatal
    std::uint32_t witness = 0;
    bool found = false;
    CHECK_OK(inventory.load_witness(witness, found));
    std::uint32_t max_erased = 0;
    for (std::uint32_t slot = 0; slot < 20; ++slot) {
      CounterRecord record{};
      bool present = false;
      CHECK_OK(inventory.load(slot, record, present));
      if (!present) max_erased = std::max(max_erased, 1 + slot);
    }
    CHECK(max_erased == 0 || (found && witness >= max_erased));
    if (cut == 0) {
      CHECK(!store.sweep_status().ok());
      CHECK(!store.records_known());
      // Unknown census: new slots are refused, never over-committed.
      CounterLease fresh(store, 0x99, 7, 30, 0, 16);
      CHECK_OK(fresh.initialize());
      std::uint64_t value = 0;
      const Status status = fresh.next(value);
      CHECK(status.code == StatusCode::NoCapacity &&
            same_detail(status, kPeerStateCapacityDetail));
    }
    nvs.writes_left = -1;
    BoundedCounterStore next_boot;
    CHECK_OK(next_boot.open(inventory, 64, 31));
    CHECK_OK(next_boot.sweep_status());
    CHECK(nvs.count(ModelCounterInventory::kNs, 'c') == 0);
  }
}

// --- D2-c: caps ------------------------------------------------------------------

void test_counter_cap_refuses_only_new_slots() {
  NvsModel nvs(10000);
  ModelCounterInventory inventory(nvs);
  BoundedCounterStore store;
  CHECK_OK(store.open(inventory, 2, 4));
  std::uint64_t value = 0;
  CounterLease a(store, 1, 7, 4, 0, 4);
  CounterLease b(store, 2, 7, 4, 0, 4);
  CounterLease c(store, 3, 7, 4, 0, 4);
  CHECK_OK(a.initialize());
  CHECK_OK(b.initialize());
  CHECK_OK(c.initialize());
  CHECK_OK(a.next(value));
  CHECK_OK(b.next(value));
  const Status refused = c.next(value);
  CHECK(refused.code == StatusCode::NoCapacity &&
        same_detail(refused, kPeerStateCapacityDetail));
  CHECK(store.capacity_rejects() == 1);
  CHECK(store.records() == 2);
  // Existing peers keep reserving new blocks past the cap.
  for (int i = 0; i < 20; ++i) {
    CHECK_OK(a.next(value));
  }
  CHECK(value == 20);
  CHECK(nvs.count(ModelCounterInventory::kNs, 'c') == 2);
}

void test_replay_cap_refuses_new_peers_never_evicts() {
  NvsModel nvs(10000);
  ModelReplayInventory inventory(nvs);
  BoundedReplayStore bounded;
  CHECK_OK(bounded.open(inventory, 2));
  ReplayGuard guard(bounded);
  ReplayGuard::Window w1{};
  ReplayGuard::Window w2{};
  ReplayGuard::Window w3{};
  CHECK_OK(guard.open_context(rx_context(SecurityScope::Link, 11, 1), w1));
  CHECK_OK(guard.accept(w1, 0));
  CHECK_OK(guard.open_context(rx_context(SecurityScope::Link, 12, 1), w2));
  CHECK_OK(guard.accept(w2, 0));
  const Status refused =
      guard.open_context(rx_context(SecurityScope::Link, 13, 1), w3);
  CHECK(refused.code == StatusCode::NoCapacity &&
        same_detail(refused, kPeerStateCapacityDetail));
  CHECK(bounded.capacity_rejects() == 1 && bounded.peers() == 2);
  CHECK(nvs.count(ModelReplayInventory::kNs, 'f') == 2);
  CHECK(nvs.count(ModelReplayInventory::kNs, 'r') == 2);
  // Existing peers continue (V1-N05), including a newer epoch of peer 11.
  CHECK_OK(guard.accept(w1, 1));
  CHECK(!guard.accept(w1, 1).ok());
  ReplayGuard::Window w1b{};
  CHECK_OK(guard.open_context(rx_context(SecurityScope::Link, 11, 2), w1b));
  CHECK_OK(guard.accept(w1b, 0));
  CHECK(!guard.open_context(rx_context(SecurityScope::Link, 11, 1), w1).ok());
  // A restart recounts the persisted floors.
  BoundedReplayStore reopened;
  CHECK_OK(reopened.open(inventory, 2));
  CHECK(reopened.peers() == 2 && reopened.peers_known());
}

void test_window_requires_floor() {
  NvsModel nvs(10000);
  ModelReplayInventory inventory(nvs);
  BoundedReplayStore bounded;
  CHECK_OK(bounded.open(inventory, 4));
  ReplayWindowRecord record{};
  const Status status = bounded.commit_window(0x42, record);
  CHECK(status.code == StatusCode::IntegrityError);
  CHECK(nvs.count(ModelReplayInventory::kNs, 'r') == 0);
  BoundedReplayStore closed;
  CHECK(closed.commit_floor(1, ReplayFloorRecord{}).code == StatusCode::InvalidState);
  BoundedCounterStore closed_counters;
  CHECK(closed_counters.commit(1, CounterRecord{}).code == StatusCode::InvalidState);
}

// --- Churn: 200 cumulative peers against a fixed-capacity partition -------------

struct PeerModel {
  NodeId id{0};
  std::uint32_t epoch{1};
  std::uint64_t next_link_counter{0};
  std::uint64_t next_end_counter{0};
};

using KeyCounter = std::tuple<int, NodeId, NodeId, std::uint32_t, std::uint64_t>;

KeyCounter key_counter(const SecurityContext& context, const std::uint64_t counter) {
  return KeyCounter{static_cast<int>(context.scope), context.sender, context.receiver,
                    context.epoch, counter};
}

void test_churn_200_peers_fixed_capacity() {
  constexpr std::uint32_t kMaxPeers = 12;
  const PeerStateLimits limits = peer_state_limits(kMaxPeers);
  // The security partition holds exactly the budget; the separate boot
  // partition is tiny and must never be blocked by peer churn.
  const std::uint32_t budget = kMaxPeers * kPeerStateEntriesPerPeer + kPeerStateFixedEntries;
  NvsModel rlsec(budget);
  BootPartition boot(4);
  ModelCounterInventory counter_inventory(rlsec);
  ModelReplayInventory replay_inventory(rlsec);

  std::vector<PeerModel> peers;
  for (NodeId id = 1; id <= 200; ++id) peers.push_back(PeerModel{id, 1, 0, 0});

  std::set<KeyCounter> issued;                    // our TX (key, counter)
  std::vector<std::pair<SecurityContext, std::uint64_t>> accepted;  // RX history
  std::set<NodeId> admitted;
  std::uint32_t tx_capacity_refusals = 0;
  std::uint32_t rx_capacity_refusals = 0;
  std::uint32_t reuse = 0;
  std::uint32_t replays_accepted = 0;

  constexpr int kBoots = 60;
  for (int boot_index = 0; boot_index < kBoots; ++boot_index) {
    std::uint32_t session = 0;
    CHECK(boot.next_session(session));  // never blocked by rlsec

    BoundedCounterStore counters;
    CHECK_OK(counters.open(counter_inventory, limits.max_counter_records, session));
    CHECK_OK(counters.sweep_status());
    BoundedReplayStore replay;
    CHECK_OK(replay.open(replay_inventory, limits.max_replay_peers));
    ReplayGuard guard(replay);

    // Replay every frame ever accepted (all earlier boots): the fresh RAM
    // state must reject each one from the persisted floors/ceilings.
    for (const auto& [context, counter] : accepted) {
      ReplayGuard::Window window{};
      if (guard.open_context(context, window).ok() &&
          guard.accept(window, counter).ok()) {
        ++replays_accepted;
      }
    }

    // This boot talks to a sliding group of 10 peers: 200 cumulative peers
    // over the run. Some peers reboot (their epoch advances).
    std::map<std::pair<int, NodeId>, CounterLease> leases;
    std::map<std::pair<int, NodeId>, ReplayGuard::Window> windows;
    const std::size_t first = static_cast<std::size_t>(boot_index) * 190U / kBoots;
    for (std::size_t index = first; index < first + 10 && index < peers.size(); ++index) {
      PeerModel& peer = peers[index];
      if ((boot_index + index) % 3 == 0) {
        ++peer.epoch;
        peer.next_link_counter = 0;
        peer.next_end_counter = 0;
      }
      for (const SecurityScope scope : {SecurityScope::Link, SecurityScope::EndToEnd}) {
        // TX to the peer.
        const SecurityContext tx = tx_context(scope, peer.id, session);
        auto lease_it =
            leases.emplace(std::make_pair(static_cast<int>(scope), peer.id),
                           make_lease(counters, tx))
                .first;
        CHECK_OK(lease_it->second.initialize());
        for (int frame = 0; frame < 20; ++frame) {
          std::uint64_t counter = 0;
          const Status status = lease_it->second.next(counter);
          if (!status) {
            CHECK(same_detail(status, kPeerStateCapacityDetail));
            ++tx_capacity_refusals;
            break;
          }
          if (!issued.insert(key_counter(tx, counter)).second) ++reuse;
        }
        // RX from the peer.
        const SecurityContext rx = rx_context(scope, peer.id, peer.epoch);
        ReplayGuard::Window& window =
            windows[std::make_pair(static_cast<int>(scope), peer.id)];
        const Status open_status = guard.open_context(rx, window);
        if (!open_status) {
          CHECK(same_detail(open_status, kPeerStateCapacityDetail));
          ++rx_capacity_refusals;
          continue;
        }
        admitted.insert(peer.id);
        std::uint64_t& next = scope == SecurityScope::Link ? peer.next_link_counter
                                                           : peer.next_end_counter;
        for (int frame = 0; frame < 70; ++frame) {
          const std::uint64_t counter = next++;
          CHECK_OK(guard.accept(window, counter));
          accepted.emplace_back(rx, counter);
          // Immediate duplicates are rejected inside the boot, too.
          if (frame % 17 == 0 && guard.accept(window, counter).ok()) ++replays_accepted;
        }
      }
    }
    for (auto& [key, window] : windows) (void)guard.close_context(window);

    // Invariants after every boot.
    CHECK(rlsec.count(ModelCounterInventory::kNs, 'c') <= limits.max_counter_records);
    CHECK(rlsec.count(ModelReplayInventory::kNs, 'f') <= limits.max_replay_peers);
    CHECK(rlsec.count(ModelReplayInventory::kNs, 'r') <=
          rlsec.count(ModelReplayInventory::kNs, 'f'));
    CHECK(rlsec.used() <= budget);
    CHECK(counters.records() <= limits.max_counter_records);
    CHECK(replay.peers() <= limits.max_replay_peers);
  }

  CHECK(reuse == 0);
  CHECK(replays_accepted == 0);
  CHECK(rlsec.full_refusals == 0);  // the cap stops growth before NVS does
  CHECK(rlsec.peak() <= budget);
  CHECK(rx_capacity_refusals > 0);  // 200 cumulative RX peers > cap: refused, counted
  CHECK(admitted.size() == kMaxPeers);
  CHECK(tx_capacity_refusals == 0);  // per-boot TX peers fit; old TX state swept
  CHECK(issued.size() == static_cast<std::size_t>(kBoots) * 10U * 2U * 20U);
}

// A boot-session regression (system NVS wiped, rlsec kept) must not let any
// (key, counter) repeat: the witness refuses the stale sessions, and records
// newer than the regressed session wedge only their own slots.
void test_boot_session_regression_never_reuses() {
  // V1-N04: a boot session at or below cmax fails closed before any use.
  NvsModel rlsec(10000);
  BootPartition boot(4);
  ModelCounterInventory inventory(rlsec);
  std::set<KeyCounter> issued;
  std::uint32_t reuse = 0;
  auto run_boot = [&](const std::uint32_t session, const bool expect_open) {
    BoundedCounterStore counters;
    const Status open_status = counters.open(inventory, 64, session);
    CHECK(open_status.ok() == expect_open);
    if (!open_status) return;
    // Peers 1..3 every boot, plus one peer only ever contacted in this
    // session: its records are swept later, so only the witness remembers
    // that this (key, counter) space was used.
    for (const NodeId peer : {NodeId{1}, NodeId{2}, NodeId{3}, NodeId{10 + session}}) {
      const SecurityContext tx = tx_context(SecurityScope::Link, peer, session);
      CounterLease lease = make_lease(counters, tx);
      if (!lease.initialize()) continue;  // newer record at the slot: Conflict
      for (int frame = 0; frame < 40; ++frame) {
        std::uint64_t counter = 0;
        if (!lease.next(counter)) break;
        if (!issued.insert(key_counter(tx, counter)).second) ++reuse;
      }
    }
  };
  std::uint32_t session = 0;
  for (int i = 0; i < 5; ++i) {
    CHECK(boot.next_session(session));
    run_boot(session, true);
  }
  CHECK(session == 5);
  // Witness is 4 now (records of session 4 were swept at session 5).
  boot.wipe();
  for (int i = 0; i < 4; ++i) {
    CHECK(boot.next_session(session));
    run_boot(session, false);  // sessions 1..4 are at or below the witness
  }
  CHECK(boot.next_session(session));
  CHECK(session == 5);
  run_boot(session, true);  // session 5 records exist: same-epoch resume
  CHECK(boot.next_session(session));
  run_boot(session, true);
  CHECK(reuse == 0);
}

}  // namespace

int main() {
  test_budget_arithmetic();
  test_sweep_erases_only_dead_records_after_witness();
  test_sweep_in_batches_and_witness_monotonic();
  test_witness_refuses_old_epochs();
  test_sweep_power_cuts_never_lose_the_witness();
  test_counter_cap_refuses_only_new_slots();
  test_replay_cap_refuses_new_peers_never_evicts();
  test_window_requires_floor();
  test_churn_200_peers_fixed_capacity();
  test_boot_session_regression_never_reuses();
  if (failures != 0) {
    std::fprintf(stderr, "%d peer-state check(s) failed\n", failures);
    return 1;
  }
  std::puts("peer state tests passed");
  return 0;
}
