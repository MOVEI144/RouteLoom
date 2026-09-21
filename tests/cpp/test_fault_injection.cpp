// Cross-cutting fault-injection tests (issue #20): byte-granular power cuts
// and corruption on the counter-lease, replay-guard and trust-store
// persistence boundaries; backwards/stalled/huge-jump clock faults across
// the node's time-driven state; and bounded-capacity saturation of the
// dedup pool, TX scheduler, neighbor table and route table.
//
// Deliberately NOT duplicated here — per-surface coverage lives in:
//   authority ledger ............. test_ledger.cpp (+ test_ledger.hpp)
//   trust-store slot sweep ....... test_trust_store.cpp
//   device credential ............ test_device_credential.cpp
//   replay/counter basics ........ test_hardening.cpp
//   scheduler classes/BUSY ....... test_congestion.cpp
//   terminal-delivery eviction ... test_main.cpp
//
// Only the gaps are exercised: mid-lease slot revalidation, torn counter
// commits, floor vanish/foreign-floor faults, an interrupted trust recover(),
// the neighbor decay windows under clock faults, dedup reserve/cap/eviction
// bounds, and queue/neighbor/route-table saturation with live-state checks.

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <map>
#include <set>
#include <vector>

#include "routeloom/counter_store.hpp"
#include "routeloom/crc32.hpp"
#include "routeloom/node.hpp"
#include "routeloom/replay.hpp"
#include "routeloom/routing.hpp"
#include "routeloom/trust_store.hpp"
#include "routeloom/types.hpp"
#include "routeloom/wire.hpp"

#include "test_provisioning.hpp"
#include "test_security.hpp"
#include "test_sim.hpp"

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
using routeloom_test::CapturingObserver;
using routeloom_test::FaultyTrustStorage;
using routeloom_test::SimNetwork;
using routeloom_test::SimRadio;
using routeloom_test::SimWorld;
using routeloom_test::TestKeyPair;
using routeloom_test::TestSecurity;
using routeloom_test::test_image;
using routeloom_test::test_keypair;

const TestKeyPair kRoot = test_keypair(0x42);

constexpr NetworkId kNet = 7;
const std::uint8_t kPayload[] = "fault-injection";
ByteView payload_view() { return ByteView{kPayload, sizeof(kPayload) - 1}; }

// --- Record CRC helpers (same formulas as the production codecs) --------------

std::uint32_t record_crc(const CounterRecord& record) {
  return crc32_iso_hdlc(
      ByteView{reinterpret_cast<const std::uint8_t*>(&record),
               offsetof(CounterRecord, crc)});
}
std::uint32_t record_crc(const ReplayFloorRecord& record) {
  return crc32_iso_hdlc(
      ByteView{reinterpret_cast<const std::uint8_t*>(&record),
               offsetof(ReplayFloorRecord, crc)});
}

// --- Byte-granular storage doubles -------------------------------------------
// Slots are raw byte arrays so a "torn" commit lands only a prefix: the next
// load sees new head bytes over a stale tail, and the record CRC must fail.

class TornCounterStore final : public CounterStore {
 public:
  Status load(std::uint32_t slot, CounterRecord& record,
              bool& found) noexcept override {
    if (fail_loads) {
      return Status::error(StatusCode::StorageFailure, "injected load failure");
    }
    const auto it = slots_.find(slot);
    found = it != slots_.end();
    if (found) std::memcpy(&record, it->second.data(), sizeof(record));
    return Status::success();
  }
  Status commit(std::uint32_t slot, const CounterRecord& record) noexcept override {
    const std::size_t call = commit_calls_++;
    if (call == cut_call_) {
      std::memcpy(slots_[slot].data(), &record, cut_bytes_);
      return Status::error(StatusCode::StorageFailure, "power cut mid commit");
    }
    if (call == drop_call_ || fail_commits) {
      return Status::error(StatusCode::StorageFailure, "commit dropped");
    }
    std::memcpy(slots_[slot].data(), &record, sizeof(record));
    return Status::success();
  }
  // Write a fully-formed record directly (seed/forge); CRC is the caller's.
  void plant(std::uint32_t slot, const CounterRecord& record) {
    std::memcpy(slots_[slot].data(), &record, sizeof(record));
  }
  // The next commit call lands only `bytes` prefix then fails.
  void cut_next_commit(std::size_t bytes) {
    cut_call_ = commit_calls_;
    cut_bytes_ = bytes;
  }
  std::size_t commits() const { return commit_calls_; }

  bool fail_loads{false};
  bool fail_commits{false};

 private:
  std::map<std::uint32_t, std::array<std::uint8_t, sizeof(CounterRecord)>> slots_;
  std::size_t commit_calls_{0};
  std::size_t cut_call_{std::numeric_limits<std::size_t>::max()};
  std::size_t cut_bytes_{0};
  std::size_t drop_call_{std::numeric_limits<std::size_t>::max()};
};

class TornReplayStore final : public ReplayStore {
 public:
  Status load_window(std::uint32_t slot, ReplayWindowRecord& record,
                     bool& found) noexcept override {
    if (fail_loads) {
      return Status::error(StatusCode::StorageFailure, "window load failed");
    }
    const auto it = windows_.find(slot);
    found = it != windows_.end();
    if (found) std::memcpy(&record, it->second.data(), sizeof(record));
    return Status::success();
  }
  Status commit_window(std::uint32_t slot,
                       const ReplayWindowRecord& record) noexcept override {
    if (fail_commits) {
      return Status::error(StatusCode::StorageFailure, "window commit dropped");
    }
    std::memcpy(windows_[slot].data(), &record, sizeof(record));
    return Status::success();
  }
  Status load_floor(std::uint32_t slot, ReplayFloorRecord& record,
                    bool& found) noexcept override {
    if (fail_loads) {
      return Status::error(StatusCode::StorageFailure, "floor load failed");
    }
    const auto it = floors_.find(slot);
    found = it != floors_.end();
    if (found) std::memcpy(&record, it->second.data(), sizeof(record));
    return Status::success();
  }
  Status commit_floor(std::uint32_t slot,
                      const ReplayFloorRecord& record) noexcept override {
    if (fail_commits) {
      return Status::error(StatusCode::StorageFailure, "floor commit dropped");
    }
    std::memcpy(floors_[slot].data(), &record, sizeof(record));
    return Status::success();
  }
  void plant_floor(std::uint32_t slot, const ReplayFloorRecord& record) {
    std::memcpy(floors_[slot].data(), &record, sizeof(record));
  }
  void erase_floor(std::uint32_t slot) { floors_.erase(slot); }

  bool fail_loads{false};
  bool fail_commits{false};

 private:
  std::map<std::uint32_t, std::array<std::uint8_t, sizeof(ReplayWindowRecord)>>
      windows_;
  std::map<std::uint32_t, std::array<std::uint8_t, sizeof(ReplayFloorRecord)>>
      floors_;
};

// A radio that accepts every frame but only reports completion when the test
// asks: the physical slot stays in-flight until ack() runs the driver
// callback — the fixture for clock-fault tests where wall time misbehaves.
class SinkRadio final : public RadioPort {
 public:
  Status send(NodeId peer, std::uint64_t token, ByteView) noexcept override {
    pending_peer_ = peer;
    pending_token_ = token;
    has_pending_ = true;
    ++sent;
    return Status::success();
  }
  void ack(MeshNode& node, MonotonicMs now, bool ok = true) {
    if (!has_pending_) return;
    has_pending_ = false;
    node.on_radio_tx_result(pending_token_, ok, now);
  }
  Status recover() noexcept override { return Status::success(); }
  std::size_t sent{0};

 private:
  NodeId pending_peer_{0};
  std::uint64_t pending_token_{0};
  bool has_pending_{false};
};

bool has_terminal_delivery(const CapturingObserver* obs) {
  for (const auto& event : obs->delivery_events) {
    if (event.state == DeliveryState::Delivered ||
        event.state == DeliveryState::Failed ||
        event.state == DeliveryState::Expired ||
        event.state == DeliveryState::Indeterminate) {
      return true;
    }
  }
  return false;
}

// --- Frame crafting (same pattern as test_congestion.cpp, kept local) ---------

wire::Header mk_header(FrameType type, NodeId origin, NodeId destination,
                       NodeId previous, NodeId next, MessageId message,
                       std::uint8_t flags, std::uint32_t deadline_ms) {
  wire::Header h{};
  h.type = type;
  h.flags = flags;
  h.delivery = DeliveryClass::Reliable;
  h.delivery_round = 0;
  h.hop_remaining = kDefaultHopLimit;
  h.network = kNet;
  h.origin = origin;
  h.destination = destination;
  h.previous_hop = previous;
  h.next_hop = next;
  h.message = message;
  h.remaining_deadline_ms = deadline_ms;
  h.original_lifetime_ms = deadline_ms;
  h.link_epoch = 1;
  h.end_epoch = 1;
  return h;
}

wire::EncodedFrame craft_frame(TestSecurity& cipher, const wire::Header& header,
                               ByteView payload) {
  wire::PlainFrame plain{};
  plain.header = header;
  plain.payload_size = payload.size;
  if (payload.size > 0) {
    std::memcpy(plain.payload.data(), payload.data, payload.size);
  }
  wire::EncodedFrame out{};
  CHECK_OK(wire::encode_new(plain, cipher, out));
  return out;
}

// End-protected DATA `prev` -> `node`, bound for `destination` (== node for a
// terminal pin, a third party for transit). `origin` may be a phantom — a
// relay/terminal never end-verifies the claimed origin identity against the
// neighbor table.
wire::EncodedFrame craft_data(TestSecurity& cipher, NodeId prev, NodeId node,
                              NodeId origin, NodeId destination,
                              std::uint64_t seq, std::uint32_t deadline_ms) {
  return craft_frame(
      cipher,
      mk_header(FrameType::Data, origin, destination, prev, node,
                MessageId{42, seq}, wire::kFlagEndProtected, deadline_ms),
      payload_view());
}

void inject(SimWorld& world, NodeId receiver, NodeId peer,
            const wire::EncodedFrame& frame, MonotonicMs now) {
  world.at(receiver)->on_radio_receive(peer, frame.view(), RadioRxMetadata{-60},
                                       now);
}

// ============================================================================
// Storage faults — counter leases
// ============================================================================

// A commit that lands only a byte prefix leaves a physically torn record.
// The CRC must catch it on the next load — the lease fails closed and a
// freshly-initialized lease must NOT silently rebase to counter 0 (that
// would reissue nonces a peer may already have seen pre-crash).
void test_counter_torn_commit_fails_closed() {
  TornCounterStore store;
  CounterLease lease(store, 1, 99, 1, 0, 4);
  CHECK_OK(lease.initialize());
  std::uint64_t value = 0;
  for (std::uint64_t expect = 0; expect < 4; ++expect) {
    CHECK_OK(lease.next(value));
    CHECK(value == expect);  // drains the committed [0,4) block
  }
  // Tear at 20 bytes: the new record body lands but the 8-byte seal prefix
  // does not — the classic "wrote data, lost power before the CRC" cut.
  store.cut_next_commit(20);
  CHECK(lease.next(value).code == StatusCode::StorageFailure);
  // Every subsequent call sees the corrupted record and fails closed.
  CHECK(lease.next(value).code == StatusCode::IntegrityError);
  CounterLease fresh(store, 1, 99, 1, 0, 4);
  CHECK(fresh.initialize().code == StatusCode::IntegrityError);
  // The torn bytes are still there — no implicit erase/reset happened.
  CHECK(fresh.initialize().code == StatusCode::IntegrityError);
}

// The shared slot is re-validated on every block reservation: a record that
// moved FORWARD under a sibling lease is adopted (never rewound into reuse),
// a record rewound behind the live mark is corruption, and a newer epoch's
// record owns the slot outright.
void test_counter_midlease_slot_revalidation() {
  TornCounterStore store;
  CounterLease stale(store, 7, 99, 1, 0, 4);
  CHECK_OK(stale.initialize());
  std::uint64_t value = 0;
  CHECK_OK(stale.next(value));  // commits [0,4), issues 0
  CHECK(value == 0);
  // A second lease on the same slot reserves [4,8) ahead of `stale`.
  CounterLease newer(store, 7, 99, 1, 0, 4);
  CHECK_OK(newer.initialize());
  CHECK_OK(newer.next(value));
  CHECK(value == 4);
  // `stale` drains its own reservation, then must adopt the persisted mark:
  // the next reservation covers [8,12) — counters 4..7 are never reissued.
  CHECK_OK(stale.next(value)); CHECK(value == 1);
  CHECK_OK(stale.next(value)); CHECK(value == 2);
  CHECK_OK(stale.next(value)); CHECK(value == 3);
  CHECK_OK(stale.next(value));
  CHECK(value == 8);

  // A rewound record (valid CRC, regressed high-water) is corruption even
  // though it is structurally intact.
  CounterRecord rewound{};
  rewound.context_id = 99;
  rewound.key_epoch = 1;
  rewound.high_water_exclusive = 4;
  rewound.generation = 99;
  rewound.crc = record_crc(rewound);
  store.plant(7, rewound);
  CHECK_OK(stale.next(value)); CHECK(value == 9);   // committed block drains
  CHECK_OK(stale.next(value)); CHECK(value == 10);
  CHECK_OK(stale.next(value)); CHECK(value == 11);
  CHECK(stale.next(value).code == StatusCode::IntegrityError);
  CHECK(stale.next(value).code == StatusCode::IntegrityError);

  // A newer epoch owns the slot now: the stale lease can never overwrite it.
  CounterRecord rekeyed{};
  rekeyed.context_id = 99;
  rekeyed.key_epoch = 2;
  rekeyed.high_water_exclusive = 40;
  rekeyed.generation = 100;
  rekeyed.crc = record_crc(rekeyed);
  store.plant(7, rekeyed);
  CHECK(stale.next(value).code == StatusCode::Conflict);
}

// At the u64 ceiling the lease must exhaust, never wrap to 0 — a wrapped
// high-water would reissue the entire counter space under the same epoch.
void test_counter_exhaustion_never_wraps() {
  TornCounterStore store;
  CounterRecord seeded{};
  seeded.context_id = 99;
  seeded.key_epoch = 1;
  seeded.high_water_exclusive = UINT64_MAX - 1;
  seeded.generation = 7;
  seeded.crc = record_crc(seeded);
  store.plant(3, seeded);

  // A 4-wide block cannot fit: end_ = MAX-1 would overflow the mark.
  CounterLease wide(store, 3, 99, 1, 0, 4);
  CHECK_OK(wide.initialize());
  std::uint64_t value = 0;
  CHECK(wide.next(value).code == StatusCode::CounterExhausted);

  // A 1-wide block fits exactly once: end_ reaches MAX, issuing MAX-1.
  CounterLease tight(store, 3, 99, 1, 0, 1);
  CHECK_OK(tight.initialize());
  CHECK_OK(tight.next(value));
  CHECK(value == UINT64_MAX - 1);
  CHECK(tight.next(value).code == StatusCode::CounterExhausted);
  CHECK(tight.next(value).code == StatusCode::CounterExhausted);
  CHECK(value == UINT64_MAX - 1);  // failures never write the output
}

// A load failure inside the shared-slot revalidation propagates and issues
// nothing; once the store recovers the lease resumes at the committed mark.
void test_counter_load_failure_propagates() {
  TornCounterStore store;
  CounterLease lease(store, 5, 99, 1, 0, 2);
  CHECK_OK(lease.initialize());
  std::uint64_t value = 0;
  CHECK_OK(lease.next(value));
  CHECK(value == 0);
  CHECK_OK(lease.next(value));
  CHECK(value == 1);
  store.fail_loads = true;
  CHECK(lease.next(value).code == StatusCode::StorageFailure);
  CHECK(value == 1);  // untouched by the failed call
  store.fail_loads = false;
  CHECK_OK(lease.next(value));
  CHECK(value == 2);  // resumes past the committed water mark
}

// ============================================================================
// Storage faults — replay guard
// ============================================================================

// accept() re-validates the shared floor on every frame: a floor load
// failure propagates and the frame is not treated as accepted — the same
// counter is admissible once the store recovers.
void test_replay_accept_load_failure() {
  TornReplayStore store;
  ReplayGuard guard(store);
  ReplayGuard::Window window{};
  const SecurityContext ctx{SecurityScope::EndToEnd, kNet, 10, 20, 3};
  CHECK_OK(guard.open_context(ctx, window));
  CHECK_OK(guard.accept(window, 5));
  store.fail_loads = true;
  CHECK(guard.accept(window, 6).code == StatusCode::StorageFailure);
  store.fail_loads = false;
  CHECK_OK(guard.accept(window, 6));
  CHECK(guard.accept(window, 6).code == StatusCode::ReplayRejected);
  CHECK(guard.accept(window, 5).code == StatusCode::ReplayRejected);
}

// If the floor record vanishes between open_context and accept, the cached
// window must refuse — committing over a floor that cannot be verified is
// the mid-epoch-loss case. check_floor then cold-start restores the floor,
// after which the INTACT window record resumes: fresh counters pass while
// the persisted bitmap still rejects the old ones.
void test_replay_floor_vanish_mid_session() {
  TornReplayStore store;
  ReplayGuard guard(store);
  ReplayGuard::Window window{};
  const SecurityContext ctx{SecurityScope::EndToEnd, kNet, 10, 20, 3};
  CHECK_OK(guard.open_context(ctx, window));
  CHECK_OK(guard.accept(window, 5));

  store.erase_floor(ReplayGuard::floor_slot(ctx));
  CHECK(guard.accept(window, 6).code == StatusCode::ReplayRejected);
  // The vanished floor is rebuilt explicitly (cold-start rule), not by
  // silently admitting the frame that tripped over it.
  CHECK_OK(guard.check_floor(ctx));
  CHECK_OK(guard.accept(window, 6));
  CHECK(guard.accept(window, 5).code == StatusCode::ReplayRejected);
}

// A structurally valid floor record carrying another peer pair's
// fingerprint — slot pollution, not bit rot — is an integrity error at both
// the per-frame gate and context open, never a fresh floor.
void test_replay_foreign_floor_record() {
  TornReplayStore store;
  ReplayGuard guard(store);
  ReplayGuard::Window window{};
  const SecurityContext ctx{SecurityScope::EndToEnd, kNet, 10, 20, 3};
  CHECK_OK(guard.open_context(ctx, window));
  CHECK_OK(guard.accept(window, 5));

  ReplayFloorRecord foreign{};
  foreign.peer_fingerprint = 0xDEADBEEFCAFEF00DULL;  // not this pair's
  foreign.minimum_epoch = 1;
  foreign.initialized = 1;
  foreign.generation = 9;
  foreign.crc = record_crc(foreign);
  store.plant_floor(ReplayGuard::floor_slot(ctx), foreign);

  CHECK(guard.check_floor(ctx).code == StatusCode::IntegrityError);
  CHECK(guard.accept(window, 7).code == StatusCode::IntegrityError);
  ReplayGuard::Window reopened{};
  CHECK(guard.open_context(ctx, reopened).code == StatusCode::IntegrityError);
}

// ============================================================================
// Storage faults — trust store (fixture: test_provisioning.hpp)
// ============================================================================

// recover() writes the attested image to BOTH slots. A power cut inside the
// second slot's pending write must not leave a falsely clean store: the
// next boot adopts the landed twin as a known value, marks uncertain, and
// commits stay refused until an operator re-attests above the proven floor.
void test_trust_recover_power_cut_midway() {
  FaultyTrustStorage storage;
  {
    TrustStore store(storage);
    CHECK_OK(store.initialize());
    CHECK_OK(store.commit_image(test_image(1, kNet, kRoot)));  // slot 0
    CHECK_OK(store.commit_image(test_image(2, kNet, kRoot)));  // slot 1
  }
  // Corrupt both committed images -> quarantine on the next boot.
  storage.corrupt(0, 100);
  storage.corrupt(1, 100);
  {
    TrustStore store(storage);
    CHECK(store.initialize().code == StatusCode::IntegrityError);
    CHECK(store.quarantined());
    // Two write calls per store_image: pending body, then the seal. Cut the
    // SECOND slot's pending write (call index +2) inside the record head.
    storage.cut_call = storage.write_calls + 2;
    storage.cut_bytes = 8;
    CHECK(store.recover(test_image(3, kNet, kRoot)).code ==
          StatusCode::StorageFailure);
  }
  // Reboot: slot 0 committed the epoch-3 twin; slot 1's torn head is
  // corrupt -> known value + uncertain (sibling loss is unproven).
  TrustStore reboot(storage);
  CHECK(reboot.initialize().code == StatusCode::IntegrityError);
  CHECK(reboot.has_active());
  CHECK(reboot.uncertain());
  CHECK(!reboot.quarantined());
  CHECK(reboot.store_epoch() == 3);
  CHECK(reboot.epoch_floor() == 3);
  CHECK(reboot.commit_image(test_image(4, kNet, kRoot)).code ==
        StatusCode::RecoveryRequired);
  // The floor proved by the interrupted recovery still bounds re-recovery.
  CHECK(reboot.recover(test_image(3, kNet, kRoot)).code ==
        StatusCode::InvalidArgument);
  CHECK_OK(reboot.recover(test_image(4, kNet, kRoot)));
  CHECK(!reboot.uncertain() && !reboot.quarantined());
  CHECK(reboot.store_epoch() == 4);
  // And the healed twin pair commits normally afterwards.
  CHECK_OK(reboot.commit_image(test_image(5, kNet, kRoot)));
}

// A dead slot that reads all-zero (not just all-0xFF) is the NVS-erased
// convention too: both-zero slots are a cold start, never corruption.
void test_trust_zero_fill_cold_start() {
  FaultyTrustStorage storage;
  storage.fill(0, 0x00);
  storage.fill(1, 0x00);
  TrustStore store(storage);
  CHECK_OK(store.initialize());
  CHECK(!store.has_active() && !store.quarantined() && !store.uncertain());
  CHECK_OK(store.commit_image(test_image(1, kNet, kRoot)));
  CHECK(store.store_epoch() == 1);
}

// ============================================================================
// Clock faults
// ============================================================================

// The neighbor exchange/sojourn decay windows used to halve counters in a
// `while` loop driven by `now_ms - anchor` — unsigned arithmetic makes a
// backwards clock read as ~2^63 elapsed windows and the loop never returns.
// The same applies to a huge forward jump. Both must collapse in O(1).
void test_clock_faults_decay_windows_bounded() {
  SinkRadio radio;
  TestSecurity security;
  CapturingObserver observer;
  NodeConfig config{};
  config.network = kNet;
  config.node = 1;
  config.message_session = 100;
  config.route_advertisement_period_ms = 30000;
  config.route_lifetime_ms = 60000;
  MeshNode node(config, radio, security, observer);
  CHECK_OK(node.start(100));
  CHECK_OK(node.add_neighbor(2, 1, 100));

  SendOptions options{};
  options.lifetime_ms = 5000;
  MessageId id{};
  CHECK_OK(node.send(2, payload_view(), options, 100, id));
  // Dispatch at t=100 arms the per-peer exchange/sojourn window anchors.
  node.poll(100);
  CHECK(radio.sent >= 1);
  radio.ack(node, 100);

  // Backwards clock — this hung forever before the decay collapse fix.
  node.poll(50);
  node.poll(49);
  node.poll(50);  // repeated backwards reads stay bounded
  // A huge forward jump collapses into a single bounded decay step.
  const MonotonicMs far = 50 + (std::uint64_t{1} << 50);
  node.poll(far);
  node.poll(far + 1000);
  // The node is still sane: the neighbor metric is finite (not corrupted to
  // infinity or zero) and fresh work is admitted.
  CHECK(node.peer_link_cost(2) != kInfiniteRouteMetric);
  CHECK(node.peer_link_cost(2) >= 1);
  // The direct route expired across the jump — re-observe the peer, then
  // confirm fresh work still dispatches at the jumped clock.
  CHECK_OK(node.add_neighbor(2, 1, far + 1000));
  const std::size_t sent_before = radio.sent;
  MessageId again{};
  CHECK_OK(node.send(2, payload_view(), options, far + 1000, again));
  node.poll(far + 1000);
  CHECK(radio.sent > sent_before);
  radio.ack(node, far + 1000);
}

// A stalled clock must not manufacture expiries — and must not let bounded
// pools silently overwrite live work: admissions keep succeeding until the
// delivery table is honestly full, then refuse with NoCapacity.
void test_clock_stall_bounded_admission() {
  SinkRadio radio;
  TestSecurity security;
  CapturingObserver observer;
  NodeConfig config{};
  config.network = kNet;
  config.node = 1;
  config.message_session = 100;
  config.route_advertisement_period_ms = 30000;
  config.route_lifetime_ms = 60000;
  MeshNode node(config, radio, security, observer);
  CHECK_OK(node.start(1000));
  CHECK_OK(node.add_neighbor(2, 1, 1000));

  SendOptions options{};
  options.lifetime_ms = 5000;
  std::set<std::uint64_t> sequences;
  // The delivery table is 8 deep; the clock never advances.
  for (int i = 0; i < 8; ++i) {
    MessageId id{};
    CHECK_OK(node.send(2, payload_view(), options, 1000, id));
    CHECK(sequences.insert(id.sequence).second);  // ids never reused
  }
  MessageId extra{};
  CHECK(node.send(2, payload_view(), options, 1000, extra).code ==
        StatusCode::NoCapacity);
  // Stalled polls never expire, never fabricate results, never overwrite.
  for (int i = 0; i < 50; ++i) node.poll(1000);
  std::size_t live = 0;
  node.for_each_delivery([&](const DeliverySnapshot& d) {
    if (d.state != DeliveryState::Empty) ++live;
  });
  CHECK(live == 8);
  // Transition events exist (Pending/WaitingForMac); none may be terminal.
  CHECK(!has_terminal_delivery(&observer));
}

// A large forward jump expires everything at once — deliveries end in an
// honest terminal state, dedup records release (counted), routes lapse —
// without crashing, spinning, or resurrecting stale work afterwards.
void test_clock_forward_jump_mass_expiry() {
  SimWorld world;
  world.network_id = kNet;
  MeshNode* a = world.add(1);
  MeshNode* b = world.add(2);
  world.start_all();
  world.link(1, 2, 1, 1);
  world.run(400);
  CHECK(a->routes().best(2).valid);

  // Deliver a frame so B pins a terminal dedup record.
  wire::EncodedFrame frame = craft_data(*world.security[1], 1, 2, 1, 2, 9001,
                                        /*deadline_ms=*/9000);
  inject(world, 2, 1, frame, world.now);
  world.run(200);
  CHECK(world.obs(2)->messages.size() == 1);
  CHECK(world.at(2)->dedup_stats().admitted_terminal == 1);

  // A leaves a delivery in flight (send admitted, never flushed to a result).
  SendOptions options{};
  options.lifetime_ms = 2000;
  MessageId id{};
  CHECK_OK(a->send(2, payload_view(), options, world.now, id));

  // Jump both nodes past every deadline: deliveries, dedup retention, route
  // leases and hop-accept waits all expire in one pass.
  const MonotonicMs jumped = world.now + 120000;
  a->poll(jumped);
  b->poll(jumped);
  // A's delivery resolved honestly — never a fabricated Delivered.
  bool terminal_seen = false;
  for (const auto& event : world.obs(1)->delivery_events) {
    if (event.id.sequence == id.sequence &&
        (event.state == DeliveryState::Expired ||
         event.state == DeliveryState::Failed ||
         event.state == DeliveryState::Indeterminate)) {
      terminal_seen = true;
    }
  }
  CHECK(terminal_seen);
  // B's dedup record expired and was counted — retention did not pin forever.
  CHECK(world.at(2)->dedup_stats().expired >= 1);
  // The route lease lapsed: A no longer claims a path to B.
  CHECK(!a->routes().best(2).valid);
  // The mesh still functions: fresh work is admitted at the jumped clock.
  world.now = jumped;
  world.run(500);
  MessageId later{};
  CHECK_OK(a->send(2, payload_view(), options, world.now, later));
}

// A backwards clock must extend dedup retention, never shorten it: the
// terminal record survives, a re-injected frame is still deduplicated, and
// the node re-ACKs instead of double-delivering.
void test_clock_backwards_dedup_retention() {
  SimWorld world;
  world.network_id = kNet;
  world.add(1);
  MeshNode* b = world.add(2);
  world.start_all();
  world.link(1, 2, 1, 1);
  world.run(400);

  wire::EncodedFrame frame = craft_data(*world.security[1], 1, 2, 1, 2, 4242,
                                        /*deadline_ms=*/9000);
  const MonotonicMs t = world.now;
  inject(world, 2, 1, frame, t);
  CHECK(world.obs(2)->messages.size() == 1);
  CHECK(b->dedup_stats().admitted_terminal == 1);

  // Clock runs backwards on every poll/receive; the record must not lapse.
  for (int i = 1; i <= 5; ++i) {
    b->poll(t - i);
    inject(world, 2, 1, frame, t - i);  // identical bytes: same dedup key
  }
  b->poll(t - 10);
  world.net.flush(t - 10);
  CHECK(world.obs(2)->messages.size() == 1);         // never double-delivered
  CHECK(b->dedup_stats().admitted_terminal == 1);    // record survived
  CHECK(b->dedup_stats().expired == 0);

  // Past the hard retention cap a re-arrival is legitimately new: the pin is
  // bounded, not permanent — assert the boundary rather than silent reuse.
  const MonotonicMs late = t + 120000;
  b->poll(late);
  inject(world, 2, 1, frame, late);
  CHECK(world.obs(2)->messages.size() == 2);
  CHECK(b->dedup_stats().expired >= 1);
  CHECK(b->dedup_stats().admitted_terminal == 2);
}

// ============================================================================
// Capacity faults
// ============================================================================

// The 128-entry route table refuses a 129th distinct destination without
// touching live entries, keeps serving updates to known destinations, and
// recovers through the normal lease/tombstone GC — never by evicting a live
// route under pressure.
void test_route_table_saturation() {
  RouteTable table;
  const MonotonicMs t = 1000;
  for (NodeId dest = 0x1000; dest < 0x1000 + kMaxRouteEntries; ++dest) {
    const RouteAdvertisement ad{dest, /*generation=*/1, /*sequence=*/1,
                                /*metric=*/10};
    CHECK(table.consider(ad, /*next_hop=*/7, /*link_metric=*/1, t,
                         /*lifetime_ms=*/60000) ==
          RouteUpdateResult::Accepted);
  }
  CHECK(table.size() == kMaxRouteEntries);
  // The 129th destination is refused — the pool is honest about saturation.
  const RouteAdvertisement extra{0xFFFF, 1, 1, 10};
  CHECK(table.consider(extra, 7, 1, t, 60000) == RouteUpdateResult::NoCapacity);
  // Live state is untouched: the first route still selects and still accepts
  // fresher advertisements.
  CHECK(table.best(0x1000).valid);
  CHECK(table.best(0x1000).next_hop == 7);
  const RouteAdvertisement fresher{0x1000, 1, 2, 5};
  CHECK(table.consider(fresher, 7, 1, t, 60000) == RouteUpdateResult::Updated);
  CHECK(table.best(0x1000).sequence == 2);
  // Saturation is not a wedge: after leases lapse and the tombstone dwell
  // passes, GC reclaims the slots and new destinations admit again.
  table.expire(t + 60001);                // candidates lapse, tombstones arm
  CHECK(table.size() == kMaxRouteEntries);  // tombstoned, not yet freed
  table.expire(t + 60001 + 60001);        // dwell passed: entries released
  CHECK(table.size() == 0);
  CHECK(table.consider(extra, 7, 1, t + 120002, 60000) ==
        RouteUpdateResult::Accepted);
  CHECK(table.best(0xFFFF).valid);
}

// The 32-entry neighbor table refuses a 33rd peer without losing existing
// neighbors; updates to admitted peers keep working while full.
void test_neighbor_table_saturation() {
  SinkRadio radio;
  TestSecurity security;
  CapturingObserver observer;
  NodeConfig config{};
  config.network = kNet;
  config.node = 1;
  config.message_session = 100;
  MeshNode node(config, radio, security, observer);
  CHECK_OK(node.start(0));
  for (NodeId peer = 10; peer < 42; ++peer) {  // 32 neighbors
    CHECK_OK(node.add_neighbor(peer, 1, 0));
  }
  CHECK(node.add_neighbor(42, 1, 0).code == StatusCode::NoCapacity);
  // Updating an admitted peer is not an allocation: still fine when full.
  CHECK_OK(node.add_neighbor(10, 5, 0));
  CHECK(node.peer_link_cost(10) == 5);
  CHECK(node.add_neighbor(43, 1, 0).code == StatusCode::NoCapacity);
  // Removal frees a slot honestly; the table is not wedged.
  CHECK_OK(node.remove_neighbor(10, 0));
  CHECK_OK(node.add_neighbor(43, 1, 0));
  CHECK(node.peer_link_cost(43) == 1);
}

// Fill the dedup pool to the terminal pin bound (64 - 8 reserve), then show:
// the 57th terminal is refused + counted + diagnosed (never evicting a live
// pin), a transit still fits inside the reserve, and a full pool of
// Live+Terminal records refuses cleanly with DEDUP_OVERFLOW.
void test_dedup_terminal_reserve_and_pool_full() {
  SimWorld world;
  world.network_id = kNet;
  world.add(2);   // M: terminal + relay under test
  world.add(3);   // P: upstream peer (real node so acks drain cleanly)
  world.add(4);   // E: downstream destination for transit
  world.start_all();
  world.link(2, 3, 1, 1);
  world.link(2, 4, 1, 1);
  world.run(400);
  CHECK(world.at(2)->routes().best(4).valid);
  world.at(2)->set_peer_busy_capable(3, true);

  // Pin the terminal class: 56 end-protected DATA bound for M itself.
  // Each admission queues a HOP_ACCEPT on the 8-deep control lane, so drain
  // after every injection.
  for (std::uint64_t i = 1; i <= 56; ++i) {
    inject(world, 2, 3,
           craft_data(*world.security[3], 3, 2, /*origin=*/900 + i, /*dest=*/2,
                      /*seq=*/i, /*deadline_ms=*/30000),
           world.now);
    world.run(60);
  }
  CHECK(world.at(2)->dedup_stats().admitted_terminal == 56);
  CHECK(world.obs(2)->messages.size() == 56);

  // The 57th terminal hits the transit reserve: counted, diagnosed, BUSY'd.
  const std::uint64_t busy_before = world.at(2)->congestion_stats().busy_sent;
  inject(world, 2, 3,
         craft_data(*world.security[3], 3, 2, 957, 2, 57, 30000), world.now);
  CHECK(world.at(2)->dedup_stats().refused_terminal_reserve == 1);
  CHECK(world.obs(2)->has_diag("DEDUP_TERMINAL_RESERVE"));
  CHECK(world.at(2)->congestion_stats().busy_sent > busy_before);
  CHECK(world.obs(2)->messages.size() == 56);  // refused, never delivered

  // The surviving pins still dedup: a replayed seq-1 frame re-ACKs instead
  // of re-delivering — live state was not overwritten under pressure.
  inject(world, 2, 3,
         craft_data(*world.security[3], 3, 2, 901, 2, 1, 30000), world.now);
  world.run(60);
  CHECK(world.obs(2)->messages.size() == 56);

  // The 8-slot reserve still admits transit (Live) traffic...
  for (std::uint64_t i = 1; i <= 8; ++i) {
    inject(world, 2, 3,
           craft_data(*world.security[3], 3, 2, /*origin=*/800 + i,
                      /*dest=*/4, /*seq=*/i, /*deadline_ms=*/30000),
           world.now);
  }
  CHECK(world.at(2)->dedup_stats().admitted_transit == 8);
  // ...and a 9th finds the pool truly full: nothing evictable (all Live or
  // Terminal), so the refusal is counted, diagnosed and BUSY'd — the
  // exactly-once pin is never weakened to make room.
  inject(world, 2, 3,
         craft_data(*world.security[3], 3, 2, 809, 4, 9, 30000), world.now);
  CHECK(world.at(2)->dedup_stats().refused_pool_full == 1);
  CHECK(world.obs(2)->has_diag("DEDUP_OVERFLOW"));
  CHECK(world.at(2)->dedup_stats().admitted_transit == 8);

  // After the forwards drain and resolve, a Resolved record is the honest
  // eviction victim — the next admission reclaims it instead of refusing.
  world.run(2000);  // forwards dispatch; hop accepts resolve them
  CHECK(world.obs(4)->messages.size() == 8);  // all transit work delivered
  inject(world, 2, 3,
         craft_data(*world.security[3], 3, 2, 810, 4, 10, 30000), world.now);
  CHECK(world.at(2)->dedup_stats().evicted_resolved >= 1);
  CHECK(world.obs(2)->has_diag("DEDUP_EVICTED_RESOLVED"));
  CHECK(world.at(2)->dedup_stats().admitted_transit == 9);
  CHECK(world.at(2)->dedup_stats().refused_pool_full == 1);  // unchanged
}

// One upstream peer may hold at most 24 non-terminal dedup records: the
// 25th distinct message is refused (counted + diagnosed + BUSY), while
// accepted work still forwards — the bound is per-peer flood resistance,
// not a cap on legitimate throughput.
void test_dedup_upstream_cap() {
  SimWorld world;
  world.network_id = kNet;
  world.add(2);   // relay under test
  world.add(3);   // upstream peer
  world.add(4);   // destination
  world.start_all();
  world.link(2, 3, 1, 1);
  world.link(2, 4, 1, 1);
  world.run(400);
  CHECK(world.at(2)->routes().best(4).valid);
  world.at(2)->set_peer_busy_capable(3, true);

  for (std::uint64_t i = 1; i <= 24; ++i) {
    inject(world, 2, 3,
           craft_data(*world.security[3], 3, 2, /*origin=*/700 + i,
                      /*dest=*/4, /*seq=*/i, /*deadline_ms=*/30000),
           world.now);
    world.run(120);  // dispatch + hop accept -> Resolved (still counted)
  }
  CHECK(world.at(2)->dedup_stats().admitted_transit == 24);
  CHECK(world.obs(4)->messages.size() == 24);

  const std::uint64_t busy_before = world.at(2)->congestion_stats().busy_sent;
  inject(world, 2, 3,
         craft_data(*world.security[3], 3, 2, 725, 4, 25, 30000), world.now);
  CHECK(world.at(2)->dedup_stats().refused_upstream_cap == 1);
  CHECK(world.obs(2)->has_diag("DEDUP_UPSTREAM_CAP"));
  CHECK(world.at(2)->congestion_stats().busy_sent > busy_before);
  // A different upstream peer is unaffected — the cap is per-sender-scope.
  world.add(5);
  world.link(2, 5, 1, 1);
  world.run(300);
  inject(world, 2, 5,
         craft_data(*world.security[5], 5, 2, 726, 4, 26, 30000), world.now);
  CHECK(world.at(2)->dedup_stats().admitted_transit == 25);
}

// Eviction order under a full pool: an already-expired record is reclaimed
// as a normal expiry first; only when nothing is expired does a Resolved
// record get force-evicted; with only Live/Terminal left the refusal is
// honest overflow.
void test_dedup_eviction_expired_then_resolved() {
  SimWorld world;
  world.network_id = kNet;
  world.add(2);   // relay under test
  world.add(3);   // upstream peer
  world.add(4);   // destination
  world.start_all();
  world.link(2, 3, 1, 1);
  world.link(2, 4, 1, 1);
  world.run(400);

  // 55 terminal pins leave 9 non-reserve slots.
  for (std::uint64_t i = 1; i <= 55; ++i) {
    inject(world, 2, 3,
           craft_data(*world.security[3], 3, 2, 500 + i, 2, i, 30000),
           world.now);
    world.run(60);
  }
  CHECK(world.at(2)->dedup_stats().admitted_terminal == 55);

  // One short-deadline transit (expires ~5.1s in) plus 8 long ones fill the
  // pool to 64 without dispatching — the records stay Live.
  inject(world, 2, 3,
         craft_data(*world.security[3], 3, 2, 600, 4, 9001, 100), world.now);
  for (std::uint64_t i = 2; i <= 9; ++i) {
    inject(world, 2, 3,
           craft_data(*world.security[3], 3, 2, 600 + i, 4, 9000 + i, 30000),
           world.now);
  }
  CHECK(world.at(2)->dedup_stats().admitted_transit == 9);

  // Advance past the short record's expiry (100 + 5000 slack < 6000) while
  // the 8 long transits (30000 + 5000) and terminals (30000 + 30000) live.
  world.now += 6000;
  inject(world, 2, 3,
         craft_data(*world.security[3], 3, 2, 610, 4, 9010, 30000), world.now);
  // The expired record was reclaimed as a normal expiry — not a forced
  // eviction and not a refusal.
  CHECK(world.at(2)->dedup_stats().expired >= 1);
  CHECK(world.at(2)->dedup_stats().refused_pool_full == 0);
  CHECK(world.at(2)->dedup_stats().evicted_resolved == 0);
  CHECK(world.at(2)->dedup_stats().admitted_transit == 10);

  // Pool still full, nothing expired: only Live/Terminal records remain, so
  // the next admission is an honest overflow.
  inject(world, 2, 3,
         craft_data(*world.security[3], 3, 2, 611, 4, 9011, 30000), world.now);
  CHECK(world.at(2)->dedup_stats().refused_pool_full == 1);

  // Drain the queued forwards: hop accepts demote them to Resolved. The pool
  // is still full, and now Resolved victims exist — the next admission takes
  // one, counted and diagnosed.
  world.run(2000);
  CHECK(world.obs(4)->messages.size() >= 8);
  inject(world, 2, 3,
         craft_data(*world.security[3], 3, 2, 612, 4, 9012, 30000), world.now);
  CHECK(world.at(2)->dedup_stats().evicted_resolved >= 1);
  CHECK(world.obs(2)->has_diag("DEDUP_EVICTED_RESOLVED"));
  CHECK(world.at(2)->dedup_stats().refused_pool_full == 1);  // still one
}

// A transit flood that outruns the scheduler: the 32-slot TX pool plus the
// per-scope cap refuse new admissions with a counted BUSY/drop — never an
// overwrite, never an unbounded queue — and the pool drains and re-admits.
void test_scheduler_pool_saturation() {
  SimWorld world;
  world.network_id = kNet;
  world.add(2);   // relay under test
  world.add(3);   // upstream peer 1
  world.add(5);   // upstream peer 2 (second scope -> pool, not just scope cap)
  world.add(4);   // destination
  world.start_all();
  world.link(2, 3, 1, 1);
  world.link(2, 5, 1, 1);
  world.link(2, 4, 1, 1);
  world.run(400);
  world.at(2)->set_peer_busy_capable(3, true);
  world.at(2)->set_peer_busy_capable(5, true);

  // No drain between injections: forwards and their HOP_ACCEPTs pile into
  // the 32-slot queue; the per-scope cap (12) binds at each peer first, then
  // the pool itself refuses.
  for (std::uint64_t i = 1; i <= 40; ++i) {
    const NodeId peer = (i % 2 == 0) ? 3 : 5;
    inject(world, 2, peer,
           craft_data(*world.security[peer], peer, 2, /*origin=*/300 + i,
                      /*dest=*/4, /*seq=*/i, /*deadline_ms=*/30000),
           world.now);
  }
  CHECK(world.obs(2)->has_diag("TRANSIT_ADMISSION_DENIED"));
  const CongestionStats stats = world.at(2)->congestion_stats();
  CHECK(stats.queued <= 32);               // pool bound is absolute
  CHECK(stats.busy_sent + stats.busy_send_failed >= 1);  // honest refusal
  // Accepted work is intact: every admitted transit still has its dedup
  // record, and dispatching the backlog delivers it.
  const std::uint64_t admitted = world.at(2)->dedup_stats().admitted_transit;
  CHECK(admitted >= 20 && admitted <= 32);
  world.run(4000);
  CHECK(world.obs(4)->messages.size() == admitted);
  // Once drained, the same flood admission succeeds again — saturation is a
  // refusal, never a wedge.
  inject(world, 2, 3,
         craft_data(*world.security[3], 3, 2, 999, 4, 9001, 30000), world.now);
  CHECK(world.at(2)->dedup_stats().admitted_transit == admitted + 1);
}

// The per-peer TX window bounds in-flight hop exchanges: work beyond the
// window is skipped by the scheduler (counted window_limited), never
// dropped — and completes once accepts open the window again.
void test_peer_window_bounded() {
  SimWorld world;
  world.network_id = kNet;
  world.add(1);
  world.add(2);
  world.start_all();
  world.link(1, 2, 1, 1);
  world.run(400);

  // Queue three deliveries at once; B is never polled so no HOP_ACCEPT can
  // come back — the initial peer window (2) fills and the third job waits.
  SendOptions options{};
  options.lifetime_ms = 30000;
  for (int i = 0; i < 3; ++i) {
    MessageId id{};
    CHECK_OK(world.at(1)->send(2, payload_view(), options, world.now, id));
  }
  for (int i = 0; i < 30; ++i) {
    world.at(1)->poll(world.now);
    world.net.flush(world.now);  // delivers A's TX to B; B never acks
    ++world.now;
  }
  CHECK(world.at(1)->congestion_stats().window_limited >= 1);
  // Nothing was dropped: the jobs are still queued/awaiting — every delivery
  // event so far is a non-terminal transition, never a failure or timeout.
  CHECK(!has_terminal_delivery(world.obs(1)));

  // Poll B now: its queued HOP_ACCEPTs flow back, the window opens, the held
  // job dispatches — bounded waiting, never a silent loss.
  world.run(3000);
  bool delivered = false;
  for (const auto& event : world.obs(1)->delivery_events) {
    if (event.state == DeliveryState::Delivered) delivered = true;
  }
  CHECK(delivered);
}

}  // namespace

int main() {
#define RUN(fn)                                          \
  do {                                                   \
    std::fprintf(stderr, "[run] %s\n", #fn);             \
    fn();                                                \
  } while (false)
  // Storage: counter lease
  RUN(test_counter_torn_commit_fails_closed);
  RUN(test_counter_midlease_slot_revalidation);
  RUN(test_counter_exhaustion_never_wraps);
  RUN(test_counter_load_failure_propagates);
  // Storage: replay guard
  RUN(test_replay_accept_load_failure);
  RUN(test_replay_floor_vanish_mid_session);
  RUN(test_replay_foreign_floor_record);
  // Storage: trust store
  RUN(test_trust_recover_power_cut_midway);
  RUN(test_trust_zero_fill_cold_start);
  // Clock faults
  RUN(test_clock_faults_decay_windows_bounded);
  RUN(test_clock_stall_bounded_admission);
  RUN(test_clock_forward_jump_mass_expiry);
  RUN(test_clock_backwards_dedup_retention);
  // Capacity
  RUN(test_route_table_saturation);
  RUN(test_neighbor_table_saturation);
  RUN(test_dedup_terminal_reserve_and_pool_full);
  RUN(test_dedup_upstream_cap);
  RUN(test_dedup_eviction_expired_then_resolved);
  RUN(test_scheduler_pool_saturation);
  RUN(test_peer_window_bounded);
  return failures == 0 ? (std::puts("RouteLoom fault-injection tests passed"), 0)
                       : (std::fprintf(stderr, "%d fault-injection checks failed\n",
                                       failures),
                         1);
}
