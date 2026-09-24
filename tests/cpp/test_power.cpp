// Power coordinator model tests: every state transition, sleep-ticket
// invalidation sources, prepare policies, counter-lease continuity across
// simulated power cuts, cold boot vs deep-sleep resume separation and the
// TIME_UNCERTAIN deadline rule. All clocks and storage are fakes.

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <limits>
#include <map>
#include <new>
#include <set>
#include <string>
#include <vector>

#include "routeloom/authority.hpp"
#include "routeloom/counter_store.hpp"
#include "routeloom/node.hpp"
#include "routeloom/power.hpp"

#include "test_ledger.hpp"
#include "test_security.hpp"
#include "test_sim.hpp"

// Global new/delete accounting for the no-heap test. Production spans run
// with counting armed; allocations forward to malloc (still ASan-checked).
namespace heap_probe {
bool armed{false};
std::size_t new_calls{0};
}  // namespace heap_probe

void* operator new(std::size_t size) {
  if (heap_probe::armed) ++heap_probe::new_calls;
  void* p = std::malloc(size);
  if (p == nullptr) throw std::bad_alloc();
  return p;
}
void operator delete(void* p) noexcept { std::free(p); }
void* operator new[](std::size_t size) {
  if (heap_probe::armed) ++heap_probe::new_calls;
  void* p = std::malloc(size);
  if (p == nullptr) throw std::bad_alloc();
  return p;
}
void operator delete[](void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t) noexcept { std::free(p); }

namespace {

int failures = 0;
#define CHECK(expr)                                                              \
  do {                                                                           \
    if (!(expr)) {                                                               \
      std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__,       \
                   #expr);                                                       \
      ++failures;                                                                \
    }                                                                            \
  } while (false)
#define CHECK_OK(expr)                                                           \
  do {                                                                           \
    const auto _status = (expr);                                                 \
    if (!_status.ok()) {                                                         \
      std::fprintf(stderr, "STATUS failed %s:%d: %s (%s)\n", __FILE__, __LINE__, \
                   #expr, _status.detail);                                       \
      ++failures;                                                                \
    }                                                                            \
  } while (false)

using namespace routeloom;
using routeloom_test::CapturingObserver;
using routeloom_test::SimNetwork;
using routeloom_test::SimRadio;
using routeloom_test::TestSecurity;

class MemoryCounterStore final : public CounterStore {
 public:
  Status load(std::uint32_t slot, CounterRecord& record,
              bool& found) noexcept override {
    const auto it = records.find(slot);
    found = it != records.end();
    if (found) record = it->second;
    return Status::success();
  }
  Status commit(std::uint32_t slot, const CounterRecord& record) noexcept override {
    records[slot] = record;
    return Status::success();
  }
  std::map<std::uint32_t, CounterRecord> records;
};

class MemoryPowerStorage final : public PowerStorage {
 public:
  Status read(std::uint8_t slot, MutableByteView target) noexcept override {
    if (slot >= kPowerImageSlots || target.data == nullptr ||
        target.size != kPowerImageRecordSize) {
      return Status::error(StatusCode::InvalidArgument, "bad power read");
    }
    if (read_error) {
      return Status::error(StatusCode::StorageFailure, "injected read error");
    }
    std::memcpy(target.data, slots_[slot].data(), target.size);
    return Status::success();
  }
  Status write(std::uint8_t slot, ByteView data) noexcept override {
    if (slot >= kPowerImageSlots || data.data == nullptr ||
        data.size != kPowerImageRecordSize) {
      return Status::error(StatusCode::InvalidArgument, "bad power write");
    }
    ++write_calls;
    last_slot = slot;
    // Stage-scoped faults: arm at the test site that owns the commit stage
    // (persist / refresh / consume) instead of depending on the absolute
    // write-call index, which shifts when the commit pattern changes.
    if (fail_skip_writes > 0) {
      --fail_skip_writes;
    } else if (fail_writes_remaining > 0) {
      --fail_writes_remaining;
      if (fail_write_bytes < data.size) {
        std::memcpy(slots_[slot].data(), data.data, fail_write_bytes);
        return Status::error(StatusCode::StorageFailure, "power cut mid write");
      }
      return Status::error(StatusCode::StorageFailure, "power lost before write");
    }
    std::memcpy(slots_[slot].data(), data.data, data.size);
    return Status::success();
  }

  // Fail the next `count` writes outright (nothing lands).
  void fail_next_writes(std::size_t count) noexcept {
    fail_writes_remaining = count;
    fail_write_bytes = kPowerImageRecordSize;
  }
  // Tear the next write after `bytes` (a torn prefix lands, CRC rejects).
  void tear_next_write(std::size_t bytes) noexcept {
    fail_writes_remaining = 1;
    fail_write_bytes = bytes;
  }
  // Fail the (n+1)-th upcoming write: `n` succeed first. Targets the second
  // commit of a dual write without depending on absolute call indices.
  void fail_after_writes(std::size_t n) noexcept {
    fail_writes_remaining = 1;
    fail_write_bytes = kPowerImageRecordSize;
    fail_skip_writes = n;
  }

  void corrupt(std::uint8_t slot, std::size_t offset) noexcept {
    slots_[slot][offset] ^= 0xFFU;
  }
  bool slot_blank(std::uint8_t slot) const noexcept {
    for (const auto byte : slots_[slot]) {
      if (byte != 0) return false;
    }
    return true;
  }

  std::size_t write_calls{0};
  std::size_t fail_writes_remaining{0};
  std::size_t fail_write_bytes{kPowerImageRecordSize};
  std::size_t fail_skip_writes{0};
  int last_slot{-1};
  bool read_error{false};

 private:
  std::array<std::array<std::uint8_t, kPowerImageRecordSize>, kPowerImageSlots>
      slots_{};
};

class FakePowerPort final : public PowerPort {
 public:
  Status capture_cache(PowerImage& image) noexcept override {
    ++capture_calls;
    if (!inject_capture) return inject_capture;
    image.channel = channel;
    for (const auto& peer : peers) {
      if (!peer.used) continue;
      PowerPeerRecord* slot = nullptr;
      for (auto& candidate : image.peers) {
        if (candidate.used && candidate.node == peer.node) slot = &candidate;
      }
      if (slot == nullptr) {
        for (auto& candidate : image.peers) {
          if (!candidate.used) {
            slot = &candidate;
            break;
          }
        }
      }
      if (slot == nullptr) return Status::success();  // image cache full
      *slot = peer;
    }
    return Status::success();
  }
  Status quiesce_radio() noexcept override {
    ++quiesce_calls;
    if (!inject_quiesce) return inject_quiesce;
    radio_quiesced = true;
    return Status::success();
  }
  Status start_radio(const PowerImage* image) noexcept override {
    ++start_calls;
    last_start_peers = 0;
    if (image != nullptr) {
      for (const auto& peer : image->peers) {
        if (peer.used) ++last_start_peers;
      }
    }
    if (!inject_start) return inject_start;
    radio_quiesced = false;
    return Status::success();
  }
  Status configure_wake(const WakePlan& plan) noexcept override {
    ++wakecfg_calls;
    last_plan = plan;
    return inject_wakecfg;
  }
  Status enter_sleep() noexcept override {
    ++sleep_calls;
    return inject_enter;
  }
  Status start_discovery(const PowerImage& image) noexcept override {
    ++discovery_calls;
    last_discovery = image;
    return inject_discovery;
  }

  std::array<PowerPeerRecord, kPowerPeerCacheCapacity> peers{};
  std::uint8_t channel{6};
  bool radio_quiesced{false};
  int capture_calls{0};
  int quiesce_calls{0};
  int start_calls{0};
  int wakecfg_calls{0};
  int sleep_calls{0};
  int discovery_calls{0};
  std::size_t last_start_peers{0};
  WakePlan last_plan{};
  PowerImage last_discovery{};
  Status inject_capture{};
  Status inject_quiesce{};
  Status inject_start{};
  Status inject_wakecfg{};
  Status inject_enter{};
  Status inject_discovery{};
};

class RecordingPowerEvents final : public PowerEvents {
 public:
  struct Transition {
    PowerState from;
    PowerState to;
    std::string reason;
  };
  std::vector<Transition> transitions;
  std::vector<std::pair<MessageId, StatusCode>> pending_results;
  std::vector<std::string> diagnostics;
  // Hooks run INSIDE their notification — for re-entrant coordinator calls
  // from PowerEvents callbacks.
  std::function<void(PowerState, PowerState, const char*)> on_transition_fn;
  std::function<void(const PendingDeliveryRecord&, StatusCode)>
      on_pending_result_fn;
  std::function<void(const char*)> on_diagnostic_fn;

  void on_transition(PowerState from, PowerState to,
                     const char* reason) noexcept override {
    transitions.push_back({from, to, reason});
    if (on_transition_fn) on_transition_fn(from, to, reason);
  }
  void on_pending_result(const PendingDeliveryRecord& record,
                         StatusCode code) noexcept override {
    pending_results.emplace_back(record.original_id, code);
    if (on_pending_result_fn) on_pending_result_fn(record, code);
  }
  void on_diagnostic(const char* reason) noexcept override {
    diagnostics.emplace_back(reason);
    if (on_diagnostic_fn) on_diagnostic_fn(reason);
  }
  bool saw(PowerState from, PowerState to) const {
    for (const auto& t : transitions) {
      if (t.from == from && t.to == to) return true;
    }
    return false;
  }
  bool saw(PowerState from, PowerState to, const char* reason) const {
    for (const auto& t : transitions) {
      if (t.from == from && t.to == to && t.reason == reason) return true;
    }
    return false;
  }
  bool has_diag(const char* prefix) const {
    for (const auto& d : diagnostics) {
      if (d.rfind(prefix, 0) == 0) return true;
    }
    return false;
  }
  std::size_t pending_with(StatusCode code) const {
    std::size_t count = 0;
    for (const auto& r : pending_results) count += r.second == code ? 1U : 0U;
    return count;
  }
};

struct PowerWorld {
  static constexpr NodeId kSelf = 7;
  MemoryPowerStorage& storage;
  TestSecurity security;
  CapturingObserver observer;
  SimNetwork net;
  SimRadio radio;
  FakePowerPort port;
  RecordingPowerEvents events;
  MeshNode node;
  PowerCoordinator coordinator;
  MonotonicMs now{0};

  explicit PowerWorld(MemoryPowerStorage& store,
                      const PowerConfig& power = PowerConfig{500, 50})
      : storage(store), radio(net, kSelf),
        node(make_config(), radio, security, observer),
        coordinator(power, node, port, storage, events) {}

  static NodeConfig make_config() {
    NodeConfig config{};
    config.network = 1;
    config.node = kSelf;
    config.message_session = 500;
    config.route_advertisement_period_ms = 100000;
    config.route_lifetime_ms = 200000;
    return config;
  }

  void platform_peer(NodeId id, std::uint8_t mac_seed,
                     RouteMetric metric = 1) {
    for (auto& peer : port.peers) {
      if (peer.used) continue;
      peer = PowerPeerRecord{};
      peer.used = true;
      peer.node = id;
      peer.metric = metric;
      peer.address_size = 6;
      peer.address.fill(mac_seed);
      return;
    }
  }

  void pump(MonotonicMs duration, MonotonicMs step = 5) {
    const MonotonicMs end = now + duration;
    for (; now <= end; now += step) {
      coordinator.poll(now);
      net.flush(now);
    }
  }

  bool pump_until(PowerState target, int max_iterations = 400) {
    for (int i = 0; i < max_iterations && coordinator.state() != target; ++i) {
      coordinator.poll(now);
      net.flush(now);
      now += 5;
    }
    return coordinator.state() == target;
  }

  void inject_rx() {
    // A well-formed, link-authenticated frame from peer 2 addressed to us —
    // the only kind of inbound traffic that may confirm a fast resume.
    wire::PlainFrame plain{};
    plain.header.type = FrameType::Data;
    plain.header.flags = wire::kFlagEndProtected;
    plain.header.delivery = DeliveryClass::Reliable;
    plain.header.hop_remaining = 1;
    plain.header.network = 1;
    plain.header.origin = 2;
    plain.header.destination = kSelf;
    plain.header.previous_hop = 2;
    plain.header.next_hop = kSelf;
    plain.header.message = MessageId{9, 1};
    plain.header.remaining_deadline_ms = 5000;
    plain.header.original_lifetime_ms = 5000;
    plain.header.link_epoch = 1;
    plain.header.end_epoch = 1;
    const std::array<std::uint8_t, 4> payload{{9, 9, 9, 9}};
    std::memcpy(plain.payload.data(), payload.data(), payload.size());
    plain.payload_size = payload.size();
    wire::EncodedFrame encoded{};
    if (wire::encode_new(plain, security, encoded).ok()) {
      node.on_radio_receive(2, encoded.view(), RadioRxMetadata{-60}, now);
    }
  }

  void inject_junk_rx() {
    const std::array<std::uint8_t, 8> junk{{0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4}};
    node.on_radio_receive(2, ByteView{junk.data(), junk.size()},
                          RadioRxMetadata{-60}, now);
  }
};

void test_cold_boot_and_errors() {
  MemoryPowerStorage storage;
  PowerWorld w(storage);
  CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, 0));
  CHECK(w.coordinator.state() == PowerState::Running);
  CHECK(w.coordinator.resume_outcome() == ResumeOutcome::ColdStart);
  CHECK(w.coordinator.reset_cause() == ResetCause::ColdBoot);
  CHECK(w.node.started());
  CHECK(w.coordinator
            .begin(ResetCause::ColdBoot, ElapsedInterval{0, 0, false}, 0)
            .code == StatusCode::AlreadyExists);
  CHECK(w.coordinator.sleep_enter(w.coordinator.ticket(), 0).code ==
        StatusCode::InvalidState);
  CHECK(w.coordinator.wake(ResetCause::DeepSleepWake,
                           ElapsedInterval{0, 0, false}, 0)
            .code == StatusCode::InvalidState);
  CHECK(w.coordinator.sleep_abort("x").code == StatusCode::InvalidState);
}

void test_full_cycle_transition_order() {
  MemoryPowerStorage storage;
  PowerWorld w(storage);
  CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, 0));
  SleepRequest request{};
  request.wake.wake_after_ms = 30000;
  CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
  CHECK(w.coordinator.state() == PowerState::Draining);
  CHECK(w.node.draining());
  CHECK(w.pump_until(PowerState::ReadyToSleep));
  CHECK(w.storage.write_calls == 1);
  CHECK(w.port.radio_quiesced);
  const SleepTicket ticket = w.coordinator.ticket();
  CHECK(ticket.issued && w.coordinator.ticket_valid(ticket));
  CHECK_OK(w.coordinator.sleep_enter(ticket, w.now));
  CHECK(w.coordinator.state() == PowerState::Sleeping);
  CHECK(w.port.sleep_calls == 1 && w.port.last_plan.wake_after_ms == 30000);
  CHECK_OK(w.coordinator.wake(ResetCause::DeepSleepWake,
                              ElapsedInterval{0, 0, false}, w.now));
  CHECK(w.coordinator.state() == PowerState::Running);  // no peers: cold start
  const auto& t = w.events.transitions;
  const std::vector<std::pair<PowerState, PowerState>> expected{
      {PowerState::Running, PowerState::Resuming},
      {PowerState::Resuming, PowerState::Running},
      {PowerState::Running, PowerState::Draining},
      {PowerState::Draining, PowerState::Persisting},
      {PowerState::Persisting, PowerState::ReadyToSleep},
      {PowerState::ReadyToSleep, PowerState::Sleeping},
      {PowerState::Sleeping, PowerState::Resuming},
      {PowerState::Resuming, PowerState::Running},
  };
  CHECK(t.size() == expected.size());
  for (std::size_t i = 0; i < expected.size() && i < t.size(); ++i) {
    CHECK(t[i].from == expected[i].first && t[i].to == expected[i].second);
  }
}

// Reaches READY_TO_SLEEP on a quiet node and returns the issued ticket.
SleepTicket reach_ready(PowerWorld& w) {
  SleepRequest request{};
  CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
  CHECK(w.pump_until(PowerState::ReadyToSleep));
  return w.coordinator.ticket();
}

void test_ticket_invalidated_by_app_event() {
  MemoryPowerStorage storage;
  PowerWorld w(storage);
  CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, 0));
  const SleepTicket ticket = reach_ready(w);
  w.coordinator.notify_app_event();
  CHECK(!w.coordinator.ticket_valid(ticket));
  CHECK(w.coordinator.sleep_enter(ticket, w.now).code ==
        StatusCode::InvalidState);
  w.pump(10);
  CHECK(w.coordinator.state() == PowerState::Running);
  CHECK(!w.node.draining());
  CHECK(w.port.start_calls >= 1);
}

void test_ticket_invalidated_by_rx() {
  MemoryPowerStorage storage;
  PowerWorld w(storage);
  CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, 0));
  const SleepTicket ticket = reach_ready(w);
  w.inject_rx();
  CHECK(!w.coordinator.ticket_valid(ticket));
  w.pump(10);
  CHECK(w.coordinator.state() == PowerState::Running);
}

void test_ticket_invalidated_by_tx_attempt() {
  MemoryPowerStorage storage;
  PowerWorld w(storage);
  CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, 0));
  const SleepTicket ticket = reach_ready(w);
  const std::array<std::uint8_t, 3> payload{{1, 2, 3}};
  MessageId id{};
  // The send is rejected while draining, but the attempt itself is new work
  // and must invalidate the outstanding ticket.
  CHECK(w.node.send(2, ByteView{payload.data(), payload.size()}, SendOptions{},
                    w.now, id)
            .code == StatusCode::InvalidState);
  CHECK(!w.coordinator.ticket_valid(ticket));
  w.pump(10);
  CHECK(w.coordinator.state() == PowerState::Running);
  // After the abort the node accepts work again.
  CHECK(w.node.send(2, ByteView{payload.data(), payload.size()}, SendOptions{},
                    w.now, id)
            .ok());
}

void test_ticket_invalidated_by_config_change() {
  MemoryPowerStorage storage;
  PowerWorld w(storage);
  CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, 0));
  const SleepTicket ticket = reach_ready(w);
  CHECK_OK(w.node.add_neighbor(5, 1, w.now));
  CHECK(!w.coordinator.ticket_valid(ticket));
  w.pump(10);
  CHECK(w.coordinator.state() == PowerState::Running);
}

void test_ticket_invalidated_by_radio_reset() {
  MemoryPowerStorage storage;
  PowerWorld w(storage);
  CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, 0));
  const SleepTicket ticket = reach_ready(w);
  w.coordinator.notify_radio_reset();
  CHECK(!w.coordinator.ticket_valid(ticket));
  w.pump(10);
  CHECK(w.coordinator.state() == PowerState::Running);
}

void test_stale_ticket_rejected_outstanding_stays_valid() {
  MemoryPowerStorage storage;
  PowerWorld w(storage);
  CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, 0));
  const SleepTicket ticket = reach_ready(w);
  SleepTicket stale = ticket;
  stale.id = ticket.id + 9;
  CHECK(w.coordinator.sleep_enter(stale, w.now).code ==
        StatusCode::InvalidState);
  CHECK(w.coordinator.state() == PowerState::ReadyToSleep);
  CHECK_OK(w.coordinator.sleep_enter(ticket, w.now));
  CHECK(w.coordinator.state() == PowerState::Sleeping);
}

void test_send_rejected_while_draining() {
  MemoryPowerStorage storage;
  PowerWorld w(storage);
  CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, 0));
  SleepRequest request{};
  CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
  const std::array<std::uint8_t, 2> payload{{9, 9}};
  MessageId id{};
  CHECK(w.node.send(2, ByteView{payload.data(), payload.size()}, SendOptions{},
                    w.now, id)
            .code == StatusCode::InvalidState);
  w.pump(10);
  CHECK(w.coordinator.state() == PowerState::ReadyToSleep);
}

MessageId queue_pending(PowerWorld& w, NodeId destination, bool durable,
                        std::uint32_t lifetime = 5000) {
  SendOptions options{};
  options.lifetime_ms = lifetime;
  options.persist_across_sleep = durable;
  const std::array<std::uint8_t, 4> payload{{7, 7, 7, 7}};
  MessageId id{};
  // Destination unreachable -> WaitingForRoute, a non-terminal pending
  // delivery that the sleep image can persist.
  CHECK_OK(w.node.send(destination, ByteView{payload.data(), payload.size()},
                       options, w.now, id));
  return id;
}

void test_policy_fail() {
  MemoryPowerStorage storage;
  PowerWorld w(storage);
  CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, 0));
  const MessageId id = queue_pending(w, 99, false);
  SleepRequest request{};
  request.pending_policy = SleepWorkPolicy::Fail;
  CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
  CHECK(w.pump_until(PowerState::ReadyToSleep));
  CHECK(w.node.delivery(id).state == DeliveryState::Failed);
  CHECK(std::strcmp(w.node.delivery(id).reason, "SLEEP_DRAIN") == 0);
  CHECK(w.storage.write_calls == 1);
}

void test_policy_save_durable() {
  MemoryPowerStorage storage;
  PowerWorld w(storage);
  CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, 0));
  const MessageId id = queue_pending(w, 99, true);
  SleepRequest request{};
  request.pending_policy = SleepWorkPolicy::Fail;
  CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
  CHECK(w.pump_until(PowerState::ReadyToSleep));
  CHECK(w.node.delivery(id).state == DeliveryState::Indeterminate);
  CHECK(std::strcmp(w.node.delivery(id).reason, "SLEEP_SAVED") == 0);
}

void test_policy_defer() {
  MemoryPowerStorage storage;
  PowerWorld w(storage);
  CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, 0));
  const MessageId id = queue_pending(w, 99, false);
  SleepRequest request{};
  request.pending_policy = SleepWorkPolicy::Defer;
  CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
  CHECK(w.pump_until(PowerState::ReadyToSleep));
  CHECK(w.node.delivery(id).state == DeliveryState::Indeterminate);
  CHECK(std::strcmp(w.node.delivery(id).reason, "SLEEP_DEFERRED") == 0);
}

void test_persist_full_fails_explicitly() {
  MemoryPowerStorage storage;
  PowerWorld w(storage);
  CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, 0));
  std::vector<MessageId> ids;
  for (std::size_t i = 0; i < kPowerPendingCapacity + 1; ++i) {
    ids.push_back(queue_pending(w, 90 + i, true));
  }
  SleepRequest request{};
  CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
  CHECK(w.pump_until(PowerState::ReadyToSleep));
  for (std::size_t i = 0; i < kPowerPendingCapacity; ++i) {
    CHECK(std::strcmp(w.node.delivery(ids[i]).reason, "SLEEP_SAVED") == 0);
  }
  // The overflow delivery fails loudly instead of being dropped silently.
  CHECK(w.node.delivery(ids.back()).state == DeliveryState::Failed);
  CHECK(std::strcmp(w.node.delivery(ids.back()).reason, "SLEEP_PERSIST_FULL") ==
        0);
}

void test_drain_deadline_forces_settle() {
  MemoryPowerStorage storage;
  const PowerConfig power{120, 50};
  PowerWorld w(storage, power);
  CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, 0));
  CHECK_OK(w.node.add_neighbor(2, 1, w.now));
  const std::array<std::uint8_t, 4> payload{{1, 2, 3, 4}};
  MessageId id{};
  CHECK_OK(w.node.send(2, ByteView{payload.data(), payload.size()},
                       SendOptions{}, w.now, id));
  // Node is not registered on the sim network: frames are dropped without a
  // TX result, so the physical job never resolves on its own.
  w.pump(20);
  CHECK(!w.node.quiesced());
  SleepRequest request{};
  CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
  CHECK(w.pump_until(PowerState::ReadyToSleep, 60));  // ~300ms > 120ms bound
  CHECK(w.events.saw(PowerState::Draining, PowerState::Persisting,
                     "DRAIN_DEADLINE"));
  CHECK(w.observer.has_diag("SLEEP_TX_INFLIGHT"));
  // The delivery was forced to a terminal state, never reported as sent.
  const auto result = w.node.delivery(id);
  CHECK(result.state == DeliveryState::Failed ||
        result.state == DeliveryState::Indeterminate);
}

void test_sleep_abort() {
  MemoryPowerStorage storage;
  PowerWorld w(storage);
  CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, 0));
  SleepRequest request{};
  CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
  CHECK(w.coordinator.state() == PowerState::Draining);
  CHECK_OK(w.coordinator.sleep_abort("APP_CHANGED_MIND"));
  CHECK(w.coordinator.state() == PowerState::Running);
  CHECK(!w.node.draining());
  const std::array<std::uint8_t, 2> payload{{1, 1}};
  MessageId id{};
  CHECK_OK(w.node.send(2, ByteView{payload.data(), payload.size()},
                       SendOptions{}, w.now, id));
}

// Durable pending delivery through a full sleep/resume cycle. `elapsed`
// controls the resume deadline outcome.
void run_durable_cycle(PowerWorld& w, ElapsedInterval elapsed) {
  SleepRequest request{};
  CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
  CHECK(w.pump_until(PowerState::ReadyToSleep));
  CHECK_OK(w.coordinator.sleep_enter(w.coordinator.ticket(), w.now));
  CHECK_OK(w.coordinator.wake(ResetCause::DeepSleepWake, elapsed, w.now));
}

std::size_t accepted_count(const CapturingObserver& observer) {
  std::size_t count = 0;
  for (const auto& event : observer.delivery_events) {
    if (event.state == DeliveryState::Accepted) ++count;
  }
  return count;
}

void test_resume_time_uncertain_no_resend() {
  MemoryPowerStorage storage;
  PowerWorld w(storage);
  w.platform_peer(2, 0xaa);
  CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  w.pump(60);  // past confirm window -> RUNNING
  (void)queue_pending(w, 2, true);
  const std::size_t baseline = accepted_count(w.observer);
  run_durable_cycle(w, ElapsedInterval{0, 0, false});
  CHECK(w.events.pending_with(StatusCode::TimeUncertain) == 1);
  CHECK(w.events.pending_with(StatusCode::Ok) == 0);
  CHECK(accepted_count(w.observer) == baseline);  // nothing auto-resent
}

void test_resume_known_elapsed_resends() {
  MemoryPowerStorage storage;
  PowerWorld w(storage);
  w.platform_peer(2, 0xaa);
  CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  w.pump(60);
  (void)queue_pending(w, 2, true, 5000);
  const std::size_t baseline = accepted_count(w.observer);
  run_durable_cycle(w, ElapsedInterval{100, 200, true});
  CHECK(w.events.pending_with(StatusCode::Ok) == 1);
  CHECK(accepted_count(w.observer) == baseline + 1);
}

void test_resume_expired_no_resend() {
  MemoryPowerStorage storage;
  PowerWorld w(storage);
  w.platform_peer(2, 0xaa);
  CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  w.pump(60);
  (void)queue_pending(w, 2, true, 5000);
  const std::size_t baseline = accepted_count(w.observer);
  run_durable_cycle(w, ElapsedInterval{6000, 7000, true});
  CHECK(w.events.pending_with(StatusCode::Expired) == 1);
  CHECK(accepted_count(w.observer) == baseline);
}

void test_resume_running_time_only_resends() {
  MemoryPowerStorage storage;
  PowerConfig power{};
  power.resume_confirm_ms = 50;
  power.deadline_policy = DeadlinePolicy::RunningTimeOnly;
  PowerWorld w(storage, power);
  w.platform_peer(2, 0xaa);
  CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  w.pump(60);
  (void)queue_pending(w, 2, true, 5000);
  const std::size_t baseline = accepted_count(w.observer);
  run_durable_cycle(w, ElapsedInterval{0, 0, false});
  CHECK(w.events.pending_with(StatusCode::Ok) == 1);
  CHECK(accepted_count(w.observer) == baseline + 1);
}

void test_cold_boot_uses_cache_but_uncertain_time() {
  MemoryPowerStorage storage;
  {
    PowerWorld w(storage);
    w.platform_peer(2, 0xaa);
    CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                                 ElapsedInterval{0, 0, false}, w.now));
    w.pump(60);
    (void)queue_pending(w, 2, true);
    run_durable_cycle(w, ElapsedInterval{0, 0, false});
  }
  // New incarnation, same storage: cold boot (power cut) keeps the NVS peer
  // cache but cannot claim trusted elapsed time.
  PowerWorld w(storage);
  CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  CHECK(w.coordinator.reset_cause() == ResetCause::ColdBoot);
  // The durable pending was already consumed at the previous resume; the
  // peer cache still restores and the node can send to it.
  const std::array<std::uint8_t, 2> payload{{4, 4}};
  MessageId id{};
  CHECK_OK(w.node.send(2, ByteView{payload.data(), payload.size()},
                       SendOptions{}, w.now, id));
}

void test_corrupt_image_cache_lost_never_regress() {
  MemoryPowerStorage storage;
  MemoryCounterStore counters;
  routeloom_test::FaultyLedgerStorage ledger_storage;
  SingleAuthority ledger(1, 42, ledger_storage);
  CHECK_OK(ledger.initialize());
  AuthorityOperation op{};
  op.network = 1;
  op.authority = 42;
  op.generation = 1;
  op.sequence = 1;
  op.previous_state_hash = ledger.state().state_hash;
  Digest256 result_hash{};
  result_hash[0] = 9;
  CHECK_OK(ledger.commit(op, result_hash, true));
  const std::uint64_t committed_revision = ledger.revision();
  {
    PowerWorld w(storage);
    w.platform_peer(2, 0xaa);
    CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                                 ElapsedInterval{0, 0, false}, w.now));
    w.pump(60);
    const SleepTicket ticket = reach_ready(w);
    CHECK_OK(w.coordinator.sleep_enter(ticket, w.now));
  }
  // Corrupt both image slots: cache loss must be detected, never rolled
  // back into counter or ledger state.
  storage.corrupt(0, 10);
  storage.corrupt(1, 100);
  PowerWorld w(storage);
  CounterLease lease(counters, 3, 42, 1, 0, 4);
  CHECK_OK(lease.initialize());
  std::uint64_t counter = 0;
  CHECK_OK(lease.next(counter));  // commits block [0,4), issues 0
  CHECK(counter == 0);
  CHECK_OK(w.coordinator.begin(ResetCause::DeepSleepWake,
                               ElapsedInterval{0, 0, false}, w.now));
  CHECK(w.coordinator.resume_outcome() == ResumeOutcome::CacheLost);
  CHECK(w.events.pending_results.empty());
  // Cache loss never rolls the nonce counter or the ledger revision back.
  CounterLease resumed_lease(counters, 3, 42, 1, 0, 4);
  CHECK_OK(resumed_lease.initialize());
  CHECK_OK(resumed_lease.next(counter));
  CHECK(counter == 4);
  CHECK(ledger.revision() == committed_revision);
}

void test_counter_lease_continuity_across_power_cuts() {
  MemoryPowerStorage storage;
  MemoryCounterStore counters;
  std::set<std::uint64_t> issued;
  auto take_counter = [&]() {
    CounterLease lease(counters, 3, 42, 1, 0, 4);
    CHECK_OK(lease.initialize());
    std::uint64_t value = 0;
    CHECK_OK(lease.next(value));
    issued.insert(value);
    return value;
  };

  // Incarnation 1: prepare, reach READY_TO_SLEEP, then "power cut" before
  // enter (scope exit). The persisted image is intact.
  {
    PowerWorld w(storage);
    w.platform_peer(2, 0xaa);
    CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                                 ElapsedInterval{0, 0, false}, w.now));
    w.pump(60);
    CHECK(take_counter() == 0);
    (void)queue_pending(w, 2, true);
    CHECK(w.pump_until(PowerState::Running));  // ensure any drain finished
    SleepRequest request{};
    CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
    CHECK(w.pump_until(PowerState::ReadyToSleep));
    CHECK(w.storage.write_calls == 1);
  }
  // Incarnation 2: deep-sleep wake; counter must continue from the
  // committed block, never reuse the uncommitted remainder.
  {
    PowerWorld w(storage);
    CHECK(take_counter() == 4);
    CHECK_OK(w.coordinator.begin(ResetCause::DeepSleepWake,
                                 ElapsedInterval{0, 0, false}, w.now));
    CHECK(w.events.pending_with(StatusCode::TimeUncertain) == 1);
    w.pump(60);
    CHECK(w.storage.write_calls == 2);  // consume commit landed
  }
  // Incarnation 3: pendings consumed — no replay, counters still ahead.
  {
    PowerWorld w(storage);
    CHECK(take_counter() == 8);
    CHECK_OK(w.coordinator.begin(ResetCause::DeepSleepWake,
                                 ElapsedInterval{0, 0, false}, w.now));
    CHECK(w.events.pending_results.empty());
  }
  CHECK(issued.size() == 3);  // 0, 4, 8 — strictly increasing, never reused
}

void test_power_cut_during_persist_write() {
  MemoryPowerStorage storage;
  storage.tear_next_write(37);  // first image write lands a torn prefix
  PowerWorld w(storage);
  CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  SleepRequest request{};
  CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
  w.pump(30);
  // Persist failed -> abort back to RUNNING, draining cleared.
  CHECK(w.coordinator.state() == PowerState::Running);
  CHECK(!w.node.draining());
  CHECK(w.events.has_diag("power cut mid write"));

  // Reboot on the torn slot: CRC rejects it, resume falls back safely.
  PowerWorld w2(storage);
  CHECK_OK(w2.coordinator.begin(ResetCause::DeepSleepWake,
                                ElapsedInterval{0, 0, false}, w2.now));
  CHECK(w2.coordinator.resume_outcome() == ResumeOutcome::CacheLost);
}

void test_power_cut_during_consume_commit() {
  MemoryPowerStorage storage;
  {
    PowerWorld w(storage);
    w.platform_peer(2, 0xaa);
    CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                                 ElapsedInterval{0, 0, false}, w.now));
    w.pump(60);
    (void)queue_pending(w, 2, true);
    SleepRequest request{};
    CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
    CHECK(w.pump_until(PowerState::ReadyToSleep));
    CHECK_OK(w.coordinator.sleep_enter(w.coordinator.ticket(), w.now));
  }
  // The persist commit plus the sleep_enter refresh commits landed above.
  // Arm the fault at the consume stage itself: the next write — the consume
  // commit — is lost, regardless of how many refresh writes preceded it.
  storage.fail_next_writes(1);  // consume commit is lost
  PowerWorld w(storage);
  CHECK_OK(w.coordinator.begin(ResetCause::DeepSleepWake,
                               ElapsedInterval{0, 0, false}, w.now));
  CHECK(w.events.pending_with(StatusCode::TimeUncertain) == 1);
  CHECK(w.storage.write_calls == 4);
  // Next boot may replay the pending once (bounded duplicate REPORT, still
  // TIME_UNCERTAIN — never a resend on an unknown clock).
  PowerWorld w2(storage);
  CHECK_OK(w2.coordinator.begin(ResetCause::DeepSleepWake,
                                ElapsedInterval{0, 0, false}, w2.now));
  CHECK(w2.events.pending_with(StatusCode::TimeUncertain) == 1);
}

void test_pending_reinject_failure_retained() {
  MemoryPowerStorage storage;
  {
    PowerWorld w(storage);
    w.platform_peer(2, 0xaa);
    CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                                 ElapsedInterval{0, 0, false}, w.now));
    w.pump(60);
    (void)queue_pending(w, 99, true);
    SleepRequest request{};
    CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
    CHECK(w.pump_until(PowerState::ReadyToSleep));
    CHECK(w.storage.write_calls == 1);
  }
  // Incarnation 2: the delivery table is already full of live work, so the
  // durable re-inject fails. The failure is reported AND the record stays in
  // the committed sleep image for a later retry — never silently dropped.
  {
    PowerWorld w(storage);
    w.platform_peer(2, 0xaa);
    CHECK_OK(w.node.start(w.now));
    for (std::size_t i = 0; i < MeshNode::delivery_capacity(); ++i) {
      // WaitingForRoute entries are live (non-terminal), so the pool cannot
      // evict them to make room for the restored pending.
      (void)queue_pending(w, static_cast<NodeId>(90 + i), false);
    }
    CHECK_OK(w.coordinator.begin(ResetCause::DeepSleepWake,
                                 ElapsedInterval{0, 0, true}, w.now));
    // The re-inject fails before allocation: this incarnation already owns a
    // live delivery under the same sequence (counters restart on boot), so
    // resume_delivery refuses the collision instead of conflating messages.
    CHECK(w.events.pending_with(StatusCode::AlreadyExists) == 1);
    CHECK(w.storage.write_calls == 2);  // consume-commit retained the record
  }
  // Incarnation 3: with a free table the same durable pending is retried —
  // a durable record survives failed re-injection, not just torn writes.
  {
    PowerWorld w(storage);
    w.platform_peer(2, 0xaa);
    CHECK_OK(w.coordinator.begin(ResetCause::DeepSleepWake,
                                 ElapsedInterval{0, 0, true}, w.now));
    CHECK(w.events.pending_with(StatusCode::Ok) == 1);
  }
}

// Issue #49 regression: a durable pending retained after a failed resume
// re-inject must survive the next sleep cycle on the same incarnation —
// re-injected on the following wake or explicitly terminated, never
// silently dropped when finish_drain rebuilds the image.
void test_retained_pending_survives_next_sleep_cycle() {
  MemoryPowerStorage storage;
  {
    PowerWorld w(storage);
    w.platform_peer(2, 0xaa);
    CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                                 ElapsedInterval{0, 0, false}, w.now));
    w.pump(60);
    (void)queue_pending(w, 99, true);
    SleepRequest request{};
    CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
    CHECK(w.pump_until(PowerState::ReadyToSleep));
    CHECK_OK(w.coordinator.sleep_enter(w.coordinator.ticket(), w.now));
  }
  {
    PowerWorld w(storage);
    w.platform_peer(2, 0xaa);
    CHECK_OK(w.node.start(w.now));
    for (std::size_t i = 0; i < MeshNode::delivery_capacity(); ++i) {
      // Live WaitingForRoute entries fill the pool so the durable re-inject
      // collides with an already-live id and the record is retained.
      (void)queue_pending(w, static_cast<NodeId>(90 + i), false);
    }
    CHECK_OK(w.coordinator.begin(ResetCause::DeepSleepWake,
                                 ElapsedInterval{0, 0, true}, w.now));
    CHECK(w.events.pending_with(StatusCode::AlreadyExists) == 1);
    w.pump(60);  // past the confirm window -> RUNNING
    // Same incarnation goes back to sleep and wakes again: the retained
    // record must be carried into the new image and retried, not dropped.
    SleepRequest request{};
    CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
    CHECK(w.pump_until(PowerState::ReadyToSleep));
    CHECK_OK(w.coordinator.sleep_enter(w.coordinator.ticket(), w.now));
    CHECK_OK(w.coordinator.wake(ResetCause::DeepSleepWake,
                                ElapsedInterval{0, 0, true}, w.now));
    // The drain freed the colliding slot, so the retry re-injects cleanly.
    CHECK(w.events.pending_with(StatusCode::Ok) == 1);
    CHECK(w.events.pending_results.size() == 2);  // [AlreadyExists, Ok]
  }
}

// Companion to the test above: a retained record whose deadline runs out
// while the node is still awake must be terminated by an explicit Expired
// result at the next sleep — not persisted again and not dropped silently.
void test_retained_pending_expires_while_awake() {
  MemoryPowerStorage storage;
  {
    PowerWorld w(storage);
    w.platform_peer(2, 0xaa);
    CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                                 ElapsedInterval{0, 0, false}, w.now));
    w.pump(60);
    (void)queue_pending(w, 99, true, 5000);
    SleepRequest request{};
    CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
    CHECK(w.pump_until(PowerState::ReadyToSleep));
    CHECK_OK(w.coordinator.sleep_enter(w.coordinator.ticket(), w.now));
  }
  {
    PowerWorld w(storage);
    w.platform_peer(2, 0xaa);
    CHECK_OK(w.node.start(w.now));
    for (std::size_t i = 0; i < MeshNode::delivery_capacity(); ++i) {
      (void)queue_pending(w, static_cast<NodeId>(90 + i), false);
    }
    CHECK_OK(w.coordinator.begin(ResetCause::DeepSleepWake,
                                 ElapsedInterval{0, 0, true}, w.now));
    CHECK(w.events.pending_with(StatusCode::AlreadyExists) == 1);
    w.pump(60);
    w.now += 5000;  // stay awake past the retained record's remaining budget
    SleepRequest request{};
    CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
    CHECK(w.pump_until(PowerState::ReadyToSleep));
    CHECK(w.events.pending_with(StatusCode::Expired) == 1);
    CHECK_OK(w.coordinator.sleep_enter(w.coordinator.ticket(), w.now));
    CHECK_OK(w.coordinator.wake(ResetCause::DeepSleepWake,
                                ElapsedInterval{0, 0, true}, w.now));
    CHECK(w.events.pending_with(StatusCode::Ok) == 0);  // nothing re-injected
    CHECK(w.events.pending_results.size() == 2);  // [AlreadyExists, Expired]
  }
}

// Issue #49 review regression: when finish_drain's image commit fails the
// sleep attempt aborts with every snapshotted delivery still live — the
// uncommitted records must NOT stay in image_ and leak into the next
// drain's carry-over set. The delivery completes normally while awake, so
// the following sleep/wake must re-inject nothing: a completed delivery is
// never resurrected.
void test_completed_delivery_not_carried_over() {
  MemoryPowerStorage storage;
  PowerWorld w(storage);
  // Node 2 is wired into the sim but not yet a neighbor — the durable send
  // parks in WaitingForRoute until a route appears after the abort.
  TestSecurity security_b;
  CapturingObserver observer_b;
  SimRadio radio_b(w.net, 2);
  NodeConfig config_b = PowerWorld::make_config();
  config_b.node = 2;
  MeshNode b(config_b, radio_b, security_b, observer_b);
  w.net.register_node(7, &w.node);
  w.net.register_node(2, &b);
  w.net.connect(7, 2);
  CHECK_OK(b.start(0));

  CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  w.pump(60);
  const MessageId id = queue_pending(w, 2, true);
  CHECK(w.node.delivery(id).state == DeliveryState::WaitingForRoute);

  // First image write fails: the snapshot is committed nowhere and the
  // original delivery stays live (same setup as persist-failure test).
  w.storage.fail_next_writes(1);
  SleepRequest request{};
  CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
  w.pump(600);  // drain deadline -> finish_drain -> commit fails -> abort
  CHECK(w.coordinator.state() == PowerState::Running);
  CHECK(w.node.delivery(id).state == DeliveryState::WaitingForRoute);

  // Route appears while awake; the delivery runs to terminal Delivered.
  CHECK_OK(w.node.add_neighbor(2, 1, w.now));
  CHECK_OK(b.add_neighbor(7, 1, w.now));
  // w.pump only drives the coordinator's node; poll b too so its TX
  // scheduler emits the hop-accept and end-receipt that finish the run.
  for (int i = 0; i < 200 &&
                  w.node.delivery(id).state != DeliveryState::Delivered;
       ++i) {
    b.poll(w.now);
    w.pump(5);
  }
  CHECK(observer_b.messages.size() == 1);
  CHECK(w.node.delivery(id).state == DeliveryState::Delivered);

  // Next sleep/wake: zero re-injections and the verdict is preserved —
  // the aborted snapshot record must not be carried over.
  CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
  CHECK(w.pump_until(PowerState::ReadyToSleep));
  CHECK_OK(w.coordinator.sleep_enter(w.coordinator.ticket(), w.now));
  CHECK_OK(w.coordinator.wake(ResetCause::DeepSleepWake,
                              ElapsedInterval{0, 0, true}, w.now));
  CHECK(w.events.pending_results.empty());
  CHECK(w.node.delivery(id).state == DeliveryState::Delivered);
}

void test_resume_confirm_fast_and_discovery() {
  // Fast path: an RX inside the confirm window marks FastResume.
  {
    MemoryPowerStorage storage;
    PowerWorld w(storage);
    w.platform_peer(2, 0xaa);
    CHECK_OK(w.coordinator.begin(ResetCause::DeepSleepWake,
                                 ElapsedInterval{0, 0, false}, w.now));
    CHECK(w.coordinator.state() == PowerState::Resuming);
    w.inject_rx();
    w.pump(10);
    CHECK(w.coordinator.state() == PowerState::Running);
    CHECK(w.coordinator.resume_outcome() == ResumeOutcome::FastResume);
    CHECK(w.port.discovery_calls == 0);
  }
  // Slow path: silence until the deadline starts bounded discovery once.
  {
    MemoryPowerStorage storage;
    PowerWorld w(storage);
    w.platform_peer(2, 0xaa);
    CHECK_OK(w.coordinator.begin(ResetCause::DeepSleepWake,
                                 ElapsedInterval{0, 0, false}, w.now));
    CHECK(w.coordinator.state() == PowerState::Resuming);
    w.pump(60);  // past the 50 ms confirm window
    CHECK(w.coordinator.state() == PowerState::Running);
    CHECK(w.coordinator.resume_outcome() == ResumeOutcome::DiscoveryRequired);
    CHECK(w.port.discovery_calls == 1);
    w.pump(60);
    CHECK(w.port.discovery_calls == 1);  // bounded: fired exactly once
  }
  // Junk RX still counts as activity but must NOT confirm a fast resume —
  // only authenticated, well-formed peer traffic may. The window expires and
  // bounded discovery starts exactly like silence.
  {
    MemoryPowerStorage storage;
    PowerWorld w(storage);
    w.platform_peer(2, 0xaa);
    CHECK_OK(w.coordinator.begin(ResetCause::DeepSleepWake,
                                 ElapsedInterval{0, 0, false}, w.now));
    CHECK(w.coordinator.state() == PowerState::Resuming);
    w.inject_junk_rx();
    w.pump(60);
    CHECK(w.coordinator.state() == PowerState::Running);
    CHECK(w.coordinator.resume_outcome() == ResumeOutcome::DiscoveryRequired);
    CHECK(w.port.discovery_calls == 1);
  }
}

void test_image_slots_alternate() {
  MemoryPowerStorage storage;
  PowerWorld w(storage);
  CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  CHECK(reach_ready(w).issued);
  CHECK(w.storage.last_slot == 1);
  CHECK_OK(w.coordinator.sleep_enter(w.coordinator.ticket(), w.now));
  CHECK_OK(w.coordinator.wake(ResetCause::DeepSleepWake,
                              ElapsedInterval{0, 0, false}, w.now));
  w.pump(60);
  CHECK(w.pump_until(PowerState::Running));
  CHECK(reach_ready(w).issued);
  CHECK(w.storage.last_slot == 0);
  CHECK(!w.storage.slot_blank(0) && !w.storage.slot_blank(1));
}

void test_persist_failure_aborts() {
  MemoryPowerStorage storage;
  PowerWorld w(storage);
  CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  w.port.inject_quiesce =
      Status::error(StatusCode::RadioFailure, "radio stop failed");
  SleepRequest request{};
  CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
  w.pump(30);
  CHECK(w.coordinator.state() == PowerState::Running);
  CHECK(!w.node.draining());
  CHECK(w.events.has_diag("radio stop failed"));
}

void test_persist_failure_keeps_pending_live() {
  // The durable commit must succeed BEFORE any delivery is marked
  // SLEEP_SAVED: when the image write fails, the abort has to leave the
  // original live delivery untouched so the work can retry — not report
  // SLEEP_SAVED with both slots blank (review reproduction).
  MemoryPowerStorage storage;
  PowerWorld w(storage);
  w.platform_peer(2, 0xaa);
  CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  w.pump(60);
  const MessageId id = queue_pending(w, 99, true);
  SleepRequest request{};
  w.storage.fail_next_writes(1);  // the image commit itself fails
  CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
  w.pump(600);  // in-flight route work drains until the deadline, then aborts
  CHECK(w.coordinator.state() == PowerState::Running);
  CHECK(!w.node.draining());
  const auto result = w.node.delivery(id);
  CHECK(result.state == DeliveryState::WaitingForRoute);
  CHECK(std::strcmp(result.reason, "SLEEP_SAVED") != 0);
}

void test_ready_wait_deducts_pending_lifetime() {
  // READY_TO_SLEEP wait is real elapsed lifetime: a pending that expires
  // while the ticket waits must never be resurrected after the wake.
  MemoryPowerStorage storage;
  PowerWorld w(storage);
  w.platform_peer(2, 0xaa);
  CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  w.pump(60);
  (void)queue_pending(w, 2, true, 5000);
  SleepRequest request{};
  CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
  CHECK(w.pump_until(PowerState::ReadyToSleep));
  w.now += 10010;  // hold the ticket past the pending's 5000 ms lifetime
  CHECK_OK(w.coordinator.sleep_enter(w.coordinator.ticket(), w.now));
  CHECK(w.coordinator.state() == PowerState::Sleeping);
  CHECK(w.events.pending_with(StatusCode::Expired) == 1);
  CHECK_OK(w.coordinator.wake(ResetCause::DeepSleepWake,
                              ElapsedInterval{0, 0, true}, w.now));
  CHECK(w.events.pending_with(StatusCode::Ok) == 0);  // nothing re-injected
}

// Drops every frame of a chosen type so a test can lose END_RECEIPTs while
// still letting DATA through — a receipt loss must not be simulated by
// tearing the whole link down.
class DropTypeRadio final : public RadioPort {
 public:
  DropTypeRadio(RadioPort& inner, FrameType drop) : inner_(inner), drop_(drop) {}
  Status send(NodeId peer, std::uint64_t token, ByteView frame) noexcept override {
    routeloom_test::FrameSight sight{};
    if (routeloom_test::sight_frame(frame, sight) && sight.type == drop_) {
      return Status::success();  // swallowed: sender sees TX ok, peer never does
    }
    return inner_.send(peer, token, frame);
  }
  Status recover() noexcept override { return inner_.recover(); }

 private:
  RadioPort& inner_;
  FrameType drop_;
};

void test_resume_reuses_original_id_dedup_once() {
  // End-to-end identity check: B accepts the DATA, the end receipt is lost,
  // A sleeps and resumes — the retransmission must carry the ORIGINAL
  // message id so B's terminal dedup suppresses it (payload delivered once).
  MemoryPowerStorage storage;
  PowerWorld w(storage);  // node 7 + coordinator
  w.platform_peer(2, 0xaa);

  TestSecurity security_b;
  CapturingObserver observer_b;
  SimRadio radio_b_inner(w.net, 2);
  DropTypeRadio radio_b(radio_b_inner, FrameType::EndReceipt);
  NodeConfig config_b = PowerWorld::make_config();
  config_b.node = 2;
  MeshNode b(config_b, radio_b, security_b, observer_b);
  w.net.register_node(7, &w.node);
  w.net.register_node(2, &b);
  w.net.connect(7, 2);

  CHECK_OK(b.start(0));
  CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, 0));
  w.pump(60);
  CHECK_OK(w.node.add_neighbor(2, 1, w.now));
  CHECK_OK(b.add_neighbor(7, 1, w.now));

  // The longest lifetime an origin may request (issue #55): a message is
  // never allowed to outlive the receiver's dedup retention.
  const MessageId id = queue_pending(w, 2, true, kMaxMessageLifetimeMs);
  w.pump(100);  // DATA -> B delivers once; END_RECEIPT swallowed -> non-terminal
  CHECK(observer_b.messages.size() == 1);
  const auto before_sleep = w.node.delivery(id);
  CHECK(before_sleep.state == DeliveryState::WaitingForEndReceipt ||
        before_sleep.state == DeliveryState::WaitingForMac ||
        before_sleep.state == DeliveryState::WaitingForHopAccept ||
        before_sleep.state == DeliveryState::Queued ||
        before_sleep.state == DeliveryState::Accepted);

  SleepRequest request{};
  CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
  CHECK(w.pump_until(PowerState::ReadyToSleep));
  CHECK_OK(w.coordinator.sleep_enter(w.coordinator.ticket(), w.now));
  CHECK_OK(w.coordinator.wake(ResetCause::DeepSleepWake,
                              ElapsedInterval{100, 200, true}, w.now));

  // The re-injected delivery keeps the ORIGINAL id and is live again.
  CHECK(w.events.pending_with(StatusCode::Ok) == 1);
  const auto resumed = w.node.delivery(id);
  CHECK(resumed.state != DeliveryState::Empty);
  CHECK(resumed.state != DeliveryState::Indeterminate);
  // Resume re-adds the saved peer as a neighbor, so the route is back and
  // the retransmission flows; B's dedup suppresses the duplicate payload.
  w.pump(100);
  CHECK(observer_b.messages.size() == 1);
}

// Issue #39 rig: A (the PowerWorld node 7) sends one max-lifetime durable
// DATA to B, whose END_RECEIPTs are swallowed so A's delivery stays
// non-terminal and is persisted across sleep. Unlike the test above, B is
// polled on the shared wall clock throughout — its terminal pin expires on
// schedule, so suppression is proven by live retention, not by a record
// that was never swept.
struct ResumeDedupRig {
  MemoryPowerStorage storage;
  PowerWorld w{storage};
  TestSecurity security_b;
  CapturingObserver observer_b;
  SimRadio radio_b_inner{w.net, 2};
  DropTypeRadio radio_b{radio_b_inner, FrameType::EndReceipt};
  MeshNode b{make_b_config(), radio_b, security_b, observer_b};
  MessageId id{};

  static NodeConfig make_b_config() {
    NodeConfig config = PowerWorld::make_config();
    config.node = 2;
    return config;
  }

  // Both nodes run: A through its coordinator, B directly.
  void pump(MonotonicMs duration) {
    const MonotonicMs end = w.now + duration;
    for (; w.now <= end; w.now += 5) {
      w.coordinator.poll(w.now);
      b.poll(w.now);
      w.net.flush(w.now);
    }
  }

  std::size_t data_to_b() const {
    std::size_t count = 0;
    for (const auto& sight : w.net.sights) {
      if (sight.type == FrameType::Data && sight.from == PowerWorld::kSelf &&
          sight.to == 2) {
        ++count;
      }
    }
    return count;
  }

  // Deliver once to B, then sleep with the delivery still pending.
  void deliver_then_sleep() {
    w.platform_peer(2, 0xaa);
    w.net.register_node(PowerWorld::kSelf, &w.node);
    w.net.register_node(2, &b);
    w.net.connect(PowerWorld::kSelf, 2);
    CHECK_OK(b.start(0));
    CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                                 ElapsedInterval{0, 0, false}, 0));
    pump(60);
    CHECK_OK(w.node.add_neighbor(2, 1, w.now));
    CHECK_OK(b.add_neighbor(PowerWorld::kSelf, 1, w.now));
    id = queue_pending(w, 2, true, kMaxMessageLifetimeMs);
    pump(100);  // DATA -> B delivers once; END_RECEIPT swallowed
    CHECK(observer_b.messages.size() == 1);
    CHECK(b.dedup_stats().admitted_terminal == 1);
    const auto state = w.node.delivery(id).state;
    CHECK(state != DeliveryState::Delivered && state != DeliveryState::Empty);
    SleepRequest request{};
    CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
    for (int i = 0; i < 400 && w.coordinator.state() != PowerState::ReadyToSleep;
         ++i) {
      pump(0);
    }
    CHECK(w.coordinator.state() == PowerState::ReadyToSleep);
    CHECK_OK(w.coordinator.sleep_enter(w.coordinator.ticket(), w.now));
  }

  // A sleeps `sleep_ms` of wall time; B keeps running on the same clock.
  void sleep_and_wake(MonotonicMs sleep_ms) {
    const MonotonicMs wake_at = w.now + sleep_ms;
    while (w.now < wake_at) {
      b.poll(w.now);
      w.now += 100;
    }
    w.now = wake_at;
    b.poll(w.now);
    CHECK_OK(w.coordinator.wake(ResetCause::DeepSleepWake,
                                ElapsedInterval{sleep_ms, sleep_ms + 50, true},
                                w.now));
  }
};

// Issue #39 (b): the receiver's clock runs 61 s past the delivery while the
// sender sleeps. B's terminal pin (max lifetime + late result = 60 s) has
// expired, so a resend under the original id would reach the application a
// second time. Lifetime is wall-elapsed including sleep and origin lifetimes
// are capped at 30 s: the durable pending must resume as EXPIRED and never
// be resent.
void test_long_sleep_pending_expires_no_duplicate() {
  ResumeDedupRig rig;
  rig.deliver_then_sleep();
  const std::size_t data_before = rig.data_to_b();
  rig.sleep_and_wake(61000);
  // The danger is real: B's exactly-once pin is gone.
  CHECK(rig.b.dedup_stats().expired >= 1);
  CHECK(rig.b.dedup_resident() == 0);
  // The sender refuses to resend on its own expiry.
  CHECK(rig.w.events.pending_with(StatusCode::Expired) == 1);
  CHECK(rig.w.events.pending_with(StatusCode::Ok) == 0);
  rig.pump(2000);
  CHECK(rig.data_to_b() == data_before);          // nothing on the air
  CHECK(rig.observer_b.messages.size() == 1);     // delivered exactly once
  CHECK(rig.b.dedup_stats().admitted_terminal == 1);
}

// Issue #39: a 20 s sleep resumes with ~10 s of lifetime left. The resend
// under the original id reaches B inside its pin and is suppressed; the
// origin's own expiry (<= 30 s after send) precedes the pin's (60 s), so
// when the pin finally expires nothing is left to resend.
void test_short_sleep_resend_dedups_once() {
  ResumeDedupRig rig;
  rig.deliver_then_sleep();
  const MonotonicMs first_seen = rig.w.now;
  const std::size_t data_before = rig.data_to_b();
  rig.sleep_and_wake(20000);
  CHECK(rig.b.dedup_stats().expired == 0);  // pin alive at wake
  CHECK(rig.w.events.pending_with(StatusCode::Ok) == 1);
  rig.pump(200);
  CHECK(rig.data_to_b() > data_before);            // the resend reached B
  CHECK(rig.observer_b.messages.size() == 1);      // ...and was suppressed
  CHECK(rig.b.dedup_stats().admitted_terminal == 1);
  // Retries continue until the resumed lifetime runs out (receipts are
  // swallowed); the verdict turns terminal well before the pin expires.
  rig.pump(12000);
  const auto state = rig.w.node.delivery(rig.id).state;
  CHECK(state == DeliveryState::Expired || state == DeliveryState::Failed);
  CHECK(rig.w.now - first_seen < kDedupHardCapMs);
  CHECK(rig.b.dedup_resident() == 1);  // pin still holding
  // Past the pin's end: it expires, and the origin sends nothing more.
  const std::size_t data_settled = rig.data_to_b();
  rig.pump(kDedupHardCapMs);
  CHECK(rig.b.dedup_resident() == 0);
  CHECK(rig.data_to_b() == data_settled);
  CHECK(rig.observer_b.messages.size() == 1);
}


// Issue #55: the 30s normal-lifetime ceiling is enforced at every origin
// send API — refused, never silently clamped (dedup retention is sized on
// this bound).
void test_send_lifetime_ceiling() {
  MemoryPowerStorage storage;
  PowerWorld w(storage);
  CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, 0));
  w.pump(60);
  const std::array<std::uint8_t, 4> payload{{1, 2, 3, 4}};
  const ByteView body{payload.data(), payload.size()};
  MessageId id{};
  SendOptions options{};
  options.lifetime_ms = kMaxMessageLifetimeMs;
  CHECK_OK(w.node.send(9, body, options, w.now, id));
  options.lifetime_ms = kMaxMessageLifetimeMs + 1;
  CHECK(w.node.send(9, body, options, w.now, id).code ==
        StatusCode::InvalidArgument);
  CHECK(w.node.send_service(9, body, kMaxMessageLifetimeMs + 1, w.now, id)
            .code == StatusCode::InvalidArgument);
  CHECK(w.node.resend_service(MessageId{1, 1}, 9, body, 1,
                              kMaxMessageLifetimeMs + 1, w.now)
            .code == StatusCode::InvalidArgument);
}

// ---------------------------------------------------------------------------
// Issue #110: group delivery vs the sleep drain and settlement. A
// gateway-scoped pair — gateway 1 (the group source) and leaf 2 (a tree
// member), either of which a PowerCoordinator may drive. Group state is
// RAM-only: unfinished origins get an explicit terminal verdict instead of a
// persist record, and ordered holds are released to the application before
// READY_TO_SLEEP.
// ---------------------------------------------------------------------------

// NodeObserver that records the events these tests assert on and can run a
// hook INSIDE a terminal delivery callback — for re-entrant coordinator
// calls (sleep_abort / send) from a disposition notification.
struct HookedObserver final : NodeObserver {
  std::vector<DeliveryResult> delivery_events;
  std::vector<GroupDeliveryResult> group_results;
  struct GroupReceipt {
    GroupMessageInfo info;
    std::vector<std::uint8_t> payload;
  };
  std::vector<GroupReceipt> group_messages;
  struct Message {
    MessageKey key;
    NodeId source;
    std::vector<std::uint8_t> payload;
  };
  std::vector<Message> messages;
  struct Diagnostic {
    std::string reason;
    NodeId peer;
  };
  std::vector<Diagnostic> diags;
  // Hooks run INSIDE their notification — for re-entrant coordinator calls
  // from NodeObserver callbacks.
  std::function<void(const DeliveryResult&)> on_delivery_fn;
  std::function<void(const GroupDeliveryResult&)> on_group_fn;
  std::function<void(const GroupMessageInfo&, ByteView)> on_group_message_fn;
  std::function<void(const MessageKey&, NodeId, ByteView)> on_message_fn;
  std::function<void(const char*, NodeId, const MessageId*)> on_diag_fn;
  std::function<void(const MessageKey&, const AppliedResultView&)>
      on_applied_result_fn;

  void on_message(const MessageKey& key, NodeId source,
                  ByteView payload) noexcept override {
    messages.push_back(Message{key, source,
                               std::vector<std::uint8_t>(
                                   payload.data, payload.data + payload.size)});
    if (on_message_fn) on_message_fn(key, source, payload);
  }
  void on_diagnostic(const char* reason, NodeId peer,
                     const MessageId* message) noexcept override {
    diags.push_back(Diagnostic{reason, peer});
    if (on_diag_fn) on_diag_fn(reason, peer, message);
  }
  void on_delivery(const DeliveryResult& result) noexcept override {
    delivery_events.push_back(result);
    if (on_delivery_fn) on_delivery_fn(result);
  }
  void on_group_message(const GroupMessageInfo& info,
                        ByteView payload) noexcept override {
    group_messages.push_back(GroupReceipt{
        info, std::vector<std::uint8_t>(payload.data, payload.data + payload.size)});
    if (on_group_message_fn) on_group_message_fn(info, payload);
  }
  void on_group_delivery(const GroupDeliveryResult& result) noexcept override {
    group_results.push_back(result);
    if (on_group_fn) on_group_fn(result);
  }
  void on_applied_result(const MessageKey& key,
                         const AppliedResultView& result) noexcept override {
    if (on_applied_result_fn) on_applied_result_fn(key, result);
  }
  bool has_diag(const char* prefix) const {
    for (const auto& d : diags) {
      if (d.reason.rfind(prefix, 0) == 0) return true;
    }
    return false;
  }
};

struct GroupPowerWorld {
  static constexpr NodeId kGateway = 1;
  static constexpr NodeId kLeaf = 2;

  SimNetwork net;
  TestSecurity security_a;
  TestSecurity security_b;
  HookedObserver observer_a;
  HookedObserver observer_b;
  SimRadio radio_a;
  SimRadio radio_b;
  MeshNode a;
  MeshNode b;
  FakePowerPort port;
  RecordingPowerEvents events;
  MonotonicMs now{0};

  GroupPowerWorld()
      : radio_a(net, kGateway), radio_b(net, kLeaf),
        a(config(kGateway), radio_a, security_a, observer_a),
        b(config(kLeaf), radio_b, security_b, observer_b) {
    net.register_node(kGateway, &a);
    net.register_node(kLeaf, &b);
    net.connect(kGateway, kLeaf);
  }

  static NodeConfig config(const NodeId id) {
    NodeConfig config{};
    config.network = 1;
    config.node = id;
    config.message_session = 100 + static_cast<std::uint32_t>(id);
    config.route_gateways = {kGateway, kInvalidNodeId};
    config.route_advertisement_period_ms = 500;
    config.route_lifetime_ms = 9000;  // scoped lease rule: >= 14 x period
    config.route_refresh_ticks = kScopedDefaultRefreshTicks;
    return config;
  }

  void run(MonotonicMs duration) {
    const MonotonicMs end = now + duration;
    for (; now <= end; now += 5) {
      a.poll(now);
      b.poll(now);
      net.flush(now);
    }
  }

  // Drives the coordinated node's state machine while the peer node is
  // polled directly, so the mesh keeps moving while `coordinator` drains.
  bool run_until(PowerCoordinator& coordinator, MeshNode& other,
                 PowerState target, int max_iterations = 400) {
    for (int i = 0; i < max_iterations && coordinator.state() != target; ++i) {
      coordinator.poll(now);
      other.poll(now);
      net.flush(now);
      now += 5;
    }
    return coordinator.state() == target;
  }

  void converge() {
    CHECK_OK(a.start(now));
    CHECK_OK(b.start(now));
    CHECK_OK(a.add_neighbor(kLeaf, 1, now));
    CHECK_OK(b.add_neighbor(kGateway, 1, now));
    for (int i = 0; i < 400 && !a.scoped_child(kLeaf); ++i) run(50);
    CHECK(a.scoped_child(kLeaf));
  }

  MessageId send_all(MeshNode& source, const GroupSendOptions& options) {
    const std::array<std::uint8_t, 3> payload{{'g', 'o', '!'}};
    MessageId id{};
    CHECK_OK(source.send_group(kGroupAll,
                               ByteView{payload.data(), payload.size()},
                               options, now, id));
    return id;
  }
};

// Deterministic loss for the group-sleep tests: drops every frame of
// `g_drop_type` matching the optional receiver/sequence filters — reports to
// hold a source round open, or one group seq toward the leaf for the hold.
FrameType g_drop_type = FrameType::GroupReport;
NodeId g_drop_to = kInvalidNodeId;
std::uint64_t g_drop_sequence = 0;

bool group_loss_hook(const SimNetwork::Pending& pending) {
  routeloom_test::FrameSight sight{};
  if (!routeloom_test::sight_frame(
          ByteView{pending.frame.data(), pending.frame.size()}, sight)) {
    return false;
  }
  return sight.type == g_drop_type &&
         (g_drop_to == kInvalidNodeId || pending.to == g_drop_to) &&
         (g_drop_sequence == 0 || sight.sequence == g_drop_sequence);
}

void drop_all_reports() {
  g_drop_type = FrameType::GroupReport;
  g_drop_to = kInvalidNodeId;
  g_drop_sequence = 0;
}

// The most recent group delivery event, or Empty when none was emitted.
GroupDeliveryResult last_group_result(const HookedObserver& observer) {
  if (observer.group_results.empty()) return GroupDeliveryResult{};
  return observer.group_results.back();
}

// Mirror of the node's sleep-terminal verdict set, for "still live" asserts.
bool sleep_verdict_terminal(DeliveryState state) {
  switch (state) {
    case DeliveryState::Empty:
    case DeliveryState::Delivered:
    case DeliveryState::Failed:
    case DeliveryState::Expired:
    case DeliveryState::CancelledBeforeTx:
    case DeliveryState::Indeterminate:
      return true;
    default:
      return false;
  }
}

void test_group_drain_completes_round() {
  // The drain waits on the round in flight: the origin reaches Delivered and
  // needs no disposition at all (regression: quiesced ignored group work).
  MemoryPowerStorage storage;
  GroupPowerWorld w;
  w.converge();
  PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                               w.events);
  CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  GroupSendOptions options{};
  const MessageId id = w.send_all(w.a, options);
  CHECK(w.a.group_delivery(id).state == DeliveryState::WaitingForEndReceipt);
  SleepRequest request{};
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
  CHECK(w.events.saw(PowerState::Draining, PowerState::Persisting,
                     "DRAIN_SETTLED"));
  const auto result = w.a.group_delivery(id);
  CHECK(result.state == DeliveryState::Delivered);
  CHECK(std::strcmp(result.reason, "GROUP_COMPLETE") == 0);
  CHECK(w.observer_b.group_messages.size() == 1);
}

void test_group_sleep_policy_fail() {
  // The round can never finish (every report is lost): at the drain deadline
  // the unfinished origin must fail loudly, not ride into READY_TO_SLEEP.
  MemoryPowerStorage storage;
  GroupPowerWorld w;
  w.converge();
  drop_all_reports();
  w.net.drop_frame = group_loss_hook;
  PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                               w.events);
  CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  GroupSendOptions options{};
  const MessageId id = w.send_all(w.a, options);
  SleepRequest request{};
  request.pending_policy = SleepWorkPolicy::Fail;
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
  CHECK(w.events.saw(PowerState::Draining, PowerState::Persisting,
                     "DRAIN_DEADLINE"));
  const auto result = w.a.group_delivery(id);
  CHECK(result.state == DeliveryState::Failed);
  CHECK(std::strcmp(result.reason, "SLEEP_DRAIN") == 0);
  const auto last = last_group_result(w.observer_a);
  CHECK(last.id == id && last.state == DeliveryState::Failed &&
        std::strcmp(last.reason, "SLEEP_DRAIN") == 0);
}

void test_group_sleep_policy_save() {
  // Save cannot apply — the group lane has no persistence: the origin fails
  // with an honest reason and nothing enters the sleep image.
  MemoryPowerStorage storage;
  GroupPowerWorld w;
  w.converge();
  drop_all_reports();
  w.net.drop_frame = group_loss_hook;
  PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                               w.events);
  CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  GroupSendOptions options{};
  const MessageId id = w.send_all(w.a, options);
  SleepRequest request{};
  request.pending_policy = SleepWorkPolicy::Save;
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
  const auto result = w.a.group_delivery(id);
  CHECK(result.state == DeliveryState::Failed);
  CHECK(std::strcmp(result.reason, "SLEEP_GROUP_NOT_PERSISTED") == 0);
  const auto last = last_group_result(w.observer_a);
  CHECK(last.id == id && last.state == DeliveryState::Failed &&
        std::strcmp(last.reason, "SLEEP_GROUP_NOT_PERSISTED") == 0);
  // Nothing was saved: a wake re-injects no pending work at all.
  CHECK_OK(coordinator.sleep_enter(coordinator.ticket(), w.now));
  CHECK_OK(coordinator.wake(ResetCause::DeepSleepWake,
                              ElapsedInterval{0, 0, true}, w.now));
  CHECK(w.events.pending_results.empty());
}

void test_group_sleep_policy_defer() {
  // Defer leaves the outcome unknown — the same Indeterminate a non-durable
  // unicast delivery gets, surfaced through the usual delivery event.
  MemoryPowerStorage storage;
  GroupPowerWorld w;
  w.converge();
  drop_all_reports();
  w.net.drop_frame = group_loss_hook;
  PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                               w.events);
  CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  GroupSendOptions options{};
  const MessageId id = w.send_all(w.a, options);
  SleepRequest request{};
  request.pending_policy = SleepWorkPolicy::Defer;
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
  const auto result = w.a.group_delivery(id);
  CHECK(result.state == DeliveryState::Indeterminate);
  CHECK(std::strcmp(result.reason, "SLEEP_DEFERRED") == 0);
  const auto last = last_group_result(w.observer_a);
  CHECK(last.id == id && last.state == DeliveryState::Indeterminate &&
        std::strcmp(last.reason, "SLEEP_DEFERRED") == 0);
}

void test_group_ordered_hold_released_for_sleep() {
  // Leaf 2 receives ordered seq 1 and 3 while seq 2 is lost: seq 3 stays
  // held. Sleep must release the held payload to the app through the same
  // gap-skip path a hold timeout uses — never carry it into READY_TO_SLEEP.
  MemoryPowerStorage storage;
  GroupPowerWorld w;
  w.converge();
  GroupSendOptions options{};
  options.ordered = true;
  options.lifetime_ms = 10000;
  w.send_all(w.a, options);  // seq 1
  w.run(60);
  // seq 2 toward the leaf is lost for good; an Urgent seq 3 overtakes it.
  g_drop_type = FrameType::GroupData;
  g_drop_to = GroupPowerWorld::kLeaf;
  g_drop_sequence = kGroupSequenceFlag | 2;
  w.net.drop_frame = group_loss_hook;
  w.send_all(w.a, options);
  GroupSendOptions urgent = options;
  urgent.priority = Priority::Urgent;
  w.send_all(w.a, urgent);
  w.run(80);
  // Only seq 1 reached the app; seq 3 is held behind the seq-2 gap.
  CHECK(w.observer_b.group_messages.size() == 1);
  if (w.observer_b.group_messages.size() == 1) {
    CHECK(w.observer_b.group_messages[0].info.group_seq == 1);
  }
  CHECK(w.b.group_stats().held == 1);
  CHECK(w.b.group_holds_in_use() == 1);

  PowerCoordinator coordinator(PowerConfig{500, 50}, w.b, w.port, storage,
                               w.events);
  CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  SleepRequest request{};
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  CHECK(w.run_until(coordinator, w.a, PowerState::ReadyToSleep));
  CHECK(w.events.saw(PowerState::Draining, PowerState::Persisting,
                     "DRAIN_SETTLED"));
  // Flushed through the ordered path before the ticket existed: the app sees
  // {1, 3}, the gap is counted and nothing remains held or persisted.
  CHECK(w.b.group_holds_in_use() == 0);
  CHECK(w.observer_b.group_messages.size() == 2);
  if (w.observer_b.group_messages.size() == 2) {
    CHECK(w.observer_b.group_messages[1].info.group_seq == 3);
    CHECK(!w.observer_b.group_messages[1].info.late);
  }
  CHECK(w.b.group_stats().gaps_skipped >= 1);
  CHECK_OK(coordinator.sleep_enter(coordinator.ticket(), w.now));
  CHECK_OK(coordinator.wake(ResetCause::DeepSleepWake,
                              ElapsedInterval{0, 0, true}, w.now));
  CHECK(w.events.pending_results.empty());
}

void test_group_sleep_commit_failure_keeps_state() {
  // A failed image commit aborts with the group lane untouched — origin
  // dispositions and the hold release run only AFTER the commit — so the
  // node comes back to RUNNING with the hold still held and no event.
  MemoryPowerStorage storage;
  GroupPowerWorld w;
  w.converge();
  GroupSendOptions options{};
  options.ordered = true;
  options.lifetime_ms = 10000;
  w.send_all(w.a, options);  // seq 1
  w.run(60);
  g_drop_type = FrameType::GroupData;
  g_drop_to = GroupPowerWorld::kLeaf;
  g_drop_sequence = kGroupSequenceFlag | 2;
  w.net.drop_frame = group_loss_hook;
  w.send_all(w.a, options);  // seq 2: lost toward the leaf
  GroupSendOptions urgent = options;
  urgent.priority = Priority::Urgent;
  w.send_all(w.a, urgent);   // seq 3: overtakes, held
  w.run(80);
  CHECK(w.b.group_holds_in_use() == 1);

  PowerCoordinator coordinator(PowerConfig{500, 50}, w.b, w.port, storage,
                               w.events);
  CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  storage.fail_next_writes(1);  // the image commit itself fails
  SleepRequest request{};
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  CHECK(w.run_until(coordinator, w.a, PowerState::Running));
  CHECK(!w.b.draining());
  CHECK(w.b.group_holds_in_use() == 1);
  CHECK(w.observer_b.group_messages.size() == 1);
  // With storage healthy again, the same drain flushes the hold normally.
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  CHECK(w.run_until(coordinator, w.a, PowerState::ReadyToSleep));
  CHECK(w.b.group_holds_in_use() == 0);
  CHECK(w.observer_b.group_messages.size() == 2);
}

void test_group_settled_callback_abort_new_send() {
  // Inside the SLEEP_DRAIN terminal event the app vetoes the sleep and sends
  // again: the abort is ACCEPTED (queued, applied at the safe point — no
  // ticket, no READY transition), but the callback runs while the drain is
  // still active, so the send is refused with NODE_DRAINING and creates no
  // origin. The app resends after RUNNING is observed (#110: an accepted
  // abort never reopens admission inside its own callback).
  MemoryPowerStorage storage;
  GroupPowerWorld w;
  w.converge();
  drop_all_reports();
  w.net.drop_frame = group_loss_hook;
  PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                               w.events);
  CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  GroupSendOptions options{};
  w.send_all(w.a, options);

  const std::array<std::uint8_t, 4> again{{'n', 'e', 'w', '!'}};
  MessageId new_id{};
  PowerState callback_state = PowerState::Running;
  Status abort_status = Status::error(StatusCode::InternalError, "not run");
  Status send_status = Status::error(StatusCode::InternalError, "not run");
  w.observer_a.on_group_fn = [&](const GroupDeliveryResult& result) {
    if (result.state != DeliveryState::Failed ||
        std::strcmp(result.reason, "SLEEP_DRAIN") != 0) {
      return;  // act once, on the settlement event itself
    }
    callback_state = coordinator.state();
    abort_status = coordinator.sleep_abort("APP_VETO");
    send_status = w.a.send_group(kGroupAll,
                                 ByteView{again.data(), again.size()},
                                 options, w.now, new_id);
  };
  SleepRequest request{};
  request.pending_policy = SleepWorkPolicy::Fail;
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  CHECK(w.run_until(coordinator, w.b, PowerState::Running));
  CHECK(callback_state == PowerState::Persisting);
  CHECK(abort_status.ok());
  CHECK(std::strcmp(abort_status.detail, "POWER_REQUEST_QUEUED") == 0);
  CHECK(!send_status.ok());
  CHECK(std::strcmp(send_status.detail, "NODE_DRAINING") == 0);
  CHECK(!w.events.saw(PowerState::Persisting, PowerState::ReadyToSleep,
                      "SLEEP_READY"));
  // The refused send created nothing resendable: the app sends afresh after
  // RUNNING and the new origin runs to Delivered once reports flow again.
  CHECK(w.a.group_delivery(new_id).state == DeliveryState::Empty);
  w.net.drop_frame = nullptr;
  MessageId retry{};
  CHECK_OK(w.a.send_group(kGroupAll, ByteView{again.data(), again.size()},
                          options, w.now, retry));
  w.run(500);
  const auto done = w.a.group_delivery(retry);
  CHECK(done.state == DeliveryState::Delivered);
}

void test_unicast_disposition_callback_abort_new_send() {
  // Same reentrancy through the unicast disposition: the abort inside
  // on_delivery is accepted, the send inside the same callback is refused
  // with NODE_DRAINING (admission reopens only after RUNNING), and the
  // resend from outside completes (#110, unicast leg of the test above).
  MemoryPowerStorage storage;
  GroupPowerWorld w;
  w.converge();
  PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                               w.events);
  CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  const std::array<std::uint8_t, 3> payload{{'x', 'y', 'z'}};
  MessageId id{}, new_id{};
  SendOptions send_options{};
  CHECK_OK(w.a.send(9, ByteView{payload.data(), payload.size()},
                    send_options, w.now, id));  // unreachable: stays WaitingForRoute

  Status abort_status = Status::error(StatusCode::InternalError, "not run");
  Status send_status = Status::error(StatusCode::InternalError, "not run");
  w.observer_a.on_delivery_fn = [&](const DeliveryResult& result) {
    if (result.state != DeliveryState::Failed ||
        std::strcmp(result.reason, "SLEEP_DRAIN") != 0) {
      return;
    }
    abort_status = coordinator.sleep_abort("APP_VETO");
    send_status = w.a.send(GroupPowerWorld::kLeaf,
                           ByteView{payload.data(), payload.size()},
                           send_options, w.now, new_id);
  };
  SleepRequest request{};
  request.pending_policy = SleepWorkPolicy::Fail;
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  CHECK(w.run_until(coordinator, w.b, PowerState::Running));
  CHECK(abort_status.ok());
  CHECK(std::strcmp(abort_status.detail, "POWER_REQUEST_QUEUED") == 0);
  CHECK(!send_status.ok());
  CHECK(std::strcmp(send_status.detail, "NODE_DRAINING") == 0);
  CHECK(!w.events.saw(PowerState::Persisting, PowerState::ReadyToSleep,
                      "SLEEP_READY"));
  MessageId retry{};
  CHECK_OK(w.a.send(GroupPowerWorld::kLeaf,
                    ByteView{payload.data(), payload.size()},
                    send_options, w.now, retry));
  w.run(500);
  const auto result = w.a.delivery(retry);
  CHECK(result.state == DeliveryState::Delivered);
}

void test_disposition_callback_send_refused() {
  // Without an abort the drain pause still applies inside a settlement
  // callback — the coordinator is still PERSISTING, not READY — so
  // send()/send_group() are refused deterministically and the sleep
  // proceeds to READY_TO_SLEEP.
  MemoryPowerStorage storage;
  GroupPowerWorld w;
  w.converge();
  drop_all_reports();
  w.net.drop_frame = group_loss_hook;
  PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                               w.events);
  CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  const std::array<std::uint8_t, 3> payload{{'x', 'y', 'z'}};
  MessageId id{}, retry{};
  SendOptions send_options{};
  CHECK_OK(w.a.send(9, ByteView{payload.data(), payload.size()},
                    send_options, w.now, id));
  GroupSendOptions group_options{};
  w.send_all(w.a, group_options);

  Status send_status{};
  Status group_status{};
  w.observer_a.on_delivery_fn = [&](const DeliveryResult& result) {
    if (result.state == DeliveryState::Failed &&
        std::strcmp(result.reason, "SLEEP_DRAIN") == 0) {
      send_status = w.a.send(GroupPowerWorld::kLeaf,
                             ByteView{payload.data(), payload.size()},
                             send_options, w.now, retry);
    }
  };
  w.observer_a.on_group_fn = [&](const GroupDeliveryResult& result) {
    if (result.state == DeliveryState::Failed &&
        std::strcmp(result.reason, "SLEEP_DRAIN") == 0) {
      group_status = w.a.send_group(kGroupAll,
                                    ByteView{payload.data(), payload.size()},
                                    group_options, w.now, retry);
    }
  };
  SleepRequest request{};
  request.pending_policy = SleepWorkPolicy::Fail;
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
  CHECK(!send_status.ok());
  CHECK(std::strcmp(send_status.detail, "NODE_DRAINING") == 0);
  CHECK(!group_status.ok());
  CHECK(std::strcmp(group_status.detail, "NODE_DRAINING") == 0);
}

void test_settlement_abort_reprepare_stops_old_policy() {
  // A settlement callback that aborts AND re-prepares ends the old attempt
  // outright: the second group origin settles under the NEW attempt's Defer
  // policy, never under the stale Fail one (#110 review: the callback's
  // abort ends the old attempt at the safe point and its prepare starts a
  // new attempt on the next poll).
  MemoryPowerStorage storage;
  GroupPowerWorld w;
  w.converge();
  drop_all_reports();
  w.net.drop_frame = group_loss_hook;
  PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                               w.events);
  CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  GroupSendOptions options{};
  const MessageId id1 = w.send_all(w.a, options);  // seq 1
  const MessageId id2 = w.send_all(w.a, options);  // seq 2

  Status abort_status = Status::error(StatusCode::InternalError, "not run");
  Status prepare_status = Status::error(StatusCode::InternalError, "not run");
  w.observer_a.on_group_fn = [&](const GroupDeliveryResult& result) {
    if (result.state != DeliveryState::Failed ||
        std::strcmp(result.reason, "SLEEP_DRAIN") != 0 ||
        abort_status.code != StatusCode::InternalError) {
      return;  // act once, on the first settled origin
    }
    abort_status = coordinator.sleep_abort("APP_VETO");
    SleepRequest retry{};
    retry.pending_policy = SleepWorkPolicy::Defer;
    prepare_status = coordinator.sleep_prepare(retry, w.now);
  };
  SleepRequest request{};
  request.pending_policy = SleepWorkPolicy::Fail;
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  // Inspect the aborting poll itself: when it returns the old attempt is
  // over (RUNNING), origin 2 is still live, and the new attempt has not
  // committed anything yet — its prepare starts on a LATER outer poll.
  bool aborted = false;
  for (int i = 0; i < 400 && !aborted; ++i) {
    coordinator.poll(w.now);
    w.b.poll(w.now);
    w.net.flush(w.now);
    w.now += 5;
    aborted = abort_status.code != StatusCode::InternalError &&
              coordinator.state() == PowerState::Running;
  }
  CHECK(aborted);
  CHECK(abort_status.ok());
  CHECK(prepare_status.ok());
  CHECK(storage.write_calls == 1);  // the old attempt's commit only
  CHECK(w.observer_a.group_results.size() == 1);
  CHECK(sleep_verdict_terminal(w.a.group_delivery(id1).state));
  CHECK(!sleep_verdict_terminal(w.a.group_delivery(id2).state));
  CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
  // Origin 1 settled under the old Fail attempt; origin 2 belongs to the
  // new Defer attempt — the stale Fail settlement must not resume for it.
  CHECK(w.observer_a.group_results.size() == 2);
  CHECK(w.observer_a.group_results[0].state == DeliveryState::Failed);
  CHECK(std::strcmp(w.observer_a.group_results[0].reason, "SLEEP_DRAIN") == 0);
  CHECK(w.observer_a.group_results[1].state == DeliveryState::Indeterminate);
  CHECK(std::strcmp(w.observer_a.group_results[1].reason, "SLEEP_DEFERRED") == 0);
}

void test_poll_delivery_callback_abort_stops_drain() {
  // A delivery callback fired by node_.poll() mid-drain can veto the sleep:
  // the same poll must not roll into finish_drain and reach READY_TO_SLEEP
  // with a live ticket (#110 review, GROUP_INCOMPLETE repro).
  MemoryPowerStorage storage;
  GroupPowerWorld w;
  w.converge();
  drop_all_reports();
  w.net.drop_frame = group_loss_hook;
  PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                               w.events);
  CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  GroupSendOptions options{};
  options.lifetime_ms = 300;  // expires mid-drain → GROUP_INCOMPLETE
  w.send_all(w.a, options);

  Status abort_status = Status::error(StatusCode::InternalError, "not run");
  w.observer_a.on_group_fn = [&](const GroupDeliveryResult& result) {
    if (abort_status.code == StatusCode::InternalError &&
        result.state == DeliveryState::Failed &&
        std::strcmp(result.reason, "GROUP_INCOMPLETE") == 0) {
      abort_status = coordinator.sleep_abort("APP_VETO");
    }
  };
  SleepRequest request{};
  request.pending_policy = SleepWorkPolicy::Fail;
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  CHECK(w.run_until(coordinator, w.b, PowerState::Running));
  CHECK(abort_status.ok());
  CHECK(!w.events.saw(PowerState::Persisting, PowerState::ReadyToSleep,
                      "SLEEP_READY"));
  CHECK(!coordinator.ticket().issued);
}

void test_settlement_callback_app_event_invalidates_ticket() {
  // App activity signalled inside a settlement callback must invalidate the
  // sleep exactly like late activity in READY_TO_SLEEP: no ticket is
  // issued and the attempt aborts to RUNNING (#110 review).
  MemoryPowerStorage storage;
  GroupPowerWorld w;
  w.converge();
  drop_all_reports();
  w.net.drop_frame = group_loss_hook;
  PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                               w.events);
  CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  GroupSendOptions options{};
  w.send_all(w.a, options);

  w.observer_a.on_group_fn = [&](const GroupDeliveryResult& result) {
    if (result.state == DeliveryState::Failed &&
        std::strcmp(result.reason, "SLEEP_DRAIN") == 0) {
      coordinator.notify_app_event();
    }
  };
  SleepRequest request{};
  request.pending_policy = SleepWorkPolicy::Fail;
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  CHECK(w.run_until(coordinator, w.b, PowerState::Running));
  CHECK(!w.events.saw(PowerState::Persisting, PowerState::ReadyToSleep,
                      "SLEEP_READY"));
  CHECK(!coordinator.ticket().issued);
  CHECK(w.events.has_diag("SLEEP_TICKET_INVALID"));
}

void test_ready_transition_callback_abort_not_overwritten() {
  // The SLEEP_READY transition notification is an app callback: the state is
  // already READY when it runs (post-state notification), an abort inside it
  // is accepted, and the same outer call then lands in RUNNING with the
  // ticket invalidated and no platform enter. ReadyToSleep→Running is the
  // honest history here — not a stale assignment (#110 review).
  MemoryPowerStorage storage;
  GroupPowerWorld w;
  w.converge();
  PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                               w.events);
  CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  Status abort_status = Status::error(StatusCode::InternalError, "not run");
  PowerState callback_state = PowerState::Running;
  w.events.on_transition_fn = [&](PowerState from, PowerState to,
                                  const char* reason) {
    if (from == PowerState::Persisting && to == PowerState::ReadyToSleep &&
        std::strcmp(reason, "SLEEP_READY") == 0 &&
        abort_status.code == StatusCode::InternalError) {
      callback_state = coordinator.state();
      abort_status = coordinator.sleep_abort("APP_VETO");
    }
  };
  SleepRequest request{};
  request.pending_policy = SleepWorkPolicy::Fail;
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  CHECK(w.run_until(coordinator, w.b, PowerState::Running));
  CHECK(callback_state == PowerState::ReadyToSleep);
  CHECK(abort_status.ok());
  CHECK(std::strcmp(abort_status.detail, "POWER_REQUEST_QUEUED") == 0);
  CHECK(coordinator.state() == PowerState::Running);
  CHECK(!coordinator.ticket().issued);
  CHECK(!coordinator.ticket_valid(coordinator.ticket()));
  CHECK(w.events.saw(PowerState::Persisting, PowerState::ReadyToSleep,
                     "SLEEP_READY"));
  CHECK(w.events.saw(PowerState::ReadyToSleep, PowerState::Running,
                     "SLEEP_ABORTED"));
  CHECK(w.port.sleep_calls == 0);
  // The explicit abort reason wins over the activity veto: no
  // SLEEP_TICKET_INVALID diagnostic for an explicit APP_VETO abort.
  CHECK(!w.events.has_diag("SLEEP_TICKET_INVALID"));
}

// Drives one group message to GROUP_REPAIR_PENDING with every report lost:
// round 0 can never resolve, so the source schedules a repair round.
MessageId drive_to_repair_pending(GroupPowerWorld& w) {
  w.converge();
  drop_all_reports();
  w.net.drop_frame = group_loss_hook;
  GroupSendOptions options{};
  const MessageId id = w.send_all(w.a, options);
  bool pending = false;
  for (int i = 0; i < 400 && !pending; ++i) {
    w.run(50);
    for (const auto& result : w.observer_a.group_results) {
      if (result.id == id && std::strcmp(result.reason, "GROUP_REPAIR_PENDING") == 0) {
        pending = true;
      }
    }
  }
  CHECK(pending);
  return id;
}

void test_group_repair_not_waited_by_drain() {
  // A scheduled repair is a retry round (kRetryRounds): the drain masks it
  // instead of waiting, and the unfinished origin settles under the sleep
  // policy. The control twin shows the same message completing once the
  // reports flow again (#110 R1-2: intended behavior, pinned here).
  {
    MemoryPowerStorage storage;
    GroupPowerWorld w;
    const MessageId id = drive_to_repair_pending(w);
    PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                                 w.events);
    CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                                 ElapsedInterval{0, 0, false}, w.now));
    SleepRequest request{};
    request.pending_policy = SleepWorkPolicy::Fail;
    CHECK_OK(coordinator.sleep_prepare(request, w.now));
    CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
    const auto result = w.a.group_delivery(id);
    CHECK(result.state == DeliveryState::Failed);
    CHECK(std::strcmp(result.reason, "SLEEP_DRAIN") == 0);
    CHECK(w.a.group_stats().repair_rounds == 0);
  }
  {
    GroupPowerWorld w;
    const MessageId id = drive_to_repair_pending(w);
    w.net.drop_frame = nullptr;  // reports flow again: the repair runs
    w.run(2000);
    const auto result = w.a.group_delivery(id);
    CHECK(result.state == DeliveryState::Delivered);
    CHECK(std::strcmp(result.reason, "GROUP_COMPLETE") == 0);
  }
}

void test_poll_unicast_callback_abort_stops_drain() {
  // Unicast leg of the GROUP_INCOMPLETE abort test: a normal expiry event
  // fired by node_.poll() mid-drain vetoes the sleep, and the same poll
  // must not roll into the settlement (#110 R2-2).
  MemoryPowerStorage storage;
  GroupPowerWorld w;
  w.converge();
  PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                               w.events);
  CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  const std::array<std::uint8_t, 3> payload{{'x', 'y', 'z'}};
  MessageId id{};
  SendOptions send_options{};
  send_options.lifetime_ms = 100;  // expires mid-drain, through node_.poll()
  CHECK_OK(w.a.send(9, ByteView{payload.data(), payload.size()},
                    send_options, w.now, id));

  Status abort_status = Status::error(StatusCode::InternalError, "not run");
  w.observer_a.on_delivery_fn = [&](const DeliveryResult& result) {
    if (abort_status.code == StatusCode::InternalError && result.id == id &&
        sleep_verdict_terminal(result.state)) {
      abort_status = coordinator.sleep_abort("APP_VETO");
    }
  };
  SleepRequest request{};
  request.pending_policy = SleepWorkPolicy::Fail;
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  bool aborted = false;
  for (int i = 0; i < 400 && !aborted; ++i) {
    coordinator.poll(w.now);
    w.b.poll(w.now);
    w.net.flush(w.now);
    w.now += 5;
    aborted = abort_status.code != StatusCode::InternalError &&
              coordinator.state() == PowerState::Running;
  }
  CHECK(aborted);
  CHECK(abort_status.ok());
  CHECK(!w.events.saw(PowerState::Persisting, PowerState::ReadyToSleep,
                      "SLEEP_READY"));
  CHECK(!coordinator.ticket().issued);
}

void test_unicast_settlement_callback_app_event_vetoes() {
  // Unicast leg of the settlement app-event veto: activity signalled from a
  // SLEEP_DRAIN on_delivery aborts before the ticket, with the
  // SLEEP_TICKET_INVALID diagnostic (#110 R2-3).
  MemoryPowerStorage storage;
  GroupPowerWorld w;
  w.converge();
  PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                               w.events);
  CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  const std::array<std::uint8_t, 3> payload{{'x', 'y', 'z'}};
  MessageId id{};
  SendOptions send_options{};
  CHECK_OK(w.a.send(9, ByteView{payload.data(), payload.size()},
                    send_options, w.now, id));

  bool vetoed = false;
  w.observer_a.on_delivery_fn = [&](const DeliveryResult& result) {
    if (result.state == DeliveryState::Failed &&
        std::strcmp(result.reason, "SLEEP_DRAIN") == 0) {
      vetoed = true;
      coordinator.notify_app_event();
    }
  };
  SleepRequest request{};
  request.pending_policy = SleepWorkPolicy::Fail;
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  CHECK(w.run_until(coordinator, w.b, PowerState::Running));
  CHECK(vetoed);
  CHECK(!w.events.saw(PowerState::Persisting, PowerState::ReadyToSleep,
                      "SLEEP_READY"));
  CHECK(!coordinator.ticket().issued);
  CHECK(w.events.has_diag("SLEEP_TICKET_INVALID"));
}

// Counts pending results for one logical id with one code.
std::size_t pending_results_for(const RecordingPowerEvents& events,
                                const MessageId& id, StatusCode code) {
  std::size_t count = 0;
  for (const auto& r : events.pending_results) {
    if (r.first == id && r.second == code) ++count;
  }
  return count;
}

void test_save_abort_fail_carries_only_settled() {
  // Save persists two non-durable unicasts; the first SLEEP_SAVED
  // notification aborts the attempt. Only the settled record is carried:
  // the unsettled one settles under the NEXT attempt's Fail policy (after
  // its commit), and a fresh node waking from the same storage re-injects
  // the carried record only — never the failed one (#110 R3-1). Two
  // variants: the retry is requested inside the aborting callback, or from
  // outside afterwards.
  for (int variant = 0; variant < 2; ++variant) {
    MemoryPowerStorage storage;
    GroupPowerWorld w;
    w.converge();
    PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                                 w.events);
    CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                                 ElapsedInterval{0, 0, false}, w.now));
    const std::array<std::uint8_t, 3> payload{{'a', 'b', 'c'}};
    MessageId id_a{}, id_b{};
    SendOptions send_options{};
    send_options.lifetime_ms = 20000;
    CHECK_OK(w.a.send(9, ByteView{payload.data(), payload.size()},
                      send_options, w.now, id_a));
    CHECK_OK(w.a.send(9, ByteView{payload.data(), payload.size()},
                      send_options, w.now, id_b));

    bool aborted = false;
    w.observer_a.on_delivery_fn = [&](const DeliveryResult& result) {
      if (aborted || result.state != DeliveryState::Indeterminate ||
          std::strcmp(result.reason, "SLEEP_SAVED") != 0) {
        return;  // act once, on the first settled record
      }
      aborted = true;
      CHECK_OK(coordinator.sleep_abort("APP_VETO"));
      if (variant == 0) {
        SleepRequest retry{};
        retry.pending_policy = SleepWorkPolicy::Fail;
        CHECK_OK(coordinator.sleep_prepare(retry, w.now));
      }
    };
    SleepRequest request{};
    request.pending_policy = SleepWorkPolicy::Save;
    CHECK_OK(coordinator.sleep_prepare(request, w.now));
    if (variant == 1) {
      CHECK(w.run_until(coordinator, w.b, PowerState::Running));
      SleepRequest retry{};
      retry.pending_policy = SleepWorkPolicy::Fail;
      CHECK_OK(coordinator.sleep_prepare(retry, w.now));
    }
    CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
    // A settled under Save; B failed under the Fail retry, after its own
    // commit — not under the stale Save candidate.
    CHECK(w.a.delivery(id_a).state == DeliveryState::Indeterminate);
    CHECK(std::strcmp(w.a.delivery(id_a).reason, "SLEEP_SAVED") == 0);
    CHECK(w.a.delivery(id_b).state == DeliveryState::Failed);
    CHECK(std::strcmp(w.a.delivery(id_b).reason, "SLEEP_DRAIN") == 0);
    CHECK_OK(coordinator.sleep_enter(coordinator.ticket(), w.now));

    // A fresh node on the same storage re-injects A — and only A.
    GroupPowerWorld fresh;
    FakePowerPort fresh_port;
    RecordingPowerEvents fresh_events;
    PowerCoordinator woken(PowerConfig{500, 50}, fresh.a, fresh_port, storage,
                           fresh_events);
    CHECK_OK(woken.begin(ResetCause::DeepSleepWake,
                         ElapsedInterval{100, 200, true}, fresh.now));
    CHECK(pending_results_for(fresh_events, id_a, StatusCode::Ok) == 1);
    CHECK(pending_results_for(fresh_events, id_b, StatusCode::Ok) == 0);
    CHECK(fresh_events.pending_results.size() == 1);

    // Slot hygiene: even when the newest slot is lost, the fallback slot
    // restores A only — the old Save candidate's B is gone from BOTH slots
    // (the retry dual-wrote its candidate).
    storage.corrupt(static_cast<std::uint8_t>(storage.last_slot), 10);
    GroupPowerWorld fallback;
    FakePowerPort fallback_port;
    RecordingPowerEvents fallback_events;
    PowerCoordinator woken2(PowerConfig{500, 50}, fallback.a, fallback_port,
                            storage, fallback_events);
    CHECK_OK(woken2.begin(ResetCause::DeepSleepWake,
                          ElapsedInterval{100, 200, true}, fallback.now));
    CHECK(pending_results_for(fallback_events, id_a, StatusCode::Ok) == 1);
    CHECK(pending_results_for(fallback_events, id_b, StatusCode::Ok) == 0);
  }
}

void test_save_abort_fail_durable_saved_again() {
  // Companion of the test above: when B is individually durable, the Fail
  // retry still saves it — an individual durable mark outranks the
  // fallback, so this is specified behavior, not a ghost re-injection.
  MemoryPowerStorage storage;
  GroupPowerWorld w;
  w.converge();
  PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                               w.events);
  CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  const std::array<std::uint8_t, 3> payload{{'a', 'b', 'c'}};
  MessageId id_a{}, id_b{};
  SendOptions plain{};
  plain.lifetime_ms = 20000;
  SendOptions durable = plain;
  durable.persist_across_sleep = true;
  CHECK_OK(
      w.a.send(9, ByteView{payload.data(), payload.size()}, plain, w.now, id_a));
  CHECK_OK(w.a.send(9, ByteView{payload.data(), payload.size()}, durable,
                    w.now, id_b));

  bool aborted = false;
  w.observer_a.on_delivery_fn = [&](const DeliveryResult& result) {
    if (aborted || result.state != DeliveryState::Indeterminate ||
        std::strcmp(result.reason, "SLEEP_SAVED") != 0) {
      return;
    }
    aborted = true;
    CHECK_OK(coordinator.sleep_abort("APP_VETO"));
  };
  SleepRequest request{};
  request.pending_policy = SleepWorkPolicy::Save;
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  CHECK(w.run_until(coordinator, w.b, PowerState::Running));
  SleepRequest retry{};
  retry.pending_policy = SleepWorkPolicy::Fail;
  CHECK_OK(coordinator.sleep_prepare(retry, w.now));
  CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
  CHECK(std::strcmp(w.a.delivery(id_a).reason, "SLEEP_SAVED") == 0);
  CHECK(w.a.delivery(id_b).state == DeliveryState::Indeterminate);
  CHECK(std::strcmp(w.a.delivery(id_b).reason, "SLEEP_SAVED") == 0);
  CHECK_OK(coordinator.sleep_enter(coordinator.ticket(), w.now));

  GroupPowerWorld fresh;
  FakePowerPort fresh_port;
  RecordingPowerEvents fresh_events;
  PowerCoordinator woken(PowerConfig{500, 50}, fresh.a, fresh_port, storage,
                         fresh_events);
  CHECK_OK(woken.begin(ResetCause::DeepSleepWake,
                       ElapsedInterval{100, 200, true}, fresh.now));
  CHECK(pending_results_for(fresh_events, id_a, StatusCode::Ok) == 1);
  CHECK(pending_results_for(fresh_events, id_b, StatusCode::Ok) == 1);
}

struct ServiceSinkDouble final : GatewayServiceSink {
  void on_service_payload(NodeId, const wire::PlainFrame&,
                          MonotonicMs) noexcept override {}
  void on_service_job_done(const MessageId& id, bool hop_accepted,
                           const char* reason,
                           MonotonicMs) noexcept override {
    ++calls;
    last_id = id;
    last_ok = hop_accepted;
    last_reason = reason;
  }
  void poll(MonotonicMs) noexcept override {}

  int calls{0};
  MessageId last_id{};
  bool last_ok{false};
  const char* last_reason{""};
};

void test_tx_notice_abort_keeps_queues() {
  // A service job is stuck in physical TX at the drain deadline. The
  // SLEEP_TX_INFLIGHT diagnostic fires; its callback aborts and sends. The
  // send is refused (draining), and the safe point after the notice aborts
  // WITHOUT the blanket clear, radio quiesce or ticket: the job survives
  // with its id and completes normally after RUNNING (#110 R3-2).
  MemoryPowerStorage storage;
  GroupPowerWorld w;
  w.converge();
  ServiceSinkDouble sink;
  w.a.set_gateway_sink(&sink);
  PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                               w.events);
  CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  const std::array<std::uint8_t, 3> payload{{'s', 'v', 'c'}};
  MessageId service_id{};
  CHECK_OK(w.a.send_service(GroupPowerWorld::kLeaf,
                            ByteView{payload.data(), payload.size()}, 30000,
                            w.now, service_id));
  w.a.poll(w.now);  // dispatch into physical; no flush, so no TX result
  CHECK(!w.a.quiesced());

  Status abort_status = Status::error(StatusCode::InternalError, "not run");
  Status send_status = Status::error(StatusCode::InternalError, "not run");
  PowerState callback_state = PowerState::Running;
  bool noticed = false;
  w.observer_a.on_diag_fn = [&](const char* reason, NodeId,
                                const MessageId*) {
    if (std::strcmp(reason, "SLEEP_TX_INFLIGHT") != 0 ||
        abort_status.code != StatusCode::InternalError) {
      return;
    }
    noticed = true;
    callback_state = coordinator.state();
    abort_status = coordinator.sleep_abort("APP_VETO");
    MessageId retry{};
    SendOptions send_options{};
    send_status = w.a.send(GroupPowerWorld::kLeaf,
                           ByteView{payload.data(), payload.size()},
                           send_options, w.now, retry);
  };
  SleepRequest request{};
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  // Drive WITHOUT flushing the network: the physical TX result never lands
  // until the abort is over.
  bool aborted = false;
  for (int i = 0; i < 400 && !aborted; ++i) {
    coordinator.poll(w.now);
    w.b.poll(w.now);
    w.now += 5;
    aborted = abort_status.code != StatusCode::InternalError &&
              coordinator.state() == PowerState::Running;
  }
  CHECK(noticed);
  CHECK(aborted);
  CHECK(callback_state == PowerState::Persisting);
  CHECK(abort_status.ok());
  CHECK(!send_status.ok());
  CHECK(std::strcmp(send_status.detail, "NODE_DRAINING") == 0);
  CHECK(!w.events.saw(PowerState::Persisting, PowerState::ReadyToSleep,
                      "SLEEP_READY"));
  CHECK(!coordinator.ticket().issued);
  CHECK(w.port.quiesce_calls == 0);  // never reached radio quiesce
  // The job was never cleared: its TX result resolves normally (no
  // STALE_TX_CALLBACK) and the exchange completes under its own id.
  for (int i = 0; i < 200 && sink.calls == 0; ++i) {
    w.a.poll(w.now);
    w.b.poll(w.now);
    w.net.flush(w.now);
    w.now += 5;
  }
  CHECK(sink.calls == 1);
  CHECK(sink.last_ok);
  CHECK(sink.last_id == service_id);
  CHECK(!w.observer_a.has_diag("STALE_TX_CALLBACK"));
}

void test_sleep_hold_release_abort_keeps_rest() {
  // ORDERED seq 2 is lost; seq 3 AND 4 are held. The sleep release hands seq
  // 3 to the app and its callback aborts: the same outer call stops there —
  // {1, 3} delivered, one hold left, cursor at 4, the seq-2 gap counted
  // once, no callback for 4 yet. A later attempt delivers 4 exactly once
  // (#110 R3-3: one message per release, no trailing drain).
  MemoryPowerStorage storage;
  GroupPowerWorld w;
  w.converge();
  GroupSendOptions options{};
  options.ordered = true;
  options.lifetime_ms = 10000;
  const MessageId first = w.send_all(w.a, options);  // seq 1
  for (int i = 0; i < 200 &&
                  w.a.group_delivery(first).state != DeliveryState::Delivered;
       ++i) {
    w.run(50);  // seq 1 completes, freeing its origin slot for seq 4
  }
  CHECK(w.a.group_delivery(first).state == DeliveryState::Delivered);
  g_drop_type = FrameType::GroupData;
  g_drop_to = GroupPowerWorld::kLeaf;
  g_drop_sequence = kGroupSequenceFlag | 2;
  w.net.drop_frame = group_loss_hook;
  w.send_all(w.a, options);  // seq 2: lost toward the leaf
  w.send_all(w.a, options);  // seq 3: held
  GroupSendOptions urgent = options;
  urgent.priority = Priority::Urgent;  // may take the last origin slot
  w.send_all(w.a, urgent);   // seq 4: held
  w.run(200);
  CHECK(w.observer_b.group_messages.size() == 1);
  CHECK(w.b.group_holds_in_use() == 2);

  PowerCoordinator coordinator(PowerConfig{500, 50}, w.b, w.port, storage,
                               w.events);
  CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  Status abort_status = Status::error(StatusCode::InternalError, "not run");
  w.observer_b.on_group_message_fn = [&](const GroupMessageInfo& info,
                                         ByteView) {
    if (abort_status.code == StatusCode::InternalError &&
        info.group_seq == 3) {
      abort_status = coordinator.sleep_abort("APP_VETO");
    }
  };
  SleepRequest request{};
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  bool aborted = false;
  for (int i = 0; i < 400 && !aborted; ++i) {
    coordinator.poll(w.now);
    w.a.poll(w.now);
    w.net.flush(w.now);
    w.now += 5;
    aborted = abort_status.code != StatusCode::InternalError &&
              coordinator.state() == PowerState::Running;
  }
  CHECK(aborted);
  CHECK(abort_status.ok());
  // The aborting outer call released exactly one message.
  CHECK(w.observer_b.group_messages.size() == 2);
  if (w.observer_b.group_messages.size() == 2) {
    CHECK(w.observer_b.group_messages[0].info.group_seq == 1);
    CHECK(w.observer_b.group_messages[1].info.group_seq == 3);
    CHECK(!w.observer_b.group_messages[1].info.late);
  }
  CHECK(w.b.group_holds_in_use() == 1);
  std::uint32_t next_seq = 0;
  w.b.for_each_group_stream([&](const GroupStreamSnapshot& stream) {
    if (stream.source == GroupPowerWorld::kGateway) next_seq = stream.next_seq;
  });
  CHECK(next_seq == 4);
  CHECK(w.b.group_stats().gaps_skipped == 1);
  // A later attempt delivers the kept hold exactly once.
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  CHECK(w.run_until(coordinator, w.a, PowerState::ReadyToSleep));
  CHECK(w.b.group_holds_in_use() == 0);
  CHECK(w.observer_b.group_messages.size() == 3);
  if (w.observer_b.group_messages.size() == 3) {
    CHECK(w.observer_b.group_messages[2].info.group_seq == 4);
    CHECK(!w.observer_b.group_messages[2].info.late);
  }
  CHECK(w.b.group_stats().gaps_skipped == 1);
}

// Three-node rig for the multi-stream sleep-hold test: gateways 1 and 2
// source group traffic, leaf 3 (chained behind 2) receives from both.
struct TwoSourceWorld {
  static constexpr NodeId kGw1 = 1;
  static constexpr NodeId kGw2 = 2;
  static constexpr NodeId kLeaf = 3;

  SimNetwork net;
  TestSecurity s1;
  TestSecurity s2;
  TestSecurity s3;
  HookedObserver o1;
  HookedObserver o2;
  HookedObserver o3;
  SimRadio r1;
  SimRadio r2;
  SimRadio r3;
  MeshNode n1;
  MeshNode n2;
  MeshNode n3;
  FakePowerPort port;
  RecordingPowerEvents events;
  MonotonicMs now{0};

  TwoSourceWorld()
      : r1(net, kGw1),
        r2(net, kGw2),
        r3(net, kLeaf),
        n1(config(kGw1), r1, s1, o1),
        n2(config(kGw2), r2, s2, o2),
        n3(config(kLeaf), r3, s3, o3) {
    net.register_node(kGw1, &n1);
    net.register_node(kGw2, &n2);
    net.register_node(kLeaf, &n3);
    net.connect(kGw1, kGw2);
    net.connect(kGw2, kLeaf);
  }

  static NodeConfig config(const NodeId id) {
    NodeConfig config{};
    config.network = 1;
    config.node = id;
    config.message_session = 100 + static_cast<std::uint32_t>(id);
    config.route_gateways = {kGw1, kGw2};
    config.route_advertisement_period_ms = 500;
    config.route_lifetime_ms = 9000;
    config.route_refresh_ticks = kScopedDefaultRefreshTicks;
    return config;
  }

  void run(MonotonicMs duration) {
    const MonotonicMs end = now + duration;
    for (; now <= end; now += 5) {
      n1.poll(now);
      n2.poll(now);
      n3.poll(now);
      net.flush(now);
    }
  }

  bool run_until(PowerCoordinator& coordinator, PowerState target,
                 int max_iterations = 400) {
    for (int i = 0; i < max_iterations && coordinator.state() != target; ++i) {
      coordinator.poll(now);
      n1.poll(now);
      n2.poll(now);
      net.flush(now);
      now += 5;
    }
    return coordinator.state() == target;
  }

  void converge() {
    CHECK_OK(n1.start(now));
    CHECK_OK(n2.start(now));
    CHECK_OK(n3.start(now));
    CHECK_OK(n1.add_neighbor(kGw2, 1, now));
    CHECK_OK(n2.add_neighbor(kGw1, 1, now));
    CHECK_OK(n2.add_neighbor(kLeaf, 1, now));
    CHECK_OK(n3.add_neighbor(kGw2, 1, now));
    for (int i = 0; i < 400 && !n2.scoped_child(kLeaf); ++i) run(50);
    CHECK(n2.scoped_child(kLeaf));
  }

  MessageId send_all(MeshNode& source, const GroupSendOptions& options) {
    const std::array<std::uint8_t, 3> payload{{'g', 'o', '!'}};
    MessageId id{};
    CHECK_OK(source.send_group(kGroupAll,
                               ByteView{payload.data(), payload.size()},
                               options, now, id));
    return id;
  }
};

void test_sleep_hold_release_abort_multi_stream() {
  // Two sources, one sleeper: the leaf holds one ORDERED message per stream
  // (both seq 3, both missing seq 2). The first release takes the lowest
  // (seq, source) — source 1 — and its callback aborts: the other stream's
  // hold and cursor stay untouched, and a later attempt delivers it (#110
  // R3-3, stable cross-stream order).
  MemoryPowerStorage storage;
  TwoSourceWorld w;
  w.converge();
  GroupSendOptions options{};
  options.ordered = true;
  options.lifetime_ms = 10000;
  w.send_all(w.n1, options);
  w.send_all(w.n2, options);
  w.run(400);
  CHECK(w.o3.group_messages.size() == 2);
  g_drop_type = FrameType::GroupData;
  g_drop_to = TwoSourceWorld::kLeaf;
  g_drop_sequence = kGroupSequenceFlag | 2;
  w.net.drop_frame = group_loss_hook;
  w.send_all(w.n1, options);  // src1 seq 2: lost toward the leaf
  w.send_all(w.n2, options);  // src2 seq 2: lost toward the leaf
  GroupSendOptions urgent = options;
  urgent.priority = Priority::Urgent;  // bypasses the one-round-0 gate so the
                                       // held messages overtake the repair loop
  w.send_all(w.n1, urgent);  // src1 seq 3: held
  w.send_all(w.n2, urgent);  // src2 seq 3: held
  for (int i = 0; i < 100 && w.n3.group_holds_in_use() != 2; ++i) {
    w.run(100);
  }
  CHECK(w.n3.group_holds_in_use() == 2);

  PowerCoordinator coordinator(PowerConfig{500, 50}, w.n3, w.port, storage,
                               w.events);
  CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  Status abort_status = Status::error(StatusCode::InternalError, "not run");
  w.o3.on_group_message_fn = [&](const GroupMessageInfo& info, ByteView) {
    if (abort_status.code == StatusCode::InternalError) {
      abort_status = coordinator.sleep_abort("APP_VETO");
    }
    (void)info;
  };
  SleepRequest request{};
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  bool aborted = false;
  for (int i = 0; i < 400 && !aborted; ++i) {
    coordinator.poll(w.now);
    w.n1.poll(w.now);
    w.n2.poll(w.now);
    w.net.flush(w.now);
    w.now += 5;
    aborted = abort_status.code != StatusCode::InternalError &&
              coordinator.state() == PowerState::Running;
  }
  CHECK(aborted);
  CHECK(abort_status.ok());
  // Exactly one release happened, from the lowest (seq, source) stream.
  CHECK(w.o3.group_messages.size() == 3);
  if (w.o3.group_messages.size() == 3) {
    CHECK(w.o3.group_messages[2].info.key.origin == TwoSourceWorld::kGw1);
    CHECK(w.o3.group_messages[2].info.group_seq == 3);
  }
  CHECK(w.n3.group_holds_in_use() == 1);
  std::uint32_t next1 = 0;
  std::uint32_t next2 = 0;
  w.n3.for_each_group_stream([&](const GroupStreamSnapshot& stream) {
    if (stream.source == TwoSourceWorld::kGw1) next1 = stream.next_seq;
    if (stream.source == TwoSourceWorld::kGw2) next2 = stream.next_seq;
  });
  CHECK(next1 == 4);
  CHECK(next2 == 2);  // untouched stream keeps its cursor
  // A later attempt delivers the kept hold exactly once.
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  CHECK(w.run_until(coordinator, PowerState::ReadyToSleep));
  CHECK(w.n3.group_holds_in_use() == 0);
  CHECK(w.o3.group_messages.size() == 4);
  if (w.o3.group_messages.size() == 4) {
    CHECK(w.o3.group_messages[3].info.key.origin == TwoSourceWorld::kGw2);
    CHECK(w.o3.group_messages[3].info.group_seq == 3);
  }
}

void test_carry_expired_callback_app_event_vetoes() {
  // A retained record expires while awake. At the next sleep its Expired
  // result is notified AFTER the phase-1 commit; activity signalled from
  // that callback vetoes the attempt before any ticket, and the consumed
  // Expired is never re-notified nor re-injected (#110 R3-4).
  MemoryPowerStorage storage;
  {
    PowerWorld w(storage);
    w.platform_peer(2, 0xaa);
    CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                                 ElapsedInterval{0, 0, false}, w.now));
    w.pump(60);
    (void)queue_pending(w, 2, true, 5000);
    SleepRequest request{};
    CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
    CHECK(w.pump_until(PowerState::ReadyToSleep));
    CHECK_OK(w.coordinator.sleep_enter(w.coordinator.ticket(), w.now));
  }
  {
    PowerWorld w(storage);
    w.platform_peer(2, 0xaa);
    CHECK_OK(w.node.start(w.now));
    for (std::size_t i = 0; i < MeshNode::delivery_capacity(); ++i) {
      (void)queue_pending(w, static_cast<NodeId>(90 + i), false);
    }
    CHECK_OK(w.coordinator.begin(ResetCause::DeepSleepWake,
                                 ElapsedInterval{0, 0, true}, w.now));
    CHECK(w.events.pending_with(StatusCode::AlreadyExists) == 1);
    w.pump(60);
    w.now += 5000;  // stay awake past the retained record's remaining budget
    const std::size_t writes_before_prepare = storage.write_calls;
    std::size_t writes_at_notify = 0;
    bool vetoed = false;
    w.events.on_pending_result_fn = [&](const PendingDeliveryRecord&,
                                        StatusCode code) {
      if (code == StatusCode::Expired && !vetoed) {
        vetoed = true;
        writes_at_notify = storage.write_calls;
        w.coordinator.notify_app_event();
      }
    };
    SleepRequest request{};
    CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
    CHECK(w.pump_until(PowerState::Running));
    CHECK(vetoed);
    // The notification moved past the commit: the image landed first.
    CHECK(writes_at_notify > writes_before_prepare);
    CHECK(!w.events.saw(PowerState::Persisting, PowerState::ReadyToSleep,
                        "SLEEP_READY"));
    CHECK(!w.coordinator.ticket().issued);
    CHECK(w.events.has_diag("SLEEP_TICKET_INVALID"));
    // The consumed Expired is gone for good: no duplicate, no re-injection.
    w.events.on_pending_result_fn = nullptr;
    CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
    CHECK(w.pump_until(PowerState::ReadyToSleep));
    CHECK(w.events.pending_with(StatusCode::Expired) == 1);
    CHECK_OK(w.coordinator.sleep_enter(w.coordinator.ticket(), w.now));
    CHECK_OK(w.coordinator.wake(ResetCause::DeepSleepWake,
                                ElapsedInterval{0, 0, true}, w.now));
    CHECK(w.events.pending_with(StatusCode::Ok) == 0);
  }
}

void test_enter_expired_callback_app_event_vetoes() {
  // A durable pending expires while its ticket waits. sleep_enter refreshes
  // and commits first, then notifies Expired; activity from that callback
  // vetoes the entry — the platform handoff never runs — and the consumed
  // record is never re-injected (#110 R3-5).
  MemoryPowerStorage storage;
  PowerWorld w(storage);
  w.platform_peer(2, 0xaa);
  CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  w.pump(60);
  (void)queue_pending(w, 2, true, 5000);
  SleepRequest request{};
  CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
  CHECK(w.pump_until(PowerState::ReadyToSleep));
  const SleepTicket ticket = w.coordinator.ticket();
  w.now += 10010;  // hold the ticket past the pending's 5000 ms lifetime
  const std::size_t writes_before_enter = storage.write_calls;
  bool vetoed = false;
  w.events.on_pending_result_fn = [&](const PendingDeliveryRecord&,
                                      StatusCode code) {
    if (code == StatusCode::Expired && !vetoed) {
      vetoed = true;
      w.coordinator.notify_app_event();
    }
  };
  CHECK(w.coordinator.sleep_enter(ticket, w.now).code ==
        StatusCode::InvalidState);
  CHECK(vetoed);
  // The refresh landed before the vetoing notification (dual slot update).
  CHECK(storage.write_calls == writes_before_enter + 2);
  CHECK(w.coordinator.state() == PowerState::Running);
  CHECK(!w.coordinator.ticket_valid(ticket));
  CHECK(w.port.wakecfg_calls == 0);
  CHECK(w.port.sleep_calls == 0);
  CHECK(w.events.pending_with(StatusCode::Expired) == 1);
  // The consumed record stays gone: a clean retry re-injects nothing.
  w.events.on_pending_result_fn = nullptr;
  CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
  CHECK(w.pump_until(PowerState::ReadyToSleep));
  CHECK_OK(w.coordinator.sleep_enter(w.coordinator.ticket(), w.now));
  CHECK_OK(w.coordinator.wake(ResetCause::DeepSleepWake,
                              ElapsedInterval{0, 0, true}, w.now));
  CHECK(w.events.pending_with(StatusCode::Ok) == 0);
  CHECK(w.events.pending_with(StatusCode::Expired) == 1);
}

// --- Section 9.3: callback x operation contract matrix -----------------------
// The model below is transcribed from the design text (deferred-request
// rules): the test drives the REAL coordinator through every op sequence of
// length 1..3 in five lifecycle states and compares each op result plus the
// settled end state against the model. Mesh tests elsewhere assert the same
// rules end-to-end; this one proves them exhaustively.

enum class ModelOp : std::uint8_t {
  Abort = 0,
  Prepare,
  AppEvent,
  Send,
  SendGroup,
  Enter,
};

enum class ModelState : std::uint8_t {
  Running = 0,
  Draining,
  Persisting,
  Ready,
  Entering,
};

struct ModelBox {
  bool abort{false};
  bool app{false};
  bool prepare{false};
  bool enter{false};
  std::uint64_t seq{0};
  std::uint64_t abort_seq{0};
  std::uint64_t prepare_seq{0};
  bool ticket_broken{false};  // a send bumped the work generation
};

bool model_active(ModelState state) {
  return state == ModelState::Draining || state == ModelState::Persisting ||
         state == ModelState::Ready || state == ModelState::Entering;
}

bool model_draining(ModelState state) { return model_active(state); }

struct ModelOpResult {
  bool has_result{false};  // app_event is void
  StatusCode code{StatusCode::Ok};
  const char* detail{""};
};

ModelOpResult model_apply(ModelBox& box, ModelState state, ModelOp op) {
  switch (op) {
    case ModelOp::Abort:
      if (model_active(state) || box.prepare) {
        box.abort = true;
        box.abort_seq = ++box.seq;  // last-wins
        return {true, StatusCode::Ok, "POWER_REQUEST_QUEUED"};
      }
      return {true, StatusCode::InvalidState, "no sleep in progress"};
    case ModelOp::Prepare:
      if (box.app) {
        return {true, StatusCode::Busy, "POWER_ACTIVITY_PENDING"};
      }
      if (box.prepare) {
        return {true, StatusCode::Busy, "POWER_REQUEST_PENDING"};
      }
      if (state != ModelState::Running &&
          !(box.abort && model_active(state))) {
        return {true, StatusCode::InvalidState, "not running"};
      }
      box.prepare = true;
      box.prepare_seq = ++box.seq;
      return {true, StatusCode::Ok, "POWER_REQUEST_QUEUED"};
    case ModelOp::AppEvent:
      box.app = true;
      return {false, StatusCode::Ok, ""};
    case ModelOp::Send:
      box.ticket_broken = true;
      if (model_draining(state)) {
        return {true, StatusCode::InvalidState, "NODE_DRAINING"};
      }
      return {true, StatusCode::Ok, "ok"};
    case ModelOp::SendGroup:
      box.ticket_broken = true;
      if (model_draining(state)) {
        return {true, StatusCode::InvalidState, "NODE_DRAINING"};
      }
      // The matrix rig is flat-profiled: outside the drain the gateway
      // check (not the pause) rejects group sends.
      return {true, StatusCode::Unsupported,
              "GROUP_REQUIRES_GATEWAY_SCOPED"};
    case ModelOp::Enter:
      if (box.enter || state == ModelState::Entering) {
        return {true, StatusCode::Busy, "SLEEP_ENTER_IN_PROGRESS"};
      }
      if (state != ModelState::Ready) {
        return {true, StatusCode::InvalidState, "not ready to sleep"};
      }
      if (box.abort || box.app || box.ticket_broken) {
        return {true, StatusCode::InvalidState, "SLEEP_TICKET_INVALID"};
      }
      box.enter = true;
      return {true, StatusCode::Ok, "POWER_REQUEST_QUEUED"};
  }
  return {true, StatusCode::InternalError, "unreachable"};
}

PowerState model_end_state(ModelState state, const ModelBox& box) {
  const bool veto = box.abort || box.app;
  const bool prepare_survives =
      box.prepare && !box.app &&
      !(box.abort && box.prepare_seq < box.abort_seq);
  const bool enter_survives = box.enter && !veto;
  // Counter-only veto (no latch): a refused send during the READY wait or
  // the SLEEP_ENTER handoff breaks the issued ticket's generation.
  const bool counter_veto =
      box.ticket_broken &&
      (state == ModelState::Ready || state == ModelState::Entering);
  if (state == ModelState::Entering) {
    return (veto || counter_veto) ? PowerState::Running : PowerState::Sleeping;
  }
  if (prepare_survives) return PowerState::ReadyToSleep;  // next attempt runs
  if (enter_survives) {
    return counter_veto ? PowerState::Running : PowerState::Sleeping;
  }
  if (veto || counter_veto) return PowerState::Running;
  switch (state) {
    case ModelState::Running:
      return PowerState::Running;
    case ModelState::Draining:
    case ModelState::Persisting:
    case ModelState::Ready:
      return PowerState::ReadyToSleep;
    case ModelState::Entering:
      break;
  }
  return PowerState::Running;  // unreachable
}

// Flat-profiled single-node world with hookable observers for the matrix.
struct MatrixWorld {
  MemoryPowerStorage storage;
  TestSecurity security;
  HookedObserver observer;
  SimNetwork net;
  SimRadio radio;
  FakePowerPort port;
  RecordingPowerEvents events;
  MeshNode node;
  PowerCoordinator coordinator;
  MonotonicMs now{0};

  MatrixWorld()
      : radio(net, 7), node(make_config(), radio, security, observer),
        coordinator(PowerConfig{500, 50}, node, port, storage, events) {}

  static NodeConfig make_config() {
    NodeConfig config{};
    config.network = 1;
    config.node = 7;
    config.message_session = 500;
    config.route_advertisement_period_ms = 100000;
    config.route_lifetime_ms = 200000;
    return config;
  }

  void pump(MonotonicMs duration, MonotonicMs step = 5) {
    const MonotonicMs end = now + duration;
    for (; now <= end; now += step) {
      coordinator.poll(now);
      net.flush(now);
    }
  }

  bool pump_until(PowerState target, int max_iterations = 400) {
    for (int i = 0; i < max_iterations && coordinator.state() != target; ++i) {
      coordinator.poll(now);
      net.flush(now);
      now += 5;
    }
    return coordinator.state() == target;
  }
};

void test_callback_operation_matrix_model() {
  // All 6 + 36 + 216 op sequences in five lifecycle states. Each scenario:
  // fresh world, hook runs the sequence inside ONE callback, then compare
  // per-op results, in-callback state freeze, and the settled end state.
  const ModelOp ops[] = {ModelOp::Abort,  ModelOp::Prepare, ModelOp::AppEvent,
                         ModelOp::Send,   ModelOp::SendGroup, ModelOp::Enter};
  const ModelState states[] = {
      ModelState::Running, ModelState::Draining, ModelState::Persisting,
      ModelState::Ready, ModelState::Entering};
  const std::array<std::uint8_t, 3> payload{{'m', 'a', 't'}};
  std::size_t scenarios = 0;
  for (const ModelState state : states) {
    for (std::size_t len = 1; len <= 3; ++len) {
      const std::size_t count =
          len == 1 ? 6 : (len == 2 ? 36 : 216);
      for (std::size_t n = 0; n < count; ++n) {
        std::array<ModelOp, 3> sequence{};
        std::size_t rest = n;
        for (std::size_t i = 0; i < len; ++i) {
          sequence[i] = ops[rest % 6];
          rest /= 6;
        }
        MatrixWorld w;
        CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                                     ElapsedInterval{0, 0, false}, w.now));
        w.pump(60);
        // Scenario hook: runs the sequence exactly once, inside the
        // lifecycle callback for `state`.
        int hook_runs = 0;
        SleepTicket captured{};
        PowerState frozen = PowerState::Running;
        bool frozen_draining = false;
        std::vector<ModelOpResult> got;
        auto run_sequence = [&]() {
          if (hook_runs > 0) return;  // once: ignore nested notifications
          ++hook_runs;
          captured = w.coordinator.ticket();
          frozen = w.coordinator.state();
          frozen_draining = w.node.draining();
          for (std::size_t i = 0; i < len; ++i) {
            switch (sequence[i]) {
              case ModelOp::Abort: {
                const Status s = w.coordinator.sleep_abort("MODEL");
                got.push_back({true, s.code, s.detail});
                break;
              }
              case ModelOp::Prepare: {
                SleepRequest request{};
                const Status s = w.coordinator.sleep_prepare(request, w.now);
                got.push_back({true, s.code, s.detail});
                break;
              }
              case ModelOp::AppEvent:
                w.coordinator.notify_app_event();
                got.push_back({false, StatusCode::Ok, ""});
                break;
              case ModelOp::Send: {
                MessageId id{};
                SendOptions send_options{};
                const Status s =
                    w.node.send(9, ByteView{payload.data(), payload.size()},
                                send_options, w.now, id);
                got.push_back({true, s.code, s.detail});
                break;
              }
              case ModelOp::SendGroup: {
                MessageId id{};
                GroupSendOptions group_options{};
                const Status s = w.node.send_group(
                    kGroupAll, ByteView{payload.data(), payload.size()},
                    group_options, w.now, id);
                got.push_back({true, s.code, s.detail});
                break;
              }
              case ModelOp::Enter: {
                const Status s = w.coordinator.sleep_enter(captured, w.now);
                got.push_back({true, s.code, s.detail});
                break;
              }
            }
          }
        };
        switch (state) {
          case ModelState::Running: {
            MessageId id{};
            SendOptions send_options{};
            send_options.lifetime_ms = 5;  // expires on the next poll
            CHECK_OK(w.node.send(9, ByteView{payload.data(), payload.size()},
                                 send_options, w.now, id));
            w.observer.on_delivery_fn = [&, id](const DeliveryResult& result) {
              if (result.id == id && sleep_verdict_terminal(result.state)) {
                run_sequence();
              }
            };
            for (int i = 0; i < 100 && hook_runs == 0; ++i) {
              w.coordinator.poll(w.now);
              w.net.flush(w.now);
              w.now += 5;
            }
            break;
          }
          case ModelState::Draining: {
            MessageId id{};
            SendOptions send_options{};
            send_options.lifetime_ms = 5;
            CHECK_OK(w.node.send(9, ByteView{payload.data(), payload.size()},
                                 send_options, w.now, id));
            // Past the lifetime already: the first drain poll expires the
            // delivery inside node_.poll() instead of settling it.
            w.now += 10;
            SleepRequest request{};
            CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
            w.observer.on_delivery_fn = [&, id](const DeliveryResult& result) {
              if (result.id == id && sleep_verdict_terminal(result.state)) {
                run_sequence();
              }
            };
            for (int i = 0; i < 100 && hook_runs == 0; ++i) {
              w.coordinator.poll(w.now);
              w.net.flush(w.now);
              w.now += 5;
            }
            break;
          }
          case ModelState::Persisting: {
            MessageId id{};
            SendOptions send_options{};
            send_options.lifetime_ms = 5000;
            CHECK_OK(w.node.send(9, ByteView{payload.data(), payload.size()},
                                 send_options, w.now, id));
            SleepRequest request{};
            CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
            w.observer.on_delivery_fn = [&](const DeliveryResult& result) {
              if (result.state == DeliveryState::Failed &&
                  std::strcmp(result.reason, "SLEEP_DRAIN") == 0) {
                run_sequence();
              }
            };
            for (int i = 0; i < 200 && hook_runs == 0; ++i) {
              w.coordinator.poll(w.now);
              w.net.flush(w.now);
              w.now += 5;
            }
            break;
          }
          case ModelState::Ready: {
            SleepRequest request{};
            CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
            w.events.on_transition_fn = [&](PowerState from, PowerState to,
                                            const char* reason) {
              if (from == PowerState::Persisting &&
                  to == PowerState::ReadyToSleep &&
                  std::strcmp(reason, "SLEEP_READY") == 0) {
                run_sequence();
              }
            };
            for (int i = 0; i < 200 && hook_runs == 0; ++i) {
              w.coordinator.poll(w.now);
              w.net.flush(w.now);
              w.now += 5;
            }
            w.events.on_transition_fn = nullptr;
            break;
          }
          case ModelState::Entering: {
            SleepRequest request{};
            CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
            CHECK(w.pump_until(PowerState::ReadyToSleep));
            const SleepTicket ticket = w.coordinator.ticket();
            w.events.on_transition_fn = [&](PowerState from, PowerState to,
                                            const char* reason) {
              if (to == PowerState::Sleeping &&
                  std::strcmp(reason, "SLEEP_ENTER") == 0) {
                (void)from;
                run_sequence();
              }
            };
            (void)w.coordinator.sleep_enter(ticket, w.now);
            w.events.on_transition_fn = nullptr;
            break;
          }
        }
        if (hook_runs != 1) {
          CHECK(hook_runs == 1);  // setup must fire the hook exactly once
          continue;
        }
        // Compare against the model transcribed from the design text.
        ModelBox box;
        for (std::size_t i = 0; i < len; ++i) {
          const ModelOpResult want = model_apply(box, state, sequence[i]);
          const ModelOpResult& actual = got[i];
          if (want.has_result != actual.has_result ||
              (want.has_result &&
               (want.code != actual.code ||
                std::strcmp(want.detail, actual.detail) != 0))) {
            std::fprintf(stderr,
                         "matrix mismatch: state=%d len=%zu n=%zu op=%zu "
                         "want=(%d,'%s') got=(%d,'%s')\n",
                         static_cast<int>(state), len, n, i,
                         static_cast<int>(want.code), want.detail,
                         static_cast<int>(actual.code), actual.detail);
            CHECK(want.code == actual.code);
            CHECK(std::strcmp(want.detail, actual.detail) == 0);
          }
        }
        // The callback never moves the machine synchronously.
        {
          const PowerState want_state =
              state == ModelState::Entering ? PowerState::Sleeping
              : state == ModelState::Ready ? PowerState::ReadyToSleep
              : state == ModelState::Persisting ? PowerState::Persisting
              : state == ModelState::Draining   ? PowerState::Draining
                                                : PowerState::Running;
          if (frozen != want_state) {
            std::fprintf(stderr,
                         "matrix frozen mismatch: state=%d len=%zu n=%zu "
                         "frozen=%d want=%d\n",
                         static_cast<int>(state), len, n,
                         static_cast<int>(frozen), static_cast<int>(want_state));
          }
          CHECK(frozen == want_state);
          CHECK(frozen_draining == model_draining(state));
        }
        // The settled end state matches the model too.
        const PowerState want_end = model_end_state(state, box);
        CHECK(w.pump_until(want_end, 200));
        ++scenarios;
      }
    }
  }
  CHECK(scenarios == 5 * (6 + 36 + 216));
}

// --- Section 9.3 (families): one op per remaining callback family ------------
// The matrix above covers on_delivery/on_transition exhaustively; the tables
// here pin every other family (single ops) at representative points:
// group delivery/message, pending_result, TX notice, normal message, power
// diagnostic, applied result, the applied extended sink, and the restore
// notifications inside begin()/wake().

struct FamilyCell {
  ModelOp op;
  StatusCode code;
  const char* detail;
  bool vetoes;  // the settled end state is RUNNING (else READY_TO_SLEEP)
};

// PERSISTING settlement families (group origin, hold release, carry
// expiry, TX notice): identical submit rules, shared expectation table.
const FamilyCell kPersistingCells[] = {
    {ModelOp::Abort, StatusCode::Ok, "POWER_REQUEST_QUEUED", true},
    {ModelOp::Prepare, StatusCode::InvalidState, "not running", false},
    {ModelOp::AppEvent, StatusCode::Ok, "", true},
    {ModelOp::Send, StatusCode::InvalidState, "NODE_DRAINING", false},
    {ModelOp::SendGroup, StatusCode::InvalidState, "NODE_DRAINING", false},
    {ModelOp::Enter, StatusCode::InvalidState, "not ready to sleep", false},
};

// RUNNING families on the gateway rig (group sends admitted): no attempt is
// active, so abort/enter are refused while prepare is queued for the next
// poll. begin()/wake() restore notifications use the RESUMING variant,
// where a prepare cannot even queue.
const FamilyCell kRunningCells[] = {
    {ModelOp::Abort, StatusCode::InvalidState, "no sleep in progress", false},
    {ModelOp::Prepare, StatusCode::Ok, "POWER_REQUEST_QUEUED", false},
    {ModelOp::AppEvent, StatusCode::Ok, "", false},
    {ModelOp::Send, StatusCode::Ok, "ok", false},
    {ModelOp::SendGroup, StatusCode::Ok, "ok", false},
    {ModelOp::Enter, StatusCode::InvalidState, "not ready to sleep", false},
};

const FamilyCell kResumingCells[] = {
    {ModelOp::Abort, StatusCode::InvalidState, "no sleep in progress", false},
    {ModelOp::Prepare, StatusCode::InvalidState, "not running", false},
    {ModelOp::AppEvent, StatusCode::Ok, "", false},
    {ModelOp::Send, StatusCode::Ok, "ok", false},
    {ModelOp::SendGroup, StatusCode::Ok, "ok", false},
    {ModelOp::Enter, StatusCode::InvalidState, "not ready to sleep", false},
};

Status run_family_op(ModelOp op, PowerCoordinator& coordinator, MeshNode& node,
                     MonotonicMs now) {
  static const std::array<std::uint8_t, 3> payload{{'f', 'a', 'm'}};
  switch (op) {
    case ModelOp::Abort:
      return coordinator.sleep_abort("FAMILY");
    case ModelOp::Prepare: {
      SleepRequest request{};
      return coordinator.sleep_prepare(request, now);
    }
    case ModelOp::AppEvent:
      coordinator.notify_app_event();
      return Status::success();
    case ModelOp::Send: {
      MessageId id{};
      SendOptions send_options{};
      return node.send(9, ByteView{payload.data(), payload.size()},
                       send_options, now, id);
    }
    case ModelOp::SendGroup: {
      MessageId id{};
      GroupSendOptions group_options{};
      return node.send_group(kGroupAll, ByteView{payload.data(), payload.size()},
                             group_options, now, id);
    }
    case ModelOp::Enter:
      return coordinator.sleep_enter(coordinator.ticket(), now);
  }
  return Status::error(StatusCode::InternalError, "unreachable");
}

void test_family_group_delivery_ops() {
  for (const FamilyCell& cell : kPersistingCells) {
    MemoryPowerStorage storage;
    GroupPowerWorld w;
    w.converge();
    drop_all_reports();
    w.net.drop_frame = group_loss_hook;
    PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                                 w.events);
    CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                                 ElapsedInterval{0, 0, false}, w.now));
    GroupSendOptions options{};
    w.send_all(w.a, options);
    Status got = Status::error(StatusCode::InternalError, "not run");
    bool ran = false;
    w.observer_a.on_group_fn = [&](const GroupDeliveryResult& result) {
      if (!ran && result.state == DeliveryState::Failed &&
          std::strcmp(result.reason, "SLEEP_DRAIN") == 0) {
        ran = true;
        CHECK(coordinator.state() == PowerState::Persisting);
        got = run_family_op(cell.op, coordinator, w.a, w.now);
      }
    };
    SleepRequest request{};
    request.pending_policy = SleepWorkPolicy::Fail;
    CHECK_OK(coordinator.sleep_prepare(request, w.now));
    CHECK(w.run_until(coordinator, w.b,
                      cell.vetoes ? PowerState::Running
                                  : PowerState::ReadyToSleep));
    CHECK(ran);
    if (cell.op != ModelOp::AppEvent) {
      CHECK(got.code == cell.code);
      CHECK(std::strcmp(got.detail, cell.detail) == 0);
    }
    if (cell.op == ModelOp::AppEvent) {
      CHECK(w.events.has_diag("SLEEP_TICKET_INVALID"));
    }
  }
}

void test_family_group_message_ops() {
  for (const FamilyCell& cell : kPersistingCells) {
    MemoryPowerStorage storage;
    GroupPowerWorld w;
    w.converge();
    GroupSendOptions options{};
    options.ordered = true;
    options.lifetime_ms = 10000;
    w.send_all(w.a, options);
    w.run(60);
    g_drop_type = FrameType::GroupData;
    g_drop_to = GroupPowerWorld::kLeaf;
    g_drop_sequence = kGroupSequenceFlag | 2;
    w.net.drop_frame = group_loss_hook;
    w.send_all(w.a, options);
    GroupSendOptions urgent = options;
    urgent.priority = Priority::Urgent;
    w.send_all(w.a, urgent);
    w.run(200);
    CHECK(w.b.group_holds_in_use() == 1);
    PowerCoordinator coordinator(PowerConfig{500, 50}, w.b, w.port, storage,
                                 w.events);
    CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                                 ElapsedInterval{0, 0, false}, w.now));
    Status got = Status::error(StatusCode::InternalError, "not run");
    bool ran = false;
    w.observer_b.on_group_message_fn = [&](const GroupMessageInfo& info,
                                           ByteView) {
      if (!ran && info.group_seq == 3) {
        ran = true;
        CHECK(coordinator.state() == PowerState::Persisting);
        got = run_family_op(cell.op, coordinator, w.b, w.now);
      }
    };
    SleepRequest request{};
    CHECK_OK(coordinator.sleep_prepare(request, w.now));
    CHECK(w.run_until(coordinator, w.a,
                      cell.vetoes ? PowerState::Running
                                  : PowerState::ReadyToSleep));
    CHECK(ran);
    if (cell.op != ModelOp::AppEvent) {
      CHECK(got.code == cell.code);
      CHECK(std::strcmp(got.detail, cell.detail) == 0);
    }
    if (cell.op == ModelOp::AppEvent) {
      CHECK(w.events.has_diag("SLEEP_TICKET_INVALID"));
    }
  }
}

void test_family_pending_result_ops() {
  for (const FamilyCell& cell : kPersistingCells) {
    MemoryPowerStorage storage;
    GroupPowerWorld w;
    w.converge();
    PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                                 w.events);
    CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                                 ElapsedInterval{0, 0, false}, w.now));
    // Build a carry set, then let it expire: save one durable record and
    // abort before anything else settles.
    const std::array<std::uint8_t, 3> payload{{'c', 'a', 'r'}};
    MessageId id{};
    SendOptions durable{};
    durable.persist_across_sleep = true;
    durable.lifetime_ms = 1000;
    CHECK_OK(w.a.send(9, ByteView{payload.data(), payload.size()}, durable,
                      w.now, id));
    bool saved = false;
    w.observer_a.on_delivery_fn = [&](const DeliveryResult& result) {
      if (!saved && result.state == DeliveryState::Indeterminate) {
        saved = true;
        CHECK_OK(coordinator.sleep_abort("CARRY"));
      }
    };
    SleepRequest save{};
    save.pending_policy = SleepWorkPolicy::Save;
    CHECK_OK(coordinator.sleep_prepare(save, w.now));
    CHECK(w.run_until(coordinator, w.b, PowerState::Running));
    CHECK(saved);
    w.observer_a.on_delivery_fn = nullptr;
    w.run(2000);  // the carried record's budget lapses while awake
    Status got = Status::error(StatusCode::InternalError, "not run");
    bool ran = false;
    w.events.on_pending_result_fn = [&](const PendingDeliveryRecord&,
                                        StatusCode code) {
      if (!ran && code == StatusCode::Expired) {
        ran = true;
        CHECK(coordinator.state() == PowerState::Persisting);
        got = run_family_op(cell.op, coordinator, w.a, w.now);
      }
    };
    SleepRequest retry{};
    retry.pending_policy = SleepWorkPolicy::Fail;
    CHECK_OK(coordinator.sleep_prepare(retry, w.now));
    CHECK(w.run_until(coordinator, w.b,
                      cell.vetoes ? PowerState::Running
                                  : PowerState::ReadyToSleep));
    CHECK(ran);
    if (cell.op != ModelOp::AppEvent) {
      CHECK(got.code == cell.code);
      CHECK(std::strcmp(got.detail, cell.detail) == 0);
    }
    if (cell.op == ModelOp::AppEvent) {
      CHECK(w.events.has_diag("SLEEP_TICKET_INVALID"));
    }
  }
}

void test_family_tx_notice_ops() {
  for (const FamilyCell& cell : kPersistingCells) {
    MemoryPowerStorage storage;
    GroupPowerWorld w;
    w.converge();
    PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                                 w.events);
    CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                                 ElapsedInterval{0, 0, false}, w.now));
    // A frame stuck in physical TX at the drain deadline raises the notice.
    const std::array<std::uint8_t, 3> payload{{'t', 'x', '!'}};
    MessageId id{};
    SendOptions send_options{};
    send_options.delivery = DeliveryClass::BestEffort;  // single TX attempt
    CHECK_OK(w.a.send(GroupPowerWorld::kLeaf,
                      ByteView{payload.data(), payload.size()}, send_options,
                      w.now, id));
    w.a.poll(w.now);  // dispatch into physical; no flush, so no TX result
    Status got = Status::error(StatusCode::InternalError, "not run");
    bool ran = false;
    w.observer_a.on_diag_fn = [&](const char* reason, NodeId,
                                  const MessageId*) {
      if (!ran && std::strcmp(reason, "SLEEP_TX_INFLIGHT") == 0) {
        ran = true;
        CHECK(coordinator.state() == PowerState::Persisting);
        got = run_family_op(cell.op, coordinator, w.a, w.now);
      }
    };
    SleepRequest request{};
    CHECK_OK(coordinator.sleep_prepare(request, w.now));
    // No flush until the notice ran: the TX result must not land first.
    for (int i = 0; i < 400 && !ran; ++i) {
      coordinator.poll(w.now);
      w.b.poll(w.now);
      w.now += 5;
    }
    CHECK(ran);
    if (cell.op != ModelOp::AppEvent) {
      CHECK(got.code == cell.code);
      CHECK(std::strcmp(got.detail, cell.detail) == 0);
    }
    CHECK(w.run_until(coordinator, w.b,
                      cell.vetoes ? PowerState::Running
                                  : PowerState::ReadyToSleep));
  }
}

void test_family_normal_message_ops() {
  // Normal on_message delivery in RUNNING and mid-drain: the same submit
  // rules, different admission. (Gateway-scoped rig: group sends outside
  // the drain are admitted here, unlike the flat matrix rig.)
  for (bool draining : {false, true}) {
    for (const FamilyCell& cell :
         draining ? std::vector<FamilyCell>(std::begin(kPersistingCells),
                                            std::end(kPersistingCells))
                  : std::vector<FamilyCell>(std::begin(kRunningCells),
                                            std::end(kRunningCells))) {
      MemoryPowerStorage storage;
      GroupPowerWorld w;
      w.converge();
      PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                                   w.events);
      CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                                   ElapsedInterval{0, 0, false}, w.now));
      if (draining) {
        // A collecting group round holds the drain open until the trigger
        // message arrives mid-drain (a quiet node would settle first).
        drop_all_reports();
        w.net.drop_frame = group_loss_hook;
        GroupSendOptions options{};
        w.send_all(w.a, options);
        SleepRequest request{};
        CHECK_OK(coordinator.sleep_prepare(request, w.now));
      }
      Status got = Status::error(StatusCode::InternalError, "not run");
      bool ran = false;
      w.observer_a.on_message_fn = [&](const MessageKey&, NodeId, ByteView) {
        if (ran) return;
        ran = true;
        CHECK(coordinator.state() ==
              (draining ? PowerState::Draining : PowerState::Running));
        got = run_family_op(cell.op, coordinator, w.a, w.now);
      };
      const std::array<std::uint8_t, 3> payload{{'h', 'i', '!'}};
      MessageId id{};
      SendOptions send_options{};
      CHECK_OK(w.b.send(GroupPowerWorld::kGateway,
                        ByteView{payload.data(), payload.size()}, send_options,
                        w.now, id));
      for (int i = 0; i < 400 && !ran; ++i) {
        coordinator.poll(w.now);
        w.b.poll(w.now);
        w.net.flush(w.now);
        w.now += 5;
      }
      CHECK(ran);
      if (cell.op != ModelOp::AppEvent) {
        CHECK(got.code == cell.code);
        CHECK(std::strcmp(got.detail, cell.detail) == 0);
      }
      // Drain the aftermath: a queued prepare starts the next poll and the
      // quiet attempt reaches READY; anything else settles per the veto.
      if (!draining && cell.op == ModelOp::Prepare) {
        CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
      } else {
        CHECK(w.run_until(coordinator, w.b,
                          cell.vetoes ? PowerState::Running
                                      : (draining ? PowerState::ReadyToSleep
                                                  : PowerState::Running)));
      }
    }
  }
}

struct AppliedSinkHook final : AppliedEndpointSink {
  std::function<void()> on_request_fn;
  void on_applied_request(const AppliedRequest&,
                          AppliedReply& reply) noexcept override {
    reply.outcome = endpoint::AppResultOutcome::Success;
    reply.code = 7;
    reply.size = 0;
    if (on_request_fn) on_request_fn();
  }
};

void test_family_power_diagnostic_ops() {
  // PowerEvents::on_diagnostic fires in RUNNING — abort_to_running tears
  // down first and notifies last. Abort from a settlement callback, then
  // run the op table inside the abort diagnostic: acceptance only, the
  // machine is already RUNNING and stays there (a queued prepare starts
  // the next poll and reaches READY on the quiet node).
  for (const FamilyCell& cell : kRunningCells) {
    MemoryPowerStorage storage;
    GroupPowerWorld w;
    w.converge();
    PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                                 w.events);
    CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                                 ElapsedInterval{0, 0, false}, w.now));
    const std::array<std::uint8_t, 3> payload{{'p', 'd', '!'}};
    MessageId id{};
    SendOptions send_options{};
    send_options.lifetime_ms = 20000;
    CHECK_OK(w.a.send(9, ByteView{payload.data(), payload.size()},
                      send_options, w.now, id));
    w.observer_a.on_delivery_fn = [&](const DeliveryResult& result) {
      if (result.state == DeliveryState::Failed &&
          std::strcmp(result.reason, "SLEEP_DRAIN") == 0) {
        CHECK_OK(coordinator.sleep_abort("FAMILY_DIAG"));
      }
    };
    Status got = Status::error(StatusCode::InternalError, "not run");
    bool ran = false;
    PowerState frozen = PowerState::Draining;
    bool frozen_draining = true;
    bool frozen_ticket = true;
    w.events.on_diagnostic_fn = [&](const char* reason) {
      if (!ran && std::strcmp(reason, "FAMILY_DIAG") == 0) {
        ran = true;
        frozen = coordinator.state();
        frozen_draining = w.a.draining();
        frozen_ticket = coordinator.ticket().issued;
        got = run_family_op(cell.op, coordinator, w.a, w.now);
      }
    };
    SleepRequest request{};
    request.pending_policy = SleepWorkPolicy::Fail;
    CHECK_OK(coordinator.sleep_prepare(request, w.now));
    CHECK(w.run_until(coordinator, w.b,
                      cell.op == ModelOp::Prepare ? PowerState::ReadyToSleep
                                                  : PowerState::Running));
    CHECK(ran);
    CHECK(frozen == PowerState::Running);
    CHECK(!frozen_draining);
    CHECK(!frozen_ticket);
    if (cell.op != ModelOp::AppEvent) {
      CHECK(got.code == cell.code);
      CHECK(std::strcmp(got.detail, cell.detail) == 0);
    }
  }
}

void test_family_applied_and_sink_ops() {
  // NodeObserver::on_applied_result (origin side) and the extended
  // AppliedEndpointSink (terminal side): one applied exchange fires each
  // exactly once with the coordinator begun but idle, so the op table
  // runs under the node-callback flag alone — acceptance only, no
  // immediate effect (a queued prepare still reaches READY afterwards).
  for (bool sink_side : {false, true}) {
    for (const FamilyCell& cell : kRunningCells) {
      MemoryPowerStorage storage;
      GroupPowerWorld w;
      w.converge();
      AppliedSinkHook sink;
      MeshNode& origin = sink_side ? w.b : w.a;
      MeshNode& terminal = sink_side ? w.a : w.b;
      HookedObserver& origin_obs = sink_side ? w.observer_b : w.observer_a;
      terminal.set_applied_sink(&sink);
      PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                                   w.events);
      CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                                   ElapsedInterval{0, 0, false}, w.now));
      Status got = Status::error(StatusCode::InternalError, "not run");
      bool ran = false;
      PowerState frozen = PowerState::Draining;
      bool frozen_draining = true;
      bool frozen_ticket = true;
      const auto fire = [&]() {
        if (ran) return;
        ran = true;
        frozen = coordinator.state();
        frozen_draining = w.a.draining();
        frozen_ticket = coordinator.ticket().issued;
        got = run_family_op(cell.op, coordinator, w.a, w.now);
      };
      if (sink_side) {
        sink.on_request_fn = fire;
      } else {
        origin_obs.on_applied_result_fn =
            [&](const MessageKey&, const AppliedResultView&) { fire(); };
      }
      const std::array<std::uint8_t, 4> payload{{0x61, 0x62, 0x63, 0x64}};
      MessageId id{};
      SendOptions applied{};
      applied.delivery = DeliveryClass::Applied;
      applied.lifetime_ms = 10000;
      CHECK_OK(origin.send_applied(sink_side ? GroupPowerWorld::kGateway
                                             : GroupPowerWorld::kLeaf,
                                   ByteView{payload.data(), payload.size()},
                                   terminal.applied_lease(), applied, w.now,
                                   id));
      // Direct node drive: the coordinator stays idle, so only the
      // node-callback flag marks the re-entrant request as deferred.
      for (int i = 0; i < 400 && !ran; ++i) {
        w.a.poll(w.now);
        w.b.poll(w.now);
        w.net.flush(w.now);
        w.now += 5;
      }
      CHECK(ran);
      CHECK(frozen == PowerState::Running);
      CHECK(!frozen_draining);
      CHECK(!frozen_ticket);
      if (cell.op != ModelOp::AppEvent) {
        CHECK(got.code == cell.code);
        CHECK(std::strcmp(got.detail, cell.detail) == 0);
      }
      CHECK(w.run_until(coordinator, w.b,
                        cell.op == ModelOp::Prepare ? PowerState::ReadyToSleep
                                                  : PowerState::Running));
    }
  }
}

void test_family_begin_wake_ops() {
  // on_pending_result during restore — once via begin() on a fresh
  // instance, once via wake() after a real enter: the op table runs in
  // RESUMING with the node started and undrained; begin()/wake() then
  // completes to RUNNING in the same call.
  for (bool via_wake : {false, true}) {
    for (const FamilyCell& cell : kResumingCells) {
      MemoryPowerStorage storage;
      GroupPowerWorld w;
      w.converge();
      PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                                   w.events);
      CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                                   ElapsedInterval{0, 0, false}, w.now));
      const std::array<std::uint8_t, 3> payload{{'b', 'w', '!'}};
      MessageId id{};
      SendOptions durable{};
      durable.persist_across_sleep = true;
      durable.lifetime_ms = 20000;
      CHECK_OK(w.a.send(9, ByteView{payload.data(), payload.size()}, durable,
                        w.now, id));
      SleepRequest save{};
      save.pending_policy = SleepWorkPolicy::Save;
      CHECK_OK(coordinator.sleep_prepare(save, w.now));
      CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
      Status got = Status::error(StatusCode::InternalError, "not run");
      bool ran = false;
      PowerState frozen = PowerState::Running;
      bool frozen_draining = true;
      bool frozen_ticket = true;
      if (!via_wake) {
        GroupPowerWorld fresh;
        fresh.converge();
        FakePowerPort fresh_port;
        RecordingPowerEvents fresh_events;
        PowerCoordinator woken(PowerConfig{500, 50}, fresh.a, fresh_port,
                               storage, fresh_events);
        fresh_events.on_pending_result_fn = [&](const PendingDeliveryRecord&,
                                                StatusCode) {
          if (ran) return;
          ran = true;
          frozen = woken.state();
          frozen_draining = fresh.a.draining();
          frozen_ticket = woken.ticket().issued;
          got = run_family_op(cell.op, woken, fresh.a, fresh.now);
        };
        CHECK_OK(woken.begin(ResetCause::DeepSleepWake,
                             ElapsedInterval{100, 200, true}, fresh.now));
        CHECK(ran);
        CHECK(woken.state() == PowerState::Running);
      } else {
        w.events.on_pending_result_fn = [&](const PendingDeliveryRecord&,
                                            StatusCode) {
          if (ran) return;
          ran = true;
          frozen = coordinator.state();
          frozen_draining = w.a.draining();
          frozen_ticket = coordinator.ticket().issued;
          got = run_family_op(cell.op, coordinator, w.a, w.now);
        };
        CHECK_OK(coordinator.sleep_enter(coordinator.ticket(), w.now));
        CHECK_OK(coordinator.wake(ResetCause::DeepSleepWake,
                                  ElapsedInterval{100, 200, true}, w.now));
        CHECK(ran);
        CHECK(coordinator.state() == PowerState::Running);
      }
      CHECK(frozen == PowerState::Resuming);
      CHECK(!frozen_draining);
      CHECK(!frozen_ticket);
      if (cell.op != ModelOp::AppEvent) {
        CHECK(got.code == cell.code);
        CHECK(std::strcmp(got.detail, cell.detail) == 0);
      }
    }
  }
}

// --- Section 9.3 (boundaries): radio, recursive drive, node-flag deferral ---

void test_callback_radio_reset_vetoes() {
  // A radio reset signalled from a settlement callback vetoes like app
  // activity; one signalled outside latches until the next poll, blocking a
  // new prepare meanwhile (#110: sticky invalidation requests).
  {
    MemoryPowerStorage storage;
    GroupPowerWorld w;
    w.converge();
    PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                                 w.events);
    CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                                 ElapsedInterval{0, 0, false}, w.now));
    const std::array<std::uint8_t, 3> payload{{'r', 'r', '!'}};
    MessageId id{};
    SendOptions send_options{};
    CHECK_OK(w.a.send(9, ByteView{payload.data(), payload.size()},
                      send_options, w.now, id));
    bool vetoed = false;
    w.observer_a.on_delivery_fn = [&](const DeliveryResult& result) {
      if (result.state == DeliveryState::Failed &&
          std::strcmp(result.reason, "SLEEP_DRAIN") == 0) {
        vetoed = true;
        coordinator.notify_radio_reset();
      }
    };
    SleepRequest request{};
    CHECK_OK(coordinator.sleep_prepare(request, w.now));
    CHECK(w.run_until(coordinator, w.b, PowerState::Running));
    CHECK(vetoed);
    CHECK(!w.events.saw(PowerState::Persisting, PowerState::ReadyToSleep,
                        "SLEEP_READY"));
    CHECK(!coordinator.ticket().issued);
    CHECK(w.events.has_diag("SLEEP_TICKET_INVALID"));
  }
  {
    // Outside latch: prepare is Busy until a poll consumes the request.
    MemoryPowerStorage storage;
    PowerWorld w(storage);
    CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                                 ElapsedInterval{0, 0, false}, w.now));
    w.pump(60);
    w.coordinator.notify_radio_reset();
    SleepRequest request{};
    CHECK(w.coordinator.sleep_prepare(request, w.now).code ==
          StatusCode::Busy);
    w.pump(10);
    CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
    CHECK(w.pump_until(PowerState::ReadyToSleep));
  }
}

void test_recursive_coordinator_drive_rejected() {
  // begin/wake/poll issued from an application callback never drive the
  // machine re-entrantly: poll is a silent no-op, begin/wake are Busy.
  MemoryPowerStorage storage;
  GroupPowerWorld w;
  w.converge();
  PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                               w.events);
  CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  const std::array<std::uint8_t, 3> payload{{'r', 'e', '!'}};
  MessageId id{};
  SendOptions send_options{};
  CHECK_OK(w.a.send(9, ByteView{payload.data(), payload.size()},
                    send_options, w.now, id));
  Status begin_status = Status::error(StatusCode::InternalError, "not run");
  Status wake_status = Status::error(StatusCode::InternalError, "not run");
  PowerState poll_state = PowerState::Running;
  bool ran = false;
  w.observer_a.on_delivery_fn = [&](const DeliveryResult& result) {
    if (ran || result.state != DeliveryState::Failed ||
        std::strcmp(result.reason, "SLEEP_DRAIN") != 0) {
      return;
    }
    ran = true;
    coordinator.poll(w.now);  // silent no-op: still settling afterwards
    poll_state = coordinator.state();
    begin_status = coordinator.begin(ResetCause::ColdBoot,
                                     ElapsedInterval{0, 0, false}, w.now);
    wake_status = coordinator.wake(ResetCause::DeepSleepWake,
                                   ElapsedInterval{0, 0, false}, w.now);
  };
  SleepRequest request{};
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
  CHECK(ran);
  CHECK(poll_state == PowerState::Persisting);
  CHECK(begin_status.code == StatusCode::Busy);
  CHECK(std::strcmp(begin_status.detail, "POWER_REENTRANT_DRIVE") == 0);
  CHECK(wake_status.code == StatusCode::Busy);
  CHECK(std::strcmp(wake_status.detail, "POWER_REENTRANT_DRIVE") == 0);
}

void test_node_callback_defers_without_driving() {
  // The node-flag deferral path (coordinator idle, no worker on the stack):
  // driving node_.poll() directly, a callback's prepare is queued, a later
  // abort in the same callback cancels it, and the next coordinator poll
  // consumes both without starting an attempt.
  MemoryPowerStorage storage;
  MatrixWorld w;
  CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  w.pump(60);
  const std::array<std::uint8_t, 3> payload{{'d', 'e', 'f'}};
  MessageId id{};
  SendOptions send_options{};
  send_options.lifetime_ms = 5;
  CHECK_OK(w.node.send(9, ByteView{payload.data(), payload.size()},
                       send_options, w.now, id));
  Status prepare_status = Status::error(StatusCode::InternalError, "not run");
  Status abort_status = Status::error(StatusCode::InternalError, "not run");
  w.observer.on_delivery_fn = [&](const DeliveryResult& result) {
    if (result.id == id && sleep_verdict_terminal(result.state)) {
      SleepRequest request{};
      prepare_status = w.coordinator.sleep_prepare(request, w.now);
      abort_status = w.coordinator.sleep_abort("NODE_FLAG");
    }
  };
  w.now += 10;
  w.node.poll(w.now);  // direct drive: coordinator idle throughout
  CHECK(prepare_status.ok());
  CHECK(std::strcmp(prepare_status.detail, "POWER_REQUEST_QUEUED") == 0);
  CHECK(abort_status.ok());
  CHECK(w.coordinator.state() == PowerState::Running);
  // Next poll: the abort cancels the unstarted prepare; no attempt starts.
  w.coordinator.poll(w.now);
  CHECK(w.coordinator.state() == PowerState::Running);
  CHECK(!w.events.saw(PowerState::Running, PowerState::Draining,
                      "SLEEP_PREPARE"));
}

// --- Section 9.3 (group sequences): listed op sequences at group points ----
struct GroupSequence {
  const char* name;
  std::array<ModelOp, 3> ops;
  std::size_t len;
  std::array<StatusCode, 3> codes;
  PowerState end;
};

const GroupSequence kGroupSequences[] = {
    {"abort->prepare",
     {ModelOp::Abort, ModelOp::Prepare, ModelOp::Abort},
     2,
     {StatusCode::Ok, StatusCode::Ok, StatusCode::Ok},
     PowerState::ReadyToSleep},  // old attempt ends; the new one runs
    {"prepare->abort",
     {ModelOp::Prepare, ModelOp::Abort, ModelOp::Abort},
     2,
     {StatusCode::InvalidState, StatusCode::Ok, StatusCode::Ok},
     PowerState::Running},
    {"abort->prepare->abort",
     {ModelOp::Abort, ModelOp::Prepare, ModelOp::Abort},
     3,
     {StatusCode::Ok, StatusCode::Ok, StatusCode::Ok},
     PowerState::Running},  // the second abort cancels the new prepare too
    {"prepare->app_event",
     {ModelOp::Prepare, ModelOp::AppEvent, ModelOp::Abort},
     2,
     {StatusCode::InvalidState, StatusCode::Ok, StatusCode::Ok},
     PowerState::Running},
    {"app_event->prepare",
     {ModelOp::AppEvent, ModelOp::Prepare, ModelOp::Abort},
     2,
     {StatusCode::Ok, StatusCode::Busy, StatusCode::Ok},
     PowerState::Running},  // the later prepare is refused while veto stands
    {"abort->enter",
     {ModelOp::Abort, ModelOp::Enter, ModelOp::Abort},
     2,
     {StatusCode::Ok, StatusCode::InvalidState, StatusCode::Ok},
     PowerState::Running},
    {"enter->abort",
     {ModelOp::Enter, ModelOp::Abort, ModelOp::Abort},
     2,
     {StatusCode::InvalidState, StatusCode::Ok, StatusCode::Ok},
     PowerState::Running},
    {"prepare->enter",
     {ModelOp::Prepare, ModelOp::Enter, ModelOp::Abort},
     2,
     {StatusCode::InvalidState, StatusCode::InvalidState, StatusCode::Ok},
     PowerState::ReadyToSleep},  // both refused; the attempt continues
};

void test_group_origin_sequences() {
  for (const GroupSequence& seq : kGroupSequences) {
    MemoryPowerStorage storage;
    GroupPowerWorld w;
    w.converge();
    drop_all_reports();
    w.net.drop_frame = group_loss_hook;
    PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                                 w.events);
    CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                                 ElapsedInterval{0, 0, false}, w.now));
    GroupSendOptions options{};
    w.send_all(w.a, options);
    std::vector<StatusCode> got;
    bool ran = false;
    w.observer_a.on_group_fn = [&](const GroupDeliveryResult& result) {
      if (!ran && result.state == DeliveryState::Failed &&
          std::strcmp(result.reason, "SLEEP_DRAIN") == 0) {
        ran = true;
        for (std::size_t i = 0; i < seq.len; ++i) {
          got.push_back(run_family_op(seq.ops[i], coordinator, w.a, w.now).code);
        }
      }
    };
    SleepRequest request{};
    request.pending_policy = SleepWorkPolicy::Fail;
    CHECK_OK(coordinator.sleep_prepare(request, w.now));
    CHECK(w.run_until(coordinator, w.b, seq.end));
    CHECK(ran);
    CHECK(got.size() == seq.len);
    for (std::size_t i = 0; i < seq.len && i < got.size(); ++i) {
      if (got[i] != seq.codes[i]) {
        std::fprintf(stderr, "group sequence %s op %zu: want %d got %d\n",
                     seq.name, i, static_cast<int>(seq.codes[i]),
                     static_cast<int>(got[i]));
      }
      CHECK(got[i] == seq.codes[i]);
    }
    (void)seq.name;
  }
}

void test_hold_release_sequences() {
  for (const GroupSequence& seq : kGroupSequences) {
    MemoryPowerStorage storage;
    GroupPowerWorld w;
    w.converge();
    GroupSendOptions options{};
    options.ordered = true;
    options.lifetime_ms = 10000;
    w.send_all(w.a, options);
    w.run(60);
    g_drop_type = FrameType::GroupData;
    g_drop_to = GroupPowerWorld::kLeaf;
    g_drop_sequence = kGroupSequenceFlag | 2;
    w.net.drop_frame = group_loss_hook;
    w.send_all(w.a, options);
    GroupSendOptions urgent = options;
    urgent.priority = Priority::Urgent;
    w.send_all(w.a, urgent);
    w.run(200);
    CHECK(w.b.group_holds_in_use() == 1);
    PowerCoordinator coordinator(PowerConfig{500, 50}, w.b, w.port, storage,
                                 w.events);
    CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                                 ElapsedInterval{0, 0, false}, w.now));
    std::vector<StatusCode> got;
    bool ran = false;
    w.observer_b.on_group_message_fn = [&](const GroupMessageInfo& info,
                                           ByteView) {
      if (!ran && info.group_seq == 3) {
        ran = true;
        for (std::size_t i = 0; i < seq.len; ++i) {
          got.push_back(
              run_family_op(seq.ops[i], coordinator, w.b, w.now).code);
        }
      }
    };
    SleepRequest request{};
    CHECK_OK(coordinator.sleep_prepare(request, w.now));
    CHECK(w.run_until(coordinator, w.a, seq.end));
    CHECK(ran);
    CHECK(got.size() == seq.len);
    for (std::size_t i = 0; i < seq.len && i < got.size(); ++i) {
      CHECK(got[i] == seq.codes[i]);
    }
  }
}

// --- Section 9.4 (invariants) -------------------------------------------------

void test_callback_requests_have_no_immediate_effect() {
  // Inside a settlement callback the app fires abort, prepare, enter, an
  // activity event and both sends: NONE of it moves the machine, the drain
  // mask, the ticket, storage, or the radio synchronously — no nested
  // worker starts from the callback (or its scope exit).
  MemoryPowerStorage storage;
  GroupPowerWorld w;
  w.converge();
  PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                               w.events);
  CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  const std::array<std::uint8_t, 3> payload{{'n', 'o', '!'}};
  MessageId id{};
  SendOptions send_options{};
  CHECK_OK(w.a.send(9, ByteView{payload.data(), payload.size()},
                    send_options, w.now, id));
  bool ran = false;
  w.observer_a.on_delivery_fn = [&](const DeliveryResult& result) {
    if (ran || result.state != DeliveryState::Failed ||
        std::strcmp(result.reason, "SLEEP_DRAIN") != 0) {
      return;
    }
    ran = true;
    const PowerState before = coordinator.state();
    const bool draining = w.a.draining();
    const bool issued = coordinator.ticket().issued;
    const std::size_t transitions = w.events.transitions.size();
    const std::size_t writes = storage.write_calls;
    const int quiesce = w.port.quiesce_calls;
    const int wakecfg = w.port.wakecfg_calls;
    const int sleeps = w.port.sleep_calls;
    CHECK_OK(coordinator.sleep_abort("TRACE"));
    SleepRequest request{};
    CHECK_OK(coordinator.sleep_prepare(request, w.now));
    CHECK(!coordinator.sleep_enter(coordinator.ticket(), w.now).ok());
    coordinator.notify_app_event();
    MessageId ignored{};
    CHECK(!w.a.send(GroupPowerWorld::kLeaf,
                    ByteView{payload.data(), payload.size()}, send_options,
                    w.now, ignored)
               .ok());
    GroupSendOptions group_options{};
    CHECK(!w.a.send_group(kGroupAll, ByteView{payload.data(), payload.size()},
                          group_options, w.now, ignored)
               .ok());
    // Nothing moved: acceptance only, applied at the safe point.
    CHECK(coordinator.state() == before);
    CHECK(w.a.draining() == draining);
    CHECK(coordinator.ticket().issued == issued);
    CHECK(w.events.transitions.size() == transitions);
    CHECK(storage.write_calls == writes);
    CHECK(w.port.quiesce_calls == quiesce);
    CHECK(w.port.wakecfg_calls == wakecfg);
    CHECK(w.port.sleep_calls == sleeps);
  };
  SleepRequest request{};
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  CHECK(w.run_until(coordinator, w.b, PowerState::Running));
  CHECK(ran);
}

void test_settlement_stops_at_cancelled_item() {
  // Each lane settles item-by-item: aborting at the k-th settlement
  // callback settles exactly k+1 items under the old policy and leaves the
  // rest live — never settled, never notified (#110: stop granularity).
  for (int cancel_at = 0; cancel_at < 3; ++cancel_at) {
    MemoryPowerStorage storage;
    GroupPowerWorld w;
    w.converge();
    PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                                 w.events);
    CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                                 ElapsedInterval{0, 0, false}, w.now));
    const std::array<std::uint8_t, 3> payload{{'g', 'r', 'n'}};
    std::array<MessageId, 3> ids{};
    SendOptions send_options{};
    for (auto& id : ids) {
      CHECK_OK(w.a.send(9, ByteView{payload.data(), payload.size()},
                        send_options, w.now, id));
    }
    int seen = 0;
    w.observer_a.on_delivery_fn = [&](const DeliveryResult& result) {
      if (result.state == DeliveryState::Failed &&
          std::strcmp(result.reason, "SLEEP_DRAIN") == 0) {
        if (seen++ == cancel_at) {
          CHECK_OK(coordinator.sleep_abort("STOP"));
        }
      }
    };
    SleepRequest request{};
    request.pending_policy = SleepWorkPolicy::Fail;
    CHECK_OK(coordinator.sleep_prepare(request, w.now));
    CHECK(w.run_until(coordinator, w.b, PowerState::Running));
    int settled = 0;
    int live = 0;
    for (const auto& id : ids) {
      const auto outcome = w.a.delivery(id);
      if (outcome.state == DeliveryState::Failed &&
          std::strcmp(outcome.reason, "SLEEP_DRAIN") == 0) {
        ++settled;
      } else if (!sleep_verdict_terminal(outcome.state)) {
        ++live;
      }
    }
    CHECK(settled == cancel_at + 1);
    CHECK(live == 2 - cancel_at);
  }
  for (int cancel_at = 0; cancel_at < 3; ++cancel_at) {
    MemoryPowerStorage storage;
    GroupPowerWorld w;
    w.converge();
    drop_all_reports();
    w.net.drop_frame = group_loss_hook;
    PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                                 w.events);
    CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                                 ElapsedInterval{0, 0, false}, w.now));
    GroupSendOptions options{};
    GroupSendOptions urgent = options;
    urgent.priority = Priority::Urgent;  // may take the last origin slot
    std::array<MessageId, 3> ids{};
    ids[0] = w.send_all(w.a, options);
    ids[1] = w.send_all(w.a, options);
    ids[2] = w.send_all(w.a, urgent);
    int seen = 0;
    w.observer_a.on_group_fn = [&](const GroupDeliveryResult& result) {
      if (result.state == DeliveryState::Failed &&
          std::strcmp(result.reason, "SLEEP_DRAIN") == 0) {
        if (seen++ == cancel_at) {
          CHECK_OK(coordinator.sleep_abort("STOP"));
        }
      }
    };
    SleepRequest request{};
    request.pending_policy = SleepWorkPolicy::Fail;
    CHECK_OK(coordinator.sleep_prepare(request, w.now));
    CHECK(w.run_until(coordinator, w.b, PowerState::Running));
    int settled = 0;
    int live = 0;
    for (const auto& id : ids) {
      const auto outcome = w.a.group_delivery(id);
      if (outcome.state == DeliveryState::Failed &&
          std::strcmp(outcome.reason, "SLEEP_DRAIN") == 0) {
        ++settled;
      } else if (!sleep_verdict_terminal(outcome.state)) {
        ++live;
      }
    }
    CHECK(settled == cancel_at + 1);
    CHECK(live == 2 - cancel_at);
  }
  for (int cancel_at = 0; cancel_at < 2; ++cancel_at) {
    MemoryPowerStorage storage;
    GroupPowerWorld w;
    w.converge();
    GroupSendOptions options{};
    options.ordered = true;
    options.lifetime_ms = 10000;
    const MessageId first = w.send_all(w.a, options);
    for (int i = 0;
         i < 200 && w.a.group_delivery(first).state != DeliveryState::Delivered;
         ++i) {
      w.run(50);
    }
    g_drop_type = FrameType::GroupData;
    g_drop_to = GroupPowerWorld::kLeaf;
    g_drop_sequence = kGroupSequenceFlag | 2;
    w.net.drop_frame = group_loss_hook;
    w.send_all(w.a, options);
    w.send_all(w.a, options);
    GroupSendOptions urgent = options;
    urgent.priority = Priority::Urgent;
    w.send_all(w.a, urgent);
    w.run(200);
    CHECK(w.b.group_holds_in_use() == 2);
    PowerCoordinator coordinator(PowerConfig{500, 50}, w.b, w.port, storage,
                                 w.events);
    CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                                 ElapsedInterval{0, 0, false}, w.now));
    int seen = 0;
    w.observer_b.on_group_message_fn = [&](const GroupMessageInfo& info,
                                           ByteView) {
      if (info.group_seq >= 3 && seen++ == cancel_at) {
        CHECK_OK(coordinator.sleep_abort("STOP"));
      }
    };
    SleepRequest request{};
    CHECK_OK(coordinator.sleep_prepare(request, w.now));
    CHECK(w.run_until(coordinator, w.a, PowerState::Running));
    CHECK(w.b.group_holds_in_use() == static_cast<std::size_t>(1 - cancel_at));
    std::size_t released = 0;
    for (const auto& receipt : w.observer_b.group_messages) {
      if (receipt.info.group_seq >= 3) ++released;
    }
    CHECK(released == static_cast<std::size_t>(cancel_at + 1));
  }
}

void test_late_activity_invalidates_waiting_ticket() {
  // READY + {RX, refused-TX, config change, radio reset, app event}: the
  // copied ticket AND the current ticket are both unusable, and the next
  // poll aborts to RUNNING. (A forged ticket alone never harms the valid
  // one — pinned by the stale-ticket test.)
  for (int kind = 0; kind < 5; ++kind) {
    MemoryPowerStorage storage;
    PowerWorld w(storage);
    CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                                 ElapsedInterval{0, 0, false}, w.now));
    w.pump(60);
    SleepRequest request{};
    CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
    CHECK(w.pump_until(PowerState::ReadyToSleep));
    const SleepTicket copy = w.coordinator.ticket();
    switch (kind) {
      case 0:
        w.inject_rx();  // inbound traffic bumps the work generation
        break;
      case 1: {
        // A refused send still retires the ticket's generation.
        const std::array<std::uint8_t, 3> payload{{'t', 'x', '!'}};
        MessageId id{};
        SendOptions send_options{};
        CHECK(!w.node.send(9, ByteView{payload.data(), payload.size()},
                           send_options, w.now, id)
                   .ok());
        break;
      }
      case 2:
        CHECK_OK(w.node.add_neighbor(5, 1, w.now));  // config revision moves
        break;
      case 3:
        w.coordinator.notify_radio_reset();
        break;
      default:
        w.coordinator.notify_app_event();
        break;
    }
    CHECK(w.coordinator.sleep_enter(copy, w.now).code ==
          StatusCode::InvalidState);
    CHECK(w.coordinator.sleep_enter(w.coordinator.ticket(), w.now).code ==
          StatusCode::InvalidState);
    CHECK(!w.coordinator.ticket_valid(copy));
    CHECK(w.pump_until(PowerState::Running));
  }
}

void test_enter_notify_op_matrix() {
  // Entry notifications x single ops: Expired (refresh) and SLEEP_ENTER
  // callbacks each run one op; vetoes cancel the handoff (0 platform
  // enters), refusals let it complete (exactly 1).
  struct Cell {
    ModelOp op;
    StatusCode code;
    bool vetoes;  // end state RUNNING with no platform enter (else SLEEPING)
  };
  const Cell kCells[] = {
      {ModelOp::Abort, StatusCode::Ok, true},
      {ModelOp::Prepare, StatusCode::InvalidState, false},
      {ModelOp::AppEvent, StatusCode::Ok, true},
      // Radio reset behaves like app activity; covered once here.
      {ModelOp::Send, StatusCode::InvalidState, true},
      {ModelOp::SendGroup, StatusCode::InvalidState, true},
      {ModelOp::Enter, StatusCode::Busy, false},
  };
  for (int point = 0; point < 2; ++point) {
    for (const Cell& cell : kCells) {
      MemoryPowerStorage storage;
      PowerWorld w(storage);
      w.platform_peer(2, 0xaa);
      CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                                   ElapsedInterval{0, 0, false}, w.now));
      w.pump(60);
      (void)queue_pending(w, 2, true, 5000);
      SleepRequest request{};
      CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
      CHECK(w.pump_until(PowerState::ReadyToSleep));
      const SleepTicket ticket = w.coordinator.ticket();
      Status got = Status::error(StatusCode::InternalError, "not run");
      bool ran = false;
      auto fire = [&]() {
        if (ran) return;
        ran = true;
        switch (cell.op) {
          case ModelOp::Abort:
            got = w.coordinator.sleep_abort("ENTER_MATRIX");
            break;
          case ModelOp::Prepare: {
            SleepRequest retry{};
            got = w.coordinator.sleep_prepare(retry, w.now);
            break;
          }
          case ModelOp::AppEvent:
            w.coordinator.notify_app_event();
            w.coordinator.notify_radio_reset();  // same sticky veto class
            got = Status::success();
            break;
          case ModelOp::Send: {
            MessageId id{};
            SendOptions send_options{};
            const std::array<std::uint8_t, 3> payload{{'e', 'n', '!'}};
            got = w.node.send(9, ByteView{payload.data(), payload.size()},
                              send_options, w.now, id);
            break;
          }
          case ModelOp::SendGroup: {
            MessageId id{};
            GroupSendOptions group_options{};
            const std::array<std::uint8_t, 3> payload{{'e', 'n', '!'}};
            got = w.node.send_group(kGroupAll,
                                    ByteView{payload.data(), payload.size()},
                                    group_options, w.now, id);
            break;
          }
          case ModelOp::Enter:
            got = w.coordinator.sleep_enter(ticket, w.now);
            break;
        }
      };
      if (point == 0) {
        w.now += 10010;  // the pending expires during the READY wait
        w.events.on_pending_result_fn = [&](const PendingDeliveryRecord&,
                                            StatusCode code) {
          if (code == StatusCode::Expired) fire();
        };
      } else {
        w.events.on_transition_fn = [&](PowerState, PowerState to,
                                        const char* reason) {
          if (to == PowerState::Sleeping &&
              std::strcmp(reason, "SLEEP_ENTER") == 0) {
            fire();
          }
        };
      }
      const Status entered = w.coordinator.sleep_enter(ticket, w.now);
      CHECK(ran);
      CHECK(got.code == cell.code);
      if (cell.vetoes) {
        CHECK(entered.code == StatusCode::InvalidState);
        CHECK(w.coordinator.state() == PowerState::Running);
        CHECK(!w.coordinator.ticket_valid(ticket));
        CHECK(w.port.sleep_calls == 0);
      } else {
        CHECK(entered.ok());
        CHECK(w.coordinator.state() == PowerState::Sleeping);
        CHECK(w.port.sleep_calls == 1);
      }
    }
  }
}

void test_enter_stage_faults_abort_cleanly() {
  // Refresh-commit (either copy), wake-config and platform-enter failures
  // all abort to RUNNING with no half-terminated records and no entry.
  for (int fault = 0; fault < 4; ++fault) {
    MemoryPowerStorage storage;
    PowerWorld w(storage);
    w.platform_peer(2, 0xaa);
    CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                                 ElapsedInterval{0, 0, false}, w.now));
    w.pump(60);
    (void)queue_pending(w, 2, true, 5000);
    SleepRequest request{};
    CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
    CHECK(w.pump_until(PowerState::ReadyToSleep));
    const SleepTicket ticket = w.coordinator.ticket();
    w.now += 100;  // decay the budget so the refresh commits (dual)
    if (fault == 0) storage.fail_next_writes(1);   // refresh copy 1 lost
    if (fault == 1) storage.fail_after_writes(1);  // refresh copy 2 lost
    if (fault == 2)
      w.port.inject_wakecfg =
          Status::error(StatusCode::InvalidState, "wake config refused");
    if (fault == 3)
      w.port.inject_enter =
          Status::error(StatusCode::InvalidState, "platform enter refused");
    const Status entered = w.coordinator.sleep_enter(ticket, w.now);
    CHECK(!entered.ok());
    CHECK(w.coordinator.state() == PowerState::Running);
    CHECK(!w.coordinator.ticket().issued);
    CHECK(!w.coordinator.ticket_valid(ticket));
    // The refused platform call still counts as attempted (fault 3); every
    // earlier fault never reaches the port.
    CHECK(w.port.sleep_calls == (fault == 3 ? 1 : 0));
    if (fault <= 1) {
      // The refresh never landed: no new Expired notification either.
      CHECK(w.events.pending_results.empty());
      CHECK(w.events.has_diag("power lost before write"));
    } else {
      CHECK(w.events.has_diag("SLEEP_ENTER_FAILED"));
    }
    // The attempt is cleanly over: a retry sleeps and restores normally.
    w.port.inject_wakecfg = Status::success();
    w.port.inject_enter = Status::success();
    CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
    CHECK(w.pump_until(PowerState::ReadyToSleep));
    CHECK_OK(w.coordinator.sleep_enter(w.coordinator.ticket(), w.now));
    CHECK_OK(w.coordinator.wake(ResetCause::DeepSleepWake,
                                ElapsedInterval{100, 200, true}, w.now));
    CHECK(w.events.pending_with(StatusCode::Ok) == 1);
  }
}

void test_phase1_faults_keep_work_live() {
  // Capture failure, either dual-commit copy failure, and a torn prefix on
  // either slot: the attempt aborts with live work, carry and holds
  // untouched, no settlement notification, and a retry succeeds.
  for (int fault = 0; fault < 6; ++fault) {
    MemoryPowerStorage storage;
    PowerWorld w(storage);  // flat: no route, the delivery stays queued live
    CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                                 ElapsedInterval{0, 0, false}, w.now));
    w.pump(60);
    // Dual-write precondition for faults 2, 3, 5: an older slot already
    // holds pending records (a prior committed sleep with pending work).
    // Fault 5 additionally lands the torn prefix on the even slot.
    if (fault == 2 || fault == 3 || fault == 5) {
      (void)queue_pending(w, 2, true, 20000);
      SleepRequest warm{};
      CHECK_OK(w.coordinator.sleep_prepare(warm, w.now));
      CHECK(w.pump_until(PowerState::ReadyToSleep));
      CHECK_OK(w.coordinator.sleep_abort("WARM"));
      CHECK(w.coordinator.state() == PowerState::Running);
    }
    const MessageId id = queue_pending(w, 2, true, 20000);
    if (fault == 0)
      w.port.inject_capture =
          Status::error(StatusCode::InvalidState, "cache capture refused");
    if (fault == 1) storage.fail_next_writes(1);   // persist copy 1 lost
    if (fault == 2) storage.fail_next_writes(1);   // dual copy 1 lost
    if (fault == 3) storage.fail_after_writes(1);  // dual copy 2 lost
    if (fault == 4) storage.tear_next_write(37);   // torn prefix, odd slot
    if (fault == 5) storage.tear_next_write(37);   // torn prefix, even slot
    const std::size_t transitions_before = w.events.transitions.size();
    SleepRequest request{};
    CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
    CHECK(w.pump_until(PowerState::Running));
    if (fault == 0) {
      CHECK(w.events.has_diag("cache capture refused"));
    } else {
      CHECK(w.events.has_diag("power cut mid write") ||
            w.events.has_diag("power lost before write"));
    }
    for (std::size_t i = transitions_before; i < w.events.transitions.size();
         ++i) {
      const auto& t = w.events.transitions[i];
      CHECK(!(t.from == PowerState::Persisting &&
              t.to == PowerState::ReadyToSleep));
    }
    // Live work untouched, nothing settled or notified.
    CHECK(!sleep_verdict_terminal(w.node.delivery(id).state));
    // A clean retry commits, sleeps and restores the record (plus the warm
    // record still carried from the precondition attempt, if any).
    w.port.inject_capture = Status::success();
    CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
    CHECK(w.pump_until(PowerState::ReadyToSleep));
    CHECK_OK(w.coordinator.sleep_enter(w.coordinator.ticket(), w.now));
    CHECK_OK(w.coordinator.wake(ResetCause::DeepSleepWake,
                                ElapsedInterval{100, 200, true}, w.now));
    const bool warmed = (fault == 2 || fault == 3 || fault == 5);
    CHECK(w.events.pending_with(StatusCode::Ok) == (warmed ? 2 : 1));
  }
}

void test_partial_carry_policy_matrix() {
  // Save settles two records; the attempt aborts after the first (carry 1)
  // or the second (carry 2). The retry runs under Fail/Save/Defer: the
  // unsettled record settles under the NEW policy only, and the wake
  // restores exactly the carried set (#110: partial-carry matrix).
  const SleepWorkPolicy kPolicies[] = {SleepWorkPolicy::Fail,
                                       SleepWorkPolicy::Save,
                                       SleepWorkPolicy::Defer};
  for (const SleepWorkPolicy retry_policy : kPolicies) {
    for (int abort_after = 1; abort_after <= 2; ++abort_after) {
      MemoryPowerStorage storage;
      GroupPowerWorld w;
      w.converge();
      PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                                   w.events);
      CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                                   ElapsedInterval{0, 0, false}, w.now));
      const std::array<std::uint8_t, 3> payload{{'p', 'c', '!'}};
      std::array<MessageId, 2> ids{};
      SendOptions send_options{};
      send_options.lifetime_ms = 20000;
      for (auto& id : ids) {
        CHECK_OK(w.a.send(9, ByteView{payload.data(), payload.size()},
                          send_options, w.now, id));
      }
      int saved = 0;
      bool fired = false;
      w.observer_a.on_delivery_fn = [&](const DeliveryResult& result) {
        if (fired) return;  // count the first attempt's saves only
        if (result.state == DeliveryState::Indeterminate &&
            std::strcmp(result.reason, "SLEEP_SAVED") == 0 &&
            ++saved == abort_after) {
          fired = true;
          CHECK_OK(coordinator.sleep_abort("PARTIAL"));
          SleepRequest retry{};
          retry.pending_policy = retry_policy;
          CHECK_OK(coordinator.sleep_prepare(retry, w.now));
        }
      };
      SleepRequest request{};
      request.pending_policy = SleepWorkPolicy::Save;
      CHECK_OK(coordinator.sleep_prepare(request, w.now));
      CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
      CHECK(saved == abort_after);
      if (abort_after == 1) {
        // The unsettled record belongs to the retry's policy alone.
        const auto outcome = w.a.delivery(ids[1]);
        if (retry_policy == SleepWorkPolicy::Fail) {
          CHECK(outcome.state == DeliveryState::Failed);
          CHECK(std::strcmp(outcome.reason, "SLEEP_DRAIN") == 0);
        } else if (retry_policy == SleepWorkPolicy::Save) {
          CHECK(outcome.state == DeliveryState::Indeterminate);
          CHECK(std::strcmp(outcome.reason, "SLEEP_SAVED") == 0);
        } else {
          CHECK(outcome.state == DeliveryState::Indeterminate);
          CHECK(std::strcmp(outcome.reason, "SLEEP_DEFERRED") == 0);
        }
      }
      CHECK_OK(coordinator.sleep_enter(coordinator.ticket(), w.now));
      GroupPowerWorld fresh;
      FakePowerPort fresh_port;
      RecordingPowerEvents fresh_events;
      PowerCoordinator woken(PowerConfig{500, 50}, fresh.a, fresh_port,
                             storage, fresh_events);
      CHECK_OK(woken.begin(ResetCause::DeepSleepWake,
                           ElapsedInterval{100, 200, true}, fresh.now));
      const std::size_t want =
          abort_after == 2 ? 2 : (retry_policy == SleepWorkPolicy::Save ? 2
                                : retry_policy == SleepWorkPolicy::Fail ? 1
                                                                        : 1);
      CHECK(fresh_events.pending_with(StatusCode::Ok) == want);
      CHECK(pending_results_for(fresh_events, ids[0], StatusCode::Ok) == 1);
    }
  }
}

void test_carry_overflow_keeps_carry_fails_fresh() {
  // Carry 2 + fresh 3 under Save: the candidate keeps both un-notified
  // carried records first and takes two fresh records; the fresh overflow
  // fails its live delivery loudly (SLEEP_PERSIST_FULL) instead of
  // evicting durable carry from the persisted image.
  MemoryPowerStorage storage;
  GroupPowerWorld w;
  w.converge();
  PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                               w.events);
  CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  const std::array<std::uint8_t, 3> payload{{'n', 'c', '!'}};
  SendOptions durable{};
  durable.persist_across_sleep = true;
  durable.lifetime_ms = 20000;
  std::array<MessageId, 2> carried{};
  for (auto& id : carried) {
    CHECK_OK(w.a.send(9, ByteView{payload.data(), payload.size()}, durable,
                      w.now, id));
  }
  int saved = 0;
  w.observer_a.on_delivery_fn = [&](const DeliveryResult& result) {
    if (result.state == DeliveryState::Indeterminate &&
        std::strcmp(result.reason, "SLEEP_SAVED") == 0 && ++saved == 2) {
      CHECK_OK(coordinator.sleep_abort("CARRY2"));
    }
  };
  SleepRequest save{};
  save.pending_policy = SleepWorkPolicy::Save;
  CHECK_OK(coordinator.sleep_prepare(save, w.now));
  CHECK(w.run_until(coordinator, w.b, PowerState::Running));
  CHECK(saved == 2);
  w.observer_a.on_delivery_fn = nullptr;
  std::array<MessageId, 3> fresh_ids{};
  for (auto& id : fresh_ids) {
    CHECK_OK(w.a.send(9, ByteView{payload.data(), payload.size()}, durable,
                      w.now, id));
  }
  CHECK_OK(coordinator.sleep_prepare(save, w.now));
  CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
  CHECK(w.events.pending_with(StatusCode::NoCapacity) == 0);
  std::size_t saved_count = 0;
  std::size_t persist_full = 0;
  for (const auto& id : fresh_ids) {
    const char* reason = w.a.delivery(id).reason;
    saved_count += std::strcmp(reason, "SLEEP_SAVED") == 0 ? 1U : 0U;
    persist_full += std::strcmp(reason, "SLEEP_PERSIST_FULL") == 0 ? 1U : 0U;
  }
  CHECK(saved_count == 2);
  CHECK(persist_full == 1);
  CHECK_OK(coordinator.sleep_enter(coordinator.ticket(), w.now));
  GroupPowerWorld fresh;
  FakePowerPort fresh_port;
  RecordingPowerEvents fresh_events;
  PowerCoordinator woken(PowerConfig{500, 50}, fresh.a, fresh_port, storage,
                         fresh_events);
  CHECK_OK(woken.begin(ResetCause::DeepSleepWake,
                       ElapsedInterval{100, 200, true}, fresh.now));
  CHECK(fresh_events.pending_with(StatusCode::Ok) == 4);  // 2 kept + 2 fresh
  CHECK(pending_results_for(fresh_events, carried[0], StatusCode::Ok) == 1);
  CHECK(pending_results_for(fresh_events, carried[1], StatusCode::Ok) == 1);
}

void test_carry_abort_mid_settlement_restores_on_new_node() {
  // Carry 2 + fresh 4 over the 4-slot candidate: aborting mid-settlement
  // must not lose the un-notified durable carry — a NEW node restarting
  // from the same storage still restores both carried records (#110).
  MemoryPowerStorage storage;
  GroupPowerWorld w;
  w.converge();
  PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                               w.events);
  CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  const std::array<std::uint8_t, 3> payload{{'m', 's', '!'}};
  SendOptions durable{};
  durable.persist_across_sleep = true;
  durable.lifetime_ms = 20000;
  std::array<MessageId, 2> carried{};
  for (auto& id : carried) {
    CHECK_OK(w.a.send(9, ByteView{payload.data(), payload.size()}, durable,
                      w.now, id));
  }
  int saved = 0;
  w.observer_a.on_delivery_fn = [&](const DeliveryResult& result) {
    if (result.state == DeliveryState::Indeterminate &&
        std::strcmp(result.reason, "SLEEP_SAVED") == 0 && ++saved == 2) {
      CHECK_OK(coordinator.sleep_abort("CARRY2"));
    }
  };
  SleepRequest save{};
  save.pending_policy = SleepWorkPolicy::Save;
  CHECK_OK(coordinator.sleep_prepare(save, w.now));
  CHECK(w.run_until(coordinator, w.b, PowerState::Running));
  CHECK(saved == 2);
  w.observer_a.on_delivery_fn = nullptr;
  std::array<MessageId, 4> fresh_ids{};
  for (auto& id : fresh_ids) {
    CHECK_OK(w.a.send(9, ByteView{payload.data(), payload.size()}, durable,
                      w.now, id));
  }
  (void)fresh_ids;
  bool aborted = false;
  w.observer_a.on_delivery_fn = [&](const DeliveryResult&) {
    if (!aborted) {
      aborted = true;
      CHECK_OK(coordinator.sleep_abort("MID_SETTLEMENT"));
    }
  };
  w.events.on_pending_result_fn = [&](const PendingDeliveryRecord&,
                                      StatusCode) {
    if (!aborted) {
      aborted = true;
      CHECK_OK(coordinator.sleep_abort("MID_SETTLEMENT"));
    }
  };
  CHECK_OK(coordinator.sleep_prepare(save, w.now));
  CHECK(w.run_until(coordinator, w.b, PowerState::Running));
  CHECK(aborted);
  GroupPowerWorld fresh;
  FakePowerPort fresh_port;
  RecordingPowerEvents fresh_events;
  PowerCoordinator woken(PowerConfig{500, 50}, fresh.a, fresh_port, storage,
                         fresh_events);
  CHECK_OK(woken.begin(ResetCause::DeepSleepWake,
                       ElapsedInterval{100, 200, true}, fresh.now));
  CHECK(pending_results_for(fresh_events, carried[0], StatusCode::Ok) == 1);
  CHECK(pending_results_for(fresh_events, carried[1], StatusCode::Ok) == 1);
  CHECK(fresh_events.pending_with(StatusCode::Ok) == 4);  // + 2 fresh
}

void test_carry_same_id_replaced_by_fresh() {
  // A retained record shares its logical id with a live durable delivery
  // (fresh incarnation, restarted counters): the fresh record supersedes
  // the carry in place — settled once, restored once, never duplicated.
  MemoryPowerStorage storage;
  {
    GroupPowerWorld w;
    w.converge();
    PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                                 w.events);
    CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                                 ElapsedInterval{0, 0, false}, w.now));
    const std::array<std::uint8_t, 3> payload{{'s', 'i', '!'}};
    MessageId id{};
    SendOptions durable{};
    durable.persist_across_sleep = true;
    durable.lifetime_ms = 20000;
    CHECK_OK(w.a.send(9, ByteView{payload.data(), payload.size()}, durable,
                      w.now, id));
    SleepRequest request{};
    CHECK_OK(coordinator.sleep_prepare(request, w.now));
    CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
    CHECK_OK(coordinator.sleep_enter(coordinator.ticket(), w.now));
  }
  {
    // Fresh incarnation on the same storage: the table fills up (the first
    // live id collides with the retained one) so the restore retains.
    GroupPowerWorld w;
    w.converge();
    PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                                 w.events);
    const std::array<std::uint8_t, 3> payload{{'s', 'i', '!'}};
    SendOptions durable{};
    durable.persist_across_sleep = true;
    durable.lifetime_ms = 20000;
    for (std::size_t i = 0; i < MeshNode::delivery_capacity(); ++i) {
      MessageId id{};
      CHECK_OK(w.a.send(90 + static_cast<NodeId>(i),
                        ByteView{payload.data(), payload.size()}, durable,
                        w.now, id));
    }
    CHECK_OK(coordinator.begin(ResetCause::DeepSleepWake,
                               ElapsedInterval{0, 0, true}, w.now));
    CHECK(w.events.pending_with(StatusCode::AlreadyExists) == 1);
    SleepRequest save{};
    save.pending_policy = SleepWorkPolicy::Save;
    CHECK_OK(coordinator.sleep_prepare(save, w.now));
    CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
    std::size_t saved = 0;
    std::size_t persist_full = 0;
    for (const auto& event : w.observer_a.delivery_events) {
      if (event.state == DeliveryState::Indeterminate &&
          std::strcmp(event.reason, "SLEEP_SAVED") == 0) {
        ++saved;
      }
      if (event.state == DeliveryState::Failed &&
          std::strcmp(event.reason, "SLEEP_PERSIST_FULL") == 0) {
        ++persist_full;
      }
    }
    CHECK(saved == 4);  // candidate-full: 4 saved (one replaces the carry)
    CHECK(persist_full == 4);
    CHECK_OK(coordinator.sleep_enter(coordinator.ticket(), w.now));
  }
  {
    GroupPowerWorld w;
    w.converge();
    FakePowerPort fresh_port;
    RecordingPowerEvents fresh_events;
    PowerCoordinator woken(PowerConfig{500, 50}, w.a, fresh_port, storage,
                           fresh_events);
    CHECK_OK(woken.begin(ResetCause::DeepSleepWake,
                         ElapsedInterval{100, 200, true}, w.now));
    // Exactly the 4 fresh records — the superseded carry is not a 5th.
    CHECK(fresh_events.pending_with(StatusCode::Ok) == 4);
  }
}

void test_carry_survives_history_eviction() {
  // The carry set is independent of delivery history: evicting a
  // SLEEP_SAVED record's terminal entry (DELIVERY_HISTORY_EVICTED) does
  // not lose the carried record — the next sleep still restores it.
  MemoryPowerStorage storage;
  GroupPowerWorld w;
  w.converge();
  PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                               w.events);
  CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  const std::array<std::uint8_t, 3> payload{{'e', 'v', '!'}};
  MessageId id{};
  SendOptions durable{};
  durable.persist_across_sleep = true;
  durable.lifetime_ms = 20000;
  CHECK_OK(w.a.send(9, ByteView{payload.data(), payload.size()}, durable,
                    w.now, id));
  bool saved = false;
  w.observer_a.on_delivery_fn = [&](const DeliveryResult& result) {
    if (!saved && result.state == DeliveryState::Indeterminate) {
      saved = true;
      CHECK_OK(coordinator.sleep_abort("EVICT"));
    }
  };
  SleepRequest save{};
  save.pending_policy = SleepWorkPolicy::Save;
  CHECK_OK(coordinator.sleep_prepare(save, w.now));
  CHECK(w.run_until(coordinator, w.b, PowerState::Running));
  CHECK(saved);
  w.observer_a.on_delivery_fn = nullptr;
  // Fill the table past capacity with short-lived work: the SAVED entry is
  // evicted as terminal history, then everything expires.
  SendOptions churn{};
  churn.lifetime_ms = 5;
  for (std::size_t i = 0; i < MeshNode::delivery_capacity(); ++i) {
    MessageId churn_id{};
    CHECK_OK(w.a.send(90 + static_cast<NodeId>(i),
                      ByteView{payload.data(), payload.size()}, churn, w.now,
                      churn_id));
  }
  CHECK(w.observer_a.has_diag("DELIVERY_HISTORY_EVICTED"));
  w.run(50);
  CHECK_OK(coordinator.sleep_prepare(save, w.now));
  CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
  CHECK_OK(coordinator.sleep_enter(coordinator.ticket(), w.now));
  GroupPowerWorld fresh;
  FakePowerPort fresh_port;
  RecordingPowerEvents fresh_events;
  PowerCoordinator woken(PowerConfig{500, 50}, fresh.a, fresh_port, storage,
                         fresh_events);
  CHECK_OK(woken.begin(ResetCause::DeepSleepWake,
                       ElapsedInterval{100, 200, true}, fresh.now));
  CHECK(pending_results_for(fresh_events, id, StatusCode::Ok) == 1);
}

void test_retry_after_empty_carry_commit() {
  // The first attempt commits a candidate but settles nothing saved (its
  // only settlement fails first, aborting with carry 0): the retry plans
  // from live + carry alone — the stale on-disk candidate never leaks in —
  // and the wake restores exactly the retry's set.
  MemoryPowerStorage storage;
  GroupPowerWorld w;
  w.converge();
  PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                               w.events);
  CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  const std::array<std::uint8_t, 3> payload{{'e', 'c', '!'}};
  MessageId id_b{};
  SendOptions plain{};
  plain.lifetime_ms = 20000;
  CHECK_OK(w.a.send(9, ByteView{payload.data(), payload.size()}, plain, w.now,
                    id_b));  // first in pool order: fails, aborts, carry stays 0
  MessageId id_a{};
  SendOptions durable = plain;
  durable.persist_across_sleep = true;
  CHECK_OK(w.a.send(9, ByteView{payload.data(), payload.size()}, durable,
                    w.now, id_a));
  bool aborted = false;
  w.observer_a.on_delivery_fn = [&](const DeliveryResult& result) {
    if (!aborted && result.state == DeliveryState::Failed &&
        std::strcmp(result.reason, "SLEEP_DRAIN") == 0) {
      aborted = true;
      CHECK_OK(coordinator.sleep_abort("EMPTY_CARRY"));
    }
  };
  SleepRequest fail{};
  fail.pending_policy = SleepWorkPolicy::Fail;
  CHECK_OK(coordinator.sleep_prepare(fail, w.now));
  CHECK(w.run_until(coordinator, w.b, PowerState::Running));
  CHECK(aborted);
  CHECK(w.a.delivery(id_b).state == DeliveryState::Failed);
  CHECK(!sleep_verdict_terminal(w.a.delivery(id_a).state));
  SleepRequest retry{};
  CHECK_OK(coordinator.sleep_prepare(retry, w.now));
  CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
  CHECK(std::strcmp(w.a.delivery(id_a).reason, "SLEEP_SAVED") == 0);
  CHECK_OK(coordinator.sleep_enter(coordinator.ticket(), w.now));
  GroupPowerWorld fresh;
  FakePowerPort fresh_port;
  RecordingPowerEvents fresh_events;
  PowerCoordinator woken(PowerConfig{500, 50}, fresh.a, fresh_port, storage,
                         fresh_events);
  CHECK_OK(woken.begin(ResetCause::DeepSleepWake,
                       ElapsedInterval{100, 200, true}, fresh.now));
  CHECK(pending_results_for(fresh_events, id_a, StatusCode::Ok) == 1);
  CHECK(pending_results_for(fresh_events, id_b, StatusCode::Ok) == 0);
}

void test_settled_verdicts_survive_stale_jobs() {
  // A BestEffort unicast stuck in physical TX and a group origin with a
  // queued copy settle (SLEEP_DRAIN); the abort lands in the next origin's
  // settlement. Late TX results and the queued group retry must not revive
  // either verdict via the job paths — while the unsettled origin runs on
  // to GROUP_COMPLETE (#110: terminal-owner rule). Note: a verified peer
  // end receipt still promotes a settled unicast (pre-existing deliberate
  // promotion semantic, out of this issue's scope); the stale TX_MAC_DONE
  // completion it replaces must never fire.
  MemoryPowerStorage storage;
  GroupPowerWorld w;
  w.converge();
  drop_all_reports();
  w.net.drop_frame = group_loss_hook;
  PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                               w.events);
  CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  const std::array<std::uint8_t, 3> payload{{'s', 't', '!'}};
  MessageId uni{};
  SendOptions best_effort{};
  best_effort.delivery = DeliveryClass::BestEffort;
  CHECK_OK(w.a.send(GroupPowerWorld::kLeaf, ByteView{payload.data(), payload.size()},
                    best_effort, w.now, uni));
  w.a.poll(w.now);  // dispatch into physical; no flush yet
  GroupSendOptions options{};
  const MessageId origin1 = w.send_all(w.a, options);
  const MessageId origin2 = w.send_all(w.a, options);
  int settled_origins = 0;
  w.observer_a.on_group_fn = [&](const GroupDeliveryResult& result) {
    if (result.state == DeliveryState::Failed &&
        std::strcmp(result.reason, "SLEEP_DRAIN") == 0 &&
        ++settled_origins == 1) {
      CHECK_OK(coordinator.sleep_abort("STALE"));
    }
  };
  SleepRequest request{};
  request.pending_policy = SleepWorkPolicy::Fail;
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  // No flush until the abort landed: every TX result arrives late.
  bool aborted = false;
  for (int i = 0; i < 400 && !aborted; ++i) {
    coordinator.poll(w.now);
    w.b.poll(w.now);
    w.now += 5;
    aborted = settled_origins == 1 &&
              coordinator.state() == PowerState::Running;
  }
  CHECK(aborted);
  CHECK(!sleep_verdict_terminal(w.a.group_delivery(origin2).state));
  // Old results land now: stale job completions dropped, group verdict
  // frozen, no TX_MAC_DONE resurrection of the settled unicast.
  w.net.drop_frame = nullptr;
  for (int i = 0; i < 400 &&
                  w.a.group_delivery(origin2).state != DeliveryState::Delivered;
       ++i) {
    w.a.poll(w.now);
    w.b.poll(w.now);
    w.net.flush(w.now);
    w.now += 5;
  }
  for (const auto& event : w.observer_a.delivery_events) {
    if (event.id == uni) {
      CHECK(std::strcmp(event.reason, "TX_MAC_DONE") != 0);
    }
  }
  const auto origin1_outcome = w.a.group_delivery(origin1);
  CHECK(origin1_outcome.state == DeliveryState::Failed);
  CHECK(std::strcmp(origin1_outcome.reason, "SLEEP_DRAIN") == 0);
  CHECK(w.observer_a.has_diag("STALE_JOB_DROPPED"));
  const auto origin2_outcome = w.a.group_delivery(origin2);
  CHECK(origin2_outcome.state == DeliveryState::Delivered);
  CHECK(std::strcmp(origin2_outcome.reason, "GROUP_COMPLETE") == 0);
}

void test_evicted_origin_jobs_never_dispatch() {
  // A SLEEP_DRAIN-settled origin whose record is later evicted by new
  // sends: its leftover queued jobs must still count as stale — never
  // dispatched or retried — so the Failed-notified body never reaches a
  // receiver (#110: eviction must not resurrect a terminal origin). Two
  // leaves: one old copy is physical-in-flight while the other is still
  // queued when the abort freezes the queues.
  MemoryPowerStorage storage;
  GroupPowerWorld w;
  w.converge();
  TestSecurity security_c;
  HookedObserver observer_c;
  SimRadio radio_c(w.net, 3);
  MeshNode c(GroupPowerWorld::config(3), radio_c, security_c, observer_c);
  w.net.register_node(3, &c);
  w.net.connect(GroupPowerWorld::kGateway, 3);
  CHECK_OK(c.start(w.now));
  CHECK_OK(w.a.add_neighbor(3, 1, w.now));
  CHECK_OK(c.add_neighbor(GroupPowerWorld::kGateway, 1, w.now));
  for (int i = 0; i < 400 && !w.a.scoped_child(3); ++i) {
    w.a.poll(w.now);
    w.b.poll(w.now);
    c.poll(w.now);
    w.net.flush(w.now);
    w.now += 50;
  }
  CHECK(w.a.scoped_child(3));
  PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                               w.events);
  CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  const std::array<std::uint8_t, 3> payload{{'o', 'l', 'd'}};
  GroupSendOptions options{};
  options.lifetime_ms = 10000;
  MessageId old_id{};
  CHECK_OK(w.a.send_group(kGroupAll, ByteView{payload.data(), payload.size()},
                          options, w.now, old_id));
  CHECK(w.a.group_stats().copies_queued == 2);  // one copy per leaf
  // Silence the old frame everywhere until the eviction purge below:
  // pre-abort airtime is legitimate, but none of it may reach an app.
  g_drop_type = FrameType::GroupData;
  g_drop_to = kInvalidNodeId;
  g_drop_sequence = old_id.sequence;
  w.net.silent_drop = group_loss_hook;
  bool aborted = false;
  w.observer_a.on_group_fn = [&](const GroupDeliveryResult& result) {
    if (!aborted && result.state == DeliveryState::Failed &&
        std::strcmp(result.reason, "SLEEP_DRAIN") == 0) {
      aborted = true;
      CHECK_OK(coordinator.sleep_abort("EVICTED_ORIGIN"));
    }
  };
  SleepRequest request{};
  request.pending_policy = SleepWorkPolicy::Fail;
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  // No flush until the abort landed: leftover jobs freeze in the queues.
  for (int i = 0; i < 400 && !aborted; ++i) {
    coordinator.poll(w.now);
    w.b.poll(w.now);
    c.poll(w.now);
    w.now += 5;
  }
  CHECK(aborted);
  CHECK(coordinator.state() == PowerState::Running);
  w.observer_a.on_group_fn = nullptr;
  // Evict the settled record synchronously — no polls between the abort
  // and the eviction, so the leftover copy is still queued.
  GroupSendOptions urgent{};
  urgent.priority = Priority::Urgent;
  urgent.lifetime_ms = 10000;
  for (int i = 0; i < 2 * static_cast<int>(kGroupOriginCapacity); ++i) {
    if (std::strcmp(w.a.group_delivery(old_id).reason, "NOT_FOUND") == 0) break;
    MessageId id{};
    CHECK_OK(w.a.send_group(kGroupAll, ByteView{payload.data(), payload.size()},
                            urgent, w.now, id));
  }
  CHECK(std::strcmp(w.a.group_delivery(old_id).reason, "NOT_FOUND") == 0);
  // Purge pre-abort airtime while the silence still holds, then open the
  // lane: only post-eviction transmissions could reach a leaf now.
  w.net.flush(w.now);
  w.net.silent_drop = nullptr;
  drop_all_reports();
  for (int i = 0; i < 100; ++i) {
    coordinator.poll(w.now);
    w.b.poll(w.now);
    c.poll(w.now);
    w.net.flush(w.now);
    w.now += 5;
  }
  for (const auto& receipt : w.observer_b.group_messages) {
    CHECK(!(receipt.info.key.id == old_id));
  }
  for (const auto& receipt : observer_c.group_messages) {
    CHECK(!(receipt.info.key.id == old_id));
  }
  CHECK(w.observer_a.has_diag("STALE_JOB_DROPPED"));
}

void test_request_storm_stays_bounded() {
  // Abort/prepare storms from every callback: the one-slot box absorbs
  // duplicates (first wins, rest Busy), repeated abort/prepare cycles stay
  // consistent, and a quiet attempt still reaches READY afterwards.
  {
    // Five expiries in one poll, each preparing: one queued, four Busy.
    MemoryPowerStorage storage;
    MatrixWorld w;
    CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                                 ElapsedInterval{0, 0, false}, w.now));
    w.pump(60);
    const std::array<std::uint8_t, 3> payload{{'s', 't', '!'}};
    SendOptions send_options{};
    send_options.lifetime_ms = 5;
    for (int i = 0; i < 5; ++i) {
      MessageId id{};
      CHECK_OK(w.node.send(9, ByteView{payload.data(), payload.size()},
                           send_options, w.now, id));
    }
    std::vector<StatusCode> got;
    w.observer.on_delivery_fn = [&](const DeliveryResult& result) {
      if (!sleep_verdict_terminal(result.state)) return;
      SleepRequest request{};
      got.push_back(w.coordinator.sleep_prepare(request, w.now).code);
    };
    w.now += 10;
    w.coordinator.poll(w.now);
    CHECK(got.size() == 5);
    CHECK(got[0] == StatusCode::Ok);
    for (std::size_t i = 1; i < got.size(); ++i) {
      CHECK(got[i] == StatusCode::Busy);
    }
    // Exactly one attempt starts from the storm and runs to READY.
    CHECK(w.pump_until(PowerState::ReadyToSleep));
    std::size_t prepares = 0;
    for (const auto& t : w.events.transitions) {
      if (t.from == PowerState::Running && t.to == PowerState::Draining) {
        ++prepares;
      }
    }
    CHECK(prepares == 1);
  }
  {
    // Abort/prepare storm from every PREPARE transition: three forced
    // cycles, then the last queued prepare runs to READY. Afterwards an
    // activity storm (100 merged vetoes) absorbs cleanly and a quiet run
    // still reaches READY — the box never wedges, history stays bounded.
    MemoryPowerStorage storage;
    MatrixWorld w;
    CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                                 ElapsedInterval{0, 0, false}, w.now));
    w.pump(60);
    int cycles = 0;
    w.events.on_transition_fn = [&](PowerState from, PowerState to,
                                    const char*) {
      if (from == PowerState::Running && to == PowerState::Draining &&
          cycles < 3) {
        ++cycles;
        CHECK_OK(w.coordinator.sleep_abort("STORM"));
        SleepRequest retry{};
        CHECK_OK(w.coordinator.sleep_prepare(retry, w.now));
      }
    };
    SleepRequest request{};
    CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
    CHECK(w.pump_until(PowerState::ReadyToSleep, 900));
    CHECK(cycles == 3);
    w.events.on_transition_fn = nullptr;
    for (int i = 0; i < 100; ++i) {
      w.coordinator.notify_app_event();
      w.coordinator.notify_radio_reset();
    }
    CHECK(w.pump_until(PowerState::Running));
    CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
    CHECK(w.pump_until(PowerState::ReadyToSleep));
    CHECK(w.events.transitions.size() < 60);
  }
}

void test_callback_arguments_copied_at_receipt() {
  // Stack-owned submit arguments are value-copied at receipt: overwriting
  // the caller's buffers afterwards cannot change the queued request.
  {
    // Prepare request: queued as Defer, caller buffer flipped to Fail.
    MemoryPowerStorage storage;
    GroupPowerWorld w;
    w.converge();
    PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                                 w.events);
    CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                                 ElapsedInterval{0, 0, false}, w.now));
    const std::array<std::uint8_t, 3> payload{{'c', 'p', '!'}};
    std::array<MessageId, 2> ids{};
    SendOptions send_options{};
    for (auto& id : ids) {
      CHECK_OK(w.a.send(9, ByteView{payload.data(), payload.size()},
                        send_options, w.now, id));
    }
    bool ran = false;
    w.observer_a.on_delivery_fn = [&](const DeliveryResult& result) {
      if (ran || result.state != DeliveryState::Failed ||
          std::strcmp(result.reason, "SLEEP_DRAIN") != 0) {
        return;
      }
      ran = true;
      CHECK_OK(coordinator.sleep_abort("COPY"));
      SleepRequest retry{};  // stack-owned: Defer at submit time...
      retry.pending_policy = SleepWorkPolicy::Defer;
      CHECK_OK(coordinator.sleep_prepare(retry, w.now));
      retry.pending_policy = SleepWorkPolicy::Fail;  // ...Fail afterwards
    };
    SleepRequest request{};
    request.pending_policy = SleepWorkPolicy::Fail;
    CHECK_OK(coordinator.sleep_prepare(request, w.now));
    CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
    CHECK(ran);
    // The queued Defer won: the survivor is deferred, not drained.
    CHECK(w.a.delivery(ids[1]).state == DeliveryState::Indeterminate);
    CHECK(std::strcmp(w.a.delivery(ids[1]).reason, "SLEEP_DEFERRED") == 0);
  }
  {
    // Enter ticket: queued from a stack copy, caller copy corrupted after.
    MemoryPowerStorage storage;
    PowerWorld w(storage);
    CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                                 ElapsedInterval{0, 0, false}, w.now));
    w.pump(60);
    SleepRequest request{};
    CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
    CHECK(w.pump_until(PowerState::ReadyToSleep));
    // A second ticket issue is impossible here; queue the enter from the
    // SLEEP_READY retry path instead: abort from outside, re-prepare, and
    // queue the enter from the new SLEEP_READY notification with a stack
    // ticket that is corrupted right after the call.
    CHECK_OK(w.coordinator.sleep_abort("COPY2"));
    CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
    bool ran = false;
    w.events.on_transition_fn = [&](PowerState from, PowerState to,
                                    const char* reason) {
      if (ran || from != PowerState::Persisting ||
          to != PowerState::ReadyToSleep ||
          std::strcmp(reason, "SLEEP_READY") != 0) {
        return;
      }
      ran = true;
      SleepTicket stack = w.coordinator.ticket();
      CHECK_OK(w.coordinator.sleep_enter(stack, w.now));
      stack.id = 999;  // corrupt the caller's buffer after receipt
      stack.issued = false;
    };
    CHECK(w.pump_until(PowerState::Sleeping, 600));
    CHECK(ran);
    CHECK(w.port.sleep_calls == 1);
  }
  {
    // Abort reasons: receipt-time bytes, bounded, always NUL-terminated.
    auto reason_case = [&](const char* submit, const char* want) {
      MemoryPowerStorage storage;
      MatrixWorld w;
      CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                                   ElapsedInterval{0, 0, false}, w.now));
      w.pump(60);
      const std::array<std::uint8_t, 3> payload{{'r', 's', '!'}};
      MessageId id{};
      SendOptions send_options{};
      send_options.lifetime_ms = 5000;
      CHECK_OK(w.node.send(9, ByteView{payload.data(), payload.size()},
                           send_options, w.now, id));
      bool ran = false;
      w.observer.on_delivery_fn = [&](const DeliveryResult& result) {
        if (ran || result.state != DeliveryState::Failed ||
            std::strcmp(result.reason, "SLEEP_DRAIN") != 0) {
          return;
        }
        ran = true;
        CHECK_OK(w.coordinator.sleep_abort(submit));
      };
      SleepRequest request{};
      CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
      CHECK(w.pump_until(PowerState::Running));
      CHECK(ran);
      CHECK(w.events.has_diag(want));
    };
    reason_case(nullptr, "SLEEP_ABORT_REQUEST");
    const std::string r63(63, 'A');
    reason_case(r63.c_str(), r63.c_str());  // fits exactly
    const std::string r64(64, 'B');
    const std::string r63b(63, 'B');
    reason_case(r64.c_str(), r63b.c_str());  // truncated to 63 + NUL
    const std::string rlong(100, 'C');
    const std::string r63c(63, 'C');
    reason_case(rlong.c_str(), r63c.c_str());
    // Overwrite-after-submit: the queued bytes win, not the later ones.
    MemoryPowerStorage storage;
    MatrixWorld w;
    CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                                 ElapsedInterval{0, 0, false}, w.now));
    w.pump(60);
    const std::array<std::uint8_t, 3> payload{{'r', 's', '!'}};
    MessageId id{};
    SendOptions send_options{};
    send_options.lifetime_ms = 5000;
    CHECK_OK(w.node.send(9, ByteView{payload.data(), payload.size()},
                         send_options, w.now, id));
    bool ran = false;
    w.observer.on_delivery_fn = [&](const DeliveryResult& result) {
      if (ran || result.state != DeliveryState::Failed ||
          std::strcmp(result.reason, "SLEEP_DRAIN") != 0) {
        return;
      }
      ran = true;
      char reason[64];
      std::memset(reason, 'Q', sizeof(reason) - 1);
      reason[sizeof(reason) - 1] = '\0';
      CHECK_OK(w.coordinator.sleep_abort(reason));
      std::memset(reason, 'Z', sizeof(reason) - 1);  // overwrite after
    };
    SleepRequest request{};
    CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
    CHECK(w.pump_until(PowerState::Running));
    CHECK(ran);
    CHECK(w.events.has_diag(std::string(63, 'Q').c_str()));
    CHECK(!w.events.has_diag("ZZZ"));
  }
}

void test_abort_never_erases_committed_snapshot() {
  // Aborting mid-settlement is RAM-only: a power cut right after still
  // conservatively restores the COMMITTED candidate (both records) on a
  // fresh incarnation. No durable-cancel claim exists — and none is made.
  MemoryPowerStorage storage;
  MessageId id_a{};
  MessageId id_b{};
  {
    GroupPowerWorld w;
    w.converge();
    PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                                 w.events);
    CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                                 ElapsedInterval{0, 0, false}, w.now));
    const std::array<std::uint8_t, 3> payload{{'s', 'n', '!'}};
    SendOptions send_options{};
    send_options.lifetime_ms = 20000;
    CHECK_OK(w.a.send(9, ByteView{payload.data(), payload.size()},
                      send_options, w.now, id_a));
    CHECK_OK(w.a.send(9, ByteView{payload.data(), payload.size()},
                      send_options, w.now, id_b));
    bool aborted = false;
    w.observer_a.on_delivery_fn = [&](const DeliveryResult& result) {
      if (!aborted && result.state == DeliveryState::Indeterminate) {
        aborted = true;
        CHECK_OK(coordinator.sleep_abort("CUT"));
      }
    };
    SleepRequest request{};
    request.pending_policy = SleepWorkPolicy::Save;
    CHECK_OK(coordinator.sleep_prepare(request, w.now));
    CHECK(w.run_until(coordinator, w.b, PowerState::Running));
    CHECK(aborted);
  }
  {
    // Fresh incarnation, same storage: the committed {A, B} candidate is
    // restored wholesale — the RAM-only settlement is simply gone.
    GroupPowerWorld w;
    w.converge();
    FakePowerPort fresh_port;
    RecordingPowerEvents fresh_events;
    PowerCoordinator woken(PowerConfig{500, 50}, w.a, fresh_port, storage,
                           fresh_events);
    CHECK_OK(woken.begin(ResetCause::OtherReset,
                         ElapsedInterval{100, 200, true}, w.now));
    CHECK(pending_results_for(fresh_events, id_a, StatusCode::Ok) == 1);
    CHECK(pending_results_for(fresh_events, id_b, StatusCode::Ok) == 1);
  }
}

// --- Section 9.4 (allocation): fixed fixtures (no heap of their own) ---------
struct FixedNodeObserver final : NodeObserver {
  void on_message(const MessageKey&, NodeId, ByteView) noexcept override {
    ++messages;
  }
  void on_delivery(const DeliveryResult&) noexcept override { ++deliveries; }
  void on_diagnostic(const char*, NodeId,
                     const MessageId*) noexcept override {
    ++diagnostics;
  }
  void on_group_message(const GroupMessageInfo&,
                        ByteView) noexcept override {
    ++group_messages;
  }
  void on_group_delivery(const GroupDeliveryResult&) noexcept override {
    ++group_deliveries;
  }
  std::size_t messages{0};
  std::size_t deliveries{0};
  std::size_t diagnostics{0};
  std::size_t group_messages{0};
  std::size_t group_deliveries{0};
};

struct FixedPowerEvents final : PowerEvents {
  void on_transition(PowerState, PowerState,
                     const char*) noexcept override {
    ++transitions;
  }
  void on_pending_result(const PendingDeliveryRecord&,
                         StatusCode) noexcept override {
    ++pending_results;
  }
  void on_diagnostic(const char*) noexcept override { ++diagnostics; }
  std::size_t transitions{0};
  std::size_t pending_results{0};
  std::size_t diagnostics{0};
};

void test_sleep_path_uses_no_heap() {
  // A full sleep lifecycle plus a veto cycle, with allocation-free
  // fixtures: zero operator-new calls across every production span.
  MemoryPowerStorage storage;
  TestSecurity security;
  FixedNodeObserver observer;
  SimNetwork net;
  SimRadio radio(net, 7);
  MeshNode node(MatrixWorld::make_config(), radio, security, observer);
  FakePowerPort port;
  FixedPowerEvents events;
  PowerCoordinator coordinator(PowerConfig{500, 50}, node, port, storage,
                               events);
  MonotonicMs now = 0;
  heap_probe::armed = true;
  CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                             ElapsedInterval{0, 0, false}, now));
  for (; now <= 60; now += 5) {
    coordinator.poll(now);
    net.flush(now);
  }
  const std::array<std::uint8_t, 3> payload{{'h', 'e', '!'}};
  MessageId id{};
  SendOptions durable{};
  durable.persist_across_sleep = true;
  CHECK_OK(node.send(9, ByteView{payload.data(), payload.size()}, durable,
                     now, id));
  SleepRequest request{};
  CHECK_OK(coordinator.sleep_prepare(request, now));
  for (int i = 0; i < 400 && coordinator.state() != PowerState::ReadyToSleep;
       ++i) {
    coordinator.poll(now);
    net.flush(now);
    now += 5;
  }
  CHECK(coordinator.state() == PowerState::ReadyToSleep);
  // A veto cycle, then the real entry: abort, reprepare, enter, wake.
  CHECK_OK(coordinator.sleep_abort("HEAP"));
  CHECK(coordinator.state() == PowerState::Running);
  CHECK_OK(coordinator.sleep_prepare(request, now));
  for (int i = 0; i < 400 && coordinator.state() != PowerState::ReadyToSleep;
       ++i) {
    coordinator.poll(now);
    net.flush(now);
    now += 5;
  }
  CHECK_OK(coordinator.sleep_enter(coordinator.ticket(), now));
  CHECK_OK(coordinator.wake(ResetCause::DeepSleepWake,
                            ElapsedInterval{100, 200, true}, now));
  coordinator.notify_app_event();
  coordinator.notify_radio_reset();
  coordinator.poll(now);
  heap_probe::armed = false;
  CHECK(heap_probe::new_calls == 0);
  CHECK(events.transitions > 0);  // the spans above really ran
}

// The public sleep surface is noexcept end to end.
static_assert(noexcept(std::declval<MeshNode&>().send(
                  NodeId{}, ByteView{}, SendOptions{}, MonotonicMs{},
                  std::declval<MessageId&>())),
              "send is noexcept");
static_assert(noexcept(std::declval<MeshNode&>().send_group(
                  kGroupAll, ByteView{}, GroupSendOptions{}, MonotonicMs{},
                  std::declval<MessageId&>())),
              "send_group is noexcept");
static_assert(noexcept(std::declval<MeshNode&>().poll(MonotonicMs{})),
              "node poll is noexcept");
static_assert(noexcept(std::declval<MeshNode&>().start(MonotonicMs{})),
              "node start is noexcept");
static_assert(noexcept(std::declval<MeshNode&>().set_draining(true)),
              "set_draining is noexcept");
static_assert(noexcept(std::declval<MeshNode&>().in_external_callback()),
              "in_external_callback is noexcept");
struct NoexceptProbeSave {
  bool operator()(const DeliverySnapshot&) const noexcept { return true; }
};
struct NoexceptProbeClaim {
  bool operator()(const MessageId&) const noexcept { return true; }
};
static_assert(noexcept(std::declval<MeshNode&>().snapshot_for_sleep(
                  SleepWorkPolicy::Fail, NoexceptProbeSave{})),
              "snapshot_for_sleep is noexcept");
static_assert(noexcept(std::declval<MeshNode&>().settle_one_sleep_delivery(
                  SleepWorkPolicy::Fail, NoexceptProbeClaim{})),
              "settle_one_sleep_delivery is noexcept");
static_assert(noexcept(std::declval<MeshNode&>().settle_one_sleep_group_origin(
                  SleepWorkPolicy::Fail)),
              "settle_one_sleep_group_origin is noexcept");
static_assert(
    noexcept(std::declval<MeshNode&>().release_one_group_hold_for_sleep()),
    "release_one_group_hold_for_sleep is noexcept");
static_assert(
    noexcept(std::declval<MeshNode&>().quiesce_notice_for_sleep()),
    "quiesce_notice_for_sleep is noexcept");
static_assert(
    noexcept(std::declval<MeshNode&>().quiesce_teardown_for_sleep()),
    "quiesce_teardown_for_sleep is noexcept");
static_assert(noexcept(std::declval<MeshNode&>().resume_delivery(
                  MessageId{}, NodeId{}, ByteView{}, SendOptions{},
                  MonotonicMs{})),
              "resume_delivery is noexcept");
static_assert(noexcept(std::declval<PowerCoordinator&>().begin(
                  ResetCause::ColdBoot, ElapsedInterval{}, MonotonicMs{})),
              "begin is noexcept");
static_assert(noexcept(std::declval<PowerCoordinator&>().poll(MonotonicMs{})),
              "coordinator poll is noexcept");
static_assert(noexcept(std::declval<PowerCoordinator&>().sleep_prepare(
                  SleepRequest{}, MonotonicMs{})),
              "sleep_prepare is noexcept");
static_assert(noexcept(
                  std::declval<PowerCoordinator&>().sleep_abort(nullptr)),
              "sleep_abort is noexcept");
static_assert(noexcept(std::declval<PowerCoordinator&>().sleep_enter(
                  SleepTicket{}, MonotonicMs{})),
              "sleep_enter is noexcept");
static_assert(noexcept(std::declval<PowerCoordinator&>().wake(
                  ResetCause::ColdBoot, ElapsedInterval{}, MonotonicMs{})),
              "wake is noexcept");
static_assert(
    noexcept(std::declval<PowerCoordinator&>().notify_app_event()),
    "notify_app_event is noexcept");
static_assert(
    noexcept(std::declval<PowerCoordinator&>().notify_radio_reset()),
    "notify_radio_reset is noexcept");
static_assert(noexcept(std::declval<PowerCoordinator&>().ticket_valid(
                  SleepTicket{})),
              "ticket_valid is noexcept");

}  // namespace

int main() {
  test_send_lifetime_ceiling();
  test_cold_boot_and_errors();
  test_full_cycle_transition_order();
  test_ticket_invalidated_by_app_event();
  test_ticket_invalidated_by_rx();
  test_ticket_invalidated_by_tx_attempt();
  test_ticket_invalidated_by_config_change();
  test_ticket_invalidated_by_radio_reset();
  test_stale_ticket_rejected_outstanding_stays_valid();
  test_send_rejected_while_draining();
  test_policy_fail();
  test_policy_save_durable();
  test_policy_defer();
  test_persist_full_fails_explicitly();
  test_drain_deadline_forces_settle();
  test_sleep_abort();
  test_resume_time_uncertain_no_resend();
  test_resume_known_elapsed_resends();
  test_resume_expired_no_resend();
  test_resume_running_time_only_resends();
  test_cold_boot_uses_cache_but_uncertain_time();
  test_corrupt_image_cache_lost_never_regress();
  test_counter_lease_continuity_across_power_cuts();
  test_power_cut_during_persist_write();
  test_power_cut_during_consume_commit();
  test_pending_reinject_failure_retained();
  test_retained_pending_survives_next_sleep_cycle();
  test_retained_pending_expires_while_awake();
  test_completed_delivery_not_carried_over();
  test_resume_confirm_fast_and_discovery();
  test_image_slots_alternate();
  test_persist_failure_aborts();
  test_persist_failure_keeps_pending_live();
  test_ready_wait_deducts_pending_lifetime();
  test_resume_reuses_original_id_dedup_once();
  test_long_sleep_pending_expires_no_duplicate();
  test_short_sleep_resend_dedups_once();
  test_group_drain_completes_round();
  test_group_sleep_policy_fail();
  test_group_sleep_policy_save();
  test_group_sleep_policy_defer();
  test_group_ordered_hold_released_for_sleep();
  test_group_sleep_commit_failure_keeps_state();
  test_group_settled_callback_abort_new_send();
  test_unicast_disposition_callback_abort_new_send();
  test_disposition_callback_send_refused();
  test_settlement_abort_reprepare_stops_old_policy();
  test_poll_delivery_callback_abort_stops_drain();
  test_settlement_callback_app_event_invalidates_ticket();
  test_ready_transition_callback_abort_not_overwritten();
  test_group_repair_not_waited_by_drain();
  test_poll_unicast_callback_abort_stops_drain();
  test_unicast_settlement_callback_app_event_vetoes();
  test_save_abort_fail_carries_only_settled();
  test_save_abort_fail_durable_saved_again();
  test_tx_notice_abort_keeps_queues();
  test_sleep_hold_release_abort_keeps_rest();
  test_sleep_hold_release_abort_multi_stream();
  test_carry_expired_callback_app_event_vetoes();
  test_enter_expired_callback_app_event_vetoes();
  test_callback_operation_matrix_model();
  test_family_group_delivery_ops();
  test_family_group_message_ops();
  test_family_pending_result_ops();
  test_family_tx_notice_ops();
  test_family_normal_message_ops();
  test_family_power_diagnostic_ops();
  test_family_applied_and_sink_ops();
  test_family_begin_wake_ops();
  test_callback_radio_reset_vetoes();
  test_recursive_coordinator_drive_rejected();
  test_node_callback_defers_without_driving();
  test_group_origin_sequences();
  test_hold_release_sequences();
  test_callback_requests_have_no_immediate_effect();
  test_settlement_stops_at_cancelled_item();
  test_late_activity_invalidates_waiting_ticket();
  test_enter_notify_op_matrix();
  test_enter_stage_faults_abort_cleanly();
  test_phase1_faults_keep_work_live();
  test_partial_carry_policy_matrix();
  test_carry_overflow_keeps_carry_fails_fresh();
  test_carry_abort_mid_settlement_restores_on_new_node();
  test_carry_same_id_replaced_by_fresh();
  test_carry_survives_history_eviction();
  test_retry_after_empty_carry_commit();
  test_settled_verdicts_survive_stale_jobs();
  test_evicted_origin_jobs_never_dispatch();
  test_request_storm_stays_bounded();
  test_callback_arguments_copied_at_receipt();
  test_abort_never_erases_committed_snapshot();
  test_sleep_path_uses_no_heap();
  if (failures == 0) {
    std::printf("power tests passed\n");
    return 0;
  }
  std::fprintf(stderr, "%d failures\n", failures);
  return 1;
}
