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
#include "routeloom/crc32.hpp"

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
static_assert(trusted_deep_sleep_reset(true, true));
static_assert(!trusted_deep_sleep_reset(false, true));
static_assert(!trusted_deep_sleep_reset(true, false));
using routeloom_test::CapturingObserver;
using routeloom_test::SimNetwork;
using routeloom_test::SimRadio;
using routeloom_test::SimReplyPort;
using routeloom_test::sim_rx_metadata;
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
  SimReplyPort reply_port;
  FakePowerPort port;
  RecordingPowerEvents events;
  MeshNode node;
  PowerCoordinator coordinator;
  MonotonicMs now{0};

  explicit PowerWorld(MemoryPowerStorage& store,
                      const PowerConfig& power = PowerConfig{500, 50})
      : storage(store), radio(net, kSelf), reply_port(radio, kSelf, 1),
        node(make_config(), radio, security, observer),
        coordinator(power, node, port, storage, events) {
    (void)node.set_reply_peer_port(&reply_port);
  }

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
      node.on_radio_receive(2, encoded.view(), sim_rx_metadata(&reply_port, 2),
                            now);
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
  CHECK(w.coordinator.sleep_abort("x", w.now).code == StatusCode::InvalidState);
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

void test_power_stats_accumulate() {
  // The coordinator retains its own sleep/wake/abort/awake account for
  // triage: counts accumulate in RAM (aborts and awake spans never
  // reboot), the last abort keeps its reason text, and wakes keep their
  // reset cause. A mesh pull reads this struct back after recovery.
  MemoryPowerStorage storage;
  PowerWorld w(storage);
  CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, 0));
  CHECK(w.coordinator.stats().aborts == 0);
  CHECK(w.coordinator.stats().sleeps == 0);
  CHECK(w.coordinator.stats().wakes == 0);
  CHECK(w.coordinator.stats().awake_ms == 0);
  CHECK(w.coordinator.stats().state == PowerState::Running);
  // An app-vetoed attempt: counted, bucketed as other (not a known
  // literal), last abort kept with its stamp.
  (void)reach_ready(w);
  const MonotonicMs abort_at = w.now;
  CHECK_OK(w.coordinator.sleep_abort("APP_VETO", w.now));
  PowerStats stats = w.coordinator.stats();
  CHECK(stats.aborts == 1);
  CHECK(stats.aborts_other == 1);
  CHECK(stats.aborts_storage == 0);
  CHECK(std::strcmp(stats.last_abort, "APP_VETO") == 0);
  CHECK(stats.last_abort_ms == abort_at);
  // Awake time accumulates on leaving Running: idle a span, then start
  // the next attempt and watch the span land.
  CHECK(stats.awake_ms == 0);
  w.pump(50);
  (void)reach_ready(w);
  CHECK(w.coordinator.stats().awake_ms >= 50);
  // A policy abort lands in its literal bucket.
  CHECK_OK(w.coordinator.notify_app_event(w.now));
  stats = w.coordinator.stats();
  CHECK(stats.aborts == 2);
  CHECK(stats.aborts_ticket_invalid == 1);
  CHECK(std::strcmp(stats.last_abort, "SLEEP_TICKET_INVALID") == 0);
  // A full sleep/wake cycle: sleeps, wakes, and the deep-sleep cause.
  SleepRequest request{};
  request.wake.wake_after_ms = 30000;
  CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
  CHECK(w.pump_until(PowerState::ReadyToSleep));
  const SleepTicket ticket = w.coordinator.ticket();
  CHECK_OK(w.coordinator.sleep_enter(ticket, w.now));
  const MonotonicMs wake_at = w.now + 100;
  CHECK_OK(w.coordinator.wake(ResetCause::DeepSleepWake,
                              ElapsedInterval{0, 0, false}, wake_at));
  stats = w.coordinator.stats();
  CHECK(stats.sleeps == 1);
  CHECK(stats.wakes == 1);
  CHECK(stats.deep_wakes == 1);
  CHECK(stats.last_wake_cause == ResetCause::DeepSleepWake);
  CHECK(stats.last_wake_ms == wake_at);
  CHECK(stats.state == PowerState::Running);
  CHECK(stats.last_to == PowerState::Running);
  CHECK(std::strcmp(stats.last_reason, "COLD_START") == 0);  // no peers: cold start
}


void test_ticket_invalidated_by_app_event() {
  MemoryPowerStorage storage;
  PowerWorld w(storage);
  CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, 0));
  const SleepTicket ticket = reach_ready(w);
  w.coordinator.notify_app_event(w.now);
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
  w.coordinator.notify_radio_reset(w.now);
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

void test_owner_sleep_waits_for_unfinished_delivery() {
  MemoryPowerStorage storage;
  PowerWorld w(storage);
  CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, 0));
  CHECK(!w.node.sleep_work_pending());
  const MessageId id = queue_pending(w, 99, false);
  CHECK(w.node.quiesced());  // no radio work, but the delivery is still live
  CHECK(w.node.sleep_work_pending());
  CHECK(w.node.settle_failed_sleep_work().code == StatusCode::Busy);
  CHECK(w.node.set_draining(true).ok());
  CHECK_OK(w.node.settle_failed_sleep_work());
  CHECK(w.node.delivery(id).state == DeliveryState::Failed);
  CHECK(std::strcmp(w.node.delivery(id).reason, "SLEEP_DRAIN") == 0);
  CHECK(!w.node.sleep_work_pending());
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
  CHECK_OK(w.coordinator.sleep_abort("APP_CHANGED_MIND", w.now));
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

void test_sleep_elapsed_upper_bound() {
  using routeloom::bound_sleep_elapsed_upper_ms;
  using routeloom::kSleepElapsedBootMarginMs;
  // Untrusted shapes stay 0: cold/other reset, non-timer wake, missing
  // marker, or a zero programmed duration never bounds anything.
  CHECK(bound_sleep_elapsed_upper_ms(false, true, true, 60000, 100) == 0);
  CHECK(bound_sleep_elapsed_upper_ms(true, false, true, 60000, 100) == 0);
  CHECK(bound_sleep_elapsed_upper_ms(true, true, false, 60000, 100) == 0);
  CHECK(bound_sleep_elapsed_upper_ms(true, true, true, 0, 100) == 0);
  // A marked timer wake: twice programmed (drift) + boot margin + awake.
  CHECK(bound_sleep_elapsed_upper_ms(true, true, true, 60000, 100) ==
        120000 + kSleepElapsedBootMarginMs + 100);
  CHECK(bound_sleep_elapsed_upper_ms(true, true, true, 60000, 0) ==
        120000 + kSleepElapsedBootMarginMs);
  // Saturates instead of wrapping: a huge programmed duration still
  // yields a (uselessly large, cold-resuming) bound, never a small one.
  CHECK(bound_sleep_elapsed_upper_ms(true, true, true, 0xFFFFFFFFU, 0xFFFFFFFFU) ==
        0xFFFFFFFFU);
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
  SimReplyPort reply_b(radio_b, 2, config_b.link_epoch);
  MeshNode b(config_b, radio_b, security_b, observer_b);
  CHECK_OK(b.set_reply_peer_port(&reply_b));
  w.net.register_node(7, &w.node);
  w.net.register_node(2, &b);
  w.net.register_reply_port(7, &w.reply_port);
  w.net.register_reply_port(2, &reply_b);
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

void test_unknown_sleep_schema_is_not_overwritten() {
  MemoryPowerStorage storage;
  {
    PowerWorld w(storage);
    w.platform_peer(2, 0xaa);
    CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                                 ElapsedInterval{0, 0, false}, w.now));
    w.pump(60);
    (void)queue_pending(w, 2, true, 5000);
    CHECK(reach_ready(w).issued);  // pending image in slot 1
  }
  std::array<std::uint8_t, kPowerImageRecordSize> record{};
  CHECK_OK(storage.read(1, MutableByteView{record.data(), record.size()}));
  record[5] = 2;  // valid future schema, same image including pending payload
  const auto crc = crc32_iso_hdlc(ByteView{record.data(), record.size() - 4});
  for (int i = 0; i < 4; ++i) record[record.size() - 4 + i] =
      static_cast<std::uint8_t>(crc >> (24 - 8 * i));
  CHECK_OK(storage.write(1, ByteView{record.data(), record.size()}));
  const auto before = storage.write_calls;
  PowerWorld restarted(storage);
  CHECK_OK(restarted.coordinator.begin(ResetCause::ColdBoot,
                                       ElapsedInterval{0, 0, false}, restarted.now));
  CHECK(restarted.events.has_diag("SLEEP_IMAGE_SCHEMA_UNSUPPORTED"));
  SleepRequest request{};
  // Unknown durable state must prevent a new sleep commit.
  CHECK(restarted.coordinator.sleep_prepare(request, restarted.now).code ==
        StatusCode::CounterExhausted);
  CHECK(storage.write_calls == before);
  std::array<std::uint8_t, kPowerImageRecordSize> retained{};
  CHECK_OK(storage.read(1, MutableByteView{retained.data(), retained.size()}));
  CHECK(retained == record);
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
  SimReplyPort reply_b(radio_b, 2, config_b.link_epoch);
  MeshNode b(config_b, radio_b, security_b, observer_b);
  CHECK_OK(b.set_reply_peer_port(&reply_b));
  w.net.register_node(7, &w.node);
  w.net.register_node(2, &b);
  w.net.register_reply_port(7, &w.reply_port);
  w.net.register_reply_port(2, &reply_b);
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
  SimReplyPort reply_b{radio_b, 2, make_b_config().link_epoch};
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
    CHECK_OK(b.set_reply_peer_port(&reply_b));
    w.net.register_node(PowerWorld::kSelf, &w.node);
    w.net.register_node(2, &b);
    w.net.register_reply_port(PowerWorld::kSelf, &w.reply_port);
    w.net.register_reply_port(2, &reply_b);
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
  SimReplyPort reply_a;
  SimReplyPort reply_b;
  MeshNode a;
  MeshNode b;
  FakePowerPort port;
  RecordingPowerEvents events;
  MonotonicMs now{0};

  GroupPowerWorld()
      : radio_a(net, kGateway), radio_b(net, kLeaf),
        reply_a(radio_a, kGateway, config(kGateway).link_epoch),
        reply_b(radio_b, kLeaf, config(kLeaf).link_epoch),
        a(config(kGateway), radio_a, security_a, observer_a),
        b(config(kLeaf), radio_b, security_b, observer_b) {
    (void)a.set_reply_peer_port(&reply_a);
    (void)b.set_reply_peer_port(&reply_b);
    net.register_node(kGateway, &a);
    net.register_node(kLeaf, &b);
    net.register_reply_port(kGateway, &reply_a);
    net.register_reply_port(kLeaf, &reply_b);
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
  CHECK(w.a.sleep_work_pending());
  SleepRequest request{};
  request.pending_policy = SleepWorkPolicy::Fail;
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
  CHECK(w.events.saw(PowerState::Draining, PowerState::Persisting,
                     "DRAIN_DEADLINE"));
  const auto result = w.a.group_delivery(id);
  CHECK(result.state == DeliveryState::Failed);
  CHECK(!w.a.sleep_work_pending());
  CHECK(std::strcmp(result.reason, "SLEEP_DRAIN") == 0);
  const auto last = last_group_result(w.observer_a);
  CHECK(last.id == id && last.state == DeliveryState::Failed &&
        std::strcmp(last.reason, "SLEEP_DRAIN") == 0);
}

void test_owner_sleep_deadline_settles_group_origin() {
  GroupPowerWorld w;
  w.converge();
  drop_all_reports();
  w.net.drop_frame = group_loss_hook;
  GroupSendOptions options{};
  const MessageId id = w.send_all(w.a, options);
  CHECK(w.a.sleep_work_pending());
  CHECK_OK(w.a.set_draining(true));
  CHECK_OK(w.a.settle_failed_sleep_work());
  const auto result = w.a.group_delivery(id);
  CHECK(result.state == DeliveryState::Failed);
  CHECK(std::strcmp(result.reason, "SLEEP_DRAIN") == 0);
  CHECK(!w.a.sleep_work_pending());
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

void test_group_settled_callback_abort_busy_send_refused() {
  // Inside the SLEEP_DRAIN terminal event the app tries to veto the sleep
  // and sends again: the abort is Busy (no re-entry from callbacks), so
  // the settlement runs on to READY_TO_SLEEP, and the send is refused with
  // NODE_DRAINING and creates no origin. The app aborts after observing
  // READY and resends after RUNNING (#110: an abort never reopens
  // admission inside its own callback because it never runs there).
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
    abort_status = coordinator.sleep_abort("APP_VETO", w.now);
    send_status = w.a.send_group(kGroupAll,
                                 ByteView{again.data(), again.size()},
                                 options, w.now, new_id);
  };
  SleepRequest request{};
  request.pending_policy = SleepWorkPolicy::Fail;
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
  CHECK(callback_state == PowerState::Persisting);
  CHECK(abort_status.code == StatusCode::Busy);
  CHECK(std::strcmp(abort_status.detail, "POWER_IN_CALLBACK") == 0);
  CHECK(!send_status.ok());
  CHECK(std::strcmp(send_status.detail, "NODE_DRAINING") == 0);
  CHECK(w.events.saw(PowerState::Persisting, PowerState::ReadyToSleep,
                     "SLEEP_READY"));
  CHECK(coordinator.ticket_valid(coordinator.ticket()));
  // The refused send created nothing: the app aborts from outside, then
  // sends afresh after RUNNING, and the new origin runs to Delivered once
  // reports flow again.
  CHECK(w.a.group_delivery(new_id).state == DeliveryState::Empty);
  CHECK_OK(coordinator.sleep_abort("APP_VETO", w.now));
  CHECK(coordinator.state() == PowerState::Running);
  w.net.drop_frame = nullptr;
  MessageId retry{};
  CHECK_OK(w.a.send_group(kGroupAll, ByteView{again.data(), again.size()},
                          options, w.now, retry));
  w.run(500);
  const auto done = w.a.group_delivery(retry);
  CHECK(done.state == DeliveryState::Delivered);
}

void test_unicast_disposition_callback_abort_busy_send_refused() {
  // Same ban through the unicast disposition: the abort inside on_delivery
  // is Busy (the settlement completes to READY_TO_SLEEP), the send inside
  // the same callback is refused with NODE_DRAINING, and the abort + resend
  // from outside complete (#110, unicast leg of the test above).
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
    abort_status = coordinator.sleep_abort("APP_VETO", w.now);
    send_status = w.a.send(GroupPowerWorld::kLeaf,
                           ByteView{payload.data(), payload.size()},
                           send_options, w.now, new_id);
  };
  SleepRequest request{};
  request.pending_policy = SleepWorkPolicy::Fail;
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
  CHECK(abort_status.code == StatusCode::Busy);
  CHECK(std::strcmp(abort_status.detail, "POWER_IN_CALLBACK") == 0);
  CHECK(!send_status.ok());
  CHECK(std::strcmp(send_status.detail, "NODE_DRAINING") == 0);
  CHECK(w.events.saw(PowerState::Persisting, PowerState::ReadyToSleep,
                     "SLEEP_READY"));
  CHECK_OK(coordinator.sleep_abort("APP_VETO", w.now));
  CHECK(coordinator.state() == PowerState::Running);
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

void test_callback_abort_prepare_abort_busy_outside_works() {
  // abort->prepare->abort from a settlement callback are all Busy — no
  // request is recorded, so the attempt is never cancelled and settles
  // BOTH origins under the ORIGINAL Fail policy, reaching READY_TO_SLEEP
  // with a valid ticket. After the callback, the same calls work: an
  // outside abort lands in RUNNING, and a new send + Defer prepare
  // settles under the new policy (#110).
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

  std::vector<StatusCode> got;
  w.observer_a.on_group_fn = [&](const GroupDeliveryResult& result) {
    if (!got.empty() || result.state != DeliveryState::Failed ||
        std::strcmp(result.reason, "SLEEP_DRAIN") != 0) {
      return;  // act once, on the first settled origin
    }
    got.push_back(coordinator.sleep_abort("FIRST", w.now).code);
    SleepRequest retry{};
    retry.pending_policy = SleepWorkPolicy::Defer;
    got.push_back(coordinator.sleep_prepare(retry, w.now).code);
    got.push_back(coordinator.sleep_abort("SECOND", w.now).code);
  };
  SleepRequest request{};
  request.pending_policy = SleepWorkPolicy::Fail;
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
  CHECK(got.size() == 3);
  for (const StatusCode code : got) {
    CHECK(code == StatusCode::Busy);
  }
  // Both origins settled under the undisturbed Fail attempt.
  CHECK(w.a.group_delivery(id1).state == DeliveryState::Failed);
  CHECK(std::strcmp(w.a.group_delivery(id1).reason, "SLEEP_DRAIN") == 0);
  CHECK(w.a.group_delivery(id2).state == DeliveryState::Failed);
  CHECK(std::strcmp(w.a.group_delivery(id2).reason, "SLEEP_DRAIN") == 0);
  CHECK(coordinator.ticket_valid(coordinator.ticket()));
  // Outside the callback the same calls work: abort, resend, reprepare.
  CHECK_OK(coordinator.sleep_abort("APP_VETO", w.now));
  CHECK(coordinator.state() == PowerState::Running);
  const MessageId id3 = w.send_all(w.a, options);  // seq 3
  SleepRequest retry{};
  retry.pending_policy = SleepWorkPolicy::Defer;
  CHECK_OK(coordinator.sleep_prepare(retry, w.now));
  CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
  CHECK(w.a.group_delivery(id3).state == DeliveryState::Indeterminate);
  CHECK(std::strcmp(w.a.group_delivery(id3).reason, "SLEEP_DEFERRED") == 0);
}

void test_poll_delivery_callback_abort_busy_drain_continues() {
  // A delivery callback fired by node_.poll() mid-drain (GROUP_INCOMPLETE
  // expiry) cannot veto the sleep: the abort is Busy, the same poll rolls
  // into the settlement and reaches READY_TO_SLEEP, and an outside abort
  // afterwards still works (#110).
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
      abort_status = coordinator.sleep_abort("APP_VETO", w.now);
    }
  };
  SleepRequest request{};
  request.pending_policy = SleepWorkPolicy::Fail;
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
  CHECK(abort_status.code == StatusCode::Busy);
  CHECK(w.events.saw(PowerState::Persisting, PowerState::ReadyToSleep,
                     "SLEEP_READY"));
  CHECK(coordinator.ticket_valid(coordinator.ticket()));
  CHECK_OK(coordinator.sleep_abort("APP_VETO", w.now));
  CHECK(coordinator.state() == PowerState::Running);
  CHECK(!coordinator.ticket().issued);
}

void test_settlement_callback_app_event_busy_ticket_survives() {
  // App activity signalled inside a settlement callback is Busy — the
  // ticket is still issued honestly. Activity signalled from OUTSIDE
  // afterwards aborts to RUNNING at once with SLEEP_TICKET_INVALID (#110).
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

  Status event_status = Status::error(StatusCode::InternalError, "not run");
  w.observer_a.on_group_fn = [&](const GroupDeliveryResult& result) {
    if (result.state == DeliveryState::Failed &&
        std::strcmp(result.reason, "SLEEP_DRAIN") == 0) {
      event_status = coordinator.notify_app_event(w.now);
    }
  };
  SleepRequest request{};
  request.pending_policy = SleepWorkPolicy::Fail;
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
  CHECK(event_status.code == StatusCode::Busy);
  CHECK(std::strcmp(event_status.detail, "POWER_IN_CALLBACK") == 0);
  CHECK(w.events.saw(PowerState::Persisting, PowerState::ReadyToSleep,
                     "SLEEP_READY"));
  CHECK(coordinator.ticket_valid(coordinator.ticket()));
  CHECK(!w.events.has_diag("SLEEP_TICKET_INVALID"));
  CHECK_OK(coordinator.notify_app_event(w.now));
  CHECK(coordinator.state() == PowerState::Running);
  CHECK(w.events.has_diag("SLEEP_TICKET_INVALID"));
}

void test_ready_transition_callback_abort_busy_ticket_survives() {
  // The SLEEP_READY transition notification is an app callback: the state is
  // already READY when it runs (post-state notification), and an abort
  // inside it is Busy — the machine stays READY with a valid ticket. An
  // outside abort then lands in RUNNING with SLEEP_ABORTED history and no
  // platform enter (#110).
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
      abort_status = coordinator.sleep_abort("APP_VETO", w.now);
    }
  };
  SleepRequest request{};
  request.pending_policy = SleepWorkPolicy::Fail;
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
  CHECK(callback_state == PowerState::ReadyToSleep);
  CHECK(abort_status.code == StatusCode::Busy);
  CHECK(std::strcmp(abort_status.detail, "POWER_IN_CALLBACK") == 0);
  CHECK(coordinator.state() == PowerState::ReadyToSleep);
  CHECK(coordinator.ticket_valid(coordinator.ticket()));
  CHECK(w.events.saw(PowerState::Persisting, PowerState::ReadyToSleep,
                     "SLEEP_READY"));
  CHECK_OK(coordinator.sleep_abort("APP_VETO", w.now));
  CHECK(coordinator.state() == PowerState::Running);
  CHECK(!coordinator.ticket().issued);
  CHECK(w.events.saw(PowerState::ReadyToSleep, PowerState::Running,
                     "SLEEP_ABORTED"));
  CHECK(w.port.sleep_calls == 0);
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

void test_poll_unicast_callback_abort_busy_drain_continues() {
  // Unicast leg of the mid-drain expiry test: the abort from the
  // node_.poll() expiry event is Busy, the same poll rolls into the
  // settlement and reaches READY_TO_SLEEP, and an outside abort afterwards
  // still works (#110).
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
      abort_status = coordinator.sleep_abort("APP_VETO", w.now);
    }
  };
  SleepRequest request{};
  request.pending_policy = SleepWorkPolicy::Fail;
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
  CHECK(abort_status.code == StatusCode::Busy);
  CHECK(w.events.saw(PowerState::Persisting, PowerState::ReadyToSleep,
                     "SLEEP_READY"));
  CHECK(coordinator.ticket_valid(coordinator.ticket()));
  CHECK_OK(coordinator.sleep_abort("APP_VETO", w.now));
  CHECK(coordinator.state() == PowerState::Running);
}

void test_unicast_settlement_callback_app_event_busy() {
  // Unicast leg of the settlement app-event test: activity signalled from
  // a SLEEP_DRAIN on_delivery is Busy — the ticket is still issued — and
  // activity from OUTSIDE afterwards aborts at once (#110).
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

  Status event_status = Status::error(StatusCode::InternalError, "not run");
  w.observer_a.on_delivery_fn = [&](const DeliveryResult& result) {
    if (result.state == DeliveryState::Failed &&
        std::strcmp(result.reason, "SLEEP_DRAIN") == 0) {
      event_status = coordinator.notify_app_event(w.now);
    }
  };
  SleepRequest request{};
  request.pending_policy = SleepWorkPolicy::Fail;
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
  CHECK(event_status.code == StatusCode::Busy);
  CHECK(w.events.saw(PowerState::Persisting, PowerState::ReadyToSleep,
                     "SLEEP_READY"));
  CHECK(!w.events.has_diag("SLEEP_TICKET_INVALID"));
  CHECK_OK(coordinator.notify_app_event(w.now));
  CHECK(coordinator.state() == PowerState::Running);
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

void test_save_outside_abort_retry_fail() {
  // A Save attempt aborted from OUTSIDE during the drain (before the
  // settlement) commits nothing: both deliveries stay live. The Fail retry
  // fails both after its own commit, and a fresh node waking from the same
  // storage re-injects nothing. Slot hygiene: corrupting the newest slot
  // still restores nothing — the retry dual-wrote its candidate (#110).
  // (A mid-settlement abort is impossible: callbacks are Busy, so the
  // settlement always completes.)
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

  SleepRequest request{};
  request.pending_policy = SleepWorkPolicy::Save;
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  CHECK(coordinator.state() == PowerState::Draining);
  CHECK_OK(coordinator.sleep_abort("APP_VETO", w.now));
  CHECK(coordinator.state() == PowerState::Running);
  CHECK(storage.write_calls == 0);  // aborted before the settlement commit
  CHECK(!sleep_verdict_terminal(w.a.delivery(id_a).state));
  CHECK(!sleep_verdict_terminal(w.a.delivery(id_b).state));

  SleepRequest retry{};
  retry.pending_policy = SleepWorkPolicy::Fail;
  CHECK_OK(coordinator.sleep_prepare(retry, w.now));
  CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
  CHECK(w.a.delivery(id_a).state == DeliveryState::Failed);
  CHECK(std::strcmp(w.a.delivery(id_a).reason, "SLEEP_DRAIN") == 0);
  CHECK(w.a.delivery(id_b).state == DeliveryState::Failed);
  CHECK(std::strcmp(w.a.delivery(id_b).reason, "SLEEP_DRAIN") == 0);
  CHECK_OK(coordinator.sleep_enter(coordinator.ticket(), w.now));

  // A fresh node on the same storage re-injects nothing.
  GroupPowerWorld fresh;
  FakePowerPort fresh_port;
  RecordingPowerEvents fresh_events;
  PowerCoordinator woken(PowerConfig{500, 50}, fresh.a, fresh_port, storage,
                         fresh_events);
  CHECK_OK(woken.begin(ResetCause::DeepSleepWake,
                       ElapsedInterval{100, 200, true}, fresh.now));
  CHECK(fresh_events.pending_results.empty());

  // Slot hygiene: even when the newest slot is lost, the fallback slot
  // restores nothing either.
  storage.corrupt(static_cast<std::uint8_t>(storage.last_slot), 10);
  GroupPowerWorld fallback;
  FakePowerPort fallback_port;
  RecordingPowerEvents fallback_events;
  PowerCoordinator woken2(PowerConfig{500, 50}, fallback.a, fallback_port,
                          storage, fallback_events);
  CHECK_OK(woken2.begin(ResetCause::DeepSleepWake,
                        ElapsedInterval{100, 200, true}, fallback.now));
  CHECK(fallback_events.pending_results.empty());
}

void test_save_outside_abort_durable_saved_again() {
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

  SleepRequest request{};
  request.pending_policy = SleepWorkPolicy::Save;
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  CHECK_OK(coordinator.sleep_abort("APP_VETO", w.now));
  CHECK(coordinator.state() == PowerState::Running);
  SleepRequest retry{};
  retry.pending_policy = SleepWorkPolicy::Fail;
  CHECK_OK(coordinator.sleep_prepare(retry, w.now));
  CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
  CHECK(w.a.delivery(id_a).state == DeliveryState::Failed);
  CHECK(std::strcmp(w.a.delivery(id_a).reason, "SLEEP_DRAIN") == 0);
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
  CHECK(pending_results_for(fresh_events, id_a, StatusCode::Ok) == 0);
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

void test_tx_notice_callback_busy_quiesce_completes() {
  // A service job is stuck in physical TX at the drain deadline. The
  // SLEEP_TX_INFLIGHT diagnostic fires; its callback's abort is Busy and
  // its send is refused — the quiesce then completes honestly (radio
  // quiesced, ticket issued): the stuck frame was reported unknown and is
  // dropped by the teardown, never reported as sent (#110).
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
    abort_status = coordinator.sleep_abort("APP_VETO", w.now);
    MessageId retry{};
    SendOptions send_options{};
    send_status = w.a.send(GroupPowerWorld::kLeaf,
                           ByteView{payload.data(), payload.size()},
                           send_options, w.now, retry);
  };
  SleepRequest request{};
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  // Drive WITHOUT flushing the network: the physical TX result never lands
  // before the quiesce.
  for (int i = 0; i < 400 && !noticed; ++i) {
    coordinator.poll(w.now);
    w.b.poll(w.now);
    w.now += 5;
  }
  CHECK(noticed);
  CHECK(callback_state == PowerState::Persisting);
  CHECK(abort_status.code == StatusCode::Busy);
  CHECK(!send_status.ok());
  // The quiesce holds the node's non-reentrancy guard while the diagnostic
  // fires, so the callback's send is Busy — still refused, never queued.
  CHECK(send_status.code == StatusCode::Busy);
  CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
  CHECK(w.events.saw(PowerState::Persisting, PowerState::ReadyToSleep,
                     "SLEEP_READY"));
  CHECK(coordinator.ticket_valid(coordinator.ticket()));
  CHECK(w.port.quiesce_calls == 1);
  // The stuck job was dropped by the teardown: its late TX result resolves
  // to nothing (STALE_TX_CALLBACK), and the exchange never completes.
  CHECK_OK(coordinator.sleep_abort("APP_VETO", w.now));
  for (int i = 0; i < 200; ++i) {
    w.a.poll(w.now);
    w.b.poll(w.now);
    w.net.flush(w.now);
    w.now += 5;
  }
  CHECK(sink.calls == 0);
  CHECK(w.observer_a.has_diag("STALE_TX_CALLBACK"));
  (void)service_id;
}

void test_sleep_hold_release_callback_busy_releases_all() {
  // ORDERED seq 2 is lost; seq 3 AND 4 are held. The sleep release hands
  // both to the app: the abort from the seq-3 callback is Busy, so the
  // release continues — {1, 3, 4} delivered exactly once, no holds left,
  // cursor at 5, the seq-2 gap counted once — and the attempt reaches
  // READY_TO_SLEEP (#110: one message per release, no trailing drain).
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
      abort_status = coordinator.sleep_abort("APP_VETO", w.now);
    }
  };
  SleepRequest request{};
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  CHECK(w.run_until(coordinator, w.a, PowerState::ReadyToSleep));
  CHECK(abort_status.code == StatusCode::Busy);
  CHECK(w.observer_b.group_messages.size() == 3);
  if (w.observer_b.group_messages.size() == 3) {
    CHECK(w.observer_b.group_messages[0].info.group_seq == 1);
    CHECK(w.observer_b.group_messages[1].info.group_seq == 3);
    CHECK(!w.observer_b.group_messages[1].info.late);
    CHECK(w.observer_b.group_messages[2].info.group_seq == 4);
    CHECK(!w.observer_b.group_messages[2].info.late);
  }
  CHECK(w.b.group_holds_in_use() == 0);
  std::uint32_t next_seq = 0;
  w.b.for_each_group_stream([&](const GroupStreamSnapshot& stream) {
    if (stream.source == GroupPowerWorld::kGateway) next_seq = stream.next_seq;
  });
  CHECK(next_seq == 5);
  CHECK(w.b.group_stats().gaps_skipped == 1);
  // An outside abort afterwards still works.
  CHECK_OK(coordinator.sleep_abort("APP_VETO", w.now));
  CHECK(coordinator.state() == PowerState::Running);
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
  SimReplyPort p1;
  SimReplyPort p2;
  SimReplyPort p3;
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
        p1(r1, kGw1, config(kGw1).link_epoch),
        p2(r2, kGw2, config(kGw2).link_epoch),
        p3(r3, kLeaf, config(kLeaf).link_epoch),
        n1(config(kGw1), r1, s1, o1),
        n2(config(kGw2), r2, s2, o2),
        n3(config(kLeaf), r3, s3, o3) {
    (void)n1.set_reply_peer_port(&p1);
    (void)n2.set_reply_peer_port(&p2);
    (void)n3.set_reply_peer_port(&p3);
    net.register_node(kGw1, &n1);
    net.register_node(kGw2, &n2);
    net.register_node(kLeaf, &n3);
    net.register_reply_port(kGw1, &p1);
    net.register_reply_port(kGw2, &p2);
    net.register_reply_port(kLeaf, &p3);
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

void test_sleep_hold_release_callback_busy_multi_stream() {
  // Two sources, one sleeper: the leaf holds one ORDERED message per stream
  // (both seq 3, both missing seq 2). The release takes the lowest (seq,
  // source) first — source 1 — and its callback's abort is Busy, so the
  // other stream's hold releases next in the same attempt: both delivered
  // exactly once, in stable cross-stream order, and the attempt reaches
  // READY_TO_SLEEP (#110).
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
  w.o3.on_group_message_fn = [&](const GroupMessageInfo&, ByteView) {
    if (abort_status.code == StatusCode::InternalError) {
      abort_status = coordinator.sleep_abort("APP_VETO", w.now);
    }
  };
  SleepRequest request{};
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  CHECK(w.run_until(coordinator, PowerState::ReadyToSleep));
  CHECK(abort_status.code == StatusCode::Busy);
  CHECK(w.o3.group_messages.size() == 4);
  if (w.o3.group_messages.size() == 4) {
    CHECK(w.o3.group_messages[2].info.key.origin == TwoSourceWorld::kGw1);
    CHECK(w.o3.group_messages[2].info.group_seq == 3);
    CHECK(w.o3.group_messages[3].info.key.origin == TwoSourceWorld::kGw2);
    CHECK(w.o3.group_messages[3].info.group_seq == 3);
  }
  CHECK(w.n3.group_holds_in_use() == 0);
  std::uint32_t next1 = 0;
  std::uint32_t next2 = 0;
  w.n3.for_each_group_stream([&](const GroupStreamSnapshot& stream) {
    if (stream.source == TwoSourceWorld::kGw1) next1 = stream.next_seq;
    if (stream.source == TwoSourceWorld::kGw2) next2 = stream.next_seq;
  });
  CHECK(next1 == 4);
  CHECK(next2 == 4);
}

void test_carry_expired_callback_app_event_busy() {
  // A retained record expires while awake. At the next sleep its Expired
  // result is notified AFTER the phase-1 commit; activity signalled from
  // that callback is Busy — the attempt still completes to READY — and
  // the consumed Expired is never re-notified nor re-injected (#110).
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
    Status event_status = Status::error(StatusCode::InternalError, "not run");
    w.events.on_pending_result_fn = [&](const PendingDeliveryRecord&,
                                        StatusCode code) {
      if (code == StatusCode::Expired &&
          event_status.code == StatusCode::InternalError) {
        writes_at_notify = storage.write_calls;
        event_status = w.coordinator.notify_app_event(w.now);
      }
    };
    SleepRequest request{};
    CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
    CHECK(w.pump_until(PowerState::ReadyToSleep));
    CHECK(event_status.code == StatusCode::Busy);
    // The notification moved past the commit: the image landed first.
    CHECK(writes_at_notify > writes_before_prepare);
    CHECK(w.events.saw(PowerState::Persisting, PowerState::ReadyToSleep,
                       "SLEEP_READY"));
    CHECK(w.coordinator.ticket_valid(w.coordinator.ticket()));
    CHECK(!w.events.has_diag("SLEEP_TICKET_INVALID"));
    // The consumed Expired is gone for good: no duplicate, no re-injection.
    CHECK(w.events.pending_with(StatusCode::Expired) == 1);
    CHECK_OK(w.coordinator.sleep_enter(w.coordinator.ticket(), w.now));
    CHECK_OK(w.coordinator.wake(ResetCause::DeepSleepWake,
                                ElapsedInterval{0, 0, true}, w.now));
    CHECK(w.events.pending_with(StatusCode::Ok) == 0);
  }
}

void test_enter_expired_callback_app_event_busy() {
  // A durable pending expires while its ticket waits. sleep_enter refreshes
  // and commits first, then notifies Expired; activity from that callback
  // is Busy — the entry COMPLETES, the platform handoff runs — and the
  // consumed record is never re-injected (#110).
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
  Status event_status = Status::error(StatusCode::InternalError, "not run");
  w.events.on_pending_result_fn = [&](const PendingDeliveryRecord&,
                                      StatusCode code) {
    if (code == StatusCode::Expired &&
        event_status.code == StatusCode::InternalError) {
      event_status = w.coordinator.notify_app_event(w.now);
    }
  };
  CHECK_OK(w.coordinator.sleep_enter(ticket, w.now));
  CHECK(event_status.code == StatusCode::Busy);
  // The refresh landed before the notification (dual slot update).
  CHECK(storage.write_calls == writes_before_enter + 2);
  CHECK(w.coordinator.state() == PowerState::Sleeping);
  CHECK(w.port.wakecfg_calls == 1);
  CHECK(w.port.sleep_calls == 1);
  CHECK(w.events.pending_with(StatusCode::Expired) == 1);
  // The consumed record stays gone: the wake re-injects nothing.
  CHECK_OK(w.coordinator.wake(ResetCause::DeepSleepWake,
                              ElapsedInterval{0, 0, true}, w.now));
  CHECK(w.events.pending_with(StatusCode::Ok) == 0);
  CHECK(w.events.pending_with(StatusCode::Expired) == 1);
}

// Flat-profiled single-node world with hookable observers for the matrix.
struct MatrixWorld {
  MemoryPowerStorage storage;
  TestSecurity security;
  HookedObserver observer;
  SimNetwork net;
  SimRadio radio;
  SimReplyPort reply_port;
  FakePowerPort port;
  RecordingPowerEvents events;
  MeshNode node;
  PowerCoordinator coordinator;
  MonotonicMs now{0};

  MatrixWorld()
      : radio(net, 7), reply_port(radio, 7, make_config().link_epoch),
        node(make_config(), radio, security, observer),
        coordinator(PowerConfig{500, 50}, node, port, storage, events) {
    (void)node.set_reply_peer_port(&reply_port);
  }

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

// --- Section 9.3: the callback re-entry ban -----------------------------------
// Every application callback the coordinator issues — through PowerEvents
// or through the node — Busy-rejects every mutating coordinator call and
// freezes the machine: no state, mask, ticket, storage or radio effect,
// and poll() is a silent no-op. One table crosses every callback family
// with every mutating op; each cell then verifies the natural completion
// (the callback changed nothing, so the attempt always continues to its
// undisturbed end).

enum class BanOp : std::uint8_t {
  Abort = 0,
  Prepare,
  AppEvent,
  RadioReset,
  Enter,
  Wake,
  Begin,
};

const BanOp kBanOps[] = {
    BanOp::Abort,   BanOp::Prepare, BanOp::AppEvent, BanOp::RadioReset,
    BanOp::Enter,   BanOp::Wake,    BanOp::Begin,
};

Status run_ban_op(BanOp op, PowerCoordinator& coordinator, MonotonicMs now) {
  switch (op) {
    case BanOp::Abort:
      return coordinator.sleep_abort("BAN", now);
    case BanOp::Prepare: {
      SleepRequest request{};
      return coordinator.sleep_prepare(request, now);
    }
    case BanOp::AppEvent:
      return coordinator.notify_app_event(now);
    case BanOp::RadioReset:
      return coordinator.notify_radio_reset(now);
    case BanOp::Enter:
      return coordinator.sleep_enter(coordinator.ticket(), now);
    case BanOp::Wake:
      return coordinator.wake(ResetCause::DeepSleepWake,
                              ElapsedInterval{0, 0, false}, now);
    case BanOp::Begin:
      return coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, now);
  }
  return Status::error(StatusCode::InternalError, "unreachable");
}

// Machine state observable from inside a callback: the ban requires every
// mutating call to leave all of it untouched.
struct BanFreeze {
  PowerState state{PowerState::Running};
  bool draining{false};
  bool ticket_issued{false};
  std::size_t transitions{0};
  std::size_t write_calls{0};
  int quiesce_calls{0};
  int wakecfg_calls{0};
  int sleep_calls{0};
};

BanFreeze capture_freeze(PowerCoordinator& coordinator, const MeshNode& node,
                         const RecordingPowerEvents& events,
                         const MemoryPowerStorage& storage,
                         const FakePowerPort& port) {
  return BanFreeze{coordinator.state(),
                   node.draining(),
                   coordinator.ticket().issued,
                   events.transitions.size(),
                   storage.write_calls,
                   port.quiesce_calls,
                   port.wakecfg_calls,
                   port.sleep_calls};
}

bool same_freeze(const BanFreeze& a, const BanFreeze& b) {
  return a.state == b.state && a.draining == b.draining &&
         a.ticket_issued == b.ticket_issued &&
         a.transitions == b.transitions && a.write_calls == b.write_calls &&
         a.quiesce_calls == b.quiesce_calls &&
         a.wakecfg_calls == b.wakecfg_calls &&
         a.sleep_calls == b.sleep_calls;
}

struct BanProbe {
  BanOp op;
  const char* family;
  bool ran{false};
  // Runs inside the callback: the machine must already sit at the
  // family's undisturbed point, the op must be Busy and change nothing,
  // and the poll() afterwards must be a silent no-op too.
  void fire(PowerCoordinator& coordinator, MeshNode& node,
            RecordingPowerEvents& events, MemoryPowerStorage& storage,
            FakePowerPort& port, MonotonicMs now, PowerState want_state,
            bool want_draining, bool want_ticket) {
    if (ran) return;
    ran = true;
    if (coordinator.state() != want_state ||
        node.draining() != want_draining ||
        coordinator.ticket().issued != want_ticket) {
      std::fprintf(stderr,
                   "ban frozen mismatch: family=%s op=%d state=%d/%d "
                   "draining=%d/%d ticket=%d/%d\n",
                   family, static_cast<int>(op),
                   static_cast<int>(coordinator.state()),
                   static_cast<int>(want_state), node.draining() ? 1 : 0,
                   want_draining ? 1 : 0,
                   coordinator.ticket().issued ? 1 : 0,
                   want_ticket ? 1 : 0);
    }
    CHECK(coordinator.state() == want_state);
    CHECK(node.draining() == want_draining);
    CHECK(coordinator.ticket().issued == want_ticket);
    const BanFreeze before =
        capture_freeze(coordinator, node, events, storage, port);
    const Status got = run_ban_op(op, coordinator, now);
    if (got.code != StatusCode::Busy ||
        std::strcmp(got.detail, "POWER_IN_CALLBACK") != 0) {
      std::fprintf(stderr, "ban mismatch: family=%s op=%d got=(%d,'%s')\n",
                   family, static_cast<int>(op), static_cast<int>(got.code),
                   got.detail);
    }
    CHECK(got.code == StatusCode::Busy);
    CHECK(std::strcmp(got.detail, "POWER_IN_CALLBACK") == 0);
    coordinator.poll(now);  // silent no-op inside the callback
    CHECK(same_freeze(before, capture_freeze(coordinator, node, events,
                                             storage, port)));
  }
};

void ban_family_settle_delivery(BanOp op) {
  MatrixWorld w;
  CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  w.pump(60);
  const std::array<std::uint8_t, 3> payload{{'b', 'a', 'n'}};
  MessageId id{};
  SendOptions send_options{};
  send_options.lifetime_ms = 5000;
  CHECK_OK(w.node.send(9, ByteView{payload.data(), payload.size()},
                       send_options, w.now, id));
  BanProbe probe{op, "settle_delivery"};
  w.observer.on_delivery_fn = [&](const DeliveryResult& result) {
    if (result.state == DeliveryState::Failed &&
        std::strcmp(result.reason, "SLEEP_DRAIN") == 0) {
      probe.fire(w.coordinator, w.node, w.events, w.storage, w.port, w.now,
                 PowerState::Persisting, true, false);
    }
  };
  SleepRequest request{};
  CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
  CHECK(w.pump_until(PowerState::ReadyToSleep));
  CHECK(probe.ran);
}

void ban_family_settle_group(BanOp op) {
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
  BanProbe probe{op, "settle_group"};
  w.observer_a.on_group_fn = [&](const GroupDeliveryResult& result) {
    if (result.state == DeliveryState::Failed &&
        std::strcmp(result.reason, "SLEEP_DRAIN") == 0) {
      probe.fire(coordinator, w.a, w.events, storage, w.port, w.now,
                 PowerState::Persisting, true, false);
    }
  };
  SleepRequest request{};
  request.pending_policy = SleepWorkPolicy::Fail;
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
  CHECK(probe.ran);
}

void ban_family_hold_release(BanOp op) {
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
  BanProbe probe{op, "hold_release"};
  w.observer_b.on_group_message_fn = [&](const GroupMessageInfo& info,
                                         ByteView) {
    if (info.group_seq == 3) {
      probe.fire(coordinator, w.b, w.events, storage, w.port, w.now,
                 PowerState::Persisting, true, false);
    }
  };
  SleepRequest request{};
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  CHECK(w.run_until(coordinator, w.a, PowerState::ReadyToSleep));
  CHECK(probe.ran);
}

void ban_family_carry_expired(BanOp op) {
  MemoryPowerStorage storage;
  PowerWorld w(storage);
  CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  w.pump(60);
  (void)queue_pending(w, 2, true, 1000);
  SleepRequest request{};
  CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
  CHECK(w.pump_until(PowerState::ReadyToSleep));
  CHECK_OK(w.coordinator.sleep_abort("BAN_SETUP", w.now));
  w.now += 2000;  // the carried record's budget lapses while awake
  BanProbe probe{op, "carry_expired"};
  w.events.on_pending_result_fn = [&](const PendingDeliveryRecord&,
                                      StatusCode code) {
    if (code == StatusCode::Expired) {
      probe.fire(w.coordinator, w.node, w.events, w.storage, w.port, w.now,
                 PowerState::Persisting, true, false);
    }
  };
  CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
  CHECK(w.pump_until(PowerState::ReadyToSleep));
  CHECK(probe.ran);
}

void ban_family_tx_notice(BanOp op) {
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
  BanProbe probe{op, "tx_notice"};
  w.observer_a.on_diag_fn = [&](const char* reason, NodeId,
                                const MessageId*) {
    if (std::strcmp(reason, "SLEEP_TX_INFLIGHT") == 0) {
      probe.fire(coordinator, w.a, w.events, storage, w.port, w.now,
                 PowerState::Persisting, true, false);
    }
  };
  SleepRequest request{};
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  // No flush until the notice ran: the TX result must not land first.
  for (int i = 0; i < 400 && !probe.ran; ++i) {
    coordinator.poll(w.now);
    w.b.poll(w.now);
    w.now += 5;
  }
  CHECK(probe.ran);
  CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
}

void ban_family_message_running(BanOp op) {
  MemoryPowerStorage storage;
  GroupPowerWorld w;
  w.converge();
  PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                               w.events);
  CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  BanProbe probe{op, "message_running"};
  w.observer_a.on_message_fn = [&](const MessageKey&, NodeId, ByteView) {
    probe.fire(coordinator, w.a, w.events, storage, w.port, w.now,
               PowerState::Running, false, false);
  };
  const std::array<std::uint8_t, 3> payload{{'h', 'i', '!'}};
  MessageId id{};
  SendOptions send_options{};
  CHECK_OK(w.b.send(GroupPowerWorld::kGateway,
                    ByteView{payload.data(), payload.size()}, send_options,
                    w.now, id));
  for (int i = 0; i < 400 && !probe.ran; ++i) {
    coordinator.poll(w.now);
    w.b.poll(w.now);
    w.net.flush(w.now);
    w.now += 5;
  }
  CHECK(probe.ran);
  // Aftermath: nothing was queued — no attempt starts.
  for (int i = 0; i < 20; ++i) {
    coordinator.poll(w.now);
    w.b.poll(w.now);
    w.net.flush(w.now);
    w.now += 5;
  }
  CHECK(coordinator.state() == PowerState::Running);
  CHECK(!w.events.saw(PowerState::Running, PowerState::Draining,
                      "SLEEP_PREPARE"));
}

void ban_family_message_draining(BanOp op) {
  MemoryPowerStorage storage;
  GroupPowerWorld w;
  w.converge();
  PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                               w.events);
  CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  // A collecting group round holds the drain open until the trigger
  // message arrives mid-drain (a quiet node would settle first).
  drop_all_reports();
  w.net.drop_frame = group_loss_hook;
  GroupSendOptions options{};
  w.send_all(w.a, options);
  SleepRequest request{};
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  BanProbe probe{op, "message_draining"};
  w.observer_a.on_message_fn = [&](const MessageKey&, NodeId, ByteView) {
    probe.fire(coordinator, w.a, w.events, storage, w.port, w.now,
               PowerState::Draining, true, false);
  };
  const std::array<std::uint8_t, 3> payload{{'h', 'i', '!'}};
  MessageId id{};
  SendOptions send_options{};
  CHECK_OK(w.b.send(GroupPowerWorld::kGateway,
                    ByteView{payload.data(), payload.size()}, send_options,
                    w.now, id));
  for (int i = 0; i < 400 && !probe.ran; ++i) {
    coordinator.poll(w.now);
    w.b.poll(w.now);
    w.net.flush(w.now);
    w.now += 5;
  }
  CHECK(probe.ran);
  CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
}

void ban_family_transition_ready(BanOp op) {
  MatrixWorld w;
  CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  w.pump(60);
  BanProbe probe{op, "transition_ready"};
  w.events.on_transition_fn = [&](PowerState from, PowerState to,
                                  const char* reason) {
    if (from == PowerState::Persisting && to == PowerState::ReadyToSleep &&
        std::strcmp(reason, "SLEEP_READY") == 0) {
      probe.fire(w.coordinator, w.node, w.events, w.storage, w.port, w.now,
                 PowerState::ReadyToSleep, true, true);
    }
  };
  SleepRequest request{};
  CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
  CHECK(w.pump_until(PowerState::ReadyToSleep));
  CHECK(probe.ran);
  CHECK(w.coordinator.ticket_valid(w.coordinator.ticket()));
}

void ban_family_transition_enter(BanOp op) {
  MatrixWorld w;
  CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  w.pump(60);
  SleepRequest request{};
  CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
  CHECK(w.pump_until(PowerState::ReadyToSleep));
  const SleepTicket ticket = w.coordinator.ticket();
  BanProbe probe{op, "transition_enter"};
  w.events.on_transition_fn = [&](PowerState, PowerState to,
                                  const char* reason) {
    if (to == PowerState::Sleeping &&
        std::strcmp(reason, "SLEEP_ENTER") == 0) {
      probe.fire(w.coordinator, w.node, w.events, w.storage, w.port, w.now,
                 PowerState::Sleeping, true, true);
    }
  };
  CHECK_OK(w.coordinator.sleep_enter(ticket, w.now));
  CHECK(probe.ran);
  CHECK(w.coordinator.state() == PowerState::Sleeping);
  CHECK(w.port.sleep_calls == 1);
}

void ban_family_enter_expired(BanOp op) {
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
  w.now += 10010;  // the pending expires during the READY wait
  BanProbe probe{op, "enter_expired"};
  w.events.on_pending_result_fn = [&](const PendingDeliveryRecord&,
                                      StatusCode code) {
    if (code == StatusCode::Expired) {
      probe.fire(w.coordinator, w.node, w.events, w.storage, w.port, w.now,
                 PowerState::ReadyToSleep, true, true);
    }
  };
  CHECK_OK(w.coordinator.sleep_enter(ticket, w.now));
  CHECK(probe.ran);
  CHECK(w.coordinator.state() == PowerState::Sleeping);
  CHECK(w.port.sleep_calls == 1);
}

void ban_family_power_diagnostic(BanOp op) {
  // PowerEvents::on_diagnostic fires in RUNNING — abort_to_running tears
  // down first and notifies last.
  MemoryPowerStorage storage;
  GroupPowerWorld w;
  w.converge();
  PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                               w.events);
  CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  BanProbe probe{op, "power_diagnostic"};
  w.events.on_diagnostic_fn = [&](const char* reason) {
    if (std::strcmp(reason, "BAN_DIAG") == 0) {
      probe.fire(coordinator, w.a, w.events, storage, w.port, w.now,
                 PowerState::Running, false, false);
    }
  };
  SleepRequest request{};
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  CHECK_OK(coordinator.sleep_abort("BAN_DIAG", w.now));
  CHECK(probe.ran);
  CHECK(coordinator.state() == PowerState::Running);
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

void ban_family_applied_result(BanOp op) {
  // NodeObserver::on_applied_result (origin side): one applied exchange
  // fires it exactly once with the coordinator begun but idle, so the op
  // runs under the node-callback flag alone.
  MemoryPowerStorage storage;
  GroupPowerWorld w;
  w.converge();
  AppliedSinkHook sink;
  w.b.set_applied_sink(&sink);
  PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                               w.events);
  CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  BanProbe probe{op, "applied_result"};
  w.observer_a.on_applied_result_fn =
      [&](const MessageKey&, const AppliedResultView&) {
        probe.fire(coordinator, w.a, w.events, storage, w.port, w.now,
                   PowerState::Running, false, false);
      };
  const std::array<std::uint8_t, 4> payload{{0x61, 0x62, 0x63, 0x64}};
  MessageId id{};
  SendOptions applied{};
  applied.delivery = DeliveryClass::Applied;
  applied.lifetime_ms = 10000;
  CHECK_OK(w.a.send_applied(GroupPowerWorld::kLeaf,
                            ByteView{payload.data(), payload.size()},
                            w.b.applied_lease(), applied, w.now, id));
  // Direct node drive: the coordinator stays idle, so only the
  // node-callback flag marks the call.
  for (int i = 0; i < 400 && !probe.ran; ++i) {
    w.a.poll(w.now);
    w.b.poll(w.now);
    w.net.flush(w.now);
    w.now += 5;
  }
  CHECK(probe.ran);
  for (int i = 0; i < 20; ++i) {
    coordinator.poll(w.now);
    w.b.poll(w.now);
    w.net.flush(w.now);
    w.now += 5;
  }
  CHECK(coordinator.state() == PowerState::Running);
  CHECK(!w.events.saw(PowerState::Running, PowerState::Draining,
                      "SLEEP_PREPARE"));
}

void ban_family_applied_sink(BanOp op) {
  // The extended AppliedEndpointSink (terminal side): same idle-coordinator
  // shape as the result side above.
  MemoryPowerStorage storage;
  GroupPowerWorld w;
  w.converge();
  AppliedSinkHook sink;
  w.a.set_applied_sink(&sink);
  PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                               w.events);
  CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  BanProbe probe{op, "applied_sink"};
  sink.on_request_fn = [&]() {
    probe.fire(coordinator, w.a, w.events, storage, w.port, w.now,
               PowerState::Running, false, false);
  };
  const std::array<std::uint8_t, 4> payload{{0x61, 0x62, 0x63, 0x64}};
  MessageId id{};
  SendOptions applied{};
  applied.delivery = DeliveryClass::Applied;
  applied.lifetime_ms = 10000;
  CHECK_OK(w.b.send_applied(GroupPowerWorld::kGateway,
                            ByteView{payload.data(), payload.size()},
                            w.a.applied_lease(), applied, w.now, id));
  for (int i = 0; i < 400 && !probe.ran; ++i) {
    w.a.poll(w.now);
    w.b.poll(w.now);
    w.net.flush(w.now);
    w.now += 5;
  }
  CHECK(probe.ran);
  for (int i = 0; i < 20; ++i) {
    coordinator.poll(w.now);
    w.b.poll(w.now);
    w.net.flush(w.now);
    w.now += 5;
  }
  CHECK(coordinator.state() == PowerState::Running);
  CHECK(!w.events.saw(PowerState::Running, PowerState::Draining,
                      "SLEEP_PREPARE"));
}

std::size_t count_prepares(const RecordingPowerEvents& events) {
  std::size_t count = 0;
  for (const auto& t : events.transitions) {
    if (t.from == PowerState::Running && t.to == PowerState::Draining) ++count;
  }
  return count;
}

void ban_family_restore_begin(BanOp op) {
  // on_pending_result during restore via begin() on a fresh instance: the
  // op runs in RESUMING, and begin() then completes to RUNNING.
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
  GroupPowerWorld fresh;
  fresh.converge();
  FakePowerPort fresh_port;
  RecordingPowerEvents fresh_events;
  PowerCoordinator woken(PowerConfig{500, 50}, fresh.a, fresh_port, storage,
                         fresh_events);
  BanProbe probe{op, "restore_begin"};
  fresh_events.on_pending_result_fn = [&](const PendingDeliveryRecord&,
                                          StatusCode) {
    probe.fire(woken, fresh.a, fresh_events, storage, fresh_port, fresh.now,
               PowerState::Resuming, false, false);
  };
  CHECK_OK(woken.begin(ResetCause::DeepSleepWake,
                       ElapsedInterval{100, 200, true}, fresh.now));
  CHECK(probe.ran);
  CHECK(woken.state() == PowerState::Running);
  for (int i = 0; i < 20; ++i) {
    woken.poll(fresh.now);
    fresh.b.poll(fresh.now);
    fresh.net.flush(fresh.now);
    fresh.now += 5;
  }
  CHECK(woken.state() == PowerState::Running);
  CHECK(count_prepares(fresh_events) == 0);  // nothing queued by the op
}

void ban_family_restore_wake(BanOp op) {
  // on_pending_result during restore via wake() after a real enter.
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
  BanProbe probe{op, "restore_wake"};
  w.events.on_pending_result_fn = [&](const PendingDeliveryRecord&,
                                      StatusCode) {
    probe.fire(coordinator, w.a, w.events, storage, w.port, w.now,
               PowerState::Resuming, false, false);
  };
  CHECK_OK(coordinator.sleep_enter(coordinator.ticket(), w.now));
  CHECK_OK(coordinator.wake(ResetCause::DeepSleepWake,
                            ElapsedInterval{100, 200, true}, w.now));
  CHECK(probe.ran);
  CHECK(coordinator.state() == PowerState::Running);
  for (int i = 0; i < 20; ++i) {
    coordinator.poll(w.now);
    w.b.poll(w.now);
    w.net.flush(w.now);
    w.now += 5;
  }
  CHECK(coordinator.state() == PowerState::Running);
  // The setup's single prepare; the op queued nothing behind it.
  CHECK(count_prepares(w.events) == 1);
}

void ban_family_delivery_running_direct(BanOp op) {
  // The node-flag ban path (coordinator idle, no worker on the stack):
  // driving node_.poll() directly, every op from the expiry callback is
  // Busy, and the next coordinator polls start no attempt.
  MatrixWorld w;
  CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  w.pump(60);
  const std::array<std::uint8_t, 3> payload{{'d', 'r', '!'}};
  MessageId id{};
  SendOptions send_options{};
  send_options.lifetime_ms = 5;
  CHECK_OK(w.node.send(9, ByteView{payload.data(), payload.size()},
                       send_options, w.now, id));
  BanProbe probe{op, "delivery_running_direct"};
  w.observer.on_delivery_fn = [&](const DeliveryResult& result) {
    if (result.id == id && sleep_verdict_terminal(result.state)) {
      probe.fire(w.coordinator, w.node, w.events, w.storage, w.port, w.now,
                 PowerState::Running, false, false);
    }
  };
  w.now += 10;
  w.node.poll(w.now);  // direct drive: coordinator idle throughout
  CHECK(probe.ran);
  w.pump(20);
  CHECK(w.coordinator.state() == PowerState::Running);
  CHECK(!w.events.saw(PowerState::Running, PowerState::Draining,
                      "SLEEP_PREPARE"));
}

void test_callback_busy_matrix() {
  std::size_t cells = 0;
  for (const BanOp op : kBanOps) {
    ban_family_settle_delivery(op);
    ban_family_settle_group(op);
    ban_family_hold_release(op);
    ban_family_carry_expired(op);
    ban_family_tx_notice(op);
    ban_family_message_running(op);
    ban_family_message_draining(op);
    ban_family_transition_ready(op);
    ban_family_transition_enter(op);
    ban_family_enter_expired(op);
    ban_family_power_diagnostic(op);
    ban_family_applied_result(op);
    ban_family_applied_sink(op);
    ban_family_restore_begin(op);
    ban_family_restore_wake(op);
    ban_family_delivery_running_direct(op);
    cells += 16;
  }
  CHECK(cells == 7 * 16);
}

// --- Section 9.3 (boundaries): radio reset, recursive drive, node-flag ban ---

void test_callback_radio_reset_busy_outside_aborts() {
  // A radio reset signalled from a settlement callback is Busy — the
  // attempt completes to READY. One signalled from OUTSIDE aborts an
  // active attempt at once; without an attempt only the generation moves
  // and a prepare works immediately (#110: no latch, no Busy window).
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
    Status reset_status = Status::error(StatusCode::InternalError, "not run");
    w.observer_a.on_delivery_fn = [&](const DeliveryResult& result) {
      if (result.state == DeliveryState::Failed &&
          std::strcmp(result.reason, "SLEEP_DRAIN") == 0) {
        reset_status = coordinator.notify_radio_reset(w.now);
      }
    };
    SleepRequest request{};
    CHECK_OK(coordinator.sleep_prepare(request, w.now));
    CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
    CHECK(reset_status.code == StatusCode::Busy);
    CHECK(w.events.saw(PowerState::Persisting, PowerState::ReadyToSleep,
                       "SLEEP_READY"));
    CHECK(coordinator.ticket_valid(coordinator.ticket()));
    CHECK_OK(coordinator.notify_radio_reset(w.now));
    CHECK(coordinator.state() == PowerState::Running);
    CHECK(w.events.has_diag("SLEEP_TICKET_INVALID"));
  }
  {
    // No attempt: the generation moves, and a prepare works at once.
    MemoryPowerStorage storage;
    PowerWorld w(storage);
    CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                                 ElapsedInterval{0, 0, false}, w.now));
    w.pump(60);
    CHECK_OK(w.coordinator.notify_radio_reset(w.now));
    SleepRequest request{};
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
  CHECK(std::strcmp(begin_status.detail, "POWER_IN_CALLBACK") == 0);
  CHECK(wake_status.code == StatusCode::Busy);
  CHECK(std::strcmp(wake_status.detail, "POWER_IN_CALLBACK") == 0);
}

// --- Section 9.4 (invariants) -------------------------------------------------

void test_callback_busy_freezes_machine() {
  // Inside a settlement callback the app fires abort, prepare, enter, wake,
  // begin, both notify calls and a poll: every mutating call is Busy and
  // the poll is a no-op — the machine, drain mask, ticket, transitions,
  // storage and the radio are untouched — and the attempt then completes
  // to READY_TO_SLEEP (#110).
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
    CHECK(coordinator.sleep_abort("TRACE", w.now).code == StatusCode::Busy);
    SleepRequest request{};
    CHECK(coordinator.sleep_prepare(request, w.now).code == StatusCode::Busy);
    CHECK(coordinator.sleep_enter(coordinator.ticket(), w.now).code ==
          StatusCode::Busy);
    CHECK(coordinator.wake(ResetCause::DeepSleepWake,
                           ElapsedInterval{0, 0, false}, w.now)
              .code == StatusCode::Busy);
    CHECK(coordinator.begin(ResetCause::ColdBoot, ElapsedInterval{0, 0, false},
                            w.now)
              .code == StatusCode::Busy);
    CHECK(coordinator.notify_app_event(w.now).code == StatusCode::Busy);
    CHECK(coordinator.notify_radio_reset(w.now).code == StatusCode::Busy);
    coordinator.poll(w.now);  // silent no-op
    // Nothing moved: every call above was refused outright.
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
  CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
  CHECK(ran);
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
        w.coordinator.notify_radio_reset(w.now);
        break;
      default:
        w.coordinator.notify_app_event(w.now);
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

void test_enter_notify_busy_matrix() {
  // Entry notifications x single ops: the Expired (refresh) and SLEEP_ENTER
  // callbacks each run one op. Coordinator ops are Busy and the handoff
  // completes (exactly 1 platform enter); a refused send still retires the
  // ticket's generation, so a send from either callback aborts the entry
  // with no platform enter (#110).
  enum class EnterOp : std::uint8_t {
    Abort,
    Prepare,
    AppEvent,
    RadioReset,
    Send,
    SendGroup,
    Enter,
    Wake,
    Begin,
  };
  struct Cell {
    EnterOp op;
    StatusCode code;
    bool breaks_ticket;  // end state RUNNING, no platform enter (else SLEEPING)
  };
  const Cell kCells[] = {
      {EnterOp::Abort, StatusCode::Busy, false},
      {EnterOp::Prepare, StatusCode::Busy, false},
      {EnterOp::AppEvent, StatusCode::Busy, false},
      {EnterOp::RadioReset, StatusCode::Busy, false},
      {EnterOp::Send, StatusCode::InvalidState, true},
      {EnterOp::SendGroup, StatusCode::InvalidState, true},
      {EnterOp::Enter, StatusCode::Busy, false},
      {EnterOp::Wake, StatusCode::Busy, false},
      {EnterOp::Begin, StatusCode::Busy, false},
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
          case EnterOp::Abort:
            got = w.coordinator.sleep_abort("ENTER_MATRIX", w.now);
            break;
          case EnterOp::Prepare: {
            SleepRequest retry{};
            got = w.coordinator.sleep_prepare(retry, w.now);
            break;
          }
          case EnterOp::AppEvent:
            got = w.coordinator.notify_app_event(w.now);
            break;
          case EnterOp::RadioReset:
            got = w.coordinator.notify_radio_reset(w.now);
            break;
          case EnterOp::Send: {
            MessageId id{};
            SendOptions send_options{};
            const std::array<std::uint8_t, 3> payload{{'e', 'n', '!'}};
            got = w.node.send(9, ByteView{payload.data(), payload.size()},
                              send_options, w.now, id);
            break;
          }
          case EnterOp::SendGroup: {
            MessageId id{};
            GroupSendOptions group_options{};
            const std::array<std::uint8_t, 3> payload{{'e', 'n', '!'}};
            got = w.node.send_group(kGroupAll,
                                    ByteView{payload.data(), payload.size()},
                                    group_options, w.now, id);
            break;
          }
          case EnterOp::Enter:
            got = w.coordinator.sleep_enter(ticket, w.now);
            break;
          case EnterOp::Wake:
            got = w.coordinator.wake(ResetCause::DeepSleepWake,
                                     ElapsedInterval{0, 0, false}, w.now);
            break;
          case EnterOp::Begin:
            got = w.coordinator.begin(ResetCause::ColdBoot,
                                      ElapsedInterval{0, 0, false}, w.now);
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
      if (cell.code == StatusCode::Busy) {
        CHECK(std::strcmp(got.detail, "POWER_IN_CALLBACK") == 0);
      }
      if (cell.breaks_ticket) {
        CHECK(std::strcmp(got.detail, "NODE_DRAINING") == 0);
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
      CHECK_OK(w.coordinator.sleep_abort("WARM", w.now));
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

void test_failed_second_commit_keeps_unnotified_expired_carry() {
  MemoryPowerStorage storage;
  MessageId carried{};
  {
    PowerWorld w(storage);
    CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                                 ElapsedInterval{0, 0, false}, w.now));
    carried = queue_pending(w, 99, true, 1000);
    SleepRequest request{};
    CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
    CHECK(w.pump_until(PowerState::ReadyToSleep));
    CHECK_OK(w.coordinator.sleep_abort("RETRY", w.now));
    w.now += 2000;
    storage.fail_after_writes(1);
    CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
    CHECK(w.pump_until(PowerState::Running));
    CHECK(w.events.pending_with(StatusCode::Expired) == 0);
  }
  PowerWorld recovered(storage);
  CHECK_OK(recovered.coordinator.begin(ResetCause::OtherReset,
                                       ElapsedInterval{0, 0, true}, recovered.now));
  CHECK(pending_results_for(recovered.events, carried, StatusCode::Expired) == 1);
}

void test_failed_second_refresh_keeps_unnotified_expired_carry() {
  MemoryPowerStorage storage;
  MessageId carried{};
  {
    PowerWorld w(storage);
    CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                                 ElapsedInterval{0, 0, false}, w.now));
    carried = queue_pending(w, 99, true, 1000);
    SleepRequest request{};
    CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
    CHECK(w.pump_until(PowerState::ReadyToSleep));
    const SleepTicket ticket = w.coordinator.ticket();
    w.now += 2000;
    storage.fail_after_writes(1);
    CHECK(!w.coordinator.sleep_enter(ticket, w.now).ok());
    CHECK(w.coordinator.state() == PowerState::Running);
    CHECK(w.events.pending_with(StatusCode::Expired) == 0);
  }
  PowerWorld recovered(storage);
  CHECK_OK(recovered.coordinator.begin(ResetCause::OtherReset,
                                       ElapsedInterval{0, 0, true}, recovered.now));
  CHECK(pending_results_for(recovered.events, carried, StatusCode::Expired) == 1);
}

void test_failed_second_commit_keeps_old_same_id_carry() {
  MemoryPowerStorage storage;
  MessageId carried{};
  const std::array<std::uint8_t, 4> old_body{{'O', 'L', 'D', '!'}};
  const std::array<std::uint8_t, 4> new_body{{'N', 'E', 'W', '!'}};
  SendOptions durable{};
  durable.persist_across_sleep = true;
  durable.lifetime_ms = 20000;
  {
    GroupPowerWorld w;
    w.converge();
    PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                                 w.events);
    CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
    CHECK_OK(w.a.send(9, ByteView{old_body.data(), old_body.size()}, durable,
                      w.now, carried));
    SleepRequest request{};
    CHECK_OK(coordinator.sleep_prepare(request, w.now));
    CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
    CHECK_OK(coordinator.sleep_enter(coordinator.ticket(), w.now));
  }
  {
    GroupPowerWorld w;
    w.converge();
    PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                                 w.events);
    for (std::size_t i = 0; i < MeshNode::delivery_capacity(); ++i) {
      MessageId id{};
      CHECK_OK(w.a.send(90 + static_cast<NodeId>(i),
                        ByteView{new_body.data(), new_body.size()}, durable,
                        w.now, id));
    }
    CHECK_OK(coordinator.begin(ResetCause::DeepSleepWake,
                               ElapsedInterval{0, 0, true}, w.now));
    CHECK(w.events.pending_with(StatusCode::AlreadyExists) == 1);
    SleepRequest save{};
    save.pending_policy = SleepWorkPolicy::Save;
    storage.fail_after_writes(1);
    CHECK_OK(coordinator.sleep_prepare(save, w.now));
    CHECK(w.run_until(coordinator, w.b, PowerState::Running));
    CHECK(!sleep_verdict_terminal(w.a.delivery(carried).state));
  }
  GroupPowerWorld recovered;
  recovered.converge();
  FakePowerPort port;
  RecordingPowerEvents events;
  PowerCoordinator coordinator(PowerConfig{500, 50}, recovered.a, port,
                               storage, events);
  CHECK_OK(coordinator.begin(ResetCause::OtherReset,
                             ElapsedInterval{0, 0, true}, recovered.now));
  CHECK(pending_results_for(events, carried, StatusCode::Ok) == 1);
  std::size_t old_copies = 0;
  recovered.a.for_each_delivery([&](const DeliverySnapshot& snapshot) {
    if (snapshot.id != carried) return;
    CHECK(snapshot.payload.size == old_body.size());
    CHECK(std::memcmp(snapshot.payload.data, old_body.data(), old_body.size()) == 0);
    ++old_copies;
  });
  CHECK(old_copies == 1);
}

void test_failed_second_commit_keeps_reinjected_durable_work() {
  MemoryPowerStorage storage;
  MessageId pending{};
  {
    PowerWorld w(storage);
    CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                                 ElapsedInterval{0, 0, false}, w.now));
    pending = queue_pending(w, 99, true, 20000);
    SleepRequest request{};
    CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
    CHECK(w.pump_until(PowerState::ReadyToSleep));
    CHECK_OK(w.coordinator.sleep_enter(w.coordinator.ticket(), w.now));
  }
  {
    PowerWorld w(storage);
    CHECK_OK(w.coordinator.begin(ResetCause::DeepSleepWake,
                                 ElapsedInterval{0, 0, true}, w.now));
    CHECK(pending_results_for(w.events, pending, StatusCode::Ok) == 1);
    CHECK(!sleep_verdict_terminal(w.node.delivery(pending).state));
    storage.fail_after_writes(1);
    SleepRequest request{};
    CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
    CHECK(w.pump_until(PowerState::Running));
  }
  PowerWorld recovered(storage);
  CHECK_OK(recovered.coordinator.begin(ResetCause::OtherReset,
                                       ElapsedInterval{0, 0, true}, recovered.now));
  CHECK(pending_results_for(recovered.events, pending, StatusCode::Ok) == 1);
}

void test_retry_policy_matrix_after_outside_abort() {
  // Save settles two records; the READY attempt is aborted from OUTSIDE
  // (carry 2 kept, nothing live). A fresh non-durable delivery is queued
  // and the retry runs under Fail/Save/Defer: the live record settles
  // under the NEW policy only, and the wake restores the carried set plus
  // the retry's save, if any (#110: retry-policy matrix).
  const SleepWorkPolicy kPolicies[] = {SleepWorkPolicy::Fail,
                                       SleepWorkPolicy::Save,
                                       SleepWorkPolicy::Defer};
  for (const SleepWorkPolicy retry_policy : kPolicies) {
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
    SleepRequest request{};
    request.pending_policy = SleepWorkPolicy::Save;
    CHECK_OK(coordinator.sleep_prepare(request, w.now));
    CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
    CHECK_OK(coordinator.sleep_abort("PARTIAL", w.now));
    CHECK(coordinator.state() == PowerState::Running);
    MessageId live{};
    CHECK_OK(w.a.send(9, ByteView{payload.data(), payload.size()},
                      send_options, w.now, live));
    SleepRequest retry{};
    retry.pending_policy = retry_policy;
    CHECK_OK(coordinator.sleep_prepare(retry, w.now));
    CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
    // The live record belongs to the retry's policy alone.
    const auto outcome = w.a.delivery(live);
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
    CHECK_OK(coordinator.sleep_enter(coordinator.ticket(), w.now));
    GroupPowerWorld fresh;
    FakePowerPort fresh_port;
    RecordingPowerEvents fresh_events;
    PowerCoordinator woken(PowerConfig{500, 50}, fresh.a, fresh_port,
                           storage, fresh_events);
    CHECK_OK(woken.begin(ResetCause::DeepSleepWake,
                         ElapsedInterval{100, 200, true}, fresh.now));
    const std::size_t want = retry_policy == SleepWorkPolicy::Save ? 3 : 2;
    CHECK(fresh_events.pending_with(StatusCode::Ok) == want);
    CHECK(pending_results_for(fresh_events, ids[0], StatusCode::Ok) == 1);
    CHECK(pending_results_for(fresh_events, ids[1], StatusCode::Ok) == 1);
    CHECK(pending_results_for(fresh_events, live, StatusCode::Ok) ==
          (retry_policy == SleepWorkPolicy::Save ? 1 : 0));
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
  // Build the carry set with a completed attempt, aborted from OUTSIDE
  // in READY (a mid-settlement abort is impossible now).
  SleepRequest save{};
  save.pending_policy = SleepWorkPolicy::Save;
  CHECK_OK(coordinator.sleep_prepare(save, w.now));
  CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
  for (const auto& id : carried) {
    CHECK(std::strcmp(w.a.delivery(id).reason, "SLEEP_SAVED") == 0);
  }
  CHECK_OK(coordinator.sleep_abort("CARRY2", w.now));
  CHECK(coordinator.state() == PowerState::Running);
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

void test_carry_settlement_callback_busy_restores_on_new_node() {
  // Carry 2 + fresh 4 over the 4-slot candidate: an abort from the
  // settlement callback is Busy — nothing is recorded — so the settlement
  // completes instead of stranding un-notified carry: both carried
  // records stay carried, two fresh records are saved, two fail
  // SLEEP_PERSIST_FULL, and the ticket is issued. A NEW node restarting
  // from the same storage restores exactly the committed four (#110).
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
  SleepRequest save{};
  save.pending_policy = SleepWorkPolicy::Save;
  CHECK_OK(coordinator.sleep_prepare(save, w.now));
  CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
  CHECK_OK(coordinator.sleep_abort("CARRY2", w.now));
  CHECK(coordinator.state() == PowerState::Running);
  std::array<MessageId, 4> fresh_ids{};
  for (auto& id : fresh_ids) {
    CHECK_OK(w.a.send(9, ByteView{payload.data(), payload.size()}, durable,
                      w.now, id));
  }
  Status abort_status = Status::error(StatusCode::InternalError, "not run");
  w.observer_a.on_delivery_fn = [&](const DeliveryResult&) {
    if (abort_status.code == StatusCode::InternalError) {
      abort_status = coordinator.sleep_abort("MID_SETTLEMENT", w.now);
    }
  };
  CHECK_OK(coordinator.sleep_prepare(save, w.now));
  CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
  CHECK(abort_status.code == StatusCode::Busy);
  std::size_t saved_count = 0;
  std::size_t persist_full = 0;
  for (const auto& id : fresh_ids) {
    const char* reason = w.a.delivery(id).reason;
    saved_count += std::strcmp(reason, "SLEEP_SAVED") == 0 ? 1U : 0U;
    persist_full += std::strcmp(reason, "SLEEP_PERSIST_FULL") == 0 ? 1U : 0U;
  }
  CHECK(saved_count == 2);
  CHECK(persist_full == 2);
  CHECK_OK(coordinator.sleep_enter(coordinator.ticket(), w.now));
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

void test_carry_same_id_callback_busy_restores_new() {
  // A retained OLD record shares its logical id with a live durable NEW
  // delivery. An abort from the fresh settlement callback is Busy — the
  // settlement completes, the fresh record supersedes the carry in place,
  // and after the entry a NEW node restores NEW (not OLD), exactly once
  // (#110: same-id ownership transfers at settlement, never at commit).
  MemoryPowerStorage storage;
  MessageId retained{};
  {
    // Incarnation 1: persist one durable record with the OLD body.
    GroupPowerWorld w;
    w.converge();
    PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                                 w.events);
    CHECK_OK(coordinator.begin(ResetCause::ColdBoot,
                                 ElapsedInterval{0, 0, false}, w.now));
    const std::array<std::uint8_t, 4> old_body{{'O', 'L', 'D', '!'}};
    SendOptions durable{};
    durable.persist_across_sleep = true;
    durable.lifetime_ms = 20000;
    CHECK_OK(w.a.send(9, ByteView{old_body.data(), old_body.size()}, durable,
                      w.now, retained));
    SleepRequest request{};
    CHECK_OK(coordinator.sleep_prepare(request, w.now));
    CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
    CHECK_OK(coordinator.sleep_enter(coordinator.ticket(), w.now));
  }
  {
    // Incarnation 2 on the same storage: the table fills up (the first
    // live id collides with the retained one) so the restore retains OLD
    // and reports AlreadyExists.
    GroupPowerWorld w;
    w.converge();
    PowerCoordinator coordinator(PowerConfig{500, 50}, w.a, w.port, storage,
                                 w.events);
    const std::array<std::uint8_t, 4> new_body{{'N', 'E', 'W', '!'}};
    SendOptions durable{};
    durable.persist_across_sleep = true;
    durable.lifetime_ms = 20000;
    for (std::size_t i = 0; i < MeshNode::delivery_capacity(); ++i) {
      MessageId id{};
      CHECK_OK(w.a.send(90 + static_cast<NodeId>(i),
                        ByteView{new_body.data(), new_body.size()}, durable,
                        w.now, id));
    }
    CHECK_OK(coordinator.begin(ResetCause::DeepSleepWake,
                               ElapsedInterval{0, 0, true}, w.now));
    CHECK(w.events.pending_with(StatusCode::AlreadyExists) == 1);
    Status abort_status = Status::error(StatusCode::InternalError, "not run");
    w.observer_a.on_delivery_fn = [&](const DeliveryResult& result) {
      if (abort_status.code == StatusCode::InternalError &&
          result.state == DeliveryState::Indeterminate) {
        abort_status = coordinator.sleep_abort("SAME_ID", w.now);
      }
    };
    SleepRequest save{};
    save.pending_policy = SleepWorkPolicy::Save;
    CHECK_OK(coordinator.sleep_prepare(save, w.now));
    CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
    CHECK(abort_status.code == StatusCode::Busy);
    CHECK_OK(coordinator.sleep_enter(coordinator.ticket(), w.now));
  }
  {
    // Incarnation 3: the superseded OLD body is gone — the restored
    // record for the shared id carries NEW, exactly once.
    GroupPowerWorld w;
    w.converge();
    FakePowerPort fresh_port;
    RecordingPowerEvents fresh_events;
    PowerCoordinator woken(PowerConfig{500, 50}, w.a, fresh_port, storage,
                           fresh_events);
    CHECK_OK(woken.begin(ResetCause::DeepSleepWake,
                         ElapsedInterval{100, 200, true}, w.now));
    CHECK(fresh_events.pending_with(StatusCode::Ok) == 4);
    CHECK(pending_results_for(fresh_events, retained, StatusCode::Ok) == 1);
    const std::array<std::uint8_t, 4> new_body{{'N', 'E', 'W', '!'}};
    const std::array<std::uint8_t, 4> old_body{{'O', 'L', 'D', '!'}};
    std::size_t shared = 0;
    w.a.for_each_delivery([&](const DeliverySnapshot& snapshot) {
      if (snapshot.id == retained &&
          snapshot.payload.size == new_body.size() &&
          std::memcmp(snapshot.payload.data, new_body.data(),
                      new_body.size()) == 0) {
        ++shared;
      }
      CHECK(!(snapshot.payload.size == old_body.size() &&
              std::memcmp(snapshot.payload.data, old_body.data(),
                          old_body.size()) == 0));
    });
    CHECK(shared == 1);
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
  SleepRequest save{};
  save.pending_policy = SleepWorkPolicy::Save;
  CHECK_OK(coordinator.sleep_prepare(save, w.now));
  CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
  CHECK(std::strcmp(w.a.delivery(id).reason, "SLEEP_SAVED") == 0);
  CHECK_OK(coordinator.sleep_abort("EVICT", w.now));
  CHECK(coordinator.state() == PowerState::Running);
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

void test_retry_after_outside_abort_plans_live_only() {
  // The first attempt is aborted from OUTSIDE during the drain: it commits
  // nothing, so the retry plans from live work alone — no stale on-disk
  // candidate can leak in — and the wake restores exactly the retry's set.
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
                    id_b));
  MessageId id_a{};
  SendOptions durable = plain;
  durable.persist_across_sleep = true;
  CHECK_OK(w.a.send(9, ByteView{payload.data(), payload.size()}, durable,
                    w.now, id_a));
  SleepRequest fail{};
  fail.pending_policy = SleepWorkPolicy::Fail;
  CHECK_OK(coordinator.sleep_prepare(fail, w.now));
  CHECK(coordinator.state() == PowerState::Draining);
  CHECK_OK(coordinator.sleep_abort("EMPTY_CARRY", w.now));
  CHECK(coordinator.state() == PowerState::Running);
  CHECK(storage.write_calls == 0);
  CHECK(!sleep_verdict_terminal(w.a.delivery(id_b).state));
  CHECK(!sleep_verdict_terminal(w.a.delivery(id_a).state));
  SleepRequest retry{};
  CHECK_OK(coordinator.sleep_prepare(retry, w.now));
  CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
  CHECK(w.a.delivery(id_b).state == DeliveryState::Failed);
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
  // A BestEffort unicast stuck in physical TX and two group origins settle
  // (SLEEP_DRAIN); the attempt completes to READY and is aborted from
  // OUTSIDE. Late TX results and late group traffic must not revive any
  // verdict via the job paths (#110: terminal-owner rule). Note: a
  // verified peer end receipt still promotes a settled unicast
  // (pre-existing deliberate promotion semantic, out of this issue's
  // scope); the stale TX_MAC_DONE completion it replaces must never fire.
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
  SleepRequest request{};
  request.pending_policy = SleepWorkPolicy::Fail;
  CHECK_OK(coordinator.sleep_prepare(request, w.now));
  // No flush until READY: every TX result arrives late.
  for (int i = 0; i < 400 && coordinator.state() != PowerState::ReadyToSleep;
       ++i) {
    coordinator.poll(w.now);
    w.b.poll(w.now);
    w.now += 5;
  }
  CHECK(coordinator.state() == PowerState::ReadyToSleep);
  CHECK(w.a.delivery(uni).state == DeliveryState::Failed);
  CHECK(std::strcmp(w.a.delivery(uni).reason, "SLEEP_DRAIN") == 0);
  CHECK(w.a.group_delivery(origin1).state == DeliveryState::Failed);
  CHECK(std::strcmp(w.a.group_delivery(origin1).reason, "SLEEP_DRAIN") == 0);
  CHECK(w.a.group_delivery(origin2).state == DeliveryState::Failed);
  CHECK(std::strcmp(w.a.group_delivery(origin2).reason, "SLEEP_DRAIN") == 0);
  CHECK_OK(coordinator.sleep_abort("STALE", w.now));
  // Old results land now: the torn-down physical job resolves to nothing,
  // group verdicts stay frozen, no TX_MAC_DONE resurrection of the
  // settled unicast.
  w.net.drop_frame = nullptr;
  for (int i = 0; i < 400; ++i) {
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
  CHECK(w.a.group_delivery(origin1).state == DeliveryState::Failed);
  CHECK(std::strcmp(w.a.group_delivery(origin1).reason, "SLEEP_DRAIN") == 0);
  CHECK(w.a.group_delivery(origin2).state == DeliveryState::Failed);
  CHECK(std::strcmp(w.a.group_delivery(origin2).reason, "SLEEP_DRAIN") == 0);
  CHECK(w.observer_a.has_diag("STALE_TX_CALLBACK"));
}

void test_evicted_origin_jobs_never_dispatch() {
  // An origin whose record is evicted while its copies are still queued:
  // the leftovers count as stale at dispatch — never dispatched or
  // retried — so the evicted body never reaches a receiver (#110:
  // eviction must not resurrect the origin). Two leaves: the first copy
  // occupies the single physical slot (no flush, so no TX result), which
  // holds the second copy queued while the origin expires; the expired
  // record is then evicted synchronously, before any dispatch can run.
  // The STALE_JOB_DROPPED diagnostic carries the taken job's peer and
  // MessageId, never zeros.
  GroupPowerWorld w;
  w.converge();
  TestSecurity security_c;
  HookedObserver observer_c;
  SimRadio radio_c(w.net, 3);
  SimReplyPort reply_c(radio_c, 3, GroupPowerWorld::config(3).link_epoch);
  MeshNode c(GroupPowerWorld::config(3), radio_c, security_c, observer_c);
  CHECK_OK(c.set_reply_peer_port(&reply_c));
  w.net.register_node(3, &c);
  w.net.register_reply_port(3, &reply_c);
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
  const std::array<std::uint8_t, 3> payload{{'o', 'l', 'd'}};
  GroupSendOptions options{};
  // Expires while the driver is stuck; the 1000 ms callback watchdog must
  // not fire first, or the hold would release early.
  options.lifetime_ms = 300;
  MessageId old_id{};
  CHECK_OK(w.a.send_group(kGroupAll, ByteView{payload.data(), payload.size()},
                          options, w.now, old_id));
  CHECK(w.a.group_stats().copies_queued == 2);  // one copy per leaf
  // Silence the old frame everywhere until the eviction purge below:
  // setup airtime is legitimate, but none of it may reach an app.
  g_drop_type = FrameType::GroupData;
  g_drop_to = kInvalidNodeId;
  g_drop_sequence = old_id.sequence;
  w.net.silent_drop = group_loss_hook;
  w.a.poll(w.now);  // first copy into physical; no flush, so no TX result
  // Let the origin expire with the driver stuck: the expiry marks it
  // GROUP_INCOMPLETE while dispatch stays blocked on the physical slot,
  // so the leftover copy is still queued afterwards.
  for (int i = 0; i < 400 &&
                  !sleep_verdict_terminal(w.a.group_delivery(old_id).state);
       ++i) {
    w.a.poll(w.now);
    w.b.poll(w.now);
    c.poll(w.now);
    w.now += 5;
  }
  CHECK(w.a.group_delivery(old_id).state == DeliveryState::Failed);
  CHECK(std::strcmp(w.a.group_delivery(old_id).reason, "GROUP_INCOMPLETE") ==
        0);
  // Evict the terminal record synchronously — no polls between the expiry
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
  // Other origins may drop their own stale retries below; only the old
  // copy's diagnostic must carry its peer and id.
  bool matched_old = false;
  NodeId stale_peer = kInvalidNodeId;
  w.observer_a.on_diag_fn = [&](const char* reason, NodeId peer,
                                const MessageId* message) {
    if (std::strcmp(reason, "STALE_JOB_DROPPED") == 0 && message != nullptr &&
        *message == old_id) {
      matched_old = true;
      stale_peer = peer;
    }
  };
  // Purge setup airtime while the silence still holds, then open the
  // lane: only post-eviction transmissions could reach a leaf now.
  w.net.flush(w.now);
  w.net.silent_drop = nullptr;
  drop_all_reports();
  for (int i = 0; i < 100; ++i) {
    w.a.poll(w.now);
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
  CHECK(matched_old);
  CHECK(stale_peer == GroupPowerWorld::kLeaf || stale_peer == 3);
}

void test_stale_unicast_drop_reports_taken_job() {
  // A queued unicast retry for a cancelled (terminal) delivery is dropped
  // at dispatch — never sent — and the STALE_JOB_DROPPED diagnostic
  // carries the taken job's peer and MessageId, never zeros (unicast leg
  // of the evicted-origin diagnostic contract above).
  GroupPowerWorld w;
  w.converge();
  const std::array<std::uint8_t, 3> payload{{'s', 't', '!'}};
  MessageId id{};
  SendOptions send_options{};
  CHECK_OK(w.a.send(GroupPowerWorld::kLeaf,
                    ByteView{payload.data(), payload.size()}, send_options,
                    w.now, id));
  CHECK_OK(w.a.cancel(id));  // terminal; the queued job stays behind
  NodeId stale_peer = kInvalidNodeId;
  MessageId stale_id{};
  bool stale_has_id = false;
  w.observer_a.on_diag_fn = [&](const char* reason, NodeId peer,
                                const MessageId* message) {
    if (std::strcmp(reason, "STALE_JOB_DROPPED") == 0) {
      stale_peer = peer;
      stale_has_id = message != nullptr;
      if (message != nullptr) stale_id = *message;
    }
  };
  for (int i = 0; i < 20; ++i) {
    w.a.poll(w.now);
    w.b.poll(w.now);
    w.net.flush(w.now);
    w.now += 5;
  }
  CHECK(w.observer_a.has_diag("STALE_JOB_DROPPED"));
  CHECK(stale_peer == GroupPowerWorld::kLeaf);
  CHECK(stale_has_id);
  CHECK(stale_id == id);
  for (const auto& message : w.observer_b.messages) {
    CHECK(!(message.key.id == id));
  }
}

void test_callback_storm_all_busy() {
  // Storms from every callback: each call is Busy and changes nothing —
  // no box to wedge, no history to bound. Afterwards a quiet attempt
  // still reaches READY.
  {
    // Five expiries in one poll, each preparing: all Busy, no attempt.
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
    for (const StatusCode code : got) {
      CHECK(code == StatusCode::Busy);
    }
    // Nothing started from the storm; a quiet prepare runs to READY.
    CHECK(w.coordinator.state() == PowerState::Running);
    CHECK(!w.events.saw(PowerState::Running, PowerState::Draining,
                        "SLEEP_PREPARE"));
    SleepRequest request{};
    CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
    CHECK(w.pump_until(PowerState::ReadyToSleep));
  }
  {
    // Abort/prepare storm from the PREPARE transition: all Busy, so the
    // single outside prepare runs to READY undisturbed. Afterwards an
    // activity storm (100 outside signals) aborts the READY attempt on
    // the first signal and a quiet run still reaches READY.
    MemoryPowerStorage storage;
    MatrixWorld w;
    CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                                 ElapsedInterval{0, 0, false}, w.now));
    w.pump(60);
    int storms = 0;
    w.events.on_transition_fn = [&](PowerState from, PowerState to,
                                    const char*) {
      if (from == PowerState::Running && to == PowerState::Draining) {
        ++storms;
        CHECK(w.coordinator.sleep_abort("STORM", w.now).code == StatusCode::Busy);
        SleepRequest retry{};
        CHECK(w.coordinator.sleep_prepare(retry, w.now).code ==
              StatusCode::Busy);
      }
    };
    SleepRequest request{};
    CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
    CHECK(w.pump_until(PowerState::ReadyToSleep));
    CHECK(storms == 1);  // the one outside prepare; nothing re-armed it
    w.events.on_transition_fn = nullptr;
    for (int i = 0; i < 100; ++i) {
      CHECK_OK(w.coordinator.notify_app_event(w.now));
      CHECK_OK(w.coordinator.notify_radio_reset(w.now));
    }
    CHECK(w.coordinator.state() == PowerState::Running);
    CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
    CHECK(w.pump_until(PowerState::ReadyToSleep));
    CHECK(w.events.transitions.size() < 60);
  }
}

void test_enter_copies_aliased_ticket() {
  // sleep_enter value-copies its ticket at receipt: passing
  // coordinator.ticket() itself — a reference to the live member — works,
  // because the submitted copy cannot be corrupted by later calls.
  MemoryPowerStorage storage;
  PowerWorld w(storage);
  CHECK_OK(w.coordinator.begin(ResetCause::ColdBoot,
                               ElapsedInterval{0, 0, false}, w.now));
  w.pump(60);
  SleepRequest request{};
  CHECK_OK(w.coordinator.sleep_prepare(request, w.now));
  CHECK(w.pump_until(PowerState::ReadyToSleep));
  CHECK_OK(w.coordinator.sleep_enter(w.coordinator.ticket(), w.now));
  CHECK(w.coordinator.state() == PowerState::Sleeping);
  CHECK(w.port.sleep_calls == 1);
}

void test_abort_never_erases_committed_snapshot() {
  // Aborting a READY attempt from OUTSIDE is RAM-only: a power cut right
  // after still conservatively restores the COMMITTED candidate (both
  // records) on a fresh incarnation. No durable-cancel claim exists —
  // and none is made.
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
    SleepRequest request{};
    request.pending_policy = SleepWorkPolicy::Save;
    CHECK_OK(coordinator.sleep_prepare(request, w.now));
    CHECK(w.run_until(coordinator, w.b, PowerState::ReadyToSleep));
    CHECK_OK(coordinator.sleep_abort("CUT", w.now));
    CHECK(coordinator.state() == PowerState::Running);
  }
  {
    // Fresh incarnation, same storage: the committed {A, B} candidate is
    // restored wholesale.
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
  SimReplyPort reply_port(radio, 7, MatrixWorld::make_config().link_epoch);
  MeshNode node(MatrixWorld::make_config(), radio, security, observer);
  FakePowerPort port;
  FixedPowerEvents events;
  PowerCoordinator coordinator(PowerConfig{500, 50}, node, port, storage,
                               events);
  (void)node.set_reply_peer_port(&reply_port);
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
  CHECK_OK(coordinator.sleep_abort("HEAP", now));
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
  coordinator.notify_app_event(now);
  coordinator.notify_radio_reset(now);
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
static_assert(noexcept(std::declval<MeshNode&>().quiesce_for_sleep()),
              "quiesce_for_sleep is noexcept");
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
static_assert(noexcept(std::declval<PowerCoordinator&>().sleep_abort(
                  nullptr, MonotonicMs{})),
              "sleep_abort is noexcept");
static_assert(noexcept(std::declval<PowerCoordinator&>().sleep_enter(
                  SleepTicket{}, MonotonicMs{})),
              "sleep_enter is noexcept");
static_assert(noexcept(std::declval<PowerCoordinator&>().wake(
                  ResetCause::ColdBoot, ElapsedInterval{}, MonotonicMs{})),
              "wake is noexcept");
static_assert(
    noexcept(std::declval<PowerCoordinator&>().notify_app_event(MonotonicMs{})),
    "notify_app_event is noexcept");
static_assert(
    noexcept(std::declval<PowerCoordinator&>().notify_radio_reset(MonotonicMs{})),
    "notify_radio_reset is noexcept");
static_assert(noexcept(std::declval<PowerCoordinator&>().ticket_valid(
                  SleepTicket{})),
              "ticket_valid is noexcept");

void test_trusted_sleep_elapsed() {
  // A timer wake and marker identify the intended sleep, but neither
  // bounds oscillator drift or post-wake boot time.
  CHECK(!classify_sleep_elapsed(true, true, true, 30000, 0).known);
  // An independently established upper bound permits deadline deduction.
  const ElapsedInterval trusted =
      classify_sleep_elapsed(true, true, true, 30000, 33000);
  CHECK(trusted.known);
  CHECK(trusted.lower_ms == 0);
  CHECK(trusted.upper_ms == 33000);
  // Any missing evidence parks TIME_UNCERTAIN instead of guessing.
  CHECK(!classify_sleep_elapsed(false, true, true, 30000, 33000).known);
  CHECK(!classify_sleep_elapsed(true, false, true, 30000, 33000).known);
  CHECK(!classify_sleep_elapsed(true, true, false, 30000, 33000).known);
  CHECK(!classify_sleep_elapsed(true, true, true, 0, 33000).known);
  const ElapsedInterval saturated = classify_sleep_elapsed(
      true, true, true, std::numeric_limits<std::uint32_t>::max(),
      std::numeric_limits<std::uint64_t>::max());
  CHECK(saturated.known);
  CHECK(saturated.upper_ms == std::numeric_limits<std::uint64_t>::max());
  // End to end: the trusted interval feeds begin() and resends a durable
  // pending whose lifetime covers it (else TIME_UNCERTAIN parks it).
  std::uint32_t remaining = 0;
  CHECK(resume_remaining_lifetime(DeadlinePolicy::WallElapsedValidity, 60000,
                                  trusted, remaining)
            .ok());
  CHECK(remaining == 60000 - static_cast<std::uint32_t>(trusted.upper_ms));
}

}  // namespace

int main() {
  test_send_lifetime_ceiling();
  test_power_stats_accumulate();
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
  test_owner_sleep_waits_for_unfinished_delivery();
  test_policy_save_durable();
  test_policy_defer();
  test_persist_full_fails_explicitly();
  test_drain_deadline_forces_settle();
  test_sleep_abort();
  test_sleep_elapsed_upper_bound();
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
  test_unknown_sleep_schema_is_not_overwritten();
  test_persist_failure_aborts();
  test_persist_failure_keeps_pending_live();
  test_ready_wait_deducts_pending_lifetime();
  test_resume_reuses_original_id_dedup_once();
  test_long_sleep_pending_expires_no_duplicate();
  test_short_sleep_resend_dedups_once();
  test_group_drain_completes_round();
  test_group_sleep_policy_fail();
  test_owner_sleep_deadline_settles_group_origin();
  test_group_sleep_policy_save();
  test_group_sleep_policy_defer();
  test_group_ordered_hold_released_for_sleep();
  test_group_sleep_commit_failure_keeps_state();
  test_group_settled_callback_abort_busy_send_refused();
  test_unicast_disposition_callback_abort_busy_send_refused();
  test_disposition_callback_send_refused();
  test_callback_abort_prepare_abort_busy_outside_works();
  test_poll_delivery_callback_abort_busy_drain_continues();
  test_settlement_callback_app_event_busy_ticket_survives();
  test_ready_transition_callback_abort_busy_ticket_survives();
  test_group_repair_not_waited_by_drain();
  test_poll_unicast_callback_abort_busy_drain_continues();
  test_unicast_settlement_callback_app_event_busy();
  test_save_outside_abort_retry_fail();
  test_save_outside_abort_durable_saved_again();
  test_tx_notice_callback_busy_quiesce_completes();
  test_sleep_hold_release_callback_busy_releases_all();
  test_sleep_hold_release_callback_busy_multi_stream();
  test_carry_expired_callback_app_event_busy();
  test_enter_expired_callback_app_event_busy();
  test_callback_busy_matrix();
  test_callback_radio_reset_busy_outside_aborts();
  test_recursive_coordinator_drive_rejected();
  test_callback_busy_freezes_machine();
  test_late_activity_invalidates_waiting_ticket();
  test_enter_notify_busy_matrix();
  test_enter_stage_faults_abort_cleanly();
  test_phase1_faults_keep_work_live();
  test_failed_second_commit_keeps_unnotified_expired_carry();
  test_failed_second_refresh_keeps_unnotified_expired_carry();
  test_failed_second_commit_keeps_old_same_id_carry();
  test_failed_second_commit_keeps_reinjected_durable_work();
  test_retry_policy_matrix_after_outside_abort();
  test_carry_overflow_keeps_carry_fails_fresh();
  test_carry_settlement_callback_busy_restores_on_new_node();
  test_carry_same_id_replaced_by_fresh();
  test_carry_same_id_callback_busy_restores_new();
  test_carry_survives_history_eviction();
  test_retry_after_outside_abort_plans_live_only();
  test_settled_verdicts_survive_stale_jobs();
  test_evicted_origin_jobs_never_dispatch();
  test_stale_unicast_drop_reports_taken_job();
  test_callback_storm_all_busy();
  test_enter_copies_aliased_ticket();
  test_abort_never_erases_committed_snapshot();
  test_sleep_path_uses_no_heap();
  test_trusted_sleep_elapsed();
  if (failures == 0) {
    std::printf("power tests passed\n");
    return 0;
  }
  std::fprintf(stderr, "%d failures\n", failures);
  return 1;
}
