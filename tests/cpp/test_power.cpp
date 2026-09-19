// Power coordinator model tests: every state transition, sleep-ticket
// invalidation sources, prepare policies, counter-lease continuity across
// simulated power cuts, cold boot vs deep-sleep resume separation and the
// TIME_UNCERTAIN deadline rule. All clocks and storage are fakes.

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <map>
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
    const std::size_t call = write_calls++;
    last_slot = slot;
    if (call == cut_call) {
      std::memcpy(slots_[slot].data(), data.data, cut_bytes);
      return Status::error(StatusCode::StorageFailure, "power cut mid write");
    }
    if (call == drop_call) {
      return Status::error(StatusCode::StorageFailure, "power lost before write");
    }
    std::memcpy(slots_[slot].data(), data.data, data.size);
    return Status::success();
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
  std::size_t cut_call{std::numeric_limits<std::size_t>::max()};
  std::size_t cut_bytes{0};
  std::size_t drop_call{std::numeric_limits<std::size_t>::max()};
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

  void on_transition(PowerState from, PowerState to,
                     const char* reason) noexcept override {
    transitions.push_back({from, to, reason});
  }
  void on_pending_result(const PendingDeliveryRecord& record,
                         StatusCode code) noexcept override {
    pending_results.emplace_back(record.original_id, code);
  }
  void on_diagnostic(const char* reason) noexcept override {
    diagnostics.emplace_back(reason);
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
  storage.cut_call = 0;     // first image write lands a torn prefix
  storage.cut_bytes = 37;
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
  storage.drop_call = 1;  // consume commit is lost
  PowerWorld w(storage);
  CHECK_OK(w.coordinator.begin(ResetCause::DeepSleepWake,
                               ElapsedInterval{0, 0, false}, w.now));
  CHECK(w.events.pending_with(StatusCode::TimeUncertain) == 1);
  CHECK(w.storage.write_calls == 2);
  // Next boot may replay the pending once (bounded duplicate REPORT, still
  // TIME_UNCERTAIN — never a resend on an unknown clock).
  PowerWorld w2(storage);
  CHECK_OK(w2.coordinator.begin(ResetCause::DeepSleepWake,
                                ElapsedInterval{0, 0, false}, w2.now));
  CHECK(w2.events.pending_with(StatusCode::TimeUncertain) == 1);
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

}  // namespace

int main() {
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
  test_resume_confirm_fast_and_discovery();
  test_image_slots_alternate();
  test_persist_failure_aborts();
  if (failures == 0) {
    std::printf("power tests passed\n");
    return 0;
  }
  std::fprintf(stderr, "%d failures\n", failures);
  return 1;
}
