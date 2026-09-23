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
  // Writes so far: the persist commit plus two sleep_enter refresh commits
  // (both slots, READY_TO_SLEEP wait deducted). The consume commit is next.
  storage.drop_call = 3;  // consume commit is lost
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
  w.storage.drop_call = 0;
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
  w.storage.drop_call = 0;  // the image commit itself fails
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
  if (failures == 0) {
    std::printf("power tests passed\n");
    return 0;
  }
  std::fprintf(stderr, "%d failures\n", failures);
  return 1;
}
