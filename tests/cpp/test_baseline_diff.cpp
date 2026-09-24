// Autonomous-mesh baseline-diff harness (docs/design/autonomous-mesh/
// 05-implementation.md: 固定250 baselineとの差分 — success rate, latency,
// TX count and resource proxy under identical simulated load).
//
// Two runs of the SAME deterministic SimWorld scenario:
//   baseline  — the fixed-250 stack: no peer proves BUSY capability, so the
//               relay falls back to the legacy silent drop on admission
//               failure (D4-09) and senders retry blind on the hop timeout.
//   autonomy  — the AUTONOMY_LR250_V1 lane: the relay holds BUSY grants for
//               the senders, but under this saturating load the reply slot
//               for the BUSY itself is unaffordable (issue #117, Q117-14),
//               so both lanes degrade to diagnosed, counted drops and the
//               senders' finite retry recovers (D4-09 unified).
//
// This is a host-side simulation diff, not an RF claim: it measures how the
// two stacks behave on the same offered load in the in-memory scheduler —
// never channel airtime, PHY timing or hardware performance.

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <vector>

#include "routeloom/congestion.hpp"
#include "routeloom/node.hpp"
#include "routeloom/types.hpp"
#include "routeloom/wire.hpp"

#include "test_security.hpp"
#include "test_sim.hpp"

namespace {

int failures = 0;
#define CHECK(expr)                                                          \
  do {                                                                       \
    if (!(expr)) {                                                           \
      std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__,   \
                   #expr);                                                   \
      ++failures;                                                            \
    }                                                                        \
  } while (false)
#define CHECK_OK(expr)                                                       \
  do {                                                                       \
    const auto _status = (expr);                                             \
    if (!_status.ok()) {                                                     \
      std::fprintf(stderr, "STATUS failed %s:%d: %s (%s)\n", __FILE__,       \
                   __LINE__, #expr, _status.detail);                         \
      ++failures;                                                            \
    }                                                                        \
  } while (false)

using namespace routeloom;
using routeloom_test::CapturingObserver;
using routeloom_test::SimWorld;
using routeloom_test::TestSecurity;

constexpr NetworkId kNet = 7;
const std::uint8_t kPayload[] = "baseline-diff";

ByteView payload_view() { return ByteView{kPayload, sizeof(kPayload) - 1}; }

constexpr NodeId kSenders[] = {1, 4, 5, 6};
constexpr NodeId kRelay = 2;
constexpr NodeId kDestination = 3;
constexpr int kMessagesPerSender = 24;

struct Pending {
  NodeId sender;
  MessageId id;
  MonotonicMs sent_ms;
  DeliveryState outcome;  // first terminal verdict; Empty while in flight
};

struct RunResult {
  std::size_t offered = 0;
  std::size_t admitted = 0;   // send() accepted into the sender scheduler
  std::size_t refused = 0;    // send() rejected at admission (own caps full)
  std::size_t delivered = 0;
  std::size_t failed = 0;     // Failed + Expired
  std::size_t pending = 0;    // no terminal verdict by the horizon
  std::size_t app_delivered = 0;  // on_message count at the destination
  std::size_t data_tx = 0;    // DATA frame transmissions on the air
  std::size_t busy_tx = 0;    // BUSY frames emitted
  std::size_t accept_tx = 0;  // HOP_ACCEPT frames
  std::uint64_t latency_ms = 0;   // summed send->delivered latency (delivered only)
  std::size_t latency_n = 0;
  std::uint64_t relay_busy_sent = 0;
  std::uint64_t relay_busy_failed = 0;
  std::uint64_t senders_busy_received = 0;
  std::uint64_t senders_readmitted = 0;
  std::uint64_t history_evicted = 0;  // sender delivery-table recycling
};

bool terminal(DeliveryState state) {
  return state == DeliveryState::Delivered || state == DeliveryState::Failed ||
         state == DeliveryState::Expired ||
         state == DeliveryState::CancelledBeforeTx;
}

// One scripted run. `autonomy` selects the only difference between the two
// worlds: whether the relay treats the senders as BUSY-capable peers.
RunResult run_scenario(const bool autonomy) {
  SimWorld world;
  world.network_id = kNet;
  for (NodeId sender : kSenders) (void)world.add(sender);
  MeshNode* relay = world.add(kRelay);
  (void)world.add(kDestination);
  world.start_all();
  for (NodeId sender : kSenders) world.link(sender, kRelay, 1, 1);
  world.link(kRelay, kDestination, 1, 1);
  // The autonomy relay holds a configured BUSY grant for every sender. A
  // grant is bounded (kCapabilitiesValidityMs) and refreshed by its owner —
  // re-applied every tick here, so the lane stays enabled for the whole run
  // instead of silently reverting to the baseline's legacy drop once the
  // first grant lapses mid-scenario.
  const auto refresh_grants = [&]() {
    if (!autonomy) return;
    for (NodeId sender : kSenders) relay->set_peer_busy_capable(sender, true);
  };
  const auto run = [&](MonotonicMs ms) {
    refresh_grants();
    world.run(ms);
  };
  run(2500);  // converge: identical prefix in both runs
  CHECK(world.at(kSenders[0])->routes().best(kDestination).valid);

  // Identical offered load: every sender offers kMessagesPerSender messages
  // for node 3, one send per sender per 4ms tick. The send() return is part
  // of the measurement — the schedule is fixed, the outcome is not.
  std::vector<Pending> pending;
  std::size_t offered = 0, admitted = 0, refused = 0;
  std::uint64_t latency_ms = 0;
  std::size_t latency_n = 0;
  // Outcome detector. The sender's 8-slot delivery table recycles terminal
  // history for new sends (DELIVERY_HISTORY_EVICTED), so re-reading
  // delivery() at the horizon reports Empty for results that were delivered
  // and then evicted — the source of the old "delivered 25 vs 30" wobble.
  // The verdict is therefore taken from the on_delivery event stream (every
  // state change, in order); the first terminal event is final (a verdict
  // is never demoted or promoted — test_properties).
  std::map<NodeId, std::size_t> cursor;
  const auto settle = [&]() {
    for (NodeId sender : kSenders) {
      const auto& events = world.obs(sender)->delivery_events;
      for (std::size_t& i = cursor[sender]; i < events.size(); ++i) {
        const DeliveryResult& event = events[i];
        if (!terminal(event.state)) continue;
        for (auto& p : pending) {
          if (p.sender != sender || !(p.id == event.id) ||
              p.outcome != DeliveryState::Empty) {
            continue;
          }
          p.outcome = event.state;
          if (event.state == DeliveryState::Delivered) {
            latency_ms += world.now - p.sent_ms;
            ++latency_n;
          }
        }
      }
    }
  };
  for (int round = 0; round < kMessagesPerSender; ++round) {
    for (NodeId sender : kSenders) {
      MessageId id{};
      SendOptions options{};
      options.lifetime_ms = 30000;  // outlives the drain horizon in both runs
      const Status status = world.at(sender)->send(
          kDestination, payload_view(), options, world.now, id);
      ++offered;
      if (status.ok()) {
        ++admitted;
        pending.push_back(Pending{sender, id, world.now, DeliveryState::Empty});
      } else {
        ++refused;
      }
      // A refused send() may still have emitted events (history eviction
      // happens inside send): fold them in before the next send.
      settle();
    }
    run(4);
    settle();
  }
  // Drain horizon: identical in both runs, long enough for every retry,
  // deferral and readmission budget to exhaust.
  const MonotonicMs drain_end = world.now + 12000;
  while (world.now < drain_end) {
    run(10);
    settle();
  }

  RunResult r{};
  r.offered = offered;
  r.admitted = admitted;
  r.refused = refused;
  r.latency_ms = latency_ms;
  r.latency_n = latency_n;
  for (const auto& p : pending) {
    if (p.outcome == DeliveryState::Delivered) ++r.delivered;
    if (p.outcome == DeliveryState::Failed || p.outcome == DeliveryState::Expired)
      ++r.failed;
    if (p.outcome == DeliveryState::Empty) ++r.pending;
  }
  r.app_delivered = world.obs(kDestination)->messages.size();
  for (const auto& sight : world.net.sights) {
    if (sight.type == FrameType::Data) ++r.data_tx;
    if (sight.type == FrameType::Busy) ++r.busy_tx;
    if (sight.type == FrameType::HopAccept) ++r.accept_tx;
  }
  const CongestionStats relay_stats = relay->congestion_stats();
  r.relay_busy_sent = relay_stats.busy_sent;
  r.relay_busy_failed = relay_stats.busy_send_failed;
  for (NodeId sender : kSenders) {
    const CongestionStats s = world.at(sender)->congestion_stats();
    r.senders_busy_received += s.busy_received;
    r.senders_readmitted += s.busy_readmitted;
    r.history_evicted += world.at(sender)->dedup_stats().delivery_terminal_evicted;
  }
  return r;
}

void report(const char* name, const RunResult& r) {
  std::printf(
      "[%s] offered=%zu admitted=%zu refused=%zu delivered=%zu failed=%zu "
      "pending=%zu app=%zu hist_evicted=%llu | data_tx=%zu busy_tx=%zu accept_tx=%zu | relay busy "
      "sent=%llu failed=%llu | senders busy_rx=%llu readmit=%llu | "
      "mean_latency=%llums (n=%zu)\n",
      name, r.offered, r.admitted, r.refused, r.delivered, r.failed,
      r.pending, r.app_delivered,
      static_cast<unsigned long long>(r.history_evicted), r.data_tx, r.busy_tx, r.accept_tx,
      static_cast<unsigned long long>(r.relay_busy_sent),
      static_cast<unsigned long long>(r.relay_busy_failed),
      static_cast<unsigned long long>(r.senders_busy_received),
      static_cast<unsigned long long>(r.senders_readmitted),
      r.latency_n == 0
          ? 0ULL
          : static_cast<unsigned long long>(r.latency_ms / r.latency_n),
      r.latency_n);
}

}  // namespace

int main() {
  const RunResult baseline = run_scenario(false);
  const RunResult autonomy = run_scenario(true);
  report("fixed-250 baseline", baseline);
  report("autonomy-enabled  ", autonomy);

  // The offered load is identical by construction — the diff is behavior,
  // not input.
  CHECK(baseline.offered == autonomy.offered);

  // At this saturating load no BUSY is affordable in either lane: the
  // relay's reply budget is held by admitted work, so every refusal is a
  // diagnosed, counted drop (Q117-14) and no BUSY reaches the air.
  CHECK(baseline.busy_tx == 0);
  CHECK(autonomy.busy_tx == 0);
  CHECK(autonomy.senders_busy_received == 0);
  // The drops are counted, not silent: the refusal path ran in both runs.
  CHECK(baseline.relay_busy_failed > 0);
  CHECK(autonomy.relay_busy_failed > 0);

  // The unified drop-plus-retry degradation must not lose more application
  // data than the silent-drop baseline under the same load.
  CHECK(autonomy.delivered >= baseline.delivered);

  // The verdicts are the application's truth: every Delivered verdict is
  // exactly one on_message at the destination, in both runs (no duplicate
  // from BUSY readmission, no delivery the origin was not told about).
  CHECK(baseline.app_delivered == baseline.delivered);
  CHECK(autonomy.app_delivered == autonomy.delivered);

  // Every offered message resolves to a declared outcome in both runs —
  // the scheduler never silently loses one.
  CHECK(baseline.admitted == baseline.delivered + baseline.failed +
                                 baseline.pending);
  CHECK(autonomy.admitted == autonomy.delivered + autonomy.failed +
                                 autonomy.pending);
  if (failures != 0) {
    std::fprintf(stderr, "%d baseline-diff checks failed\n", failures);
    return 1;
  }
  return 0;
}
