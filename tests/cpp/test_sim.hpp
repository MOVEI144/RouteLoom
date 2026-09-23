#pragma once

// Shared in-memory mesh harness for the routing tests. SimNetwork records a
// plaintext-header sighting of every delivered frame (the wire v1 header is
// AAD, not ciphertext) so tests can assert forwarding invariants: no node
// forwards the same message twice and hop_remaining decrements on each hop.

#include <array>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "routeloom/node.hpp"
#include "routeloom/types.hpp"
#include "routeloom/wire.hpp"

#include "test_security.hpp"

namespace routeloom_test {

struct FrameSight {
  routeloom::NodeId from;
  routeloom::NodeId to;
  routeloom::FrameType type;
  routeloom::NodeId origin;
  std::uint32_t session;
  std::uint64_t sequence;
  std::uint8_t round;
  std::uint8_t hop_remaining;
};

// Reads a wire v1 plaintext header directly by offset (see wire.hpp layout).
// The crypto is irrelevant here: the header is authenticated AAD, not sealed.
inline bool sight_frame(routeloom::ByteView frame, FrameSight& sight) {
  if (frame.size < 88) return false;
  const auto u8 = [&](std::size_t off) { return frame.data[off]; };
  const auto u32 = [&](std::size_t off) {
    std::uint32_t v = 0;
    for (int i = 0; i < 4; ++i) v = (v << 8U) | frame.data[off + i];
    return v;
  };
  const auto u64 = [&](std::size_t off) {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8U) | frame.data[off + i];
    return v;
  };
  if (u64(0) >> 48U != 0x524cULL) return false;  // "RL" magic
  sight.type = static_cast<routeloom::FrameType>(u8(4));
  sight.round = u8(7);
  sight.hop_remaining = u8(8);
  sight.origin = u64(16);
  sight.sequence = u64(52);
  sight.session = u32(48);
  sight.to = u64(40);    // next_hop
  sight.from = u64(32);  // previous_hop
  return true;
}

class SimNetwork;
class SimRadio final : public routeloom::RadioPort {
 public:
  SimRadio(SimNetwork& network, routeloom::NodeId owner) : network_(network), owner_(owner) {}
  routeloom::Status send(routeloom::NodeId peer, std::uint64_t token,
                         routeloom::ByteView frame) noexcept override;
  routeloom::Status recover() noexcept override { return routeloom::Status::success(); }
 private:
  SimNetwork& network_;
  routeloom::NodeId owner_;
};

class SimNetwork {
 public:
  struct Pending {
    routeloom::NodeId from;
    routeloom::NodeId to;
    std::uint64_t token;
    // Deterministic driver-service time reported at TX completion — the
    // §14 ledger and control bucket debit it verbatim (issue #46).
    std::uint64_t service_us{50};
    std::vector<std::uint8_t> frame;
  };

  void register_node(routeloom::NodeId id, routeloom::MeshNode* node) { nodes[id] = node; }
  void unregister_node(routeloom::NodeId id) { nodes.erase(id); }
  void connect(routeloom::NodeId a, routeloom::NodeId b) { links.insert(normalize(a, b)); }
  void disconnect(routeloom::NodeId a, routeloom::NodeId b) { links.erase(normalize(a, b)); }
  bool connected(routeloom::NodeId a, routeloom::NodeId b) const {
    return links.count(normalize(a, b)) != 0;
  }

  routeloom::Status enqueue(routeloom::NodeId from, routeloom::NodeId to,
                            std::uint64_t token, routeloom::ByteView frame) {
    queue.push_back(Pending{from, to, token, service_us,
                            std::vector<std::uint8_t>(frame.data, frame.data + frame.size)});
    return routeloom::Status::success();
  }

  // Deterministic service-time steering: every TX completes `service_us`
  // µs after submission unless a test overrides it per-Pending (issue #46).
  std::uint64_t service_us{50};

  // Optional deterministic loss hook for the property tests (issue #19):
  // when non-null, flush() consults it once per queued frame and a true
  // verdict drops the frame exactly like RF loss — no sighting, and the
  // sender still gets an honest TX-failure result. Null keeps flush()
  // lossless for the deterministic routing tests.
  bool (*drop_frame)(const Pending& pending) = nullptr;

  // Returns the number of undelivered frames (link down, node missing, or
  // dropped by the loss hook).
  std::size_t flush(routeloom::MonotonicMs now) {
    std::size_t dropped = 0;
    std::size_t safety = 0;
    while (!queue.empty() && safety++ < 10000) {
      Pending pending = std::move(queue.front());
      queue.pop_front();
      if (nodes.count(pending.from) == 0) {  // sender was removed mid-flight
        ++dropped;
        continue;
      }
      const bool dropped_by_hook = drop_frame != nullptr && drop_frame(pending);
      const bool success = !dropped_by_hook && connected(pending.from, pending.to) &&
                           nodes.count(pending.to) != 0;
      if (success) {
        FrameSight sight{};
        if (sight_frame(routeloom::ByteView{pending.frame.data(), pending.frame.size()}, sight)) {
          sights.push_back(sight);
        }
      } else {
        ++dropped;
      }
      {
        // The simulated driver emits the same TX-complete observation the
        // real runtime's callback produces — driver service is measured
        // here, not inside on_radio_tx_result (02-telemetry §2.3).
        routeloom::RadioTxObservation obs{};
        obs.peer = pending.to;
        obs.submitted_us = static_cast<std::uint64_t>(now) * 1000u;
        obs.completed_us = obs.submitted_us + pending.service_us;
        obs.outcome = success ? routeloom::RadioTxOutcome::Success
                              : routeloom::RadioTxOutcome::Failure;
        obs.provenance = routeloom::ObservationProvenance::LocalDriver;
        // Echo the submission token like the real runtime's Reserved lane
        // so the completion attributes to the in-flight job's §14 domain.
        obs.token = pending.token;
        nodes.at(pending.from)->note_radio_tx(obs, now);
      }
      nodes.at(pending.from)->on_radio_tx_result(pending.token, success, now);
      if (success) {
        nodes.at(pending.to)->on_radio_receive(
            pending.from, routeloom::ByteView{pending.frame.data(), pending.frame.size()},
            routeloom::RadioRxMetadata{-60}, now);
      }
    }
    return dropped;
  }

  std::vector<FrameSight> sights;

 private:
  static std::pair<routeloom::NodeId, routeloom::NodeId> normalize(routeloom::NodeId a,
                                                                 routeloom::NodeId b) {
    return a < b ? std::make_pair(a, b) : std::make_pair(b, a);
  }
  std::map<routeloom::NodeId, routeloom::MeshNode*> nodes;
  std::set<std::pair<routeloom::NodeId, routeloom::NodeId>> links;
  std::deque<Pending> queue;
};

inline routeloom::Status SimRadio::send(routeloom::NodeId peer, std::uint64_t token,
                                        routeloom::ByteView frame) noexcept {
  return network_.enqueue(owner_, peer, token, frame);
}

struct CapturingObserver final : routeloom::NodeObserver {
  std::vector<std::vector<std::uint8_t>> messages;
  std::vector<routeloom::DeliveryResult> delivery_events;
  std::vector<std::string> diagnostics;
  std::vector<routeloom::NodeId> diagnostic_peers;  // peer arg, index-aligned with diagnostics

  void on_message(const routeloom::MessageKey&, routeloom::NodeId,
                  routeloom::ByteView payload) noexcept override {
    messages.emplace_back(payload.data, payload.data + payload.size);
  }
  void on_delivery(const routeloom::DeliveryResult& result) noexcept override {
    delivery_events.push_back(result);
  }
  void on_diagnostic(const char* reason, routeloom::NodeId peer, const routeloom::MessageId*) noexcept override {
    diagnostics.emplace_back(reason);
    diagnostic_peers.push_back(peer);
  }

  bool has_diag(const char* prefix) const {
    for (const auto& d : diagnostics) {
      if (d.rfind(prefix, 0) == 0) return true;
    }
    return false;
  }
};

// Convenience world builder: owns security providers, observers, radios and
// nodes so tests stay a few lines each.
struct SimWorld {
  routeloom::NetworkId network_id{1};
  SimNetwork net;
  std::map<routeloom::NodeId, std::unique_ptr<routeloom_test::TestSecurity>> security;
  std::map<routeloom::NodeId, std::unique_ptr<CapturingObserver>> observers;
  std::map<routeloom::NodeId, std::unique_ptr<SimRadio>> radios;
  std::map<routeloom::NodeId, std::unique_ptr<routeloom::MeshNode>> nodes;
  routeloom::MonotonicMs now{0};

  routeloom::MeshNode* add(routeloom::NodeId id, routeloom::RouteGeneration generation = 1,
                           std::uint32_t adv_ms = 100, std::uint32_t life_ms = 1000) {
    routeloom::NodeConfig config{};
    config.network = network_id;
    config.node = id;
    config.message_session = 100 + static_cast<std::uint32_t>(id);
    config.boot_incarnation = 0xB000 + static_cast<std::uint32_t>(id);
    config.route_generation = generation;
    config.route_advertisement_period_ms = adv_ms;
    config.route_lifetime_ms = life_ms;
    security[id] = std::make_unique<routeloom_test::TestSecurity>();
    observers[id] = std::make_unique<CapturingObserver>();
    radios[id] = std::make_unique<SimRadio>(net, id);
    nodes[id] = std::make_unique<routeloom::MeshNode>(config, *radios[id], *security[id],
                                                    *observers[id]);
    net.register_node(id, nodes[id].get());
    return nodes[id].get();
  }

  routeloom::MeshNode* at(routeloom::NodeId id) const { return nodes.at(id).get(); }
  CapturingObserver* obs(routeloom::NodeId id) const { return observers.at(id).get(); }

  void remove_node(routeloom::NodeId id) {
    net.unregister_node(id);
    nodes.erase(id);
    radios.erase(id);
    security.erase(id);
    observers.erase(id);
  }

  void link(routeloom::NodeId a, routeloom::NodeId b, routeloom::RouteMetric metric_ab,
            routeloom::RouteMetric metric_ba) {
    net.connect(a, b);
    at(a)->add_neighbor(b, metric_ab, now);
    at(b)->add_neighbor(a, metric_ba, now);
  }

  void unlink(routeloom::NodeId a, routeloom::NodeId b) {
    net.disconnect(a, b);
    at(a)->remove_neighbor(b, now);
    at(b)->remove_neighbor(a, now);
  }

  void start_all() {
    for (auto& [id, node] : nodes) node->start(now);
  }

  // Drives the whole mesh: poll every node then flush the radio queue.
  void run(routeloom::MonotonicMs duration_ms, routeloom::MonotonicMs step = 5) {
    const routeloom::MonotonicMs end = now + duration_ms;
    for (; now <= end; now += step) {
      for (auto& [id, node] : nodes) node->poll(now);
      net.flush(now);
    }
  }
};

}  // namespace routeloom_test
