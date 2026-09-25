#pragma once

// Shared in-memory mesh harness for the routing tests. SimNetwork records a
// plaintext-header sighting of every delivered frame (the wire v1 header is
// AAD, not ciphertext) so tests can assert forwarding invariants: no node
// forwards the same message twice and hop_remaining decrements on each hop.

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "routeloom/node.hpp"
#include "routeloom/reply_peer_leases.hpp"
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
class SimReplyPort;
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
  void unregister_node(routeloom::NodeId id) {
    nodes.erase(id);
    reply_ports.erase(id);
  }
  // The receiver's Owner port: flush() snapshots the sender's binding from it
  // so deliveries carry the same RX evidence the real runtime captures.
  void register_reply_port(routeloom::NodeId id, SimReplyPort* port) {
    if (port == nullptr) {
      reply_ports.erase(id);
    } else {
      reply_ports[id] = port;
    }
  }
  SimReplyPort* reply_port(routeloom::NodeId id) const {
    const auto it = reply_ports.find(id);
    return it == reply_ports.end() ? nullptr : it->second;
  }
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
  // Silent loss (group delivery tests): when non-null and true, the sender
  // gets an honest MAC success (the frame was acknowledged on the air) but
  // the receiver never processes it — loss after the MAC ACK (RX queue
  // overflow, corruption above the MAC), which link retries cannot see.
  bool (*silent_drop)(const Pending& pending) = nullptr;
  // Driver backpressure without a physical attempt. ACKs may drain while
  // queued DATA remains live under its original deadline.
  bool (*block_send)(routeloom::NodeId from, routeloom::NodeId to,
                     routeloom::ByteView frame) = nullptr;

  // Long simulations (issue #59): sightings can be switched off so a
  // multi-minute 100-node run does not grow an unbounded vector; the
  // per-sender route-control tally below stays on regardless.
  bool record_sights{true};

  // Per-sender tally of route-control TX attempts (ROUTE_UPDATE,
  // SEQNO_REQUEST, ROUTE_REQUEST) — delivered or not, every attempt costs
  // air time. Encoded frame bytes, for the §14 airtime estimate.
  struct TxTally {
    std::uint64_t frames{0};
    std::uint64_t bytes{0};
  };
  std::map<routeloom::NodeId, TxTally> route_control_tx;
  // Every TX attempt by frame type (group delivery airtime, issue #82):
  // delivered or not, each attempt costs air time.
  std::map<routeloom::FrameType, TxTally> tx_by_type;

  // Owner-side component drive (issue #117, design-q116 §8.3): after the
  // node calls above returned, take each node's pending component events
  // (at most kComponentEventsMax per node) and hand them to the installed
  // Service/config components as ordinary outside calls, then complete
  // each event. Payload events past their deadline are completed without
  // starting new component work; completions of finished jobs are always
  // delivered. The installed components are ticked after their events.
  void pump_components(routeloom::MonotonicMs now);

  // Returns the number of undelivered frames (link down, node missing, or
  // dropped by the loss hook).
  //
  // A TX completion wakes the sender's owner task (issue #60-3): each
  // outer iteration drains every queued event, then every node a
  // completion reached runs its post-drain poll — the wake -> drain ->
  // poll the firmware owner task performs on an event. The polls enqueue
  // the next frames, which the following iteration delivers, so
  // back-to-back sends chain at the callback rate with no poll-tick tax —
  // while the whole drain still precedes any dispatch, keeping RX-raised
  // control replies ahead of queued DATA. The receiver side keeps the
  // step cadence callers already model with their own poll loops.
  //
  // The drain bound counts dequeued frames only — outer wake/poll
  // iterations cost nothing — so chained traffic keeps the historic
  // 10,000-frame budget. When the bound stops the drain with frames
  // still queued, flush() aborts instead of returning the partial drain
  // silently.
  std::size_t flush(routeloom::MonotonicMs now);


  std::vector<FrameSight> sights;

 private:
  static std::pair<routeloom::NodeId, routeloom::NodeId> normalize(routeloom::NodeId a,
                                                                 routeloom::NodeId b) {
    return a < b ? std::make_pair(a, b) : std::make_pair(b, a);
  }
  std::map<routeloom::NodeId, routeloom::MeshNode*> nodes;
  std::map<routeloom::NodeId, SimReplyPort*> reply_ports;
  std::set<std::pair<routeloom::NodeId, routeloom::NodeId>> links;
  std::deque<Pending> queue;
};

inline routeloom::Status SimRadio::send(routeloom::NodeId peer, std::uint64_t token,
                                        routeloom::ByteView frame) noexcept {
  if (network_.block_send != nullptr && network_.block_send(owner_, peer, frame)) {
    return routeloom::Status::error(routeloom::StatusCode::WouldBlock,
                                    "simulated driver backpressure");
  }
  return network_.enqueue(owner_, peer, token, frame);
}

// Simulated radio Owner's ExpectedReply lease port (issue #117): a stable
// binding directory (one minted BindingId per peer, never id 0 shared) over
// the portable ExpectedReplyLeases table, with sends routed into the sim
// radio. Mirrors the contract the real ESP-NOW runtime implements — mapping
// recheck before every acquire/send, driver pin before success — so node
// admission tests exercise the same enforcement shape host-side.
//
// The test world supplies each peer's actual receive context. Peer boot
// epochs and receiver-chosen session ids can differ from the local TX epoch.
class SimReplyPort final : public routeloom::ReplyPeerPort {
 public:
  SimReplyPort(routeloom::RadioPort& radio, routeloom::NodeId owner,
               std::uint32_t rx_context) noexcept
      : radio_(radio),
        owner_(owner),
        rx_context_(rx_context != 0 ? rx_context : 1) {}

  void set_rx_context(routeloom::NodeId peer,
                      std::uint32_t context) noexcept {
    if (context == 0) return;
    if (directory_.find(peer) == directory_.end()) (void)mapping(peer);
    auto& live = directory_.at(peer);
    if (live.rx_context_id != context) {
      (void)leases_.invalidate_binding(live.id);
      live.rx_context_id = context;
    }
  }

  routeloom::Status acquire(routeloom::ReplyBinding captured,
                            routeloom::MonotonicMs deadline,
                            routeloom::MonotonicMs now,
                            routeloom::ReplyLeaseToken& out) noexcept override {
    const routeloom::ReplyBinding live = mapping(captured.peer);
    if (live.peer != captured.peer || live.id != captured.id ||
        live.generation != captured.generation ||
        live.rx_context_id != captured.rx_context_id) {
      return routeloom::Status::error(routeloom::StatusCode::Conflict,
                                      "sim mapping changed");
    }
    pinned_.insert(captured.peer);
    const routeloom::Status status = leases_.acquire(captured, deadline, now, out);
    if (!status) pinned_.erase(captured.peer);
    return status;
  }
  routeloom::Status release(routeloom::ReplyLeaseToken token) noexcept override {
    routeloom::ReplyBinding bound{};
    const bool known = leases_.use_binding(token, bound).ok();
    const routeloom::Status status = leases_.release(token);
    if (status && known && !leases_.holds_binding(bound.id, bound.generation)) {
      pinned_.erase(bound.peer);
    }
    return status;
  }
  routeloom::Status validate(routeloom::ReplyLeaseToken token,
                             routeloom::MonotonicMs now) noexcept override {
    return leases_.validate(token, now);
  }
  routeloom::Status send_reply(routeloom::ReplyLeaseToken token,
                               std::uint64_t tx_token, routeloom::ByteView frame,
                               routeloom::MonotonicMs now) noexcept override {
    routeloom::ReplyBinding bound{};
    routeloom::Status status = leases_.use_binding(token, bound);
    if (!status) return status;
    status = leases_.validate(token, now);
    if (!status) return status;
    const routeloom::ReplyBinding live = mapping(bound.peer);
    if (live.id != bound.id || live.generation != bound.generation ||
        live.rx_context_id != bound.rx_context_id ||
        pinned_.count(bound.peer) == 0) {
      return routeloom::Status::error(routeloom::StatusCode::Conflict,
                                      "sim mapping changed");
    }
    return radio_.send(bound.peer, tx_token, frame);
  }
  routeloom::Status snapshot_binding(routeloom::NodeId peer,
                                     routeloom::ReplyBinding& out) noexcept override {
    if (peer == routeloom::kInvalidNodeId || peer == owner_) {
      return routeloom::Status::error(routeloom::StatusCode::InvalidArgument,
                                      "sim snapshot identity");
    }
    if (stale_.count(peer) != 0) {
      return routeloom::Status::error(routeloom::StatusCode::Conflict,
                                      "sim peer stale");
    }
    out = mapping(peer);
    return routeloom::Status::success();
  }
  routeloom::Status send_bound(routeloom::ReplyBinding binding,
                               std::uint64_t tx_token,
                               routeloom::ByteView frame) noexcept override {
    if (stale_.count(binding.peer) != 0) {
      return routeloom::Status::error(routeloom::StatusCode::Conflict,
                                      "sim peer stale");
    }
    const routeloom::ReplyBinding live = mapping(binding.peer);
    if (live != binding) {
      return routeloom::Status::error(routeloom::StatusCode::Conflict,
                                      "sim mapping changed");
    }
    return radio_.send(binding.peer, tx_token, frame);
  }

  // Test-only mutation: retire one peer (Stale equivalent — permanent in the
  // sim; the firmware Owner revives with a fresh generation on rebind).
  // Snapshots, bound sends, and new acquires for the peer refuse from here
  // on; outstanding uses drain via release.
  void retire_peer(routeloom::NodeId peer) noexcept {
    stale_.insert(peer);
    const auto it = directory_.find(peer);
    if (it != directory_.end()) {
      (void)leases_.invalidate_binding(it->second.id);
      directory_.erase(it);
    }
    pinned_.erase(peer);
  }
  const routeloom::ExpectedReplyLeases& leases() const noexcept { return leases_; }

 private:
  routeloom::ReplyBinding mapping(routeloom::NodeId peer) noexcept {
    if (stale_.count(peer) != 0) {
      // Frozen: a retired peer never mints again — captures mismatch it.
      return routeloom::ReplyBinding{peer, routeloom::BindingId{0},
                                     routeloom::BindingGeneration{0}, 0};
    }
    const auto it = directory_.find(peer);
    if (it != directory_.end()) return it->second;
    routeloom::BindingId id{0};
    (void)routeloom::mint_binding_id(next_binding_id_, id);
    const routeloom::ReplyBinding fresh{peer, id, routeloom::BindingGeneration{1},
                                        rx_context_};
    directory_[peer] = fresh;
    return fresh;
  }

  routeloom::RadioPort& radio_;
  routeloom::NodeId owner_;
  std::uint32_t rx_context_;
  std::uint32_t next_binding_id_{1};
  std::map<routeloom::NodeId, routeloom::ReplyBinding> directory_;
  std::set<routeloom::NodeId> pinned_;
  std::set<routeloom::NodeId> stale_;
  routeloom::ExpectedReplyLeases leases_;
};

// V2 RX metadata carrying the receiver Owner port's binding snapshot for
// `peer` — the RX evidence manual inject() helpers must supply now that
// admission requires it. A null port (or snapshot failure) yields invalid
// evidence, which admission refuses.
inline routeloom::RadioRxMetadataV2 sim_rx_metadata(
    SimReplyPort* port, routeloom::NodeId peer, std::int8_t rssi = -60) {
  routeloom::RadioRxMetadataV2 meta{};
  meta.rssi_dbm = rssi;
  meta.rssi_valid = true;
  meta.provenance = routeloom::ObservationProvenance::InjectedTest;
  if (port != nullptr) {
    routeloom::ReplyBinding binding{};
    if (port->snapshot_binding(peer, binding).ok()) {
      meta.binding = binding.id;
      meta.binding_generation = binding.generation;
    }
  }
  return meta;
}

inline std::size_t SimNetwork::flush(routeloom::MonotonicMs now) {
    std::size_t dropped = 0;
    constexpr std::size_t kFlushLimit = 10000;
    std::size_t processed = 0;
    while (!queue.empty() && processed < kFlushLimit) {
      std::set<routeloom::NodeId> woken;
      while (!queue.empty() && processed < kFlushLimit) {
        ++processed;
        Pending pending = std::move(queue.front());
        queue.pop_front();
        if (nodes.count(pending.from) == 0) {  // sender was removed mid-flight
          ++dropped;
          continue;
        }
        if (pending.frame.size() > 4) {
          const auto type = static_cast<routeloom::FrameType>(pending.frame[4]);
          auto& by_type = tx_by_type[type];
          ++by_type.frames;
          by_type.bytes += pending.frame.size();
          if (type == routeloom::FrameType::RouteUpdate ||
              type == routeloom::FrameType::SeqnoRequest ||
              type == routeloom::FrameType::RouteRequest) {
            auto& tally = route_control_tx[pending.from];
            ++tally.frames;
            tally.bytes += pending.frame.size();
          }
        }
        if (pending.to == routeloom::kBroadcastNodeId) {
          // RF broadcast (P5-2): one tally above, one sight, one driver
          // completion — a broadcast has no MAC ACK, so even a hook-dropped
          // copy still completes Success while its receiver stays silent —
          // and one delivery per connected listener, each with that
          // listener's own RX evidence. The loss hooks see a per-receiver
          // view (to = the listener), exactly like a unicast to it.
          FrameSight sight{};
          if (record_sights &&
              sight_frame(routeloom::ByteView{pending.frame.data(), pending.frame.size()}, sight)) {
            sights.push_back(sight);
          }
          {
            routeloom::RadioTxObservation obs{};
            obs.peer = pending.to;
            obs.submitted_us = static_cast<std::uint64_t>(now) * 1000u;
            obs.completed_us = obs.submitted_us + pending.service_us;
            obs.outcome = routeloom::RadioTxOutcome::Success;
            obs.provenance = routeloom::ObservationProvenance::LocalDriver;
            obs.token = pending.token;
            (void)nodes.at(pending.from)->note_radio_tx(obs, now);
          }
          (void)nodes.at(pending.from)
              ->on_radio_tx_result(pending.token, true, now);
          woken.insert(pending.from);
          for (const auto& [id, node] : nodes) {
            if (id == pending.from || !connected(pending.from, id)) continue;
            Pending view = pending;
            view.to = id;
            if (drop_frame != nullptr && drop_frame(view)) {
              ++dropped;
              continue;
            }
            if (silent_drop != nullptr && silent_drop(view)) {
              ++dropped;
              continue;
            }
            const routeloom::RadioRxMetadataV2 meta =
                sim_rx_metadata(reply_port(id), pending.from);
            (void)node->on_radio_receive(
                pending.from,
                routeloom::ByteView{pending.frame.data(), pending.frame.size()},
                meta, now);
          }
          continue;
        }
        const bool dropped_by_hook = drop_frame != nullptr && drop_frame(pending);
        const bool success = !dropped_by_hook && connected(pending.from, pending.to) &&
                             nodes.count(pending.to) != 0;
        if (success) {
          FrameSight sight{};
          if (record_sights &&
              sight_frame(routeloom::ByteView{pending.frame.data(), pending.frame.size()}, sight)) {
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
          (void)nodes.at(pending.from)->note_radio_tx(obs, now);
        }
        (void)nodes.at(pending.from)
            ->on_radio_tx_result(pending.token, success, now);
        woken.insert(pending.from);
        if (success && silent_drop != nullptr && silent_drop(pending)) {
          ++dropped;
          continue;
        }
        if (success) {
          // V2 delivery with the receiver's binding snapshot — the RX
          // evidence the real runtime captures at enqueue. A receiver
          // without a registered Owner port gets invalid evidence and
          // refuses admission.
          const routeloom::RadioRxMetadataV2 meta =
              sim_rx_metadata(reply_port(pending.to), pending.from);
          (void)nodes.at(pending.to)->on_radio_receive(
              pending.from,
              routeloom::ByteView{pending.frame.data(), pending.frame.size()},
              meta, now);
        }
      }
      // The queue is drained: every sender a completion reached wakes and
      // runs its post-drain poll — submissions from these polls land in
      // the queue the next iteration delivers.
      for (const routeloom::NodeId id : woken) {
        if (nodes.count(id) != 0) nodes.at(id)->poll(now);
      }
    }
    if (!queue.empty()) {
      // The dequeue bound stopped the drain with frames still queued: the
      // undelivered remainder would silently skew every assertion after
      // this flush, so fail here rather than return a partial drain.
      std::fprintf(stderr,
                   "SimNetwork::flush: dequeue bound (%zu frames) hit with %zu still queued\n",
                   kFlushLimit, queue.size());
      std::abort();
    }
    pump_components(now);
    return dropped;
  }

inline void SimNetwork::pump_components(routeloom::MonotonicMs now) {
  for (auto& [id, node] : nodes) {
    for (std::size_t i = 0; i < routeloom::kComponentEventsMax; ++i) {
      routeloom::ComponentEvent event{};
      if (!node->take_component_event(event).ok()) break;
      const bool payload =
          event.target == routeloom::ComponentEventTarget::ServicePayload ||
          event.target == routeloom::ComponentEventTarget::ConfigFrame;
      // A payload whose transaction already expired never starts new
      // component work; its event still completes to free the reference.
      if (!payload || now < event.deadline_ms) {
        switch (event.target) {
          case routeloom::ComponentEventTarget::ServicePayload:
            if (node->gateway_sink() != nullptr) {
              node->gateway_sink()->on_service_payload(event.peer, event.frame,
                                                       now);
            }
            break;
          case routeloom::ComponentEventTarget::ConfigFrame:
            if (node->config_sink() != nullptr) {
              node->config_sink()->on_config_frame(event.peer, event.frame,
                                                   now);
            }
            break;
          case routeloom::ComponentEventTarget::ServiceJobDone:
            if (node->gateway_sink() != nullptr) {
              node->gateway_sink()->on_service_job_done(
                  event.job_id, event.job_accepted, event.job_reason, now);
            }
            break;
          case routeloom::ComponentEventTarget::ConfigJobDone:
            if (node->config_sink() != nullptr) {
              node->config_sink()->on_config_job_done(
                  event.job_id, event.job_accepted, event.job_reason, now);
            }
            break;
        }
      }
      (void)node->complete_component_event(event.handle);
    }
    // The component tick the node poll used to provide (design-q116 §8.3):
    // gateway first, then config — the historical order.
    if (node->gateway_sink() != nullptr) node->gateway_sink()->poll(now);
    if (node->config_sink() != nullptr) node->config_sink()->poll(now);
  }
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
  // Group delivery (group-delivery.md): the payload also lands in
  // `messages` (the default on_group_message behaviour); the metadata is kept
  // index-aligned in `group_messages`.
  struct GroupReceipt {
    routeloom::GroupMessageInfo info;
    std::vector<std::uint8_t> payload;
  };
  std::vector<GroupReceipt> group_messages;
  std::vector<routeloom::GroupDeliveryResult> group_results;
  void on_group_message(const routeloom::GroupMessageInfo& info,
                        routeloom::ByteView payload) noexcept override {
    group_messages.push_back(
        GroupReceipt{info, std::vector<std::uint8_t>(payload.data, payload.data + payload.size)});
    on_message(info.key, info.key.origin, payload);
  }
  void on_group_delivery(const routeloom::GroupDeliveryResult& result) noexcept override {
    group_results.push_back(result);
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
  std::map<routeloom::NodeId, std::unique_ptr<SimReplyPort>> reply_ports;
  std::map<routeloom::NodeId, std::unique_ptr<routeloom::MeshNode>> nodes;
  std::map<routeloom::NodeId, std::uint32_t> peer_link_epochs;
  routeloom::MonotonicMs now{0};
  // Epochs stamped on nodes added afterwards (Wire v2: 32-bit).
  std::uint32_t link_epoch{1};
  std::uint32_t end_epoch{1};
  // Optional per-world config hook applied to every node added afterwards
  // (e.g. the gateway-scoped routing profile).
  std::function<void(routeloom::NodeConfig&)> configure;

  routeloom::MeshNode* add(routeloom::NodeId id, routeloom::RouteGeneration generation = 1,
                           std::uint32_t adv_ms = 100, std::uint32_t life_ms = 1000) {
    routeloom::NodeConfig config{};
    config.network = network_id;
    config.node = id;
    config.message_session = 100 + static_cast<std::uint32_t>(id);
    config.boot_incarnation = 0xB000 + static_cast<std::uint32_t>(id);
    config.route_generation = generation;
    config.link_epoch = link_epoch;
    config.end_epoch = end_epoch;
    config.route_advertisement_period_ms = adv_ms;
    config.route_lifetime_ms = life_ms;
    if (configure) configure(config);
    security[id] = std::make_unique<routeloom_test::TestSecurity>();
    observers[id] = std::make_unique<CapturingObserver>();
    radios[id] = std::make_unique<SimRadio>(net, id);
    reply_ports[id] =
        std::make_unique<SimReplyPort>(*radios[id], id, config.link_epoch);
    for (const auto& [other, epoch] : peer_link_epochs) {
      reply_ports[id]->set_rx_context(other, epoch);
      reply_ports[other]->set_rx_context(id, config.link_epoch);
    }
    peer_link_epochs[id] = config.link_epoch;
    nodes[id] = std::make_unique<routeloom::MeshNode>(config, *radios[id], *security[id],
                                                    *observers[id]);
    nodes[id]->set_reply_peer_port(reply_ports[id].get());
    net.register_node(id, nodes[id].get());
    net.register_reply_port(id, reply_ports[id].get());
    return nodes[id].get();
  }

  routeloom::MeshNode* at(routeloom::NodeId id) const { return nodes.at(id).get(); }
  CapturingObserver* obs(routeloom::NodeId id) const { return observers.at(id).get(); }

  void remove_node(routeloom::NodeId id) {
    net.unregister_node(id);
    nodes.erase(id);
    reply_ports.erase(id);
    radios.erase(id);
    security.erase(id);
    observers.erase(id);
    peer_link_epochs.erase(id);
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
