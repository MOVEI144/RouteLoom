#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/congestion.hpp"
#include "routeloom/endpoint_wire.hpp"
#include "routeloom/telemetry.hpp"
#include "routeloom/fixed_containers.hpp"
#include "routeloom/routing.hpp"
#include "routeloom/security.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"
#include "routeloom/wire.hpp"

namespace routeloom {

struct NodeConfig {
  NetworkId network{0};
  NodeId node{kInvalidNodeId};
  std::uint32_t message_session{0};
  std::uint16_t link_epoch{1};
  std::uint16_t end_epoch{1};
  // Origin generation for this node's own route source. Must be persisted
  // monotonic and incremented on every boot; a restarted node advertises a
  // higher generation so peers discard its previous-incarnation route state.
  std::uint16_t route_generation{1};
  std::uint32_t route_advertisement_period_ms{5000};
  std::uint32_t route_lifetime_ms{15000};
  std::uint32_t hop_accept_timeout_ms{60};
  std::uint32_t callback_watchdog_ms{1000};
  // Per-boot incarnation stamped on this node's telemetry observations
  // (02-telemetry §2.4). Distinct from message_session; 0 means unset —
  // observations then carry observer_boot 0 and hosts must treat boot
  // attribution as unknown.
  std::uint64_t boot_incarnation{0};
  // Transit eligibility starts enabled; the Owner drives set_relay_enabled
  // for runtime config/drain (01-forwarding §policy). Remote telemetry
  // answering stays opt-in via set_telemetry_remote.
 
  std::uint8_t max_link_attempts{2};
  std::uint8_t max_end_to_end_rounds{3};
};

struct RadioRxMetadata {
  std::int8_t rssi_dbm{0};
};

class RadioPort {
 public:
  virtual ~RadioPort() = default;
  virtual Status send(NodeId peer, std::uint64_t token, ByteView frame) noexcept = 0;
  virtual Status recover() noexcept = 0;
};

// --- APPLIED delivery (sdk-completion/01-applied-delivery.md) -----------------
// The terminal endpoint contract is synchronous and bounded: the node calls
// on_applied_request at most once per logical APPLIED message, the endpoint
// fills the reply, and the verdict is committed to a result record emitted as
// APP_RESULT RESULT. Dedup/replays answer from the stored record — the
// endpoint is never re-invoked for a retransmission.

using ExecutionLease = std::array<std::uint8_t, endpoint::kAppliedLeaseBytes>;
constexpr std::size_t kAppliedUserPayloadMax = endpoint::kAppliedUserPayloadMax;
constexpr std::size_t kAppliedResultCapacity = 8;
constexpr std::uint32_t kAppliedResultHoldMs = 60000;
constexpr std::uint32_t kAppliedLateResultMs = 30000;
constexpr std::uint8_t kAppliedMaxEmits = 3;
constexpr std::uint8_t kAppliedMaxQueries = 2;
constexpr std::uint32_t kAppliedAnswerMinIntervalMs = 200;

struct AppliedRequest {
  MessageKey key{};                  // {request origin, original MessageId}
  NodeId source{kInvalidNodeId};     // == key.origin
  ByteView payload{};                // user bytes; the 16B lease is stripped
  std::uint32_t remaining_ms{0};     // request's remaining deadline at dispatch
};

struct AppliedReply {
  endpoint::AppResultOutcome outcome{endpoint::AppResultOutcome::Failure};
  std::uint32_t code{0};             // app-chosen; the SDK band is rewritten
  std::array<std::uint8_t, endpoint::kAppResultDataMax> data{};
  std::uint8_t size{0};              // 0..48
};

class AppliedEndpointSink {
 public:
  virtual ~AppliedEndpointSink() = default;
  virtual void on_applied_request(const AppliedRequest& request,
                                  AppliedReply& reply) noexcept = 0;
};

// Stored origin-side view of a verified RESULT (01 §1.3 applied_result()).
struct AppliedResultView {
  bool present{false};
  bool late{false};                  // arrived after the delivery went terminal
  endpoint::AppResultOutcome outcome{endpoint::AppResultOutcome::Failure};
  std::uint32_t code{0};
  std::array<std::uint8_t, endpoint::kAppResultDataMax> data{};
  std::uint8_t size{0};
};

struct AppliedStats {
  std::uint32_t requests_dispatched{0};
  std::uint32_t refusals_stale_lease{0};
  std::uint32_t refusals_no_endpoint{0};
  std::uint32_t refusals_capacity{0};
  std::uint32_t refusals_malformed{0};
  std::uint32_t results_committed{0};
  std::uint32_t results_emitted{0};
  std::uint32_t result_emits_suppressed{0};
  std::uint32_t result_acks{0};
  std::uint32_t queries_received{0};
  std::uint32_t queries_sent{0};
  std::uint32_t status_sent{0};
  std::uint32_t statuses_received{0};
  std::uint32_t results_accepted{0};
  std::uint32_t results_late{0};
  std::uint32_t malformed{0};
  std::uint32_t mismatched{0};
  std::uint32_t evicted{0};
  std::uint32_t expired{0};
};

class NodeObserver {
 public:
  virtual ~NodeObserver() = default;
  virtual void on_message(const MessageKey& key, NodeId source, ByteView payload) noexcept = 0;
  virtual void on_delivery(const DeliveryResult& result) noexcept = 0;
  virtual void on_diagnostic(const char* reason, NodeId peer, const MessageId* message) noexcept = 0;
  // APPLIED verdict at the origin (sdk-completion/01 §1.3): fires once per
  // stored RESULT — on-time or `late`. Defaulted (not pure) so existing
  // observer implementations keep compiling without an APPLIED surface.
  virtual void on_applied_result(const MessageKey& key,
                                 const AppliedResultView& result) noexcept {
    (void)key;
    (void)result;
  }
};

class NullObserver final : public NodeObserver {
 public:
  void on_message(const MessageKey&, NodeId, ByteView) noexcept override {}
  void on_delivery(const DeliveryResult&) noexcept override {}
  void on_diagnostic(const char*, NodeId, const MessageId*) noexcept override {}
};

// Narrow sink for link-scoped autonomy control payloads (NeighborProbe /
// NeighborResult, docs/design/autonomous-mesh/02-discovery.md §3, plus the
// migration-control set TimeSync/ChannelNotice/ControlObject/ObjectChunk/
// ObjectAck, 04-channel-migration.md §5-§9). The radio Owner installs one; a
// frame reaches it only after wire::open_link and the network/peer identity
// checks pass, so payload bytes are link-authenticated but NOT end-verified
// — the sink must still re-validate them (binding generation, neighbor
// phase, authority signature verification) before acting.
class AutonomyFrameSink {
 public:
  virtual ~AutonomyFrameSink() = default;
  // captured_ms: when the frame was captured on the node's own clock
  // (received_us at radio enqueue); 0 = unknown, treated as now_ms.
  virtual void on_autonomy_frame(NodeId peer, FrameType type, ByteView payload,
                                 MonotonicMs now_ms,
                                 MonotonicMs captured_ms = 0) noexcept = 0;
  // Verify oracle (04 §10): fires for EVERY frame that cleared link
  // authentication + network/peer identity — not just autonomy types. The
  // migration agent uses it to close VERIFY on real connectivity evidence.
  // Implementations must exclude frames observed while the radio is parked
  // off-channel (survey/helper visits) — those are not new-channel proof.
  virtual void note_link_activity(NodeId peer, MonotonicMs now_ms) noexcept {
    (void)peer;
    (void)now_ms;
  }
};

// Service=21 terminal endpoint (docs/design/scope-gateway-config/
// 03-explicit-gateway.md): the GatewayDelivery component installs one to
// receive end-verified Service payloads at this node and completion notices
// for Service jobs it queued through send_service/resend_service. Service
// traffic never enters the DATA path — no on_message, no END_RECEIPT, no
// Delivery records; completion is the component's own evidence contract.
class GatewayServiceSink {
 public:
  virtual ~GatewayServiceSink() = default;
  // Terminal Service frame for this node: link + end verified, same-round
  // duplicates already suppressed and the hop ACK already queued.
  virtual void on_service_payload(NodeId peer, const wire::PlainFrame& frame,
                                  MonotonicMs now_ms) noexcept = 0;
  // First authenticated HOP_ACCEPT (hop_accepted=true) or terminal job
  // failure (false + `reason`) for a send_service/resend_service job,
  // correlated by the caller-supplied MessageId.
  virtual void on_service_job_done(const MessageId& id, bool hop_accepted,
                                   const char* reason, MonotonicMs now_ms) noexcept = 0;
  // Monotonic tick from MeshNode::poll for the component's bounded retries.
  virtual void poll(MonotonicMs now_ms) noexcept = 0;
};

// Routed end-protected config endpoint (docs/design/scope-gateway-config/
// 04-remote-config.md §5, 05-wire-api.md §5.5): the ConfigTarget/ConfigGateway
// components install one to receive end-verified Control (22) and
// ConfigPermit-kind object (ControlObject 49 / ObjectChunk 50 / ObjectAck 51)
// payloads at this node, plus completion notices for typed jobs queued
// through send_typed. These types ALSO carry the link-scoped autonomous
// migration objects — that path is unchanged (AutonomyFrameSink, never
// end-protected, destination==self). Only the END-PROTECTED forms route here:
// the node layer has link-authenticated, deduplicated and end-opened the
// frame, so `frame` is verified plaintext — but the permit inside still
// faces the real ConfigAuthorityVerifier; transport never grants authority.
class ConfigEndpointSink {
 public:
  virtual ~ConfigEndpointSink() = default;
  // Terminal end-verified config frame for this node. `frame.header.type`
  // distinguishes Control (challenge/status) from the object types
  // (manifest/chunk/ack); `peer` is the authenticated previous hop and
  // `frame.header.origin` the end-authenticated origin to reply to.
  virtual void on_config_frame(NodeId peer, const wire::PlainFrame& frame,
                               MonotonicMs now_ms) noexcept = 0;
  // First authenticated HOP_ACCEPT (hop_accepted=true) or terminal job
  // failure (false + `reason`) for a send_typed job, correlated by the
  // caller-supplied MessageId.
  virtual void on_config_job_done(const MessageId& id, bool hop_accepted,
                                  const char* reason, MonotonicMs now_ms) noexcept = 0;
  // Monotonic tick from MeshNode::poll for the component's bounded retries.
  virtual void poll(MonotonicMs now_ms) noexcept = 0;
  // CapabilitiesReply permit_profiles bitmap (04 §capabilities): bits for
  // configured AND ready verifier profiles only — 0 means the sink accepts
  // no permits or its verifier is unprovisioned.
  virtual std::uint32_t permit_profile_bits() const noexcept { return 0; }
};

// Terminal sink for end-protected Diagnostic (48) bodies (02-telemetry
// §4.2): TelemetrySnapshot and DiagnosticReject subtypes addressed to this
// node arrive here already subtype-validated and end-verified. The sink
// owns request_id correlation; a node without a sink drops with an honest
// diagnostic, never a fabricated answer.
class DiagnosticSink {
 public:
  virtual ~DiagnosticSink() = default;
  virtual void on_diagnostic_body(NodeId observer, ByteView body,
                                  MonotonicMs now_ms) noexcept = 0;
};

// Pause contract (01-integration.md §3.3): narrower than blanket draining.
// A PauseReason names WHY traffic is held; the mask selects WHICH traffic is
// held so the control needed to coordinate a survey/cutover keeps flowing —
// plain set_draining(true) stops route/control work and would deadlock a
// migration that still needs its control lane.
enum class PauseReason : std::uint8_t {
  None = 0,
  SleepDrain = 1,       // reserved for the legacy set_draining path
  SurveyVisit = 2,      // bounded single-radio off-channel visit (04 §3)
  MigrationPrepare = 3, // plan distribution/coordination in flight (04 §7)
  Cutover = 4,          // committed switch executing (04 §8)
};

namespace pause {
// Mask bits over traffic categories. The reserved scheduler control lane
// (HOP_ACCEPT replies, pre-admission BUSY) is NEVER masked — it is exactly
// the control a pause must keep alive.
constexpr std::uint8_t kAppAdmission = 1u << 0;   // send()/resume_delivery()
constexpr std::uint8_t kDataDispatch = 1u << 1;   // non-control scheduler dispatch
constexpr std::uint8_t kBackgroundWork = 1u << 2; // route ads + seqno probing
constexpr std::uint8_t kRetryRounds = 1u << 3;    // origin end-to-end retries
constexpr std::uint8_t kAll =
    kAppAdmission | kDataDispatch | kBackgroundWork | kRetryRounds;
// What set_draining(true) has always meant: in-flight queue entries still
// dispatch, only new admission/background/retry work stops.
constexpr std::uint8_t kSleepDrainMask =
    kAppAdmission | kBackgroundWork | kRetryRounds;
// Off-channel visit: the home channel is physically unreceivable — nothing
// home-bound may run.
constexpr std::uint8_t kSurveyVisitMask = kAll;
// Migration/cutover: bulk DATA pauses while reserved control keeps flowing.
constexpr std::uint8_t kMigrationMask = kAll;
}  // namespace pause

// Policy applied by MeshNode::settle_for_sleep to deliveries that are not in a
// terminal state when the node drains for sleep.
enum class SleepWorkPolicy : std::uint8_t {
  Fail = 0,   // fail with an explicit reason
  Save = 1,   // persist unfinished deliveries into the sleep image
  Defer = 2,  // leave them; the result is unknown after real sleep
};

// Read-only view of a Delivery slot for the power coordinator.
struct DeliverySnapshot {
  MessageId id{};
  NodeId destination{kInvalidNodeId};
  SendOptions options{};
  DeliveryState state{DeliveryState::Empty};
  MonotonicMs expires_at_ms{0};
  ByteView payload{};
};

// --- Dedup capacity classes (sdk-completion/02-dedup-capacity.md, issue #9) ---
// Pinned constants mirror docs/design/sdk-completion/contracts.json `dedup.*`.
//
// Every dedup_ pool record carries a lifecycle phase that fixes its eviction
// rank and its post-deadline retention slack:
//   Live     — an accepted forward job is still committed against the record
//   Resolved — the job resolved (hop-accepted) or the record was born with
//              only re-ACK duty (routed terminal delivery, consumed receipt)
//   Evidence — Resolved + a retained verbatim TransitFailure for replay
//   Terminal — delivered DATA at this node; the cross-round exactly-once pin
// Live and Terminal records are NEVER evicted to admit new traffic — pressure
// becomes an honest refusal instead of a weakened exactly-once guarantee.
enum class DedupPhase : std::uint8_t {
  Live = 0,
  Resolved = 1,
  Evidence = 2,
  Terminal = 3,
};

// Retention: expires_at = min(first_seen_ms + kDedupHardCapMs,
//                             horizon_ms + slack(phase)) where horizon is the
// frame's own deadline at this node (remaining_deadline minus the driver-queue
// debit). Duplicates never extend retention past the first-seen hard cap.
constexpr std::uint32_t kDedupHardCapMs = 60000;      // first-seen cap (spec floor)
constexpr std::uint32_t kTerminalSlackMs = 30000;     // cross-round exactly-once pin
constexpr std::uint32_t kTransitSlackMs = 5000;       // report budget + drain margin
// Admission bounds: terminal pins may occupy at most
// kDedupCapacity - kDedupTransitReserve slots so transit/evictable traffic
// always keeps a reserve; one previous-hop peer may hold at most
// kDedupPerUpstreamMax non-terminal records; Evidence residency is capped.
constexpr std::size_t kDedupTransitReserve = 8;
constexpr std::size_t kDedupPerUpstreamMax = 24;
constexpr std::size_t kEvidenceCap = 16;

// Saturating u64 counters in the CongestionStats idiom — a counter that would
// exceed UINT64_MAX pins (unreachable within a boot). Surfaces every forced
// refusal/eviction so dedup weakening is never silent.
struct DedupStats {
  std::uint64_t admitted_terminal{0};         // terminal (pinned) admissions
  std::uint64_t admitted_transit{0};          // non-terminal admissions
  std::uint64_t refused_pool_full{0};         // sweep found no evictable record
  std::uint64_t refused_terminal_reserve{0};  // terminal denied a reserved slot
  std::uint64_t refused_upstream_cap{0};      // per-upstream bound hit
  std::uint64_t evicted_resolved{0};          // Resolved records force-reclaimed
  std::uint64_t evicted_evidence{0};          // Evidence records force-reclaimed
  std::uint64_t expired{0};                   // expire_dedup/expired reclaims
  std::uint64_t delivery_terminal_evicted{0}; // class (a) result-history loss
};

class MeshNode {
 public:
  MeshNode(const NodeConfig& config, RadioPort& radio, SecurityProvider& security,
           NodeObserver& observer) noexcept;

  Status start(MonotonicMs now_ms) noexcept;
  Status add_neighbor(NodeId neighbor, RouteMetric link_metric,
                      MonotonicMs now_ms) noexcept;
  Status remove_neighbor(NodeId neighbor, MonotonicMs now_ms) noexcept;

  Status send(NodeId destination, ByteView payload, const SendOptions& options,
              MonotonicMs now_ms, MessageId& id) noexcept;
  // APPLIED send (sdk-completion/01): the request body is
  // `lease || payload` — `lease` must be the destination's current
  // ExecutionLease (applied_lease() at that node); a stale/absent lease is
  // refused by the destination with a committed StaleLease RESULT carrying
  // the current lease. `options.delivery` must be DeliveryClass::Applied and
  // payload <= kAppliedUserPayloadMax (112B). persist_across_sleep is
  // refused — APPLIED sleep persistence is deferred (01 §1.10).
  Status send_applied(NodeId destination, ByteView payload,
                      const ExecutionLease& lease, const SendOptions& options,
                      MonotonicMs now_ms, MessageId& id) noexcept;
  // This node's current execution lease — what an origin must place in the
  // request prefix for this boot incarnation.
  ExecutionLease applied_lease() const noexcept;
  // Install/clear the application endpoint (nullptr disables — inbound
  // APPLIED requests then commit a NoEndpoint refusal RESULT).
  void set_applied_sink(AppliedEndpointSink* sink) noexcept { applied_sink_ = sink; }
  // The stored RESULT view for a delivery: false when none was verified.
  bool applied_result(const MessageId& id, AppliedResultView& out) const noexcept;
  const AppliedStats& applied_stats() const noexcept { return applied_stats_; }
  Status cancel(const MessageId& id) noexcept;
  DeliveryResult delivery(const MessageId& id) const noexcept;

  void poll(MonotonicMs now_ms) noexcept;
  void on_radio_receive(NodeId peer, ByteView frame, const RadioRxMetadata& metadata,
                        MonotonicMs now_ms) noexcept;
  // M1 telemetry entry point (m1-completion/02-telemetry.md §2.3): same
  // receive path, plus bounded RF observation. The V1 overload forwards with
  // InjectedTest provenance — only the production adapter supplies
  // LocalDriver evidence.
  void on_radio_receive(NodeId peer, ByteView frame,
                        const RadioRxMetadataV2& metadata,
                        MonotonicMs now_ms) noexcept;
  // Completion observation for one submitted TX attempt (02 §2.2/§2.3). The
  // Owner calls this exactly once per submission, including unknown outcomes;
  // callback-absent fencing is the Owner's job — this records what arrived.
  void note_radio_tx(const RadioTxObservation& observation,
                     MonotonicMs now_ms) noexcept;
  // Submission identity the runtime froze for `token` (02 §2.3): the node
  // stamps this key onto the job at dispatch so submit/complete accounting
  // share one immutable identity — never re-guessed from a live summary.
  void note_tx_submit_identity(const std::uint64_t token,
                               const ObservationKey& key) noexcept {
    submit_identity_.token = token;
    submit_identity_.key = key;
    submit_identity_.valid = true;
  }
  // Read-only telemetry surfaces (02 §2.4/§2.7). A missing peer is nullptr,
  // not a zero record.
  const PeerTelemetrySummary* telemetry_peer(NodeId peer) const noexcept;
  const ObservationBucket* telemetry_bucket(const ObservationKey& key) const noexcept;
  // Identity invalidation from the runtime: an RX event queued before a
  // rebind/switch must retire the peer's stale summary, not refresh it.
  // The metric mirror resets with it (sdk-completion/03 §3.7): evidence
  // measured under a previous link identity is unattributable to this one.
  void note_peer_stale(NodeId peer) noexcept {
    telemetry_peers_.mark_stale(peer);
    if (Neighbor* neighbor = find_neighbor(peer)) {
      reset_neighbor_measurement(*neighbor);
    }
  }
  std::uint64_t telemetry_event_drops() const noexcept { return telemetry_event_drops_; }
  // Install/clear the autonomy control sink (Owner wiring, nullptr disables).
  void set_autonomy_sink(AutonomyFrameSink* sink) noexcept { autonomy_sink_ = sink; }
  // Install/clear the Service=21 endpoint (GatewayDelivery wiring, nullptr
  // disables). With no sink, inbound Service frames are still dedup'd/
  // hop-ACKed/forwarded but terminate as SERVICE_NO_ENDPOINT — the origin's
  // retries expire into an honest timeout, never a DATA-style success.
  void set_gateway_sink(GatewayServiceSink* sink) noexcept { gateway_sink_ = sink; }
  // Owner-side relay gate (01-forwarding §policy): runtime config and drain
  // requests write this; effective transit permission additionally requires
  // a live binding context. Reads expose configured vs effective separately.
  // Disabling withdraws our transit advertisements immediately (infinity
  // update on the next maintenance tick is too late — neighbors keep
  // sending us work we will refuse). Accepted in-flight work still drains
  // on its own deadlines.
  void set_relay_enabled(bool enabled) noexcept;
  bool relay_enabled() const noexcept { return relay_enabled_; }
  // Effective transit permission for NEW admissions. Accepted transit
  // already queued keeps its original deadline — this only gates new work.
  bool transit_permitted() const noexcept { return started_ && relay_enabled_; }
  // Accepted transit work still draining (01 §1.6): live scheduler jobs,
  // the physically in-flight forward and hop-accept-awaiting transit —
  // retained dedup evidence records are NOT work and never counted.
  std::size_t transit_in_flight() const noexcept {
    std::size_t n = scheduler_.count_owner(JobOwner::Transit);
    if (physical_.active && physical_.job.owner == JobOwner::Transit) ++n;
    awaiting_hop_.for_each([&](const AwaitingHop& hop) {
      if (hop.job.owner == JobOwner::Transit) ++n;
    });
    return n;
  }
  // Remote Diagnostic (48) telemetry queries are opt-in — answering is
  // disabled unless the owner enables it (02 §4.2 note).
  void set_telemetry_remote(bool enabled) noexcept { telemetry_remote_ = enabled; }
  bool telemetry_remote() const noexcept { return telemetry_remote_; }
  // Queue an end-protected Service=21 payload for `destination` with a
  // bounded hop-accept exchange per hop. send_service allocates a fresh
  // logical MessageId from the node's own sequence space (outcomes the
  // gateway emits are likewise new MessageKeys); resend_service re-queues an
  // existing id for the next E2E round. Completion is reported through the
  // sink's on_service_job_done — never through DeliveryResult.
  Status send_service(NodeId destination, ByteView payload, std::uint32_t lifetime_ms,
                      MonotonicMs now_ms, MessageId& id) noexcept;
  Status resend_service(const MessageId& id, NodeId destination, ByteView payload,
                        std::uint8_t round, std::uint32_t lifetime_ms,
                        MonotonicMs now_ms) noexcept;
  // Priority-tagged variant for endpoint control traffic: the gateway
  // component emits its outcomes (Descriptor/Receipt/Pending/Reject) as
  // receipt-class Management traffic while Query/Submit stay Normal.
  Status send_service(NodeId destination, ByteView payload, std::uint32_t lifetime_ms,
                      Priority priority, MonotonicMs now_ms, MessageId& id) noexcept;
  // Install/clear the routed config endpoint (ConfigTarget on a config node,
  // ConfigGateway on a bridge; nullptr disables). With no sink, inbound
  // end-protected config frames are still dedup'd/hop-ACKed/forwarded but
  // terminate as CONFIG_NO_ENDPOINT — retries expire into an honest timeout.
  void set_config_sink(ConfigEndpointSink* sink) noexcept { config_sink_ = sink; }
  // Install/clear the end-protected Diagnostic (48) terminal sink — the
  // surface remote TelemetrySnapshot/Reject bodies arrive on (02 §4.2).
  void set_diagnostic_sink(DiagnosticSink* sink) noexcept { diagnostic_sink_ = sink; }
  // Issue an end-protected TelemetryQuery toward `observer` over the routed
  // lane (02 §4.2). Returns the wire submission status; the request's own
  // deadline bounds the exchange.
  Status send_telemetry_query(NodeId observer, const TelemetryQuery& query,
                              MonotonicMs now_ms) noexcept;
  // Local-only capability advertisement (04 §capabilities): what this node
  // is wired and currently permitted to do — never a claim about a remote.
  // `echo_nonce` is the nonce from the CapabilitiesQuery being answered
  // (the USB local path supplies the host's query nonce verbatim).
  CapabilitiesReply build_capabilities_reply(
      const std::array<std::uint8_t, kCapabilitiesNonceSize>& echo_nonce)
      const noexcept;
  // Send a link-only CapabilitiesQuery (subtype 1, hop-1) to an admitted
  // peer. One outstanding query per peer (04 §capabilities); the caller's
  // nonce must be unpredictable/nonzero. Returns error when the peer already
  // has an outstanding probe or the table is full.
  Status send_capabilities_query(
      NodeId peer, const std::array<std::uint8_t, kCapabilitiesNonceSize>& nonce,
      MonotonicMs now_ms) noexcept;
  // Local snapshot builder shared by the remote diagnostic handler and the
  // USB diagnostic request: fills `out` or reports the reject reason —
  // never fabricates a zeroed record for a missing/stale peer.
  Status build_telemetry_snapshot(const TelemetryQuery& query,
                                  MonotonicMs now_ms, TelemetrySnapshot& out,
                                  DiagnosticRejectReason& reason) noexcept;
  // Queue one end-protected routed frame of `type` (Control 22 or the
  // ConfigPermit object types 49/50/51) for `destination`, with the same
  // bounded hop-accept-per-hop exchange send_service uses. Completion is
  // reported through the config sink's on_config_job_done. Service=21 stays
  // on send_service — this lane is for the config component's own types.
  Status send_typed(FrameType type, NodeId destination, ByteView payload,
                    std::uint32_t lifetime_ms, MonotonicMs now_ms,
                    MessageId& id) noexcept;
  // Free TX-pool slots: the Service endpoint needs this to make the
  // atomic admission reservation (pending + dedup + reply budget) the
  // contract demands before accepting work (03 §3.4).
  std::size_t tx_free_slots() const noexcept { return scheduler_.free_slots(); }
  void on_radio_tx_result(std::uint64_t token, bool success,
                          MonotonicMs now_ms) noexcept;

  const RouteTable& routes() const noexcept { return routes_; }
  const NodeConfig& config() const noexcept { return config_; }
  NodeId node_id() const noexcept { return config_.node; }
  bool started() const noexcept { return started_; }

  // Sleep support. While draining, send() is rejected and background work
  // (route advertisements, sequence requests, retry rounds) stops; in-flight
  // queue entries still dispatch so the TX path can settle. Equivalent to a
  // pause with pause::kSleepDrainMask; composable with a set_pause mask.
  void set_draining(bool draining) noexcept { sleep_draining_ = draining; }
  bool draining() const noexcept { return sleep_draining_; }
  // Pause contract (01 §3.3): hold only the masked traffic categories so
  // migration/survey-critical control is not deadlocked by a blanket drain.
  // One operational reason is active at a time (SleepDrain is orthogonal and
  // owned by set_draining); the reserved control lane is never masked.
  Status set_pause(PauseReason reason, std::uint8_t mask) noexcept;
  Status clear_pause(PauseReason reason) noexcept;
  PauseReason pause_reason() const noexcept { return pause_reason_; }
  // Effective mask = active reason mask ∪ the sleep-drain bits.
  std::uint8_t pause_mask() const noexcept {
    return pause_mask_ | (sleep_draining_ ? pause::kSleepDrainMask : 0);
  }
  bool paused(std::uint8_t bits) const noexcept {
    return (pause_mask() & bits) != 0;
  }
  // True when no radio-bound work remains: empty TX queue, no physical
  // in-flight frame and no job waiting for a hop accept.
  bool quiesced() const noexcept {
    return !physical_.active && scheduler_.empty() && awaiting_hop_.size() == 0;
  }

  // --- Congestion control (03-congestion.md §4, §5) ----------------------------
  // Live scheduler/BUSY counters for tests, diagnostics and the P3 observer.
  CongestionStats congestion_stats() const noexcept;
  // Dedup capacity surface (sdk-completion/02 §2.4): saturating admission,
  // refusal and eviction counters — every forced reclaim/refusal is visible.
  const DedupStats& dedup_stats() const noexcept { return dedup_stats_; }
  // Live dedup residency (records currently occupying the fixed pool).
  // Read-only test/diagnostic surface for the capacity invariants of
  // sdk-completion/02 §2.5 — always <= kDedupCapacity (64) by construction.
  std::size_t dedup_resident() const noexcept { return dedup_.size(); }
  // Current per-peer in-flight window (1..4) used by the dispatch gate.
  std::uint8_t peer_tx_window(NodeId peer) const noexcept;
  // Marks a peer as implementing the Busy(20) feedback payload. Until
  // capability negotiation lands, BUSY replies are emitted only to peers
  // marked here or proven by a valid received BUSY (03 §5, scenario D4-09).
  void set_peer_busy_capable(NodeId peer, bool capable) noexcept;
  // Whether a live (unexpired) capability grant marks this peer as
  // Busy(20)-capable right now — read-only mirror of the gate at 03 §5.
  bool peer_busy_capable(NodeId peer, MonotonicMs now_ms) const noexcept;
  // Effective link cost currently fed to routing for `peer` (nominal base
  // adjusted by the measured exchange ratio and our egress queue penalty,
  // 03 §6). kInfiniteRouteMetric when the peer is unknown.
  RouteMetric peer_link_cost(NodeId peer) const noexcept;
  // Sustained-busy start time for `peer` (0 = not busy) — diagnostic/test
  // surface for the severe-busy fast-repair path (03 §7).
  MonotonicMs peer_busy_since(NodeId peer) const noexcept;
  // Authenticated neighbor pressure feedback (Busy.pressure field or
  // NeighborResult-derived, delivered by the link-authenticated ingress
  // path). Ordered per peer by the feedback sequence and honored only
  // inside its TTL; feeds ONLY the local busy/queue picture — a peer
  // self-report is a hint, never added to a route metric and never able
  // to admit an infeasible route (03 §6.2, D4-02).
  void note_peer_pressure(NodeId peer, std::uint8_t pressure,
                          std::uint32_t feedback_sequence,
                          MonotonicMs now_ms) noexcept;
  // Bounded observation aggregates (03 §3): EWMA + counters per key, never
  // raw samples. The global buckets feed diagnostics; the per-neighbor
  // mirrors drive the P3 route-metric coupling (03 §6).
  template <typename Fn>
  void for_each_observation(Fn fn) const noexcept {
    observations_.for_each(fn);
  }
  // Bumped on every send() call, received frame and TX-result callback: any
  // radio-visible activity. Used to invalidate outstanding sleep tickets.
  std::uint32_t work_generation() const noexcept { return work_generation_; }
  // Bumps only on inbound radio frames that pass link authentication and the
  // network/peer identity check — the signal the power coordinator uses to
  // confirm saved peers actually answered after a resume. Invalid frames, TX
  // callbacks and app sends do not count as peer confirmation.
  std::uint32_t rx_generation() const noexcept { return rx_generation_; }
  // Bumped on peer/config changes (neighbor add/remove).
  std::uint32_t config_revision() const noexcept { return config_revision_; }
  static constexpr std::size_t delivery_capacity() noexcept {
    return kDeliveryCapacity;
  }

  template <typename Fn>
  void for_each_delivery(Fn fn) const noexcept {
    deliveries_.for_each([&](const Delivery& delivery) {
      fn(DeliverySnapshot{delivery.id, delivery.destination, delivery.options,
                          delivery.state, delivery.expires_at_ms,
                          ByteView{delivery.payload.data(), delivery.payload_size}});
    });
  }

  // Phase 1 of the sleep settlement — read-only. Offers every non-terminal
  // durable delivery (or all non-terminal deliveries under SleepWorkPolicy::
  // Save) to `save` WITHOUT changing delivery state: until the durable image
  // is committed, live work must stay live so a persistence failure can abort
  // back to running with nothing lost.
  template <typename SaveFn>
  void snapshot_for_sleep(SleepWorkPolicy fallback, SaveFn&& save) noexcept {
    deliveries_.for_each([&](const Delivery& delivery) {
      if (sleep_terminal(delivery.state)) return;
      if (delivery.options.persist_across_sleep ||
          fallback == SleepWorkPolicy::Save) {
        save(DeliverySnapshot{delivery.id, delivery.destination, delivery.options,
                              delivery.state, delivery.expires_at_ms,
                              ByteView{delivery.payload.data(),
                                       delivery.payload_size}});
      }
    });
  }

  // Phase 2 — only after the durable image commit succeeded. `was_saved`
  // reports whether a delivery id landed in the committed image; those
  // deliveries become Indeterminate (outcome decided after resume). Everything
  // else follows `fallback`: a delivery that was eligible but not saved fails
  // explicitly — durable work is never dropped silently.
  template <typename WasSavedFn>
  void apply_sleep_dispositions(SleepWorkPolicy fallback,
                                WasSavedFn&& was_saved) noexcept {
    deliveries_.for_each([&](Delivery& delivery) {
      if (sleep_terminal(delivery.state)) return;
      const bool durable = delivery.options.persist_across_sleep;
      const bool eligible = durable || fallback == SleepWorkPolicy::Save;
      if (eligible && was_saved(delivery.id)) {
        set_delivery_state(delivery, DeliveryState::Indeterminate, "SLEEP_SAVED");
      } else if (fallback == SleepWorkPolicy::Defer && !durable) {
        set_delivery_state(delivery, DeliveryState::Indeterminate, "SLEEP_DEFERRED");
      } else {
        set_delivery_state(delivery, DeliveryState::Failed,
                           eligible ? "SLEEP_PERSIST_FULL" : "SLEEP_DRAIN");
      }
    });
  }

  // Re-injects a persisted delivery under its ORIGINAL logical message id so
  // the destination's terminal dedup still suppresses a payload it already
  // delivered when the end receipt was lost in sleep. Only the power
  // coordinator calls this; ordinary send() always allocates a fresh id.
  // Rejected when the id is already live or collides with argument checks.
  Status resume_delivery(const MessageId& id, NodeId destination, ByteView payload,
                         const SendOptions& options, MonotonicMs now_ms) noexcept;

  // Drops all queued/in-flight radio work after apply_sleep_dispositions ran.
  // A frame
  // already handed to the driver is reported unknown, never as sent.
  void quiesce_for_sleep() noexcept {
    if (physical_.active) {
      observer_.on_diagnostic("SLEEP_TX_INFLIGHT", physical_.job.peer,
                              &physical_.job.ack.key.id);
      physical_ = PhysicalInflight{};
    }
    scheduler_.clear();
    awaiting_hop_.clear();
  }

 private:
  static constexpr std::size_t kNeighborCapacity = 32;
  static constexpr std::size_t kDeliveryCapacity = 8;
  static constexpr std::size_t kDedupCapacity = 64;
  static constexpr std::size_t kTxQueueCapacity = 32;
  static constexpr std::size_t kAwaitingHopCapacity = 8;
  static constexpr std::size_t kSeqnoSeenCapacity = 32;
  static constexpr std::size_t kSeqnoStateCapacity = 32;
  static constexpr std::uint32_t kNoFeedbackSeq = 0xFFFFFFFFu;

  struct Neighbor {
    NodeId node{kInvalidNodeId};
    RouteMetric metric{1};      // nominal link cost (add_neighbor input)
    RouteMetric link_cost{1};   // effective cost fed to RouteTable (03 §6)
    RouteGeneration generation{0};  // last origin generation the peer self-advertised
    std::uint8_t consecutive_failures{0};
    std::uint8_t route_cursor{0};  // rotation cursor for periodic route dumps
    // Congestion state (03-congestion.md §5): per-peer in-flight window and
    // the consecutive-authenticated-accept streak that grows it. A window is
    // NOT a memory-slot counter — freeing an awaiting slot never grows it.
    std::uint8_t tx_window{kPeerWindowInitial};
    std::uint8_t window_accepts{0};
    bool busy_capable{false};  // peer proved/configured for Busy(20) feedback
    // Granted-capability state from a nonce-bound CapabilitiesReply: the
    // grant expires at cap_valid_until_ms under the peer's boot identity —
    // a reply can never install a permanent capability (04 §capabilities).
    MonotonicMs cap_valid_until_ms{0};
    std::uint64_t cap_node_boot{0};
    // Renewal pacing: last completed/granted capability exchange; a new
    // query inside kCapQueryRenewalMs is refused.
    MonotonicMs last_cap_exchange_ms{0};
    // Highest feedback sequence accepted from this peer; stale/replayed
    // BUSY payloads are detected against it (FeedbackSequence ordering tag).
    // feedback_seen is separate so a first seq equal to the sentinel value
    // cannot disable ordering checks forever.
    std::uint32_t last_feedback_seq{kNoFeedbackSeq};
    bool feedback_seen{false};
    // Per-peer exchange measurement (03 §6.1): decaying-window counters of
    // eligible attempt work (every physical submission of a hop-accept
    // exchange — failures included) and authenticated accepts. Below
    // kExchangeMinAccepts the measured ratio is unused and cost stays
    // nominal.
    std::uint32_t exchange_work{0};
    std::uint32_t exchange_accepts{0};
    MonotonicMs exchange_window_ms{0};
    // Per-peer egress queue sojourn EWMA (03 §6.2): only OUR delay toward
    // this peer may penalize the link cost. Stale samples read as 0. The
    // EWMA halves once per observation window anchored at sojourn_window_ms
    // (§3.4): sparse fresh samples cannot keep re-exposing an inflated
    // average — after a burst the penalty converges within a few windows.
    std::uint32_t queue_sojourn_ewma_ms{0};
    std::uint32_t sojourn_samples{0};
    MonotonicMs last_sojourn_ms{0};
    MonotonicMs sojourn_window_ms{0};
    // Evidence gate for the metric mirror (sdk-completion/03 §3.3): a window
    // containing any Unknown-resolution attempt is dirty — dirty evidence may
    // worsen link_cost but never improve it; cleared on the next window roll.
    // metric_sources tracks which provenance classes wrote the mirror so a
    // future remote-sample wiring cannot silently violate local-only input:
    // bit0 = local exchange counters, bit1 = local queue-sojourn samples.
    static constexpr std::uint8_t kMetricSourceLocalExchange = 1u << 0;
    static constexpr std::uint8_t kMetricSourceLocalSojourn = 1u << 1;
    bool metric_window_dirty{false};
    std::uint8_t metric_sources{0};
    // Asymmetric slew state (§3.4): last time link_cost relaxed toward the
    // honest target; improvement steps are spaced one per observation window.
    MonotonicMs last_cost_relax_ms{0};
    // Sustained authenticated-busy feedback (03 §7 severe-busy): set while
    // matched BUSY deferrals or pressure hints keep arriving; cleared by an
    // authenticated accept or when feedback goes stale past its TTL. It is
    // a hint for the switch discipline, never a metric input. `busy_active`
    // is the state — busy_since_ms==0 is a legitimate timestamp (t=0), not
    // a "clear" sentinel.
    bool busy_active{false};
    MonotonicMs busy_since_ms{0};
    MonotonicMs last_busy_feedback_ms{0};
    std::uint8_t last_pressure{0};
    bool active{false};
  };

  struct SeqnoSeen {
    NodeId requester{kInvalidNodeId};
    NodeId destination{kInvalidNodeId};
    std::uint32_t request_id{0};
    MonotonicMs expires_at_ms{0};
  };

  // Per-destination request state. Survives dedup (seqno_seen_) expiry so the
  // retry cap and cooldown still apply after the seen-record is gone.
  struct SeqnoState {
    NodeId destination{kInvalidNodeId};
    RouteSequence requested_sequence{0};
    MonotonicMs next_request_ms{0};
    MonotonicMs last_sent_ms{0};
    MonotonicMs expires_at_ms{0};
    std::uint8_t attempts{0};
  };

  struct DedupEntry {
    MessageKey key{};
    FrameType type{FrameType::Data};
    std::uint8_t round{0};
    // Capacity class (sdk-completion/02 §2.3): drives retention slack and
    // eviction rank — Live/Terminal are never eviction victims.
    DedupPhase phase{DedupPhase::Live};
    // Admission timestamp: the base of the kDedupHardCapMs retention cap —
    // refreshes on re-receipt can never push a record past it (02 §2.6).
    MonotonicMs first_seen_ms{0};
    MonotonicMs expires_at_ms{0};
    bool delivered{false};
    bool forwarded{false};
    // Transit correlation (01 §failure evidence): retained ONLY for accepted
    // transit work — the upstream neighbor that handed us the frame and the
    // fingerprint of its end-protected bytes, so a post-acceptance failure
    // can be reported back without ever claiming end-verification.
    NodeId upstream_peer{kInvalidNodeId};
    // The downstream neighbor this transit was forwarded to and the frame's
    // destination — a TransitFailure report is only valid when it arrives
    // from THIS peer about THIS destination (01 §failure evidence).
    NodeId downstream_peer{kInvalidNodeId};
    // The downstream's binding generation captured when the forward was
    // physically submitted — a report is only valid against the attempt we
    // actually made (dispatch may retarget the route after admission).
    BindingGeneration downstream_binding{0};
    NodeId ref_destination{kInvalidNodeId};
    std::array<std::uint8_t, 32> fingerprint{};
    bool has_fingerprint{false};
    // A transit record that already emitted a TransitFailure: a re-received
    // duplicate re-emits the retained evidence instead of blindly re-ACKing
    // a dead job (01 §same-key-after-failure). The retained replay carries
    // the ORIGINAL claimed reporter/report_id verbatim — a relay may never
    // re-originate evidence under its own identity.
    bool failure_reported{false};
    std::uint8_t reported_phase{0};
    std::uint8_t reported_reason{0};
    NodeId reported_reporter{kInvalidNodeId};
    std::uint32_t reported_id{0};
    // Replay bounding: a duplicate storm cannot turn one retained failure
    // into unbounded re-emissions (cap + minimum spacing).
    std::uint8_t failure_replays{0};
    MonotonicMs last_replay_ms{0};
  };
  // sdk-completion/02 §2.4 budget: 152 B measured on host after the phase +
  // first_seen_ms addition (144 B before). Xtensa may differ by alignment
  // only — a larger entry shrinks real capacity silently, so growth is a
  // deliberate, documented change.
  static_assert(sizeof(DedupEntry) <= 176, "dedup entry size budget");

  struct Delivery {
    MessageId id{};
    NodeId destination{kInvalidNodeId};
    SendOptions options{};
    std::array<std::uint8_t, kMaxApplicationPayload> payload{};
    std::size_t payload_size{0};
    DeliveryState state{DeliveryState::Empty};
    MonotonicMs created_at_ms{0};
    MonotonicMs expires_at_ms{0};
    MonotonicMs next_round_at_ms{0};
    std::uint8_t round{0};
    const char* reason{"NONE"};
    // APPLIED (sdk-completion/01 §1.3): END_RECEIPT moves an Applied delivery
    // to app_phase 1 — the application verdict is still pending; only a
    // verified APP_RESULT RESULT resolves it. QUERYs while waiting are
    // bounded by kAppliedMaxQueries and correlated by app_query_nonce.
    std::uint8_t app_phase{0};  // 0 = awaiting END_RECEIPT, 1 = awaiting RESULT
    std::uint8_t app_queries{0};
    std::uint64_t app_query_nonce{0};
    // Stored verified RESULT (01 §1.3): survives a terminal state so a late
    // result is reported, never silently dropped.
    bool applied_present{false};
    bool applied_late{false};
    std::uint8_t applied_outcome{0};
    std::uint32_t applied_code{0};
    std::array<std::uint8_t, endpoint::kAppResultDataMax> applied_result{};
    std::uint8_t applied_result_size{0};
  };

  // Terminal-side committed verdict record (01 §1.4): one per delivered
  // APPLIED MessageKey, held kAppliedResultHoldMs so retransmissions/QUERYs
  // replay the stored result instead of re-invoking the endpoint.
  struct AppliedRecord {
    MessageKey key{};  // {original_origin, original MessageId}
    std::array<std::uint8_t, 32> request_digest{};
    MonotonicMs expires_at_ms{0};
    MonotonicMs emit_deadline_ms{0};  // request deadline + kAppliedLateResultMs
    MonotonicMs next_emit_ms{0};
    std::uint8_t emits{0};
    bool acked{false};  // a matching RESULT_ACK landed
    std::uint8_t outcome{0};  // endpoint::AppResultOutcome
    std::uint32_t application_code{0};
    std::array<std::uint8_t, endpoint::kAppResultDataMax> result_data{};
    std::uint8_t result_size{0};
  };

  enum class JobForm : std::uint8_t { Plain, Forwarded };
  enum class JobOwner : std::uint8_t { None, OriginDelivery, Transit,
                                       GatewayService, Config, Diagnostic,
                                       Applied };

  struct AckKey {
    FrameType accepted_type{FrameType::Data};
    MessageKey key{};
    std::uint8_t round{0};
  };

  struct TxJob {
    JobForm form{JobForm::Plain};
    JobOwner owner{JobOwner::None};
    wire::PlainFrame plain{};
    wire::LinkOpenedFrame forwarded{};
    NodeId peer{kInvalidNodeId};
    AckKey ack{};
    bool requires_hop_accept{false};
    // RF-loss retry counter (03 §5 rf_attempts_max, per-job, never reset by
    // peer/rate changes) and the bound for it.
    std::uint8_t attempts{0};
    std::uint8_t max_attempts{1};
    MonotonicMs deadline_ms{0};
    wire::EncodedFrame encoded{};
    bool encoded_valid{false};
    // Scheduler metadata — assigned at admission, preserved across requeues.
    Priority priority{Priority::Normal};       // origin DATA class input
    std::uint32_t tx_cost{0};                  // estimated on-air bytes
    MonotonicMs enqueued_at_ms{0};             // queue-sojourn measurement base
    TxJob* flow_next{nullptr};                 // intrusive per-flow list link
    // Attempt budget accounting (contracts.json congestion.*).
    std::uint8_t busy_readmissions{0};
    std::uint8_t physical_attempts{0};
    // window_limited is counted once per job per block episode — the DRR
    // select loop may revisit the same blocked flow up to kMaxSelectRounds
    // times in one pass.
    bool window_block_counted{false};
    // Observation identity stamped at physical submission (02 §2.3): the
    // runtime-frozen binding/radio/channel tuple — submission, hop-accept
    // and completion accounting share ONE key so counters can never split
    // across a rebind or channel boundary mid-attempt.
    ObservationKey obs_key{};
    bool obs_key_set{false};
  };

  // Bounded TX scheduler (03-congestion.md §4): a single fixed pool of TxJob
  // slots shared by a small reserved control lane (ACK/required responses)
  // and four DRR classes charged by estimated TX cost, with per-flow
  // round-robin inside each class. No queue duplication — flows link pool
  // jobs intrusively and classes hold only descriptor pointers.
  class TxScheduler {
   public:
    TxScheduler() noexcept = default;

    // Admission decision for `slots_needed` additional non-control jobs from
    // (scope, origin). Pure check: reserves nothing, so the caller must
    // enqueue immediately after (single-threaded owner).
    AdmitVerdict check(NodeId self, NodeId scope, NodeId origin,
                       std::size_t slots_needed) const noexcept;
    Status enqueue(TxJob&& job, NodeId self, MonotonicMs now_ms) noexcept;
    // DRR pick of the next transmittable job (control lane first). A job
    // whose peer window is full is skipped for this pass, not dropped.
    // Returns nullptr when nothing is eligible.
    TxJob* select(MonotonicMs now_ms, const MeshNode& node) noexcept;
    void take_selected(TxJob& out) noexcept;
    // Put the selected job back at the head of its lane (driver rejected
    // the submission before any transmit attempt).
    void requeue_selected() noexcept;
    // Move the selected job to the TAIL of its lane: the dispatch-time
    // route re-check holds it (bounded by its original deadline) without
    // head-of-line blocking the rest of its flow (03 §7).
    void defer_selected() noexcept;
    void clear() noexcept;

    bool empty() const noexcept { return used_ == 0; }
    bool full() const noexcept { return used_ >= capacity(); }
    std::size_t size() const noexcept { return used_; }
    // Live jobs of one owner class — used for honest drain visibility:
    // queued-but-undispatched work, not retained evidence records.
    std::size_t count_owner(JobOwner owner) const noexcept {
      std::size_t n = 0;
      pool_.for_each([&](const TxJob& job) {
        if (job.owner == owner) ++n;
      });
      return n;
    }
    static constexpr std::size_t capacity() noexcept { return kTxQueueCapacity; }
    std::size_t free_slots() const noexcept { return capacity() - used_; }
    std::size_t control_depth() const noexcept { return control_.count; }
    std::size_t flows_active() const noexcept { return flows_.size(); }
    std::uint32_t occupancy_percent() const noexcept {
      return static_cast<std::uint32_t>(used_ * 100 / capacity());
    }
    // Queue watermarks (03 §4): >=50% shrink background probe/log work,
    // >=80% suspend bulk and improvement probes.
    bool background_reduced() const noexcept {
      return occupancy_percent() >= kQueueWatermarkBackgroundPercent;
    }
    bool bulk_suspended() const noexcept {
      return occupancy_percent() >= kQueueWatermarkStopPercent;
    }

    CongestionStats stats_{};

   private:
    // Intrusive FIFO of pool jobs; only pointers, never job copies.
    struct JobList {
      TxJob* head{nullptr};
      TxJob* tail{nullptr};
      std::size_t count{0};

      bool empty() const noexcept { return head == nullptr; }
      void push_back(TxJob* job) noexcept {
        job->flow_next = nullptr;
        if (tail != nullptr) tail->flow_next = job;
        tail = job;
        if (head == nullptr) head = job;
        ++count;
      }
      void push_front(TxJob* job) noexcept {
        job->flow_next = head;
        head = job;
        if (tail == nullptr) tail = job;
        ++count;
      }
      TxJob* pop_front() noexcept {
        TxJob* job = head;
        if (job != nullptr) {
          head = job->flow_next;
          if (head == nullptr) tail = nullptr;
          job->flow_next = nullptr;
          --count;
        }
        return job;
      }
    };

    // Flow key = (verified sender scope, origin, concrete destination) per
    // class. `overflow` marks the shared bounded bucket used when the 32
    // descriptor table is full — new admissions merge instead of failing.
    struct FlowDesc {
      JobList jobs{};
      NodeId scope{kInvalidNodeId};
      NodeId origin{kInvalidNodeId};
      NodeId destination{kInvalidNodeId};
      SchedClass sched_class{SchedClass::Normal};
      bool in_rr{false};
      bool overflow{false};
    };

    static bool control_job(const TxJob& job) noexcept;
    static SchedClass classify(const TxJob& job) noexcept;
    static void flow_key(const TxJob& job, NodeId self, NodeId& scope,
                         NodeId& origin, NodeId& destination) noexcept;
    static void charge_cost(TxJob& job) noexcept;
    static std::size_t class_index(SchedClass value) noexcept {
      return sched_class_index(value);
    }
    FlowDesc* overflow_flow(SchedClass value) noexcept {
      FlowDesc& flow = overflow_[class_index(value)];
      flow.sched_class = value;
      flow.overflow = true;
      return &flow;
    }
    std::size_t origin_count(NodeId origin) const noexcept;
    std::size_t scope_count(NodeId scope) const noexcept;
    static bool data_class(SchedClass value) noexcept {
      return value != SchedClass::Management;
    }

    static constexpr std::size_t kControlLaneCapacity = 8;
    static constexpr std::size_t kMaxJobsPerOrigin = 12;
    static constexpr std::size_t kMaxJobsPerScope = 12;
    // DRR: quantum per round per class = weight * 64 bytes of estimated
    // cost; a 250-byte bulk frame becomes affordable within a few rounds.
    static constexpr std::int32_t kQuantumUnit = 64;
    static constexpr std::int32_t kDeficitCap = 1024;
    static constexpr std::size_t kMaxSelectRounds = 8;
    static constexpr std::size_t kRrCapacity = kFlowDescriptorsMax + kSchedClassCount;

    FixedPool<TxJob, kTxQueueCapacity> pool_{};
    FixedPool<FlowDesc, kFlowDescriptorsMax> flows_{};
    std::array<FlowDesc, kSchedClassCount> overflow_{};
    JobList control_{};
    std::array<FixedQueue<FlowDesc*, kRrCapacity>, kSchedClassCount> rr_{};
    std::array<std::int32_t, kSchedClassCount> deficit_{};
    std::size_t used_{0};
    std::size_t cursor_{0};
    TxJob* selected_{nullptr};
    FlowDesc* selected_flow_{nullptr};
    bool selected_control_{false};
  };

  struct PhysicalInflight {
    TxJob job{};
    std::uint64_t token{0};
    MonotonicMs submitted_at_ms{0};
    bool active{false};
    // An authenticated BUSY arrived while the frame was with the driver:
    // the deferral is applied when the TX result lands (03 §5).
    bool busy_deferred{false};
    std::uint32_t busy_retry_ms{0};
  };

  struct AwaitingHop {
    TxJob job{};
    MonotonicMs expires_at_ms{0};
    // An authenticated BUSY deferred this exchange: on expiry the job is
    // re-admitted against its BUSY readmission budget instead of consuming
    // an RF-loss attempt (03 §5).
    bool busy_deferred{false};
  };

  Status validate_config() const noexcept;
  Neighbor* find_neighbor(NodeId node) noexcept;
  const Neighbor* find_neighbor(NodeId node) const noexcept;
  // Identity reset (sdk-completion/03 §3.7): clears the measurement mirror
  // and returns link_cost to nominal — evidence gathered under a previous
  // peer incarnation/binding must not move the current identity's metric.
  static void reset_neighbor_measurement(Neighbor& neighbor) noexcept;
  Delivery* find_delivery(const MessageId& id) noexcept;
  const Delivery* find_delivery(const MessageId& id) const noexcept;
  DedupEntry* find_dedup(const MessageKey& key, FrameType type,
                         std::uint8_t round) noexcept;
  const DedupEntry* find_dedup(const MessageKey& key, FrameType type,
                               std::uint8_t round) const noexcept;
  // Phase-aware admission (sdk-completion/02 §2.5): class gates run BEFORE the
  // pool is touched (terminal-reserve, per-upstream cap); a full pool triggers
  // the bounded sweep expired -> Resolved -> Evidence, and Live/Terminal
  // records are never victims. `phase` is the birth phase (Terminal | Live |
  // Resolved — Evidence is only ever a post-resolution transition), `upstream`
  // the authenticated previous hop, `deadline_remaining_ms` the frame's own
  // remaining deadline (rx_age debited inside). Returns nullptr only after a
  // counted, diagnosed refusal — callers answer with BUSY/drop paths.
  DedupEntry* allocate_dedup(const MessageKey& key, FrameType type,
                             std::uint8_t round, DedupPhase phase,
                             NodeId upstream, std::uint32_t deadline_remaining_ms,
                             MonotonicMs now_ms) noexcept;
  // expires_at = min(first_seen + kDedupHardCapMs, horizon + slack(phase));
  // horizon = now + max(0, deadline_remaining - rx_age). Shared by admission
  // and the terminal re-receipt refresh.
  MonotonicMs dedup_expiry_for(DedupPhase phase, std::uint32_t deadline_remaining_ms,
                               MonotonicMs first_seen_ms,
                               MonotonicMs now_ms) const noexcept;
  // Non-terminal records admitted from `upstream` (the per-previous-hop bound).
  std::size_t count_transit_upstream(NodeId upstream) const noexcept;
  // Free exactly one evictable slot for a new admission: expired first (counts
  // as a normal expiry, never an eviction), then the earliest-expiry Resolved,
  // then the oldest Evidence. Live/Terminal are skipped unconditionally.
  // Emits the forced-eviction diagnostic/counter; false = true overflow.
  bool evict_dedup_for_admission(MonotonicMs now_ms) noexcept;
  // complete_job hook for JobOwner::Transit: the forward resolved, so the
  // record's duty shrinks to re-ACK + late-report relay (Live -> Resolved).
  void resolve_dedup_for_job(const TxJob& job) noexcept;
  // Resolved -> Evidence with the kEvidenceCap residency bound: at the cap the
  // oldest existing Evidence record is force-reclaimed (counted + diagnosed).
  void mark_dedup_evidence(DedupEntry& entry) noexcept;

  void set_delivery_state(Delivery& delivery, DeliveryState state,
                          const char* reason) noexcept;
  static bool sleep_terminal(DeliveryState state) noexcept;
  Status enqueue_delivery(const MessageId& id, NodeId destination, ByteView payload,
                          const SendOptions& options, MonotonicMs now_ms,
                          MessageId& out) noexcept;
  Status queue_origin_data(Delivery& delivery, MonotonicMs now_ms) noexcept;
  Status queue_forward(const wire::LinkOpenedFrame& frame, NodeId next_hop,
                       MonotonicMs now_ms) noexcept;
  Status queue_hop_accept(const wire::Header& accepted, MonotonicMs now_ms) noexcept;
  Status queue_end_receipt(const wire::Header& data, MonotonicMs now_ms) noexcept;
  // BUSY emission (03 §5): pre-admission refusal for a NEW authenticated
  // inbound DATA — never for already HOP_ACCEPT-ed work. Emits only when the
  // peer is busy-capable and a reply slot is affordable; otherwise drops and
  // counts busy_send_failed so the sender's timeout path stays honest.
  Status queue_busy(NodeId peer, const wire::Header& rejected,
                    std::uint8_t reason, MonotonicMs now_ms) noexcept;
  void emit_busy_or_drop(NodeId peer, const wire::Header& rejected,
                         std::uint8_t reason, MonotonicMs now_ms) noexcept;
  Status queue_route_update(NodeId neighbor, MonotonicMs now_ms) noexcept;
  Status queue_seqno_request(NodeId peer, NodeId requester, NodeId destination,
                             RouteSequence requested_sequence, std::uint32_t request_id,
                             std::uint8_t ttl, MonotonicMs now_ms) noexcept;
  // Shared enqueue for send_service/resend_service/send_typed: a Plain
  // end-protected routed job of `type` owned by `owner`, hop-accept required.
  Status queue_typed_job(FrameType type, JobOwner owner, const MessageId& id,
                         NodeId destination, ByteView payload, std::uint8_t round,
                         std::uint32_t lifetime_ms, Priority priority,
                         MonotonicMs now_ms) noexcept;

  Status encode_job(TxJob& job, MonotonicMs now_ms) noexcept;
  void dispatch_next(MonotonicMs now_ms) noexcept;
  void resolve_radio_tx_result(std::uint64_t token, bool success,
                               MonotonicMs now_ms) noexcept;
  void complete_job(TxJob& job, bool hop_accepted, MonotonicMs now_ms) noexcept;
  void fail_job(TxJob& job, const char* reason, MonotonicMs now_ms) noexcept;
  void retry_or_fail(TxJob& job, const char* reason, MonotonicMs now_ms) noexcept;
  // Re-admit a BUSY-deferred job after its clamped retry_after wait, bounded
  // by busy_readmissions_max and the combined physical-attempt budget (03 §5).
  void readmit_after_busy(TxJob& job, MonotonicMs now_ms) noexcept;
  // Dispatch gate for the scheduler: a job that requires HOP_ACCEPT is
  // eligible only while the peer's in-flight count is below its window.
  bool tx_admitted_now(const TxJob& job) const noexcept;
  std::size_t peer_inflight(NodeId peer) const noexcept;
  std::uint8_t peer_window(NodeId peer) const noexcept;
  std::uint32_t busy_retry_hint() const noexcept;

  // P3 load coupling (03 §6/§7): per-neighbor observation decay, busy-TTL,
  // effective link-cost refresh and the route-switch hysteresis tick.
  void refresh_neighbor_load(MonotonicMs now_ms) noexcept;
  void refresh_link_cost(Neighbor& neighbor, MonotonicMs now_ms) noexcept;

  void receive_impl(NodeId peer, ByteView frame, const RadioRxMetadataV2* metadata,
                    MonotonicMs now_ms) noexcept;

  // Observation aggregation (03 §3): bounded buckets keyed by the contract
  // tuple. find-or-allocate returns nullptr only when the pool is exhausted.
  ObservationBucket* observation_bucket(const ObservationKey& key,
                                        MonotonicMs now_ms) noexcept;
  // Convenience: egress bucket with portable-core placeholder generations
  // (0); the radio Owner keys real epochs via note_radio_tx (03 §3).
  ObservationBucket* observation_bucket(NodeId peer, std::uint8_t length_class,
                                        MonotonicMs now_ms) noexcept;
  void obs_tx_submitted(TxJob& job, std::uint64_t token,
                        MonotonicMs now_ms) noexcept;
  ObservationBucket* job_bucket(const TxJob& job, MonotonicMs now_ms) noexcept;
  void obs_driver_service(const TxJob& job, std::uint32_t service_us,
                          MonotonicMs now_ms) noexcept;
  void obs_hop_result(const TxJob& job, bool accepted, MonotonicMs now_ms) noexcept;
  void obs_count(const TxJob& job, std::uint64_t ObservationBucket::*counter,
                 MonotonicMs now_ms) noexcept;
  void obs_final(const Delivery& delivery, DeliveryState state,
                 MonotonicMs now_ms) noexcept;

  void handle_hop_accept(const wire::PlainFrame& frame, NodeId peer,
                         MonotonicMs now_ms) noexcept;
  void handle_data(const wire::LinkOpenedFrame& frame, NodeId peer,
                   MonotonicMs now_ms) noexcept;
  // End-protected routed traffic (Service 21, Control 22 and the
  // ConfigPermit object types 49/50/51): transit forwards untouched (dedup
  // + forward + hop ACK keyed on the frame's own type), terminal hands the
  // end-verified payload to the matching sink (Service -> gateway sink,
  // the config types -> config sink). Never enters the DATA path and never
  // emits END_RECEIPT. The link-scoped autonomy forms of 49/50/51 keep
  // their separate destination==self path and never reach here.
  void handle_routed(const wire::LinkOpenedFrame& frame, NodeId peer,
                     MonotonicMs now_ms) noexcept;
  // End-protected Diagnostic (48) terminal handling (02-telemetry §4.2):
  // subtype dispatch on the verified body — TelemetryQuery answers with a
  // bounded snapshot or an honest DiagnosticReject; Snapshot/Reject surface
  // to the diagnostic sink.
  void handle_diagnostic(const wire::PlainFrame& frame, NodeId peer,
                         MonotonicMs now_ms) noexcept;
  // Link-only Diagnostic subtypes addressed to this node (Capabilities,
  // TransitFailure): surfaced to the diagnostic sink; never answered on a
  // new route.
  void handle_diagnostic_link(NodeId peer, const wire::LinkOpenedFrame& frame,
                              MonotonicMs now_ms) noexcept;
  // Emit one bounded link-only TransitFailure toward `upstream` (hop-1,
  // BestEffort, never hop-ACKed — a report must not spawn reports).
  void emit_transit_failure(NodeId upstream, const TransitFailure& report,
                            MonotonicMs now_ms) noexcept;
  // fail_job hook for JobOwner::Transit: find the retained transit record
  // for job.ack and report the post-acceptance failure to its upstream.
  void report_transit_failure(const TxJob& job, const char* reason,
                              MonotonicMs now_ms) noexcept;
  // Map a local failure reason onto the wire reason space; phase is 1 for a
  // proven local failure, 2 when the attempt outcome cannot be proven.
  static void map_transit_reason(const char* reason, TransitFailurePhase& phase,
                                 TransitFailureReason& out) noexcept;
  // Refused-before-acceptance report (relay gate): no retained record, the
  // fingerprint is computed from the received frame on the spot.
  void emit_transit_refusal(const wire::LinkOpenedFrame& frame,
                            TransitFailureReason reason,
                            MonotonicMs now_ms) noexcept;
  void handle_transit_failure_report(NodeId peer,
                                     const TransitFailure& report,
                                     MonotonicMs now_ms) noexcept;
  void replay_retained_failure(DedupEntry& duplicate, FrameType type,
                               MonotonicMs now_ms) noexcept;
  Status queue_diagnostic_reply(NodeId destination, ByteView body,
                                std::uint32_t lifetime_ms,
                                MonotonicMs now_ms) noexcept;
  void handle_busy(const wire::LinkOpenedFrame& frame, NodeId peer,
                   MonotonicMs now_ms) noexcept;
  void handle_end_receipt(const wire::LinkOpenedFrame& frame, NodeId peer,
                          MonotonicMs now_ms) noexcept;
  // APPLIED (sdk-completion/01): terminal-side dispatch stores the verdict in
  // an AppliedRecord then emits RESULT; the origin side validates RESULT/
  // STATUS against the delivery and QUERY/RESULT_ACK against the record pool.
  AppliedRecord* find_applied(const MessageKey& key) noexcept;
  const AppliedRecord* find_applied(const MessageKey& key) const noexcept;
  // find-or-allocate is split: handle_data allocates BEFORE the hop ACK so a
  // full pool is a pre-acceptance refusal, never accepted work without a
  // place to store its verdict.
  AppliedRecord* allocate_applied(const wire::Header& data, ByteView body,
                                  MonotonicMs now_ms) noexcept;
  void dispatch_applied(const wire::Header& data, ByteView body,
                        AppliedRecord& record, bool fresh,
                        MonotonicMs now_ms) noexcept;
  void handle_app_result(const wire::PlainFrame& frame, NodeId peer,
                         MonotonicMs now_ms) noexcept;
  Status emit_applied_result(AppliedRecord& record, MonotonicMs now_ms) noexcept;
  void emit_app_status(NodeId origin, const MessageKey& key,
                       const std::array<std::uint8_t, 32>& request_digest,
                       endpoint::AppResultStatusCode code, std::uint64_t nonce,
                       std::uint32_t lifetime_ms, MonotonicMs now_ms) noexcept;
  void emit_app_result_ack(NodeId terminal, const endpoint::AppResultHead& head,
                           ByteView canonical_result_body,
                           MonotonicMs now_ms) noexcept;
  Status emit_app_query(Delivery& delivery, MonotonicMs now_ms) noexcept;
  // poll() driver: expiry sweep + bounded RESULT emit retries.
  void process_applied(MonotonicMs now_ms) noexcept;
  bool applied_answer_gate(NodeId peer, MonotonicMs now_ms) noexcept;
  // Same hop-scaled wait window the END_RECEIPT retry path uses (a RESULT or
  // QUERY answer has a comparable trip). `hop_limit` is the frame's own.
  static std::uint32_t applied_window_ms(std::uint8_t hop_limit,
                                         std::uint32_t hop_timeout_ms) noexcept;
  void handle_route_update(const wire::PlainFrame& frame, NodeId peer,
                           MonotonicMs now_ms) noexcept;
  void handle_seqno_request(const wire::PlainFrame& frame, NodeId peer,
                            MonotonicMs now_ms) noexcept;

  void process_awaiting_hop(MonotonicMs now_ms) noexcept;
  void process_delivery_timeouts(MonotonicMs now_ms) noexcept;
  void expire_dedup(MonotonicMs now_ms) noexcept;
  void schedule_route_advertisements(MonotonicMs now_ms) noexcept;
  void schedule_sequence_requests(MonotonicMs now_ms) noexcept;
  void expire_sequence_requests(MonotonicMs now_ms) noexcept;
  // Triggered update: schedule a full-neighbor advertisement burst after a
  // deterministic jitter, bounded by a minimum interval between bursts so a
  // flap storm cannot flood the TX queue.
  void trigger_route_advertisement(MonotonicMs now_ms) noexcept;
  void run_triggered_advertisement(MonotonicMs now_ms) noexcept;

  static Status encode_ack_payload(const AckKey& key,
                                   std::array<std::uint8_t, kMaxApplicationPayload>& payload,
                                   std::size_t& size) noexcept;
  static Status decode_ack_payload(ByteView payload, AckKey& key) noexcept;
  static Status encode_receipt_payload(const wire::Header& data,
                                       std::array<std::uint8_t, kMaxApplicationPayload>& payload,
                                       std::size_t& size) noexcept;
  static Status decode_receipt_payload(ByteView payload, MessageKey& key,
                                       std::uint8_t& round) noexcept;

  NodeConfig config_{};
  RadioPort& radio_;
  SecurityProvider& security_;
  NodeObserver& observer_;
  RouteTable routes_{};
  AutonomyFrameSink* autonomy_sink_{nullptr};
  GatewayServiceSink* gateway_sink_{nullptr};
  ConfigEndpointSink* config_sink_{nullptr};
  DiagnosticSink* diagnostic_sink_{nullptr};
  // Seen-table for inbound TransitFailure reports (dedup on
  // reference+phase+reason — a different report_id must not restart work).
  struct TransitFailureSeen {
    MessageKey key{};
    FrameType type{FrameType::Data};
    std::uint8_t round{0};
    std::uint8_t phase{0};
    std::uint8_t reason{0};
    MonotonicMs expires_at_ms{0};
  };
  static constexpr std::size_t kTransitFailureSeenCapacity = 8;
  std::array<TransitFailureSeen, kTransitFailureSeenCapacity>
      transit_failure_seen_{};
  // Per-boot monotone report id; nonzero, wrap suppresses new reports.
  std::uint32_t next_failure_report_id_{1};
  // Diagnostic intake/emission budgets (04 §capabilities, telemetry §2.7,
  // forwarding §1.4): bounded per-peer pacing for capability replies,
  // routed telemetry queries and emitted TransitFailure reports — a peer
  // cannot keep the radio busy with diagnostic traffic.
  struct DiagBudget {
    NodeId peer{kInvalidNodeId};
    MonotonicMs window_start_ms{0};
    std::uint8_t window_used{0};
    // Inbound TransitFailure intake bound (kTransitFailurePerWindow per
    // 1 s window shares window_start_ms with window_used).
    std::uint8_t failure_window_used{0};
    MonotonicMs last_cap_reply_ms{0};
    MonotonicMs last_query_ms{0};
    // APPLIED answer gate (sdk-completion/01 §1.4): QUERY answers (RESULT
    // replay / STATUS) are paced to one per kAppliedAnswerMinIntervalMs per
    // peer so QUERY floods cannot amplify into unbounded transmissions.
    MonotonicMs last_applied_ms{0};
  };
  static constexpr std::size_t kDiagBudgetCapacity = 8;
  static constexpr std::uint8_t kTransitFailurePerWindow = 2;  // per 1 s/peer
  static constexpr std::uint32_t kDiagBudgetWindowMs = 1000;
  static constexpr std::uint32_t kCapReplyMinIntervalMs = 1000;
  static constexpr std::uint32_t kDiagQueryMinIntervalMs = 200;
  std::array<DiagBudget, kDiagBudgetCapacity> diag_budget_{};
  DiagBudget* diag_budget(NodeId peer, MonotonicMs now_ms) noexcept;
  // Outstanding capability probes (04 §capabilities): a reply is accepted
  // only when its echo_nonce matches a live entry for the answering peer.
  struct PendingCapQuery {
    NodeId peer{kInvalidNodeId};
    std::array<std::uint8_t, kCapabilitiesNonceSize> nonce{};
    MonotonicMs expires_at_ms{0};
    // The peer's binding generation when the query was emitted — a reply
    // arriving after a rebind is stale evidence and never grants
    // capability (04 §capabilities).
    BindingGeneration binding{0};
  };
  static constexpr std::size_t kPendingCapCapacity = 8;
  static constexpr std::uint32_t kCapQueryLifetimeMs = 15000;
  // Renewal bound (04 §capabilities): a completed/expired probe may not be
  // restarted for the same peer inside this interval.
  static constexpr std::uint32_t kCapQueryRenewalMs = 5000;
  static constexpr std::uint8_t kMaxFailureReplays = 3;
  static constexpr std::uint32_t kFailureReplayMinIntervalMs = 1000;
  std::array<PendingCapQuery, kPendingCapCapacity> pending_caps_{};
  bool relay_enabled_{true};
  bool telemetry_remote_{false};
  // Refusal-pressure evidence (sdk-completion/03 §3.4): last observed
  // admissions_rejected counter value and when it last changed.
  std::uint64_t last_admission_rejections_{0};
  MonotonicMs last_refusal_ms_{0};

  FixedPool<Neighbor, kNeighborCapacity> neighbors_{};
  FixedPool<Delivery, kDeliveryCapacity> deliveries_{};
  FixedPool<DedupEntry, kDedupCapacity> dedup_{};
  // Terminal APPLIED result records (sdk-completion/01 §1.6): bounded pool,
  // eviction order expired -> oldest acked -> refuse admission.
  FixedPool<AppliedRecord, kAppliedResultCapacity> applied_records_{};
  AppliedEndpointSink* applied_sink_{nullptr};
  AppliedStats applied_stats_{};
  std::uint64_t next_app_nonce_{1};
  FixedPool<SeqnoSeen, kSeqnoSeenCapacity> seqno_seen_{};
  FixedPool<SeqnoState, kSeqnoStateCapacity> seqno_state_{};
  TxScheduler scheduler_{};
  FixedPool<AwaitingHop, kAwaitingHopCapacity> awaiting_hop_{};
  PhysicalInflight physical_{};
  // Single-slot submit identity handoff from the runtime (one physical
  // send in flight): obs_tx_submitted consumes it for the matching token.
  struct SubmitIdentity {
    std::uint64_t token{0};
    ObservationKey key{};
    bool valid{false};
  } submit_identity_{};
  std::uint64_t next_physical_token_{1};
  std::uint64_t next_message_sequence_{1};
  std::uint64_t next_control_sequence_{1};
  std::uint32_t next_seqno_request_id_{1};
  RouteSequence self_route_sequence_{1};
  MonotonicMs next_route_advertisement_ms_{0};
  std::size_t route_neighbor_cursor_{0};
  bool triggered_advertisement_{false};
  MonotonicMs triggered_at_ms_{0};
  MonotonicMs next_triggered_ms_{0};
  std::uint32_t trigger_counter_{0};
  // Node-global ordering tag stamped on emitted BUSY payloads; receivers
  // compare it per-peer to reject stale/replayed feedback (03 §5).
  std::uint32_t next_feedback_sequence_{1};
  // BUSY-side statistics; merged into congestion_stats() with the
  // scheduler's own counters.
  CongestionStats busy_stats_{};
  // Dedup capacity counters (sdk-completion/02 §2.4) — admissions, refusals,
  // forced evictions and expiry releases, all saturating u64.
  DedupStats dedup_stats_{};
  // Bounded observation buckets (03 §3 groundwork for P3).
  static constexpr std::size_t kObservationCapacity = 8;
  FixedPool<ObservationBucket, kObservationCapacity> observations_{};
  // M1 telemetry (m1-completion/02-telemetry.md): per-peer RF summaries and
  // the count of frames that never reached telemetry because they failed
  // link authentication or identity checks — telemetry never credits
  // unauthenticated bytes to a peer.
  PeerTelemetryTable telemetry_peers_{};
  std::uint64_t telemetry_event_drops_{0};
  // Transit refusals under a disabled/draining relay gate (01 §policy) —
  // counted so relay-off is evidence, not a silent black hole.
  std::uint64_t transit_refused_{0};
  // Driver-queue age of the frame currently inside receive_impl — debited
  // from the forwarding budget by queue_forward (01 §lifetime).
  std::uint32_t rx_age_ms_{0};
  // Latest wall time seen on the event path; observation timestamps use it
  // where the call site (e.g. delivery-state transitions) has no clock.
  MonotonicMs last_clock_ms_{0};
  std::uint32_t work_generation_{0};
  std::uint32_t rx_generation_{0};
  std::uint32_t config_revision_{0};
  bool started_{false};
  bool sleep_draining_{false};
  PauseReason pause_reason_{PauseReason::None};
  std::uint8_t pause_mask_{0};
};

}  // namespace routeloom
