#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <new>
#include <type_traits>
#include <utility>

#include "routeloom/congestion.hpp"
#include "routeloom/endpoint_wire.hpp"
#include "routeloom/telemetry.hpp"
#include "routeloom/fixed_containers.hpp"
#include "routeloom/group.hpp"
#include "routeloom/node_status.hpp"
#include "routeloom/reply_peer_leases.hpp"
#include "routeloom/route_request.hpp"
#include "routeloom/routing.hpp"
#include "routeloom/security.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"
#include "routeloom/wire.hpp"

namespace routeloom {

namespace sdkv1 {
class BootstrapSink;
struct BootstrapMeta;
}  // namespace sdkv1

// Physical submission tokens never repeat within one node lifetime. Zero is
// the exhausted sentinel after the last nonzero token is issued.
constexpr bool mint_physical_token(std::uint64_t& next,
                                   std::uint64_t& out) noexcept {
  if (next == 0) return false;
  out = next;
  ++next;
  return true;
}

struct NodeConfig {
  NetworkId network{0};
  NodeId node{kInvalidNodeId};
  std::uint32_t message_session{0};
  // Durable boot token (G-SEC P4 §9.1): the rlboot value stamped as the
  // second ExecutionLease field. 0 selects the compat init — the MeshNode
  // constructor substitutes message_session in that one place. Callers
  // behind a session-type provider must pass an explicit nonzero value
  // (the Owner refuses 0 there); end_epoch is never the fallback.
  std::uint32_t boot_session{0};
  std::uint32_t link_epoch{1};
  std::uint32_t end_epoch{1};
  // Origin generation for this node's own route source. Must be persisted
  // monotonic and incremented on every boot; a restarted node advertises a
  // higher generation so peers discard its previous-incarnation route state.
  std::uint32_t route_generation{1};
  std::uint32_t route_advertisement_period_ms{5000};
  std::uint32_t route_lifetime_ms{15000};
  // Gateway-scoped routing profile (docs/design/sdk-v1/routing-scale.md).
  // All kInvalidNodeId (the default) keeps the flat profile: every selected
  // route is advertised to every neighbor, page by page. Naming at least one
  // gateway switches the node to the scoped profile: routes to the listed
  // gateways are proactive and tree-refreshed, other destinations are
  // learned upward along the gateway tree or on demand (ROUTE_REQUEST).
  // Every node of a site must carry the same list; a gateway lists itself.
  std::array<NodeId, kMaxRouteGateways> route_gateways{};
  // Scoped profile only: every gateway-tree link is refreshed once per this
  // many advertisement periods. validate_config() enforces
  // route_lifetime_ms >= (2 * ticks + kScopedLeaseMarginTicks) * period.
  std::uint8_t route_refresh_ticks{kScopedDefaultRefreshTicks};
  // §14 management airtime budget gate (03-congestion.md §8, radio.md
  // §9/§14): the pinned spec-envelope refill is an UNCALIBRATED
  // capability, not a measured allocation — it must not gate route
  // maintenance in the default profile. Enable only for a calibrated
  // profile whose capacity decision covers fan-out, route-table page
  // count and the lease refresh deadline; the gate then re-checks that
  // bound on every deferred emission.
  bool control_budget_gate_enabled{false};
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
  // Group delivery airtime budget at a SOURCE (group-delivery.md §5): the
  // estimated network-sum air time (data copies + confirmations, §14 model)
  // that Normal/Bulk/Management group messages may start per second. Urgent
  // group messages are never held by it (they are debited, may run it into
  // debt, and delay the next non-urgent message instead). 0 disables the
  // gate (unbounded — test/bring-up only).
  std::uint32_t group_airtime_us_per_s{300000};
};

// --- Group delivery (group.hpp, group.cpp, docs/design/sdk-v1/group-delivery.md)
// Static bounds (no dynamic allocation). Per-node RAM for all group state is
// reported in group-delivery.md §9.
constexpr std::size_t kGroupMembershipMax = 8;    // locally configured groups (+ ALL)
constexpr std::size_t kGroupTreeCapacity = 4;     // messages tracked as relay/receiver
constexpr std::size_t kGroupMaxChildren = 10;     // tree children tracked per message
constexpr std::size_t kGroupOriginCapacity = 3;   // messages tracked as source (1 Urgent reserve)
constexpr std::size_t kGroupHoldCapacity = 4;     // ordered messages held for a gap
constexpr std::size_t kGroupStreamCapacity = kMaxRouteGateways;  // sources = gateways
// Report wait per remaining tree level: a node whose children received the
// copy with hop_remaining h waits h x this for their reports, one level more
// than any child waits for its own subtree (nested deadlines).
constexpr std::uint32_t kGroupLevelWaitMs = 150;
constexpr std::uint8_t kGroupMaxRounds = 12;         // round 0 + up to 11 repairs (lifetime-bound)
constexpr std::uint32_t kGroupRepairGapMs = 200;     // pause between rounds at the source
// A next-GK frame held for its durable promote expires after this when
// the promote never settles (blocked store): the repair round recovers.
constexpr MonotonicMs kGroupPromoteHoldMs = 5000;
// An ordered message waiting for a gap is released (the gap skipped) after
// min(its own remaining lifetime, this) — head-of-line blocking never
// outlives the message lifetime (group-delivery.md §6).
constexpr std::uint32_t kGroupOrderMaxHoldMs = 10000;
// Per-source duplicate window over the group stream numbers.
constexpr std::uint32_t kGroupSeenWindow = 64;
// The source retires (Failed, GROUP_SUPERSEDED) a message this many stream
// numbers behind a newly admitted one, so no receiver window can be outrun.
constexpr std::uint32_t kGroupStaleSeqs = 32;
// Airtime bucket depth at the source: two full 100-node messages.
constexpr std::int64_t kGroupBudgetCapacityUs = 3000000;

struct GroupSendOptions {
  Priority priority{Priority::Normal};
  std::uint32_t lifetime_ms{5000};        // 1..kMaxMessageLifetimeMs
  std::uint8_t hop_limit{kDefaultHopLimit};
  // In-order delivery at every receiver relative to this source's other
  // ORDERED group messages (bounded hold, group-delivery.md §6).
  bool ordered{false};
};

// What a receiving application learns about a group message.
struct GroupMessageInfo {
  MessageKey key{};                 // {source, group MessageId}
  GroupId group{0};
  std::uint32_t group_seq{0};       // the source's group stream number
  Priority priority{Priority::Normal};
  bool ordered{false};
  // ORDERED message that arrived after its slot had been skipped (the gap
  // hold timed out): delivered, but out of order — the app decides.
  bool late{false};
};

// Source-side result (group_delivery / on_group_delivery). Counts are the
// aggregated tree confirmations of the latest round; delivered counts
// member nodes whose node accepted the message for its application.
struct GroupDeliveryResult {
  MessageId id{};
  GroupId group{0};
  DeliveryState state{DeliveryState::Empty};
  const char* reason{"NONE"};
  std::uint8_t rounds{0};           // rounds sent (0 while queued)
  std::uint16_t delivered{0};
  std::uint16_t nonmember{0};       // reached, not a member of the group
  std::uint16_t missing_total{0};   // nodes known in the tree without confirmation
  // Nodes the source's route table knows that no report accounted for
  // (tree inconsistency) — ids unknown, never folded into missing ids.
  std::uint16_t unaccounted{0};
  std::uint8_t missing_count{0};    // ids listed below (<= kGroupReportMissingMax)
  bool missing_truncated{false};    // missing_total > missing_count
  std::array<NodeId, kGroupReportMissingMax> missing{};
};

// Saturating counters for the group lane (tests, diagnostics).
struct GroupStats {
  std::uint64_t sent{0};              // send_group admissions (source)
  std::uint64_t rounds_started{0};    // source rounds (repairs included)
  std::uint64_t repair_rounds{0};
  std::uint64_t budget_deferrals{0};  // admission waits on the airtime bucket
  std::uint64_t copies_queued{0};     // GROUP_DATA copies handed to the scheduler
  std::uint64_t copies_failed{0};     // copies that never got a MAC ACK
  std::uint64_t reports_sent{0};
  std::uint64_t not_child_sent{0};
  std::uint64_t reports_received{0};
  std::uint64_t reports_unmatched{0};
  std::uint64_t received{0};          // first receipts (opened)
  std::uint64_t duplicates{0};        // copies of a message already received
  std::uint64_t delivered{0};         // handed to the application
  std::uint64_t held{0};              // ordered messages held for a gap
  std::uint64_t gaps_skipped{0};      // stream numbers skipped by a hold timeout
  std::uint64_t late{0};              // ordered messages delivered late
  std::uint64_t rejected{0};          // invalid/unsupported group frames
  std::uint64_t open_failures{0};
  std::uint64_t state_refusals{0};    // no tree slot: subtree reported missing
  std::uint64_t promote_holds{0};     // next-GK frames held for the durable promote
  std::uint64_t promote_drops{0};     // held frames dropped (slot busy/expired)
};

// Read-only views of the receive-side group state (tests/diagnostics):
// the per-source dedup window + ordering cursor, and one ordered message
// held behind a gap (group-delivery.md §4, §5.1).
struct GroupStreamSnapshot {
  NodeId source{kInvalidNodeId};
  std::uint32_t session{0};
  std::uint32_t max_seq{0};   // highest stream number seen (0 = none)
  std::uint64_t seen{0};      // bit i: stream number max_seq - i seen
  std::uint32_t next_seq{0};  // in-order delivery cursor (0 = unset)
};
struct GroupHoldSnapshot {
  GroupMessageInfo info{};
  MonotonicMs release_at_ms{0};
  std::uint8_t size{0};
  std::array<std::uint8_t, kGroupPayloadMax> payload{};
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
constexpr std::uint32_t kAppliedResultHoldMs = kTerminalRetentionMs;
constexpr std::uint32_t kAppliedLateResultMs = kLateResultTtlMs;
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

// Callbacks run synchronously on the node's owner execution context and must
// return in bounded time. View/result arguments are borrowed for the call
// only — never retained. A callback must not re-enter the PowerCoordinator:
// its mutating calls return Busy and change nothing while a callback runs —
// call them after the callback returns. Do not recursively drive
// poll()/on_radio_receive()/on_radio_tx_result() from here.
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
  // Group delivery (group-delivery.md). A received group message: the default
  // forwards to on_message (group MessageIds never collide with unicast
  // ones — kGroupSequenceFlag), so observers without a group surface still
  // see the payload exactly once.
  virtual void on_group_message(const GroupMessageInfo& info, ByteView payload) noexcept {
    on_message(info.key, info.key.origin, payload);
  }
  // Source side: fires when a group message's summary changes (after every
  // round) and once more when it turns terminal.
  virtual void on_group_delivery(const GroupDeliveryResult& result) noexcept {
    (void)result;
  }
};

class NullObserver final : public NodeObserver {
 public:
  void on_message(const MessageKey&, NodeId, ByteView) noexcept override {}
  void on_delivery(const DeliveryResult&) noexcept override {}
  void on_diagnostic(const char*, NodeId, const MessageId*) noexcept override {}
};

// Outcome of one sleep-driven ordered-hold release.
enum class SleepHoldRelease : std::uint8_t {
  Released = 0,   // one held message was handed to the application
  NonePending,    // no held message remains
  StreamInvariant,  // target hold has no (source, session) stream: holds kept,
                    // the sleep attempt must abort, never drop payload
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

// P6 revocation-gossip sink (docs/design/sdk-v1/04-removal-revocation.md
// §4, PR A): the Owner installs one to receive link-scoped P6 bodies — the
// exact-shape Control (22) StateEpochs/RrsRequest payloads and kind-6
// (RevocationSet) object manifests. Frames arrive link-authenticated from
// the immediate peer (previous_hop), self-addressed and never
// end-protected; the sink still re-validates them against the verified
// binding and the SAK before acting. Chunks/ACKs carry no kind, so they
// keep flowing to the autonomy sink — the Owner demuxes them by its
// (peer, binding, protection-class, hash) registry (RrsExchange::
// owns_transfer) when production P6 wiring lands. Unwired (nullptr) in
// PR A: gossip is exercised through fake ports, and every P6 frame is
// rejected with an honest diagnostic until the P4/P5 adapters land.
class RrsGossipSink {
 public:
  virtual ~RrsGossipSink() = default;
  virtual void on_rrs_frame(NodeId peer, FrameType type, ByteView body,
                            MonotonicMs now_ms) noexcept = 0;
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

// --- ExpectedReply admission transactions (issue #117, design-q116 §7-§8) ---
// One transaction per accepted receive: it owns one Owner lease use and every
// local work item the admission created (ACK/forward/receipt jobs, component
// event). Local work ends at min(frame budget, admission + 1500 ms); the
// wire budget a forward carries is unaffected (encode keeps the job's own
// deadline). Handles are slot + strictly increasing serial so a stale handle
// can never finish another transaction's work.
constexpr std::size_t kAdmissionTransactionsMax = 8;

struct TxnHandle {
  std::uint32_t slot{0};
  std::uint32_t serial{0};

  friend constexpr bool operator==(const TxnHandle& a,
                                   const TxnHandle& b) noexcept {
    return a.slot == b.slot && a.serial == b.serial;
  }
  friend constexpr bool operator!=(const TxnHandle& a,
                                   const TxnHandle& b) noexcept {
    return !(a == b);
  }
};
constexpr TxnHandle kInvalidTxnHandle{0xFFFFFFFFu, 0};

// Deferred component deliveries (design-q116 §8.3): the node never calls the
// Service/config components synchronously. Payloads and job completions wait
// here for the Owner, which takes them after the node call returned and
// hands them to the component as ordinary outside calls.
constexpr std::size_t kComponentEventsMax = 8;

enum class ComponentEventTarget : std::uint8_t {
  ServicePayload = 0,  // GatewayServiceSink::on_service_payload
  ConfigFrame = 1,     // ConfigEndpointSink::on_config_frame
  ServiceJobDone = 2,  // GatewayServiceSink::on_service_job_done
  ConfigJobDone = 3,   // ConfigEndpointSink::on_config_job_done
};

struct ComponentEventHandle {
  std::uint32_t slot{0};
  std::uint32_t serial{0};

  friend constexpr bool operator==(const ComponentEventHandle& a,
                                   const ComponentEventHandle& b) noexcept {
    return a.slot == b.slot && a.serial == b.serial;
  }
  friend constexpr bool operator!=(const ComponentEventHandle& a,
                                   const ComponentEventHandle& b) noexcept {
    return !(a == b);
  }
};
constexpr ComponentEventHandle kInvalidComponentEventHandle{0xFFFFFFFFu, 0};

struct ComponentEvent {
  ComponentEventHandle handle{kInvalidComponentEventHandle};
  ComponentEventTarget target{ComponentEventTarget::ServicePayload};
  NodeId peer{kInvalidNodeId};  // payload events: authenticated previous hop
  TxnHandle txn{kInvalidTxnHandle};  // owning transaction, if any
  MonotonicMs deadline_ms{0};       // the transaction's deadline; the Owner
                                    // starts no new payload work past it
  wire::PlainFrame frame{};         // payload events: verified terminal frame
  MessageId job_id{};               // completion events: the job's MessageId
  bool job_accepted{false};         // completion events: HOP_ACCEPT vs failure
  const char* job_reason{nullptr};  // completion events: static reason string
};

// A receive's captured reply identity: the Owner's RX binding evidence plus
// the link-authenticated epoch. Admission passes it to the lease port, which
// rechecks it against the live mapping — equality only.
struct RxBinding {
  ReplyBinding binding{};
  bool valid{false};
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
// debit, clamped to kMaxMessageLifetimeMs). Duplicates never extend retention
// past the first-seen hard cap.
//   Terminal — slack = late-result TTL: the pin outlives the origin's own
//              expiry (its last possible round/resume) by 30 s, and never
//              exceeds the 60 s design value (max lifetime + late result).
//   others   — slack = kTransitSlackMs: a relay only suppresses duplicate
//              forwarding while the frame can still be valid, plus the
//              downstream TransitFailure report budget (3 s) and drain margin.
//              A 5 s-lifetime transit record lives ~10 s, not 60 s (#39).
constexpr std::uint32_t kDedupHardCapMs = kTerminalRetentionMs;  // first-seen cap
constexpr std::uint32_t kTerminalSlackMs = kLateResultTtlMs;     // exactly-once pin
constexpr std::uint32_t kTransitSlackMs = 5000;  // report budget + drain margin
static_assert(kMaxMessageLifetimeMs + kTerminalSlackMs <= kDedupHardCapMs,
              "a max-lifetime terminal pin must fit under the hard cap");
static_assert(kTransitSlackMs < kTerminalSlackMs,
              "transit duty ends before the terminal late-result window");

// Pool capacity is a compile-time resource-profile constant (no dynamic
// allocation; docs/reference/resource-profiles.json `dedup_entries`). Select
// it for the WHOLE build — the value changes sizeof(MeshNode), so every
// translation unit must agree: the host CMake option ROUTELOOM_DEDUP_PROFILE
// and the ESP-IDF Kconfig choice both set it as a PUBLIC definition on the
// core library. The default is the relay profile.
constexpr std::size_t kDedupCapacityLeaf = 32;      // leaf-small
constexpr std::size_t kDedupCapacityRelay = 96;     // relay-c3 (default)
constexpr std::size_t kDedupCapacityGateway = 256;  // gateway-s3
#ifndef ROUTELOOM_DEDUP_CAPACITY
#define ROUTELOOM_DEDUP_CAPACITY 96
#endif
constexpr std::size_t kDedupCapacity = ROUTELOOM_DEDUP_CAPACITY;
static_assert(kDedupCapacity == kDedupCapacityLeaf ||
                  kDedupCapacity == kDedupCapacityRelay ||
                  kDedupCapacity == kDedupCapacityGateway,
              "ROUTELOOM_DEDUP_CAPACITY must be a resource-profile value "
              "(32 leaf / 96 relay / 256 gateway)");
// Admission bounds scale with the pool at the ratios of the reviewed 64-slot
// design (8 / 24 / 16 of 64): terminal pins may occupy at most
// kDedupCapacity - kDedupTransitReserve slots so transit/evictable traffic
// always keeps a reserve; one previous-hop peer may hold at most
// kDedupPerUpstreamMax non-terminal records (at the bound it recycles its OWN
// evictable records first); Evidence residency is capped.
constexpr std::size_t kDedupTransitReserve = kDedupCapacity / 8;
constexpr std::size_t kDedupPerUpstreamMax = kDedupCapacity * 3 / 8;
constexpr std::size_t kEvidenceCap = kDedupCapacity / 4;
constexpr std::size_t kDedupTerminalPinMax = kDedupCapacity - kDedupTransitReserve;

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

// Gateway-scoped routing counters (routing-scale.md §7). Saturating
// monotonic totals; frames are counted when the job is admitted to the TX
// scheduler, not when it reaches the air.
struct RouteScaleStats {
  std::uint64_t upward_frames{0};         // periodic + triggered frames to a parent
  std::uint64_t downward_frames{0};       // periodic + triggered frames to children
  std::uint64_t other_frames{0};          // slow rotation to non-tree neighbors
  std::uint64_t pull_answers{0};          // answers to a Neighbor ROUTE_REQUEST
  std::uint64_t pulls_sent{0};            // Neighbor ROUTE_REQUEST frames sent
  std::uint64_t discoveries_started{0};   // destinations that entered discovery
  std::uint64_t discovery_requests_sent{0};
  std::uint64_t discovery_requests_forwarded{0};
  std::uint64_t discovery_replies_sent{0};
  std::uint64_t discovery_replies_forwarded{0};
  std::uint64_t discoveries_resolved{0};  // discovery state closed by a live route
  std::uint64_t route_requests_dropped{0};  // invalid, duplicate, rate-limited or no path
};

// Provider-owned sessions (sdk-v1/03 §8–§9, plan P4-1). All zero with a
// provider that does not own sessions (the default tx_epoch/context_state,
// e.g. the development PSK provider). Saturating u32 totals.
struct SessionStats {
  // Jobs held because the provider refused tx_epoch() with AuthRequired and
  // reported the context None or Establishing (counted once per job; the
  // diagnostic SESSION_REQUIRED / SESSION_PENDING names the context peer).
  std::uint32_t tx_deferred{0};
  // Deferred jobs whose deadline passed before a session appeared: failed
  // with SESSION_UNAVAILABLE instead of JOB_EXPIRED.
  std::uint32_t tx_unavailable{0};
  // Received frames whose link or end open returned AuthRequired (unknown
  // context id, 03 §9); the provider's detail is still the diagnostic.
  std::uint32_t rx_auth_required{0};
};

class MeshNode {
 public:
  // Non-reentrant facade (issue #117, design-q116 §2): every mutating call
  // below first checks the in-call guard — a call issued while another node
  // call is active (observer/sink/radio callback re-entry) returns Busy
  // with zero observable change. Internal paths never call these guarded
  // entries; read-only snapshots stay available during a call.
  MeshNode(const NodeConfig& config, RadioPort& radio, SecurityProvider& security,
           NodeObserver& observer) noexcept;

  Status start(MonotonicMs now_ms) noexcept;
  Status add_neighbor(NodeId neighbor, RouteMetric link_metric,
                      MonotonicMs now_ms) noexcept;
  Status remove_neighbor(NodeId neighbor, MonotonicMs now_ms) noexcept;

  // Synchronous admission attempts; never buffered by PowerCoordinator.
  // While the sleep drain mask is active they return NODE_DRAINING,
  // including during callbacks that Busy-reject sleep_abort(). Retry from
  // application-owned storage after RUNNING is observed. Refused attempts
  // invalidate an already-issued sleep ticket.
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
  Status set_applied_sink(AppliedEndpointSink* sink) noexcept;
  // The stored RESULT view for a delivery: false when none was verified.
  bool applied_result(const MessageId& id, AppliedResultView& out) const noexcept;
  const AppliedStats& applied_stats() const noexcept { return applied_stats_; }
  Status cancel(const MessageId& id) noexcept;
  DeliveryResult delivery(const MessageId& id) const noexcept;

  Status poll(MonotonicMs now_ms) noexcept;
  Status on_radio_receive(NodeId peer, ByteView frame, const RadioRxMetadata& metadata,
                          MonotonicMs now_ms) noexcept;
  // M1 telemetry entry point (m1-completion/02-telemetry.md §2.3): same
  // receive path, plus bounded RF observation. The V1 overload forwards with
  // InjectedTest provenance — only the production adapter supplies
  // LocalDriver evidence. Binding-less V1 input never earns a HOP_ACCEPT or
  // an application/component dispatch (issue #117): replies need the RX
  // binding evidence only the V2 entry carries.
  Status on_radio_receive(NodeId peer, ByteView frame,
                          const RadioRxMetadataV2& metadata,
                          MonotonicMs now_ms) noexcept;
  // Completion observation for one submitted TX attempt (02 §2.2/§2.3). The
  // Owner calls this exactly once per submission, including unknown outcomes;
  // callback-absent fencing is the Owner's job — this records what arrived.
  Status note_radio_tx(const RadioTxObservation& observation,
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
  Status note_peer_stale(NodeId peer) noexcept;
  std::uint64_t telemetry_event_drops() const noexcept { return telemetry_event_drops_; }
  // Install/clear the autonomy control sink (Owner wiring, nullptr disables).
  Status set_autonomy_sink(AutonomyFrameSink* sink) noexcept;
  // Install/clear the P6 revocation-gossip sink (Owner wiring, nullptr
  // disables — the PR A state: P6 frames are then honestly rejected).
  Status set_rrs_sink(RrsGossipSink* sink) noexcept {
    if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
    rrs_sink_ = sink;
    return Status::success();
  }
  // Install/clear the Service=21 endpoint (GatewayDelivery wiring, nullptr
  // disables). With no sink, inbound Service frames are still dedup'd/
  // hop-ACKed/forwarded but terminate as SERVICE_NO_ENDPOINT — the origin's
  // retries expire into an honest timeout, never a DATA-style success.
  // Busy while that endpoint's deferred events are still queued or taken.
  Status set_gateway_sink(GatewayServiceSink* sink) noexcept;
  GatewayServiceSink* gateway_sink() const noexcept { return gateway_sink_; }
  // Owner-side relay gate (01-forwarding §policy): runtime config and drain
  // requests write this; effective transit permission additionally requires
  // a live binding context. Reads expose configured vs effective separately.
  // Disabling withdraws our transit advertisements immediately (infinity
  // update on the next maintenance tick is too late — neighbors keep
  // sending us work we will refuse). Accepted in-flight work still drains
  // on its own deadlines.
  Status set_relay_enabled(bool enabled) noexcept;
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
  Status set_telemetry_remote(bool enabled) noexcept;
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
  // Busy while that endpoint's deferred events are still queued or taken.
  Status set_config_sink(ConfigEndpointSink* sink) noexcept;
  ConfigEndpointSink* config_sink() const noexcept { return config_sink_; }
  // Install/clear the end-protected Diagnostic (48) terminal sink — the
  // surface remote TelemetrySnapshot/Reject bodies arrive on (02 §4.2).
  Status set_diagnostic_sink(DiagnosticSink* sink) noexcept;
  // Install/clear the Owner's ExpectedReply lease port. Nullptr means the
  // Owner cannot reserve a protected reply binding — start() refuses without
  // one, and swapping it while transactions are live is Busy.
  Status set_reply_peer_port(ReplyPeerPort* port) noexcept {
    if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
    if (txn_in_flight() != 0) {
      return Status::error(StatusCode::Busy, "transactions live");
    }
    reply_peer_port_ = port;
    return Status::success();
  }
  ReplyPeerPort* reply_peer_port() const noexcept { return reply_peer_port_; }
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
  // Routed bootstrap send (G-SEC P4 §7.4, types 3..6): the join-relay and
  // member end-session lane. Unlike the config lane above, frames are
  // link-protected per hop only — never end-protected — so a relay can
  // forward them while holding no end session. Bounded to
  // kBootstrapJobsMax live jobs and kBootstrapJobsPerPeer per next hop so
  // pre-authentication traffic can never starve DATA/ACK; excess refuses
  // with NoCapacity (the Owner retries on its own handshake deadline).
  Status send_bootstrap(NodeId destination, FrameType type, ByteView payload,
                        std::uint32_t lifetime_ms, MonotonicMs now_ms,
                        MessageId& id) noexcept;
  // Install/clear the bootstrap terminal sink (the Owner's handshake
  // demux; nullptr disables). With no sink, inbound bootstrap frames are
  // still dedup'd/hop-ACKed/forwarded but terminate as
  // BOOTSTRAP_NO_ENDPOINT — the origin's retries expire into a timeout.
  void set_bootstrap_sink(sdkv1::BootstrapSink* sink) noexcept { bootstrap_sink_ = sink; }
  // Adopted local MemberCert role bits (rlcw1 kMemberRole*, P4 §7.4):
  // bootstrap transit additionally requires the Relay or Gateway bit —
  // a bare Endpoint never forwards handshake traffic. 0 (unset) forwards
  // nothing; relay_enabled() still gates all transit.
  void set_local_role(std::uint32_t role) noexcept { local_role_ = role; }
  std::uint32_t local_role() const noexcept { return local_role_; }
  // Free TX-pool slots: the Service endpoint needs this to make the
  // atomic admission reservation (pending + dedup + reply budget) the
  // contract demands before accepting work (03 §3.4).
  std::size_t tx_free_slots() const noexcept { return scheduler_.free_slots(); }
  // Resolve the in-flight driver attempt. Must be called on the node's
  // single owner task — a driver completion callback hands the event over
  // instead of invoking inline (issue #60-3). This resolves only: the next
  // submission is dispatched by poll() after the runtime's whole event
  // drain, so control replies queued by inbound traffic keep the control
  // lane's priority over queued DATA, and this call can never re-enter
  // radio_ from inside a driver callback.
  Status on_radio_tx_result(std::uint64_t token, bool success,
                            MonotonicMs now_ms) noexcept;
  // Owner-side component drive (issue #117, design-q116 §8.3): after a node
  // call returned, the Owner takes up to kComponentEventsMax pending events
  // and hands each to its component as an ordinary outside call, then
  // completes it. Taken events still occupy their slot and their
  // transaction's work reference — taking alone never quiesces. NotFound
  // when the queue is empty (take) or the handle is unknown/already
  // completed (complete); a completed-then-expired payload still completes,
  // the Owner checks deadline_ms before starting new payload work.
  Status take_component_event(ComponentEvent& out) noexcept;
  Status complete_component_event(ComponentEventHandle handle) noexcept;
  std::size_t component_events_pending() const noexcept;
  // Live admission transactions (tests/diagnostics): entries holding a
  // lease use, including Closing ones draining their last work.
  std::size_t txn_in_flight() const noexcept;

  const RouteTable& routes() const noexcept { return routes_; }

  // --- Node status snapshot (node_status.hpp, node_status.cpp) --------------
  // Read-only, allocation-free view assembled from the neighbor, route and
  // telemetry tables. `node_status` answers one node (false when the node is
  // neither a neighbor record nor a remembered route destination, or is this
  // node itself). `node_status_page` fills up to `capacity` records for nodes
  // with id > `after`, strictly ascending — a stable cursor that neither
  // repeats nor skips a node present across pages even while tables churn —
  // and sets `more` when further ids exist. Ages are durations against
  // `now_ms` on the device monotonic clock.
  bool node_status(NodeId node, MonotonicMs now_ms, NodeStatus& out) const noexcept;
  std::size_t node_status_page(NodeId after, NodeStatus* out, std::size_t capacity,
                               MonotonicMs now_ms, bool& more) const noexcept;

  // Gateway-scoped profile (routing-scale.md): true when at least one
  // gateway is configured. scoped_child() reports whether `neighbor`
  // currently routes to a gateway through this node (test/diagnostic view).
  bool gateway_scoped() const noexcept;
  bool scoped_child(NodeId neighbor) const noexcept;
  const RouteScaleStats& route_scale_stats() const noexcept { return route_scale_stats_; }

  // --- Group delivery (group.cpp, docs/design/sdk-v1/group-delivery.md) ------
  // Sends `payload` (<= kGroupPayloadMax) to every member of `group`
  // (kGroupAll = every node) along the gateway tree. Only a configured route
  // gateway of the gateway-scoped profile may source group messages: the
  // flat profile and non-gateway nodes get Unsupported. The message is
  // queued at the source (airtime bucket, one round-0 propagation at a time;
  // Urgent bypasses both) and confirmed by per-subtree reports; incomplete
  // subtrees are re-sent in bounded repair rounds within the lifetime.
  // WouldBlock when the source table holds no free slot (Normal traffic may
  // not take the last one — it is reserved for Urgent).
  Status send_group(GroupId group, ByteView payload, const GroupSendOptions& options,
                    MonotonicMs now_ms, MessageId& id) noexcept;
  // Latest summary of a group message this node sourced (state Empty /
  // reason NOT_FOUND once its record was evicted).
  GroupDeliveryResult group_delivery(const MessageId& id) const noexcept;
  // Replaces the locally configured group set (ALL is implicit and may not be
  // listed; group 0 is reserved; at most kGroupMembershipMax, no duplicates).
  // Non-member nodes still relay and confirm reachability.
  Status set_group_membership(const GroupId* groups, std::size_t count) noexcept;
  bool group_member(GroupId group) const noexcept;
  std::size_t group_membership(GroupId* out, std::size_t capacity) const noexcept;
  const GroupStats& group_stats() const noexcept { return group_stats_; }
  const SessionStats& session_stats() const noexcept { return session_stats_; }
  // Group lane occupancy (tests/diagnostics): relay/receiver trees in use.
  std::size_t group_trees_in_use() const noexcept { return group_trees_.size(); }
  // Ordered messages currently held for a gap (tests/diagnostics).
  std::size_t group_holds_in_use() const noexcept { return group_holds_.size(); }
  // Receive-side stream/hold snapshots (tests/diagnostics), pool order:
  // the per-source dedup/ordering state and the ordered messages held
  // behind a gap, contents included.
  template <typename Fn>
  void for_each_group_stream(Fn fn) const noexcept {
    group_streams_.for_each([&](const GroupStream& stream) {
      fn(GroupStreamSnapshot{stream.source, stream.session, stream.max_seq, stream.seen,
                             stream.next_seq});
    });
  }
  template <typename Fn>
  void for_each_group_hold(Fn fn) const noexcept {
    group_holds_.for_each([&](const GroupHold& hold) {
      fn(GroupHoldSnapshot{hold.info, hold.release_at_ms, hold.size, hold.payload});
    });
  }

  const NodeConfig& config() const noexcept { return config_; }
  NodeId node_id() const noexcept { return config_.node; }
  bool started() const noexcept { return started_; }

  // Sleep support. While draining, send() is rejected and background work
  // (route advertisements, sequence requests, retry rounds) stops; in-flight
  // queue entries still dispatch so the TX path can settle. Equivalent to a
  // pause with pause::kSleepDrainMask; composable with a set_pause mask.
  // Owned by the PowerCoordinator: the application must not call this from a
  // callback to reopen admission behind the coordinator's back.
  Status set_draining(bool draining) noexcept;
  bool draining() const noexcept { return sleep_draining_; }
  // True while an application callback (NodeObserver or an extended sink)
  // runs on this node. The PowerCoordinator rejects mutating operations
  // issued under this flag with Busy.
  bool in_external_callback() const noexcept { return in_external_callback_; }
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
  // in-flight frame, no job waiting for a hop accept and no group round
  // still collecting reports (the source's own tree or a relay/receiver
  // tree). Queued group origins and scheduled repair rounds do NOT hold the
  // drain open: admission and retry rounds are masked while draining, so
  // they can only be settled by the sleep dispositions — a group repair is a
  // retry round (kRetryRounds), the same class as a unicast end-to-end
  // retry, and waiting on it would just burn the whole drain timeout.
  bool quiesced() const noexcept {
    return !physical_.active && scheduler_.empty() && awaiting_hop_.size() == 0 &&
           !group_radio_pending();
  }

  // --- Congestion control (03-congestion.md §4, §5) ----------------------------
  // Live scheduler/BUSY counters for tests, diagnostics and the P3 observer.
  CongestionStats congestion_stats() const noexcept;
  // Dedup capacity surface (sdk-completion/02 §2.4): saturating admission,
  // refusal and eviction counters — every forced reclaim/refusal is visible.
  const DedupStats& dedup_stats() const noexcept { return dedup_stats_; }
  // Live dedup residency (records currently occupying the fixed pool).
  // Read-only test/diagnostic surface for the capacity invariants of
  // sdk-completion/02 §2.5 — always <= kDedupCapacity (profile) by construction.
  std::size_t dedup_resident() const noexcept { return dedup_.size(); }
  // Current per-peer in-flight window (1..4) used by the dispatch gate.
  std::uint8_t peer_tx_window(NodeId peer) const noexcept;
  // Marks a peer as implementing the Busy(20) feedback payload. Until
  // capability negotiation lands, BUSY replies are emitted only to peers
  // marked here or proven by a valid received BUSY (03 §5, scenario D4-09).
  Status set_peer_busy_capable(NodeId peer, bool capable) noexcept;
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
  Status note_peer_pressure(NodeId peer, std::uint8_t pressure,
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
  // back to running with nothing lost. Group origins are never offered: the
  // group lane is RAM-only state (group-delivery.md), settled — not
  // persisted — in phase 2.
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

  // Phase 2 — only after the durable image commit succeeded. Each call
  // settles ONE non-terminal delivery / group origin (pool order) and fires
  // at most one application notification; the coordinator loops these until
  // none remain. Callbacks from the notifications cannot re-enter the
  // coordinator, so the settlement always runs to completion. A delivery
  // that was eligible but not saved fails explicitly — durable work is
  // never dropped silently. Origins end in an explicit terminal state the
  // application sees through on_group_delivery (Save cannot apply — groups
  // are never persisted — so it fails honestly). `claim_saved` moves
  // durable ownership of a saved id to the coordinator and runs BEFORE the
  // SLEEP_SAVED notification; false settles the item under the fallback
  // instead. Ordered holds are released one message per call by
  // release_one_group_hold_for_sleep().
  template <typename ClaimSavedFn>
  bool settle_one_sleep_delivery(SleepWorkPolicy fallback,
                                 ClaimSavedFn&& claim_saved) noexcept {
    Delivery* target = deliveries_.find(
        [](const Delivery& delivery) { return !sleep_terminal(delivery.state); });
    if (target == nullptr) return false;
    const bool durable = target->options.persist_across_sleep;
    const bool eligible = durable || fallback == SleepWorkPolicy::Save;
    if (eligible && claim_saved(target->id)) {
      set_delivery_state(*target, DeliveryState::Indeterminate, "SLEEP_SAVED");
    } else if (fallback == SleepWorkPolicy::Defer && !durable) {
      set_delivery_state(*target, DeliveryState::Indeterminate, "SLEEP_DEFERRED");
    } else {
      set_delivery_state(*target, DeliveryState::Failed,
                         eligible ? "SLEEP_PERSIST_FULL" : "SLEEP_DRAIN");
    }
    return true;
  }
  bool settle_one_sleep_group_origin(SleepWorkPolicy fallback) noexcept;
  // Releases ONE ordered hold to the application: the lowest (group_seq,
  // source) hold across streams, with the stream cursor advanced to it and
  // the skipped gap counted under the usual rules. Exactly one
  // on_group_message fires per Released call; the trailing group_drain()
  // that group_skip_to runs is deliberately NOT run, so each call hands
  // over exactly one message. A hold whose (source, session) stream is
  // gone is kept and reported as StreamInvariant — the sleep attempt must
  // abort, never drop payload silently.
  SleepHoldRelease release_one_group_hold_for_sleep() noexcept;

  // Re-injects a persisted delivery under its ORIGINAL logical message id so
  // the destination's terminal dedup still suppresses a payload it already
  // delivered when the end receipt was lost in sleep. Only the power
  // coordinator calls this; ordinary send() always allocates a fresh id.
  // Rejected when the id is already live or collides with argument checks.
  Status resume_delivery(const MessageId& id, NodeId destination, ByteView payload,
                         const SendOptions& options, MonotonicMs now_ms) noexcept;

  // Sleep teardown, called once per attempt after the dispositions. The
  // notice reports a frame still with the driver (metadata copied out —
  // the diagnostic must not borrow the live job the teardown destroys);
  // the teardown then drops all queued/in-flight radio work. A frame
  // already handed to the driver is reported unknown, never as sent.
  // Admission transactions terminate first so no lease use survives into
  // the image and no taken component event dangles past teardown.
  Status quiesce_for_sleep() noexcept {
    if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
    NodeGuard guard(in_call_);
    if (physical_.active) {
      const NodeId peer = physical_.job.peer;
      const MessageId message = physical_.job.ack.key.id;
      observer_.on_diagnostic("SLEEP_TX_INFLIGHT", peer, &message);
    }
    terminate_all_txn_work();
    component_jobs_outstanding_ = 0;
    physical_ = PhysicalInflight{};
    scheduler_.clear();
    awaiting_hop_.clear();
    return Status::success();
  }

 private:
  // Marks one MeshNode as "inside an application callback". Every
  // NodeObserver notification runs inside one (via ObserverForwarder), and so
  // does every extended-sink call, so the PowerCoordinator can Busy-reject
  // operations issued from application code. Nesting saves/restores.
  struct ExternalCallbackScope {
    explicit ExternalCallbackScope(bool& flag) noexcept
        : flag_(flag), saved_(flag) {
      flag_ = true;
    }
    ~ExternalCallbackScope() noexcept { flag_ = saved_; }
    ExternalCallbackScope(const ExternalCallbackScope&) = delete;
    ExternalCallbackScope& operator=(const ExternalCallbackScope&) = delete;

   private:
    bool& flag_;
    bool saved_;
  };

  // Forwards the six NodeObserver methods to the application observer with an
  // ExternalCallbackScope held, so the node reports in_external_callback()
  // without instrumenting every notification site. The default
  // on_group_message -> on_message forward stays inside the scope because it
  // runs within the application's virtual call.
  class ObserverForwarder {
   public:
    ObserverForwarder(NodeObserver& app, bool& flag) noexcept
        : app_(app), flag_(flag) {}
    void on_message(const MessageKey& key, NodeId source,
                    ByteView payload) noexcept {
      ExternalCallbackScope scope(flag_);
      app_.on_message(key, source, payload);
    }
    void on_delivery(const DeliveryResult& result) noexcept {
      ExternalCallbackScope scope(flag_);
      app_.on_delivery(result);
    }
    void on_diagnostic(const char* reason, NodeId peer,
                       const MessageId* message) noexcept {
      ExternalCallbackScope scope(flag_);
      app_.on_diagnostic(reason, peer, message);
    }
    void on_applied_result(const MessageKey& key,
                           const AppliedResultView& result) noexcept {
      ExternalCallbackScope scope(flag_);
      app_.on_applied_result(key, result);
    }
    void on_group_message(const GroupMessageInfo& info,
                          ByteView payload) noexcept {
      ExternalCallbackScope scope(flag_);
      app_.on_group_message(info, payload);
    }
    void on_group_delivery(const GroupDeliveryResult& result) noexcept {
      ExternalCallbackScope scope(flag_);
      app_.on_group_delivery(result);
    }

   private:
    NodeObserver& app_;
    bool& flag_;
  };

  static constexpr std::size_t kNeighborCapacity = 32;
  static constexpr std::size_t kDeliveryCapacity = 8;
  static constexpr std::size_t kTxQueueCapacity = 32;
  static constexpr std::size_t kAwaitingHopCapacity = 8;
  // Routed bootstrap lane (G-SEC P4 §7.4): at most 8 live origin jobs, 2
  // per next hop — handshake traffic keeps a bounded slice of the pool
  // and can never crowd out the DATA/ACK reservation.
  static constexpr std::size_t kBootstrapJobsMax = 8;
  static constexpr std::size_t kBootstrapJobsPerPeer = 2;
  static constexpr std::size_t kSeqnoSeenCapacity = 32;
  static constexpr std::size_t kSeqnoStateCapacity = 32;
  static constexpr std::uint32_t kNoFeedbackSeq = 0xFFFFFFFFu;

  // Members are grouped 8-byte first, then 4/2/1-byte (ram-budget.md): the
  // fields of one mechanism are split across the groups, so each keeps its
  // comment where it is declared. 160 B instead of 192 B (LP64 and RISC-V/Xtensa).
  struct Neighbor {
    // --- 8-byte members ---
    NodeId node{kInvalidNodeId};
    // Granted-capability state from a nonce-bound CapabilitiesReply: the
    // grant expires at cap_valid_until_ms under the peer's boot identity —
    // a reply can never install a permanent capability (04 §capabilities).
    MonotonicMs cap_valid_until_ms{0};
    std::uint64_t cap_node_boot{0};
    // Renewal pacing: last completed/granted capability exchange; a new
    // query inside kCapQueryRenewalMs is refused.
    MonotonicMs last_cap_exchange_ms{0};
    // Window anchor of exchange_work/exchange_accepts (below).
    MonotonicMs exchange_window_ms{0};
    // Sample/window anchors of queue_sojourn_ewma_ms (below).
    MonotonicMs last_sojourn_ms{0};
    MonotonicMs sojourn_window_ms{0};
    // Asymmetric slew state (§3.4): last time link_cost relaxed toward the
    // honest target; improvement steps are spaced one per observation window.
    MonotonicMs last_cost_relax_ms{0};
    // Sustained authenticated-busy feedback (03 §7 severe-busy): see
    // busy_active below.
    MonotonicMs busy_since_ms{0};
    MonotonicMs last_busy_feedback_ms{0};
    // Gateway-scoped profile (routing-scale.md §3). child_until_ms: the peer
    // routes to a gateway through us (it poisoned our gateway record) — it
    // gets the periodic downward refresh and its routes travel upward.
    // interest_until_ms: the peer pulled a route or asked for a sequence —
    // triggered changes are pushed to it. A pending pull answer is emitted
    // from poll() after the selection-change scan.
    MonotonicMs child_until_ms{0};
    MonotonicMs interest_until_ms{0};
    MonotonicMs last_pull_answer_ms{0};
    NodeId pull_target{kInvalidNodeId};
    // --- 4-byte members ---
    RouteGeneration generation{0};  // last origin generation the peer self-advertised
    // Highest feedback sequence accepted from this peer; stale/replayed
    // BUSY payloads are detected against it (FeedbackSequence ordering tag).
    // feedback_seen is separate so a first seq equal to the sentinel value
    // cannot disable ordering checks forever.
    std::uint32_t last_feedback_seq{kNoFeedbackSeq};
    // Per-peer exchange measurement (03 §6.1): decaying-window counters of
    // eligible attempt work (every physical submission of a hop-accept
    // exchange — failures included) and authenticated accepts. Below
    // kExchangeMinAccepts the measured ratio is unused and cost stays
    // nominal.
    std::uint32_t exchange_work{0};
    std::uint32_t exchange_accepts{0};
    // Per-peer egress queue sojourn EWMA (03 §6.2): only OUR delay toward
    // this peer may penalize the link cost. Stale samples read as 0. The
    // EWMA halves once per observation window anchored at sojourn_window_ms
    // (§3.4): sparse fresh samples cannot keep re-exposing an inflated
    // average — after a burst the penalty converges within a few windows.
    std::uint32_t queue_sojourn_ewma_ms{0};
    std::uint32_t sojourn_samples{0};
    // Per-peer HOP_ACCEPT round-trip EWMA (radio.md §8 adaptive RTO), in ms:
    // MAC-accept -> authenticated accept arrival, measured on live
    // exchanges only — a BUSY deferral's wait is peer-directed, never a
    // link measurement. hop_rtt_samples == 0 means "unmeasured": the
    // configured initial timeout applies.
    std::uint32_t hop_rtt_ewma_ms{0};
    std::uint32_t hop_rtt_samples{0};
    // --- 2-byte members ---
    RouteMetric metric{1};      // nominal link cost (add_neighbor input)
    RouteMetric link_cost{1};   // effective cost fed to RouteTable (03 §6)
    // --- 1-byte members ---
    std::uint8_t consecutive_failures{0};
    std::uint8_t route_cursor{0};  // rotation cursor for periodic route dumps
    // Congestion state (03-congestion.md §5): per-peer in-flight window and
    // the consecutive-authenticated-accept streak that grows it. A window is
    // NOT a memory-slot counter — freeing an awaiting slot never grows it.
    std::uint8_t tx_window{kPeerWindowInitial};
    std::uint8_t window_accepts{0};
    bool busy_capable{false};  // peer proved/configured for Busy(20) feedback
    bool feedback_seen{false};
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
    // Sustained authenticated-busy feedback (03 §7 severe-busy): set while
    // matched BUSY deferrals or pressure hints keep arriving; cleared by an
    // authenticated accept or when feedback goes stale past its TTL. It is
    // a hint for the switch discipline, never a metric input. `busy_active`
    // is the state — busy_since_ms==0 is a legitimate timestamp (t=0), not
    // a "clear" sentinel.
    bool busy_active{false};
    std::uint8_t last_pressure{0};
    bool pull_answer_pending{false};
    bool active{false};
  };

  struct SeqnoSeen {
    NodeId requester{kInvalidNodeId};
    NodeId destination{kInvalidNodeId};
    std::uint32_t request_id{0};
    MonotonicMs expires_at_ms{0};
  };

  // Per-destination request state. Survives dedup (seqno_seen_) expiry so the
  // backoff/cooldown still applies after the seen-record is gone. attempts
  // saturates (never wraps) — post-cap probes ride the max cooldown (issue
  // #50). probe_cursor is the independent next-hop rotation cursor: it wraps
  // freely so post-cap requests keep walking every candidate instead of
  // pinning hops[saturated_attempts % count].
  struct SeqnoState {
    NodeId destination{kInvalidNodeId};
    MonotonicMs next_request_ms{0};
    MonotonicMs last_sent_ms{0};
    MonotonicMs expires_at_ms{0};
    RouteSequence requested_sequence{0};
    std::uint8_t attempts{0};
    std::uint8_t probe_cursor{0};
  };

  // Laid out 8-byte members first, then the 4/1-byte tail (ram-budget.md):
  // 136 B instead of 152 B on the RISC-V/Xtensa firmware ABIs.
  struct DedupEntry {
    MessageKey key{};
    // Admission timestamp: the base of the kDedupHardCapMs retention cap —
    // refreshes on re-receipt can never push a record past it (02 §2.6).
    MonotonicMs first_seen_ms{0};
    MonotonicMs expires_at_ms{0};
    // Transit correlation (01 §failure evidence): retained ONLY for accepted
    // transit work — the upstream neighbor that handed us the frame and the
    // fingerprint of its end-protected bytes, so a post-acceptance failure
    // can be reported back without ever claiming end-verification.
    NodeId upstream_peer{kInvalidNodeId};
    // The downstream neighbor this transit was forwarded to and the frame's
    // destination — a TransitFailure report is only valid when it arrives
    // from THIS peer about THIS destination (01 §failure evidence).
    NodeId downstream_peer{kInvalidNodeId};
    NodeId ref_destination{kInvalidNodeId};
    // A transit record that already emitted a TransitFailure: a re-received
    // duplicate re-emits the retained evidence instead of blindly re-ACKing
    // a dead job (01 §same-key-after-failure). The retained replay carries
    // the ORIGINAL claimed reporter/report_id verbatim — a relay may never
    // re-originate evidence under its own identity.
    NodeId reported_reporter{kInvalidNodeId};
    // Replay bounding: a duplicate storm cannot turn one retained failure
    // into unbounded re-emissions (cap + minimum spacing).
    MonotonicMs last_replay_ms{0};
    std::array<std::uint8_t, 32> fingerprint{};
    // The downstream's binding generation captured when the forward was
    // physically submitted — a report is only valid against the attempt we
    // actually made (dispatch may retarget the route after admission).
    BindingGeneration downstream_binding{0};
    std::uint32_t reported_id{0};
    FrameType type{FrameType::Data};
    std::uint8_t round{0};
    // Capacity class (sdk-completion/02 §2.3): drives retention slack and
    // eviction rank — Live/Terminal are never eviction victims.
    DedupPhase phase{DedupPhase::Live};
    bool delivered{false};
    bool forwarded{false};
    bool has_fingerprint{false};
    bool failure_reported{false};
    std::uint8_t reported_phase{0};
    std::uint8_t reported_reason{0};
    std::uint8_t failure_replays{0};
  };
  // sdk-completion/02 §2.4 budget: 152 B measured on host after the phase +
  // first_seen_ms addition (144 B before); the member order above packs it
  // to 136 B on LP64 and on RISC-V/Xtensa (which align u64 to 8). A larger
  // entry shrinks real capacity silently, so growth is a deliberate,
  // documented change.
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
    // Per-source ordering (SendOptions::ordered, group-delivery.md §6): the
    // delivery is held until its predecessor to the same destination is
    // Delivered or `order_hold_until_ms` (the predecessor's own deadline)
    // passed — whichever comes first.
    MessageId order_after{};
    MonotonicMs order_hold_until_ms{0};
    bool order_wait{false};
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
                                       Applied, Group, Bootstrap };

  // Records below are laid out largest-alignment first: MeshNode is a static
  // object in firmware and every byte of padding is .bss on the DRAM-bound
  // ESP32-C3 images (docs/design/sdk-v1/ram-budget.md).
  struct AckKey {
    AckKey() noexcept = default;
    AckKey(const FrameType type, const MessageKey& message,
           const std::uint8_t ack_round) noexcept
        : key(message), accepted_type(type), round(ack_round) {}
    MessageKey key{};
    FrameType accepted_type{FrameType::Data};
    std::uint8_t round{0};
  };

  struct TxJob {
    // The frame a job carries: EITHER a locally built plain frame (sealed at
    // encode) OR a link-opened frame being forwarded — never both — so the
    // two share storage (ram-budget.md §3). `form` names the active member
    // and every reader dispatches on it; set_forwarded() is the only way a
    // fresh (plain) job becomes a forwarded one. Both frames begin with the
    // same wire::Header (a common initial sequence).
    union {
      wire::PlainFrame plain{};
      wire::LinkOpenedFrame forwarded;
    };
    NodeId peer{kInvalidNodeId};
    AckKey ack{};
    MonotonicMs deadline_ms{0};
    // Earliest select eligibility (radio.md §8 link-retry jitter): 0 on a
    // first transmission — retries stamp now+jitter so re-queued jobs yield
    // the scheduler until the decorrelation delay elapses.
    MonotonicMs not_before_ms{0};
    MonotonicMs enqueued_at_ms{0};             // queue-sojourn measurement base
    // Observation identity stamped at physical submission (02 §2.3): the
    // runtime-frozen binding/radio/channel tuple — submission, hop-accept
    // and completion accounting share ONE key so counters can never split
    // across a rebind or channel boundary mid-attempt.
    ObservationKey obs_key{};
    TxJob* flow_next{nullptr};                 // intrusive per-flow list link
    // Scheduler metadata — assigned at admission, preserved across requeues.
    std::uint32_t tx_cost{0};                  // estimated on-air bytes
    // Identity of this job's sealed frame in MeshNode::tx_encoded_ (0 = not
    // encoded). The node keeps ONE encode buffer instead of one per job: a
    // job's sealed frame is reused only while that buffer still holds it
    // (the driver refused the frame and the job is selected again before
    // any other job is sealed); otherwise the job is sealed afresh, with a
    // fresh link counter, exactly like a retry.
    std::uint32_t encoded_tag{0};
    JobForm form{JobForm::Plain};
    JobOwner owner{JobOwner::None};
    bool requires_hop_accept{false};
    // RF-loss retry counter (03 §5 rf_attempts_max, per-job, never reset by
    // peer/rate changes) and the bound for it.
    std::uint8_t attempts{0};
    std::uint8_t max_attempts{1};
    Priority priority{Priority::Normal};       // origin DATA class input
    // Attempt budget accounting (contracts.json congestion.*).
    std::uint8_t busy_readmissions{0};
    std::uint8_t physical_attempts{0};
    // window_limited is counted once per job per block episode — the DRR
    // select loop may revisit the same blocked flow up to kMaxSelectRounds
    // times in one pass.
    bool window_block_counted{false};
    bool obs_key_set{false};
    // Held for a provider-owned session (sdk-v1/03 §9): the deferral was
    // counted and diagnosed once; cleared when the job encodes.
    bool session_deferred{false};
    // Owning admission transaction (issue #117): invalid for origin work.
    // The transaction's deadline bounds local dispatch/retry/expiry; the
    // wire budget still derives from deadline_ms. Exactly one terminal site
    // (complete/fail/drop/quiesce) finishes each transaction job's work.
    TxnHandle txn{kInvalidTxnHandle};
    // Submitted binding for ACK-awaiting TX (design-q116 §6.2): frozen from
    // the Owner at dispatch, matched against the authenticated RX binding
    // before a HOP_ACCEPT/BUSY may resolve the exchange — a rebind between
    // submit and accept must not misattribute the accept. The peer is
    // job.peer; only the mapping identity is pinned here.
    BindingId submitted_binding{kInvalidBindingId};
    BindingGeneration submitted_generation{};
    std::uint32_t submitted_rx_context{0};
    bool submitted_binding_set{false};

    void set_forwarded(const wire::LinkOpenedFrame& frame) noexcept {
      form = JobForm::Forwarded;
      // Begins the forwarded member's lifetime; both members are trivially
      // destructible, so the plain member needs no teardown.
      ::new (static_cast<void*>(&forwarded)) wire::LinkOpenedFrame(frame);
    }
  };
  static_assert(std::is_trivially_copyable_v<wire::PlainFrame> &&
                    std::is_trivially_copyable_v<wire::LinkOpenedFrame>,
                "TxJob copies its frame union bytewise");

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
    // Remove the first queued job matching `pred` into `out` (issue #117:
    // transaction close and sleep quiesce terminate unstarted work instead
    // of abandoning its lease reference). The job being dispatched is never
    // a candidate. Drained flows stay ring-linked; select() already treats
    // an empty ring flow as releasable. False when nothing matched.
    template <typename Pred>
    bool drop_one_if(Pred&& pred, TxJob& out) noexcept {
      TxJob* victim = nullptr;
      pool_.for_each([&](TxJob& job) {
        if (victim == nullptr && &job != selected_ && pred(job)) victim = &job;
      });
      if (victim == nullptr) {
        out = TxJob{};
        return false;
      }
      unlink(victim);
      out = std::move(*victim);
      pool_.release(victim);
      --used_;
      return true;
    }
    void clear() noexcept;

    // §14 airtime domain of a scheduled job: the reserved control lane is
    // the accepted work's own ACK budget, management class is the gated
    // control domain, everything else is scheduled work.
    static AirtimeDomain airtime_domain(const TxJob& job) noexcept;

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
    // Live jobs of one owner class toward one next-hop peer — the
    // bootstrap lane's per-peer cap is computed, never bookkept, so no
    // completion path can leak it.
    std::size_t count_owner_peer(JobOwner owner, NodeId peer) const noexcept {
      std::size_t n = 0;
      pool_.for_each([&](const TxJob& job) {
        if (job.owner == owner && job.peer == peer) ++n;
      });
      return n;
    }
    static constexpr std::size_t capacity() noexcept { return kTxQueueCapacity; }
    std::size_t free_slots() const noexcept { return capacity() - used_; }
    std::size_t control_depth() const noexcept { return control_.count; }
    bool control_slot_available() const noexcept {
      return control_.count < kControlLaneCapacity;
    }
    bool origin_slot_available(NodeId origin) const noexcept {
      return origin_count(origin) < kMaxJobsPerOrigin;
    }
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
    // Unlink one queued job from its lane (drop_one_if helper): the job is
    // known queued, so exactly one list holds it.
    void unlink(TxJob* job) noexcept;
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
    // Pool slots non-control admission may never take (03 §4/§5): at
    // saturation the node must still be able to answer the frame it
    // refuses with a BUSY. Without this reserve the refusal that most needs
    // backpressure finds no slot and degrades to a silent drop.
    static constexpr std::size_t kControlReserveSlots = 1;
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
    // MAC-accept time of this exchange — the RTT base for the adaptive RTO.
    MonotonicMs sent_at_ms{0};
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
  // Per-upstream bound reached (#39): free one of `upstream`'s OWN non-terminal
  // records in the same phase order (expired -> Resolved -> Evidence). Live
  // records are never victims; false = every record it holds is Live.
  bool evict_dedup_for_upstream(NodeId upstream, MonotonicMs now_ms) noexcept;
  // Release a Resolved/Evidence victim with its counter + diagnostic.
  void release_dedup_victim(DedupEntry& victim) noexcept;
  // Terminal pins currently resident (the reserve gate's operand).
  std::size_t count_terminal_pins() const noexcept;
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
  // Admission work items (issue #117): each carries its transaction handle
  // and joins the transaction's work references on success. Every queue_*
  // below runs only after the admission probes proved it infallible.
  Status queue_forward(const wire::LinkOpenedFrame& frame, NodeId next_hop,
                       TxnHandle txn, MonotonicMs now_ms) noexcept;
  Status queue_hop_accept(const wire::Header& accepted, TxnHandle txn,
                          MonotonicMs now_ms) noexcept;
  Status queue_end_receipt(const wire::Header& data, TxnHandle txn,
                           MonotonicMs now_ms) noexcept;
  // BUSY emission (03 §5): pre-admission refusal for a NEW authenticated
  // inbound DATA — never for already HOP_ACCEPT-ed work. Emits only when the
  // peer is busy-capable and a reply slot is affordable; otherwise drops and
  // counts busy_send_failed so the sender's timeout path stays honest.
  Status queue_busy(NodeId peer, const wire::Header& rejected,
                    std::uint8_t reason, TxnHandle txn,
                    MonotonicMs now_ms) noexcept;
  void emit_busy_or_drop(NodeId peer, const wire::Header& rejected,
                         std::uint8_t reason, const RxBinding& rx,
                         MonotonicMs now_ms) noexcept;
  TxJob link_control_job(FrameType type, NodeId neighbor, std::uint32_t lifetime_ms,
                         MonotonicMs now_ms) noexcept;
  Status queue_route_update(NodeId neighbor, MonotonicMs now_ms) noexcept;
  Status queue_seqno_request(NodeId peer, NodeId requester, NodeId destination,
                             RouteSequence requested_sequence, std::uint32_t request_id,
                             std::uint8_t ttl, MonotonicMs now_ms) noexcept;
  // Shared enqueue for send_service/resend_service/send_typed/
  // send_bootstrap: a Plain routed job of `type` owned by `owner`,
  // hop-accept required. `end_protected` is false only for the bootstrap
  // lane (link-only per-hop protection, P4 §7.4).
  Status queue_typed_job(FrameType type, JobOwner owner, const MessageId& id,
                         NodeId destination, ByteView payload, std::uint8_t round,
                         std::uint32_t lifetime_ms, Priority priority,
                         MonotonicMs now_ms, bool end_protected = true) noexcept;
  // Unguarded send_service body shared by the guarded public overloads —
  // internal paths never call the guarded entries.
  Status send_service_impl(NodeId destination, ByteView payload,
                           std::uint32_t lifetime_ms, Priority priority,
                           MonotonicMs now_ms, MessageId& id) noexcept;

  Status encode_job(TxJob& job, MonotonicMs now_ms) noexcept;
  // True when an AuthRequired encode refusal is a missing/pending session
  // (context_state None/Establishing): the job waits, deadline-bounded.
  bool defer_for_session(TxJob& job) noexcept;
  void note_rx_refusal(const Status& status, NodeId peer,
                       const MessageId* message) noexcept;
  void dispatch_next(MonotonicMs now_ms) noexcept;
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
  // Adaptive per-peer hop-accept timeout (radio.md §8): the configured
  // initial value while the peer is unmeasured, then EWMA*kLinkRtoMargin
  // inside [kLinkRtoMinMs, kLinkRtoMaxMs].
  std::uint32_t effective_hop_timeout_ms(NodeId peer) const noexcept;
  // Deterministic retransmission eligibility time (radio.md §8 jitter):
  // node id decorrelates peers, a counter decorrelates successive retries;
  // never lands past the job's own deadline.
  MonotonicMs link_retry_not_before_ms(const TxJob& job,
                                       MonotonicMs now_ms) noexcept;

  // --- ExpectedReply admission machinery (issue #117) ----------------------
  struct NodeGuard {
    explicit NodeGuard(bool& flag) noexcept : flag_(flag) { flag_ = true; }
    ~NodeGuard() noexcept { flag_ = false; }
    NodeGuard(const NodeGuard&) = delete;
    NodeGuard& operator=(const NodeGuard&) = delete;
    bool& flag_;
  };

  // One admission transaction: a lease use plus the work references of the
  // jobs/events the admission created. Committed at admission; Closing once
  // expired or revoked, draining until the last work finishes.
  enum class TxnState : std::uint8_t { Free, Committed, Closing };
  struct TxnSlot {
    ReplyLeaseToken use{kInvalidReplyLeaseToken};
    MonotonicMs deadline_ms{0};
    std::uint8_t work_refs{0};
    TxnState state{TxnState::Free};
    std::uint32_t serial{0};  // last issued; 0 = never issued
    bool retired{false};      // serial exhausted: never reused in this boot
  };

  // Deferred component delivery slot: Queued waits for the Owner's take,
  // Taken waits for its complete. Both hold the transaction reference.
  enum class EventState : std::uint8_t { Free, Queued, Taken };
  struct EventSlot {
    ComponentEvent event{};
    EventState state{EventState::Free};
    std::uint32_t serial{0};  // last issued; 0 = never issued
    bool retired{false};
  };

  // All-or-nothing admission reservation (design-q116 §8.1): probes first
  // (scheduler, dedup class, transaction, lease, ACK lane, applied,
  // component event), then lease + transaction + records, then the proved
  // infallible enqueues, then commit publishes dedup links, events and the
  // application dispatch. The destructor rolls an uncommitted reservation
  // back in reverse order; committed work terminates through finish_work.
  struct AdmissionReservation {
    MeshNode* node{nullptr};
    TxnHandle txn{kInvalidTxnHandle};
    ReplyLeaseToken use{kInvalidReplyLeaseToken};
    DedupEntry* dedup{nullptr};
    AppliedRecord* applied{nullptr};
    bool applied_new{false};
    bool committed{false};
    ~AdmissionReservation() noexcept;
    void rollback() noexcept;
    AdmissionReservation() noexcept = default;
    AdmissionReservation(const AdmissionReservation&) = delete;
    AdmissionReservation& operator=(const AdmissionReservation&) = delete;
  };

  // Capture the receive's reply identity from RX metadata + the
  // link-authenticated header. Invalid without a port, a binding, or an
  // epoch — such input earns no reply and no dispatch.
  RxBinding capture_rx_binding(NodeId peer,
                               const RadioRxMetadataV2* metadata,
                               std::uint32_t link_epoch) const noexcept;
  // Admission transaction deadline: min(frame budget, now + 1500 ms).
  // Refuses (Ok == false) when the frame budget is already spent or the
  // 1500 ms horizon is unrepresentable.
  bool txn_deadline_for(std::uint32_t remaining_deadline_ms,
                        MonotonicMs now_ms, MonotonicMs& out) const noexcept;
  bool txn_slot_available() const noexcept;
  Status begin_txn(ReplyLeaseToken use, MonotonicMs deadline_ms,
                   TxnHandle& out) noexcept;
  // Finish one work item of a transaction; the last finish releases the
  // lease use and recycles the slot. Stale handles are a silent no-op.
  void finish_txn_work(TxnHandle handle) noexcept;
  // Join a successfully queued job to its transaction's work references.
  // Stale handles are a silent no-op.
  void join_txn(TxnHandle handle) noexcept;
  const TxnSlot* resolve_txn(TxnHandle handle) const noexcept;
  // Effective local deadline of a job: min(job deadline, transaction
  // deadline). Dispatch/retry/expiry use this; encode keeps the job's own
  // deadline for the wire budget.
  MonotonicMs work_deadline(const TxJob& job) const noexcept;
  // True when an applied record could be allocated now (free slot, expired
  // reclaimable, or an ACKed record) — the probe before the mutating call.
  bool applied_slot_available(MonotonicMs now_ms) noexcept;
  bool component_event_available() const noexcept;
  // Payload probe: room for one more event beyond the completions already
  // held by outstanding component-origin jobs.
  bool component_payload_event_available() const noexcept;
  bool component_target_pending(ComponentEventTarget target) const noexcept;
  // Publish a payload/completion event for the Owner's outside drive; joins
  // the transaction's work references. Runs only after the availability
  // probe proved it infallible.
  void publish_component_event(ComponentEventTarget target, NodeId peer,
                               TxnHandle txn, MonotonicMs deadline_ms,
                               const wire::PlainFrame* frame,
                               const MessageId* job_id, bool job_accepted,
                               const char* job_reason) noexcept;
  // Poll-order transaction close (design-q116 §7.2): expired/revoked entries
  // go Closing, unstarted jobs and untaken events terminate, zero-reference
  // entries release their lease use. A regressed clock suspends the sweep.
  void sweep_transactions(MonotonicMs now_ms) noexcept;
  // Sleep quiesce: silently finish every transaction work item and release
  // every use — accepted radio work never survives into the image.
  void terminate_all_txn_work() noexcept;
  // Standalone short reply (BUSY/refusal/re-ACK/receipt/diagnostic/app):
  // one transaction + one lease use on the peer's snapshot binding plus the
  // scheduler slot the emission needs. Best-effort: failure counts at the
  // call site and sends nothing.
  Status reserve_short_reply(NodeId peer, bool needs_control_slot,
                             std::size_t pool_slots, MonotonicMs now_ms,
                             AdmissionReservation& out) noexcept;
  // Same, on RX evidence instead of a fresh snapshot: the lease is acquired
  // on the receive's captured binding. Refuses without valid evidence.
  Status reserve_rx_reply(const RxBinding& rx, bool needs_control_slot,
                          std::size_t pool_slots, MonotonicMs now_ms,
                          AdmissionReservation& out) noexcept;
  // Refuse admission for binding-less input: no HOP_ACCEPT, no dispatch —
  // the unsent reply is counted where BUSY drops land.
  void refuse_without_binding(NodeId peer, const wire::Header& header,
                              const char* reason, MonotonicMs now_ms) noexcept;

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
                         const RxBinding& rx, MonotonicMs now_ms) noexcept;
  void handle_data(const wire::LinkOpenedFrame& frame, NodeId peer,
                   const RxBinding& rx, MonotonicMs now_ms) noexcept;
  // End-protected routed traffic (Service 21, Control 22 and the
  // ConfigPermit object types 49/50/51): transit forwards untouched (dedup
  // + forward + hop ACK keyed on the frame's own type), terminal hands the
  // end-verified payload to the matching sink (Service -> gateway sink,
  // the config types -> config sink). Never enters the DATA path and never
  // emits END_RECEIPT. The link-scoped autonomy forms of 49/50/51 keep
  // their separate destination==self path and never reach here.
  void handle_routed(const wire::LinkOpenedFrame& frame, NodeId peer,
                     const RxBinding& rx, MonotonicMs now_ms) noexcept;
  // Routed bootstrap terminal/transit (G-SEC P4 §7.4, types 3..6): the
  // link-only sibling of handle_routed. Terminal frames deliver the
  // link-opened payload to the bootstrap sink with the previous hop's
  // authentication fact kept separate from the unverified origin claim;
  // transit additionally requires a Relay/Gateway local role. Never
  // enters the DATA path and never emits END_RECEIPT.
  void handle_bootstrap(const wire::LinkOpenedFrame& frame, NodeId peer,
                        const RxBinding& rx, MonotonicMs now_ms) noexcept;
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
                              const RxBinding& rx,
                              MonotonicMs now_ms) noexcept;
  // Emit one bounded link-only TransitFailure toward `upstream` (hop-1,
  // BestEffort, never hop-ACKed — a report must not spawn reports). The
  // caller holds the short reply reservation; Ok joins the transaction.
  Status emit_transit_failure(NodeId upstream, const TransitFailure& report,
                              TxnHandle txn, MonotonicMs now_ms) noexcept;
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
                            TransitFailureReason reason, const RxBinding& rx,
                            MonotonicMs now_ms) noexcept;
  void handle_transit_failure_report(NodeId peer,
                                     const TransitFailure& report,
                                     MonotonicMs now_ms) noexcept;
  void replay_retained_failure(DedupEntry& duplicate, FrameType type,
                               const RxBinding& rx,
                               MonotonicMs now_ms) noexcept;
  Status queue_diagnostic_reply(NodeId destination, ByteView body,
                                std::uint32_t lifetime_ms,
                                MonotonicMs now_ms) noexcept;
  // Unguarded snapshot body for the internal diagnostic handler, which
  // already runs under the node's call guard.
  Status build_telemetry_snapshot_impl(const TelemetryQuery& query,
                                       MonotonicMs now_ms,
                                       TelemetrySnapshot& out,
                                       DiagnosticRejectReason& reason) noexcept;
  void handle_busy(const wire::LinkOpenedFrame& frame, NodeId peer,
                   const RxBinding& rx, MonotonicMs now_ms) noexcept;
  void handle_end_receipt(const wire::LinkOpenedFrame& frame, NodeId peer,
                          const RxBinding& rx, MonotonicMs now_ms) noexcept;
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
  void arm_triggered_advertisement(MonotonicMs now_ms) noexcept;
  void run_triggered_advertisement(MonotonicMs now_ms) noexcept;
  // Scans selection changes (triggered-update source). Called from poll()
  // and before any receive-path emission that could sync the advertised
  // snapshot (mark_advertised) ahead of the scan.
  void scan_selection_changes(MonotonicMs now_ms) noexcept;

  // --- Gateway-scoped routing profile (route_scale.cpp, routing-scale.md) ---
  struct UpwardCycle {
    NodeId parent{kInvalidNodeId};
    std::size_t cursor{0};  // eligible records already sent this cycle
    bool active{false};
  };
  struct DiscoveryState {
    NodeId target{kInvalidNodeId};
    MonotonicMs next_request_ms{0};
    MonotonicMs expires_at_ms{0};
    std::uint8_t attempts{0};
  };
  struct RouteRequestSeen {
    NodeId requester{kInvalidNodeId};
    std::uint32_t request_id{0};
    std::uint8_t kind{0};
    NodeId previous_hop{kInvalidNodeId};  // reverse-path pointer (Discover)
    MonotonicMs expires_at_ms{0};
  };
  static constexpr std::size_t kScopedDirtyCapacity = 16;
  static constexpr std::size_t kDiscoveryCapacity = 4;
  static constexpr std::size_t kRouteRequestSeenCapacity = 32;

  bool is_route_gateway(NodeId destination) const noexcept;
  bool neighbor_is_child(NodeId neighbor, MonotonicMs now_ms) const noexcept;
  NodeId scoped_uplink(NodeId exclude) const noexcept;
  std::uint32_t scoped_link_phase(NodeId neighbor) const noexcept;
  bool upward_eligible(const RouteSelection& selection, NodeId parent,
                       MonotonicMs now_ms) const noexcept;
  void note_scoped_change(const RouteSelection& selection,
                          const RouteSelection& previous,
                          MonotonicMs now_ms) noexcept;
  void note_scoped_update(Neighbor& neighbor, const RouteAdvertisement* records,
                          std::size_t count, MonotonicMs now_ms) noexcept;
  // Appends the self record and one record per configured gateway (a
  // retraction when the gateway route is lost) toward `receiver`.
  std::size_t append_scoped_base(RouteAdvertisement* records, NodeId receiver) noexcept;
  bool scoped_record(NodeId destination, NodeId receiver,
                     RouteAdvertisement& record) noexcept;
  Status enqueue_route_records(NodeId neighbor, const RouteAdvertisement* records,
                               std::size_t count, MonotonicMs now_ms) noexcept;
  Status queue_scoped_update(NodeId neighbor, NodeId extra,
                             MonotonicMs now_ms) noexcept;
  std::size_t emit_upward(UpwardCycle& cycle, std::size_t max_frames,
                          MonotonicMs now_ms) noexcept;
  void emit_upward_dirty(NodeId parent, MonotonicMs now_ms) noexcept;
  void emit_upward_retractions(NodeId parent, MonotonicMs now_ms) noexcept;
  bool upward_change_record(NodeId destination, NodeId parent, MonotonicMs now_ms,
                            RouteAdvertisement& record) noexcept;
  void mark_scoped_dirty(NodeId destination, MonotonicMs now_ms) noexcept;
  void note_scoped_interest(Neighbor& neighbor, MonotonicMs now_ms) const noexcept;
  void schedule_parent_releases(MonotonicMs now_ms) noexcept;
  void release_parent(NodeId old_parent, MonotonicMs now_ms) noexcept;
  void defer_parent_release(std::size_t index, NodeId old_parent, MonotonicMs now_ms) noexcept;
  void run_scoped_tick(MonotonicMs now_ms) noexcept;
  void run_scoped_triggered(MonotonicMs now_ms) noexcept;
  void schedule_gateway_pulls(MonotonicMs now_ms) noexcept;
  void flush_pull_answers(MonotonicMs now_ms) noexcept;
  void request_route_discovery(NodeId destination, MonotonicMs now_ms) noexcept;
  void schedule_route_discovery(MonotonicMs now_ms) noexcept;
  void expire_route_requests(MonotonicMs now_ms) noexcept;
  bool route_request_forward_budget(MonotonicMs now_ms) noexcept;
  void handle_route_request(const wire::PlainFrame& frame, NodeId peer,
                            MonotonicMs now_ms) noexcept;
  Status queue_route_request(NodeId peer, const RouteRequestPayload& payload,
                             MonotonicMs now_ms) noexcept;

  // --- Group delivery (group.cpp, group-delivery.md) ------------------------
  // Per-message tree bookkeeping for one child of this node. Counts are the
  // child's latest report (its whole subtree); per-round flags are reset
  // when a new round starts.
  // Flags are 1-bit fields so a child record is 16 B instead of 24 B: the
  // gateway holds kGroupMaxChildren of these per tree, and the ESP32-C3
  // bridge image is DRAM-bound (static .bss). C++17 has no default member
  // initializers for bit-fields, so the constructor zeroes them.
  struct GroupChild {
    GroupChild() noexcept
        : complete(false), not_child(false), ever_reported(false), sent(false),
          reported(false), failed(false) {}
    NodeId node{kInvalidNodeId};
    std::uint16_t delivered{0};
    std::uint16_t nonmember{0};
    std::uint16_t missing{0};
    std::uint8_t report_round{0};
    bool complete : 1;       // latest report: missing 0, or NOT_CHILD
    bool not_child : 1;      // latest report was NOT_CHILD (counted elsewhere)
    bool ever_reported : 1;
    bool sent : 1;           // copy handed to the scheduler this round
    bool reported : 1;       // report for this round received
    bool failed : 1;         // copy never got a MAC ACK this round
  };
  // One group message as seen by this node (relay/receiver, or the source's
  // root in GroupOrigin::tree). Holds no payload: relays forward the copy of
  // the round being processed; the source re-wraps its sealed frame.
  struct GroupTree {
    MessageKey key{};
    GroupId group{0};
    NodeId parent{kInvalidNodeId};
    MonotonicMs deadline_ms{0};    // report deadline of the current round
    MonotonicMs expires_at_ms{0};  // retention (message deadline + slack)
    std::uint8_t round{0};
    std::uint8_t child_count{0};
    std::uint8_t report_resends{0};
    std::uint8_t missing_count{0};           // ids gathered this round
    std::uint16_t extra_missing{0};          // untracked children subtrees
    Priority priority{Priority::Normal};
    bool origin{false};
    bool collecting{false};
    bool reported{false};
    bool self_delivered{false};    // member: accepted for the application
    bool self_nonmember{false};
    std::array<NodeId, kGroupReportMissingMax> missing{};
    std::array<GroupChild, kGroupMaxChildren> children{};
  };
  struct GroupOrigin {
    MessageId id{};
    GroupId group{0};
    Priority priority{Priority::Normal};
    DeliveryState state{DeliveryState::Empty};
    const char* reason{"NONE"};
    MonotonicMs created_at_ms{0};
    MonotonicMs expires_at_ms{0};
    MonotonicMs next_round_at_ms{0};
    std::uint32_t group_seq{0};
    std::uint32_t node_cost_us{0};  // estimated air time per reached node
    // High-water of the nodes the source's route table knew since admission:
    // a route lost to churn mid-delivery must not shrink what "complete"
    // means (the summary reports it as unaccounted instead).
    std::uint16_t expected_nodes{0};
    bool admitted{false};
    bool budget_waiting{false};     // counted once in budget_deferrals
    bool force_all{false};          // next round re-sends every child
    wire::LinkOpenedFrame sealed{};
    GroupTree tree{};
    GroupDeliveryResult summary{};
  };
  // Per-source receive stream (dedup + ordering), one per gateway.
  struct GroupStream {
    NodeId source{kInvalidNodeId};
    std::uint32_t session{0};
    std::uint32_t max_seq{0};    // highest stream number seen (0 = none)
    std::uint64_t seen{0};       // bit i: stream number max_seq - i seen
    std::uint32_t next_seq{0};   // in-order delivery cursor (0 = unset)
  };
  struct GroupHold {
    GroupMessageInfo info{};
    std::uint32_t gk_epoch{0};
    MonotonicMs release_at_ms{0};
    std::uint8_t size{0};
    std::array<std::uint8_t, kGroupPayloadMax> payload{};
  };
  // One sealed GROUP_DATA frame held while its next-GK durable promote is
  // outstanding (G-SEC P5): the frame that triggers an implicit activation
  // authenticates but cannot open until the promote lands, so the node
  // retries it from process_group instead of dropping it onto the repair
  // round. A second trigger while one is held drops (bounded, counted);
  // stream seen-bits still suppress the repair duplicate.
  struct GroupPromoteHold {
    bool used{false};
    wire::LinkOpenedFrame frame{};
    NodeId peer{kInvalidNodeId};
    MonotonicMs held_at_ms{0};
  };

  void handle_group_data(const wire::LinkOpenedFrame& frame, NodeId peer,
                         MonotonicMs now_ms) noexcept;
  void handle_group_report(const wire::PlainFrame& frame, NodeId peer,
                           MonotonicMs now_ms) noexcept;
  // complete_job/fail_job hook for JobOwner::Group (copies and reports).
  void group_job_done(const TxJob& job, bool success, MonotonicMs now_ms) noexcept;
  // poll() driver: source admission/rounds, report deadlines, hold release,
  // retention expiry.
  void process_group(MonotonicMs now_ms) noexcept;
  GroupTree* find_group_tree(const MessageKey& key) noexcept;
  GroupOrigin* find_group_origin(const MessageId& id) noexcept;
  const GroupOrigin* find_group_origin(const MessageId& id) const noexcept;
  GroupOrigin* origin_of(const GroupTree& tree) noexcept;
  GroupTree* allocate_group_tree(MonotonicMs now_ms) noexcept;
  // Read-only stream lookup for a (source, session) candidate: no state is
  // touched, so an unauthenticated frame cannot move the stream (issue
  // #106). The commit runs only after the Group end layer verifies.
  GroupStream* group_stream_candidate(NodeId source, std::uint32_t session,
                                      bool& stale) noexcept;
  GroupStream* group_stream_commit(GroupStream* candidate, NodeId source,
                                   std::uint32_t session) noexcept;
  static bool group_seen(const GroupStream& stream, std::uint32_t seq) noexcept;
  static void group_mark_seen(GroupStream& stream, std::uint32_t seq) noexcept;
  void group_begin_round(GroupTree& tree, const wire::LinkOpenedFrame& frame,
                         NodeId parent, bool force_all, MonotonicMs now_ms) noexcept;
  bool queue_group_copy(const wire::LinkOpenedFrame& frame, const GroupTree& tree,
                        NodeId child, MonotonicMs now_ms) noexcept;
  bool group_round_resolved(const GroupTree& tree) const noexcept;
  void group_finalize(GroupTree& tree, MonotonicMs now_ms) noexcept;
  // Pure: the report this node would send for its current round.
  void group_build_report(const GroupTree& tree, GroupReportPayload& out) const noexcept;
  // Routes whose committed next hop is `child` (its subtree in our table):
  // appends ids to `ids` up to `capacity` via `count`, returns the total.
  std::uint16_t group_routed_subtree(NodeId child, NodeId* ids, std::size_t capacity,
                                     std::uint8_t& count) const noexcept;
  Status queue_group_report(NodeId to, const GroupReportPayload& report,
                            Priority priority, MonotonicMs now_ms) noexcept;
  void group_origin_round_done(GroupOrigin& origin, MonotonicMs now_ms) noexcept;
  void group_origin_terminal(GroupOrigin& origin, DeliveryState state,
                             const char* reason) noexcept;
  void group_admit(MonotonicMs now_ms) noexcept;
  std::int64_t group_budget_balance(MonotonicMs now_ms) noexcept;
  std::uint16_t group_expected_nodes() const noexcept;
  // Ordering + application hand-off (group-delivery.md §6).
  void group_accept(GroupStream& stream, const GroupMessageInfo& info, ByteView app,
                    bool member, std::uint32_t remaining_ms, MonotonicMs now_ms,
                    std::uint32_t gk_epoch) noexcept;
  void group_drain(GroupStream& stream) noexcept;
  void group_skip_to(GroupStream& stream, std::uint32_t target) noexcept;
  void group_deliver_app(const GroupMessageInfo& info, ByteView app) noexcept;
  // Sleep support (quiesced / settle_one_sleep_* above): true while a
  // group round still collects reports.
  bool group_radio_pending() const noexcept;
  // True when `job` belongs to this node's own group origin that already
  // reached a terminal state. Shared by dispatch, retry and completion: late
  // results and queued retries for a settled origin neither revive its
  // verdict nor burn airtime. Relay/report jobs are never stale.
  bool group_origin_job_stale(const TxJob& job) const noexcept;

  // §14 management airtime bucket (03-congestion.md §8 — local calibrated
  // accounting only). control_budget_balance refills to `now_ms` and
  // returns the signed balance: a completed management TX may run it
  // negative, and the debt is repaid by the computed wait before the next
  // emission is scheduled — never by queueing on debt.
  std::int64_t control_budget_balance(MonotonicMs now_ms) noexcept;
  // Milliseconds until the bucket covers the calibrated air-time estimate
  // of one management frame, 0 when it already can.
  MonotonicMs control_budget_wait_ms(MonotonicMs now_ms) noexcept;
  // §8 capacity decision for a gated profile: true while a deferral of
  // `wait_ms` still lets the route refresh land inside the actual lease —
  // refresh_bound = pages*round_period + fan-out wait + jitter + margin —
  // where the fan-out wait covers `fanout` frames at the calibrated
  // demand and pages is the live table's record-page count. False means
  // the budget cannot sustain route maintenance for this configuration.
  bool control_budget_refresh_fits(MonotonicMs now_ms, MonotonicMs wait_ms,
                                   std::size_t fanout) noexcept;
  // Record a §14 CONTROL_BUDGET_UNSATISFIABLE breach: the saturating
  // counter every time, the observer diagnostic once per breach episode
  // (re-armed when an emission again fits inside the route lease).
  void note_control_budget_unsat() noexcept;

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
  // Set while an application callback (observer or extended sink) runs on
  // this node. Declared before observer_ so the forwarder can bind it.
  // Mutable: a const query (capability reply) may still run sink code.
  mutable bool in_external_callback_{false};
  ObserverForwarder observer_;
  RouteTable routes_{};
  AutonomyFrameSink* autonomy_sink_{nullptr};
  RrsGossipSink* rrs_sink_{nullptr};
  GatewayServiceSink* gateway_sink_{nullptr};
  ConfigEndpointSink* config_sink_{nullptr};
  DiagnosticSink* diagnostic_sink_{nullptr};
  sdkv1::BootstrapSink* bootstrap_sink_{nullptr};
  std::uint32_t local_role_{0};
  ReplyPeerPort* reply_peer_port_{nullptr};
  // Non-reentrancy guard (issue #117): set for the whole duration of every
  // public mutating call; nested calls return Busy. The synchronous radio
  // submit handshake (note_tx_submit_identity, issued by RadioPort::send
  // during dispatch) is the single exempt entry — it only fills the pending
  // submit-identity slot the same dispatch consumes.
  bool in_call_{false};
  // Admission transactions and deferred component events (issue #117).
  std::array<TxnSlot, kAdmissionTransactionsMax> txn_slots_{};
  std::array<EventSlot, kComponentEventsMax> event_slots_{};
  // Component-origin jobs (Service/config) queued or in flight: each holds
  // one completion event slot from its send, so payload admissions must
  // leave room for their completions (design-q116 §8.3).
  std::size_t component_jobs_outstanding_{0};
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
  // The one sealed frame (TxJob::encoded_tag): only dispatch_next seals, it
  // hands the driver one frame at a time and the driver copies it, so a
  // per-job encode buffer would only ever be live for the selected job.
  wire::EncodedFrame tx_encoded_{};
  std::uint32_t tx_encoded_tag_{0};   // tag of the job tx_encoded_ holds; 0 = none
  std::uint32_t last_encoded_tag_{0};
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
  // Gateway-scoped profile state (bounded; routing-scale.md §6).
  std::array<NodeId, kScopedDirtyCapacity> scoped_dirty_{};
  std::size_t scoped_dirty_count_{0};
  bool scoped_dirty_overflow_{false};
  bool scoped_down_dirty_{false};
  bool scoped_trigger_all_{false};
  std::uint32_t scoped_tick_{0};
  std::size_t scoped_other_cursor_{0};
  std::array<UpwardCycle, kMaxRouteGateways> upward_{};
  // Deferred "no longer your child" notice to a former parent (per gateway).
  std::array<NodeId, kMaxRouteGateways> release_parent_{};
  std::array<MonotonicMs, kMaxRouteGateways> release_at_ms_{};
  std::array<MonotonicMs, kMaxRouteGateways> pull_next_ms_{};
  std::array<std::uint8_t, kMaxRouteGateways> pull_attempts_{};
  FixedPool<DiscoveryState, kDiscoveryCapacity> discoveries_{};
  FixedPool<RouteRequestSeen, kRouteRequestSeenCapacity> route_request_seen_{};
  std::uint32_t next_route_request_id_{1};
  MonotonicMs route_request_window_ms_{0};
  std::uint32_t route_request_window_count_{0};
  RouteScaleStats route_scale_stats_{};
  // Group delivery state (bounded; group-delivery.md §9).
  std::array<GroupId, kGroupMembershipMax> group_membership_{};
  std::size_t group_membership_count_{0};
  FixedPool<GroupTree, kGroupTreeCapacity> group_trees_{};
  FixedPool<GroupOrigin, kGroupOriginCapacity> group_origins_{};
  FixedPool<GroupStream, kGroupStreamCapacity> group_streams_{};
  FixedPool<GroupHold, kGroupHoldCapacity> group_holds_{};
  GroupPromoteHold group_promote_hold_{};
  std::uint32_t next_group_seq_{1};
  std::int64_t group_budget_tokens_us_{kGroupBudgetCapacityUs};
  MonotonicMs group_budget_last_ms_{0};
  GroupStats group_stats_{};
  // Retry-jitter decorrelation counter — same convention as
  // trigger_counter_ (node.cpp trigger_route_advertisement).
  std::uint32_t retry_jitter_counter_{0};
  // Node-global ordering tag stamped on emitted BUSY payloads; receivers
  // compare it per-peer to reject stale/replayed feedback (03 §5).
  std::uint32_t next_feedback_sequence_{1};
  // BUSY-side statistics; merged into congestion_stats() with the
  // scheduler's own counters.
  CongestionStats busy_stats_{};
  // §14 ledger + control-budget state: per-domain µs totals merged into
  // congestion_stats(). The signed token balance may run negative between
  // emission and completion — §14 charges measured service AT completion,
  // so a management emission scheduled with tokens in hand repays the
  // deficit via the wait computed for the NEXT one.
  CongestionStats budget_stats_{};
  std::int64_t control_budget_tokens_us_{kControlBudgetCapacityUs};
  MonotonicMs control_budget_last_ms_{0};
  // Calibrated emission demand: EWMA (alpha 1/8) of measured control-domain
  // driver service, seeded at the pinned max-frame cost so the first
  // emissions gate conservatively until local service is measured.
  std::uint32_t control_service_ewma_us_{kControlBudgetFrameCostUs};
  std::uint64_t control_service_samples_{0};
  bool control_budget_unsat_reported_{false};
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
  SessionStats session_stats_{};
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
