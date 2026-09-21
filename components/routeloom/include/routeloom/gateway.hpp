#pragma once

// Explicit Gateway delivery (docs/design/scope-gateway-config/
// 03-explicit-gateway.md, 05-wire-api.md §5.3, contracts.json gateway.*).
//
// This is the Service=21 terminal-delivery component: an ORIGIN resolves a
// named gateway into an opaque GatewayEndpoint and submits ≤96B payloads for
// a signed end outcome (Receipt/Pending/Reject); a GATEWAY role answers
// Query/Submit, dedups on the origin MessageKey, keeps 32 dedup/receipt
// records for 60s and completes GATEWAY_SDK_RAM work into a bounded mailbox
// or HOST_RECEIVE_RAM work through the injected GatewayHostSink (the USB
// half of the host path is the P3 bridge — this file owns only the
// device-side contract).
//
// Completion semantics (03 §3.1): a verified Service Receipt for the pinned
// gateway + original MessageKey + request digest. It never means "a node got
// some DATA" and is never synthesized from END_RECEIPT=18 or hop ACKs. A
// Receipt's own frame is a NEW gateway-issued MessageKey; there are no
// receipt-for-receipt chains.

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/discovery_scope.hpp"
#include "routeloom/endpoint_wire.hpp"
#include "routeloom/fixed_containers.hpp"
#include "routeloom/node.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"
#include "routeloom/wire.hpp"

namespace routeloom {

// --- Bounds (contracts.json gateway.*) ----------------------------------------
constexpr std::size_t kGatewayPayloadMaxBytes = endpoint::kGatewayPayloadMax;  // 96
constexpr std::size_t kGatewayEndpointRecords = 4;   // origin-side descriptors
constexpr std::size_t kGatewayOriginSends = 8;       // origin result slots
constexpr std::size_t kGatewayIssuedTokens = 4;      // gateway-side endpoints
constexpr std::size_t kGatewayPendingMax = 8;        // accepted work in flight
constexpr std::size_t kGatewayReceiptRecords = 32;   // dedup/receipt table
constexpr std::uint32_t kGatewayReceiptHoldMs = 60000;   // from first accept
constexpr std::uint32_t kGatewayAcceptedPerMinute = 20;  // rate bucket refill
constexpr std::uint32_t kGatewayRateBurst = 8;           // rate bucket burst
constexpr std::uint32_t kGatewayDescriptorLeaseMs = 15000;
constexpr std::uint32_t kGatewayLifetimeMaxMs = 30000;
constexpr std::uint8_t kGatewayMaxRounds = 3;   // E2E rounds incl. the first
// Implementation-chosen bound (design pins no value): how long a RESERVED
// scope-2 record waits for the host ingress ACK before its outcome becomes
// an explicit non-success. Always inside the submit's own deadline.
constexpr std::uint32_t kGatewayHostAckMs = 5000;
// Implementation-chosen bound (design pins no value): once the ACK deadline
// passed, a late ACK still gets one grace window to complete the record —
// then the wait concludes as a stored non-success and the pending slot
// frees, so a dead host can never pin all 8 slots for the 60s hold.
constexpr std::uint32_t kGatewayHostAckGraceMs = 5000;
// capabilities bit 0 in the Descriptor: HOST_RECEIVE_RAM ingress exists.
constexpr std::uint32_t kGatewayCapHostReceive = 0x01u;

using GatewayToken = std::array<std::uint8_t, 16>;
using HostDigest = std::array<std::uint8_t, 32>;
using RequestDigest = std::array<std::uint8_t, 32>;

// Opaque endpoint handle (03 §3.2). Issued only by GatewayDelivery::resolve
// after the authenticated Query/Descriptor exchange — an app can copy, hold
// and release it, but can never mint or rebind one: every use re-validates
// the (slot, generation) pair against the bounded record pool, so a
// fabricated handle resolves to NotFound, not authority.
class GatewayEndpoint {
 public:
  constexpr GatewayEndpoint() noexcept = default;

  // Handle identity (slot + generation): lets a caller correlate an
  // observer callback to the exact record it resolved — never authority,
  // every use still re-validates against the pool.
  friend constexpr bool operator==(const GatewayEndpoint& left,
                                   const GatewayEndpoint& right) noexcept {
    return left.slot_ == right.slot_ && left.generation_ == right.generation_;
  }
  friend constexpr bool operator!=(const GatewayEndpoint& left,
                                   const GatewayEndpoint& right) noexcept {
    return !(left == right);
  }

 private:
  friend class GatewayDelivery;
  explicit constexpr GatewayEndpoint(std::uint8_t slot, std::uint32_t generation) noexcept
      : slot_(slot), generation_(generation) {}
  std::uint8_t slot_{0xFF};
  std::uint32_t generation_{0};
};

enum class EndpointState : std::uint8_t {
  Resolving = 1,  // Query/Descriptor exchange in flight
  Ready = 2,      // usable for send()
  Stale = 3,      // lease expired / gateway moved on; re-resolve required
  Failed = 4,     // resolve finished without an endpoint (timeout/refusal)
};

// Origin delivery states (03 §3.7). EndpointReceived is the ONLY success.
enum class GatewaySendState : std::uint8_t {
  Queued = 1,
  HopAccepted = 2,       // a hop ACKed the Submit; receipt still owed
  WaitingEndpoint = 3,   // hop-accepted; waiting for the gateway's outcome
  EndpointReceived = 4,  // verified Receipt — terminal success
  Failed = 5,            // explicit rejection (TOKEN_STALE/UNSUPPORTED/...)
  Expired = 6,           // deadline spent before the first hop accepted
  Indeterminate = 7,     // deadline spent after TX; result unknown (03 §3.4)
};

struct GatewaySendResult {
  MessageId id{};
  GatewaySendState state{GatewaySendState::Queued};
  endpoint::ServiceReason reason{endpoint::ServiceReason::Ok};
  const char* detail{"NONE"};
};

struct GatewayEndpointInfo {
  NodeId gateway{kInvalidNodeId};
  endpoint::GatewayScope scope{endpoint::GatewayScope::GatewaySdkRam};
  GatewayToken token{};
  std::uint64_t gateway_boot{0};
  HostDigest host_digest{};
  std::uint16_t max_payload{0};
  EndpointState state{EndpointState::Failed};
  MonotonicMs lease_deadline_ms{0};
};

// Application-facing notifications. Delivery completion is reported exactly
// once; resolve completion once per resolve() call.
class GatewayDeliveryObserver {
 public:
  virtual ~GatewayDeliveryObserver() = default;
  // On success `endpoint` holds one reference; on failure it is already
  // invalid (released inside the component) and `result` says why.
  virtual void on_gateway_resolved(const GatewayEndpoint& endpoint, NodeId gateway,
                                   Status result) noexcept = 0;
  virtual void on_gateway_result(const GatewaySendResult& result) noexcept = 0;
};

class NullGatewayObserver final : public GatewayDeliveryObserver {
 public:
  void on_gateway_resolved(const GatewayEndpoint&, NodeId, Status) noexcept override {}
  void on_gateway_result(const GatewaySendResult&) noexcept override {}
};

// --- Host seam (P3 boundary) ---------------------------------------------------
// Identity of the currently registered host for HOST_RECEIVE_RAM endpoints:
// authenticated USB principal digest + host boot + live USB session (03 §3.2,
// 05 §5.6). A token binds all three; a changed host boot/session invalidates
// the token (TOKEN_STALE) instead of rebinding it.
struct HostBinding {
  HostDigest principal_digest{};
  std::uint64_t host_boot{0};
  std::uint64_t usb_session{0};
};

// Device-side half of the HOST_RECEIVE_RAM completion path, implemented by
// the bridge (P3 lands the USB HostOps 0x11/0x12 exchange). The gateway uses
// it at exactly two points: readiness inspection at Query/Submit time, and
// the ReceiveLog ingress whose ACK must arrive before any success is claimed
// (06 invariant 4 — never succeed before real storage evidence).
class GatewayHostSink {
 public:
  virtual ~GatewayHostSink() = default;
  // False = no authenticated+ready host right now (HOST_UNAVAILABLE). True
  // fills the binding the endpoint token is bound to.
  virtual bool host_ready(HostBinding& binding) noexcept = 0;
  // Queue the payload for host ReceiveLog storage. Success only means the
  // request was accepted for ingress; the store evidence arrives via
  // GatewayDelivery::on_host_ingress_ack. A failure (Busy/NoCapacity) is a
  // pre-acceptance refusal — the caller drops its reservation and answers
  // CAPACITY rather than partially accepting and losing the evidence.
  // `submit_prefix` is the 32B canonical head of the Service Submit that
  // produced the payload: the USB 0x11 ingress frame carries it verbatim
  // so the host can recompute request_digest = SHA-256(prefix+payload)
  // before storing — a tampered body can never earn a success ACK.
  virtual Status host_ingress(const MessageKey& key, const RequestDigest& request_digest,
                              ByteView submit_prefix, ByteView payload,
                              MonotonicMs now_ms) noexcept = 0;
};

// GatewayServiceSink (the MeshNode integration seam) is declared in
// node.hpp: the node delivers terminal, link+end verified Service frames
// through it and reports hop-level completion of jobs queued via
// send_service/resend_service. GatewayDelivery implements it.

struct GatewayRoleConfig {
  std::uint64_t gateway_boot{0};   // nonzero boot incarnation, persisted
  std::uint32_t capabilities{0};   // kGatewayCapHostReceive requires host_sink
  GatewayHostSink* host_sink{nullptr};  // P3 bridge implements; scope2 needs it
};

// Distinct diagnostic counters (03 §3.7): normal Node DATA, gateway SDK
// receipts and host receipts are never one bucket.
struct GatewayStats {
  std::uint32_t queries_answered{0};
  std::uint32_t queries_dropped{0};       // no role / no host / pool full
  std::uint32_t descriptors_issued{0};
  std::uint32_t submits_accepted{0};      // new work admitted
  std::uint32_t submits_duplicate{0};     // dedup hit, outcome re-sent
  std::uint32_t submits_conflict{0};      // same MessageKey, different digest
  std::uint32_t submits_stale_token{0};   // expired/foreign token on NEW work
  std::uint32_t submits_host_unavailable{0};
  std::uint32_t submits_capacity{0};      // rate/pending/receipt/reply full
  std::uint32_t sdk_ram_receipts{0};      // GATEWAY_SDK_RAM completions
  std::uint32_t host_ram_receipts{0};     // HOST_RECEIVE_RAM completions
  std::uint32_t outcomes_emitted{0};
  std::uint32_t outcomes_resend{0};       // stored outcome replayed
  std::uint32_t outcomes_emit_failed{0};
  std::uint32_t resolves_succeeded{0};
  std::uint32_t resolves_failed{0};
  std::uint32_t receipts_verified{0};     // origin accepted a Receipt
  std::uint32_t outcomes_rejected{0};     // forged/mismatched fields dropped
  std::uint32_t mailbox_stored{0};
  std::uint32_t mailbox_dropped{0};       // payload expired undrained
  std::uint32_t host_ingress_sent{0};
  std::uint32_t host_ingress_acked{0};
  std::uint32_t host_ingress_timeouts{0};
  std::uint32_t malformed_frames{0};
};

// One component per node covering BOTH roles: origin (resolve + submit) is
// always available; the responder half activates via enable_gateway(). All
// state is statically bounded — nothing allocates, nothing evicts a
// protected record to look better under load.
class GatewayDelivery final : public GatewayServiceSink {
 public:
  explicit GatewayDelivery(MeshNode& node) noexcept;

  // Install as the node's Service endpoint (idempotent).
  void attach() noexcept;
  void set_observer(GatewayDeliveryObserver& observer) noexcept { observer_ = &observer; }

  // --- Origin API --------------------------------------------------------------
  // Begin the authenticated Query/Descriptor exchange. The returned handle
  // (state Resolving) carries one reference even while the exchange runs;
  // endpoint_state() / on_gateway_resolved report the outcome. Fails fast
  // (NoCapacity) when all 4 endpoint records are in use.
  Status resolve(NodeId gateway, endpoint::GatewayScope scope,
                 const HostDigest& expected_host_digest,
                 std::uint32_t resolve_deadline_ms, MonotonicMs now_ms,
                 GatewayEndpoint& out) noexcept;
  EndpointState endpoint_state(const GatewayEndpoint& endpoint) const noexcept;
  // Read-only snapshot of the authenticated binding for diagnostics/tests.
  // Never mutates; false on an invalid handle.
  bool endpoint_info(const GatewayEndpoint& endpoint,
                     GatewayEndpointInfo& info) const noexcept;
  // Bounded references (sdk-contract.h §5.8): retain/release. Release of the
  // last reference frees the record once its in-flight sends drain; the
  // copied token inside each send keeps them honest, so a mid-flight release
  // can never fabricate an outcome.
  Status endpoint_retain(const GatewayEndpoint& endpoint) noexcept;
  void endpoint_release(const GatewayEndpoint& endpoint) noexcept;

  // Validate the endpoint (Ready, lease covers lifetime) and reserve a
  // result slot BEFORE any transmit — acceptance failure leaves nothing
  // half-queued. payload ≤96B hard cap; 97B+ is InvalidArgument, never
  // truncated. lifetime must stay inside the remaining descriptor lease
  // (ENDPOINT_LEASE_TOO_SHORT; never silently shortened) and ≤30000ms.
  // The carrier uses the node's default hop bound (kDefaultHopLimit).
  Status send(const GatewayEndpoint& endpoint, ByteView payload,
              std::uint32_t lifetime_ms,
              MonotonicMs now_ms, MessageId& out) noexcept;
  GatewaySendResult send_result(const MessageId& id) const noexcept;

  // --- Gateway role --------------------------------------------------------------
  // Advertise the gateway role (needed to answer Queries). gateway_boot must
  // be nonzero; a boot CHANGE is the only legitimate reason to re-issue all
  // tokens — reconnects never rewrite a pending record's token.
  Status enable_gateway(const GatewayRoleConfig& config) noexcept;
  void disable_gateway() noexcept;
  bool gateway_enabled() const noexcept { return role_.enabled; }

  // Bounded GATEWAY_SDK_RAM mailbox (the completion evidence). Holds at most
  // kGatewayPendingMax payloads; an undrained entry still occupies a pending
  // slot, so a reader that never drains is honest backpressure, not a leak.
  // Entries age out with their dedup record (≤60s) — mailbox_dropped counts
  // those, they are never reported as delivered-to-app.
  std::size_t mailbox_size() const noexcept;
  bool mailbox_take(MessageKey& key,
                    std::array<std::uint8_t, kGatewayPayloadMaxBytes>& payload,
                    std::size_t& payload_size) noexcept;

  // Host ingress ACK from the bridge (P3): `stored` = ReceiveLog evidence
  // (outcome OK). On it the pending record completes and its Receipt is
  // emitted; a failure/timeout produces a stored non-success outcome and
  // never a second ingress attempt for that MessageKey.
  void on_host_ingress_ack(const MessageKey& key, bool stored,
                           MonotonicMs now_ms) noexcept;

  // --- GatewayServiceSink (MeshNode calls) ----------------------------------------
  void on_service_payload(NodeId peer, const wire::PlainFrame& frame,
                          MonotonicMs now_ms) noexcept override;
  void on_service_job_done(const MessageId& id, bool hop_accepted,
                           const char* reason, MonotonicMs now_ms) noexcept override;
  void poll(MonotonicMs now_ms) noexcept override;

  const GatewayStats& stats() const noexcept { return stats_; }

  // Bounded-state introspection for tests/diagnostics.
  std::size_t endpoint_records_used() const noexcept;
  std::size_t send_records_used() const noexcept { return sends_.size(); }
  std::size_t issued_tokens_used() const noexcept { return issued_.size(); }
  std::size_t pending_records_used() const noexcept { return pending_.size(); }
  std::size_t receipt_records_used() const noexcept { return receipts_.size(); }

 private:
  // --- Origin records ----------------------------------------------------------
  // Endpoint records live in a plain indexed array (not FixedPool): the
  // GatewayEndpoint handle is a (slot, generation) pair, and generation must
  // survive reuse of the slot so a stale handle can never validate against
  // a record it did not come from.
  struct EndpointRecord {
    std::uint32_t generation{0};   // handle validity tag; bumped on allocate
    bool used{false};
    // All references: resolve hands one to the app; each accepted send holds
    // one until it finishes. refs==0 frees the record — a mid-flight release
    // can never fabricate an outcome because sends carry their own copies.
    std::uint16_t refs{0};
    EndpointState state{EndpointState::Resolving};
    NodeId gateway{kInvalidNodeId};
    endpoint::GatewayScope scope{endpoint::GatewayScope::GatewaySdkRam};
    HostDigest expected_host{};
    // Resolve exchange state (also drives bounded retries). The canonical
    // Query bytes are re-encoded from these fields at each round — the
    // deterministic codec makes resends byte-identical without storing 136B.
    GatewayToken query_nonce{};
    MessageId query_id{};
    MonotonicMs resolve_deadline_ms{0};
    MonotonicMs next_round_ms{0};
    MonotonicMs query_sent_ms{0};
    std::uint8_t round{0};
    // Authenticated descriptor contents (valid only in Ready).
    GatewayToken token{};
    std::uint64_t gateway_boot{0};
    HostDigest host_digest{};
    std::uint16_t max_payload{0};
    MonotonicMs lease_deadline_ms{0};  // rx time + lease − measured RTT
  };

  struct OriginSend {
    MessageId id{};                    // logical MessageKey (stable over rounds)
    std::uint8_t endpoint_slot{0xFF};  // informative; the send is self-contained
    NodeId gateway{kInvalidNodeId};
    endpoint::GatewayScope scope{endpoint::GatewayScope::GatewaySdkRam};
    GatewayToken token{};              // copied at send: survives endpoint release
    std::uint64_t gateway_boot{0};
    std::array<std::uint8_t, kGatewayPayloadMaxBytes> payload{};
    std::size_t payload_size{0};
    // SHA-256 over the canonical Submit; the Submit itself is re-encoded
    // from the stored fields on resend (deterministic → identical bytes).
    RequestDigest request_digest{};
    GatewaySendState state{GatewaySendState::Queued};
    endpoint::ServiceReason reason{endpoint::ServiceReason::Ok};
    const char* detail{"NONE"};
    bool hop_accepted{false};
    MonotonicMs expires_at_ms{0};
    MonotonicMs next_round_ms{0};
    std::uint8_t round{0};
  };

  // --- Gateway records -----------------------------------------------------------
  // Issued endpoint token (descriptor): bound to boot + requester + scope +
  // (scope 2) the full host binding. Lease expiry makes it stale for NEW
  // work; stored final outcomes may still be re-sent.
  struct IssuedToken {
    GatewayToken token{};
    NodeId client{kInvalidNodeId};      // Query origin this was issued to
    endpoint::GatewayScope scope{endpoint::GatewayScope::GatewaySdkRam};
    HostBinding binding{};              // scope 1: zeroed
    MonotonicMs lease_deadline_ms{0};
  };

  // Accepted work / mailbox slot (the 8). VALIDATING happens before the
  // slot exists — a record is born RESERVED only after every reservation
  // succeeds, so no partially accepted work can lose its evidence.
  enum class PendingState : std::uint8_t {
    Reserved = 1,     // slot + dedup + reply budget held; executing scope
    WaitHost = 2,     // scope 2: ingress queued, ACK outstanding
    Received = 3,     // completed; payload may still hold a mailbox entry
  };
  struct PendingRecord {
    MessageKey key{};
    std::array<std::uint8_t, kGatewayPayloadMaxBytes> payload{};
    std::size_t payload_size{0};
    PendingState state{PendingState::Reserved};
    bool mailbox_held{false};          // payload is a live mailbox entry
    bool host_timed_out{false};        // ack deadline passed once (diagnostic)
    MonotonicMs host_ack_deadline_ms{0};
  };

  // Dedup/receipt table record (the 32). A Pending record points at its
  // pending slot; a Completed one stores the final outcome fields for
  // verbatim re-encode (no double delivery, no extension by duplicates).
  enum class DedupState : std::uint8_t { Pending = 1, Completed = 2 };
  // Sentinel for DedupRecord::pending_index (not a valid pending slot).
  static constexpr std::uint8_t kNoPending = 0xFF;
  struct DedupRecord {
    MessageKey key{};
    RequestDigest request_digest{};
    GatewayToken token{};
    std::uint64_t gateway_boot{0};
    // Bounded outcome re-emit: emit_sequence tracks the live emit job (the
    // session half of every emit MessageId is this node's own) so a stale
    // completion notice can never be misread; emit_pending queues a retry.
    std::uint64_t emit_sequence{0};
    MonotonicMs first_seen_ms{0};      // hold = first_seen + 60s, never extended
    MonotonicMs next_emit_ms{0};
    endpoint::ServiceReason outcome_reason{endpoint::ServiceReason::PendingWait};
    endpoint::ServiceSubtype outcome_subtype{endpoint::ServiceSubtype::Pending};
    endpoint::GatewayScope scope{endpoint::GatewayScope::GatewaySdkRam};
    DedupState state{DedupState::Pending};
    std::uint8_t pending_index{kNoPending};  // pending_ slot while Pending
    std::uint8_t emit_retries{0};
    bool emit_pending{false};
  };

  // 20/min + burst 8 acceptance bucket; BOTH a token and free slots gate a
  // new admission (03 §3.4, 06 §6.3). Duplicates never consume.
  struct RateBucket {
    bool consume(MonotonicMs now_ms) noexcept {
      if (now_ms > last_ms_) {
        const std::uint64_t refill =
            ((now_ms - last_ms_) * kGatewayAcceptedPerMinute) / 60000;
        if (refill > 0) {
          const std::uint64_t level = tokens_ + refill;
          tokens_ = level > kGatewayRateBurst
                        ? kGatewayRateBurst
                        : static_cast<std::uint32_t>(level);
          last_ms_ = now_ms;
        }
      }
      if (tokens_ == 0) return false;
      --tokens_;
      return true;
    }
    std::uint32_t tokens_{kGatewayRateBurst};
    MonotonicMs last_ms_{0};
  };

  struct Role {
    bool enabled{false};
    std::uint64_t gateway_boot{0};
    std::uint32_t capabilities{0};
    GatewayHostSink* host_sink{nullptr};
    std::uint64_t issue_counter{0};
  };

  static bool token_nonzero(const GatewayToken& token) noexcept;
  void make_nonce(GatewayToken& out) noexcept;          // origin query nonces
  void mint_token(GatewayToken& out) noexcept;          // boot || issue counter
  static RequestDigest submit_digest(ByteView canonical_submit) noexcept;

  // Service payload handlers (frame is link+end verified, terminal here).
  void handle_query(NodeId peer, const wire::PlainFrame& frame,
                    MonotonicMs now_ms) noexcept;
  void handle_submit(NodeId peer, const wire::PlainFrame& frame,
                     MonotonicMs now_ms) noexcept;
  void handle_descriptor(NodeId peer, const wire::PlainFrame& frame,
                         MonotonicMs now_ms) noexcept;
  void handle_outcome(NodeId peer, const wire::PlainFrame& frame,
                      MonotonicMs now_ms) noexcept;

  IssuedToken* find_issued(const GatewayToken& token) noexcept;
  const IssuedToken* find_issued(const GatewayToken& token) const noexcept;
  DedupRecord* find_dedup(const MessageKey& key) noexcept;
  OriginSend* find_send(const MessageId& id) noexcept;
  const OriginSend* find_send(const MessageId& id) const noexcept;
  EndpointRecord* endpoint_record(const GatewayEndpoint& endpoint) noexcept;
  const EndpointRecord* endpoint_record(const GatewayEndpoint& endpoint) const noexcept;

  // Outcome assembly + emit. Stores the decision fields in the dedup record
  // and (re)encodes on emit so resends are byte-identical to the original.
  void set_outcome(DedupRecord& record, endpoint::ServiceSubtype subtype,
                   endpoint::ServiceReason reason) noexcept;
  Status emit_outcome(DedupRecord& record, MonotonicMs now_ms) noexcept;
  // Stores the terminal outcome on the dedup record and emits it; frees the
  // pending slot unless the payload is still held as a mailbox entry.
  void complete_pending(DedupRecord& record, endpoint::ServiceSubtype subtype,
                        endpoint::ServiceReason reason, MonotonicMs now_ms) noexcept;
  // Frees a pending slot and unlinks it from its dedup record (key match).
  void release_pending(PendingRecord* pending) noexcept;
  std::uint8_t endpoint_index(const EndpointRecord* record) const noexcept;
  // Terminal resolve failure: frees the record (app ref included) and then
  // reports with an invalid handle — a failed resolve never leaves a
  // half-usable endpoint behind.
  void fail_resolve(std::size_t slot, Status result) noexcept;
  void finish_send(OriginSend& send, GatewaySendState state,
                   endpoint::ServiceReason reason, const char* detail) noexcept;
  void retry_send(OriginSend& send, MonotonicMs now_ms) noexcept;

  MeshNode& node_;
  GatewayDeliveryObserver* observer_{nullptr};
  NullGatewayObserver null_observer_{};
  Role role_{};
  RateBucket rate_{};
  // Query admissions get their own bucket so a refused-Query flood cannot
  // starve either Submit admissions or honest resolves.
  RateBucket query_rate_{};
  GatewayStats stats_{};
  std::uint64_t nonce_counter_{0};
  std::array<EndpointRecord, kGatewayEndpointRecords> endpoints_{};
  FixedPool<OriginSend, kGatewayOriginSends> sends_{};
  FixedPool<IssuedToken, kGatewayIssuedTokens> issued_{};
  FixedPool<DedupRecord, kGatewayReceiptRecords> receipts_{};
  FixedPool<PendingRecord, kGatewayPendingMax> pending_{};
};

}  // namespace routeloom
