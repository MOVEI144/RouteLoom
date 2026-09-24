#pragma once

// P6 revocation lifecycle, PR A (docs/design/sdk-v1/04-removal-revocation.md
// §2-§5, plan P6-1): RRS1 acceptance, enforcement, 1-hop gossip and the
// traffic gate. The MembershipLifecycle is the single device-side entry for
// membership state; peer credentials, session keys and routes stay owned by
// P4/MeshNode and are only *acted on* through the narrow LifecyclePorts.
//
// PR A covers the BootGate/Active/ApplyingRrs/SelfRevoked/Recovering phases.
// Removal/Holdoff (PR B) and Prepared/Switching (PR C) extend the phase enum
// and the input/action tags — never renumber them.
//
// Production wiring (P4 link adapter, P5 authority channel, Owner routing of
// kind-6 objects) is NOT part of PR A: the component is exercised through
// fake ports, and MeshNode leaves the P6 sinks unwired (see node.hpp).
// Portable, heap-free, bounded, noexcept; the Owner thread serializes calls.

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/autonomy.hpp"
#include "routeloom/autonomy_wire.hpp"
#include "routeloom/rlcw1.hpp"
#include "routeloom/sdkv1_records.hpp"
#include "routeloom/sdkv1_store.hpp"
#include "routeloom/sdkv1_lifecycle_store.hpp"
#include "routeloom/sdkv1_grant_renew.hpp"
#include "routeloom/status.hpp"
#include "routeloom/telemetry.hpp"
#include "routeloom/types.hpp"

namespace routeloom {
class EntropySource;  // routeloom/discovery.hpp (gossip jitter only)
}  // namespace routeloom

namespace routeloom::sdkv1 {

// --- 1-hop RRS gossip bodies (04 §4) -------------------------------------------
// Link-only Control (22) payloads, exact shapes only. The link seal proves
// the immediate peer; SAK-signed content (never these hints) moves state.
constexpr std::uint8_t kRrsControlVersion = 1;
constexpr std::uint8_t kRrsSubStateEpochs = 0x61;
constexpr std::uint8_t kRrsSubRequest = 0x62;
// StateEpochs (14 B): ver u8 | sub 0x61 | site_epoch u32 | applied_rs u32 |
// gk_epoch u32. What the sender has durably applied — a hint, not evidence.
constexpr std::size_t kStateEpochsSize = 14;
struct StateEpochs {
  std::uint32_t site_epoch{0};
  std::uint32_t applied_rs_epoch{0};
  std::uint32_t gk_epoch{0};
};
Status state_epochs_encode(const StateEpochs& epochs,
                           std::array<std::uint8_t, kStateEpochsSize>& out) noexcept;
Status state_epochs_decode(ByteView body, StateEpochs& out) noexcept;
// RrsRequest (10 B): ver u8 | sub 0x62 | site_epoch u32 | have_rs u32. A
// pull for the sender's RRS1 when the receiver advertised a newer epoch.
constexpr std::size_t kRrsRequestSize = 10;
struct RrsRequest {
  std::uint32_t site_epoch{0};
  std::uint32_t have_rs_epoch{0};
};
Status rrs_request_encode(const RrsRequest& request,
                          std::array<std::uint8_t, kRrsRequestSize>& out) noexcept;
Status rrs_request_decode(ByteView body, RrsRequest& out) noexcept;

// --- Authority type-5 bodies (04 §3) --------------------------------------------
// Host->device is the RRS1 COSE object itself (<= 616 B, no wrapper).
// Device->host reports (carried by the P5 authority envelope):
//   Applied (40 B): ver=1 u8 | sub=1 u8 | reserved u16 | rs_epoch u32 |
//     object_sha256[32] — "this device applied that set".
//   Get (8 B): ver=1 | sub=2 | reserved | wanted_rs_epoch u32 (0 = latest).
//   NoticeAccepted (40 B): ver=1 | sub=3 | reserved | rs_epoch u32 |
//     notice_sha256[32] — durable removal-intent evidence (PR B consumes it).
constexpr std::uint8_t kAuthorityTypeRevocation = 5;
constexpr std::size_t kRrsAppliedSize = 40;
constexpr std::size_t kRrsGetSize = 8;
constexpr std::size_t kRrsNoticeAcceptedSize = 40;
struct RrsApplied {
  std::uint32_t rs_epoch{0};
  std::array<std::uint8_t, 32> object_sha256{};
};
struct RrsGet {
  std::uint32_t wanted_rs_epoch{0};
};
struct RrsNoticeAccepted {
  std::uint32_t rs_epoch{0};
  std::array<std::uint8_t, 32> notice_sha256{};
};
Status rrs_applied_encode(const RrsApplied& applied,
                          std::array<std::uint8_t, kRrsAppliedSize>& out) noexcept;
Status rrs_applied_decode(ByteView body, RrsApplied& out) noexcept;
Status rrs_get_encode(const RrsGet& get, std::array<std::uint8_t, kRrsGetSize>& out) noexcept;
Status rrs_get_decode(ByteView body, RrsGet& out) noexcept;
Status rrs_notice_accepted_encode(const RrsNoticeAccepted& accepted,
                                 std::array<std::uint8_t, kRrsNoticeAcceptedSize>& out) noexcept;
Status rrs_notice_accepted_decode(ByteView body, RrsNoticeAccepted& out) noexcept;

// --- Gossip bounds (04 §4) --------------------------------------------------------
namespace rrs_const {
constexpr std::uint32_t kGossipRefreshMs = 5000;    // idle StateEpochs period
constexpr std::uint32_t kGossipJitterMs = 1000;     // refresh jitter 0..1 s
constexpr std::uint32_t kGossipControlGapMs = 100;  // <= 10 control jobs/s
constexpr std::uint32_t kRequestCooldownMs = 60000;  // one fetch per peer/min
constexpr std::uint32_t kAssembleDeadlineMs = 10000;
constexpr std::uint32_t kAckTimeoutMs = 2000;
constexpr std::uint8_t kSendAttemptsMax = 3;  // first attempt included
constexpr std::uint32_t kAuthorityGetCooldownMs = 60000;
constexpr std::uint32_t kAuthorityGetRetryMs = 1000;  // while the port refuses
constexpr std::uint32_t kFetchWindowMs = 15000;  // request round + assembly + slack
constexpr std::uint8_t kLinkFailureThreshold = 3;
constexpr std::size_t kNeighborMax = 32;  // == discovery kNeighborCapacity
constexpr std::size_t kInputBodyMax = 1024;
constexpr std::size_t kSweepAttemptsMax = 3;  // then StorageBlocked
}  // namespace rrs_const

// --- Kind-6 object exchange --------------------------------------------------------
// One RX + one TX RRS1 object transfer (manifest + in-order chunks + ack)
// over the link-scoped ControlObject/ObjectChunk/ObjectAck carriers. Not
// thread-safe; the Owner serializes. Delivery is transport-only: the sink
// copies the bytes and the Owner re-feeds them through dispatch() as a
// CompletedRrsObject — the sink never touches stores or starts new sends.
class RrsObjectSink {
 public:
  virtual ~RrsObjectSink() = default;
  virtual void on_rrs_object(NodeId peer, ByteView object, MonotonicMs now_ms) noexcept = 0;
};

class LifecyclePeerPort {
 public:
  virtual ~LifecyclePeerPort() = default;
  // One link-sealed 1-hop frame to a verified peer (a P6 Control body or a
  // kind-6 manifest/chunk/ack). WouldBlock/failure = unsent; the port
  // copies `body` during the call.
  virtual Status peer_send(NodeId peer, FrameType carrier, ByteView body) noexcept = 0;
};

class RrsExchange {
 public:
  RrsExchange(LifecyclePeerPort& port, RrsObjectSink& sink) noexcept;

  void on_manifest(NodeId peer, std::uint32_t binding,
                   const autonomy::ControlObjectPayload& manifest,
                   MonotonicMs now_ms) noexcept;
  void on_chunk(NodeId peer, std::uint32_t binding,
                const autonomy::ObjectChunkPayload& chunk, MonotonicMs now_ms) noexcept;
  void on_ack(NodeId peer, std::uint32_t binding,
              const autonomy::ObjectAckPayload& ack, MonotonicMs now_ms) noexcept;

  // Queue one RRS1 object for transfer; content is copied. NoCapacity
  // while a transfer is already running — the requester retries.
  Status publish(NodeId dest, std::uint32_t binding, ByteView object,
                 MonotonicMs now_ms) noexcept;
  void poll(MonotonicMs now_ms) noexcept;

  // Owner chunk/ack demux: true when this exchange owns a transfer for
  // (peer, binding, hash), so the frame is not fanned to every engine.
  bool owns_transfer(NodeId peer, std::uint32_t binding,
                     const autonomy::ObjectHash& hash) const noexcept;
  // Silently drops both transfers (Stop path; completion is not claimed).
  void abort() noexcept;
  // Next RX deadline / TX retry, 0 when a send is due now, UINT64_MAX idle.
  MonotonicMs next_deadline() const noexcept;
  bool busy() const noexcept { return rx_.used || tx_.used; }
  std::uint32_t delivered() const noexcept { return delivered_; }
  std::uint32_t failed() const noexcept { return failed_; }

 private:
  struct Rx {
    bool used{false};
    NodeId peer{kInvalidNodeId};
    std::uint32_t binding{0};
    autonomy::ObjectHash hash{};
    std::uint16_t total_len{0};
    std::uint16_t received{0};
    MonotonicMs deadline_ms{0};
    std::array<std::uint8_t, kRevocationObjectMax> data{};
  };
  struct Tx {
    bool used{false};
    NodeId dest{kInvalidNodeId};
    std::uint32_t binding{0};
    autonomy::ObjectHash hash{};
    std::uint16_t total_len{0};
    std::uint16_t sent{0};
    std::uint8_t attempts{0};
    bool manifest_sent{false};
    MonotonicMs ack_deadline_ms{0};
    std::array<std::uint8_t, kRevocationObjectMax> data{};
  };
  // Metadata beside the 616 B buffers stays small (04 §4: <= 96 B each).
  static_assert(sizeof(Rx) - kRevocationObjectMax <= 96, "RX metadata bound");
  static_assert(sizeof(Tx) - kRevocationObjectMax <= 96, "TX metadata bound");

  void send_ack(NodeId peer, const autonomy::ObjectHash& hash, std::uint16_t received_len,
                autonomy::ObjectAckStatus status) noexcept;
  void complete_rx(MonotonicMs now_ms) noexcept;
  bool recent_total(NodeId peer, std::uint32_t binding, const autonomy::ObjectHash& hash,
                    std::uint16_t& total) const noexcept;
  void note_delivered(NodeId peer, std::uint32_t binding, const autonomy::ObjectHash& hash,
                      std::uint16_t total) noexcept;
  void transmit_tx(MonotonicMs now_ms) noexcept;

  LifecyclePeerPort& port_;
  RrsObjectSink& sink_;
  Rx rx_{};
  Tx tx_{};
  // Recently completed objects (re-ACK duplicates without extending work).
  struct Recent {
    NodeId peer{kInvalidNodeId};
    std::uint32_t binding{0};
    autonomy::ObjectHash hash{};
    std::uint16_t total{0};
    bool used{false};
  };
  std::array<Recent, 2> recent_{};
  std::uint32_t delivered_{0};
  std::uint32_t failed_{0};
};

// --- Membership lifecycle ------------------------------------------------------------

enum class LifecyclePhase : std::uint8_t {
  BootGate = 0,
  Active = 1,
  ApplyingRrs = 2,
  SelfRevoked = 3,
  Recovering = 4,
  StorageBlocked = 5,
  Stopped = 6,
  Removing = 7,
  Holdoff = 8,
  UnassignedReady = 9,
  Prepared = 10,
  Switching = 11,
};

enum class TrafficUse : std::uint8_t {
  LinkHandshake = 0,
  Resume = 1,
  EndHandshake = 2,
  Data = 3,
  RouteOrigin = 4,
  // Recovery-control-only link/E2E establishment: the adapter additionally
  // restricts it to P5 type-5 Get/Notify carriage — never a generic bypass.
  RecoveryControl = 5,
};

// A P4-verified peer credential: only credentials the link layer proved
// (SAK-signed MemberCert + proof of possession, current binding) may be
// stamped. The site_epoch is derived from `network` (network >> 32).
struct PeerCredentialStamp {
  NodeId peer{kInvalidNodeId};
  NetworkId network{0};
  std::uint32_t assignment_generation{0};
  std::uint8_t role{0};
  // first8(SHA-256(MemberCert)), as in RLP1 peer_cert_id.
  std::array<std::uint8_t, 8> credential_fingerprint{};
  // P4 context/binding incarnation the stamp was verified under.
  std::uint32_t binding_incarnation{0};
};

enum class LifecycleInputTag : std::uint8_t {
  Boot = 0,
  Poll = 1,
  MemberReady = 2,
  VerifiedAuthorityMessage = 3,
  VerifiedPeerControl = 4,
  CompletedRrsObject = 5,
  LinkFailure = 6,
  JoinRecoveryComplete = 7,
  ActionComplete = 8,
  Stop = 9,
  RemovalRequired = 10,
};

struct LifecycleBootEvidence {
  // Durable boot trace the Owner read (rlboot present and sane).
  bool boot_trace_healthy{false};
};

struct LifecycleMemberReady {
  std::uint32_t site_commit_seq{0};  // RLS1 commit_seq the Joiner saw
  std::uint32_t rs_epoch_to_fetch{0};  // acquisition target, not a floor
};

struct LifecycleAuthorityMessage {
  PeerCredentialStamp authority{};  // bound to the authority context
  std::uint8_t authority_type{0};   // PR A: 5 (RevocationNotify) only
  ByteView body{};                  // call-scoped; <= kInputBodyMax
};

struct LifecyclePeerControl {
  PeerCredentialStamp peer{};
  FrameType carrier{FrameType::Data};  // Control/Object/Chunk/Ack only
  ByteView body{};                     // call-scoped; <= kInputBodyMax
};
// NOTE (04 §4): the Owner also reports P4-authenticated epoch exchanges
// (EDHOC EAD / RLRES1 R2) as synthetic StateEpochs bodies through this
// input, so a link-up starts gossip without waiting for a wire frame. The
// stamp stays P4-verified; the bodies remain unverified hints either way
// (only SAK-signed objects move state).

struct LifecycleCompletedObject {
  NodeId peer{kInvalidNodeId};
  ByteView object{};  // call-scoped reassembled RRS1 bytes
};

struct LifecycleLinkFailure {
  NodeId peer{kInvalidNodeId};
  std::uint8_t consecutive_failures{0};  // Owner-counted, saturating
  std::uint8_t usable_neighbors{0};      // Owner-counted (Discovery view)
};

struct LifecycleJoinRecovery {
  bool success{false};  // the recovery join re-provisioned the stores
};

struct LifecycleActionComplete {
  std::uint64_t token{0};
  Status result{};
};

union LifecyclePayload {
  LifecycleBootEvidence boot;
  LifecycleMemberReady member_ready;
  LifecycleAuthorityMessage authority;
  LifecyclePeerControl peer_control;
  LifecycleCompletedObject completed;
  LifecycleLinkFailure link_failure;
  LifecycleJoinRecovery recovery;
  LifecycleActionComplete action_complete;
  ByteView removal_required;
};

struct LifecycleInput {
  LifecycleInputTag tag{LifecycleInputTag::Poll};
  LifecyclePayload payload{};

  static LifecycleInput Poll() noexcept {
    LifecycleInput in{};
    in.tag = LifecycleInputTag::Poll;
    return in;
  }
  static LifecycleInput Boot(bool boot_trace_healthy) noexcept {
    LifecycleInput in{};
    in.tag = LifecycleInputTag::Boot;
    in.payload.boot.boot_trace_healthy = boot_trace_healthy;
    return in;
  }
  static LifecycleInput MemberReady(std::uint32_t site_commit_seq,
                                    std::uint32_t rs_epoch_to_fetch) noexcept {
    LifecycleInput in{};
    in.tag = LifecycleInputTag::MemberReady;
    in.payload.member_ready.site_commit_seq = site_commit_seq;
    in.payload.member_ready.rs_epoch_to_fetch = rs_epoch_to_fetch;
    return in;
  }
  static LifecycleInput Authority(const PeerCredentialStamp& authority, std::uint8_t type,
                                 ByteView body) noexcept {
    LifecycleInput in{};
    in.tag = LifecycleInputTag::VerifiedAuthorityMessage;
    in.payload.authority.authority = authority;
    in.payload.authority.authority_type = type;
    in.payload.authority.body = body;
    return in;
  }
  static LifecycleInput PeerControl(const PeerCredentialStamp& peer, FrameType carrier,
                                   ByteView body) noexcept {
    LifecycleInput in{};
    in.tag = LifecycleInputTag::VerifiedPeerControl;
    in.payload.peer_control.peer = peer;
    in.payload.peer_control.carrier = carrier;
    in.payload.peer_control.body = body;
    return in;
  }
  static LifecycleInput Completed(NodeId peer, ByteView object) noexcept {
    LifecycleInput in{};
    in.tag = LifecycleInputTag::CompletedRrsObject;
    in.payload.completed.peer = peer;
    in.payload.completed.object = object;
    return in;
  }
  static LifecycleInput LinkFailure(NodeId peer, std::uint8_t consecutive,
                                   std::uint8_t usable) noexcept {
    LifecycleInput in{};
    in.tag = LifecycleInputTag::LinkFailure;
    in.payload.link_failure.peer = peer;
    in.payload.link_failure.consecutive_failures = consecutive;
    in.payload.link_failure.usable_neighbors = usable;
    return in;
  }
  static LifecycleInput Recovery(bool success) noexcept {
    LifecycleInput in{};
    in.tag = LifecycleInputTag::JoinRecoveryComplete;
    in.payload.recovery.success = success;
    return in;
  }
  static LifecycleInput ActionDone(std::uint64_t token, Status result) noexcept {
    LifecycleInput in{};
    in.tag = LifecycleInputTag::ActionComplete;
    in.payload.action_complete.token = token;
    in.payload.action_complete.result = result;
    return in;
  }
  static LifecycleInput RemovalRequired(ByteView notice) noexcept {
    LifecycleInput in{};
    in.tag = LifecycleInputTag::RemovalRequired;
    in.payload.removal_required = notice;
    return in;
  }
  static LifecycleInput Stop() noexcept {
    LifecycleInput in{};
    in.tag = LifecycleInputTag::Stop;
    return in;
  }
};

enum class LifecycleActionTag : std::uint8_t {
  None = 0,
  // PR B: hand store ownership to the Joiner for a recovery join.
  StartRecoveryJoin = 1,
  // PR B: restart unassigned after the removal holdoff.
  RestartUnassigned = 2,
  // PR C: adopt the staged next-network membership.
  AdoptNetwork = 3,
  // Owner-owned recovery is required (recovery join / maintenance).
  RecoveryRequired = 4,
};

enum class LifecycleActionReason : std::uint8_t {
  None = 0,
  SelfRevocation = 1,
  LinkFailure = 2,
};

// Owner work order: tag, monotonic token, the RLS1 commit_seq the decision
// was taken under (the Owner re-checks before acting), site/network, reason.
// No keys or certificates — the Owner re-reads the guarded stores.
struct LifecycleAction {
  LifecycleActionTag tag{LifecycleActionTag::None};
  std::uint64_t token{0};  // nonzero while an action is outstanding
  std::uint32_t expected_site_commit_seq{0};
  std::uint64_t site_id{0};
  NetworkId network{0};
  LifecycleActionReason reason{LifecycleActionReason::None};
};

enum class LifecycleEventKind : std::uint8_t {
  RrsApplied = 1,      // epoch = adopted rs_epoch
  RrsRejected = 2,     // epoch = candidate rs_epoch (0 if undecodable),
                       // detail = StatusCode
  SelfRevoked = 3,     // peer = self, epoch = rejecting rs_epoch
  RecoveryStarted = 4,  // detail = LifecycleActionReason
  RecoveryFinished = 5,  // epoch = rs_epoch adopted after recovery
  GossipStalled = 6,   // peer = fetch peer, epoch = wanted rs_epoch
  StorageBlocked = 7,  // detail = LifecycleBlockReason
};

enum class LifecycleBlockReason : std::uint8_t {
  None = 0,
  Identity = 1,
  Site = 2,
  RevocationStore = 3,
  ResumeGeometry = 4,
  StoreCommit = 5,
  PolicyExhausted = 6,
};

// Fixed value types only — never secrets or raw wire.
struct LifecycleEvent {
  LifecycleEventKind kind{LifecycleEventKind::RrsApplied};
  NodeId peer{kInvalidNodeId};
  std::uint32_t epoch{0};
  std::uint32_t detail{0};
};

class LifecycleObserver {
 public:
  virtual ~LifecycleObserver() = default;
  virtual void on_lifecycle_event(const LifecycleEvent& event,
                                  MonotonicMs now_ms) noexcept = 0;
};

class LifecycleAuthorityPort {
 public:
  virtual ~LifecycleAuthorityPort() = default;
  // One message for P5 sealing/sending (PR A: type 5 only). WouldBlock or
  // failure = unsent; the port copies `body` during the call.
  virtual Status authority_send(std::uint8_t authority_type, ByteView body) noexcept = 0;
};

// The single side-effecting enforcement entry, run on the Owner thread:
// cancel in-flight handshakes and retire every context whose credential
// `set` rejects at `site_epoch`, withdraw revoked routes/queue/group/RTC
// state. Called after the RRS1 commit, before the RLS1 floor commit.
class LifecycleRuntimePort {
 public:
  virtual ~LifecycleRuntimePort() = default;
  virtual Status enforce_revocation(const RevocationSet& set, std::uint32_t site_epoch,
                                    MonotonicMs now_ms) noexcept = 0;
  // Retire every member-scoped RAM/RTC context, TX, group callback and
  // queued job before persistent erasure. Default refuses until wired.
  virtual Status remove_member_runtime() noexcept {
    return Status::error(StatusCode::Unsupported, "removal runtime not wired");
  }
  // Erase/read back only the site's two RLT1 blobs and clear its RAM view.
  virtual Status erase_site_trust() noexcept {
    return Status::error(StatusCode::Unsupported, "site trust erasure not wired");
  }
  // Cutover must retire old RAM/RTC contexts and all pending traffic, without
  // erasing the device identity or the new site trust. No implicit fallback.
  virtual Status retire_network() noexcept {
    return Status::error(StatusCode::Unsupported, "network retirement not wired");
  }
  virtual Status install_site_trust(const SiteRecord&) noexcept {
    return Status::error(StatusCode::Unsupported, "site trust install not wired");
  }
};

struct LifecyclePorts {
  LifecycleAuthorityPort& authority;
  LifecyclePeerPort& peer;
  LifecycleRuntimePort& runtime;
  EntropySource& entropy;
  RrsObjectSink& object_sink;
  LifecycleObserver* observer{nullptr};  // nullable
};

enum class LifecycleProfile : std::uint8_t {
  Node = 0,     // RLP1 geometry: exactly 16 slots (05 §3.2)
  Gateway = 1,  // RLP1 geometry: exactly 160 slots
};

struct LifecycleConfig {
  NodeId self{kInvalidNodeId};  // must match the RLI1 node id
  LifecycleProfile profile{LifecycleProfile::Node};
  // CapabilityFeature bits this build wires (04 §capabilities): gossip
  // transmission requires kCapRrsGossipV1, otherwise the lifecycle still
  // accepts and applies RRS1 but stays silent on the gossip lane.
  std::uint32_t enabled_features{0};
};

// Point-in-time view: phase, adopted network, applied epochs, the
// outstanding fetch target, store health and saturating counters. No
// secrets, no raw wire, no keys.
struct LifecycleSnapshot {
  LifecyclePhase phase{LifecyclePhase::BootGate};
  NetworkId adopted_network{0};
  std::uint32_t site_commit_seq{0};
  std::uint32_t own_generation{0};
  std::uint32_t applied_rs_epoch{0};
  std::uint32_t applied_gk_epoch{0};
  std::uint32_t rs_epoch_to_fetch{0};
  std::uint64_t policy_revision{0};
  bool stores_healthy{false};
  bool action_pending{false};
  bool equivocated{false};
  std::uint32_t rrs_applied{0};
  std::uint32_t rrs_duplicates{0};
  std::uint32_t rrs_stale{0};
  std::uint32_t rrs_failed{0};
  std::uint32_t equivocations{0};
  std::uint32_t gossip_state_sent{0};
  std::uint32_t gossip_requests_sent{0};
  std::uint32_t gossip_dropped{0};
  std::uint32_t fetches_started{0};
  std::uint32_t fetches_done{0};
  std::uint32_t fetch_failures{0};
  std::uint32_t authority_gets_sent{0};
  std::uint32_t authority_acks_sent{0};
  std::uint32_t recoveries{0};
  std::uint32_t clock_regressions{0};
  std::uint64_t holdoff_remaining_ms{0};
};

class MembershipLifecycle final {
 public:
  MembershipLifecycle(const LifecycleConfig& config, IdentityStore& identity, SiteStore& site,
                      RevocationStore& revocations, ResumeCache& resume, LifecyclePorts& ports,
                      const Es256Verifier& verifier = default_es256_verifier(),
                      LifecycleStore* journal = nullptr) noexcept;

  // Accepts one input; success means "received", never "durably done" —
  // completion shows in the phase, the pending action and the ACKs. Busy
  // (with zero state change, not even counters) when called back
  // re-entrantly from a port/storage/observer callback.
  Status dispatch(const LifecycleInput& input, MonotonicMs now_ms) noexcept;
  // Takes the single outstanding Owner action (NotFound when empty). Taking
  // does not advance the FSM; progress needs ActionComplete.
  Status take_action(LifecycleAction& action) noexcept;
  LifecycleSnapshot snapshot() const noexcept;
  // Pure traffic gate over the adopted policy: no side effects, callable
  // any time (including while another call is in flight).
  bool permits(const PeerCredentialStamp& stamp, TrafficUse use) const noexcept;
  bool quiescent() const noexcept;
  // Next gossip/exchange work, or UINT64_MAX when nothing is scheduled.
  MonotonicMs next_deadline() const noexcept;

 private:
  enum class ApplyStep : std::uint8_t { Verify, Store, Enforce, Sweep, Floor, Done };
  enum class CandidateSource : std::uint8_t { None, Authority, Gossip, Stored };
  enum class RemovalStep : std::uint8_t { Runtime, Resume, Trust, Site, Revocation, Finish };

  struct Neighbor {
    // u64 fields first: the entry must stay <= 40 B (32 x 40 = 1280 B).
    NodeId node{kInvalidNodeId};
    MonotonicMs request_not_before{0};  // 60 s rate per peer (kept on rebind)
    MonotonicMs notify_due{0};
    std::uint32_t binding{0};
    std::uint32_t advertised_rs{0};
    std::uint32_t advertised_gk{0};
    bool used{false};
  };
  static_assert(sizeof(Neighbor) <= 40, "gossip neighbor bound: 32 x <=40 B");

  struct Adopted {
    bool identity_ok{false};
    bool site_ok{false};
    std::uint64_t site_id{0};
    NetworkId network{0};
    std::uint32_t generation{0};
    std::uint32_t site_commit_seq{0};
    std::uint32_t rs_floor{0};
    std::uint32_t gk_epoch{0};
    bool has_rrs{false};
    std::uint32_t rs_epoch{0};
  };

  // dispatch() bodies (in_call_ already held).
  Status on_boot(const LifecycleBootEvidence& evidence, MonotonicMs now_ms) noexcept;
  Status on_poll(MonotonicMs now_ms) noexcept;
  Status on_member_ready(const LifecycleMemberReady& ready, MonotonicMs now_ms) noexcept;
  Status on_authority(const LifecycleAuthorityMessage& message, MonotonicMs now_ms) noexcept;
  Status on_peer_control(const LifecyclePeerControl& control, MonotonicMs now_ms) noexcept;
  Status on_completed(const LifecycleCompletedObject& completed, MonotonicMs now_ms) noexcept;
  Status on_link_failure(const LifecycleLinkFailure& failure, MonotonicMs now_ms) noexcept;
  Status on_recovery(const LifecycleJoinRecovery& recovery, MonotonicMs now_ms) noexcept;
  Status on_action_complete(const LifecycleActionComplete& done, MonotonicMs now_ms) noexcept;
  Status on_stop(MonotonicMs now_ms) noexcept;
  Status on_removal(ByteView notice, MonotonicMs now_ms) noexcept;
  Status removal_poll(MonotonicMs now_ms) noexcept;
  bool removal_proof_valid(const LifecycleRecord& record) noexcept;
  Status on_renew(ByteView body, MonotonicMs now_ms) noexcept;
  Status renew_prepare(ByteView body) noexcept;
  Status renew_commit(ByteView body, MonotonicMs now_ms) noexcept;
  bool staged_site(const LifecycleRecord& record, SiteRecord& out) noexcept;
  bool switching_proof(const LifecycleRecord& record, SiteRecord& out,
                       RevocationSet& rrs) noexcept;
  Status switch_poll(MonotonicMs now_ms) noexcept;
  bool restore_applied_receipt() noexcept;
  void send_renew_receipt(GrantRenewPhase phase, ByteView digest) noexcept;

  LifecycleBlockReason adopt_stores() noexcept;
  Status begin_apply(ByteView object, CandidateSource source, NodeId peer,
                     MonotonicMs now_ms) noexcept;
  Status apply_poll(MonotonicMs now_ms) noexcept;
  Status apply_verify(MonotonicMs now_ms) noexcept;
  Status apply_store(MonotonicMs now_ms) noexcept;
  Status apply_enforce(MonotonicMs now_ms) noexcept;
  Status apply_sweep(MonotonicMs now_ms) noexcept;
  Status apply_floor(MonotonicMs now_ms) noexcept;
  Status apply_done(MonotonicMs now_ms) noexcept;
  void abort_apply(LifecyclePhase resume) noexcept;
  bool self_rejected() const noexcept;

  void observe_epochs(NodeId peer, std::uint32_t binding, const StateEpochs& epochs,
                      MonotonicMs now_ms) noexcept;
  void on_request(NodeId peer, std::uint32_t binding, const RrsRequest& request,
                  MonotonicMs now_ms) noexcept;
  void gossip_poll(MonotonicMs now_ms) noexcept;
  void send_state_epochs(Neighbor& neighbor, MonotonicMs now_ms) noexcept;
  void send_request(Neighbor& neighbor, MonotonicMs now_ms) noexcept;
  void clear_fetch(bool failed, MonotonicMs now_ms) noexcept;
  void queue_applied_ack(std::uint32_t rs_epoch, const autonomy::ObjectHash& hash,
                         MonotonicMs now_ms) noexcept;
  void send_pending_ack(MonotonicMs now_ms) noexcept;
  void send_authority_get(MonotonicMs now_ms) noexcept;
  void need_authority_rrs(MonotonicMs now_ms) noexcept;
  void enter_recovering(LifecycleActionReason reason, MonotonicMs now_ms) noexcept;
  void enter_storage_blocked(LifecycleBlockReason reason, MonotonicMs now_ms) noexcept;
  Status adopt_and_enter(MonotonicMs now_ms) noexcept;
  bool need_rrs() const noexcept;
  bool gossip_tx_enabled() const noexcept {
    return (config_.enabled_features & kCapRrsGossipV1) != 0;
  }
  std::uint32_t site_epoch() const noexcept {
    return static_cast<std::uint32_t>(adopted_.network >> 32U);
  }
  void emit_action(LifecycleActionTag tag, LifecycleActionReason reason) noexcept;
  void notify(LifecycleEventKind kind, NodeId peer, std::uint32_t epoch, std::uint32_t detail,
              MonotonicMs now_ms) noexcept;
  void refresh_snapshot() noexcept;
  bool bump_policy() noexcept;
  static void saturate_inc(std::uint32_t& counter) noexcept {
    if (counter < 0xFFFFFFFFu) ++counter;
  }

  struct Counters {
    std::uint32_t rrs_applied{0};
    std::uint32_t rrs_duplicates{0};
    std::uint32_t rrs_stale{0};
    std::uint32_t rrs_failed{0};
    std::uint32_t equivocations{0};
    std::uint32_t gossip_state_sent{0};
    std::uint32_t gossip_requests_sent{0};
    std::uint32_t gossip_dropped{0};
    std::uint32_t fetches_started{0};
    std::uint32_t fetches_done{0};
    std::uint32_t fetch_failures{0};
    std::uint32_t authority_gets_sent{0};
    std::uint32_t authority_acks_sent{0};
    std::uint32_t recoveries{0};
    std::uint32_t clock_regressions{0};
  };

  LifecycleConfig config_{};
  IdentityStore& identity_;
  SiteStore& site_;
  RevocationStore& revocations_;
  ResumeCache& resume_;
  LifecycleStore* journal_{nullptr};
  LifecyclePorts& ports_;
  const Es256Verifier& verifier_;
  RrsExchange exchange_;

  LifecyclePhase phase_{LifecyclePhase::BootGate};
  LifecyclePhase resume_phase_{LifecyclePhase::Active};
  bool in_call_{false};
  Adopted adopted_{};
  P256PublicKey sak_{};
  bool sak_valid_{false};
  std::uint64_t policy_revision_{0};
  bool equivocated_{false};
  bool self_revoked_{false};
  RemovalStep removal_step_{RemovalStep::Runtime};
  std::size_t removal_cursor_{0};
  MonotonicMs holdoff_start_{0};
  std::size_t switch_cursor_{0};
  std::uint8_t switch_step_{0};
  GrantReceipt applied_receipt_{};
  bool applied_receipt_pending_{false};

  LifecycleAction action_{};
  bool action_pending_{false};
  std::uint64_t next_token_{1};

  // ApplyingRrs workspace (owned copies: inputs are call-scoped).
  ByteBuffer<kRevocationObjectMax> candidate_object_{};
  // Re-read scratch for the stored set bytes (duplicate compare, serving).
  ByteBuffer<kRevocationObjectMax> stored_object_{};
  RevocationSet candidate_set_{};
  RevocationSet verified_store_set_{};
  CandidateSource candidate_source_{CandidateSource::None};
  NodeId candidate_peer_{kInvalidNodeId};
  ApplyStep apply_step_{ApplyStep::Verify};
  std::size_t sweep_cursor_{0};
  std::uint8_t sweep_attempts_{0};

  // Gossip state.
  std::array<Neighbor, rrs_const::kNeighborMax> neighbors_{};
  std::size_t gossip_cursor_{0};
  MonotonicMs next_gossip_allowed_{0};
  bool fetch_outstanding_{false};
  NodeId fetch_peer_{kInvalidNodeId};
  std::uint32_t fetch_wanted_{0};
  MonotonicMs fetch_deadline_{0};
  std::uint32_t rs_to_fetch_{0};
  MonotonicMs next_get_allowed_{0};
  bool pending_ack_{false};
  std::uint32_t pending_ack_epoch_{0};
  std::array<std::uint8_t, 32> pending_ack_hash_{};
  MonotonicMs pending_ack_due_{0};
  MonotonicMs last_now_{0};
  Counters counters_{};

  LifecycleSnapshot snapshot_{};
};

// P6 coordinator RAM ceiling (04 §4): exchange + gossip + workspaces, the
// caller-owned stores excluded.
static_assert(sizeof(MembershipLifecycle) <= 8192, "P6 coordinator RAM bound");

}  // namespace routeloom::sdkv1
