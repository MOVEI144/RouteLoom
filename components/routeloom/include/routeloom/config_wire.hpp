#pragma once

// Routed config transport glue (docs/design/scope-gateway-config/
// 04-remote-config.md §5, 05-wire-api.md §5.5/§5.6). Sits between the
// MeshNode end-protected routed lane (ConfigEndpointSink) and the portable
// ConfigJournal: nothing here trusts the transport — the journal still
// runs the real ConfigAuthorityVerifier, CAS and maintenance gate on every
// permit it assembles.
//
// Two roles share the file:
//   - ConfigTarget  : a config-bearing node. Routes terminal Control
//     (challenge/status) and ConfigPermit object (manifest/chunk) frames to
//     its ConfigJournals and emits the Control/ObjectAck replies.
//   - ConfigGateway : a bridge node. Issues challenge/status queries and
//     ConfigPermit transfers toward a target on behalf of the USB host and
//     reports each outcome through ConfigHostSink.
//
// Frame discipline: Control (22) carries the versioned query/reply
// payloads (subtype 1-4 challenge/status, 5/6 trust status, 7/8 recovery
// info); ControlObject/ObjectChunk/ObjectAck (49/50/51) carry ONE bounded
// object reassembly at a time — kind 3 (permit), kind 4 (recovery) or
// kind 5 (trust manifest) — dispatched by kind on completion. A stalled
// permit assembly never blocks recovery or trust for longer than the 10 s
// assembly bound, and while impaired kind 3 cannot reserve the slot at
// all. All are end-protected and routed — the link-scoped autonomous
// forms of 49/50/51 (migration kinds 1/2) are a separate, unchanged path.

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/autonomy_wire.hpp"
#include "routeloom/config.hpp"
#include "routeloom/endpoint_wire.hpp"
#include "routeloom/node.hpp"
#include "routeloom/security_floor.hpp"
#include "routeloom/status.hpp"
#include "routeloom/trust_manifest.hpp"
#include "routeloom/trust_store.hpp"
#include "routeloom/types.hpp"
#include "routeloom/usb_host_ops.hpp"
#include "routeloom/wire.hpp"

namespace routeloom {

// The wire result code the config endpoint reports (0x20-0x23 replies) —
// defined beside the other HostOps result enums. Imported here so the mesh
// components and the USB bridge share one value space.
using usb::ConfigOpsResult;

namespace config_wire_const {
constexpr std::size_t kMaxJournals = kConfigNamespaceLimit;      // 4
constexpr std::uint16_t kChunkDataMax =
    kMaxApplicationPayload - autonomy::kObjectChunkHeaderSize;   // 90
// Query (challenge/status) round-trip and full permit-transfer budgets.
// The target's own reassembly window is kConfigReassemblyTimeoutMs (10 s);
// the transfer budget leaves room for manifest+chunks plus the ack.
constexpr std::uint32_t kQueryTimeoutMs = 3000;
constexpr std::uint32_t kPermitTimeoutMs = 15000;
constexpr std::uint32_t kControlLifetimeMs = 4000;  // routed hop-accept TTL
}  // namespace config_wire_const

// Send surface the config endpoints need from the node layer: one
// end-protected routed frame of `type` to `dest`, payload already encoded.
// MeshConfigPort implements it over MeshNode::send_typed; tests substitute a
// fake so the components never need a radio.
class ConfigWirePort {
 public:
  virtual ~ConfigWirePort() = default;
  virtual Status config_send(NodeId dest, FrameType type, ByteView payload,
                             MonotonicMs now_ms) noexcept = 0;
};

// MeshNode adapter for ConfigWirePort.
class MeshConfigPort final : public ConfigWirePort {
 public:
  explicit MeshConfigPort(MeshNode& node) noexcept : node_(node) {}
  Status config_send(NodeId dest, FrameType type, ByteView payload,
                     MonotonicMs now_ms) noexcept override {
    MessageId id{};
    return node_.send_typed(type, dest, payload,
                            config_wire_const::kControlLifetimeMs, now_ms, id);
  }

 private:
  MeshNode& node_;
};

constexpr std::size_t kConfigTrustObjectMax =
    autonomy::kAuthenticatedObjectMax;  // kind-5 RTM1 intake cap (2048)

// --- ConfigTarget (config-bearing node) ------------------------------------
//
// Bounded set of ConfigJournals behind one routed endpoint. Control frames
// are dispatched to the journal for the decoded namespace (trust status is
// answered from the attached trust store instead); object manifests/chunks
// drive the single bounded assembler below. Completion dispatches by kind:
// kind 3 → the owning journal's submit_permit, kind 4 → submit_recovery,
// kind 5 → trust_manifest_accept (never a journal). Every accepted
// manifest/chunk is answered with an ObjectAck to the end-authenticated
// origin: received_len + status, never a config verdict.
class ConfigTarget final : public ConfigEndpointSink {
 public:
  // `limiter` MUST be the same device-wide limiter the journals use: the
  // kind-5 trust-manifest verify shares the expensive-verify budget with
  // the permit/recovery submits (failures charged too). Caller-owned, like
  // the wire port; both must outlive this.
  ConfigTarget(ConfigWirePort& wire, ConfigRateLimiter& limiter) noexcept
      : wire_(wire), limiter_(limiter) {}

  // Register a journal for `config_namespace` (must match the journal's own
  // ConfigJournalConfig). Up to kMaxJournals. The v1 manifest does not name
  // a namespace, so intake offers the object to the journals in
  // registration order; a permit whose decoded namespace does not match is
  // refused by the owning journal's own validation. Journals are
  // caller-owned and must outlive this.
  Status add_journal(std::uint16_t config_namespace, ConfigJournal& journal) noexcept;
  // Attach the trust-management connection kind-5 intake and the trust
  // status query answer from. Optional: without it kind-5 manifests are
  // refused and subtype-5 queries denied. Caller-owned; must outlive this.
  void attach_trust_store(TrustStore& store, SecurityFloorStore& floor) noexcept;

  // ConfigEndpointSink
  void on_config_frame(NodeId peer, const wire::PlainFrame& frame,
                       MonotonicMs now_ms) noexcept override;
  void on_config_job_done(const MessageId& id, bool hop_accepted,
                          const char* reason, MonotonicMs now_ms) noexcept override;
  void poll(MonotonicMs now_ms) noexcept override;
  std::uint32_t permit_profile_bits() const noexcept override {
    // M1 selects one profile globally; OR over ready journals still yields
    // a single bit. An unprovisioned verifier contributes nothing.
    std::uint32_t bits = 0;
    for (std::size_t i = 0; i < journal_count_; ++i) {
      bits |= journals_[i]->permit_profile_bits();
    }
    return bits;
  }

  // Diagnostics surface.
  std::uint32_t control_denied() const noexcept { return control_denied_; }
  std::uint32_t object_acks() const noexcept { return object_acks_; }
  bool object_active() const noexcept { return assembly_.active; }

 private:
  // The single bounded assembler: one object at a time, keyed by the
  // pinned (origin, kind, hash, total_len) tuple. Kind caps differ —
  // kind 3/4 ride the 1024 B permit bound, kind 5 the full 2048 B carrier
  // — but the buffer and bitmap are shared: a second buffer for recovery
  // would only double the worst-case RAM for no liveness gain (a stalled
  // assembly frees at the 10 s bound, and while impaired kind 3 cannot
  // reserve the slot at all).
  struct Assembly {
    bool active{false};
    autonomy::ControlObjectKind kind{autonomy::ControlObjectKind::ConfigPermit};
    NodeId origin{kInvalidNodeId};
    ConfigJournal* journal{nullptr};  // owner for kind 3/4; null for kind 5
    autonomy::ObjectHash hash{};
    std::uint16_t total_len{0};
    std::uint16_t received{0};
    MonotonicMs started_ms{0};
    std::array<std::uint8_t, kConfigTrustObjectMax> buffer{};
    std::array<std::uint8_t, kConfigTrustObjectMax / 8> bitmap{};
  };

  ConfigJournal* find_journal(std::uint16_t config_namespace) noexcept;
  void handle_control(NodeId peer, const wire::PlainFrame& frame,
                      MonotonicMs now_ms) noexcept;
  void handle_trust_status_query(NodeId origin,
                                 const wire::PlainFrame& frame,
                                 MonotonicMs now_ms) noexcept;
  void handle_manifest(NodeId peer, const wire::PlainFrame& frame,
                       MonotonicMs now_ms) noexcept;
  void handle_chunk(NodeId peer, const wire::PlainFrame& frame,
                    MonotonicMs now_ms) noexcept;
  // Digest-check the completed assembly and dispatch by kind; frees the
  // slot either way (a refused completion is not resumable).
  void dispatch_complete(MonotonicMs now_ms) noexcept;
  void drop_assembly() noexcept;
  void send_ack(NodeId dest, const autonomy::ObjectHash& hash,
                std::uint16_t received_len, autonomy::ObjectAckStatus status,
                MonotonicMs now_ms) noexcept;

  ConfigWirePort& wire_;
  ConfigRateLimiter& limiter_;
  TrustStore* trust_{nullptr};
  SecurityFloorStore* trust_floor_{nullptr};
  std::array<ConfigJournal*, config_wire_const::kMaxJournals> journals_{};
  std::array<std::uint16_t, config_wire_const::kMaxJournals> namespaces_{};
  std::size_t journal_count_{0};
  Assembly assembly_{};
  std::uint32_t control_denied_{0};
  std::uint32_t object_acks_{0};
};

// --- ConfigGateway (bridge node) --------------------------------------------
//
// Reports one config operation's outcome to the USB host. `sub` is the
// HostOps subcommand the reply is framed under (0x21 permit / 0x22 status /
// 0x23 challenge); `body` is the reply payload after the u16 result —
// the raw ControlStatus (72 B) or ControlChallenge (92 B) on a successful
// query, empty otherwise. The bridge encodes and frames it.
class ConfigHostSink {
 public:
  virtual ~ConfigHostSink() = default;
  virtual void on_config_reply(std::uint64_t request, std::uint8_t sub,
                               ConfigOpsResult result, NodeId target,
                               ByteView body, MonotonicMs now_ms) noexcept = 0;
};

// One outstanding query, plus one outstanding transfer per object kind —
// the single-transaction bound the design fixes. The USB bridge calls
// submit_*; the replies arrive on on_config_frame and are reported to the
// host once, correlated by the original request id.
class ConfigGateway final : public ConfigEndpointSink {
 public:
  ConfigGateway(ConfigWirePort& wire, ConfigHostSink& host) noexcept
      : wire_(wire), host_(host) {}

  // 0x20 ConfigQuery: issue a StatusQuery3 for (target, ns, operation_id).
  // Busy while any query is outstanding.
  Status submit_status_query(std::uint64_t request, NodeId target,
                             std::uint16_t config_namespace,
                             const std::array<std::uint8_t, 16>& operation_id,
                             MonotonicMs now_ms) noexcept;
  // 0x23 ConfigChallenge: issue a ChallengeQuery1.
  Status submit_challenge(std::uint64_t request, NodeId target,
                          std::uint16_t config_namespace, std::uint16_t schema,
                          const std::array<std::uint8_t, 16>& client_nonce,
                          MonotonicMs now_ms) noexcept;
  // 0x26 TrustStatus: issue a TrustStatusQuery5. `network` binds the
  // reply: a TrustStatus naming any other network is foreign, never this
  // query's completion.
  Status submit_trust_status_query(std::uint64_t request, NodeId target,
                                   NetworkId network,
                                   const std::array<std::uint8_t, 16>& nonce,
                                   MonotonicMs now_ms) noexcept;
  // 0x27 RecoveryInfo: issue a RecoveryInfoQuery7 for (target, ns).
  // `network` binds the reply like the trust query above.
  Status submit_recovery_info_query(std::uint64_t request, NodeId target,
                                    NetworkId network,
                                    std::uint16_t config_namespace,
                                    const std::array<std::uint8_t, 16>& nonce,
                                    MonotonicMs now_ms) noexcept;
  // 0x21 ConfigPermit: transfer `permit` (the signed object, <=1024 B) to
  // `target` as a kind-3 manifest+chunk exchange; resolves on the ack.
  Status submit_permit(std::uint64_t request, NodeId target, ByteView permit,
                       MonotonicMs now_ms) noexcept;
  // 0x24 ConfigRecover: the same manifest+chunk pump for a signed recovery
  // object on the kind-4 lane — the reply reports under sub 0x24. Runs on
  // its own transfer slot so a permit transfer in flight never holds the
  // recovery a quarantined target is waiting for.
  Status submit_recovery(std::uint64_t request, NodeId target, ByteView object,
                         MonotonicMs now_ms) noexcept;
  // 0x25 ConfigTrust: the same pump for a signed trust-manifest (RTM1)
  // object (<=2048 B) on the kind-5 lane — the reply reports under sub
  // 0x25. Its own slot, so trust delivery never waits on config traffic.
  Status submit_trust(std::uint64_t request, NodeId target, ByteView object,
                      MonotonicMs now_ms) noexcept;

  // ConfigEndpointSink
  void on_config_frame(NodeId peer, const wire::PlainFrame& frame,
                       MonotonicMs now_ms) noexcept override;
  void on_config_job_done(const MessageId& id, bool hop_accepted,
                          const char* reason, MonotonicMs now_ms) noexcept override;
  void poll(MonotonicMs now_ms) noexcept override;

  bool query_active() const noexcept { return query_.active; }
  bool transfer_active() const noexcept { return transfer_.active; }
  bool recovery_transfer_active() const noexcept {
    return recovery_transfer_.active;
  }
  bool trust_transfer_active() const noexcept {
    return trust_transfer_.active;
  }
  std::uint32_t replies_reported() const noexcept { return replies_reported_; }

 private:
  enum class QueryExpect : std::uint8_t {
    None,
    Challenge = 2,
    Status = 4,
    TrustStatus = 6,
    RecoveryInfo = 8,
  };
  struct PendingQuery {
    bool active{false};
    std::uint64_t request{0};
    NodeId target{kInvalidNodeId};
    std::uint8_t usb_sub{0};  // 0x22 status / 0x23 challenge / 0x26 / 0x27
    QueryExpect expect{QueryExpect::None};
    MonotonicMs deadline_ms{0};
    // Reply binding (05 §5.5): the client_nonce / operation_id / query
    // nonce as SENT — an end-authenticated reply that doesn't echo them
    // is a foreign frame, never this query's completion. The trust and
    // recovery queries additionally bind the full network below.
    std::array<std::uint8_t, 16> echo{};
    std::uint16_t config_namespace{0};
    NetworkId network{0};
  };
  enum class TransferPhase : std::uint8_t { Chunks, AwaitAck };
  // One manifest+chunk transfer slot, sized by the kind it carries (1024
  // for kind 3/4, 2048 for kind 5). The pump below is shared — the size
  // parameter only bounds the staging buffer.
  template <std::size_t N>
  struct TransferSlot {
    bool active{false};
    std::uint64_t request{0};
    NodeId target{kInvalidNodeId};
    autonomy::ObjectHash hash{};
    std::uint8_t usb_sub{0};
    std::uint16_t next_offset{0};  // next byte to send (chunks phase)
    std::uint16_t object_size{0};
    TransferPhase phase{TransferPhase::Chunks};
    MonotonicMs deadline_ms{0};
    ByteBuffer<N> object{};
  };

  // Shared manifest+chunk pump for one transfer slot of any kind: the
  // slot's buffer size caps the object, so a kind can never overflow the
  // slot it was given.
  template <std::size_t N>
  void pump_transfer(TransferSlot<N>& transfer, MonotonicMs now_ms) noexcept;
  template <std::size_t N>
  void start_transfer(TransferSlot<N>& transfer, std::uint64_t request,
                      NodeId target, autonomy::ControlObjectKind kind,
                      ByteView object, MonotonicMs now_ms,
                      Status& out) noexcept;
  void finish_query(ConfigOpsResult result, ByteView body,
                    MonotonicMs now_ms) noexcept;
  template <std::size_t N>
  void finish_transfer(TransferSlot<N>& transfer, ConfigOpsResult result,
                       MonotonicMs now_ms) noexcept;
  template <std::size_t N>
  void resolve_transfer_ack(TransferSlot<N>& transfer,
                            const autonomy::ObjectAckPayload& ack,
                            MonotonicMs now_ms) noexcept;

  ConfigWirePort& wire_;
  ConfigHostSink& host_;
  PendingQuery query_{};
  TransferSlot<kConfigPermitObjectMax> transfer_{};
  TransferSlot<kConfigPermitObjectMax> recovery_transfer_{};
  TransferSlot<kConfigTrustObjectMax> trust_transfer_{};
  std::uint32_t replies_reported_{0};
};

}  // namespace routeloom
