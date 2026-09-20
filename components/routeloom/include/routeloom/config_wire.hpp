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
// Frame discipline: Control (22) carries the versioned challenge/status
// payloads (subtype 1-4); ControlObject/ObjectChunk/ObjectAck (49/50/51)
// carry the kind-3 permit object. All are end-protected and routed — the
// link-scoped autonomous forms of 49/50/51 (migration kinds 1/2) are a
// separate, unchanged path.

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/autonomy_wire.hpp"
#include "routeloom/config.hpp"
#include "routeloom/endpoint_wire.hpp"
#include "routeloom/node.hpp"
#include "routeloom/status.hpp"
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

// --- ConfigTarget (config-bearing node) ------------------------------------
//
// Bounded set of ConfigJournals behind one routed endpoint. Control frames
// are dispatched to the journal for the decoded namespace; ConfigPermit
// object manifests/chunks drive one bounded reassembly at a time (the v1
// manifest does not name a namespace, so object intake binds the primary —
// first registered — journal; a permit whose decoded namespace does not
// match is refused by that journal's own validation). Every accepted
// manifest/chunk is answered with an ObjectAck to the end-authenticated
// origin: received_len + status, never a config verdict.
class ConfigTarget final : public ConfigEndpointSink {
 public:
  explicit ConfigTarget(ConfigWirePort& wire) noexcept : wire_(wire) {}

  // Register a journal for `config_namespace` (must match the journal's own
  // ConfigJournalConfig). Up to kMaxJournals; the FIRST registered is the
  // object-intake journal. Journals are caller-owned and must outlive this.
  Status add_journal(std::uint16_t config_namespace, ConfigJournal& journal) noexcept;

  // ConfigEndpointSink
  void on_config_frame(NodeId peer, const wire::PlainFrame& frame,
                       MonotonicMs now_ms) noexcept override;
  void on_config_job_done(const MessageId& id, bool hop_accepted,
                          const char* reason, MonotonicMs now_ms) noexcept override;
  void poll(MonotonicMs now_ms) noexcept override;

  // Diagnostics surface.
  std::uint32_t control_denied() const noexcept { return control_denied_; }
  std::uint32_t object_acks() const noexcept { return object_acks_; }
  bool object_active() const noexcept { return intake_.active; }

 private:
  struct Intake {
    bool active{false};
    ConfigJournal* journal{nullptr};
    autonomy::ObjectHash hash{};
    std::uint16_t total_len{0};
    std::uint16_t received{0};
    MonotonicMs started_ms{0};
    // Mirror of the distinct received bytes so the ObjectAck's
    // received_len is honest even across duplicate/out-of-order chunks.
    std::array<std::uint8_t, kConfigPermitObjectMax / 8> bitmap{};
  };

  ConfigJournal* find_journal(std::uint16_t config_namespace) noexcept;
  void handle_control(NodeId peer, const wire::PlainFrame& frame,
                      MonotonicMs now_ms) noexcept;
  void handle_manifest(NodeId peer, const wire::PlainFrame& frame,
                       MonotonicMs now_ms) noexcept;
  void handle_chunk(NodeId peer, const wire::PlainFrame& frame,
                    MonotonicMs now_ms) noexcept;
  void send_ack(NodeId dest, const autonomy::ObjectHash& hash,
                std::uint16_t received_len, autonomy::ObjectAckStatus status,
                MonotonicMs now_ms) noexcept;
  std::uint16_t bitmap_count() const noexcept;

  ConfigWirePort& wire_;
  std::array<ConfigJournal*, config_wire_const::kMaxJournals> journals_{};
  std::array<std::uint16_t, config_wire_const::kMaxJournals> namespaces_{};
  std::size_t journal_count_{0};
  Intake intake_{};
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

// One outstanding challenge or status query, plus one outstanding permit
// transfer — the single-transaction bound the design fixes. The USB bridge
// calls submit_*; the replies arrive on on_config_frame and are reported to
// the host once, correlated by the original request id.
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
  // 0x21 ConfigPermit: transfer `permit` (the signed object, <=1024 B) to
  // `target` as a kind-3 manifest+chunk exchange; resolves on the ack.
  Status submit_permit(std::uint64_t request, NodeId target, ByteView permit,
                       MonotonicMs now_ms) noexcept;

  // ConfigEndpointSink
  void on_config_frame(NodeId peer, const wire::PlainFrame& frame,
                       MonotonicMs now_ms) noexcept override;
  void on_config_job_done(const MessageId& id, bool hop_accepted,
                          const char* reason, MonotonicMs now_ms) noexcept override;
  void poll(MonotonicMs now_ms) noexcept override;

  bool query_active() const noexcept { return query_.active; }
  bool transfer_active() const noexcept { return transfer_.active; }
  std::uint32_t replies_reported() const noexcept { return replies_reported_; }

 private:
  enum class QueryExpect : std::uint8_t { None, Challenge = 2, Status = 4 };
  struct PendingQuery {
    bool active{false};
    std::uint64_t request{0};
    NodeId target{kInvalidNodeId};
    std::uint8_t usb_sub{0};      // 0x22 status / 0x23 challenge
    QueryExpect expect{QueryExpect::None};
    MonotonicMs deadline_ms{0};
  };
  enum class TransferPhase : std::uint8_t { Chunks, AwaitAck };
  struct PermitTransfer {
    bool active{false};
    std::uint64_t request{0};
    NodeId target{kInvalidNodeId};
    autonomy::ObjectHash hash{};
    std::uint16_t next_offset{0};      // next byte to send (chunks phase)
    std::uint16_t object_size{0};
    TransferPhase phase{TransferPhase::Chunks};
    MonotonicMs deadline_ms{0};
    ByteBuffer<kConfigPermitObjectMax> object{};
  };

  void pump_transfer(MonotonicMs now_ms) noexcept;
  void finish_query(ConfigOpsResult result, ByteView body,
                    MonotonicMs now_ms) noexcept;
  void finish_transfer(ConfigOpsResult result, MonotonicMs now_ms) noexcept;

  ConfigWirePort& wire_;
  ConfigHostSink& host_;
  PendingQuery query_{};
  PermitTransfer transfer_{};
  std::uint32_t replies_reported_{0};
};

}  // namespace routeloom
