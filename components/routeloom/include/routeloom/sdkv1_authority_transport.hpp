#pragma once

// Authority-channel mesh transport (G-SEC P5, 03-key-hierarchy.md §5.3).
//
// Carriers move between a device AuthorityClient and the site gateway over
// the routed end-protected mesh: small carriers (R1/R2/R3/Wake and
// envelopes up to 120 B) ride one FrameType::Control frame with the
// AuthorityCarrier head below; larger envelopes ride a
// ControlObjectKind::AuthorityEnvelope (kind 7) 49/50/51 object transfer
// verbatim (28..2048 B). A gateway relays opaque carrier bytes between
// the mesh and USB 0x64/0x65 without decrypting them; its own channel
// bypasses the mesh and talks USB directly (hops=0).
//
// Numbering collisions with the design text (recorded here, not silently
// redefined): the design's Control subtype 5 was already
// trust-status-query on this wire, so the carrier takes the next free
// end-protected Control subtype 9; the design's object kind 5 was already
// TrustManifest (and 6 RevocationSet), so the envelope object is kind 7.
// protocol/semantics.json registers both.
//
// Portable-core discipline: no heap, no exceptions, every API noexcept,
// all state bounded and owned by the instance. Receive intake
// (on_control/on_manifest/on_chunk/on_ack) only copies into bounded slots
// and is safe in the node RX callback; the Owner drains completions
// (take_rx/take_tx_result) and drives retries (poll) from its own poll.

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/autonomy_wire.hpp"
#include "routeloom/config_wire.hpp"
#include "routeloom/rlres1.hpp"
#include "routeloom/sdkv1_authority.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"
#include "routeloom/usb_host_ops.hpp"
#include "routeloom/wire.hpp"

namespace routeloom::sdkv1 {

// Next free end-protected Control-22 subtype (1..8 are config/trust
// queries; see config_wire.cpp). Unknown subtypes keep their existing
// deny-and-drop.
constexpr std::uint8_t kAuthorityControlSubtype = 9;
// Carrier head: v:u8=1 | sub:u8=9 | kind:u8 (1..5) | reserved:u8=0 |
// exchange_id:u32, then the carrier body.
constexpr std::size_t kAuthorityCarrierHeadSize = 8;
// One Control frame carries 128 B, so a carrier body above this rides a
// kind-7 object instead.
constexpr std::size_t kAuthorityCarrierBodyMax = 120;
// Full envelope ceiling on every leg (mesh object, USB fragments).
constexpr std::size_t kAuthorityObjectMax = 2048;
// Single-transfer retry budget: one outstanding chunk, resent every
// 500 ms up to 4 sends; the whole transfer aborts at 15 s.
constexpr MonotonicMs kAuthorityChunkResendMs = 500;
constexpr std::uint8_t kAuthorityChunkSendsMax = 4;
constexpr MonotonicMs kAuthorityTransferTimeoutMs = 15000;
constexpr MonotonicMs kAuthorityReassemblyTimeoutMs = 10000;

// Carrier body lengths: R1 without/with ticket, R2 ok/short, R3,
// envelope bounds, Wake. Anything else is a framing error, never a
// channel input.
constexpr bool authority_carrier_length_valid(AuthorityCarrierKind kind,
                                              std::size_t size) noexcept {
  switch (kind) {
    case AuthorityCarrierKind::R1:
      return size >= rlres1::kR1BaseSize && size <= rlres1::kR1MaxSize;
    case AuthorityCarrierKind::R2:
      return size == rlres1::kR2Size || size == 12;
    case AuthorityCarrierKind::R3:
      return size == rlres1::kR3Size;
    case AuthorityCarrierKind::Envelope:
      return size >= keys::kAuthorityEnvelopeMin && size <= kAuthorityObjectMax;
    case AuthorityCarrierKind::Wake:
      return size == 8;
  }
  return false;
}

// Encode one carrier frame payload (head + body copy). Exchange ids are
// nonzero transport tokens for R1/R2/R3 and 0 for Envelope/Wake; the
// channel correlates by content (RLRES1 nonces, envelope counters), the
// token only pairs retries on the wire.
Status authority_carrier_encode(AuthorityCarrierKind kind, std::uint32_t exchange_id,
                                ByteView body, MutableByteView out,
                                std::size_t& written) noexcept;
// Decode one carrier frame payload. `body` borrows `input` (head bytes
// skipped); the caller copies what it keeps.
Status authority_carrier_decode(ByteView input, AuthorityCarrierKind& kind,
                                std::uint32_t& exchange_id, ByteView& body) noexcept;

// --- Mesh demux ---------------------------------------------------------------
// Offered to ConfigTarget::attach_authority: authority frames are claimed
// before the config path sees them. Chunks and acks carry no kind, so
// they route by the live transfer hash only — never broadcast to every
// sink. All intake copies into bounded slots; nothing sends from here
// except the immediate object ack.
class AuthorityMeshDemux {
 public:
  virtual ~AuthorityMeshDemux() = default;
  virtual bool claim_control(std::uint8_t subtype) noexcept = 0;
  virtual bool claim_kind(autonomy::ControlObjectKind kind) noexcept = 0;
  virtual bool claim_transfer(NodeId origin,
                              const autonomy::ObjectHash& hash) noexcept = 0;
  virtual void on_control(NodeId origin, ByteView payload,
                          MonotonicMs now_ms) noexcept = 0;
  virtual void on_manifest(NodeId origin, const autonomy::ControlObjectPayload& manifest,
                           MonotonicMs now_ms) noexcept = 0;
  virtual void on_chunk(NodeId origin, const autonomy::ObjectChunkPayload& chunk,
                        MonotonicMs now_ms) noexcept = 0;
  virtual void on_ack(NodeId origin, const autonomy::ObjectAckPayload& ack,
                      MonotonicMs now_ms) noexcept = 0;
};

// --- Device endpoint ------------------------------------------------------------
// The AuthorityPort over the mesh for one local AuthorityClient: small
// carriers leave as Control-22/sub-9 frames, large envelopes as kind-7
// objects; one RX assembly (2048 B) plus one small-carrier slot feed the
// client. One transfer each way; a second send while busy answers false
// and the client retries on Tick.
class AuthorityEndpoint final : public AuthorityMeshDemux, public AuthorityPort {
 public:
  explicit AuthorityEndpoint(ConfigWirePort& mesh, NodeId self) noexcept
      : mesh_(mesh), self_(self) {}

  AuthorityEndpoint(const AuthorityEndpoint&) = delete;
  AuthorityEndpoint& operator=(const AuthorityEndpoint&) = delete;
  ~AuthorityEndpoint() override;

  // AuthorityPort: stage one carrier for TX to `gateway`. False (nothing
  // staged, no token spent) when a transfer is already live or the mesh
  // port refuses. Small carriers send synchronously; envelopes stage the
  // kind-7 pump and leave on poll.
  bool try_send(NodeId gateway, AuthorityCarrierKind kind, ByteView carrier,
                std::uint64_t& token) noexcept override;

  // AuthorityMeshDemux: RX intake from the node callback. Small carriers
  // land in the carrier slot, kind-7 manifests/chunks in the assembly;
  // acks complete the TX pump. A second object while one is live (in
  // either direction) is refused with a Failed ack, never evicted.
  bool claim_control(std::uint8_t subtype) noexcept override;
  bool claim_kind(autonomy::ControlObjectKind kind) noexcept override;
  bool claim_transfer(NodeId origin,
                      const autonomy::ObjectHash& hash) noexcept override;
  void on_control(NodeId origin, ByteView payload,
                  MonotonicMs now_ms) noexcept override;
  void on_manifest(NodeId origin, const autonomy::ControlObjectPayload& manifest,
                   MonotonicMs now_ms) noexcept override;
  void on_chunk(NodeId origin, const autonomy::ObjectChunkPayload& chunk,
                MonotonicMs now_ms) noexcept override;
  void on_ack(NodeId origin, const autonomy::ObjectAckPayload& ack,
              MonotonicMs now_ms) noexcept override;

  // Owner drain, polled (never called back): one completed RX carrier at
  // a time (`out.bytes` borrows this until the next endpoint call — the
  // Owner advances the client synchronously), then TX completions.
  bool take_rx(AuthorityRxCarrier& out) noexcept;
  bool take_tx_result(AuthorityTxResult& out) noexcept;
  // Pump TX retries/timeouts and RX expiry. Returns false while a port
  // callback runs inside (the Owner re-polls after the outer call).
  void poll(MonotonicMs now_ms) noexcept;
  bool quiescent() const noexcept;
  // Adoption binds the member NodeId (construction carries the
  // pre-adoption id). Safe with live transfers: self only gates
  // self-addressed sends and reflected origins, never slot keys.
  void set_self(NodeId self) noexcept { self_ = self; }

  struct Counters {
    std::uint32_t rx_carriers{0};
    std::uint32_t rx_objects{0};
    std::uint32_t rx_denied{0};
    std::uint32_t tx_carriers{0};
    std::uint32_t tx_objects{0};
    std::uint32_t tx_timeouts{0};
  };
  const Counters& counters() const noexcept { return counters_; }

 private:
  struct Assembly {
    bool active{false};
    NodeId origin{kInvalidNodeId};
    autonomy::ObjectHash hash{};
    std::uint16_t total_len{0};
    std::uint16_t received{0};
    MonotonicMs started_ms{0};
    std::array<std::uint8_t, kAuthorityObjectMax> buffer{};
    std::array<std::uint8_t, kAuthorityObjectMax / 8> bitmap{};
  };
  struct TxTransfer {
    bool active{false};
    AuthorityCarrierKind kind{AuthorityCarrierKind::Envelope};
    NodeId gateway{kInvalidNodeId};
    std::uint64_t token{0};
    autonomy::ObjectHash hash{};
    std::uint16_t total_len{0};
    std::uint16_t acked{0};  // contiguously acknowledged bytes
    std::uint8_t sends{0};   // sends of the outstanding chunk
    MonotonicMs started_ms{0};
    MonotonicMs last_send_ms{0};
    std::array<std::uint8_t, kAuthorityObjectMax> buffer{};
  };

  void drop_rx() noexcept;
  void drop_tx() noexcept;
  void send_ack(NodeId dest, const autonomy::ObjectHash& hash, std::uint16_t received,
                autonomy::ObjectAckStatus status, MonotonicMs now_ms) noexcept;
  bool pump_tx(MonotonicMs now_ms) noexcept;
  void complete_tx(bool delivered) noexcept;

  ConfigWirePort& mesh_;
  NodeId self_{kInvalidNodeId};
  Assembly rx_{};
  // Small-carrier RX slot: one Control carrier waits here for take_rx.
  std::array<std::uint8_t, kAuthorityCarrierBodyMax> carrier_buf_{};
  AuthorityCarrierKind carrier_kind_{AuthorityCarrierKind::Envelope};
  std::size_t carrier_size_{0};
  bool carrier_ready_{false};
  bool object_ready_{false};  // completed assembly waits for take_rx
  TxTransfer tx_{};
  AuthorityTxResult tx_result_{};
  bool tx_result_ready_{false};
  std::uint64_t next_token_{1};
  std::uint32_t next_exchange_{1};
  bool in_call_{false};
  Counters counters_{};
};

class AuthorityHostSink {
 public:
  virtual ~AuthorityHostSink() = default;
  // One 0x64 fragment toward the host. False = USB queue full; the
  // gateway keeps the bytes and retries on poll.
  virtual bool send_up(const usb::AuthorityFragment& fragment) noexcept = 0;
};

// Completed 0x65 downs addressed at the gateway itself: the gateway's
// own channel bypasses the mesh, so reassembled self-downs deliver here
// (poll context; bytes borrow the slot during the call) instead of
// looping back onto the radio.
class AuthorityLocalSink {
 public:
  virtual ~AuthorityLocalSink() = default;
  virtual void on_local_down(AuthorityCarrierKind kind, ByteView bytes) noexcept = 0;
};

// --- Gateway relay --------------------------------------------------------------
// Relays opaque carrier bytes between the mesh and USB 0x64/0x65 on a
// gateway node: mesh Control-22/sub-9 carriers and kind-7 objects become
// 0x64 AuthorityUp fragments; 0x65 AuthorityDown fragments reassemble
// (at most 3) and leave as mesh carriers or kind-7 objects, except
// self-addressed downs, which deliver to the local sink. Two shared
// 2048 B slots keyed by (device, direction, transfer_id, kind); a third
// live object answers Busy and the endpoints retry — live slots are
// never evicted. Never decrypts: the gateway holds no DAMS and no
// authority traffic keys.
class AuthorityGateway final : public AuthorityMeshDemux {
 public:
  AuthorityGateway(ConfigWirePort& mesh, AuthorityHostSink& host, AuthorityLocalSink& local,
                   NodeId self) noexcept
      : mesh_(mesh), host_(host), local_(local), self_(self) {}

  AuthorityGateway(const AuthorityGateway&) = delete;
  AuthorityGateway& operator=(const AuthorityGateway&) = delete;
  ~AuthorityGateway() override;

  // AuthorityMeshDemux: mesh RX intake from the node callback.
  bool claim_control(std::uint8_t subtype) noexcept override;
  bool claim_kind(autonomy::ControlObjectKind kind) noexcept override;
  bool claim_transfer(NodeId origin,
                      const autonomy::ObjectHash& hash) noexcept override;
  void on_control(NodeId origin, ByteView payload,
                  MonotonicMs now_ms) noexcept override;
  void on_manifest(NodeId origin, const autonomy::ControlObjectPayload& manifest,
                   MonotonicMs now_ms) noexcept override;
  void on_chunk(NodeId origin, const autonomy::ObjectChunkPayload& chunk,
                MonotonicMs now_ms) noexcept override;
  void on_ack(NodeId origin, const autonomy::ObjectAckPayload& ack,
              MonotonicMs now_ms) noexcept override;

  // One 0x65 down fragment from the USB bridge (bridge RX context: copies
  // only). `complete` reports whether this fragment finished the object
  // (result 1 vs 0 in the 0x67). Busy while both slots are live;
  // Conflict when the token's bytes change mid-transfer.
  Status authority_down(NodeId device, const usb::AuthorityFragment& fragment,
                        bool& complete, MonotonicMs now_ms) noexcept;
  // USB session death: drop every slot. Epoch/key application is never
  // resumed from a slot — the endpoints resync over a fresh channel.
  void drop_all() noexcept;
  // Pump mesh TX (manifest/chunks/retries) and USB egress cursors.
  void poll(MonotonicMs now_ms) noexcept;
  bool quiescent() const noexcept;
  // Adoption binds the member NodeId (construction carries the
  // pre-adoption id): self-addressed downs deliver locally from here
  // on. Safe with live slots: delivery branches, never keys, on self.
  void set_self(NodeId self) noexcept { self_ = self; }

  struct Counters {
    std::uint32_t up_fragments{0};
    std::uint32_t down_objects{0};
    std::uint32_t denied{0};
    std::uint32_t timeouts{0};
  };
  const Counters& counters() const noexcept { return counters_; }

 private:
  enum class Direction : std::uint8_t { Up = 0, Down };
  struct Slot {
    bool active{false};
    Direction direction{Direction::Up};
    NodeId device{kInvalidNodeId};
    std::uint32_t transfer_id{0};
    AuthorityCarrierKind kind{AuthorityCarrierKind::Envelope};
    std::uint16_t total_len{0};
    std::uint16_t received{0};
    std::uint16_t emitted{0};  // USB egress cursor (Up) / mesh ack cursor (Down)
    std::uint8_t sends{0};     // sends of the outstanding mesh chunk (Down)
    NodeId origin{kInvalidNodeId};  // mesh RX peer (Up, for acks)
    autonomy::ObjectHash hash{};
    MonotonicMs started_ms{0};
    MonotonicMs last_send_ms{0};
    bool mesh_manifest_sent{false};  // Down objects only
    std::array<std::uint8_t, kAuthorityObjectMax> buffer{};
    std::array<std::uint8_t, kAuthorityObjectMax / 8> bitmap{};
  };

  Slot* find_slot(NodeId device, Direction direction, std::uint32_t transfer_id,
                  AuthorityCarrierKind kind) noexcept;
  Slot* claim_slot() noexcept;
  void drop_slot(Slot& slot) noexcept;
  void send_ack(NodeId dest, const autonomy::ObjectHash& hash, std::uint16_t received,
                autonomy::ObjectAckStatus status, MonotonicMs now_ms) noexcept;
  bool pump_down_mesh(Slot& slot, MonotonicMs now_ms) noexcept;
  bool pump_up_usb(Slot& slot) noexcept;
  void expire_slots(MonotonicMs now_ms) noexcept;

  ConfigWirePort& mesh_;
  AuthorityHostSink& host_;
  AuthorityLocalSink& local_;
  NodeId self_{kInvalidNodeId};
  std::array<Slot, 2> slots_{};
  std::uint32_t next_transfer_{1};
  bool in_call_{false};
  Counters counters_{};
};

// --- Standalone mesh sink ---------------------------------------------------------
// A ConfigEndpointSink that serves ONLY the authority lane (for nodes
// without a ConfigTarget, i.e. USB gateways): claimed frames route to
// the demux, everything else is ignored — never denied, never answered.
// Nodes with a real config endpoint attach the demux to their
// ConfigTarget instead (ConfigTarget::attach_authority).
class AuthorityMeshSink final : public ConfigEndpointSink {
 public:
  explicit AuthorityMeshSink(AuthorityMeshDemux& demux) noexcept : demux_(demux) {}
  void on_config_frame(NodeId peer, const wire::PlainFrame& frame,
                       MonotonicMs now_ms) noexcept override;
  // The authority lane issues no send_typed jobs, so no completion can
  // correlate to it; the job-done callback is unreachable by
  // construction, not by trust.
  void on_config_job_done(const MessageId& /*id*/, bool /*hop_accepted*/,
                          const char* /*reason*/,
                          MonotonicMs /*now_ms*/) noexcept override {}
  // A pure frame router: the Owner polls the concrete endpoint/gateway
  // itself (retries, TX pump, RX expiry), so the sink tick does nothing.
  void poll(MonotonicMs /*now_ms*/) noexcept override {}

 private:
  AuthorityMeshDemux& demux_;
};

}  // namespace routeloom::sdkv1
