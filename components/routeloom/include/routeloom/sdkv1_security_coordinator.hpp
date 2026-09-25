#pragma once

// The single device security Owner (G-SEC P4 §8, PR4): one state, one
// entry, no callbacks that re-enter it.
//
// The Coordinator owns the mode workspace — the P3-4 Joiner while
// unprovisioned (radio or USB-direct), the member HandshakeEngine with
// its session bank while adopted — plus the RLD1 demux owner table, the
// join proxy and relay gateway, the APPLIED boot lease's rlboot witness,
// the local-removal evidence, the single GroupKeyState with its group
// provider and member scope view, and the authority channel client.
// It implements the sink/port interfaces
// of everything it owns (BootstrapSink, JoinDirectPort, JoinCommitPolicy,
// JoinRelayHostSink, the engine's membership/peer/boot views) so the
// wiring has no free functions and no second owner.
//
// Entry is step(event) only; outputs leave via take_action (single slot)
// and the injected firmware ports. Frames that arrive inside someone
// else's callback (BootstrapSink::on_frame from the Node's RX path) are
// staged in a bounded queue and processed on Poll — the Coordinator
// never sends from inside a receive callback.
//
// What the Coordinator does NOT own: the radio (tune/channel via the
// TuneChannel action), the MeshNode and NeighborDiscovery (adopted via
// member actions, polled by the firmware), the USB transport (frames via
// the USB port/events), and any flash layout (stores stay injected).
// Sleep images are PR5: PrepareSleep only reports drain readiness.
//
// No heap, no exceptions; every entry is noexcept.

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/admission.hpp"
#include "routeloom/bootstrap_transport.hpp"
#include "routeloom/discovery.hpp"
#include "routeloom/discovery_scope.hpp"
#include "routeloom/rlres1.hpp"
#include "routeloom/sdkv1_authority.hpp"
#include "routeloom/sdkv1_group_keys.hpp"
#include "routeloom/sdkv1_group_security.hpp"
#include "routeloom/sdkv1_handshake.hpp"
#include "routeloom/sdkv1_join_relay.hpp"
#include "routeloom/sdkv1_join_transport.hpp"
#include "routeloom/sdkv1_joiner.hpp"
#include "routeloom/sdkv1_membership.hpp"
#include "routeloom/sdkv1_records.hpp"
#include "routeloom/sdkv1_store.hpp"
#include "routeloom/security.hpp"
#include "routeloom/session_bank.hpp"
#include "routeloom/status.hpp"
#include "routeloom/trust_store.hpp"
#include "routeloom/types.hpp"

namespace routeloom::sdkv1 {

// --- Firmware ports ----------------------------------------------------------------------
// Implemented by the firmware/runtime; must never call back into the
// Coordinator (single entry is step()).

// Routed bootstrap TX (MeshNode::send_bootstrap): join-relay and
// member end-session frames, link-protected per hop.
class CoordinatorMeshPort {
 public:
  virtual ~CoordinatorMeshPort() = default;
  virtual Status send_bootstrap(NodeId destination, FrameType type, ByteView payload,
                                std::uint32_t lifetime_ms, MonotonicMs now_ms,
                                MessageId& id) noexcept = 0;
};

// USB join transport (the UsbBridge LocalJoin + join-relay endpoints).
// `usb_request` echoes the H→G request id in the 0x63 result; ups carry 0.
class CoordinatorUsbPort {
 public:
  virtual ~CoordinatorUsbPort() = default;
  // LocalJoin up (device gateway joining over USB): 0x60, proxy=self.
  virtual Status send_local_join_up(JoinAuthPhase phase, std::uint8_t step,
                                    ByteView message) noexcept = 0;
  // Gateway relay up to the Site Authority (0x60). Valid during the call.
  virtual Status send_relay_up_to_host(NodeId proxy, std::uint8_t hops,
                                       ByteView object) noexcept = 0;
  // Gateway relay end to the Site Authority (0x62): the full #116
  // token plus the explicit USB reason.
  virtual Status send_relay_abort_to_host(NodeId proxy, RelayToken token,
                                          RelayAbortReason reason) noexcept = 0;
  // No 0x63 here: every Usb*Down step returns queue admission
  // synchronously and the USB bridge maps it to the 0x63 verdict.
};

// --- Events (the single entry) -------------------------------------------------------------
enum class CoordinatorEventKind : std::uint8_t {
  Boot,  // stores are readable; decide zero-touch vs member
  Poll,  // drive Joiner/engine/deadlines, drain the staged RX queue
  Rld1Rx,          // one observed RLD1 frame (radio generation pre-checked)
  UsbLocalDown,    // H→G 0x61 for a local direct join
  UsbRelayDown,    // H→G 0x61 for a mesh proxy
  UsbRelayAbort,   // H→G 0x62 (only HostAborted is a defined H→G reason)
  UsbSessionDown,  // USB disconnect: USB-bound state drops, never reused
  UsbSessionUp,    // USB session (re)established: restart USB-bound channels
  AuthorityRx,     // one authority carrier from the mesh/USB transport
  AuthorityTx,     // one authority send completion from the transport
  RequestPull,     // ask the authority for the current GK (unknown epoch)
  ChannelReady,    // radio tune completion (answers a TuneChannel action)
  PrepareSleep,    // Busy while work is outstanding, else parks sleeping
  Wake,            // resume polling after sleep
  Stop,            // full stop back to Fresh (wipes the mode workspace)
};

struct CoordinatorEvent {
  CoordinatorEventKind kind{CoordinatorEventKind::Poll};
  MonotonicMs now{0};
  // Boot:
  std::uint32_t boot_witness{0};
  bool boot_prepared{false};
  // Boot transport: USB-direct (a gateway attached to its host) vs radio
  // scan. Healthy adopted boots ignore it (the Joiner adopts silently).
  bool usb_direct{false};
  // Rld1Rx: the frame bytes are valid during the call only.
  JoinRxMeta rld1_meta{};
  ByteView rld1_frame{};
  std::uint32_t radio_generation{0};
  // USB downs: bodies valid during the call only. The 0x63 request id
  // stays bridge-internal: steps return admission synchronously.
  JoinAuthPhase usb_phase{JoinAuthPhase::EdhocMessage};
  std::uint8_t usb_step{0};
  ByteView usb_body{};
  NodeId usb_proxy{kInvalidNodeId};
  ByteView usb_object{};
  std::uint32_t usb_relay_id{0};
  // #116 token epochs for UsbRelayAbort (the 0x62 names the full token).
  std::uint32_t usb_gateway_epoch{0};
  std::uint32_t usb_proxy_epoch{0};
  std::uint8_t usb_reason{0};
  // ChannelReady:
  std::uint32_t channel_token{0};
  StatusCode channel_result{StatusCode::Ok};
  std::uint8_t channel{0};
  JoinPhy channel_phy{JoinPhy::Lr250};
  std::uint32_t channel_generation{0};
  // AuthorityRx: one carrier (bytes valid during the call only; the
  // transport's take_rx view is fed synchronously, never staged).
  AuthorityCarrierKind auth_kind{AuthorityCarrierKind::Envelope};
  ByteView auth_bytes{};
  // AuthorityTx: the transport's completion for an earlier try_send.
  std::uint64_t auth_token{0};
  bool auth_delivered{false};
  // RequestPull: 1 UnknownNewerEpoch, 2 BootReconnectSync, 3 LostAckRepair.
  std::uint8_t pull_reason{0};
};

// --- Actions (single slot, take_action) ------------------------------------------------------
enum class CoordinatorActionKind : std::uint8_t {
  None,
  TuneChannel,          // tune the radio, report via ChannelReady
  ApplyMemberConfig,    // (re)build the MeshNode with the adopted config
  StartMemberDiscovery,  // start discovery with Required GK scope
  ReportRemoval,         // verified removal landed: display + stop traffic
  ReportRecovery,        // stores need recovery: display + maintenance
};

struct CoordinatorTune {
  std::uint32_t token{0};
  std::uint8_t channel{0};
  JoinPhy phy{JoinPhy::Lr250};
};

// The adopted member identity for the firmware's MeshNode. Plain data —
// never RLS1/SAK/GK bytes (those stay in the stores and the Coordinator).
struct CoordinatorMemberConfig {
  NetworkId network{0};  // full64 (low32 filters the radio)
  NodeId node{kInvalidNodeId};
  std::uint32_t message_session{0};
  std::uint32_t boot_session{0};  // rlboot witness, nonzero
  std::uint32_t link_epoch{1};
  std::uint32_t end_epoch{1};
  std::uint64_t boot_incarnation{0};
  std::uint32_t role{0};  // rlcw1 member role bits
  std::array<NodeId, kSiteGatewayMax> route_gateways{};
  std::size_t route_gateway_count{0};
};

struct CoordinatorRemoval {
  std::uint64_t site_id{0};
  std::uint32_t generation{0};
  RemovalNotice notice{};
};

struct CoordinatorAction {
  CoordinatorActionKind kind{CoordinatorActionKind::None};
  CoordinatorTune tune{};
  CoordinatorMemberConfig member{};
  CoordinatorRemoval removal{};
  JoinRecoveryReason recovery{JoinRecoveryReason::BootWitnessMismatch};
};

enum class CoordinatorMode : std::uint8_t {
  Fresh,      // constructed / stopped: no workspace running
  ZeroTouch,  // Joiner running (radio scan or USB direct)
  Member,     // adopted: engine + bank + proxy (+ gateway on role) live
  Removed,    // verified removal landed: traffic stopped, evidence durable
  Recovery,   // stores need recovery before any mode can run
};

struct CoordinatorSnapshot {
  CoordinatorMode mode{CoordinatorMode::Fresh};
  MembershipState membership{MembershipState::Unprovisioned};
  bool sleeping{false};
  bool action_pending{false};
  JoinState joiner{JoinState::Stopped};
  bool engine_quiescent{true};
  std::uint32_t link_sessions{0};
  std::uint32_t end_sessions{0};
  std::uint32_t demands{0};
  std::uint16_t resume_link_slots{0};
  std::uint16_t resume_end_slots{0};
  // Authority channel (G-SEC P5): live once the member config lands and
  // the transport port attaches. join_confirmed latches on the verified
  // JoinConfirm ACK; authority_busy gates sleep while work is in flight.
  bool authority_started{false};
  bool authority_ready{false};
  bool authority_busy{false};
  bool join_confirmed{false};
  // Consecutive member-link failures behind the stale-GK refresh (P5 §7.4).
  std::uint8_t refresh_strikes{0};
};

struct CoordinatorCounters {
  std::uint32_t boots{0};
  std::uint32_t member_adoptions{0};
  std::uint32_t removals{0};
  std::uint32_t demux_drops{0};
  std::uint32_t staged_drops{0};
  std::uint32_t usb_drops{0};
  std::uint32_t sleep_parks{0};
  std::uint32_t authority_ready{0};
  std::uint32_t authority_lost{0};
  std::uint32_t authority_confirmed{0};
  std::uint32_t authority_updates{0};
  std::uint32_t authority_activates{0};
  std::uint32_t authority_passthrough{0};  // verified type 5..8, P6 unconnected
  std::uint32_t refreshes{0};
};

// The Owner. See the header comment for the ownership map.
class SecurityCoordinator final : public BootstrapSink,
                                   public JoinDirectPort,
                                   public JoinCommitPolicy,
                                   public JoinRelayHostSink,
                                   public ZtRelayPort,
                                   public HandshakeMembershipView,
                                   public AuthenticatedPeerView,
                                   public BootWitnessView,
                                   public AuthorityObserver {
 public:
  // The stores, discovery, entropy and ports stay firmware-owned and must
  // outlive the Coordinator. `local_mac`/`local_node` identify this device
  // on the radio; the adopted NodeId replaces local_node on MemberReady.
  struct Deps {
    IdentityStore* identity{nullptr};
    SiteStore* site{nullptr};
    RevocationStore* revocations{nullptr};
    LocalRevocationStore* local_revocation{nullptr};
    ResumeSlotStorage2* resume_storage{nullptr};
    // (No TrustStore: anchors are established before the coordinator
    // boots and consulted through the adopted stores, never directly.)
    // Member discovery, attached late: null at Boot (adoption precedes
    // discovery start), set by attach_discovery() before the firmware
    // starts member discovery. ZT legs skip it; member legs need it.
    NeighborDiscovery* discovery{nullptr};
    EntropySource* entropy{nullptr};
    ZtRld1Port* rld1{nullptr};
    CoordinatorMeshPort* mesh{nullptr};
    CoordinatorUsbPort* usb{nullptr};
    SessionCredentialVerifier* verifier{nullptr};
    AeadGcm bank_aead{};
    // Combined-tag GCM for the group provider and the authority channel
    // (a different port than the bank's split-tag AeadGcm above).
    routeloom::AeadGcm crypto_aead{};
    JoinCookieSealer* proxy_sealer{nullptr};
    MacAddress local_mac{};
    NodeId local_node{kInvalidNodeId};
    JoinerConfig joiner_config{};
  };

  explicit SecurityCoordinator(const Deps& deps) noexcept;
  SecurityCoordinator(const SecurityCoordinator&) = delete;
  SecurityCoordinator& operator=(const SecurityCoordinator&) = delete;
  ~SecurityCoordinator() noexcept override;

  // The single entry. Boot/Poll/Stop/PrepareSleep/Wake drive the mode
  // workspace; Rld1Rx demuxes to Joiner/proxy/member engine; USB downs
  // feed the direct join or the relay gateway; ChannelReady completes a
  // TuneChannel action. Refuses Busy while a port callback runs inside.
  Status step(const CoordinatorEvent& event) noexcept;
  Status take_action(CoordinatorAction& out) noexcept;
  CoordinatorSnapshot snapshot() const noexcept;
  const CoordinatorCounters& counters() const noexcept { return counters_; }
  // Next service time for the firmware scheduler; kNoDeadline when idle.
  MonotonicMs next_deadline(MonotonicMs now) const noexcept;
  bool quiescent() const noexcept;

  // The GK-backed discovery scope provider, handed to the firmware's
  // DiscoveryConfig at construction (with the kMemberScopeRef handle).
  // Refuses until a member config is adopted; the StartMemberDiscovery
  // action only says when. Reads the single GroupKeyState — no second
  // GK copy, no dev-PSK fallback.
  DiscoveryScopeProvider& gk_scope() noexcept { return member_scope_; }
  // The session provider view over the member bank, handed to the
  // firmware's MeshNode at construction. Unconfigured (not ready) until
  // a member config is adopted; the node must not start on it before
  // ApplyMemberConfig. Pairwise scopes delegate to the member bank;
  // group scopes seal/open under the adopted GK.
  SecurityProvider& session_provider() noexcept { return group_provider_; }
  // The membership hooks over the adopted stores, for the member
  // discovery's MembershipHooks port (the firmware initializes the
  // discovery's controller with these at StartMemberDiscovery).
  MembershipHooks& membership_hooks() noexcept { return hooks_; }
  // The member OFFER cookie box, live in Member mode only (null
  // otherwise): the member discovery authenticator seals OFFER cookies
  // through it. Never stored beyond the call — the workspace may be
  // replaced by removal or stop.
  const MemberCookie* member_cookie() const noexcept {
    return mode_ == CoordinatorMode::Member ? &member().member_cookie : nullptr;
  }
  // Attaches the member discovery (once): the firmware constructs it
  // with the adopted network + Required GK scope at StartMemberDiscovery
  // and attaches it before starting it. The coordinator never owns it.
  Status attach_discovery(NeighborDiscovery& discovery) noexcept {
    if (deps_.discovery != nullptr) {
      return Status::error(StatusCode::AlreadyExists, "discovery already attached");
    }
    deps_.discovery = &discovery;
    return Status::success();
  }
  // Attaches the authority transport port (once): the mesh endpoint on a
  // device, the direct USB port on a gateway. Until attached the channel
  // stages its carriers and retries on Tick; detaching is not supported
  // (Stop wipes the channel instead). The port must outlive the Owner.
  Status attach_authority_port(AuthorityPort& port) noexcept {
    if (authority_port_.live() != nullptr) {
      return Status::error(StatusCode::AlreadyExists, "authority port already attached");
    }
    authority_port_.attach(port);
    return Status::success();
  }
  // Secret-free channel view for firmware diagnostics (safe in callbacks).
  AuthoritySnapshot authority_snapshot() const noexcept { return authority_.snapshot(); }
  // Adopted GK epochs for the 0x66 QueryLocal answer (0/0 pre-adoption;
  // false until the member config lands).
  bool group_epochs(std::uint32_t& current, std::uint32_t& next) const noexcept {
    current = group_keys_.current();
    next = 0;
    if (deps_.site != nullptr && deps_.site->has_site()) {
      next = deps_.site->site().gk_epoch_next;
    }
    return group_keys_.ready();
  }

  // BootstrapSink (Node RX context): stages the frame, never sends.
  Status on_frame(const BootstrapMeta& meta, FrameType type, ByteView payload,
                  MonotonicMs now_ms) noexcept override;
  // JoinDirectPort (Joiner context): forwards to the USB port.
  Status send_direct(JoinAuthPhase phase, std::uint8_t step,
                     ByteView message) noexcept override;
  // JoinCommitPolicy (Commit poll): the RLV1 read-only veto.
  bool check(const SiteRecord& prepared, MonotonicMs now) noexcept override;
  // JoinRelayHostSink (gateway context): forwards to the USB port.
  Status relay_up(NodeId proxy, std::uint8_t hops, ByteView object) noexcept override;
  Status relay_abort(NodeId proxy, RelayToken token,
                     RelayAbortReason reason) noexcept override;
  // ZtRelayPort (proxy/gateway context): routed mesh TX; a relay addressed
  // to self loops back into the local gateway without touching the radio.
  Status send_relay(NodeId destination, FrameType type,
                    ByteView payload) noexcept override;
  // HandshakeMembershipView / AuthenticatedPeerView / BootWitnessView:
  bool local(HandshakeLocal& out) const noexcept override;
  bool revoked(NodeId peer, std::uint32_t generation) const noexcept override;
  bool authenticated(NodeId peer, NetworkId network, std::uint32_t& generation,
                     std::uint32_t& role) const noexcept override;
  bool boot_witness_ok(std::uint32_t witness) const noexcept override;
  // AuthorityObserver (channel context): counts verified events. Never
  // drives the channel (no advance from the callback).
  void on_event(const AuthorityEvent& event) noexcept override;

 private:
  friend struct SecurityCoordinatorTestAccess;
  static constexpr std::size_t kDemuxEntries = 8;
  static constexpr std::size_t kStagedFrames = 4;
  static constexpr std::uint32_t kDemuxHoldMs = 30000;
  static constexpr std::uint32_t kRemovalHoldoffMs = 600000;

  enum class DemuxOwner : std::uint8_t { None, Joiner, Proxy, Member };

  struct DemuxEntry {
    bool used{false};
    MacAddress mac{};
    NodeId peer{kInvalidNodeId};  // claimed (taken start / request)
    std::uint32_t object_id{0};
    DemuxOwner owner{DemuxOwner::None};
    MonotonicMs expires_at{0};
    // Member responder legs park the taken discovery start until m1/R1.
    bool has_start{false};
    bool initiator{false};
    keys::LinkCarrier carrier{};
    std::uint32_t discovery_token{NeighborDiscovery::kMemberHandshakeNone};
    // Our transaction nonce (initiator: drawn on first send; responder:
    // echoed from the inbound m1/R1). object_id is its first 4 bytes.
    std::array<std::uint8_t, 16> txn{};
  };

  struct StagedFrame {
    bool used{false};
    BootstrapMeta meta{};
    FrameType type{FrameType::Data};
    std::array<std::uint8_t, kMaxApplicationPayload> payload{};
    std::size_t payload_size{0};
    MonotonicMs now{0};
  };

  // rlres1::Environment for the authority initiator: entropy and
  // receive context ids. The slot directory is unused (the client only
  // initiates, never answers R1). A nested class (not another base)
  // because the environment's non-const revoked() would collide with
  // the membership view's const one.
  class AuthorityEnv final : public rlres1::Environment {
   public:
    void bind(EntropySource* entropy) noexcept { entropy_ = entropy; }
    bool random(MutableByteView out) noexcept override {
      return entropy_ != nullptr && entropy_->fill(out).ok();
    }
    bool find_slot(rlres1::Purpose purpose, const rlres1::ResumeId& rid,
                   rlres1::Slot& out) noexcept override {
      (void)purpose;
      (void)rid;
      (void)out;
      return false;
    }
    bool revoked(NodeId peer, std::uint32_t generation) noexcept override {
      (void)peer;
      (void)generation;
      return false;  // initiator-only: never consulted
    }
    bool allocate_context_id(rlres1::Purpose purpose, NodeId peer,
                             std::uint32_t& cid) noexcept override {
      (void)purpose;
      (void)peer;
      if (++next_cid_ == 0) next_cid_ = 1;
      cid = next_cid_;
      return true;
    }
    bool reserve_resume_use(rlres1::Purpose purpose,
                            const rlres1::ResumeId& rid) noexcept override {
      (void)purpose;
      (void)rid;
      return false;
    }

   private:
    EntropySource* entropy_{nullptr};
    std::uint32_t next_cid_{0};
  };

  // Late-bound authority port: the firmware attaches the mesh endpoint
  // or the direct USB port after construction. try_send refuses (false,
  // nothing spent) until attached, so the channel stages and retries.
  class AuthorityPortProxy final : public AuthorityPort {
   public:
    void attach(AuthorityPort& port) noexcept { live_ = &port; }
    AuthorityPort* live() const noexcept { return live_; }
    bool try_send(NodeId gateway, AuthorityCarrierKind kind, ByteView carrier,
                  std::uint64_t& token) noexcept override {
      if (live_ == nullptr) return false;
      return live_->try_send(gateway, kind, carrier, token);
    }

   private:
    AuthorityPort* live_{nullptr};
  };

  // --- step() legs ---
  Status on_boot(const CoordinatorEvent& event) noexcept;
  Status on_poll(MonotonicMs now) noexcept;
  Status on_rld1_rx(const CoordinatorEvent& event) noexcept;
  Status on_usb(const CoordinatorEvent& event) noexcept;
  Status on_channel_ready(const CoordinatorEvent& event) noexcept;
  Status on_prepare_sleep(MonotonicMs now) noexcept;
  Status on_wake(MonotonicMs now) noexcept;
  Status on_stop(MonotonicMs now) noexcept;
  // --- authority channel legs ---
  Status on_authority_rx(const CoordinatorEvent& event) noexcept;
  Status on_authority_tx(const CoordinatorEvent& event) noexcept;
  Status on_request_pull(const CoordinatorEvent& event) noexcept;
  Status on_usb_session_up(MonotonicMs now) noexcept;
  void drive_authority(MonotonicMs now) noexcept;
  bool build_authority_start(AuthorityStart& out) const noexcept;
  void suspend_authority() noexcept;
  // --- stale-GK refresh (P5 §7.4) ---
  void note_link_established() noexcept;
  void note_link_failed() noexcept;
  void watch_linkless(MonotonicMs now) noexcept;
  void start_refresh(MonotonicMs now) noexcept;
  void maybe_abandon_refresh(MonotonicMs now) noexcept;
  // --- MemberReady adoption ---
  Status adopt_member(const JoinAction& ready, MonotonicMs now) noexcept;
  Status adopt_boot_rls1(MonotonicMs now) noexcept;  // same tail, stored site
  Status install_member_config(const SiteRecord& site, const IdentityRecord& identity,
                               std::uint32_t boot_session, MonotonicMs now) noexcept;
  void emit_member_action() noexcept;
  // --- RLD1 demux ---
  DemuxEntry* find_demux(const MacAddress& mac, std::uint32_t object_id) noexcept;
  DemuxEntry* claim_demux(const MacAddress& mac, std::uint32_t object_id, DemuxOwner owner,
                          MonotonicMs now) noexcept;
  void sweep_demux(MonotonicMs now) noexcept;
  Status demux_member_frame(const autonomy::Rld1Envelope& env, DemuxEntry* entry,
                            MonotonicMs now) noexcept;
  // --- engine legs ---
  Status drive_engine(MonotonicMs now) noexcept;
  Status emit_send(const HandshakeResult& result, MonotonicMs now) noexcept;
  Status emit_link_send(const HandshakeResult& result, MonotonicMs now) noexcept;
  Status emit_end_send(const HandshakeResult& result, MonotonicMs now) noexcept;
  Status installed_link(const HandshakeResult& result, MonotonicMs now) noexcept;
  void drain_demands(MonotonicMs now) noexcept;
  void drain_engine_results(MonotonicMs now) noexcept;
  // --- staged bootstrap RX ---
  void drain_staged(MonotonicMs now) noexcept;
  void handle_bootstrap_frame(const StagedFrame& frame, MonotonicMs now) noexcept;
  void handle_end_single(const BootstrapMeta& meta, ByteView payload, MonotonicMs now) noexcept;
  void handle_end_chunk(const BootstrapMeta& meta, ByteView payload, MonotonicMs now) noexcept;
  // --- Joiner legs ---
  void drain_joiner(MonotonicMs now) noexcept;
  void on_joiner_action(const JoinAction& action, MonotonicMs now) noexcept;
  void emit_action(const CoordinatorAction& action) noexcept;
  // --- removal ---
  Status land_removal(const RemovalNotice& notice, MonotonicMs now) noexcept;
  void stop_traffic() noexcept;
  // The real quiescence check, for PrepareSleep (which runs inside step()
  // with the re-entry guard set, where the public query answers false).
  bool quiescent_locked() const noexcept;

  // Everything the member handshake owns that no outside reference
  // touches: the engine with its cookie and resume cache, the demand
  // driver, the link/end chunk slots, the proxy and relay gateway, and
  // the RLD1 demux table. Lives in the workspace union opposite the
  // Joiner — the two never share a boot phase, so they never share RAM.
  struct MemberEngine {
    ResumeCache2 resume_cache;
    MemberCookie member_cookie;
    HandshakeEngine engine;
    BootstrapDemandDriver<32, 128> demands;
    BootstrapBudgets budgets;
    // One TX + one RX assembly per lane: member link (RLD1, join lane)
    // and member end-session (mesh, end lane) chunk independently — one
    // shared TX slot would live-lock interleaved link+end sends (every
    // load evicts), so the §12.2 "one object each" line is deliberately
    // doubled here.
    JoinObjectSlot link_tx;
    JoinObjectSlot link_rx;
    JoinObjectSlot end_tx;
    JoinObjectSlot end_rx;
    JoinProxy proxy;
    JoinRelayGateway gateway;
    std::array<DemuxEntry, kDemuxEntries> demux{};
    bool gateway_active{false};

    MemberEngine(ResumeSlotStorage2& resume, GatewaySessionBank& bank,
                 BankSessionSink<32, 128>& sink, HandshakeMembershipView& membership,
                 SessionCredentialVerifier& verifier, EntropySource& entropy, ZtRld1Port& rld1,
                 ZtRelayPort& relay, JoinCookieSealer& sealer,
                 const JoinProxyConfig& proxy_config,
                 const JoinRelayGatewayConfig& gateway_config) noexcept;
  };

  // Tagged by mode_: joiner iff ZeroTouch, member iff Member, neither
  // anywhere else. Transitions destroy one side (wiping it) before
  // constructing the other; the destructor destroys the live side.
  union Workspace {
    Workspace() noexcept {}
    ~Workspace() noexcept {}
    Joiner joiner;
    MemberEngine member;
  };

  // --- mode workspace (exactly one live; see above) ---
  void destroy_workspace() noexcept;
  void create_joiner() noexcept;
  void create_member() noexcept;
  Joiner& joiner() noexcept { return ws_.joiner; }
  const Joiner& joiner() const noexcept { return ws_.joiner; }
  MemberEngine& member() noexcept { return ws_.member; }
  const MemberEngine& member() const noexcept { return ws_.member; }

  Deps deps_{};
  CoordinatorMode mode_{CoordinatorMode::Fresh};
  SdkMembershipHooks hooks_;
  NullJoinObserver joiner_observer_{};
  // The bank stays outside the union: the firmware binds the session
  // provider over it at construction, before any workspace exists. The
  // GK state, the group/pairwise provider, the member scope view and the
  // authority channel stay outside the union too: a stale-GK refresh
  // destroys the member engine around them without resetting group
  // counters, replay windows or the adopted scope.
  GatewaySessionBank bank_;
  BankSessionSink<32, 128> bank_sink_;
  RamSessionProvider<32, 128> pairwise_provider_;
  GroupKeyState group_keys_;
  GroupSecurityProvider group_provider_;
  GkMemberScopeProvider member_scope_;
  AuthorityPortProxy authority_port_;
  AuthorityEnv authority_env_;
  AuthorityClient authority_;
  Workspace ws_{};

  std::array<StagedFrame, kStagedFrames> staged_{};
  CoordinatorAction action_{};
  bool action_pending_{false};
  bool authority_wanted_{false};  // adopted: the channel (re)starts on poll
  bool join_confirmed_{false};    // latched on the verified JoinConfirm ACK
  std::uint8_t refresh_strikes_{0};
  std::uint32_t last_unknown_generation_{0};  // discovery scope_stats sample
  bool refresh_active_{false};
  MonotonicMs refresh_start_{0};
  MonotonicMs refresh_cooldown_until_{0};
  MonotonicMs last_authority_start_{0};
  CoordinatorMemberConfig adopted_{};
  bool member_valid_{false};
  std::uint32_t tune_token_{0};
  std::uint32_t tune_outstanding_{0};
  std::uint8_t channel_{0};
  std::uint32_t radio_generation_{0};
  std::uint32_t boot_witness_{0};
  bool sleeping_{false};
  bool in_port_{false};
  bool usb_direct_{false};
  bool discovery_started_{false};
  MonotonicMs last_now_{0};
  bool removal_holdoff_armed_{false};
  MonotonicMs removal_holdoff_at_{0};
  CoordinatorCounters counters_{};
};

}  // namespace routeloom::sdkv1
