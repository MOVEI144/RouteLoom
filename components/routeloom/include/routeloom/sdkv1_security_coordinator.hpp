#pragma once

// The single device security Owner (G-SEC P4 §8, PR4): one state, one
// entry, no callbacks that re-enter it.
//
// The Coordinator owns the mode workspace — the P3-4 Joiner while
// unprovisioned (radio or USB-direct), the member HandshakeEngine with
// its session bank while adopted, the same engine dev-armed (P4 §10.1)
// under a static dev adoption — plus the RLD1 demux owner table, the
// join proxy and relay gateway (member only), the APPLIED boot lease's
// rlboot witness, the local-removal evidence, the single GroupKeyState
// with its group provider and member scope view, the dev group/scope
// views, and the authority channel client (member only).
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
// Sleep images are caller-backed: PrepareSleep parks after work drains.
//
// No heap, no exceptions; every entry is noexcept.

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>

#include "routeloom/admission.hpp"
#include "routeloom/bootstrap_transport.hpp"
#include "routeloom/discovery.hpp"
#include "routeloom/discovery_scope.hpp"
#include "routeloom/sdkv1_ead.hpp"
#include "routeloom/rlres1.hpp"
#include "routeloom/sdkv1_authority.hpp"
#include "routeloom/sdkv1_dev_session.hpp"
#include "routeloom/sdkv1_group_keys.hpp"
#include "routeloom/sdkv1_group_security.hpp"
#include "routeloom/sdkv1_handshake.hpp"
#include "routeloom/sdkv1_join_relay.hpp"
#include "routeloom/sdkv1_join_transport.hpp"
#include "routeloom/sdkv1_joiner.hpp"
#include "routeloom/observation.hpp"
#include "routeloom/profile.hpp"
#include "routeloom/sdkv1_membership.hpp"
#include "routeloom/sdkv1_records.hpp"
#include "routeloom/sdkv1_session_rtc.hpp"
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
  StopForLifecycle, // journaled removal/switch: Owner sweeps durable RLP2 one slot per Poll
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
  // Owner verified an RLX1 LeftReady boot: a local leave has no holdoff.
  // RLV1 cleanup and generation checks still apply.
  bool local_leave_completed{false};
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
  MutableByteView auth_writable{};
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
  std::uint8_t channel{0};  // adopted operating channel, independent of stale stores
  std::uint32_t message_session{0};
  std::uint32_t boot_session{0};  // rlboot witness, nonzero
  std::uint32_t rs_epoch_to_fetch{0};  // verified fresh-join package target
  std::uint32_t link_epoch{1};
  std::uint32_t end_epoch{1};
  std::uint64_t boot_incarnation{0};
  std::uint32_t role{0};  // rlcw1 member role bits
  // The two root lists are mutually exclusive — install_dev_config refuses
  // a config carrying both — so the arrays share one storage block. The
  // live arm follows the counts: route_gateway_count>0 selects
  // route_gateways, group_root_count>0 selects group_roots.
  // Flat-profile group tree roots (dev-flow §6.3): set by the dev adoption
  // path when the board config chooses flat routing; always empty on the
  // member path (the owner's local routing policy decides there).
  union {
    std::array<NodeId, kSiteGatewayMax> route_gateways;
    std::array<NodeId, kSiteGatewayMax> group_roots;
  };
  std::size_t route_gateway_count{0};
  std::size_t group_root_count{0};
};

struct CoordinatorRemoval {
  std::uint64_t site_id{0};
  std::uint32_t generation{0};
  RemovalNotice notice{};
  // The verified 103 B notice object the Joiner acted on, for the P6
  // lifecycle's journaled erasure (it re-verifies the COSE itself).
  std::array<std::uint8_t, kRemovalNoticeObjectSize> object{};
};

struct CoordinatorAction {
  CoordinatorActionKind kind{CoordinatorActionKind::None};
  // Single-slot staging (action_pending_ allows one action at a time), so
  // the payloads share storage; only the arm named by kind is live. All
  // arms are trivially copyable, so assigning an arm activates it.
  union {
    CoordinatorTune tune;
    CoordinatorMemberConfig member;
    CoordinatorRemoval removal;
    JoinRecoveryReason recovery;
  };
};

enum class CoordinatorMode : std::uint8_t {
  Fresh,      // constructed / stopped: no workspace running
  ZeroTouch,  // Joiner running (radio scan or USB direct)
  Member,     // adopted: engine + bank + proxy (+ gateway on role) live
  Dev,        // static dev adoption: dev-armed engine + bank live, no
              // Joiner/proxy/gateway/authority (P4 §10.1)
  Removed,    // verified removal landed: traffic stopped, evidence durable
  Recovery,   // stores need recovery before any mode can run
};

// Static dev adoption (P4 §10.1): the shared development PSK, network,
// node, durable boot token, local allow-role and operating channel. The
// boot must already be reserved (boot_hi) and the radio already on the
// channel — the dev route has no cutover. The PSK is copied into the
// engine policy and the group provider at adoption; the caller wipes its
// own copy (it cannot be wiped through this struct afterwards).
struct CoordinatorDevConfig {
  keys::Secret psk{};
  NetworkId network{0};
  NodeId node{kInvalidNodeId};
  std::uint32_t boot{0};  // reserved durable boot (message/boot session)
  std::uint32_t role{0};  // local allow-role (nonzero member-role bits)
  std::uint8_t channel{0};
  // Routing/group roots the board config picked for the dev profile
  // (dev-flow §6.1): gateways for the scoped profile, group_roots for the
  // flat group tree — at most one list is non-empty. Empty both keeps the
  // previous no-tree dev posture.
  std::array<NodeId, kSiteGatewayMax> route_gateways{};
  std::size_t route_gateway_count{0};
  std::array<NodeId, kSiteGatewayMax> group_roots{};
  std::size_t group_root_count{0};
};

struct CoordinatorSnapshot {
  CoordinatorMode mode{CoordinatorMode::Fresh};
  MembershipState membership{MembershipState::Unprovisioned};
  bool sleeping{false};
  bool action_pending{false};
  JoinState joiner{JoinState::Stopped};
  StatusCode joiner_last_error{StatusCode::Ok};
  std::uint32_t joiner_rx_dropped{0};
  std::uint32_t joiner_observations{0};
  std::uint32_t radio_generation{0};
  bool engine_quiescent{true};
  std::uint32_t link_sessions{0};
  std::uint32_t end_sessions{0};
  std::uint32_t demands{0};
  // Idle end contexts evicted to admit a new peer (profile end capacity).
  std::uint32_t end_evictions{0};
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
  std::uint32_t dev_adoptions{0};
  std::uint32_t removals{0};
  std::uint32_t demux_drops{0};
  std::uint32_t member_starts{0};
  std::uint32_t link_requests{0};
  std::uint32_t link_request_failures{0};
  std::uint32_t link_send_failures{0};
  std::uint32_t link_established{0};
  std::uint32_t link_failed{0};
  StatusCode link_last_error{StatusCode::Ok};
  std::uint32_t end_send_failures{0};
  std::uint32_t end_established{0};
  std::uint32_t end_failed{0};
  StatusCode end_last_error{StatusCode::Ok};
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
class AuthorityVerifiedSink {
 public:
  virtual ~AuthorityVerifiedSink() = default;
  // Called inside the channel's receive guard; copy only and dispatch later.
  virtual void on_verified_authority(std::uint8_t type, ByteView plaintext) noexcept = 0;
};

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
    // Sleep-capable firmware supplies a stable image outside the Owner's
    // always-on RAM. Null disables warm session save/restore.
    RtcSessionImage* sleep_image{nullptr};
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
    // EDHOC suite 2 AES-CCM. ESP-IDF has no portable builtin backend.
    const edhoc::AeadCcm* join_aead{nullptr};
    // Combined-tag GCM for the group provider and the authority channel
    // (a different port than the bank's split-tag AeadGcm above).
    routeloom::AeadGcm crypto_aead{};
    JoinCookieSealer* proxy_sealer{nullptr};
    AuthorityVerifiedSink* authority_sink{nullptr};
    MacAddress local_mac{};
    profile::Role allowed_role{profile::kMaxRole};
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
  // Static dev adoption (P4 §10.1) INSTEAD of Boot: arms the engine with
  // the dev-resume policy, configures the bank at the fixed dev epoch,
  // adopts the dev group sender/provider, scope and hooks, and emits
  // ApplyMemberConfig for the direct node adopt (no join, no RLS1). From
  // Fresh only; dev or member/boot, never both. Refuses Busy while a
  // port callback runs inside. Like Boot, advances the clock to `now`.
  Status adopt_dev(const CoordinatorDevConfig& config, MonotonicMs now) noexcept;
  Status take_action(CoordinatorAction& out) noexcept;
  CoordinatorSnapshot snapshot() const noexcept;
  // The mode alone: snapshot() also walks the session bank and joiner.
  CoordinatorMode mode() const noexcept { return mode_; }
  // Manual channel plan (V2-08): the channel of the node's durable plan
  // record replaces the SitePackage channel as the Member operating
  // channel. set_plan_channel() before Boot takes the stored record;
  // note_plan_cutover() after a verified plan switch moves the RLD1 demux
  // to the new channel and radio generation (false while an adoption or a
  // join tune owns the channel: retry later). 0 = no plan.
  void set_plan_channel(std::uint8_t channel) noexcept { plan_channel_ = channel; }
  std::uint8_t operating_channel(std::uint8_t package_channel) const noexcept {
    return plan_channel_ != 0 ? plan_channel_ : package_channel;
  }
  bool note_plan_cutover(std::uint8_t channel, std::uint32_t radio_generation) noexcept;
  // Join-lifecycle record for this run (observation_v1, lab timetables).
  // Ages are durations against `now`; unstamped stages read unknown. The
  // flags mirror the live adoption latches (member_valid_, join_confirmed_);
  // the stamps are set beside those latches and cleared with them, so a
  // failed adoption or a stop can never leave a stale milestone behind.
  JoinMilestones milestones(MonotonicMs now) const noexcept;
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
  // Full radio discovery identity for the adopted member (or the dev
  // adoption: then the DevRam capability bit with the Required dev
  // scope). The capability word and observed local MAC must match the
  // handshake carrier exactly.
  Status member_discovery_config(DiscoveryConfig& out) noexcept;
  // The session provider view over the member bank, handed to the
  // firmware's MeshNode at construction. Unconfigured (not ready) until
  // a member config (or a dev adoption) lands; the node must not start
  // on it before ApplyMemberConfig. The view is the sleep write-ahead
  // guard over the group/pairwise mux: unarmed it purely delegates, so
  // every existing caller behaves exactly as before until a sleep image
  // restores into the bank. Pairwise scopes delegate to the adopted
  // bank; group scopes seal/open under the adopted GK (dev: under the
  // boot-scoped dev group key).
  SecurityProvider& session_provider() noexcept { return sleep_guard_; }
  std::uint32_t revoked_group_tx_attempts() const noexcept {
    return group_provider_.revoked_tx_attempts();
  }
  // Sleep save (P4 §9.3, V1-F07), Member mode after PrepareSleep parked
  // the coordinator: exports the (Link, parent) session plus the first
  // live EndToEnd session (when one stands) into `port` with the adopted
  // membership and the parent radio identity. Requires the park — call
  // after prepare_sleep, before sleep_enter — and re-verifies quiescence
  // (Busy: new work arrived, abort the attempt and retry later). Any
  // other refusal means cold sleep: proceed without warm restore. A
  // refusal leaves the port untouched; a stale image always fails the
  // wake boot check, so it can never warm-restore by accident.
  Status save_sleep_image(RtcSessionPort& port, NodeId parent, const MacAddress& parent_mac,
                          std::uint32_t parent_binding, MonotonicMs now) noexcept;
  // Sleep restore (P4 §9.3, V1-F07): consumes the retained image one-shot
  // once adopted, holds it while the parent re-binds post-wake, then
  // installs it and arms TX write-ahead. `next_boot` is this boot's
  // retained boot witness, `trusted_elapsed_ms` the upper bound proved
  // by post-wake evidence (0 = unknown, refused), `deep_sleep` /
  // `sleep_marker` the reset-cause + marker evidence. Busy (not adopted
  // yet, parked, or parent not bound yet) is retryable and touches
  // nothing durable; retries may raise trusted_elapsed_ms as the awake
  // time grows (positive deltas deduct from the held image, so the
  // install never over-credits the rebind gap). Any other refusal is
  // terminal for this boot and the device resumes through RLRES1
  // instead. Idempotent once restored. Clock-free: every time input
  // arrives pre-proved as the elapsed bound.
  Status restore_sleep_image(RtcSessionPort& port, std::uint32_t next_boot,
                             std::uint32_t trusted_elapsed_ms, bool deep_sleep,
                             bool sleep_marker) noexcept;
  // First usable session peer for `scope` in bank table order (false
  // when none stands): the save side resolves the retained link through
  // this. Side-effect-free observation, like snapshot().
  bool first_live_peer(SecurityScope scope, NodeId& peer) const noexcept;
  // The membership hooks over the adopted stores (dev: over the static
  // dev config plus the shared revocation gates), for the adopted
  // discovery's MembershipHooks port (the firmware initializes the
  // discovery's controller with these at StartMemberDiscovery).
  MembershipHooks& membership_hooks() noexcept {
    return mode_ == CoordinatorMode::Dev ? static_cast<MembershipHooks&>(dev().hooks)
                                         : static_cast<MembershipHooks&>(hooks_);
  }
  // The member OFFER cookie box, live in Member and Dev mode (null
  // otherwise): the adopted discovery authenticator seals OFFER cookies
  // through it. Never stored beyond the call — the workspace may be
  // replaced by removal or stop.
  const MemberCookie* member_cookie() const noexcept {
    return has_member_engine() ? &member().member_cookie : nullptr;
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
  // The live member discovery for read-only observation (neighbor
  // phase/lease): nullptr until attach_discovery, detached on P6 cutover
  // re-adoption — readers through here always see the current engine.
  const NeighborDiscovery* discovery() const noexcept { return deps_.discovery; }
  // Detaches the member discovery (P6 cutover re-adoption): the
  // firmware destroys the old-network engine and attaches a fresh one.
  // Refuses unless `discovery` is the attached instance.
  Status detach_discovery(NeighborDiscovery& discovery) noexcept {
    if (deps_.discovery != &discovery) {
      return Status::error(StatusCode::InvalidArgument, "foreign discovery detach");
    }
    deps_.discovery = nullptr;
    return Status::success();
  }

  // --- P6 lifecycle connection points (G-SEC P6 PR D) ---------------------------
  // Driven by the firmware Owner's MembershipLifecycle drain. Each is a
  // small, explicit hook — never a callback into the lifecycle — and
  // refuses Busy while a port callback runs inside.
  //
  // Starts a recovery join over the retained stores (SelfRevoked /
  // link-failure recovery, #139): the member engine stops (traffic
  // halted, bank/scope/cookies scrubbed) and the Joiner re-proves the
  // membership in VerifyExistingMembership mode. Member mode only; the
  // stores are untouched, so completion re-adopts (MemberReady),
  // lands the removal (RemovalRequired) or reports recovery. The mesh
  // node and discovery stay up: recovery never changes the network.
  Status start_recovery_join(MonotonicMs now) noexcept;
  // Device::request_join: a member re-verifies its membership (the
  // recovery join above); a zero-touch joiner ends its scan backoff now.
  Status request_join(MonotonicMs now) noexcept;
  // JoinPolicy (range-checked by the caller): the requested role and join
  // timing for the running and every later Joiner, and the RLV1 removal
  // holdoff from the next removal on.
  Status apply_join_policy(const JoinerConfig& policy, std::uint32_t holdoff_ms) noexcept;
  // Names the last removed (site, generation) from the RLX1 journal's
  // UnassignedReady watermark; both zero clears. Consumed at every
  // Joiner start so a post-removal Allow for an older generation of
  // the same site refuses. Harmless for recovery joins: the retained
  // generation always exceeds any removed one.
  void set_removal_watermark(std::uint64_t site_id, std::uint32_t generation) noexcept {
    removal_watermark_site_id_ = site_id;
    removal_watermark_generation_ = generation;
  }
  // Lifecycle-driven: true while the journal holds a Prepared/Switching
  // cutover intent. Such a member EXPECTS newer-generation traffic (the
  // new network's credentials going live is what its COMMIT installs),
  // so the unknown-ahead evidence must not accrue refresh strikes —
  // churning the workspace here is what strands the node mid-cutover.
  void set_cutover_intent(bool intent) noexcept { cutover_intent_ = intent; }
  // The site's durable ProxyPolicySet (RLPP1, #176): applied to the member
  // proxy now when it serves `site_id`, and at every adoption of that
  // site before the proxy starts. Another site's proxy stays open.
  void set_proxy_policy(std::uint64_t site_id, bool zero_touch_open,
                        const ExpectedJoinList* expected = nullptr, MonotonicMs now = 0) noexcept;
  // Wipes the member site trust held outside the stores (GK scope,
  // discovery membership) and verifies it is gone. Idempotent: safe to
  // re-assert after traffic already stopped.
  Status wipe_site_trust() noexcept;
  // Enforces an adopted RRS1 over the live member state: cancels
  // in-flight handshakes, retires every bank session of a rejected
  // peer, revokes the Discovery binding. RLP1 is swept by the
  // lifecycle itself; RLP2 lookups already fence on the adopted set.
  // A readmitted entry retires only sessions below its min_generation;
  // `retired_old` marks entries whose old context needs queued sends
  // cancelled; `retired_links` marks those needing route withdrawal.
  // No-op outside Member mode.
  Status revoke_member_sessions(const RevocationSet& set, std::uint32_t site_epoch,
                                MonotonicMs now,
                                std::uint32_t* retired_old = nullptr,
                                std::uint32_t* retired_links = nullptr) noexcept;
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
  AuthoritySnapshot authority_snapshot() const noexcept {
    // No channel exists in Dev (see snapshot): report the unstarted view.
    if (mode_ == CoordinatorMode::Dev) return AuthoritySnapshot{};
    return small().authority.snapshot();
  }
  // Secret-free ZT proxy view for diagnostics and the D04 mesh harness
  // (zero without a member engine — a refreshing joiner proxies for no
  // one while it re-verifies).
  JoinProxyStats proxy_stats() const noexcept {
    if (!has_member_engine()) return JoinProxyStats{};
    return member().proxy.stats();
  }
  // Secret-free ZT joiner view for diagnostics and the D04 mesh
  // harness (zero outside ZeroTouch mode).
  JoinSnapshot joiner_snapshot() const noexcept {
    if (mode_ != CoordinatorMode::ZeroTouch) return JoinSnapshot{};
    return joiner().snapshot();
  }
  // Retained membership can resume after an exhausted search; the Device
  // operation must report that result rather than a new successful join.
  StatusCode join_search_result() const noexcept { return join_search_result_; }
  Status send_authority_typed(std::uint8_t type, ByteView body, MonotonicMs now) noexcept;
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
  bool authenticated_link(NodeId peer, NetworkId network, std::uint32_t& generation,
                          std::uint32_t& role) const noexcept;
  bool boot_witness_ok(std::uint32_t witness) const noexcept override;
  // AuthorityObserver (channel context): counts verified events. Never
  // drives the channel (no advance from the callback).
  void on_event(const AuthorityEvent& event) noexcept override;

 private:
  friend struct SecurityCoordinatorTestAccess;
  static constexpr std::size_t kDemuxEntries = 8;
  static constexpr std::size_t kStagedFrames = 4;
  static constexpr std::uint32_t kDemuxHoldMs = 30000;

  struct DemuxEntry {
    bool used{false};
    MacAddress mac{};
    NodeId peer{kInvalidNodeId};  // claimed (taken start / request)
    std::uint32_t object_id{0};
    MonotonicMs expires_at{0};
    // Member responder legs park the taken discovery start until m1/R1.
    bool has_start{false};
    bool initiator{false};
    keys::LinkCarrier carrier{};
    std::uint32_t discovery_token{NeighborDiscovery::kMemberHandshakeNone};
    std::uint32_t quiet_retry_token{0};  // RLRES1 R3 may need three more sends
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

  // Stable session view over the two adopted profiles (P4 §10.1):
  // pairwise scopes always delegate to the member bank, group scopes to
  // the GK-backed provider in Member mode and to the boot-scoped dev
  // group provider once a dev adoption binds it. The firmware holds this
  // (through the sleep guard) from construction; the Owner flips the
  // group side exactly once per adoption and back on stop.
  class SessionProviderMux final : public SecurityProvider {
   public:
    SessionProviderMux(SecurityProvider& pairwise, SecurityProvider& member_group) noexcept
        : pairwise_(pairwise), member_group_(member_group) {}
    SessionProviderMux(const SessionProviderMux&) = delete;
    SessionProviderMux& operator=(const SessionProviderMux&) = delete;
    void set_dev_group(SecurityProvider* dev_group) noexcept { dev_group_ = dev_group; }
    void set_dev(bool dev) noexcept { dev_ = dev && dev_group_ != nullptr; }
    bool dev() const noexcept { return dev_; }

    bool ready() const noexcept override;
    SecurityProfile security_profile() const noexcept override;
    Status tx_epoch(SecurityScope scope, NodeId peer, std::uint32_t& epoch) noexcept override;
    Status current_rx_epoch(SecurityScope scope, NodeId peer,
                            std::uint32_t& epoch) const noexcept override;
    ContextState context_state(SecurityScope scope, NodeId peer) const noexcept override;
    Status tx_group_link_epochs(std::uint32_t& boot, std::uint32_t& g) noexcept override;
    bool accepts_group_epoch(std::uint32_t g) const noexcept override;
    bool revoked_group_sender(NodeId sender, std::uint32_t gk_epoch) const noexcept override;
    bool group_promotion_pending() const noexcept override;
    Status next_counter(const SecurityContext& context, std::uint64_t& counter) noexcept override;
    Status seal(const SecurityContext& context, std::uint64_t counter, ByteView aad,
                ByteView plaintext, MutableByteView ciphertext,
                std::array<std::uint8_t, kAeadTagSize>& tag) noexcept override;
    Status open(const SecurityContext& context, std::uint64_t counter, ByteView aad,
                ByteView ciphertext, const std::array<std::uint8_t, kAeadTagSize>& tag,
                MutableByteView plaintext) noexcept override;
    void note_rx_unknown_context(const SecurityContext& context) noexcept override;

   private:
    static bool is_group(SecurityScope scope) noexcept {
      return scope == SecurityScope::Group || scope == SecurityScope::GroupLink;
    }
    SecurityProvider& group() noexcept {
      return dev_ && dev_group_ != nullptr ? *dev_group_ : member_group_;
    }
    const SecurityProvider& group() const noexcept {
      return dev_ && dev_group_ != nullptr ? *dev_group_ : member_group_;
    }
    SecurityProvider& pairwise_;
    SecurityProvider& member_group_;
    SecurityProvider* dev_group_{nullptr};
    bool dev_{false};
  };

  // --- step() legs ---
  Status on_boot(const CoordinatorEvent& event) noexcept;
  Status on_poll(MonotonicMs now) noexcept;
  Status on_rld1_rx(const CoordinatorEvent& event) noexcept;
  Status on_usb(const CoordinatorEvent& event) noexcept;
  Status on_channel_ready(const CoordinatorEvent& event) noexcept;
  Status on_prepare_sleep(MonotonicMs now) noexcept;
  Status on_wake(MonotonicMs now) noexcept;
  Status on_stop(MonotonicMs now, bool defer_resume_clear = false) noexcept;
  // --- authority channel legs ---
  Status on_authority_rx(const CoordinatorEvent& event) noexcept;
  Status on_authority_tx(const CoordinatorEvent& event) noexcept;
  Status on_request_pull(const CoordinatorEvent& event) noexcept;
  Status on_usb_session_up(MonotonicMs now) noexcept;
  void drive_authority(MonotonicMs now) noexcept;
  void probe_quiet_authority(MonotonicMs now) noexcept;
  bool build_authority_start(AuthorityStart& out) const noexcept;
  void suspend_authority() noexcept;
  // --- stale-GK refresh (P5 §7.4) ---
  void note_link_established() noexcept;
  void note_link_failed(MonotonicMs now) noexcept;
  void watch_linkless(MonotonicMs now) noexcept;
  void start_refresh(MonotonicMs now) noexcept;
  void maybe_abandon_refresh(MonotonicMs now) noexcept;
  // --- MemberReady adoption ---
  Status adopt_member(const JoinAction& ready, MonotonicMs now) noexcept;
  Status adopt_boot_rls1(MonotonicMs now, std::uint32_t rs_epoch_to_fetch = 0) noexcept;  // same tail, stored site
  Status install_member_config(const SiteRecord& site, const IdentityRecord& identity,
                               std::uint32_t boot_session, MonotonicMs now,
                              std::uint32_t rs_epoch_to_fetch = 0) noexcept;
  // --- static dev adoption (P4 §10.1) ---
  Status install_dev_config(const CoordinatorDevConfig& config, MonotonicMs now) noexcept;
  // Scrubs the half-built dev adoption into Recovery (ReportRecovery).
  void abandon_dev_adoption(JoinRecoveryReason reason) noexcept;
  DevGroupProvider& dev_group() noexcept;
  void emit_member_action() noexcept;
  // The workspace holds the member engine side (Member or Dev): the
  // engine, bank, cookie, demands and demux legs all run there; only the
  // join proxy/gateway, authority channel and GK refresh are Member-only.
  bool has_member_engine() const noexcept {
    return mode_ == CoordinatorMode::Member || mode_ == CoordinatorMode::Dev;
  }
  // --- RLD1 demux ---
  DemuxEntry* find_demux(const MacAddress& mac, std::uint32_t object_id) noexcept;
  DemuxEntry* claim_demux(const MacAddress& mac, std::uint32_t object_id,
                          MonotonicMs now) noexcept;
  void sweep_demux(MonotonicMs now) noexcept;
  Status demux_member_frame(const autonomy::Rld1Envelope& env, DemuxEntry* entry,
                            MonotonicMs now) noexcept;
  // Reserves the discovery elevation token for a parked responder leg on
  // first inbound handshake traffic (the initiator side reserves at leg
  // claim instead). Best-effort: a refused reservation leaves the token
  // None and the session installs without discovery elevation.
  void ensure_responder_token(DemuxEntry& entry, MonotonicMs now) noexcept;
  // --- engine legs ---
  Status drive_engine(MonotonicMs now) noexcept;
  Status emit_send(const HandshakeResult& result, MonotonicMs now) noexcept;
  Status emit_link_send(const HandshakeResult& result, MonotonicMs now) noexcept;
  Status pump_link_tx(MonotonicMs now) noexcept;
  Status emit_end_send(const HandshakeResult& result, MonotonicMs now) noexcept;
  Status pump_end_tx(MonotonicMs now) noexcept;
  Status installed_link(const HandshakeResult& result, MonotonicMs now) noexcept;
  void drain_demands(MonotonicMs now) noexcept;
  void drain_engine_results(MonotonicMs now) noexcept;
  // --- staged bootstrap RX ---
  void drain_staged(MonotonicMs now) noexcept;
  void handle_bootstrap_frame(const StagedFrame& frame, MonotonicMs now) noexcept;
  void handle_end_single(const BootstrapMeta& meta, ByteView payload, MonotonicMs now) noexcept;
  // Hands a join-relay frame the proxy saw to the gateway engine: gateway
  // profiles only, and only while the site grants this node the gateway
  // role.
  void gateway_relay_rx(const BootstrapMeta& meta, FrameType type, ByteView payload,
                        MonotonicMs now) noexcept;
  void handle_end_chunk(const BootstrapMeta& meta, ByteView payload, MonotonicMs now) noexcept;
  // --- Joiner legs ---
  void drain_joiner(MonotonicMs now) noexcept;
  void on_joiner_action(const JoinAction& action, MonotonicMs now) noexcept;
  void emit_action(const CoordinatorAction& action) noexcept;
  // --- removal ---
  Status land_removal(const RemovalNotice& notice, ByteView removal_object,
                      MonotonicMs now) noexcept;
  void stop_traffic(bool clear_resume = true) noexcept;
  // The real quiescence check, for PrepareSleep (which runs inside step()
  // with the re-entry guard set, where the public query answers false).
  bool quiescent_locked() const noexcept;
  // Member handshake/session work regardless of the park: live engine
  // legs, bank establishment demands, or live demux legs (completed
  // member legs only route late duplicates and never count). Shared by
  // quiescent_locked and the save-time re-check (which may not use the
  // parked short-circuit).
  bool member_work_pending() const noexcept;
  // Abandons the held restore image (wiped) and latches the terminal
  // failure for this boot.
  Status fail_restore(const Status& status) noexcept;

  // Everything the member handshake owns that no outside reference
  // touches: the engine with its cookie and resume cache, the demand
  // driver, the link/end chunk slots, the proxy and relay gateway, and
  // the RLD1 demux table. Lives in the workspace union opposite the
  // Joiner — the two never share a boot phase, so they never share RAM.
  struct MemberEngine {
    ResumeCache2 resume_cache;
    MemberCookie member_cookie;
    HandshakeEngine engine;
    BootstrapDemandDriver<profile::kLinkSessions, profile::kEndSessions> demands;
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
    NodeId end_tx_peer{kInvalidNodeId};
    MonotonicMs end_tx_last_attempt_ms{0};
    JoinProxy proxy;
#if ROUTELOOM_PROFILE_HAS_GATEWAY
    // Join relay (gateway profiles only): the gateway engine and the
    // colocated proxy use one Owner callback stack. Defer local relay
    // frames until poll so replies and chunk receipts never re-enter
    // either engine's guarded port callback.
    JoinRelayGateway gateway;
    static constexpr std::size_t kLocalRelaySlots = 16;
    struct LocalRelayFrame {
      FrameType type{FrameType::BootstrapAuth};
      std::uint8_t size{0};
      std::array<std::uint8_t, kMaxApplicationPayload> bytes{};
    };
    std::array<LocalRelayFrame, kLocalRelaySlots> local_relay{};
    std::uint8_t local_relay_head{0};
    std::uint8_t local_relay_count{0};
#endif
    std::array<DemuxEntry, kDemuxEntries> demux{};
    // Always false outside the gateway profiles.
    bool gateway_active{false};

    MemberEngine(ResumeSlotStorage2& resume, ProfileSessionBank& bank,
                 BankSessionSink<profile::kLinkSessions, profile::kEndSessions>& sink,
                 HandshakeMembershipView& membership, SessionCredentialVerifier& verifier,
                 EntropySource& entropy, ZtRld1Port& rld1, ZtRelayPort& relay,
                 JoinCookieSealer& sealer, const JoinProxyConfig& proxy_config,
                 const JoinRelayGatewayConfig& gateway_config, const edhoc::AeadCcm* aead) noexcept;
  };

  // Tagged by mode_: joiner iff ZeroTouch, member iff Member or Dev,
  // neither anywhere else. Transitions destroy one side (wiping it)
  // before constructing the other; the destructor destroys the live side.
  union Workspace {
    Workspace() noexcept {}
    ~Workspace() noexcept {}
    Joiner joiner;
    MemberEngine member;
  };

  // The member small side holds the authority channel client (G-SEC P5).
  // The sleep image is supplied separately by sleep-capable firmware, so
  // an always-on gateway does not reserve that memory. Live except in Dev.
  struct MemberSmallSide {
    AuthorityClient authority;
    MemberSmallSide(const routeloom::AeadGcm& aead, AuthorityPort& port,
                    AuthorityObserver& observer, rlres1::Environment& rlres1_env,
                    GroupKeyState* group) noexcept;
    ~MemberSmallSide() noexcept = default;
    MemberSmallSide(const MemberSmallSide&) = delete;
    MemberSmallSide& operator=(const MemberSmallSide&) = delete;
  };

  // The dev side (P4 §10.1, Dev mode only): the boot-scoped group sender,
  // the group provider over it (placement-built at adoption), the
  // Required dev scope view and the dev hooks. The destructor tears the
  // provider down and wipes the sender/scope/hooks.
  struct DevSide {
    DevGroupSender sender{};
    alignas(DevGroupProvider) std::array<std::uint8_t, sizeof(DevGroupProvider)> group_box{};
    bool group_live{false};
    DevScopeProvider scope{};
    DevMembershipHooks hooks;
    DevSide(const RevocationStore& revocations, const LocalRevocationStore& local_revocation,
            const AuthenticatedPeerView* peers) noexcept;
    ~DevSide() noexcept;
    DevSide(const DevSide&) = delete;
    DevSide& operator=(const DevSide&) = delete;
    DevGroupProvider& group() noexcept;
  };

  // Tagged by mode_: dev iff Dev, small everywhere else. Dev adoption
  // destroys the small side before constructing the dev side; stop and
  // abandon rebuild the small side when leaving Dev. The two sides never
  // share a boot phase, so they never share RAM: the dev side rides
  // inside the slack of the member-only channel state — bridge DRAM has
  // no room for both (RAM floor matrix).
  union ModeSides {
    ModeSides() noexcept {}
    ~ModeSides() noexcept {}
    MemberSmallSide small;
    DevSide dev;
  };
  static_assert(sizeof(DevSide) <= sizeof(MemberSmallSide),
                "dev side must fit the member small side");

  // --- mode workspace (exactly one live; see above) ---
  void destroy_workspace() noexcept;
  void create_joiner() noexcept;
  void create_member() noexcept;
  Joiner& joiner() noexcept {
    assert(mode_ == CoordinatorMode::ZeroTouch);
    return ws_.joiner;
  }
  const Joiner& joiner() const noexcept {
    assert(mode_ == CoordinatorMode::ZeroTouch);
    return ws_.joiner;
  }
  MemberEngine& member() noexcept {
    assert(has_member_engine());
    return ws_.member;
  }
  const MemberEngine& member() const noexcept {
    assert(has_member_engine());
    return ws_.member;
  }
  // --- mode sides (exactly one live; see above) ---
  void destroy_small() noexcept;
  void create_small() noexcept;
  void create_dev() noexcept;
  void destroy_dev() noexcept;
  MemberSmallSide& small() noexcept { return sides_.small; }
  const MemberSmallSide& small() const noexcept { return sides_.small; }
  DevSide& dev() noexcept { return sides_.dev; }
  const DevSide& dev() const noexcept { return sides_.dev; }

  Deps deps_{};
  CoordinatorMode mode_{CoordinatorMode::Fresh};
  SdkMembershipHooks hooks_;
  NullJoinObserver joiner_observer_{};
  StatusCode join_search_result_{StatusCode::Ok};
  // The bank stays outside the union: the firmware binds the session
  // provider over it at construction, before any workspace exists. The
  // GK state, the group/pairwise mux, the scope views and the authority
  // channel stay outside the union too: a stale-GK refresh destroys the
  // member engine around them without resetting group counters, replay
  // windows or the adopted scope.
  ProfileSessionBank bank_;
  BankSessionSink<profile::kLinkSessions, profile::kEndSessions> bank_sink_;
  RamSessionProvider<profile::kLinkSessions, profile::kEndSessions> pairwise_provider_;
  GroupKeyState group_keys_;
  GroupSecurityProvider group_provider_;
  // Mode sides (exactly one live; tagged by mode_): the member small
  // side everywhere except Dev, the dev route (P4 §10.1 — group sender
  // and provider, Required dev scope view, dev hooks) in Dev. The
  // constructor builds the small side; dev adoption swaps it for the dev
  // side and stop/abandon swap back when leaving Dev.
  ModeSides sides_;
  // Stable session view: pairwise to the bank, group to the GK provider
  // (Member) or the dev group provider (Dev, once bound above).
  SessionProviderMux provider_mux_;
  // Retained TX write-ahead over the mux (unarmed: pure delegate; the
  // bank installer underneath retires diverged slots). Armed only by
  // restore_sleep_image (Member); disarmed by stop, removal, and wake.
  RtcWriteAheadProvider sleep_guard_;
  GkMemberScopeProvider member_scope_;
  AuthorityPortProxy authority_port_;
  AuthorityEnv authority_env_;
  Workspace ws_{};

  std::array<StagedFrame, kStagedFrames> staged_{};
  CoordinatorAction action_{};
  bool action_pending_{false};
  bool authority_wanted_{false};  // adopted: the channel (re)starts on poll
  bool join_confirmed_{false};    // latched on the verified JoinConfirm ACK
  // Milestone stamps (observation_v1): each lives and dies with the latch
  // it mirrors — join_started_ with the current join leg, adopted_ with
  // member_valid_, confirmed_ with join_confirmed_. A stop clears all
  // three; a failed adoption clears adopted_/confirmed_ with member_valid_.
  // Three 48-bit boot-monotonic millisecond stamps cover more than a year
  // without the 32-bit millisecond wrap or lost subsecond precision, while
  // keeping the bridge's 24-byte state footprint. Flags indicate validity.
  std::array<std::uint8_t, 6> milestone_join_started_ms_{};
  std::array<std::uint8_t, 6> milestone_adopted_ms_{};
  std::array<std::uint8_t, 6> milestone_confirmed_ms_{};
  // Attempts saturate at u16: one leg cannot handshake that often in a boot.
  // Handshake attempts in the current leg: live from the Joiner while
  // ZeroTouch, latched here at adoption (the Joiner is destroyed once the
  // member side goes live).
  std::uint16_t milestone_attempts_{0};
  std::uint8_t milestone_flags_{0};
  std::uint8_t milestone_joiner_latched_{kJoinerUnknown};
  static constexpr std::uint8_t kMilestoneStarted = 0x01;
  static constexpr std::uint8_t kMilestoneAdoptedBit = 0x02;
  static constexpr std::uint8_t kMilestoneConfirmedBit = 0x04;
  static constexpr std::uint8_t kMilestoneLatched = 0x08;
  void note_milestone_leg_started(MonotonicMs now) noexcept;
  void note_milestone_adopted(MonotonicMs now) noexcept;
  void note_milestone_dev_adopted(MonotonicMs now) noexcept;
  void note_milestone_confirmed() noexcept;
  void clear_milestone_adopted() noexcept;
  void clear_milestone_confirmed() noexcept;
  void clear_milestones() noexcept;
  std::uint8_t refresh_strikes_{0};
  std::uint32_t last_unknown_newer_generation_{0};  // discovery scope_stats sample
  bool refresh_active_{false};
  MonotonicMs refresh_start_{0};
  MonotonicMs refresh_cooldown_until_{0};
  MonotonicMs last_authority_start_{0};
  // 04 §3.5: last live-links strike (spacing clock — the live road
  // strikes once per window at most, so one rotation overlap cannot
  // refresh a converging member by itself).
  MonotonicMs last_live_strike_{0};
  // The last actual strike increment — the refresh herd-spread arms
  // its start slot from here (the spacing stamp moves every window;
  // this one only on real evidence, so the due is a fixed point).
  MonotonicMs last_strike_ms_{0};
  // 04 §3.5: quiet-channel present-check probe. A Ready channel with
  // no verified RX for the idle-retire span asks (Pull) instead of
  // retiring silently; consecutive unanswered probes strike. Poll-
  // gated (a sleeping member never probes), so the power cost lands
  // only on awake-but-quiet members, one Pull per interval.
  MonotonicMs last_probe_ms_{0};
  MonotonicMs last_rx_ms_{0};    // last verified-RX growth (0 = never)
  MonotonicMs intent_since_ms_{0};  // first poll the cutover-intent hold was seen
  std::uint64_t last_rx_value_{0};
  CoordinatorMemberConfig adopted_{};
  bool member_valid_{false};
  std::uint32_t tune_outstanding_{0};
  std::uint8_t channel_{0};
  std::uint8_t plan_channel_{0};
  std::uint32_t radio_generation_{0};
  std::uint32_t boot_witness_{0};
  bool sleeping_{false};
  bool in_port_{false};
  bool usb_direct_{false};
  bool discovery_started_{false};
  bool member_apply_pending_{false};
  MonotonicMs last_now_{0};
  bool removal_holdoff_armed_{false};
  std::uint32_t removal_holdoff_ms_{kLocalRevocationHoldoffMs};
  MonotonicMs removal_holdoff_at_{0};
  std::uint64_t removal_watermark_site_id_{0};
  // The site whose stored ProxyPolicySet is closed (0: every proxy open).
  ExpectedJoinList proxy_expected_{};
  MonotonicMs proxy_expected_expires_{0};
  std::uint64_t proxy_expected_site_{0};
  std::uint64_t proxy_closed_site_id_{0};
  std::uint32_t removal_watermark_generation_{0};
  bool cutover_intent_{false};
  CoordinatorCounters counters_{};
  // Sleep restore one-shot state (P4 §9.3): the consumed image waits in
  // caller-supplied storage while the parent re-binds post-wake. Terminal
  // once done/failed. restore_elapsed_ms_ is the bound already deducted
  // from the held image; retries with a larger bound deduct the delta.
  //
  // Dev boot consumption memory (P4 §10.1): the highest dev boot this
  // coordinator configured a group sender for (0 = none yet). The dev side is rebuilt
  // per adoption, so the sender's own boot guard cannot see a previous
  // adoption's boot — install refuses any non-advancing boot before configuring
  // (the same key never restarts its counter space). Survives stop: the
  // boot does not change across one.
  std::uint32_t dev_boot_seen_{0};
  bool restore_holding_{false};
  bool restore_done_{false};
  bool restore_failed_{false};
  std::uint32_t restore_elapsed_ms_{0};
  Status restore_error_{StatusCode::Ok, "ok"};
};

}  // namespace routeloom::sdkv1
