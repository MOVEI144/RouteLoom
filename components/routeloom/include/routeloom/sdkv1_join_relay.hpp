#pragma once

// SDK v1 zero-touch join transport engines (docs/design/sdk-v1/02-zero-touch-
// join.md §4, §5, §7; plan P3-1/P3-2). Three portable, allocation-free state
// machines over the codecs of sdkv1_join_transport.hpp:
//
//   ZtJoinerLink      the unassigned device's end of the RLD1 hop: ZT
//                     DISCOVER/OFFER, BootstrapAuth phases 4-6, one bounded
//                     1024 B object slot. The join FSM (P3-4) drives it.
//   JoinProxy         a member that relays ONE neighbour's join exchange at a
//                     time between RLD1 and the Wire relay lane toward its
//                     gateway (02 §7.3), with the stateless OFFER cookie, the
//                     1-per-2 s m1 budget, the 20 s / 5 s timeouts and
//                     RelayStatus hints.
//   JoinRelayGateway  the gateway end: reassembles relay objects from proxies
//                     and hands them to the host (USB HostOps 0x60/0x62 via
//                     JoinRelayHostSink), and delivers the host's down objects
//                     (0x61) to the proxy, retransmitting chunks until the
//                     proxy's receipt.
//
// None of them touches a radio, the mesh or the clock: all TX goes through
// ports, all time through the injected now_ms, all randomness through an
// EntropySource. They never parse EDHOC: the device and the Site Authority
// own the handshake; a relay forwards bytes and cannot read or alter them
// undetected (EDHOC protects end to end, 02 §7.1).
//
// Not wired into firmware yet (P3-4 / the Owner): RLD1 frames of the
// zero-touch lane (zt_rld1_frame) must be routed here by transaction nonce,
// and the relay port must ride MeshNode's routed Wire lane (FrameTypes 3-6,
// link-protected per hop, no kFlagEndProtected).

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/admission.hpp"
#include "routeloom/fixed_containers.hpp"
#include "routeloom/sdkv1_join_transport.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom {
class EntropySource;  // routeloom/discovery.hpp
}  // namespace routeloom

namespace routeloom::sdkv1 {

// --- Ports -------------------------------------------------------------------------

// RLD1 TX (1 hop). `frame` is a complete RLD1 frame.
class ZtRld1Port {
 public:
  virtual ~ZtRld1Port() = default;
  virtual Status send_rld1(const MacAddress& destination, ByteView frame) noexcept = 0;
};

// Wire relay TX between members (routed, link-protected per hop). `payload`
// is the Wire payload of FrameType 3/4/5/6.
class ZtRelayPort {
 public:
  virtual ~ZtRelayPort() = default;
  virtual Status send_relay(NodeId destination, FrameType type, ByteView payload) noexcept = 0;
};

// --- OFFER cookie (02 §5.2, 06 admission §3.2) ---------------------------------------
// The cookie authorizes the proxy's expensive work for the peer that echoes
// it: bound to the requester's observed MAC, its transaction nonce, the
// proxy and site network and a coarse time bucket. It is not identity.
struct JoinCookieMaterial {
  MacAddress requester_mac{};
  JoinNonce nonce{};
  NodeId proxy{kInvalidNodeId};
  std::uint32_t network_low32{0};
  std::uint64_t bucket{0};
};

class JoinCookieSealer {
 public:
  virtual ~JoinCookieSealer() = default;
  virtual Status seal(const JoinCookieMaterial& material, JoinCookieBytes& out) noexcept = 0;
};

// first16(HMAC-SHA-256(key, "RouteLoom/zt-cookie/v1" 00 || mac 6 || nonce 16 ||
// proxy u64 || network_low32 u32 || bucket u64)). The 32-byte key is local
// RAM-only state drawn from boot entropy; a reboot invalidates old cookies.
class HmacJoinCookie final : public JoinCookieSealer {
 public:
  // Unkeyed: seal() refuses until install_key() arms the sealer. The
  // firmware owner needs this split — the coordinator (which holds the
  // sealer) is constructed before radio-up entropy exists, and the
  // cookie key must be drawn only after the radio entropy source is
  // ready (G-SEC P4 §8.4), never from weak pre-RF randomness.
  HmacJoinCookie() noexcept = default;
  explicit HmacJoinCookie(const std::array<std::uint8_t, 32>& key) noexcept
      : key_(key), keyed_(true) {}
  ~HmacJoinCookie() override;
  // One-time arming; refuses a second key (no silent rekey under a live
  // coordinator) and refuses to arm from an all-zero key.
  Status install_key(const std::array<std::uint8_t, 32>& key) noexcept;
  bool keyed() const noexcept { return keyed_; }
  Status seal(const JoinCookieMaterial& material, JoinCookieBytes& out) noexcept override;

 private:
  std::array<std::uint8_t, 32> key_{};
  bool keyed_{false};
};

inline constexpr char kJoinCookieDomain[] = "RouteLoom/zt-cookie/v1";

// --- Frame header rules for the object lane ---------------------------------------
// Every BootstrapAuth/chunk/reply frame of an exchange repeats the DISCOVER's
// transaction nonce; the device sends network_hint 0 and claimed_node = its
// NodeId, the proxy network_hint = network_low32 and claimed_node = its
// NodeId; capability_bits are 0. Receivers check the peer's values.

// ===================================================================================
// ZtJoinerLink — the device end
// ===================================================================================
struct ZtOfferView {
  MacAddress proxy_mac{};  // observed source
  NodeId proxy{kInvalidNodeId};
  std::uint32_t network_low32{0};
  JoinNonce nonce{};
  ZtOfferBody body{};
};

class ZtJoinerObserver {
 public:
  virtual ~ZtJoinerObserver() = default;
  // A well-formed OFFER for the current DISCOVER whose org_hint matches.
  virtual void on_offer(const ZtOfferView& offer) noexcept = 0;
  // A complete down message (phase 4 steps 2/4/5, phase 5 step 2), once per
  // stage: retransmitted duplicates are filtered by the link. `message` is
  // valid only during the call and may alias the object slot, so read it
  // before re-entering the link. send()/close()/discover() from inside the
  // callback return Busy and leave the link unchanged; the Owner drives the
  // next step after this callback returns.
  virtual void on_message(JoinAuthPhase phase, std::uint8_t step, ByteView message) noexcept = 0;
  // Unauthenticated proxy hint (02 §5.3 phase 6): wait, never a verdict.
  virtual void on_relay_status(RelayStatusCode status, std::uint32_t retry_after_ms) noexcept = 0;
  // The up object could not be delivered (retransmissions exhausted).
  virtual void on_link_failure(const char* reason) noexcept = 0;
};

struct ZtJoinerConfig {
  NodeId node{kInvalidNodeId};
  MacAddress mac{};
  std::uint32_t org_hint{0};
  std::uint32_t assembly_timeout_ms{3000};  // 02 §10.1: one assembly, 3 s
  std::uint32_t retransmit_ms{400};
  std::uint8_t max_sends{4};  // first send + 3 retransmissions
};

struct ZtJoinerStats {
  std::uint32_t discovers_tx{0};
  std::uint32_t offers_rx{0};
  std::uint32_t offers_ignored{0};
  std::uint32_t frames_rejected{0};
  std::uint32_t messages_rx{0};
  std::uint32_t objects_tx{0};
  std::uint32_t retransmissions{0};
  std::uint32_t assembly_conflicts{0};
  std::uint32_t assembly_expired{0};
  std::uint32_t send_failures{0};
};

class ZtJoinerLink {
 public:
  ZtJoinerLink(const ZtJoinerConfig& config, ZtRld1Port& port, EntropySource& entropy,
               ZtJoinerObserver& observer) noexcept;

  // The owner's MembershipState (Discovering / Authenticating); every RX and
  // TX is re-checked with zt_admit_rld1 on it.
  Status set_membership(MembershipState state) noexcept;

  // New attempt: fresh nonce, forget any proxy, broadcast one DISCOVER.
  Status discover(const ZtDiscoverBody& body, MonotonicMs now_ms) noexcept;
  // Pin the exchange to one OFFER of the current DISCOVER.
  Status connect(const ZtOfferView& offer) noexcept;
  // Send an up message (phase 4 steps 1/3/5, phase 5 steps 1/3). The cookie
  // rides step 1 of both phases; objects above 116 B are chunked and
  // retransmitted until the proxy's Complete reply.
  Status send(JoinAuthPhase phase, std::uint8_t step, ByteView message,
              MonotonicMs now_ms) noexcept;
  // Forget the proxy and wipe the slot (attempt finished or abandoned).
  Status close() noexcept;

  Status on_rld1_rx(const MacAddress& source, const MacAddress& destination, ByteView frame,
                    MonotonicMs now_ms) noexcept;
  Status poll(MonotonicMs now_ms) noexcept;

  bool connected() const noexcept { return connected_; }
  const JoinNonce& nonce() const noexcept { return nonce_; }
  const ZtJoinerStats& stats() const noexcept { return stats_; }
  const JoinObjectSlot& slot() const noexcept { return slot_; }

 private:
  Status emit(const MacAddress& destination, FrameType kind, ByteView body) noexcept;
  Status discover_impl(const ZtDiscoverBody& body, MonotonicMs now_ms) noexcept;
  Status connect_impl(const ZtOfferView& offer) noexcept;
  Status send_impl(JoinAuthPhase phase, std::uint8_t step, ByteView message,
                   MonotonicMs now_ms) noexcept;
  void close_impl() noexcept;
  void on_rld1_rx_impl(const MacAddress& source, const MacAddress& destination, ByteView frame,
                       MonotonicMs now_ms) noexcept;
  void poll_impl(MonotonicMs now_ms) noexcept;
  void send_reply(const JoinReply& reply) noexcept;
  void send_due_chunks(MonotonicMs now_ms) noexcept;
  bool from_proxy(const MacAddress& source, const autonomy::Rld1Envelope& env) const noexcept;

  ZtJoinerConfig config_{};
  ZtRld1Port& port_;
  EntropySource& entropy_;
  ZtJoinerObserver& observer_;
  MembershipState membership_{MembershipState::Discovering};
  JoinNonce nonce_{};
  // org_hint of the DISCOVER that produced `nonce_`: OFFERs answer the
  // scan window that is open, not the constructor's single anchor, so a
  // multi-anchor scan can rotate windows without rewiring the link.
  std::uint32_t discover_org_hint_{0};
  bool discovering_{false};
  bool connected_{false};
  MacAddress proxy_mac_{};
  NodeId proxy_{kInvalidNodeId};
  std::uint32_t network_low32_{0};
  JoinCookieBytes cookie_{};
  // join_sub() of the newest down message handed to the observer; a frame
  // or chunk only displaces the Sending object when it advances past it.
  std::uint8_t last_down_sub_{0};
  JoinObjectSlot slot_{};
  ZtJoinerStats stats_{};
  bool in_call_{false};
};

// ===================================================================================
// JoinProxy — one relay at a time (02 §7.3)
// ===================================================================================

// Gateway-epoch cache and query policy (#116 §3.3): a proxy learns its
// gateway's service epoch with a 24 B query before admitting a relay, keeps
// it for 30 s, and retries a lost query every 500 ms (at most 4 sends, the
// query dies after 2 s). An ongoing 20 s exchange is never interrupted by a
// mere cache expiry.
constexpr std::uint32_t kGatewayEpochCacheMs = 30000;
constexpr std::uint32_t kEpochQueryIntervalMs = 500;
constexpr std::uint8_t kEpochQueryMaxSends = 4;
constexpr std::uint32_t kEpochQueryLifetimeMs = 2000;

struct JoinProxyConfig {
  NodeId node{kInvalidNodeId};
  MacAddress mac{};
  std::uint32_t network_low32{0};
  std::uint32_t org_hint{0};    // of this site's Site CA
  std::uint32_t site_hint{0};   // join_site_hint(site_id)
  NodeId gateway{kInvalidNodeId};
  // This proxy relay service's incarnation, injected by the Owner from a
  // committed durable allocator value and immutable afterwards (#116 §3.2).
  // Zero (or any other invalid config) makes every mutator fail with
  // InvalidArgument; the engine never sends before it learns its epoch.
  std::uint32_t proxy_epoch{0};
  // The Owner's single-device deployment (G-SEC P4 §8.2): gateway == node
  // addresses the co-located JoinRelayGateway through a direction-demuxed
  // loopback (never the radio). The proxy still only consumes downs and
  // the gateway only ups; each engine's admission drops the other's
  // direction, so no frame ping-pongs. Default false keeps the
  // standalone guard (a proxy forwarding to itself over the mesh is a
  // misconfiguration).
  bool colocated_gateway{false};
  std::uint32_t cookie_bucket_ms{2000};
  std::uint32_t offer_slots{32};       // random OFFER slot (02-discovery §5)
  std::uint32_t offer_slot_ms{10};
  std::uint32_t m1_interval_ms{2000};  // 02 §13: one new m1 per 2 s
  std::uint32_t relay_timeout_ms{20000};
  std::uint32_t device_silence_ms{5000};
  std::uint32_t assembly_timeout_ms{3000};
  std::uint32_t retransmit_ms{500};
  std::uint8_t max_sends{4};
  std::uint32_t busy_retry_after_ms{2000};
};

struct JoinProxyStats {
  std::uint32_t discovers_rx{0};
  std::uint32_t offers_tx{0};
  std::uint32_t offers_suppressed{0};
  std::uint32_t cookie_rejects{0};
  std::uint32_t frames_rejected{0};
  std::uint32_t relays_started{0};
  std::uint32_t relays_completed{0};
  std::uint32_t relays_aborted{0};
  std::uint32_t busy_replies{0};
  std::uint32_t rate_limited{0};
  std::uint32_t unreachable_replies{0};
  std::uint32_t up_objects{0};
  std::uint32_t down_objects{0};
  std::uint32_t retransmissions{0};
  std::uint32_t send_failures{0};
  std::uint32_t epoch_queries_tx{0};
  std::uint32_t epoch_replies_rx{0};
};

class JoinProxy {
 public:
  enum class State : std::uint8_t { Idle = 0, Relaying };

  JoinProxy(const JoinProxyConfig& config, ZtRld1Port& rld1, ZtRelayPort& relay,
            JoinCookieSealer& cookie, EntropySource& entropy) noexcept;

  // Owner-fed policy: the site's zero_touch_open flag, whether the gateway
  // path is currently usable (and its hop count), and the local membership.
  // Leaving Member (revoked, GK unknown) aborts any relay and stops OFFERs.
  // All mutators refuse re-entry from a port callback with Busy and change
  // nothing; a regressed clock fails new work with TimeUncertain.
  Status set_policy(bool zero_touch_open) noexcept;
  Status set_authority(bool reachable, std::uint8_t hops, MonotonicMs now_ms) noexcept;
  Status set_membership(MembershipState state, MonotonicMs now_ms) noexcept;

  Status on_rld1_rx(const MacAddress& source, const MacAddress& destination,
                    std::int8_t rssi_dbm, ByteView frame, MonotonicMs now_ms) noexcept;
  // `from` is the routed frame's origin claim as received over a
  // link-authenticated previous hop — hop authentication, NOT origin
  // authentication. Only the terminal EDHOC/resume verification proves the
  // origin (P4 §7.4); a relaying member can forge it.
  Status on_relay_rx(NodeId from, FrameType type, ByteView payload,
                     MonotonicMs now_ms) noexcept;
  Status poll(MonotonicMs now_ms) noexcept;

  State state() const noexcept { return relay_.active ? State::Relaying : State::Idle; }
  std::uint32_t relay_id() const noexcept { return relay_.active ? relay_.relay_id : 0; }
  const JoinProxyStats& stats() const noexcept { return stats_; }
  const JoinObjectSlot& slot() const noexcept { return slot_; }

 private:
  static constexpr std::size_t kPendingOffers = 4;

  struct PendingOffer {
    MacAddress mac{};
    JoinNonce nonce{};
    MonotonicMs due_ms{0};
  };

  struct Relay {
    bool active{false};
    std::uint32_t relay_id{0};
    std::uint32_t gateway_epoch{0};  // the gateway incarnation this relay uses
    MacAddress joiner_mac{};
    JoinNonce nonce{};
    NodeId joiner{kInvalidNodeId};
    std::int8_t rssi{0};
    JoinAuthPhase phase{JoinAuthPhase::EdhocMessage};
    std::uint8_t last_step{0};
    std::uint8_t accepted_up_mask{0};
    std::array<std::uint16_t, 2> accepted_up_totals{};
    std::uint8_t accepted_down_step{0};
    std::uint16_t accepted_down_total{0};
    MonotonicMs started_ms{0};
    MonotonicMs device_deadline_ms{0};  // 0 = not waiting for the device
    bool final_pending{false};          // Final object handed to the device
    bool slot_up{false};                // slot Sending holds an up object
  };

  // One outstanding gateway-epoch query (#116 §3.3).
  struct EpochQueryState {
    bool active{false};
    JoinNonce nonce{};
    std::uint8_t sends{0};
    MonotonicMs next_ms{0};
    MonotonicMs deadline_ms{0};
  };

  void handle_discover(const MacAddress& source, const MacAddress& destination,
                       ByteView frame, MonotonicMs now_ms) noexcept;
  void handle_auth(const MacAddress& source, const autonomy::Rld1Envelope& env,
                   std::int8_t rssi, MonotonicMs now_ms) noexcept;
  void handle_chunk(const MacAddress& source, const autonomy::Rld1Envelope& env,
                    std::int8_t rssi, MonotonicMs now_ms) noexcept;
  void handle_reply(const MacAddress& source, const autonomy::Rld1Envelope& env,
                    MonotonicMs now_ms) noexcept;
  // Step-1 admission: cookie + epoch + budget + slot; answers RelayStatus
  // on refusal.
  bool admit_first(const MacAddress& source, const autonomy::Rld1Envelope& env,
                   const JoinCookieBytes& cookie, std::int8_t rssi, MonotonicMs now_ms) noexcept;
  bool cookie_valid(const MacAddress& mac, const JoinNonce& nonce, const JoinCookieBytes& cookie,
                    MonotonicMs now_ms) noexcept;
  bool relay_peer(const MacAddress& source, const autonomy::Rld1Envelope& env) const noexcept;
  // Up: message already at slot offset `offset`; wraps it in a RelayHeader
  // in place and sends it single-frame or chunked.
  void forward_up(JoinAuthPhase phase, std::uint8_t step, std::size_t offset, std::size_t size,
                  MonotonicMs now_ms) noexcept;
  void deliver_down(const RelayObject& object, MonotonicMs now_ms) noexcept;
  void send_offer(const PendingOffer& offer, MonotonicMs now_ms) noexcept;
  void send_relay_status(const MacAddress& mac, const JoinNonce& nonce, RelayStatusCode status,
                         std::uint32_t retry_after_ms) noexcept;
  void send_rld1_reply(const JoinReply& reply) noexcept;
  void send_wire_receipt(const JoinReply& reply) noexcept;
  void send_due_chunks(MonotonicMs now_ms) noexcept;
  void abort_relay(RelayStatusCode device_status, bool notify_gateway) noexcept;
  void end_relay() noexcept;
  Status emit_rld1(const MacAddress& mac, const JoinNonce& nonce, FrameType kind,
                   ByteView body) noexcept;
  // Gateway-epoch cache (#116 §3.3): a DISCOVER creates the need when the
  // cache is missing; admit_first consumes it; poll drives retransmission.
  bool epoch_cache_valid(MonotonicMs now_ms) const noexcept;
  void need_gateway_epoch(MonotonicMs now_ms) noexcept;
  void send_epoch_query(MonotonicMs now_ms) noexcept;
  void handle_epoch_reply(const EpochReply& reply, MonotonicMs now_ms) noexcept;
  bool down_expected(const RelayHeader& header) const noexcept;
  void on_relay_rx_impl(NodeId from, FrameType type, ByteView payload,
                        MonotonicMs now_ms) noexcept;

  JoinProxyConfig config_{};
  ZtRld1Port& rld1_;
  ZtRelayPort& relay_port_;
  JoinCookieSealer& cookie_;
  EntropySource& entropy_;
  bool open_{false};
  bool reachable_{false};
  std::uint8_t hops_{kZtHopsUnknown};
  MembershipState membership_{MembershipState::Unprovisioned};
  // Guards: re-entry from a port callback is Busy; a bad config fails every
  // mutator; time never runs backwards for new work.
  bool in_call_{false};
  bool config_valid_{false};
  MonotonicMs last_now_ms_{0};
  FixedPool<PendingOffer, kPendingOffers> offers_{};
  Relay relay_{};
  JoinObjectSlot slot_{};
  MonotonicMs next_m1_ms_{0};
  std::uint32_t next_relay_id_{1};  // strictly increasing within proxy_epoch
  bool relay_ids_exhausted_{false};
  // The gateway incarnation cache: the epoch, whether the gateway reported
  // its authority ready, when it was cached, and the largest epoch seen
  // (a smaller reply is stale and refused).
  std::uint32_t gateway_epoch_{0};
  bool gateway_ready_{false};
  MonotonicMs gateway_cached_ms_{0};
  std::uint32_t gateway_max_epoch_{0};
  EpochQueryState query_{};
  JoinProxyStats stats_{};
};

// ===================================================================================
// JoinRelayGateway — Wire relay <-> host (USB HostOps 0x60-0x63)
// ===================================================================================
// Why a relay ended (USB 0x62 reason). Superseded is new in #116: a larger
// key from the same proxy closed this exchange.
enum class RelayAbortReason : std::uint8_t {
  ProxyAborted = 1,    // the proxy ended the relay (device silent, 20 s cap, stopped)
  GatewayExpired = 2,  // the exchange ran past its 20 s bound at the gateway
  DeliveryFailed = 3,  // the proxy never confirmed a down object
  HostAborted = 4,     // H->G: the Site Authority cancels the relay
  Superseded = 5,      // a newer key from the same proxy replaced this relay
};
constexpr bool relay_abort_reason_known(const std::uint8_t value) noexcept {
  return value >= 1 && value <= 5;
}

class JoinRelayHostSink {
 public:
  virtual ~JoinRelayHostSink() = default;
  // A complete up relay object (v2 RelayHeader dir=up + message) from
  // `proxy`, `hops` mesh hops away, handed over at most once per up stage.
  // `object` is valid only during the call and may alias a gateway slot, so
  // copy it before keeping it. The callback must not re-enter the gateway:
  // every mutating call returns Busy while it runs — call them after it
  // returns. Returning an error terminates the relay; the proxy is told
  // authority_unreachable.
  virtual Status relay_up(NodeId proxy, std::uint8_t hops, ByteView object) noexcept = 0;
  // The relay ended at the gateway: the first termination of `token` only,
  // never a late duplicate. The callback must not re-enter the gateway —
  // the same rules as relay_up apply.
  virtual Status relay_abort(NodeId proxy, RelayToken token,
                             RelayAbortReason reason) noexcept = 0;
};

// One exchange lives at most 20 s from its first admission; a duplicate
// never extends it (#116 §4.4).
constexpr std::uint32_t kRelayExchangeTimeoutMs = 20000;
// The gateway answers epoch queries statelessly through a token bucket:
// bursts of 4, 10 answers per second at most (#116 §3.3).
constexpr std::uint32_t kEpochAnswerBurst = 4;
constexpr std::uint32_t kEpochAnswersPerSecond = 10;

struct JoinRelayGatewayConfig {
  NodeId node{kInvalidNodeId};
  // This gateway relay service's incarnation, injected by the Owner from a
  // committed durable allocator value and immutable afterwards (#116 §3.2).
  // Zero (or any other invalid config) makes every mutator fail with
  // InvalidArgument; the engine never relays before it learns its epoch.
  std::uint32_t gateway_epoch{0};
  // Retry hint the gateway gives a proxy when no host (Site Authority) is
  // attached or the host refused the object (07 §7: authority_unreachable).
  std::uint32_t unreachable_retry_ms{5000};
  std::uint32_t assembly_timeout_ms{3000};
  std::uint32_t retransmit_ms{500};
  std::uint8_t max_sends{4};
};

struct JoinRelayGatewayStats {
  std::uint32_t up_objects{0};
  std::uint32_t down_objects{0};
  std::uint32_t proxy_aborts{0};
  std::uint32_t host_aborts{0};
  std::uint32_t frames_rejected{0};
  std::uint32_t slot_busy{0};
  std::uint32_t expired{0};
  std::uint32_t delivery_failed{0};
  std::uint32_t retransmissions{0};
  std::uint32_t host_unavailable{0};
  std::uint32_t epoch_queries_rx{0};
  std::uint32_t epoch_replies_tx{0};
};

class JoinRelayGateway {
 public:
  // Concurrent chunked objects (either direction). The Site Authority runs
  // at most 4 joins (02 §13); single-frame objects need no slot.
  static constexpr std::size_t kSlots = 2;
  // The RelayBook (#116 §4.1): one floor row per proxy seen in this gateway
  // service epoch (never evicted, never expired), one live exchange each.
  static constexpr std::size_t kProxyFloors = 128;
  static constexpr std::size_t kActiveRelays = 8;
  static constexpr std::uint8_t kNoActive = 0xFF;
  static constexpr std::uint8_t kNoSlot = 0xFF;

  JoinRelayGateway(const JoinRelayGatewayConfig& config, ZtRelayPort& wire) noexcept;

  // (De)attaches the host sink. Detaching terminates every live exchange
  // (the proxies hear authority_unreachable, best effort) but keeps the
  // floors and the epoch. Busy inside a sink callback.
  Status set_host_sink(JoinRelayHostSink* sink) noexcept;
  Status set_membership(MembershipState state) noexcept;

  // Wire RX: `from` is the origin claim of a link-authenticated routed
  // frame (see JoinProxy::on_relay_rx — not a proven origin), `hops` its
  // distance.
  Status on_relay_rx(NodeId from, std::uint8_t hops, FrameType type, ByteView payload,
                     MonotonicMs now_ms) noexcept;
  // USB 0x61: deliver a down relay object to `to_proxy`. Ok = accepted for
  // Wire delivery (not delivered to the device). NotFound/Expired = unknown
  // or terminated token, Conflict/ProtocolError = wrong order or identity,
  // NoCapacity = no slot, InvalidState = not a member. A down Abort object
  // is refused here — cancel with host_abort instead.
  Status host_down(NodeId to_proxy, ByteView object, MonotonicMs now_ms) noexcept;
  // USB 0x62 (H->G): cancel the live relay `token`. NotFound when the
  // gateway does not know it.
  Status host_abort(NodeId proxy, RelayToken token, MonotonicMs now_ms) noexcept;
  Status poll(MonotonicMs now_ms) noexcept;

  const JoinRelayGatewayStats& stats() const noexcept { return stats_; }
  bool configured() const noexcept { return config_valid_; }
  std::size_t slots_in_use() const noexcept;

 private:
  // One proxy's monotonic frontier within this gateway epoch: the largest
  // key seen, and the live exchange for it if any (kNoActive = terminated:
  // smaller keys stay old forever, the same key never reopens).
  struct ProxyFloor {
    NodeId proxy{kInvalidNodeId};
    std::uint32_t max_proxy_epoch{0};
    std::uint32_t max_relay_id{0};
    std::uint8_t active{kNoActive};
    bool valid{false};
  };
  // One live exchange. The only stage floor: it never moves with a slot,
  // so losing a buffer can never resurrect an old stage (#116 R-I2/R-I3).
  struct ActiveRelay {
    bool active{false};
    std::uint8_t floor{0};
    RelayToken token{};
    MacAddress joiner_mac{};
    JoinAuthPhase phase{JoinAuthPhase::EdhocMessage};
    std::uint8_t hops{0};
    MonotonicMs started_ms{0};
    MonotonicMs deadline_ms{0};
    // Accepted up stages: bit i covers step (1, 3, 5)[i]; totals[i] is the
    // accepted encoded-or-chunk total, used to re-acknowledge a duplicate.
    std::uint8_t accepted_up_mask{0};
    std::array<std::uint16_t, 3> accepted_totals{};
    bool host_up_delivered{false};  // the host owns a session for this key
    // The down object in flight or just done (a step number, 0 = none yet).
    std::uint8_t down_step{0};
    bool down_sending{false};
    bool down_done{false};
    bool down_final{false};
    bool m2_done{false};  // a step-2 down completed (a duplicate is Expired)
    std::uint8_t slot{kNoSlot};
  };
  struct Slot {
    bool active{false};
    bool down{false};  // Sending a down object (else assembling an up one)
    std::uint8_t relay{kNoActive};
    JoinObjectSlot object{};
  };

  // Compares `token` against the floor row of `proxy`: older (drop), same
  // (classify against the live exchange), or newer (may open).
  enum class KeyOrder : std::uint8_t { Older = 0, Same, Newer, UnknownProxy };
  KeyOrder order_key(NodeId proxy, const RelayToken& token, ProxyFloor*& floor) noexcept;
  ActiveRelay* live_exchange(ProxyFloor& floor) noexcept;
  // Opens a new exchange for a larger key (or a first key of a new proxy):
  // validates the inner header, batch-allocates floor/active/slot and
  // supersedes the proxy's previous exchange. Fails without changing any
  // other exchange when resources are missing.
  Status open_exchange(NodeId proxy, std::uint8_t hops, const RelayHeader& header,
                       MonotonicMs now_ms, ActiveRelay*& relay) noexcept;
  Slot* slot_for(ActiveRelay& relay) noexcept;
  Slot* allocate_slot(ActiveRelay& relay, std::uint8_t relay_index, bool down) noexcept;
  void free_slot(Slot& slot) noexcept;
  // Commits the termination before any callback: floors stay terminated,
  // buffers are wiped, the live row is unlinked, then at most one
  // notification goes out. A second finish of the same key is a no-op.
  void finish_exchange(ActiveRelay& relay, RelayAbortReason reason, bool notify_sink) noexcept;
  void finish_index(std::uint8_t relay_index, RelayAbortReason reason, bool notify_sink) noexcept;
  // Unlinks and wipes without counting or notifying: sink detach, membership
  // leave, host-refused ups (already counted) and silent completions.
  void finish_silent(ActiveRelay& relay) noexcept;
  void deliver_up(ActiveRelay& relay, std::uint8_t relay_index, std::uint8_t hops,
                  const RelayObject& object, ByteView bytes) noexcept;
  // A valid new up stage implicitly received the down object in flight.
  void implicit_down_receipt(ActiveRelay& relay) noexcept;
  Status send_due_chunks(Slot& slot, NodeId proxy, MonotonicMs now_ms) noexcept;
  void send_down_abort(NodeId proxy, const RelayHeader& up, RelayStatusCode status,
                       std::uint32_t retry_after_ms) noexcept;
  void send_up_complete(NodeId proxy, const RelayToken& token, JoinAuthPhase phase,
                        std::uint8_t step, std::uint16_t total) noexcept;
  void answer_epoch_query(NodeId proxy, const EpochQuery& query, MonotonicMs now_ms) noexcept;
  void expire_due(MonotonicMs now_ms) noexcept;
  void on_relay_rx_impl(NodeId from, std::uint8_t hops, FrameType type, ByteView payload,
                        MonotonicMs now_ms) noexcept;
  void handle_up_single(NodeId from, std::uint8_t hops, const RelayObject& object, ByteView bytes,
                        MonotonicMs now_ms) noexcept;
  void handle_up_same(ActiveRelay& relay, std::uint8_t hops, const RelayHeader& header,
                      ByteView bytes, std::uint16_t total) noexcept;
  void handle_up_chunk(NodeId from, std::uint8_t hops, const JoinChunk& chunk,
                       MonotonicMs now_ms) noexcept;
  void handle_chunk_same(NodeId from, ActiveRelay& relay, const JoinChunk& chunk,
                         MonotonicMs now_ms) noexcept;
  void feed_assembly(NodeId from, ActiveRelay& relay, Slot& slot, const JoinChunk& chunk,
                     MonotonicMs now_ms) noexcept;
  void handle_proxy_aborted(NodeId from, const RelayToken& token,
                            const RelayHeader& header) noexcept;
  void handle_down_reply(NodeId from, const JoinReply& reply, MonotonicMs now_ms) noexcept;
  // The first chunk of a new stage carries the whole 32 B object head in
  // the clear: it is checked before any buffer is granted or freed.
  bool first_chunk_header(ByteView chunk_data, RelayHeader& header) const noexcept;

  JoinRelayGatewayConfig config_{};
  ZtRelayPort& wire_;
  JoinRelayHostSink* sink_{nullptr};
  MembershipState membership_{MembershipState::Unprovisioned};
  // Guards: re-entry from a sink/port callback is Busy; a bad config fails
  // every mutator; time never runs backwards for new work.
  bool in_call_{false};
  bool config_valid_{false};
  MonotonicMs last_now_ms_{0};
  std::array<Slot, kSlots> slots_{};
  std::array<ProxyFloor, kProxyFloors> floors_{};
  std::array<ActiveRelay, kActiveRelays> relays_{};
  // Epoch-answer bucket in tenths of a token (burst 40 = 4 tokens).
  std::uint32_t answer_budget_{kEpochAnswerBurst * 10};
  MonotonicMs answer_refill_ms_{0};
  JoinRelayGatewayStats stats_{};
};

}  // namespace routeloom::sdkv1
