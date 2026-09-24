#pragma once

// Portable neighbor-discovery core for the autonomous-mesh profile
// (docs/design/autonomous-mesh/02-discovery.md §2-§8,
//  docs/design/autonomous-mesh/06-membership-admission.md §2-§4).
//
// Implements the per-peer NeighborPhase lifecycle, the RLD1 exchange
// (DISCOVER/OFFER + cookie, BootstrapAuth PROVE/CONFIRM/FINISH, bounded
// BootstrapChunk/BootstrapReply reassembly), storm control, peer-slot
// accounting and lease management. It never touches a radio driver: all TX
// goes through DiscoveryPort, all cryptography through
// NeighborAuthenticator/SecurityProvider, and all time through an injected
// monotonic now_ms — there is no std::chrono here.
//
// Two state axes stay strictly separate (06 §2): MembershipState
// (node x network, owned by MembershipController) and NeighborPhase
// (peer radio x exchange, owned by NeighborDiscovery). A peer's
// Conflict/Revoked phase never mutates local membership, and local Revoked
// silences the engine without touching per-peer records.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "routeloom/admission.hpp"
#include "routeloom/autonomy.hpp"
#include "routeloom/autonomy_wire.hpp"
#include "routeloom/discovery_scope.hpp"
#include "routeloom/endpoint_wire.hpp"
#include "routeloom/fixed_containers.hpp"
#include "routeloom/peer_directory.hpp"
#include "routeloom/security.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom {

// --- Bounds (contracts.json discovery.* / resources) ---------------------------

namespace discovery_const {
constexpr std::size_t kCandidateCapacity = 16;      // candidate_records_max
constexpr std::size_t kNeighborCapacity = 32;       // logical_neighbors_max
constexpr std::size_t kRegularPeerSlots = 16;       // peer_partition.regular
constexpr std::size_t kTransientPeerSlots = 3;      // peer_partition.transient
constexpr std::size_t kRegularPinsMax = 12;         // regular_pins_max
constexpr std::size_t kReassemblySlots = 4;         // bootstrap_rx_slots
constexpr std::size_t kBootstrapObjectMax = autonomy::kBootstrapObjectMax;  // 1024
// OFFER response-time spread: radio-defaults.json discovery.offer_slots x
// offer_slot_ms = 160ms must stay under the 200ms channel dwell
// (radio.md §7/§13 name the same 16 slots; check_docs.py offer_window).
constexpr std::uint32_t kOfferSlots = 16;           // offer_slots
constexpr std::uint32_t kOfferSlotMs = 10;          // offer_slot_ms
constexpr MacAddress kBroadcastMac{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};
}  // namespace discovery_const

// --- Entropy -------------------------------------------------------------------

// Entropy for transaction nonces and offer-slot picks. The production
// implementation is a real RNG; tests inject a deterministic source. Every
// attempt nonce is refreshed — retries are independent (02 §6).
class EntropySource {
 public:
  virtual ~EntropySource() = default;
  virtual Status fill(MutableByteView out) noexcept = 0;
};

// --- Authenticator boundary (02 §5, 06 §2.2) -----------------------------------

using AuthTag = std::array<std::uint8_t, 16>;

// Everything a device-auth proof binds. Both MACs are the OBSERVED radio
// addresses (RX metadata), never the claimed ones; the full-width NetworkId
// is bound here even though RLD1 only carries the 4-byte hint.
struct AuthTranscript {
  NodeId requester_node{kInvalidNodeId};
  NodeId responder_node{kInvalidNodeId};
  MacAddress requester_mac{};
  MacAddress responder_mac{};
  NetworkId network{0};
  std::array<std::uint8_t, 16> requester_nonce{};
  std::array<std::uint8_t, 16> responder_nonce{};
  std::uint32_t requester_capability{0};
  std::uint32_t responder_capability{0};
  // SHA256(domain_binding || class|generation|scheme|scoped ||
  // discover_digest||offer_digest) — ties the proof to the exact exchanged
  // frames (02-discovery-scope §2.4). Legacy exchanges bind the same field
  // with class/generation/scheme/scoped zeroed and real legacy digests.
  ScopeDigest scope_binding{};
};

// OFFER cookie material (02 §5): bound to the requester's MAC + transaction
// nonce + Network + a coarse monotonic time bucket. A cookie authorizes the
// expensive proof check for the matching peer only — it is NOT identity
// evidence.
struct CookieMaterial {
  MacAddress requester_mac{};
  std::array<std::uint8_t, 16> requester_nonce{};
  NetworkId network{0};
  std::uint64_t time_bucket{0};
  NodeId responder_node{kInvalidNodeId};
  NodeId requester_node{kInvalidNodeId};
};

// Opaque evidence that the peer proved the configured credential over a
// specific transcript. NOT membership: the membership controller and the
// Owner still re-verify before a VerifiedBinding exists. Only an
// authenticator may construct one — applications cannot mint proofs from a
// bare bool.
class AuthenticatedPeerProof {
 public:
  NodeId peer() const noexcept { return peer_; }
  const MacAddress& mac() const noexcept { return mac_; }
  NetworkId network() const noexcept { return network_; }
  const AuthTag& evidence() const noexcept { return evidence_; }
  // A default-constructed proof carries no evidence and is never valid.
  bool valid() const noexcept { return peer_ != kInvalidNodeId; }

 private:
  friend class NeighborAuthenticator;
  friend class NeighborDiscovery;  // out-parameter holder only, cannot mint
  AuthenticatedPeerProof() noexcept = default;
  AuthenticatedPeerProof(NodeId peer, const MacAddress& mac, NetworkId network,
                         const AuthTag& evidence) noexcept
      : peer_(peer), mac_(mac), network_(network), evidence_(evidence) {}

  NodeId peer_{kInvalidNodeId};
  MacAddress mac_{};
  NetworkId network_{0};
  AuthTag evidence_{};
};

// NeighborAuthenticator contract (02 §5): the engine supplies cookie
// material and transcripts; the provider returns tags and, once both
// directions verify, issues the opaque proof. The provider owns all key
// handling — the engine never sees key material.
class NeighborAuthenticator {
 public:
  virtual ~NeighborAuthenticator() = default;

  // EXPERIMENTAL for every implementation in the portable core today; the
  // qualified production profile (G-SEC) reports Production.
  virtual SecurityProfile security_profile() const noexcept = 0;

  // Whether attest/verify fold AuthTranscript::scope_binding into the tag.
  // Required-scope discovery is only usable with a provider that returns
  // true — an older provider would silently drop the binding (02 §2.4/§5.2).
  virtual bool binds_scope() const noexcept { return false; }

  // OFFER cookie (02 §5): seal/verify the cookie material for this node as
  // responder. Verify MUST accept the current and previous time bucket only.
  virtual Status cookie_seal(const CookieMaterial& material, AuthTag& out) noexcept = 0;
  virtual Status cookie_verify(const CookieMaterial& material,
                               const AuthTag& cookie) noexcept = 0;

  // Per-phase transcript tag: PROVE/CONFIRM are attested by requester and
  // responder respectively, FINISH closes the exchange.
  virtual Status attest(autonomy::AuthPhase phase, const AuthTranscript& transcript,
                        AuthTag& out) noexcept = 0;
  virtual Status verify(autonomy::AuthPhase phase, const AuthTranscript& transcript,
                        const AuthTag& tag) noexcept = 0;

  // Issue the opaque proof after both directions verified. `self` names the
  // local end of the transcript; the proof records the remote peer. The
  // authenticator is the only issuer; the engine just carries the result.
  virtual Status issue_proof(const AuthTranscript& transcript, NodeId self,
                             const AuthTag& closing_tag,
                             AuthenticatedPeerProof& out) noexcept = 0;

 protected:
  static AuthenticatedPeerProof make_proof(NodeId peer, const MacAddress& mac,
                                           NetworkId network,
                                           const AuthTag& evidence) noexcept {
    return AuthenticatedPeerProof(peer, mac, network, evidence);
  }
};

// Development profile (02 §5): mutual shared-PSK possession proof over the
// exchange transcript, using the SecurityProvider's AEAD tag as a keyed MAC
// over a domain-separated AAD string — no new crypto primitive. Labeled
// EXPERIMENTAL / GROUP_SECRET_POSSESSION: it proves knowledge of the shared
// key, so it CANNOT distinguish two holders of that key (NodeId spoofing or
// key cloning among group members is out of scope).
//
// `domain_tag` selects the possession domain and is folded into the security
// context epoch; different domains cannot verify each other's tags. It is a
// test/deployment separator, not extra key material.
class DevPskAuthenticator final : public NeighborAuthenticator {
 public:
  explicit DevPskAuthenticator(SecurityProvider& provider,
                               std::uint16_t domain_tag = 1) noexcept
      : provider_(provider), domain_tag_(domain_tag) {}

  SecurityProfile security_profile() const noexcept override {
    return SecurityProfile::Development;
  }
  bool binds_scope() const noexcept override { return true; }
  Status cookie_seal(const CookieMaterial& material, AuthTag& out) noexcept override;
  Status cookie_verify(const CookieMaterial& material,
                       const AuthTag& cookie) noexcept override;
  Status attest(autonomy::AuthPhase phase, const AuthTranscript& transcript,
                AuthTag& out) noexcept override;
  Status verify(autonomy::AuthPhase phase, const AuthTranscript& transcript,
                const AuthTag& tag) noexcept override;
  Status issue_proof(const AuthTranscript& transcript, NodeId self,
                     const AuthTag& closing_tag,
                     AuthenticatedPeerProof& out) noexcept override;

 private:
  Status tag_for(const SecurityContext& context, ByteView aad, AuthTag& out) noexcept;
  static bool tag_equal(const AuthTag& a, const AuthTag& b) noexcept;

  SecurityProvider& provider_;
  std::uint16_t domain_tag_{1};
};

// Production profile placeholder (02 §5): until the qualified G-SEC provider
// lands, production authentication is AUTH_PROFILE_UNAVAILABLE — never a stub
// that claims security.
class UnavailableAuthenticator final : public NeighborAuthenticator {
 public:
  SecurityProfile security_profile() const noexcept override {
    return SecurityProfile::Production;
  }
  Status cookie_seal(const CookieMaterial&, AuthTag&) noexcept override {
    return unavailable();
  }
  Status cookie_verify(const CookieMaterial&, const AuthTag&) noexcept override {
    return unavailable();
  }
  Status attest(autonomy::AuthPhase, const AuthTranscript&, AuthTag&) noexcept override {
    return unavailable();
  }
  Status verify(autonomy::AuthPhase, const AuthTranscript&,
                const AuthTag&) noexcept override {
    return unavailable();
  }
  Status issue_proof(const AuthTranscript&, NodeId, const AuthTag&,
                     AuthenticatedPeerProof&) noexcept override {
    return unavailable();
  }

 private:
  static Status unavailable() noexcept {
    return Status::error(StatusCode::AuthProfileUnavailable,
                         "production auth profile unavailable");
  }
};

// --- Membership controller glue (06 §2, §5) -------------------------------------

// Deployment policy consulted by the membership controller. For the dev
// profile this is an explicit allowlist/approval hook; a production
// implementation backs these with the real admission provider. The
// production backing must also persist LOCAL revocation (authority
// ledger): the controller's Revoked state is RAM-only, so a reboot
// re-derives membership from `local_member` — a revocation the hooks
// cannot prove fails open back to Member/Discovering.
class MembershipHooks {
 public:
  virtual ~MembershipHooks() = default;
  // Persistent evidence that THIS node is a member of `network` already.
  virtual bool local_member(NetworkId network) const noexcept = 0;
  // Verified evidence that `peer` is a member of `network` WITHOUT a new
  // authority round trip (D3-03 established-member re-binding; dev:
  // allowlist of member NodeIds).
  virtual bool known_member(NodeId peer, NetworkId network) const noexcept = 0;
  // Admission decision for a NEW local join (dev: explicit approval hook
  // modeling the Authority's MembershipResult). Returning false leaves the
  // controller AuthorizedPendingCommit — never silently approved.
  virtual bool approve_join(NodeId node, NetworkId network) noexcept = 0;
};

// Sole writer of MembershipState (node x network). Values and semantics are
// frozen; a peer's NeighborPhase never writes here. A Member stays Member
// while discovering new peers (06 §2.1 row 4-5): discovery never demotes an
// established node back to Discovering.
class MembershipController {
 public:
  MembershipState state() const noexcept { return state_; }

  // Initial assignment from provisioned evidence: Member or Unprovisioned.
  Status initialize(const MembershipHooks& hooks, NetworkId network) noexcept;
  // Unprovisioned -> Discovering; Member stays Member (local re-binding does
  // not re-join). Revoked refuses.
  Status begin_discovery() noexcept;
  // Discovering/Unprovisioned -> Authenticating once a bounded mutual
  // exchange actually starts; Member stays Member.
  Status begin_authentication() noexcept;
  // Device auth completed. Member stays Member; Authenticating advances to
  // AuthorizedPendingCommit and consults the admission hook — approved
  // commits to Member. Returns the resulting state.
  MembershipState complete_authentication(MembershipHooks& hooks, NodeId self,
                                          NetworkId network) noexcept;
  // Exchange died before completion: drop back to Discovering (never to
  // Unprovisioned — provisioning was confirmed) unless already further along.
  Status abort_authentication() noexcept;
  // A pending commit can be retried (e.g. an approval hook that becomes
  // available later). No-op outside AuthorizedPendingCommit.
  MembershipState retry_commit(MembershipHooks& hooks, NodeId self,
                               NetworkId network) noexcept;
  // Authoritative revocation of THIS node's membership: every binding
  // becomes unusable; the radio path may not self-rejoin (06 §5). The
  // revoked state is RAM-only — persistence is a production-hooks
  // (authority ledger) requirement, so a reboot before durable backing
  // exists fails open.
  void revoke() noexcept { state_ = MembershipState::Revoked; }

 private:
  MembershipState state_{MembershipState::Unprovisioned};
};

// --- Discovery engine ------------------------------------------------------------

struct DiscoveryConfig {
  NodeId node{kInvalidNodeId};
  MacAddress mac{};
  NetworkId network{0};
  std::uint32_t network_hint{0};     // 4-byte discovery filter, never proof
  std::uint32_t capability_bits{0};
  // Discovery Scope Key filter (02-discovery-scope). Off/OpenLegacy keep the
  // exact legacy pipeline; OptionalMigration/Required engage scoped lanes.
  ScopeMode scope_mode{ScopeMode::Off};
  DiscoveryScopeProvider* scope_provider{nullptr};
  ScopeRef scope{kInvalidScopeRef};
  endpoint::ScopeClass scope_class{endpoint::ScopeClass::Member};
  // OptionalMigration only: owner-proven absolute deadline for the legacy
  // fallback lane (0 = never; capped at +24h from start). A restart that
  // cannot prove elapsed migration time must leave this 0 -> Required-like.
  MonotonicMs migration_until_ms{0};
  std::uint32_t candidate_ttl_ms{5000};       // contracts candidate_ttl_ms
  std::uint32_t awake_lease_ms{30000};        // awake_neighbor_lease_ms
  std::uint32_t idle_refresh_ms{10000};       // idle_refresh_ms
  std::uint32_t cookie_bucket_ms{2000};       // cookie time bucket
  std::uint32_t auth_timeout_ms{5000};        // bound on one exchange
  std::uint32_t offer_window_ms{discovery_const::kOfferSlots *
                                discovery_const::kOfferSlotMs};  // 16 x 10ms = 160ms
  std::uint32_t handshake_start_interval_ms{1000};  // 1/s, burst 1
  // Requester re-discovery cadence (radio.md §7/§13,
  // radio-defaults.json discovery.retry_*): a powered node's re-search
  // starts from a uniform draw in [backoff_min_ms, backoff_initial_max_ms]
  // and doubles toward backoff_max_ms. begin_discovery additionally
  // defers the first DISCOVER of a fresh exchange by a uniform
  // [0, cold_start_jitter_max_ms) so simultaneous boots decorrelate.
  std::uint32_t cold_start_jitter_max_ms{1000};
  std::uint32_t backoff_min_ms{500};
  std::uint32_t backoff_initial_max_ms{2000};
  std::uint32_t backoff_max_ms{60000};
  std::uint32_t probe_timeout_ms{2000};       // unanswered probe retry bound
  std::uint8_t max_attempts{5};
  // Stale re-confirmation (02 §9): a lapsed-lease record keeps resolving,
  // so a slow unicast re-probe can re-open the lane without a full exchange.
  // The cadence stays well below idle_refresh and the attempt budget parks
  // the record dormant until fresh RX evidence — a permanently partitioned
  // peer can never turn this into a background storm (02 §6).
  std::uint32_t stale_reprobe_ms{150000};     // stale re-probe cadence
  std::uint8_t stale_reprobe_attempts{4};     // probes before dormancy
};

// Phases where the verified MAC<->NodeId mapping may still resolve.
// Conflict records are quarantined (the mapping is disputed) and Revoked
// bindings are dead — neither may attribute traffic or sends. Stale keeps
// resolving precisely so re-confirmation probes can find the peer;
// Suspended is a planned absence, not a broken binding.
bool resolvable_phase(NeighborPhase phase) noexcept;

// Radio-facing TX surface the Owner implements (P1b wires this to the real
// driver; tests wire it to a fake medium). send_rld1 carries the bootstrap
// lane; send_wire carries authenticated Wire-lane autonomy payloads
// (NeighborProbe/NeighborResult) toward an existing binding.
class DiscoveryPort {
 public:
  virtual ~DiscoveryPort() = default;
  virtual Status send_rld1(const MacAddress& dest, ByteView encoded) noexcept = 0;
  virtual Status send_wire(BindingId binding, const MacAddress& dest, FrameType type,
                           ByteView payload) noexcept = 0;
};

class DiscoveryObserver {
 public:
  virtual ~DiscoveryObserver() = default;
  // Stable reason strings ("PEER_CAPACITY", "BINDING_CONFLICT", ...) for
  // diagnostics; `peer` may be kInvalidNodeId when no identity is verified.
  virtual void on_discovery_event(const char* reason, NodeId peer) noexcept = 0;
};

class NullDiscoveryObserver final : public DiscoveryObserver {
 public:
  void on_discovery_event(const char*, NodeId) noexcept override {}
};

// Observed RX link metadata (02-discovery-scope §2.4): the MACs the radio
// actually saw, never values claimed inside the frame. Scoped MAC inputs
// and the DISCOVER-broadcast/OFFER-unicast rules bind these, not the body.
struct DiscoveryRxMetadata {
  MacAddress source{};
  MacAddress destination{};
};

// Observable counters so storms and capacity behavior are never silent.
struct DiscoveryStats {
  std::uint32_t discovers_rx{0};
  std::uint32_t offers_tx{0};
  std::uint32_t offers_rx{0};
  std::uint32_t proves_rx{0};
  std::uint32_t auths_completed{0};
  std::uint32_t probes_tx{0};
  std::uint32_t kind_rejects{0};
  std::uint32_t cookie_rejects{0};
  std::uint32_t auth_tag_rejects{0};
  std::uint32_t suppressed_offers{0};
  std::uint32_t rate_limited{0};
  std::uint32_t peer_capacity{0};
  // Handle-space exhaustion (issue #117, Q117-13): the binding/exchange is
  // refused instead of reusing id 0 or a wrapped handle.
  std::uint32_t binding_id_exhausted{0};
  std::uint32_t candidate_id_exhausted{0};
  std::uint32_t binding_generation_exhausted{0};
  std::uint32_t conflicts{0};
  std::uint32_t simultaneous_resolved{0};
  std::uint32_t stale_expirations{0};
  // Sends the radio port refused — transport failure is never silent
  // (offers_tx/probes_tx count accepted sends only).
  std::uint32_t send_failures{0};
};

// The portable per-peer lifecycle + RLD1 exchange engine. One instance per
// (node, network, radio). Not thread-safe: the Owner serializes calls.
class NeighborDiscovery {
 public:
  NeighborDiscovery(const DiscoveryConfig& config, DiscoveryPort& port,
                    NeighborAuthenticator& authenticator, MembershipHooks& hooks,
                    EntropySource& entropy, DiscoveryObserver& observer) noexcept;

  Status start(MonotonicMs now_ms) noexcept;

  // Requester path: broadcast a DISCOVER and run one bounded exchange.
  // Already-member nodes keep their MembershipState (local re-binding, D3-03).
  Status begin_discovery(MonotonicMs now_ms) noexcept;

  // Ingress points fed by the Owner after carrier classification. RLD1 input
  // arrives only here with OBSERVED source/destination MACs; authenticated
  // Wire-lane autonomy payloads via on_wire_rx. An unknown source MAC on the
  // Wire lane is rejected outright.
  void on_rld1_rx(const DiscoveryRxMetadata& rx, ByteView frame, MonotonicMs now_ms) noexcept;
  void on_wire_rx(const MacAddress& source, FrameType type, ByteView payload,
                  MonotonicMs now_ms) noexcept;

  // Time-driven work: due OFFERs, rate-limited PROVEs, retries with backoff,
  // lease expiry (-> Stale, never silent delete), idle refresh probes.
  void poll(MonotonicMs now_ms) noexcept;

  // --- inspection gates used by the Owner/tests -------------------------------
  // Lookup across bound records first, then live candidates.
  bool phase_of(const MacAddress& mac, NeighborPhase& out) const noexcept;
  bool phase_of(NodeId peer, NeighborPhase& out) const noexcept;
  // True only for a REACHABLE peer with verified membership on a Member
  // local node — the only state where policy-limited DATA may flow.
  bool data_permitted(const MacAddress& mac) const noexcept;
  bool data_permitted(NodeId peer) const noexcept;
  bool binding_of(NodeId peer, BindingId& out) const noexcept;
  // Binding generation under which the peer's verified record stands — the
  // epoch that keys telemetry attribution (02-telemetry §2.4). Same
  // resolvability bar as binding_of; false when no live binding exists.
  bool binding_generation_of(NodeId peer, BindingGeneration& out) const noexcept;
  // Owner-side lease sync: resolve the verified NodeId recorded for a radio
  // MAC (bound neighbor records only — candidates are unverified and never
  // resolve). False when the MAC has no neighbor record.
  bool node_of(const MacAddress& mac, NodeId& out) const noexcept;

  // Owner-driven controls.
  Status revoke_peer(NodeId peer) noexcept;                 // -> Revoked (binding unusable)
  // Explicit exit from Revoked/Conflict (issue #43): drops every dead
  // (Revoked or Conflict) record held for `peer` so a fresh authenticated
  // exchange may bind it again — the owner's decision after, e.g., an
  // authority re-approval or a MAC flip-back. Never implicit: a revoked
  // record otherwise blocks re-authentication for its whole lifetime.
  // NotFound when `peer` has no record; InvalidState when its only
  // records are live (revoke first — a live binding is never forgotten).
  Status forget_peer(NodeId peer) noexcept;
  // P6 limited re-auth (04 §5, V1-R04): admits ONE new-credential handshake
  // attempt for a Revoked peer, at most once per minute per peer. Normal
  // traffic stays refused while Revoked; after P4 verifies the new
  // MemberCert + PoP against the latest RRS1 floor, the Owner promotes via
  // forget_peer() and the fresh exchange binds normally — no permanent
  // blacklist. NotFound when `peer` holds no Revoked record; Busy inside
  // the per-peer minute.
  Status reauth_revoked(NodeId peer, MonotonicMs now_ms) noexcept;
  Status suspend_peer(NodeId peer, MonotonicMs until_ms) noexcept;  // planned absence
  Status pin_peer(NodeId peer) noexcept;                    // topology pin, <= 12
  // Local membership was revoked/committed elsewhere — re-evaluate pending
  // records against the freshest context (06 §2.2: late completions must
  // re-check, never resurrect).
  void reevaluate(MonotonicMs now_ms) noexcept;

  const MembershipController& membership() const noexcept { return membership_; }
  MembershipController& membership() noexcept { return membership_; }
  const DiscoveryStats& stats() const noexcept { return stats_; }
  // Aggregate scope-filter counters only — never keys, tags or sources.
  const ScopeStats& scope_stats() const noexcept { return scope_stats_; }
  std::size_t candidate_count() const noexcept { return candidates_.size(); }
  std::size_t neighbor_count() const noexcept { return neighbors_.size(); }

 private:
  enum class OutboundStage : std::uint8_t {
    Idle = 0,
    AwaitingOffers,    // DISCOVER sent, collecting OFFERs in the window
    ProvePending,      // OFFER accepted, waiting for the handshake token
    AwaitingConfirm,   // PROVE sent
  };

  struct Candidate {
    CandidateId id{kInvalidCandidateId};
    MacAddress mac{};
    NodeId claimed_node{kInvalidNodeId};
    std::array<std::uint8_t, 16> txn_nonce{};    // requester nonce (echoed)
    std::array<std::uint8_t, 16> our_nonce{};    // responder contribution
    AuthTag cookie{};
    std::uint32_t peer_capability{0};
    NeighborPhase phase{NeighborPhase::Candidate};
    MonotonicMs expires_at_ms{0};
    MonotonicMs offer_due_ms{0};
    bool offer_pending{false};
    bool transient_held{false};
    // Pins the accepted DISCOVER's scope context (class/generation + frame
    // digest, legacy = scoped:false) so the OFFER tag and the final
    // transcript binding reproduce the exact exchange (02 §2.4/§5.2).
    ScopeExchangeContext exchange{};
  };

  struct Neighbor {
    BindingId binding{kInvalidBindingId};
    BindingGeneration generation{0};
    NodeId node{kInvalidNodeId};
    MacAddress mac{};
    NeighborPhase phase{NeighborPhase::Bound};
    bool peer_member_verified{false};
    bool pinned{false};
    bool regular_held{false};
    MonotonicMs lease_expires_at_ms{0};
    MonotonicMs last_confirmed_ms{0};
    MonotonicMs suspended_until_ms{0};
    std::uint32_t probe_outstanding{0};
    MonotonicMs probe_deadline_ms{0};
    // Stale re-confirmation scheduler (02 §9): first tick fires immediately
    // on the demotion poll, then every stale_reprobe_ms. The attempt count
    // only counts emitted probes; verified RX evidence re-arms it.
    MonotonicMs next_reprobe_ms{0};
    std::uint8_t stale_reprobes{0};
    // P6 (04 §5): last admitted re-auth attempt for this record; a Revoked
    // peer may start a new-credential handshake at most once per minute.
    // UINT64_MAX = never attempted.
    MonotonicMs last_reauth_attempt_ms{0xFFFFFFFFFFFFFFFFULL};
  };

  struct Outbound {
    bool active{false};
    MacAddress peer_mac{};
    NodeId peer_node{kInvalidNodeId};
    std::array<std::uint8_t, 16> our_nonce{};
    std::array<std::uint8_t, 16> peer_nonce{};
    AuthTag cookie_echo{};
    std::uint32_t peer_capability{0};
    OutboundStage stage{OutboundStage::Idle};
    MonotonicMs stage_deadline_ms{0};
    MonotonicMs discover_due_ms{0};
    std::uint8_t attempts{0};
    // Next retry wait: drawn uniformly in [backoff_min_ms,
    // backoff_initial_max_ms] on the first failure, then doubled toward
    // backoff_max_ms (radio.md §7/§13). 0 = not yet drawn.
    std::uint32_t retry_backoff_ms{0};
    bool transient_held{false};
    bool have_offer{false};
    // Scope context of the CURRENT attempt (02 §2.4): legacy attempts carry
    // scoped=false so a migration fallback binds a distinct transcript.
    ScopeExchangeContext exchange{};
    // OptionalMigration: the single permitted legacy fallback attempt is
    // consumed once per outbound exchange — never retried as legacy.
    bool legacy_attempted{false};
  };

  // A v2 Discover/Offer that passed cheap parse+hint and waits for its
  // bounded scope-MAC verification (at most kScopeMacsPerPoll per Owner poll).
  struct PendingVerify {
    bool offer{false};
    DiscoveryRxMetadata rx{};
    autonomy::Rld1Envelope env{};
    autonomy::Rld1Encoded frame{};
    ScopeDigest frame_digest{};      // SHA256 of this exact frame
    ScopeDigest discover_digest{};   // offer lane: digest of our DISCOVER
    ScopeTag expected_tag{};
    std::uint32_t generation{0};
    endpoint::ScopeClass scope_class{endpoint::ScopeClass::Member};
    std::array<std::uint8_t, 16> offer_cookie{};
    std::array<std::uint8_t, 16> offer_nonce{};
  };

  struct RxAssembly {
    bool active{false};
    MacAddress mac{};
    std::uint32_t transaction{0};
    std::uint16_t total{0};
    std::uint16_t received{0};
    MonotonicMs expires_at_ms{0};
    std::array<std::uint8_t, discovery_const::kBootstrapObjectMax> data{};
  };

  // RLD1 handlers.
  void handle_discover(const DiscoveryRxMetadata& rx,
                       const autonomy::Rld1Envelope& env, ByteView frame,
                       MonotonicMs now_ms) noexcept;
  void handle_discover_legacy(const MacAddress& source,
                              const autonomy::Rld1Envelope& env, ByteView frame,
                              MonotonicMs now_ms) noexcept;
  void handle_discover_scoped(const DiscoveryRxMetadata& rx,
                              const autonomy::Rld1Envelope& env, ByteView frame,
                              MonotonicMs now_ms) noexcept;
  void handle_offer(const DiscoveryRxMetadata& rx, const autonomy::Rld1Envelope& env,
                    ByteView frame, MonotonicMs now_ms) noexcept;
  void queue_offer_verify(const DiscoveryRxMetadata& rx,
                          const autonomy::Rld1Envelope& env, ByteView frame,
                          MonotonicMs now_ms) noexcept;
  void handle_auth(const MacAddress& source, const autonomy::Rld1Envelope& env,
                   MonotonicMs now_ms) noexcept;
  void handle_chunk(const MacAddress& source, const autonomy::Rld1Envelope& env,
                    MonotonicMs now_ms) noexcept;
  void handle_prove(const MacAddress& source, const autonomy::Rld1Envelope& env,
                    const autonomy::BootstrapAuthBody& auth, MonotonicMs now_ms) noexcept;
  void handle_confirm(const MacAddress& source, const autonomy::Rld1Envelope& env,
                      const autonomy::BootstrapAuthBody& auth, MonotonicMs now_ms) noexcept;
  void handle_finish(const MacAddress& source, const autonomy::Rld1Envelope& env,
                     const autonomy::BootstrapAuthBody& auth, MonotonicMs now_ms) noexcept;

  // Wire-lane handlers (post-BIND probes only).
  void handle_probe(Neighbor& neighbor, ByteView payload, MonotonicMs now_ms) noexcept;
  void handle_probe_result(Neighbor& neighbor, ByteView payload,
                           MonotonicMs now_ms) noexcept;

  // Exchange machinery.
  Status send_discover(MonotonicMs now_ms) noexcept;
  Status send_scoped_discover(MonotonicMs now_ms) noexcept;
  Status send_offer(Candidate& candidate, MonotonicMs now_ms) noexcept;
  Status send_scoped_offer(Candidate& candidate, MonotonicMs now_ms) noexcept;
  Status send_prove(MonotonicMs now_ms) noexcept;
  Status send_confirm(Candidate& candidate, MonotonicMs now_ms) noexcept;
  Status send_finish(MonotonicMs now_ms) noexcept;
  Status send_probe(Neighbor& neighbor, MonotonicMs now_ms) noexcept;
  Status emit_rld1(const MacAddress& dest, FrameType kind,
                   const std::array<std::uint8_t, 16>& nonce, NodeId claimed,
                   ByteView body, MonotonicMs now_ms,
                   ScopeDigest* frame_digest = nullptr) noexcept;

  // Scope pipeline (02-discovery-scope §2.4-§2.7).
  void drain_scope_pending(MonotonicMs now_ms) noexcept;
  void admit_scoped_discover(PendingVerify& pending, MonotonicMs now_ms) noexcept;
  void accept_scoped_offer(PendingVerify& pending, MonotonicMs now_ms) noexcept;
  void admit_discover(const MacAddress& source, const autonomy::Rld1Envelope& env,
                      const ScopeExchangeContext& exchange, std::uint32_t density,
                      MonotonicMs now_ms) noexcept;
  void accept_offer(const MacAddress& source, const autonomy::Rld1Envelope& env,
                    const std::array<std::uint8_t, 16>& cookie,
                    const std::array<std::uint8_t, 16>& responder_nonce,
                    ByteView frame, MonotonicMs now_ms) noexcept;
  bool scope_rx_usable() const noexcept;
  bool scope_tx_usable() noexcept;
  bool scoped_attempt(MonotonicMs now_ms) noexcept;
  bool legacy_permitted(MonotonicMs now_ms) const noexcept;
  bool scoped_hint_for(endpoint::ScopeClass scope_class, std::uint32_t generation,
                       std::uint32_t& out) noexcept;
  void record_discover(MonotonicMs now_ms) noexcept;
  Status emit_auth_body(const MacAddress& dest,
                        const std::array<std::uint8_t, 16>& nonce, NodeId claimed,
                        const autonomy::BootstrapAuthBody& body,
                        MonotonicMs now_ms) noexcept;
  Status send_chunk_reply(const MacAddress& dest,
                          const std::array<std::uint8_t, 16>& nonce, NodeId claimed,
                          std::uint32_t transaction, std::uint16_t received,
                          std::uint8_t status, MonotonicMs now_ms) noexcept;

  // Gate: carrier + coarse allowlist + transaction liveness for the given
  // kind, on the freshest context. Re-run before every dispatch and every TX.
  bool gate(AdmissionCarrier carrier, AdmissionDirection direction, FrameType type,
            bool transaction_alive, MonotonicMs now_ms) noexcept;
  AdmissionRole local_role() const noexcept;

  // `we_are_requester` selects which transcript side is local; `exchange`
  // binds the exact DISCOVER/OFFER digests into the auth transcript.
  void complete_exchange(const MacAddress& peer_mac, NodeId peer_node,
                         std::uint32_t peer_capability,
                         const std::array<std::uint8_t, 16>& requester_nonce,
                         const std::array<std::uint8_t, 16>& responder_nonce,
                         const AuthTag& closing_tag,
                         const ScopeExchangeContext& exchange,
                         bool we_are_requester,
                         MonotonicMs now_ms) noexcept;
  void fail_outbound(MonotonicMs now_ms, const char* reason) noexcept;
  void release_candidate(Candidate& candidate) noexcept;
  void cancel_competing(const MacAddress& mac, NodeId node) noexcept;
  // Drop a passive responder back to Discovering when no auth exchange is
  // left in flight; never demotes Member/AuthorizedPendingCommit.
  void relax_membership() noexcept;

  Candidate* find_candidate(const MacAddress& mac,
                            const std::array<std::uint8_t, 16>& nonce) noexcept;
  Neighbor* find_neighbor(const MacAddress& mac) noexcept;
  Neighbor* find_neighbor(NodeId node) noexcept;
  const Neighbor* find_neighbor(const MacAddress& mac) const noexcept;
  const Neighbor* find_neighbor(NodeId node) const noexcept;

  bool reserve_transient() noexcept;
  void release_transient() noexcept;
  bool reserve_regular(Neighbor& neighbor) noexcept;

  bool next_u64(std::uint64_t& out) noexcept;  // false = entropy unavailable
  // Uniform draw in [backoff_min_ms, backoff_initial_max_ms] for the first
  // retry wait (radio.md §7/§13). False when entropy is unavailable.
  bool draw_retry_backoff(std::uint32_t& out_ms) noexcept;
  std::uint32_t recent_discovers(MonotonicMs now_ms) const noexcept;
  void event(const char* reason, NodeId peer) noexcept {
    observer_.on_discovery_event(reason, peer);
  }

  // Reject-path events can fire at line rate under malformed/replayed
  // traffic: thin emission deterministically (1st, then every 8th) per
  // reason so logging can never crowd out the RX path. The aggregate loss
  // stays observable through stats_.*_rejects counters, which still count
  // every occurrence.
  void reject_event(const char* reason, NodeId peer) noexcept {
    RejectBudget* budget = reject_budgets_.find([&](const RejectBudget& b) {
      return b.reason != nullptr && std::strcmp(b.reason, reason) == 0;
    });
    if (budget == nullptr) {
      budget = reject_budgets_.allocate();
      if (budget == nullptr) {
        event(reason, peer);  // reasons are a fixed literal set; emit anyway
        return;
      }
      budget->reason = reason;
      budget->count = 0;
    }
    ++budget->count;
    if ((budget->count & 7U) == 1U) {
      event(reason, peer);
    }
  }

  struct RejectBudget {
    const char* reason{nullptr};
    std::uint16_t count{0};
  };

  DiscoveryConfig config_{};
  DiscoveryPort& port_;
  NeighborAuthenticator& authenticator_;
  MembershipHooks& hooks_;
  EntropySource& entropy_;
  DiscoveryObserver& observer_;
  MembershipController membership_{};

  FixedPool<Candidate, discovery_const::kCandidateCapacity> candidates_{};
  FixedPool<Neighbor, discovery_const::kNeighborCapacity> neighbors_{};
  FixedPool<RxAssembly, discovery_const::kReassemblySlots> assemblies_{};
  // Reject-reason literals are a fixed compile-time set (13 today); 16
  // slots cover all of them so throttling never evicts under mixed floods.
  FixedPool<RejectBudget, 16> reject_budgets_{};
  std::array<MonotonicMs, discovery_const::kCandidateCapacity> discover_times_{};
  std::size_t discover_cursor_{0};

  Outbound outbound_{};
  std::uint32_t next_candidate_id_{1};
  std::uint32_t next_binding_id_{1};
  std::uint32_t next_probe_sequence_{1};
  MonotonicMs next_handshake_ms_{0};   // 1/s burst-1 token bucket
  // Stranded-node re-discovery (04 §9.2): armed when the last usable edge
  // is gone but resolvable Stale records survive; backoff doubles from a
  // [backoff_min, backoff_initial_max] draw to backoff_max between bounded
  // begin_discovery runs (radio.md §7/§13).
  MonotonicMs next_rediscovery_ms_{0};
  std::uint32_t rediscovery_backoff_ms_{0};
  std::size_t transient_used_{0};
  std::size_t regular_used_{0};
  std::size_t pins_used_{0};
  DiscoveryStats stats_{};
  bool started_{false};

  // Scope-filter state (02-discovery-scope §2.5-§2.7): raw ingress token
  // bucket, replay dedup, the bounded pending-MAC queue and the cached
  // (class,generation)->hint hints that keep step-3 checks MAC-free.
  ScopeRawBudget raw_budget_{};
  ScopeDedupTable dedup_{};
  FixedPool<PendingVerify, kScopePendingCapacity> pending_verify_{};
  struct HintEntry {
    bool valid{false};
    endpoint::ScopeClass scope_class{endpoint::ScopeClass::Member};
    std::uint32_t generation{0};
    std::uint32_t hint{0};
  };
  std::array<HintEntry, 4> hint_cache_{};
  std::size_t hint_cursor_{0};
  MonotonicMs migration_deadline_ms_{0};
  ScopeStats scope_stats_{};
};

}  // namespace routeloom
