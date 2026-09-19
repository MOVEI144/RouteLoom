#pragma once

// Peer/binding contract types for the autonomous-mesh profile
// (docs/design/autonomous-mesh/02-discovery.md §2, §7 and
// 06-membership-admission.md §2). These are pure contract types: discovery,
// authentication and binding management are implemented in later phases.
//
// Two independent state axes exist and must never be conflated:
//   - MembershipState (admission.hpp): Node x Network belonging, 6 states,
//     owned by the membership controller.
//   - NeighborPhase (below): per (peer, radio, exchange) connection phase,
//     owned by discovery/binding management. Same display names
//     (AUTHENTICATING, REVOKED) are DIFFERENT enum types on purpose.

#include <cstdint>

#include "routeloom/types.hpp"

namespace routeloom {

// --- Distinct id types -------------------------------------------------------

// Identifies a VerifiedBinding: the tuple (authenticated peer, both radio
// addresses, Network, security context, binding generation) as issued by the
// radio Owner after membership and evidence re-verification. Only the Owner
// may mint bindings; other components hold the id.
struct BindingId {
  std::uint32_t value{0};

  friend constexpr bool operator==(const BindingId& a, const BindingId& b) noexcept {
    return a.value == b.value;
  }
  friend constexpr bool operator!=(const BindingId& a, const BindingId& b) noexcept {
    return !(a == b);
  }
};
constexpr BindingId kInvalidBindingId{0};

// Identifies an unauthenticated discovery candidate. Deliberately NOT
// convertible to BindingId or NodeId: candidate ids must never reach Core
// delivery APIs (MeshNode::send/add_neighbor take NodeId and must only be
// fed post-BOUND, membership-verified identities).
struct CandidateId {
  std::uint32_t value{0};

  friend constexpr bool operator==(const CandidateId& a, const CandidateId& b) noexcept {
    return a.value == b.value;
  }
  friend constexpr bool operator!=(const CandidateId& a, const CandidateId& b) noexcept {
    return !(a == b);
  }
};
constexpr CandidateId kInvalidCandidateId{0};

// Generation of a specific (peer, address, session) binding. Re-authenticating
// the same peer or observing an address change bumps this; stale TX/ACK/load
// feedback must never be attributed to a newer generation. Not a nonce
// counter and not a MessageId.
struct BindingGeneration {
  std::uint32_t value{0};

  friend constexpr bool operator==(const BindingGeneration& a,
                                   const BindingGeneration& b) noexcept {
    return a.value == b.value;
  }
  friend constexpr bool operator!=(const BindingGeneration& a,
                                   const BindingGeneration& b) noexcept {
    return !(a == b);
  }
};

// --- NeighborPhase -----------------------------------------------------------

// Per (peer radio x exchange) connection phase. Scope: peer-radio-exchange,
// NOT node-network membership. CONFLICT/REVOKED are per-peer rejection
// states/reasons — a peer's REVOKED phase never changes the local node's own
// MembershipState.
enum class NeighborPhase : std::uint8_t {
  Candidate = 0,        // cheap parse, cookie, few OFFERs; no DATA
  Authenticating,       // one bounded mutual proof in progress; no DATA
  Authenticated,        // identity + peer radio proven; membership unchecked
  ApprovalPending,      // bounded proxy toward admission provider; no DATA
  Bound,                // membership + binding valid; availability probe only
  Reachable,            // verified bidirectional liveness; policy-limited DATA
  Suspended,            // sleep/planned absence/revocation check pending
  Stale,                // lease expired; re-confirmation only
  Conflict,             // identity/address conflict; quarantined
  Revoked,              // this peer's binding is revoked; unusable
};

// --- BootstrapAddress --------------------------------------------------------

// The ONLY non-binding recipient a TX intent may name: a limited bootstrap
// address used for discovery/initial mutual confirmation on the RLD1 carrier.
// The DATA path must never accept an arbitrary MAC; everything else goes
// through a BindingId.
struct BootstrapAddress {
  MacAddress mac{};
  std::uint32_t network_hint{0};  // 4-byte discovery hint, never proof of membership
};

// --- PeerLease ---------------------------------------------------------------

// Why a driver peer slot is being held. Matches 02-discovery.md §7: held
// peers are not evictable.
enum class PeerLeasePurpose : std::uint8_t {
  TopologyPin = 0,     // normal topology pin (bounded count)
  InFlightTx,          // TX in flight for this peer
  ExpectedReply,       // a reply lease reserved before acceptance
  AuthExchange,        // transient peer for an in-progress auth exchange
  MigrationCriticalEdge,  // edge required by a committed channel plan
};

// A bounded hold on a driver peer record. Expiry is on the local monotonic
// clock; remote timestamps are never compared directly. ttl_ms records the
// granted bound so a lease cannot be silently extended.
struct PeerLease {
  BindingId binding{kInvalidBindingId};
  BindingGeneration binding_generation{};
  PeerLeasePurpose purpose{PeerLeasePurpose::TopologyPin};
  std::uint16_t refcount{0};
  MonotonicMs expires_at_ms{0};
  std::uint32_t ttl_ms{0};

  bool expired(MonotonicMs now_ms) const noexcept { return now_ms >= expires_at_ms; }
};

}  // namespace routeloom
