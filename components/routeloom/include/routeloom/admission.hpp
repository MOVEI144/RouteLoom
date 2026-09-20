#pragma once

#include <cstdint>

#include "routeloom/autonomy.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom {

// Node x Network belonging — the authoritative six membership states. Values
// 0-5 and their semantics are frozen (protocol/semantics.json); the
// membership controller is the only writer. A peer's self-declared state is
// never assigned into this enum.
enum class MembershipState : std::uint8_t {
  Unprovisioned = 0,
  Discovering,
  Authenticating,
  AuthorizedPendingCommit,
  Member,
  Revoked,
};

// Coarse candidate screen only — synchronized with the authoritative
// `membership_allowlist` in protocol/semantics.json (the normative source;
// see docs/design/autonomous-mesh/06-membership-admission.md §4). This is the
// SECOND conjunct of the full admission product, never the final gate:
// carrier, role, transaction liveness, evidence, feature capability and
// budget still apply. Unknown FrameTypes and out-of-range states default to
// false.
constexpr bool member_frame_type(const FrameType type) noexcept {
  // Explicit list so a future FrameType does not silently become admissible.
  switch (type) {
    case FrameType::Discover:
    case FrameType::Offer:
    case FrameType::BootstrapAuth:
    case FrameType::MembershipResult:
    case FrameType::BootstrapChunk:
    case FrameType::BootstrapReply:
    case FrameType::MembershipQuery:
    case FrameType::Data:
    case FrameType::HopAccept:
    case FrameType::EndReceipt:
    case FrameType::AppResult:
    case FrameType::Busy:
    case FrameType::Service:
    case FrameType::Control:
    case FrameType::TimeSync:
    case FrameType::ChannelNotice:
    case FrameType::RouteUpdate:
    case FrameType::RouteWithdraw:
    case FrameType::SeqnoRequest:
    case FrameType::RouteRequest:
    case FrameType::NeighborProbe:
    case FrameType::NeighborResult:
    case FrameType::Diagnostic:
    case FrameType::ControlObject:
    case FrameType::ObjectChunk:
    case FrameType::ObjectAck:
      return true;
  }
  return false;
}

constexpr bool bootstrap_frame_type(const FrameType type) noexcept {
  switch (type) {
    case FrameType::Discover:
    case FrameType::Offer:
    case FrameType::BootstrapAuth:
    case FrameType::MembershipResult:
    case FrameType::BootstrapChunk:
    case FrameType::BootstrapReply:
    case FrameType::MembershipQuery:
      return true;
    default:
      return false;
  }
}

constexpr bool frame_allowed(const MembershipState state, const FrameType type) noexcept {
  switch (state) {
    case MembershipState::Unprovisioned:
    case MembershipState::Discovering:
      return type == FrameType::Discover || type == FrameType::Offer;
    case MembershipState::Authenticating:
      return type == FrameType::Discover || type == FrameType::Offer ||
             type == FrameType::BootstrapAuth || type == FrameType::BootstrapChunk ||
             type == FrameType::BootstrapReply;
    case MembershipState::AuthorizedPendingCommit:
      return type == FrameType::MembershipQuery || type == FrameType::MembershipResult ||
             type == FrameType::BootstrapChunk || type == FrameType::BootstrapReply;
    case MembershipState::Member:
      // semantics.json MEMBER = bootstrap set + member_only set = every known
      // type id. Enumerated explicitly: an unknown type id is denied.
      return member_frame_type(type);
    case MembershipState::Revoked:
      return false;
  }
  return false;
}

// --- Context-carrying admission contract (06-membership-admission.md §4.3) ---

// Carrier the frame arrived on / would leave on. RLD1 is the limited 1-hop
// bootstrap carrier; it shares FrameType numbers with Wire v1 but is a
// different carrier with a smaller kind set and never carries DATA,
// MembershipResult or MembershipQuery.
enum class AdmissionCarrier : std::uint8_t {
  WireV1 = 0,
  Rld1 = 1,
};

// The LOCAL node's role in this admission decision — assigned from verified
// local state, never from a received packet's self-declared role.
enum class AdmissionRole : std::uint8_t {
  JoiningNode = 0,
  MemberResponder,
  JoinProxy,
  Authority,
  EstablishedPeer,
};

enum class AdmissionDirection : std::uint8_t {
  Rx = 0,
  Tx = 1,
};

// Everything the final gate may consult. role/state are populated from
// verified records only; a packet's self-declared membership/role must never
// fill these fields.
struct AdmissionContext {
  MembershipState local_membership{MembershipState::Unprovisioned};
  AdmissionDirection direction{AdmissionDirection::Rx};
  AdmissionCarrier carrier{AdmissionCarrier::WireV1};
  AdmissionRole role{AdmissionRole::JoiningNode};
  // The subject peer's VERIFIED record (membership + binding). Absent until
  // the membership controller/authenticator produced evidence.
  MembershipState subject_membership{MembershipState::Unprovisioned};
  NeighborPhase subject_phase{NeighborPhase::Candidate};
  bool subject_record_verified{false};
  BindingId subject_binding{kInvalidBindingId};
  MacAddress subject_address{};
  BindingGeneration binding_generation{};
  RadioGeneration radio_generation{};
  // Bootstrap transaction binding (mandatory for bootstrap types): the live
  // transaction id and the step this exchange expects next.
  std::uint32_t transaction{0};
  std::uint8_t expected_step{0};
  bool transaction_alive{false};
  MonotonicMs deadline_ms{0};
  // Verified evidence, negotiated feature capability and remaining preauth
  // resource budget for this decision.
  bool evidence_verified{false};
  bool feature_capable{false};
  std::uint16_t budget_remaining{0};
};

enum class AdmissionVerdict : std::uint8_t {
  Denied = 0,
  // Passed the known-type + carrier + coarse-allowlist screen ONLY. This is
  // not authorization: transaction liveness, evidence, role and budget must
  // still be re-checked on the freshest context before dispatch, assembly
  // completion, TX commit or state promotion.
  CoarseAllow,
};

// What a CoarseAllow scopes the frame to.
enum class AdmissionScope : std::uint8_t {
  None = 0,
  Bootstrap,  // pre-membership discovery/bootstrap traffic only
  Member,     // member-eligible traffic (still requires the full context gate)
};

struct AdmissionDecision {
  AdmissionVerdict verdict{AdmissionVerdict::Denied};
  AdmissionScope scope{AdmissionScope::None};
  StatusCode reason{StatusCode::ProtocolError};
};

// RLD1 kind allowlist {1,2,3,5,6} — MembershipResult/MembershipQuery, DATA and
// every unknown kind are forbidden on the RLD1 carrier (contracts.json
// admission.rld1_type_ids).
constexpr bool rld1_kind_allowed(const FrameType type) noexcept {
  return type == FrameType::Discover || type == FrameType::Offer ||
         type == FrameType::BootstrapAuth || type == FrameType::BootstrapChunk ||
         type == FrameType::BootstrapReply;
}

// First two conjuncts of the admission product: known type AND correct
// carrier AND local-membership coarse allowlist. A CoarseAllow is an entry
// ticket to heavier checks, never the final permit.
constexpr AdmissionDecision admission_decision(const AdmissionContext& context,
                                               const FrameType type) noexcept {
  if (!member_frame_type(type)) {
    return AdmissionDecision{AdmissionVerdict::Denied, AdmissionScope::None,
                             StatusCode::ProtocolError};
  }
  if (context.carrier == AdmissionCarrier::Rld1 && !rld1_kind_allowed(type)) {
    return AdmissionDecision{AdmissionVerdict::Denied, AdmissionScope::None,
                             StatusCode::ProtocolError};
  }
  if (!frame_allowed(context.local_membership, type)) {
    return AdmissionDecision{AdmissionVerdict::Denied, AdmissionScope::None,
                             StatusCode::AuthorizationFailed};
  }
  const AdmissionScope scope = bootstrap_frame_type(type)
                                   ? AdmissionScope::Bootstrap
                                   : AdmissionScope::Member;
  return AdmissionDecision{AdmissionVerdict::CoarseAllow, scope, StatusCode::Ok};
}

}  // namespace routeloom
