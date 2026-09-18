#pragma once

#include <cstdint>

#include "routeloom/types.hpp"

namespace routeloom {

enum class MembershipState : std::uint8_t {
  Unprovisioned = 0,
  Discovering,
  Authenticating,
  AuthorizedPendingCommit,
  Member,
  Revoked,
};

constexpr bool frame_allowed(const MembershipState state, const FrameType type) noexcept {
  switch (state) {
    case MembershipState::Unprovisioned:
      return type == FrameType::Discover;
    case MembershipState::Discovering:
      return type == FrameType::Discover || type == FrameType::Offer;
    case MembershipState::Authenticating:
      return type == FrameType::Discover || type == FrameType::Offer ||
             type == FrameType::BootstrapAuth;
    case MembershipState::AuthorizedPendingCommit:
      return type == FrameType::BootstrapAuth || type == FrameType::MembershipResult;
    case MembershipState::Member:
      return type != FrameType::Discover && type != FrameType::Offer;
    case MembershipState::Revoked:
      return type == FrameType::Discover;
  }
  return false;
}

}  // namespace routeloom
