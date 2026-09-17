#include "routeloom/authority.hpp"

#include <algorithm>

namespace routeloom {

SingleAuthority::SingleAuthority(const NetworkId network, const NodeId authority,
                                 AuthorityStore& store) noexcept
    : network_(network), authority_(authority), store_(store) {}

Status SingleAuthority::initialize() noexcept {
  if (network_ == 0 || authority_ == kInvalidNodeId || authority_ == kBroadcastNodeId) {
    return Status::error(StatusCode::InvalidArgument, "invalid authority identity");
  }
  bool found = false;
  AuthorityRecord stored{};
  auto status = store_.load(stored, found);
  if (!status) return status;
  if (!found) {
    state_.network = network_;
    state_.authority = authority_;
    state_.generation = 1;
    state_.applied_sequence = 0;
  } else {
    if (stored.network != network_ || stored.authority != authority_ || stored.generation == 0) {
      return Status::error(StatusCode::Conflict, "authority store identity mismatch");
    }
    state_ = stored;
  }
  initialized_ = true;
  return Status::success();
}

Status SingleAuthority::validate(const AuthorityOperation& operation,
                                 const bool cryptographic_signature_verified) const noexcept {
  if (!initialized_) return Status::error(StatusCode::InvalidState, "authority not initialized");
  if (!cryptographic_signature_verified) {
    return Status::error(StatusCode::AuthenticationFailed, "authority signature not verified");
  }
  if (operation.network != state_.network || operation.authority != state_.authority ||
      operation.generation != state_.generation) {
    return Status::error(StatusCode::AuthorizationFailed, "authority scope mismatch");
  }
  if (operation.sequence != state_.applied_sequence + 1U) {
    return operation.sequence <= state_.applied_sequence
        ? Status::error(StatusCode::Conflict, "authority operation replayed")
        : Status::error(StatusCode::InvalidState, "authority operation has a gap");
  }
  if (!std::equal(operation.previous_state_hash.begin(), operation.previous_state_hash.end(),
                  state_.state_hash.begin())) {
    return Status::error(StatusCode::Conflict, "authority previous-state hash mismatch");
  }
  return Status::success();
}

Status SingleAuthority::commit(const AuthorityOperation& operation,
                               const Digest256& resulting_state_hash,
                               const bool cryptographic_signature_verified) noexcept {
  auto status = validate(operation, cryptographic_signature_verified);
  if (!status) return status;
  AuthorityRecord next = state_;
  next.applied_sequence = operation.sequence;
  next.state_hash = resulting_state_hash;
  status = store_.commit(next);
  if (!status) return status;
  state_ = next;
  return Status::success();
}

}  // namespace routeloom
