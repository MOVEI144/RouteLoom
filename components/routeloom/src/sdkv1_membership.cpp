#include "routeloom/sdkv1_membership.hpp"

#include "routeloom/device_credential.hpp"  // CredentialKeyLocation

namespace routeloom::sdkv1 {
namespace {

bool site_matches(const SiteRecord& site, NetworkId network) noexcept {
  return site.state == SiteState::Member && site.network == network;
}

}  // namespace

// --- LocalRevocationStore --------------------------------------------------------

LocalRevocationStore::LocalRevocationStore(RecordSlotStorage& storage) noexcept
    : pair_(storage, local_revocation_record_format(), scratch_.writable(), &record_) {}

Status LocalRevocationStore::initialize() noexcept {
  const Status status = pair_.initialize();
  const Status loaded = reload();
  if (!loaded) return loaded;
  return status;
}

Status LocalRevocationStore::refresh() noexcept {
  if (!pair_.initialized()) {
    return Status::error(StatusCode::InvalidState, "rlv1 not initialized");
  }
  const Status status = pair_.initialize();
  const Status loaded = reload();
  if (!loaded) return loaded;
  return status;
}

Status LocalRevocationStore::reload() noexcept {
  record_ = LocalRevocationRecord{};
  if (!pair_.has_active()) return Status::success();
  ByteView record{};
  const Status loaded = pair_.load_active(record);
  if (!loaded) return loaded;
  return local_revocation_record_decode(record, record_);
}

Status LocalRevocationStore::encode(const LocalRevocationRecord& record, const std::uint32_t seal,
                                    std::size_t& used_len, const std::uint32_t seq) noexcept {
  scratch_.clear();
  const Status status = local_revocation_record_encode(record, seal, seq, scratch_);
  if (!status) return status;
  used_len = scratch_.size;
  return Status::success();
}

Status LocalRevocationStore::commit_blocked(const LocalRevocationRecord& record) noexcept {
  if (!pair_.initialized()) {
    return Status::error(StatusCode::InvalidState, "rlv1 not initialized");
  }
  if (record.state != LocalRevocationState::Blocked) {
    return Status::error(StatusCode::InvalidArgument, "rlv1 not blocked");
  }
  const Status valid = local_revocation_validate(record);
  if (!valid) return valid;
  if (pair_.has_active()) {
    const bool same = record_.local_node == record.local_node && record_.site_id == record.site_id &&
                      record_.network == record.network;
    if (!same || record.removed_generation < record_.removed_generation) {
      // A different removal while one stands (or a generation that walks
      // backwards): finish the recorded cleanup first.
      return Status::error(StatusCode::Conflict, "rlv1 removal superseded");
    }
  }
  // commit_prepared refuses while quarantined/uncertain; recovery from those
  // states is the Owner's explicit re-commit path (via refresh + the same
  // call), never an implicit twin overwrite — a torn removal record must
  // stay blocking until its replacement reads back.
  std::size_t used_len = 0;
  Status status = encode(record, kSealPending, used_len, 0);
  if (status) status = pair_.commit_prepared(used_len);
  if (!status) {
    // Unknown landing: re-read so the caller learns the adopted state
    // instead of guessing.
    static_cast<void>(refresh());
    return status;
  }
  return reload();
}

Status LocalRevocationStore::commit_cleaned() noexcept {
  if (!pair_.initialized()) {
    return Status::error(StatusCode::InvalidState, "rlv1 not initialized");
  }
  if (!pair_.has_active() || record_.state != LocalRevocationState::Blocked) {
    return Status::error(StatusCode::InvalidState, "rlv1 not blocked");
  }
  LocalRevocationRecord cleaned = record_;
  cleaned.state = LocalRevocationState::Cleaned;
  std::size_t used_len = 0;
  Status status = encode(cleaned, kSealPending, used_len, 0);
  if (status) status = pair_.commit_prepared(used_len);
  if (!status) {
    static_cast<void>(refresh());
    return status;
  }
  return reload();
}

bool LocalRevocationStore::blocks_membership(const bool holdoff_elapsed) const noexcept {
  if (!pair_.initialized()) return true;
  if (!pair_.has_active()) {
    // Missing/missing is the only non-blocking shape: quarantine,
    // uncertainty, or a pending-but-unproven sibling all block.
    return pair_.quarantined() || pair_.uncertain();
  }
  if (record_.state == LocalRevocationState::Cleaned && holdoff_elapsed) return false;
  return true;
}

Status LocalRevocationStore::check_join(const std::uint64_t site_id, const std::uint32_t generation,
                                        const bool holdoff_elapsed) const noexcept {
  if (!pair_.initialized()) {
    return Status::error(StatusCode::InvalidState, "rlv1 not initialized");
  }
  if (quarantined() || uncertain()) {
    return Status::error(StatusCode::StorageFailure, "rlv1 gate unprovable");
  }
  if (!pair_.has_active()) return Status::success();
  if (record_.state != LocalRevocationState::Cleaned || !holdoff_elapsed) {
    return Status::error(StatusCode::AuthorizationFailed, "rlv1 removal unresolved");
  }
  // Cleaned + holdoff elapsed: only a strictly newer same-site generation
  // (or a full join to another site) may adopt.
  if (site_id == record_.site_id && generation <= record_.removed_generation) {
    return Status::error(StatusCode::AuthorizationFailed, "rlv1 generation not superseded");
  }
  return Status::success();
}

// --- SdkMembershipHooks ------------------------------------------------------------

SdkMembershipHooks::SdkMembershipHooks(
    const IdentityStore& identity, const SiteStore& site, const RevocationStore& revocations,
    const LocalRevocationStore& local_revocation, const AuthenticatedPeerView* peers,
    const BootWitnessView* boot) noexcept
    : identity_(identity),
      site_(site),
      revocations_(revocations),
      local_revocation_(local_revocation),
      peers_(peers),
      boot_(boot) {}

bool SdkMembershipHooks::stores_healthy() const noexcept {
  if (!identity_.initialized() || !site_.initialized() || !revocations_.initialized() ||
      !local_revocation_.initialized()) {
    return false;
  }
  if (!identity_.has_identity() || identity_.quarantined() || identity_.uncertain()) return false;
  if (site_.quarantined() || site_.uncertain()) return false;
  if (revocations_.quarantined() || revocations_.uncertain()) return false;
  if (local_revocation_.quarantined() || local_revocation_.uncertain()) return false;
  return true;
}

bool SdkMembershipHooks::self_rejected() const noexcept {
  const SiteRecord& site = site_.site();
  if (site.state != SiteState::Member || !revocations_.has_set()) return false;
  const RevocationSet& set = revocations_.set();
  if (set.site_id != site.site_id || set.network != site.network) return false;
  if (set.rs_epoch < site.rs_epoch_floor) return false;
  return revocation_rejects(set, identity_.identity().node_id, site.assignment_generation,
                            static_cast<std::uint32_t>(site.network >> 32U));
}

bool SdkMembershipHooks::floor_lost() const noexcept {
  const SiteRecord& site = site_.site();
  if (site.state != SiteState::Member) return false;
  if (revocations_.has_set()) {
    const RevocationSet& set = revocations_.set();
    if (set.site_id != site.site_id || set.network != site.network) return true;
    return set.rs_epoch < site.rs_epoch_floor;
  }
  // No set adopted: only a zero floor is consistent (a fresh join that has
  // not fetched revocations yet). A nonzero floor with no set behind it is
  // a lost floor — traffic closes rather than presume an empty set.
  return site.rs_epoch_floor != 0;
}

bool SdkMembershipHooks::local_member(const NetworkId network) const noexcept {
  if (!stores_healthy()) return false;
  const IdentityRecord& identity = identity_.identity();
  const SiteRecord& site = site_.site();
  if (!site_matches(site, network)) return false;
  if (identity.node_id == kInvalidNodeId) return false;
  // Only a plaintext key the boot checks reproduced (location 1) can do
  // member crypto; a handle (2/3) is never passed as a scalar (P4 §3.1).
  if (identity.key_location != CredentialKeyLocation::NvsPlaintext) return false;
  if (!site_matches_identity(site, identity).ok()) return false;
  if (local_revocation_.blocks_membership(holdoff_elapsed_)) return false;
  if (local_revocation_.has_record() && local_revocation_.record().site_id == site.site_id &&
      site.assignment_generation <= local_revocation_.record().removed_generation) {
    // Even past the holdoff, the removed generation never comes back.
    return false;
  }
  if (self_rejected() || floor_lost()) return false;
  if (boot_ == nullptr || !boot_->boot_witness_ok(site.boot_witness)) return false;
  return true;
}

bool SdkMembershipHooks::known_member(const NodeId peer, const NetworkId network) const noexcept {
  if (peers_ == nullptr || !stores_healthy()) return false;
  if (!site_matches(site_.site(), network)) return false;
  if (local_revocation_.blocks_membership(holdoff_elapsed_)) return false;
  std::uint32_t generation = 0, role = 0;
  if (!peers_->authenticated(peer, network, generation, role)) return false;
  // This boot's authentication, re-checked against the latest revocation
  // view: a peer revoked after the handshake is no longer known.
  if (generation == 0 || role == 0) return false;
  if (revocations_.has_set() &&
      revocation_rejects(revocations_.set(), peer, generation,
                         static_cast<std::uint32_t>(network >> 32U))) {
    return false;
  }
  return true;
}

bool SdkMembershipHooks::approve_join(const NodeId node, const NetworkId network) noexcept {
  // Re-examination of the durably committed adoption only (P4 §3.1): the
  // adopted RLS1 must name this node on this network and pass the full
  // member evidence — a radio peer's approval is never reused here.
  if (!stores_healthy()) return false;
  if (node != identity_.identity().node_id) return false;
  return local_member(network);
}

Status SdkMembershipHooks::local_state(const NetworkId network,
                                        MembershipState& out) const noexcept {
  // The durable refusal wins over every other signal: a removal the node
  // accepted never reboots back into Member.
  if (!local_revocation_.initialized() || local_revocation_.quarantined() ||
      local_revocation_.uncertain()) {
    out = MembershipState::Revoked;
    return Status::error(StatusCode::StorageFailure, "rlv1 gate unprovable");
  }
  if (local_revocation_.has_record() &&
      local_revocation_.blocks_membership(holdoff_elapsed_)) {
    out = MembershipState::Revoked;
    return Status::success();
  }
  if (!identity_.initialized() || !site_.initialized() || !revocations_.initialized() ||
      identity_.quarantined() || identity_.uncertain() || site_.quarantined() ||
      site_.uncertain() || revocations_.quarantined() || revocations_.uncertain()) {
    // Storage cannot prove either way: gate traffic as Revoked and say so.
    out = MembershipState::Revoked;
    return Status::error(StatusCode::StorageFailure, "membership stores unprovable");
  }
  if (identity_.has_identity() && site_matches(site_.site(), network)) {
    if (self_rejected()) {
      out = MembershipState::Revoked;
      return Status::success();
    }
    if (floor_lost()) {
      out = MembershipState::Revoked;
      return Status::error(StatusCode::RecoveryRequired, "rrs1 floor lost");
    }
  }
  if (local_member(network)) {
    out = MembershipState::Member;
    return Status::success();
  }
  out = MembershipState::Unprovisioned;
  return Status::success();
}

}  // namespace routeloom::sdkv1
