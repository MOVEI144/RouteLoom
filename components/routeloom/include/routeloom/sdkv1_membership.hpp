#pragma once

// P4 membership evidence (G-SEC P4 design §3): the durable local-removal
// record (RLV1, issue #60-2) and the RLI1/RLS1/RRS1-backed membership hooks.
//
// A removal the node durably accepted is never forgotten — not across
// reboot, not across cleanup: the LocalRevocationStore keeps the last
// removal evidence, and SdkMembershipHooks refuses Member while any removal
// stands unresolved (Blocked, Cleaned within holdoff, torn, or unreadable).
// No heap, no exceptions; the Owner serializes calls.

#include <cstddef>
#include <cstdint>

#include "routeloom/discovery.hpp"  // MembershipHooks, MembershipState
#include "routeloom/sdkv1_records.hpp"
#include "routeloom/sdkv1_store.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom::sdkv1 {

// --- LocalRevocationStore (RLV1) ------------------------------------------------
// Fixed two keys, sequenced A/B through the shared sealed-store discipline.
// Operations are deliberately narrow: there is no erase gate — only a newer
// removal overwrites the evidence, and only the fixed cleanup order (§3.3
// steps 1-5, owned by the PR4 Owner) moves Blocked -> Cleaned.
class LocalRevocationStore {
 public:
  explicit LocalRevocationStore(RecordSlotStorage& storage) noexcept;

  Status initialize() noexcept;
  // Re-read the adopted record after an error, so the caller never has to
  // guess whether a failed commit landed.
  Status refresh() noexcept;

  // Durably record a verified removal (`record.state` must be Blocked).
  // An unresolved Blocked record only accepts the same membership with a
  // non-decreasing removed generation. Once Cleaned, a later joined site
  // may record its own removal; the same site's generation cannot regress.
  // Reports success only after the commit read back.
  Status commit_blocked(const LocalRevocationRecord& record) noexcept;
  // The recorded site/network is fully cleaned (RLS1/RLT1/RLP/RRS1
  // tombstones all read back): Blocked -> Cleaned. Refused unless Blocked.
  Status commit_cleaned() noexcept;

  bool initialized() const noexcept { return pair_.initialized(); }
  bool has_record() const noexcept { return pair_.has_active(); }
  bool quarantined() const noexcept { return pair_.quarantined(); }
  bool uncertain() const noexcept { return pair_.uncertain(); }
  std::uint32_t commit_seq() const noexcept { return pair_.active_seq(); }
  const LocalRevocationRecord& record() const noexcept { return record_; }

  // True unless the store provably holds nothing: a Blocked/Cleaned record,
  // quarantine, uncertainty, or a store that never initialized all block.
  // A Cleaned record stops blocking once the Owner's 10-minute monotonic
  // holdoff elapsed (`holdoff_elapsed`, RAM-measured from the Cleaned
  // commit; a reboot restarts it).
  bool blocks_membership(bool holdoff_elapsed) const noexcept;

  // Read-only join-commit gate: a same-site adoption must strictly exceed
  // the removed generation; any adoption needs Cleaned + elapsed holdoff
  // when a record stands. No record: always allowed.
  Status check_join(std::uint64_t site_id, std::uint32_t generation,
                    bool holdoff_elapsed) const noexcept;

 private:
  Status encode(const LocalRevocationRecord& record, std::uint32_t seal, std::size_t& used_len,
                std::uint32_t seq) noexcept;
  Status reload() noexcept;

  ByteBuffer<kLocalRevocationSlotBytes> scratch_{};
  SealedSlotPair pair_;
  LocalRevocationRecord record_{};
};

// --- Membership evidence ports ---------------------------------------------------

// "Authenticated this boot": the Owner answers from the bank/handshake
// summary (P4 §3.1). A NodeId in a cache, a shared GK, or an RLP peer name
// is NOT enough — only a completed authentication of this boot counts.
class AuthenticatedPeerView {
 public:
  virtual ~AuthenticatedPeerView() = default;
  // True with the verified generation/role when `peer` completed member
  // authentication on `network` this boot.
  virtual bool authenticated(NodeId peer, NetworkId network, std::uint32_t& generation,
                             std::uint32_t& role) const noexcept = 0;
};

// Durable boot evidence: the RLS1 boot witness must be plausible against
// the system boot counter (P4 §3.1, §9.2).
class BootWitnessView {
 public:
  virtual ~BootWitnessView() = default;
  virtual bool boot_witness_ok(std::uint32_t witness) const noexcept = 0;
};

// --- SdkMembershipHooks ------------------------------------------------------------
// MembershipHooks backed by the adopted RLI1/RLS1/RRS1, the local-removal
// gate and the boot-authenticated peer summary. Null views fail closed.
class SdkMembershipHooks final : public MembershipHooks {
 public:
  SdkMembershipHooks(const IdentityStore& identity, const SiteStore& site,
                     const RevocationStore& revocations, const LocalRevocationStore& local_revocation,
                     const AuthenticatedPeerView* peers,
                     const BootWitnessView* boot) noexcept;

  // The Owner sets this once its RAM-measured 10-minute holdoff since the
  // Cleaned commit elapsed (a reboot clears it by reconstruction).
  void set_holdoff_elapsed(bool elapsed) noexcept { holdoff_elapsed_ = elapsed; }

  bool local_member(NetworkId network) const noexcept override;
  bool known_member(NodeId peer, NetworkId network) const noexcept override;
  bool approve_join(NodeId node, NetworkId network) noexcept override;
  Status local_state(NetworkId network, MembershipState& out) const noexcept override;

 private:
  // Determined rejection: the adopted RRS1 names this node's generation.
  bool self_rejected() const noexcept;
  // Unprovable floor: set/site mismatch, a set below the adopted floor, or
  // a nonzero floor with no set behind it. Traffic closes (recovery), but
  // it is not a determined rejection.
  bool floor_lost() const noexcept;
  bool stores_healthy() const noexcept;

  const IdentityStore& identity_;
  const SiteStore& site_;
  const RevocationStore& revocations_;
  const LocalRevocationStore& local_revocation_;
  const AuthenticatedPeerView* peers_;
  const BootWitnessView* boot_;
  bool holdoff_elapsed_{false};
};

}  // namespace routeloom::sdkv1
