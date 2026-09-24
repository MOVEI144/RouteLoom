#pragma once

// SDK v1 persistent stores (docs/design/sdk-v1/08 P1-3) over a storage port,
// so the ESP-IDF NVS adapter (`rlsec` partition: rlident / rlsite / rlrevo /
// rlres) can land separately. Portable, heap-free, not thread-safe (the
// radio Owner serializes calls). None of these objects is a MeshNode
// member; each owns exactly one slot-sized scratch buffer.
//
// SealedSlotPair is the dual-slot discipline shared with RLT1/RLC1 and the
// authority ledger: seal -> write -> readback -> commit, a power cut
// leaving a discardable pending record, committed-but-CRC-failed records
// still bounding the A/B ordinal floor, both slots lost -> quarantine, an
// unproven sibling -> "uncertain" (known value, commits refused), and an
// explicit recover() as the only way back — never an implicit erase.
//
// Two modes:
//  - Twin (RLI1): no ordinal; every commit writes the identical record to
//    both slots, so two valid survivors must be byte-identical.
//  - Sequenced (RLS1, RRS1 storage record): commit_seq u32 at offset 16;
//    commits alternate slots and the higher sequence wins at boot. Twin
//    writes (same sequence in both slots) are used by recover() and by the
//    removal tombstone so no stale secret survives in the other slot.
//
// Semantic monotonicity (RLS1 generation/epochs, RRS1 rs_epoch and
// site_epoch_floor) is enforced by the typed stores against the adopted
// record before anything is written.

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/authority.hpp"
#include "routeloom/sdkv1_records.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom::sdkv1 {

// Raw two-slot persistence. read() fills the whole slot view (a missing
// blob reads uniformly erased); write() lands a record no larger than the
// slot. Implementations must tolerate power loss at any byte boundary and
// never erase or reformat on error.
class RecordSlotStorage {
 public:
  virtual ~RecordSlotStorage() = default;
  virtual Status read(std::uint8_t slot, MutableByteView target) noexcept = 0;
  virtual Status write(std::uint8_t slot, ByteView data) noexcept = 0;
};

struct SealedRecordFormat {
  std::uint32_t magic{0};
  std::uint32_t seal_committed{0};
  std::size_t slot_bytes{0};
  std::size_t min_len{0};
  std::size_t max_len{0};
  bool sequenced{false};
  // Structural parse of [0, used_len) with a committed seal, CRC not yet
  // checked. Passing proves the commit_seq field is meaningful.
  Status (*structure)(ByteView record) noexcept{nullptr};
  // Full semantic check after CRC and schema prove the record is real.
  // `context` is the typed store's decode target (reused as workspace so
  // no record-sized object lands on the stack).
  Status (*semantic)(ByteView record, void* context) noexcept{nullptr};
};

class SealedSlotPair {
 public:
  static constexpr std::uint8_t kSlots = 2;

  SealedSlotPair(RecordSlotStorage& storage, const SealedRecordFormat& format,
                 MutableByteView scratch, void* decode_context) noexcept;

  Status initialize() noexcept;

  // Re-read the adopted record into the scratch buffer.
  Status load_active(ByteView& record) noexcept;
  // The caller encodes a complete record (any seal/sequence) into
  // scratch()[0, used_len) and then commits it:
  //  - sequenced: to the inactive slot with commit_seq = floor + 1;
  //  - twin: identical bytes to both slots.
  // Refused while quarantined/uncertain.
  MutableByteView scratch() noexcept { return scratch_; }
  Status commit_prepared(std::size_t used_len) noexcept;
  // Same record to BOTH slots (sequenced: one new sequence). Allowed in the
  // impaired states — recover() and the removal tombstone are the explicit
  // ways out; clears quarantine/uncertain on success.
  Status commit_twin_prepared(std::size_t used_len) noexcept;

  bool initialized() const noexcept { return initialized_; }
  bool has_active() const noexcept { return has_active_; }
  bool quarantined() const noexcept { return quarantined_; }
  bool uncertain() const noexcept { return uncertain_; }
  std::uint8_t active_slot() const noexcept { return active_slot_; }
  // Sequenced: the adopted record's sequence, and the highest sequence any
  // committed record (including a CRC-failed one) proved this boot.
  std::uint32_t active_seq() const noexcept { return has_active_ ? active_seq_ : 0; }
  std::uint32_t seq_floor() const noexcept { return seq_floor_; }

 private:
  enum class SlotContent : std::uint8_t { Empty, Pending, Corrupt, Unsupported, Valid };

  Status classify(std::uint8_t slot, SlotContent& content, std::uint32_t& seq,
                  bool& seq_proven, Digest256& digest) noexcept;
  Status write_slot(std::uint8_t slot, std::size_t used_len, std::uint32_t seq) noexcept;
  Status next_seq(std::uint32_t& seq) const noexcept;

  RecordSlotStorage& storage_;
  const SealedRecordFormat& format_;
  MutableByteView scratch_{};
  void* decode_context_{nullptr};
  std::array<StatusCode, kSlots> slot_reserved_{};
  std::uint32_t active_seq_{0};
  std::uint32_t seq_floor_{0};
  std::uint8_t active_slot_{0};
  bool has_active_{false};
  bool initialized_{false};
  bool quarantined_{false};
  bool uncertain_{false};
};

const SealedRecordFormat& identity_record_format() noexcept;
const SealedRecordFormat& site_record_format() noexcept;
const SealedRecordFormat& revocation_record_format() noexcept;
const SealedRecordFormat& local_revocation_record_format() noexcept;

// --- RLI1: device identity (office-written, twin pair) -------------------------
class IdentityStore {
 public:
  explicit IdentityStore(RecordSlotStorage& storage) noexcept;
  Status initialize() noexcept;
  Status commit(const IdentityRecord& record) noexcept;
  Status recover(const IdentityRecord& record) noexcept;

  bool initialized() const noexcept { return pair_.initialized(); }
  bool has_identity() const noexcept { return pair_.has_active(); }
  bool quarantined() const noexcept { return pair_.quarantined(); }
  bool uncertain() const noexcept { return pair_.uncertain(); }
  const IdentityRecord& identity() const noexcept { return identity_; }

 private:
  Status encode(const IdentityRecord& record, std::size_t& used_len) noexcept;

  ByteBuffer<kIdentitySlotBytes> scratch_{};
  SealedSlotPair pair_;
  IdentityRecord identity_{};
};

// --- RLS1: site membership (A/B alternating) ----------------------------------
class SiteStore {
 public:
  explicit SiteStore(RecordSlotStorage& storage) noexcept;
  Status initialize() noexcept;

  // Commit a Member record. With a Member record already adopted, the new
  // one must keep site_id, and must not regress site_epoch (network>>32;
  // an unchanged site_epoch requires the identical network),
  // assignment_generation, gk_epoch_current, rs_epoch_floor or
  // boot_witness (Conflict otherwise).
  Status commit(const SiteRecord& record) noexcept;
  // Removal (04 §6.4): write the cleared tombstone to both slots so no
  // GK/DAMS copy survives. Allowed in any initialized state.
  Status clear() noexcept;
  // Explicit recovery from quarantine/uncertain with a complete Member
  // record (e.g. the idempotent re-issue after a zero-touch rejoin).
  Status recover(const SiteRecord& record) noexcept;

  bool initialized() const noexcept { return pair_.initialized(); }
  bool has_site() const noexcept {
    return pair_.has_active() && site_.state == SiteState::Member;
  }
  bool quarantined() const noexcept { return pair_.quarantined(); }
  bool uncertain() const noexcept { return pair_.uncertain(); }
  std::uint32_t commit_seq() const noexcept { return pair_.active_seq(); }
  const SiteRecord& site() const noexcept { return site_; }

 private:
  Status encode(const SiteRecord& record, std::size_t& used_len) noexcept;

  ByteBuffer<kSiteSlotBytes> scratch_{};
  SealedSlotPair pair_;
  SiteRecord site_{};
};

// --- RRS1: revocation set (A/B alternating) -----------------------------------
class RevocationStore {
 public:
  explicit RevocationStore(RecordSlotStorage& storage) noexcept;
  Status initialize() noexcept;

  // 04 §2 acceptance: structure, SAK signature with the AAD bound to the
  // caller's RLS1 network, site_id/network equal to RLS1, rs_epoch strictly
  // greater than the adopted set's (same site), site_epoch_floor not below
  // it. Malformed -> ProtocolError; wrong site/network or bad signature ->
  // AuthorizationFailed; stale epoch or regressed floor -> Conflict.
  // Refused while quarantined/uncertain.
  Status accept(ByteView object, const P256PublicKey& sak_pubkey, std::uint64_t site_id,
                NetworkId network,
                const Es256Verifier& verifier = default_es256_verifier()) noexcept;
  // Removal: both slots become the object-less tombstone.
  Status clear() noexcept;
  // Explicit recovery (quarantine/uncertain): a verified set whose epoch is
  // not below any set adopted this boot.
  Status recover(ByteView object, const P256PublicKey& sak_pubkey, std::uint64_t site_id,
                 NetworkId network,
                 const Es256Verifier& verifier = default_es256_verifier()) noexcept;

  bool initialized() const noexcept { return pair_.initialized(); }
  bool has_set() const noexcept { return has_set_; }
  bool quarantined() const noexcept { return pair_.quarantined(); }
  bool uncertain() const noexcept { return pair_.uncertain(); }
  const RevocationSet& set() const noexcept { return set_; }
  std::uint32_t rs_epoch() const noexcept { return has_set_ ? set_.rs_epoch : 0; }
  // The signed object as stored (for 1-hop gossip, 04 §4); re-read from
  // storage into `out`.
  Status load_object(ByteBuffer<kRevocationObjectMax>& out) noexcept;
  bool rejects(NodeId node, std::uint32_t generation, std::uint32_t site_epoch) const noexcept {
    return has_set_ && revocation_rejects(set_, node, generation, site_epoch);
  }

 private:
  Status check(ByteView object, const P256PublicKey& sak_pubkey, std::uint64_t site_id,
               NetworkId network, const Es256Verifier& verifier,
               RevocationSet& candidate) noexcept;
  Status store(ByteView object, bool twin, const RevocationSet& candidate) noexcept;

  ByteBuffer<kRevocationSlotBytes> scratch_{};
  SealedSlotPair pair_;
  RevocationSet set_{};
  bool has_set_{false};
};

// --- RLP1: resumption cache (fixed slots, LRU) --------------------------------
// Fixed slot count and fixed key names (05 §3.2), so NVS usage never grows
// with the number of peers. Nothing is cached in RAM: every operation scans
// the slots through one 84-byte buffer, so a 160-slot gateway cache costs
// the same RAM as a 16-slot node cache (C3 gateway sizing floor).
class ResumeSlotStorage {
 public:
  virtual ~ResumeSlotStorage() = default;
  virtual std::size_t slot_count() const noexcept = 0;
  // read() fills 84 bytes (a missing blob reads uniformly erased).
  virtual Status read(std::size_t index, MutableByteView target) noexcept = 0;
  virtual Status write(std::size_t index, ByteView data) noexcept = 0;
};

struct ResumeContext {
  NetworkId network{0};                       // RLS1 network
  std::uint32_t gk_epoch{0};                  // current GK epoch
  const RevocationSet* revocations{nullptr};  // adopted RRS1, if any
};

class ResumeCache {
 public:
  static constexpr std::uint32_t kTouchBootInterval = 256;

  explicit ResumeCache(ResumeSlotStorage& storage) noexcept : storage_(storage) {}

  // 05 §3.2 validity: valid state, CRC, network == context network,
  // created_gk_epoch + 2 > gk_epoch, peer not rejected by the RRS1.
  bool usable(const ResumeSlot& slot, const ResumeContext& context) const noexcept;
  // NotFound when no usable slot for (purpose, peer) exists.
  Status find(ResumePurpose purpose, NodeId peer, const ResumeContext& context,
              ResumeSlot& out, std::size_t& index) noexcept;
  // Written only after a full EDHOC (new RMS). Replaces the peer's slot for
  // the same purpose, else the first empty/unusable slot, else the unpinned
  // slot with the smallest last_used_boot. Pinned slots are capped at
  // slot_count - 2 so a new peer always fits (NoCapacity past the cap).
  Status put(const ResumeSlot& slot, const ResumeContext& context) noexcept;
  // last_used_boot is rewritten only when `boot` moved >= 256 past it or
  // the caller reports a GK epoch change (sleepy-node wear rule).
  Status touch(std::size_t index, std::uint32_t boot, bool gk_epoch_changed) noexcept;
  // RRS1 / REMOVED: overwrite with the empty record (RMS scrubbed).
  Status invalidate_peer(NodeId peer) noexcept;
  Status clear_all() noexcept;

 private:
  Status read_slot(std::size_t index, ResumeSlot& out, bool& intact) noexcept;
  Status write_slot(std::size_t index, const ResumeSlot& slot) noexcept;

  ResumeSlotStorage& storage_;
  std::array<std::uint8_t, kResumeSlotBytes> buffer_{};
};

// --- RLP2: resumption cache with the enforceable 64-use ceiling ----------------
// G-SEC P4 (§6.2): the RLP1 layout cannot express the reboot-surviving use
// count, so RLP2 is a new record (new magic, never a silent redefinition).
// Slots are structurally partitioned by purpose ([0, link_quota) link,
// [link_quota, link_quota + end_quota) end: 12+4 on a node, 32+128 on a
// gateway), so the per-purpose quota needs no runtime accounting. As with
// RLP1 nothing is cached in RAM except the 8-entry use-budget table below:
// every lookup scans NVS through one 96-byte buffer.
class ResumeSlotStorage2 {
 public:
  virtual ~ResumeSlotStorage2() = default;
  virtual std::size_t slot_count() const noexcept = 0;
  // read() fills 96 bytes (a missing blob reads uniformly erased).
  virtual Status read(std::size_t index, MutableByteView target) noexcept = 0;
  virtual Status write(std::size_t index, ByteView data) noexcept = 0;
};

// Purpose quotas (P4 §4.1): 12 link + 4 end on a node, 32 link + 128 end
// on a gateway. tools/nvs_budget.py reads these for the NVS entry model.
constexpr std::size_t kResume2NodeLinkQuota = 12;
constexpr std::size_t kResume2NodeEndQuota = 4;
constexpr std::size_t kResume2GatewayLinkQuota = 32;
constexpr std::size_t kResume2GatewayEndQuota = 128;

class ResumeCache2 {
 public:
  static constexpr std::uint32_t kTouchBootInterval = 256;
  static constexpr std::size_t kUseBudgetEntries = 8;

  ResumeCache2(ResumeSlotStorage2& storage, std::size_t link_quota,
               std::size_t end_quota) noexcept
      : storage_(storage), link_quota_(link_quota), end_quota_(end_quota) {}

  std::size_t link_quota() const noexcept { return link_quota_; }
  std::size_t end_quota() const noexcept { return end_quota_; }

  // Validity: valid state, network == context network, created_gk_epoch <=
  // gk_epoch < created_gk_epoch + 2 (u64 arithmetic: a wrapped or regressed
  // GK fails closed), nonzero generation and role, peer not rejected by the
  // RRS1. The 64-use ceiling is NOT part of validity: it is enforced by
  // reserve_uses, so a fully-reserved slot still verifies its MAC and then
  // falls back to a full EDHOC instead of answering UnknownId.
  bool usable(const ResumeSlot2& slot, const ResumeContext& context) const noexcept;
  // Usable slot for (purpose, peer), if any. Scans the purpose partition.
  Status find_by_peer(ResumePurpose purpose, NodeId peer, const ResumeContext& context,
                      ResumeSlot2& out, std::size_t& index) noexcept;
  // Responder-side lookup by resumption id: slots whose
  // resume_id(rms, purpose) equals `rid`, filtered by purpose/network and —
  // when known — by the carrier-claimed peer, must identify exactly one
  // slot, else NotFound (an rid alone never names a peer).
  Status find_by_id(ResumePurpose purpose, const std::array<std::uint8_t, 8>& rid,
                    NodeId claimed_peer, const ResumeContext& context, ResumeSlot2& out,
                    std::size_t& index) noexcept;
  // Direct slot read. `intact=false` (with an empty slot) on torn/corrupt
  // bytes; a storage error is still an error.
  Status read_at(std::size_t index, ResumeSlot2& out, bool& intact) noexcept;
  // Consume one of the 64 RMS uses. The first use and every 8th grant a new
  // durable quantum (`reserved_uses = min(64, old + 8)`, written and read
  // back) and the RAM budget serves up to 8 uses from it; failed attempts
  // consume a use and never refund it. Exceeded (reserved == 64 and no
  // budget left) or unprovable (torn slot, storage error) returns a
  // non-Ok status and the caller must run a full EDHOC. `boot`/`changed`
  // fold the touch wear rule into the same write (never a second write).
  Status reserve_uses(std::size_t index, const ResumeContext& context, std::uint32_t boot,
                      bool gk_epoch_changed) noexcept;
  // Written only after a full EDHOC (new RMS, reserved_uses starts at 0).
  // Replaces the peer's slot for the same purpose, else the first
  // empty/unusable slot of the purpose partition, else the unpinned slot
  // with the smallest last_used_boot. Pinned slots are capped at
  // quota - 2 per purpose (NoCapacity past the cap).
  Status put(const ResumeSlot2& slot, const ResumeContext& context) noexcept;
  Status touch(std::size_t index, std::uint32_t boot, bool gk_epoch_changed) noexcept;
  Status invalidate_peer(NodeId peer) noexcept;
  Status clear_all() noexcept;

 private:
  struct BudgetEntry {
    bool used{false};
    std::uint32_t slot_index{0};
    // reserved_uses the durable grant left behind: any cache write to this
    // slot changes it (or validity), which invalidates the remainder.
    std::uint32_t granted{0};
    std::uint8_t remaining{0};
  };
  static_assert(sizeof(BudgetEntry) <= 16, "P4 §6.2: use budget entry <= 16 B");

  Status read_slot(std::size_t index, ResumeSlot2& out, bool& intact) noexcept;
  Status write_slot(std::size_t index, const ResumeSlot2& slot) noexcept;
  bool in_partition(ResumePurpose purpose, std::size_t index) const noexcept;
  void drop_budget(std::size_t index) noexcept;

  ResumeSlotStorage2& storage_;
  std::size_t link_quota_{0};
  std::size_t end_quota_{0};
  std::array<std::uint8_t, kResume2SlotBytes> buffer_{};
  std::array<BudgetEntry, kUseBudgetEntries> budget_{};
  std::size_t budget_next_{0};
};

}  // namespace routeloom::sdkv1
