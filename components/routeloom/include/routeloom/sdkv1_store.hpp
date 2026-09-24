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
  // Per-slot classification of the last initialize(): unknown schemas and
  // unreadable slots, so the caller can tell "known-impaired" (explicit
  // recovery allowed) from "unknown" (never recovered over) without
  // comparing Status details.
  bool slot_unsupported(std::uint8_t slot) const noexcept {
    return slot < kSlots && slot_reserved_[slot] == StatusCode::Unsupported;
  }
  bool slot_unreadable(std::uint8_t slot) const noexcept {
    return slot < kSlots && slot_unreadable_[slot];
  }
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
  std::array<bool, kSlots> slot_unreadable_{};
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

// --- RLI1: device identity (office-written, twin pair) -------------------------
class IdentityStore {
 public:
  explicit IdentityStore(RecordSlotStorage& storage) noexcept;
  Status initialize() noexcept;
  Status commit(const IdentityRecord& record) noexcept;
  Status recover(const IdentityRecord& record) noexcept;

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
// Read-only health of the last initialize(): enough to classify the boot
// and reconcile paths (design P3-4 §7.2) without string-matching Status.
struct SiteStoreHealth {
  bool initialized{false};
  bool has_site{false};
  bool quarantined{false};
  bool uncertain{false};
  std::uint8_t unsupported_mask{0};  // bit i: slot i holds an unknown schema
  std::uint8_t read_error_mask{0};   // bit i: slot i was unreadable
  bool active_load_failed{false};    // adopted slot could not be re-read/decoded
  std::uint32_t seq_floor{0};
};

class SiteStore {
 public:
  explicit SiteStore(RecordSlotStorage& storage) noexcept;
  Status initialize() noexcept;
  SiteStoreHealth health() const noexcept;
  // Stable digest of the canonical semantic record (sequence/seal excluded).
  // Uses this store's scratch buffer; it never reads or writes flash.
  Status fingerprint(const SiteRecord& record, Digest256& out) noexcept;

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

  bool has_site() const noexcept {
    return pair_.has_active() && site_.state == SiteState::Member;
  }
  bool quarantined() const noexcept { return pair_.quarantined(); }
  bool uncertain() const noexcept { return pair_.uncertain(); }
  std::uint32_t commit_seq() const noexcept { return pair_.active_seq(); }
  const SiteRecord& site() const noexcept { return site_; }

 private:
  Status encode(const SiteRecord& record, std::size_t& used_len) noexcept;
  void wipe_scratch() noexcept;

  ByteBuffer<kSiteSlotBytes> scratch_{};
  SealedSlotPair pair_;
  SiteRecord site_{};
  bool active_load_failed_{false};
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

}  // namespace routeloom::sdkv1
