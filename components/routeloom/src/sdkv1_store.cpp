#include "routeloom/sdkv1_store.hpp"

#include <cstring>
#include <limits>

#include "routeloom/crc32.hpp"
#include "routeloom/discovery_scope.hpp"  // sha256
#include "routeloom/secure_clear.hpp"

namespace routeloom::sdkv1 {
namespace {

bool is_erased(const std::uint8_t* data, const std::size_t size) noexcept {
  const std::uint8_t fill = data[0];
  if (fill != 0x00U && fill != 0xFFU) return false;
  for (std::size_t i = 1; i < size; ++i) {
    if (data[i] != fill) return false;
  }
  return true;
}

std::uint32_t be32(const std::uint8_t* p) noexcept {
  return (static_cast<std::uint32_t>(p[0]) << 24U) | (static_cast<std::uint32_t>(p[1]) << 16U) |
         (static_cast<std::uint32_t>(p[2]) << 8U) | static_cast<std::uint32_t>(p[3]);
}

std::uint16_t be16(const std::uint8_t* p) noexcept {
  return static_cast<std::uint16_t>((p[0] << 8U) | p[1]);
}

void put_be32(std::uint8_t* p, const std::uint32_t value) noexcept {
  p[0] = static_cast<std::uint8_t>(value >> 24U);
  p[1] = static_cast<std::uint8_t>(value >> 16U);
  p[2] = static_cast<std::uint8_t>(value >> 8U);
  p[3] = static_cast<std::uint8_t>(value);
}

void reseal(std::uint8_t* record, const std::size_t used_len, const std::uint32_t seal) noexcept {
  put_be32(record + kRecordSealOffset, seal);
  put_be32(record + used_len - 4, crc32_iso_hdlc(ByteView{record, used_len - 4}));
}

Status identity_semantic(const ByteView record, void* context) noexcept {
  return identity_record_decode(record, *static_cast<IdentityRecord*>(context));
}

Status site_semantic(const ByteView record, void* context) noexcept {
  return site_record_decode(record, *static_cast<SiteRecord*>(context));
}

Status revocation_semantic(const ByteView record, void* context) noexcept {
  ByteView object{};
  return revocation_record_decode(record, *static_cast<RevocationSet*>(context), object);
}

const SealedRecordFormat kIdentityFormat{
    kIdentityMagic,     kIdentitySealCommitted, kIdentitySlotBytes, kIdentityRecordMin,
    kIdentityRecordMax, false,                  &identity_record_structure,
    &identity_semantic};

const SealedRecordFormat kSiteFormat{
    kSiteMagic,     kSiteSealCommitted, kSiteSlotBytes,          kSiteRecordMin,
    kSiteRecordMax, true,               &site_record_structure, &site_semantic};

const SealedRecordFormat kRevocationFormat{
    kRevocationMagic,     kRevocationSealCommitted, kRevocationSlotBytes, kRevocationRecordMin,
    kRevocationRecordMax, true,                     &revocation_record_structure,
    &revocation_semantic};

}  // namespace

const SealedRecordFormat& identity_record_format() noexcept { return kIdentityFormat; }
const SealedRecordFormat& site_record_format() noexcept { return kSiteFormat; }
const SealedRecordFormat& revocation_record_format() noexcept { return kRevocationFormat; }

// --- SealedSlotPair ------------------------------------------------------------

SealedSlotPair::SealedSlotPair(RecordSlotStorage& storage, const SealedRecordFormat& format,
                               const MutableByteView scratch, void* decode_context) noexcept
    : storage_(storage), format_(format), scratch_(scratch), decode_context_(decode_context) {}

Status SealedSlotPair::classify(const std::uint8_t slot, SlotContent& content,
                                std::uint32_t& seq, bool& seq_proven,
                                Digest256& digest) noexcept {
  seq = 0;
  seq_proven = false;
  const MutableByteView view{scratch_.data, format_.slot_bytes};
  const Status status = storage_.read(slot, view);
  if (!status) return status;
  const std::uint8_t* raw = scratch_.data;
  if (is_erased(raw, format_.slot_bytes)) {
    content = SlotContent::Empty;
    return Status::success();
  }
  const std::uint32_t magic = be32(raw);
  const std::uint16_t record_format = be16(raw + 4);
  const std::size_t used_len = be16(raw + 6);
  const std::uint32_t schema = be32(raw + 8);
  const std::uint32_t seal = be32(raw + kRecordSealOffset);
  if (magic != format_.magic || record_format != kRecordFormat || used_len < format_.min_len ||
      used_len > format_.max_len) {
    content = SlotContent::Corrupt;
    return Status::success();
  }
  if (seal != format_.seal_committed) {
    // A well-formed pending record never committed: always discardable.
    content = seal == kSealPending ? SlotContent::Pending : SlotContent::Corrupt;
    return Status::success();
  }
  const ByteView record{raw, used_len};
  // Structural gate: a record that fails it is indistinguishable from
  // noise and must not bound the ordinal floor (bitrot could otherwise
  // mint an arbitrary floor).
  if (!format_.structure(record).ok()) {
    content = SlotContent::Corrupt;
    return Status::success();
  }
  if (format_.sequenced) {
    seq = be32(raw + kRecordSeqOffset);
    seq_proven = true;
  }
  if (crc32_iso_hdlc(ByteView{raw, used_len - 4}) != be32(raw + used_len - 4)) {
    content = SlotContent::Corrupt;  // committed fields still bound the floor
    return Status::success();
  }
  if (schema != kRecordSchema) {
    content = SlotContent::Unsupported;
    return Status::success();
  }
  if (!format_.semantic(record, decode_context_).ok()) {
    content = SlotContent::Corrupt;
    return Status::success();
  }
  sha256(record, digest);
  content = SlotContent::Valid;
  return Status::success();
}

Status SealedSlotPair::initialize() noexcept {
  initialized_ = false;
  has_active_ = false;
  quarantined_ = false;
  uncertain_ = false;
  active_seq_ = 0;
  seq_floor_ = 0;
  active_slot_ = 0;
  if (scratch_.data == nullptr || scratch_.size < format_.slot_bytes ||
      format_.structure == nullptr || format_.semantic == nullptr) {
    return Status::error(StatusCode::InvalidArgument, "sealed slot pair setup");
  }
  std::array<SlotContent, kSlots> content{};
  std::array<std::uint32_t, kSlots> seq{};
  std::array<Digest256, kSlots> digest{};
  std::array<bool, kSlots> unreadable{};
  Status read_error = Status::success();
  int valid = 0, corrupt = 0, unsupported = 0;
  for (std::uint8_t slot = 0; slot < kSlots; ++slot) {
    slot_reserved_[slot] = StatusCode::Ok;
    slot_unreadable_[slot] = false;
    bool proven = false;
    const Status status = classify(slot, content[slot], seq[slot], proven, digest[slot]);
    if (!status) {
      unreadable[slot] = true;
      slot_unreadable_[slot] = true;
      if (read_error.ok()) read_error = status;
      continue;
    }
    if (proven && seq[slot] > seq_floor_) seq_floor_ = seq[slot];
    switch (content[slot]) {
      case SlotContent::Valid: ++valid; break;
      case SlotContent::Unsupported:
        ++unsupported;
        slot_reserved_[slot] = StatusCode::Unsupported;
        break;
      case SlotContent::Corrupt: ++corrupt; break;
      default: break;
    }
  }

  const auto quarantine = [&](const StatusCode code, const char* detail) {
    quarantined_ = true;
    initialized_ = true;
    has_active_ = false;
    return Status::error(code, detail);
  };
  const auto provably_absent = [&](const std::uint8_t slot) {
    return !unreadable[slot] &&
           (content[slot] == SlotContent::Empty || content[slot] == SlotContent::Pending);
  };
  const auto adopt = [&](const std::uint8_t slot) {
    active_slot_ = slot;
    active_seq_ = seq[slot];
    has_active_ = true;
    initialized_ = true;
  };

  if (unreadable[0] && unreadable[1]) {
    return read_error.ok() ? Status::error(StatusCode::StorageFailure, "record slots unreadable")
                           : read_error;
  }
  if (valid == 2) {
    if (format_.sequenced && seq[0] != seq[1]) {
      adopt(seq[1] > seq[0] ? 1 : 0);
      return Status::success();
    }
    // Twin mode, or equal sequences: only an identical twin pair is
    // legitimate — different content cannot be ordered.
    if (digest[0] != digest[1]) {
      return quarantine(StatusCode::IntegrityError, "record slots diverge");
    }
    adopt(0);
    return Status::success();
  }
  if (valid == 1) {
    const std::uint8_t slot = content[0] == SlotContent::Valid ? 0 : 1;
    adopt(slot);
    if (!provably_absent(static_cast<std::uint8_t>(slot ^ 1U))) {
      // The lost sibling may have held a newer record: known value only,
      // commits refused until recover().
      uncertain_ = true;
      return Status::error(StatusCode::IntegrityError, "record sibling state unproven");
    }
    return Status::success();
  }
  if (unreadable[0] || unreadable[1]) return read_error;  // retryable storage fault
  if (unsupported > 0) {
    return quarantine(StatusCode::Unsupported, "record schema unsupported");
  }
  if (corrupt > 0) return quarantine(StatusCode::IntegrityError, "record slots corrupt");
  initialized_ = true;  // fresh: empty or pending-only
  return Status::success();
}

Status SealedSlotPair::load_active(ByteView& record) noexcept {
  record = ByteView{};
  if (!has_active_) return Status::error(StatusCode::NotFound, "no active record");
  const Status status =
      storage_.read(active_slot_, MutableByteView{scratch_.data, format_.slot_bytes});
  if (!status) return status;
  const std::size_t used_len = be16(scratch_.data + 6);
  if (used_len < format_.min_len || used_len > format_.max_len) {
    return Status::error(StatusCode::IntegrityError, "active record changed");
  }
  record = ByteView{scratch_.data, used_len};
  return Status::success();
}

Status SealedSlotPair::next_seq(std::uint32_t& seq) const noexcept {
  if (seq_floor_ == std::numeric_limits<std::uint32_t>::max()) {
    return Status::error(StatusCode::RecoveryRequired, "record sequence exhausted");
  }
  seq = seq_floor_ + 1U;
  return Status::success();
}

Status SealedSlotPair::write_slot(const std::uint8_t slot, const std::size_t used_len,
                                  const std::uint32_t seq) noexcept {
  std::uint8_t* record = scratch_.data;
  if (format_.sequenced) put_be32(record + kRecordSeqOffset, seq);
  // Phase 1: the record lands unsealed. A power cut here leaves a pending
  // slot the classifier discards; the committed sibling is untouched.
  reseal(record, used_len, kSealPending);
  Status status = storage_.write(slot, ByteView{record, used_len});
  if (!status) return status;
  // Phase 2: commit marker.
  reseal(record, used_len, format_.seal_committed);
  status = storage_.write(slot, ByteView{record, used_len});
  if (!status) return status;
  // Phase 3: readback. The scratch buffer is the only record-sized RAM, so
  // compare digests: after a match the scratch holds the committed bytes
  // again (the twin path re-uses them for the second slot).
  Digest256 expected{};
  sha256(ByteView{record, used_len}, expected);
  status = storage_.read(slot, MutableByteView{record, format_.slot_bytes});
  if (!status) return status;
  Digest256 actual{};
  sha256(ByteView{record, used_len}, actual);
  if (actual != expected) {
    return Status::error(StatusCode::StorageFailure, "record readback mismatch");
  }
  return Status::success();
}

Status SealedSlotPair::commit_prepared(const std::size_t used_len) noexcept {
  if (!initialized_) return Status::error(StatusCode::InvalidState, "record store not initialized");
  if (quarantined_) return Status::error(StatusCode::IntegrityError, "record store quarantined");
  if (uncertain_) {
    return Status::error(StatusCode::RecoveryRequired, "record store storage uncertain");
  }
  if (used_len < format_.min_len || used_len > format_.max_len) {
    return Status::error(StatusCode::InvalidArgument, "record length");
  }
  if (!format_.sequenced) {
    for (std::uint8_t slot = 0; slot < kSlots; ++slot) {
      if (slot_reserved_[slot] != StatusCode::Ok) {
        return Status::error(slot_reserved_[slot], "record slot owned by other data");
      }
    }
    Status status = write_slot(0, used_len, 0);
    if (status) status = write_slot(1, used_len, 0);
    if (!status) return status;
    active_slot_ = 0;
    has_active_ = true;
    return Status::success();
  }
  const std::uint8_t target = has_active_ ? static_cast<std::uint8_t>(active_slot_ ^ 1U) : 0;
  if (slot_reserved_[target] != StatusCode::Ok) {
    return Status::error(slot_reserved_[target], "record slot owned by other data");
  }
  std::uint32_t seq = 0;
  Status status = next_seq(seq);
  if (status) status = write_slot(target, used_len, seq);
  if (!status) return status;
  active_slot_ = target;
  active_seq_ = seq;
  seq_floor_ = seq;
  has_active_ = true;
  return Status::success();
}

Status SealedSlotPair::commit_twin_prepared(const std::size_t used_len) noexcept {
  if (!initialized_) return Status::error(StatusCode::InvalidState, "record store not initialized");
  if (used_len < format_.min_len || used_len > format_.max_len) {
    return Status::error(StatusCode::InvalidArgument, "record length");
  }
  std::uint32_t seq = 0;
  if (format_.sequenced) {
    const Status status = next_seq(seq);
    if (!status) return status;
  }
  // Slot 0 first, then slot 1, same bytes. A cut between them leaves the
  // new record (higher sequence) valid in slot 0 and the old or a pending
  // record in slot 1 — the classifier adopts the new one.
  Status status = write_slot(0, used_len, seq);
  if (!status) return status;
  if (format_.sequenced) seq_floor_ = seq;
  status = write_slot(1, used_len, seq);
  if (!status) return status;
  slot_reserved_[0] = StatusCode::Ok;
  slot_reserved_[1] = StatusCode::Ok;
  active_slot_ = 0;
  active_seq_ = seq;
  has_active_ = true;
  quarantined_ = false;
  uncertain_ = false;
  return Status::success();
}

// --- IdentityStore ---------------------------------------------------------------

IdentityStore::IdentityStore(RecordSlotStorage& storage) noexcept
    : pair_(storage, kIdentityFormat, scratch_.writable(), &identity_) {}

Status IdentityStore::initialize() noexcept {
  const Status status = pair_.initialize();
  identity_ = IdentityRecord{};
  if (pair_.has_active()) {
    ByteView record{};
    Status loaded = pair_.load_active(record);
    if (loaded) loaded = identity_record_decode(record, identity_);
    if (!loaded) return loaded;
  }
  return status;
}

Status IdentityStore::encode(const IdentityRecord& record, std::size_t& used_len) noexcept {
  used_len = 0;
  const Status status = identity_record_encode(record, kSealPending, scratch_);
  if (!status) return status;
  used_len = scratch_.size;
  return Status::success();
}

Status IdentityStore::commit(const IdentityRecord& record) noexcept {
  if (!pair_.initialized()) {
    return Status::error(StatusCode::InvalidState, "identity store not initialized");
  }
  std::size_t used_len = 0;
  Status status = encode(record, used_len);
  if (status) status = pair_.commit_prepared(used_len);
  if (!status) return status;
  identity_ = record;
  return Status::success();
}

Status IdentityStore::recover(const IdentityRecord& record) noexcept {
  if (!pair_.quarantined() && !pair_.uncertain()) {
    return Status::error(StatusCode::InvalidState, "identity store not impaired");
  }
  std::size_t used_len = 0;
  Status status = encode(record, used_len);
  if (status) status = pair_.commit_twin_prepared(used_len);
  if (!status) return status;
  identity_ = record;
  return Status::success();
}

// --- SiteStore -------------------------------------------------------------------

SiteStore::SiteStore(RecordSlotStorage& storage) noexcept
    : pair_(storage, kSiteFormat, scratch_.writable(), &site_) {}

void SiteStore::wipe_scratch() noexcept {
  secure_clear(scratch_.bytes);
  scratch_.size = 0;
}

Status SiteStore::initialize() noexcept {
  active_load_failed_ = false;
  const Status status = pair_.initialize();
  site_ = SiteRecord{};
  if (pair_.has_active()) {
    ByteView record{};
    Status loaded = pair_.load_active(record);
    if (loaded) loaded = site_record_decode(record, site_);
    if (!loaded) {
      active_load_failed_ = true;
      site_ = SiteRecord{};
      wipe_scratch();
      return loaded;
    }
  }
  wipe_scratch();
  return status;
}

SiteStoreHealth SiteStore::health() const noexcept {
  SiteStoreHealth health{};
  health.initialized = pair_.initialized();
  health.has_site = has_site();
  health.quarantined = pair_.quarantined();
  health.uncertain = pair_.uncertain();
  health.active_load_failed = active_load_failed_;
  for (std::uint8_t slot = 0; slot < SealedSlotPair::kSlots; ++slot) {
    if (pair_.slot_unsupported(slot)) {
      health.unsupported_mask |= static_cast<std::uint8_t>(1U << slot);
    }
    if (pair_.slot_unreadable(slot)) {
      health.read_error_mask |= static_cast<std::uint8_t>(1U << slot);
    }
  }
  health.seq_floor = pair_.seq_floor();
  return health;
}

Status SiteStore::fingerprint(const SiteRecord& record, Digest256& out) noexcept {
  out.fill(0);
  std::size_t used_len = 0;
  const Status status = encode(record, used_len);
  if (status) sha256(ByteView{scratch_.bytes.data(), used_len}, out);
  wipe_scratch();
  return status;
}

Status SiteStore::encode(const SiteRecord& record, std::size_t& used_len) noexcept {
  used_len = 0;
  const Status status = site_record_encode(record, kSealPending, 0, scratch_);
  if (!status) return status;
  used_len = scratch_.size;
  return Status::success();
}

Status SiteStore::commit(const SiteRecord& record) noexcept {
  if (!pair_.initialized()) {
    return Status::error(StatusCode::InvalidState, "site store not initialized");
  }
  if (active_load_failed_) {
    return Status::error(StatusCode::StorageFailure, "site active record unreadable");
  }
  if (record.state != SiteState::Member) {
    return Status::error(StatusCode::InvalidArgument, "site commit needs a member record");
  }
  if (has_site()) {
    const SiteRecord& current = site_;
    const std::uint32_t old_epoch = static_cast<std::uint32_t>(current.network >> 32U);
    const std::uint32_t new_epoch = static_cast<std::uint32_t>(record.network >> 32U);
    if (record.site_id != current.site_id) {
      return Status::error(StatusCode::Conflict, "site changed without removal");
    }
    if (new_epoch < old_epoch || (new_epoch == old_epoch && record.network != current.network)) {
      return Status::error(StatusCode::Conflict, "site epoch regressed");
    }
    if (record.assignment_generation < current.assignment_generation ||
        record.gk_epoch_current < current.gk_epoch_current ||
        record.rs_epoch_floor < current.rs_epoch_floor ||
        record.boot_witness < current.boot_witness) {
      return Status::error(StatusCode::Conflict, "site record regressed");
    }
  }
  std::size_t used_len = 0;
  Status status = encode(record, used_len);
  if (status) status = pair_.commit_prepared(used_len);
  wipe_scratch();
  if (!status) return status;
  site_ = record;
  return Status::success();
}

Status SiteStore::clear() noexcept {
  const SiteRecord tombstone{};
  std::size_t used_len = 0;
  Status status = encode(tombstone, used_len);
  if (status) status = pair_.commit_twin_prepared(used_len);
  wipe_scratch();
  if (!status) return status;
  site_ = tombstone;
  return Status::success();
}

Status SiteStore::recover(const SiteRecord& record) noexcept {
  if (active_load_failed_) {
    return Status::error(StatusCode::StorageFailure, "site active record unreadable");
  }
  if (!pair_.quarantined() && !pair_.uncertain()) {
    return Status::error(StatusCode::InvalidState, "site store not impaired");
  }
  if (record.state != SiteState::Member) {
    return Status::error(StatusCode::InvalidArgument, "site recover needs a member record");
  }
  std::size_t used_len = 0;
  Status status = encode(record, used_len);
  if (status) status = pair_.commit_twin_prepared(used_len);
  wipe_scratch();
  if (!status) return status;
  site_ = record;
  return Status::success();
}

// --- RevocationStore -------------------------------------------------------------

RevocationStore::RevocationStore(RecordSlotStorage& storage) noexcept
    : pair_(storage, kRevocationFormat, scratch_.writable(), &set_) {}

Status RevocationStore::initialize() noexcept {
  const Status status = pair_.initialize();
  set_ = RevocationSet{};
  has_set_ = false;
  if (pair_.has_active()) {
    ByteView record{}, object{};
    Status loaded = pair_.load_active(record);
    if (loaded) loaded = revocation_record_decode(record, set_, object);
    if (!loaded) return loaded;
    has_set_ = object.size > 0;
  }
  return status;
}

Status RevocationStore::check(const ByteView object, const P256PublicKey& sak_pubkey,
                              const std::uint64_t site_id, const NetworkId network,
                              const Es256Verifier& verifier, RevocationSet& candidate) noexcept {
  bool verified = false;
  const Status status =
      revocation_object_verify(object, sak_pubkey, site_id, network, candidate, verified, verifier);
  if (!status) return status;
  if (!verified) {
    return Status::error(StatusCode::AuthorizationFailed, "revocation set not authentic");
  }
  return Status::success();
}

Status RevocationStore::store(const ByteView object, const bool twin,
                              const RevocationSet& candidate) noexcept {
  Status status = revocation_record_encode(object, kSealPending, 0, scratch_);
  if (status) {
    status = twin ? pair_.commit_twin_prepared(scratch_.size)
                  : pair_.commit_prepared(scratch_.size);
  }
  if (!status) return status;
  set_ = candidate;
  has_set_ = object.size > 0;
  return Status::success();
}

Status RevocationStore::accept(const ByteView object, const P256PublicKey& sak_pubkey,
                               const std::uint64_t site_id, const NetworkId network,
                               const Es256Verifier& verifier) noexcept {
  if (!pair_.initialized()) {
    return Status::error(StatusCode::InvalidState, "revocation store not initialized");
  }
  if (pair_.quarantined()) {
    return Status::error(StatusCode::IntegrityError, "revocation store quarantined");
  }
  if (pair_.uncertain()) {
    return Status::error(StatusCode::RecoveryRequired, "revocation store storage uncertain");
  }
  RevocationSet candidate{};
  const Status checked = check(object, sak_pubkey, site_id, network, verifier, candidate);
  if (!checked) return checked;
  if (has_set_ && set_.site_id == candidate.site_id) {
    // Complete replacement ordered by rs_epoch; the floor never regresses.
    if (candidate.rs_epoch <= set_.rs_epoch) {
      return Status::error(StatusCode::Conflict, "revocation epoch not newer");
    }
    if (candidate.site_epoch_floor < set_.site_epoch_floor) {
      return Status::error(StatusCode::Conflict, "revocation floor regressed");
    }
  }
  return store(object, false, candidate);
}

Status RevocationStore::clear() noexcept {
  const Status status = store(ByteView{}, true, RevocationSet{});
  if (!status) return status;
  has_set_ = false;
  return Status::success();
}

Status RevocationStore::recover(const ByteView object, const P256PublicKey& sak_pubkey,
                                const std::uint64_t site_id, const NetworkId network,
                                const Es256Verifier& verifier) noexcept {
  if (!pair_.quarantined() && !pair_.uncertain()) {
    return Status::error(StatusCode::InvalidState, "revocation store not impaired");
  }
  RevocationSet candidate{};
  const Status checked = check(object, sak_pubkey, site_id, network, verifier, candidate);
  if (!checked) return checked;
  if (has_set_ && set_.site_id == candidate.site_id &&
      (candidate.rs_epoch < set_.rs_epoch ||
       candidate.site_epoch_floor < set_.site_epoch_floor)) {
    return Status::error(StatusCode::Conflict, "revocation recovery regressed");
  }
  return store(object, true, candidate);
}

Status RevocationStore::load_object(ByteBuffer<kRevocationObjectMax>& out) noexcept {
  out.clear();
  if (!has_set_) return Status::error(StatusCode::NotFound, "no revocation set");
  ByteView record{}, object{};
  RevocationSet scratch_set{};
  Status status = pair_.load_active(record);
  if (status) status = revocation_record_decode(record, scratch_set, object);
  if (!status) return status;
  if (object.size == 0 || object.size > out.bytes.size()) {
    return Status::error(StatusCode::IntegrityError, "revocation object missing");
  }
  std::memcpy(out.bytes.data(), object.data, object.size);
  out.size = object.size;
  return Status::success();
}

// --- ResumeCache -----------------------------------------------------------------

Status ResumeCache::read_slot(const std::size_t index, ResumeSlot& out, bool& intact) noexcept {
  out = ResumeSlot{};
  intact = true;
  const Status status = storage_.read(index, MutableByteView{buffer_.data(), buffer_.size()});
  if (!status) return status;
  if (is_erased(buffer_.data(), buffer_.size())) return Status::success();
  if (!resume_slot_decode(ByteView{buffer_.data(), buffer_.size()}, out).ok()) {
    // Torn or corrupt: treated as empty (the consequence is one full
    // EDHOC), never as a usable secret.
    out = ResumeSlot{};
    intact = false;
  }
  return Status::success();
}

Status ResumeCache::write_slot(const std::size_t index, const ResumeSlot& slot) noexcept {
  Status status = resume_slot_encode(slot, buffer_);
  if (status) status = storage_.write(index, ByteView{buffer_.data(), buffer_.size()});
  if (!status) return status;
  std::array<std::uint8_t, kResumeSlotBytes> expected = buffer_;
  status = storage_.read(index, MutableByteView{buffer_.data(), buffer_.size()});
  if (!status) return status;
  if (buffer_ != expected) {
    return Status::error(StatusCode::StorageFailure, "resume slot readback mismatch");
  }
  return Status::success();
}

bool ResumeCache::usable(const ResumeSlot& slot, const ResumeContext& context) const noexcept {
  if (!slot.valid || slot.network != context.network) return false;
  if (static_cast<std::uint64_t>(slot.created_gk_epoch) + 2U <= context.gk_epoch) return false;
  if (context.revocations != nullptr &&
      revocation_rejects(*context.revocations, slot.peer, slot.peer_generation,
                         static_cast<std::uint32_t>(slot.network >> 32U))) {
    return false;
  }
  return true;
}

Status ResumeCache::find(const ResumePurpose purpose, const NodeId peer,
                         const ResumeContext& context, ResumeSlot& out,
                         std::size_t& index) noexcept {
  out = ResumeSlot{};
  index = 0;
  const std::size_t count = storage_.slot_count();
  for (std::size_t i = 0; i < count; ++i) {
    ResumeSlot slot{};
    bool intact = true;
    const Status status = read_slot(i, slot, intact);
    if (!status) return status;
    if (slot.valid && slot.purpose == purpose && slot.peer == peer && usable(slot, context)) {
      out = slot;
      index = i;
      return Status::success();
    }
  }
  return Status::error(StatusCode::NotFound, "no resumption slot");
}

Status ResumeCache::put(const ResumeSlot& slot, const ResumeContext& context) noexcept {
  if (!slot.valid) return Status::error(StatusCode::InvalidArgument, "resume slot not valid");
  const Status valid = resume_validate(slot);
  if (!valid) return valid;
  const std::size_t count = storage_.slot_count();
  if (count < 3) return Status::error(StatusCode::InvalidState, "resume cache too small");
  constexpr std::size_t kNone = std::numeric_limits<std::size_t>::max();
  std::size_t same = kNone, free_slot = kNone, lru = kNone;
  std::uint32_t lru_boot = 0;
  std::size_t pinned = 0;
  for (std::size_t i = 0; i < count; ++i) {
    ResumeSlot current{};
    bool intact = true;
    const Status status = read_slot(i, current, intact);
    if (!status) return status;
    const bool live = usable(current, context);
    if (current.valid && current.purpose == slot.purpose && current.peer == slot.peer) {
      if (same == kNone) same = i;
      continue;  // replaced below; its pin does not count
    }
    if (!live) {
      if (free_slot == kNone) free_slot = i;
      continue;
    }
    if ((current.flags & kResumeFlagPinned) != 0) {
      ++pinned;
      continue;
    }
    if (lru == kNone || current.last_used_boot < lru_boot) {
      lru = i;
      lru_boot = current.last_used_boot;
    }
  }
  if ((slot.flags & kResumeFlagPinned) != 0 && pinned + 1 > count - 2) {
    return Status::error(StatusCode::NoCapacity, "resume pin budget");
  }
  const std::size_t target = same != kNone ? same : (free_slot != kNone ? free_slot : lru);
  if (target == kNone) return Status::error(StatusCode::NoCapacity, "resume cache full");
  return write_slot(target, slot);
}

Status ResumeCache::touch(const std::size_t index, const std::uint32_t boot,
                          const bool gk_epoch_changed) noexcept {
  if (index >= storage_.slot_count()) {
    return Status::error(StatusCode::InvalidArgument, "resume slot index");
  }
  ResumeSlot slot{};
  bool intact = true;
  const Status status = read_slot(index, slot, intact);
  if (!status) return status;
  if (!slot.valid) return Status::error(StatusCode::NotFound, "resume slot empty");
  if (!gk_epoch_changed && boot - slot.last_used_boot < kTouchBootInterval) {
    return Status::success();  // wear rule: no write
  }
  slot.last_used_boot = boot;
  return write_slot(index, slot);
}

Status ResumeCache::invalidate_peer(const NodeId peer) noexcept {
  const std::size_t count = storage_.slot_count();
  for (std::size_t i = 0; i < count; ++i) {
    ResumeSlot slot{};
    bool intact = true;
    Status status = read_slot(i, slot, intact);
    if (!status) return status;
    if (slot.valid && slot.peer == peer) {
      status = write_slot(i, ResumeSlot{});
      if (!status) return status;
    }
  }
  return Status::success();
}

Status ResumeCache::clear_all() noexcept {
  const std::size_t count = storage_.slot_count();
  for (std::size_t i = 0; i < count; ++i) {
    ResumeSlot slot{};
    bool intact = true;
    Status status = read_slot(i, slot, intact);
    if (!status) return status;
    const bool erased_empty = !slot.valid && intact;
    if (!erased_empty) {
      // Valid or torn: overwrite so no RMS fragment survives.
      status = write_slot(i, ResumeSlot{});
      if (!status) return status;
    }
  }
  return Status::success();
}

}  // namespace routeloom::sdkv1
