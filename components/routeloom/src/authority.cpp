#include "routeloom/authority.hpp"

#include <cstring>

#include "routeloom/byte_io.hpp"
#include "routeloom/crc32.hpp"

namespace routeloom {
namespace {

// Ledger record byte layout (big-endian via ByteWriter, 156 bytes):
//   0   u32  magic "RLA1"
//   4   u16  format version (1)
//   6   u16  record length (156)
//   8   u32  schema_version (kAuthorityLedgerSchemaVersion)
//   12  u32  commit seal (kSealPending while writing, kSealCommitted when active)
//   16  u64  revision (monotonic ledger index)
//   24  u64  network
//   32  u64  authority
//   40  u32  generation
//   44  u32  reserved
//   48  u64  applied_sequence
//   56  32B  state_hash
//   88  32B  previous_state_hash (hash chain to the superseded record)
//   120 32B  operation_hash
//   152 u32  crc32_iso_hdlc over bytes [0,152)
constexpr std::uint32_t kLedgerMagic = 0x524C4131U;
constexpr std::uint16_t kLedgerFormat = 1;
constexpr std::uint32_t kSealPending = 0U;
constexpr std::uint32_t kSealCommitted = 0x5A3CC3A5U;
constexpr std::size_t kCrcOffset = kAuthorityLedgerRecordSize - 4;

enum class SlotContent : std::uint8_t {
  Empty,        // uniform erased bytes; never written
  Pending,      // well-formed record never sealed; safe to discard
  Corrupt,      // non-erased bytes that fail structural checks
  Unsupported,  // intact record from a different schema_version
  Foreign,      // intact record owned by a different network/authority
  Valid,
};

struct ParsedRecord {
  std::uint64_t revision{0};
  AuthorityRecord state{};
  Digest256 previous_state_hash{};
  Digest256 operation_hash{};
};

bool is_erased(const std::uint8_t* data, const std::size_t size) noexcept {
  const std::uint8_t fill = data[0];
  if (fill != 0x00U && fill != 0xFFU) return false;
  for (std::size_t i = 1; i < size; ++i) {
    if (data[i] != fill) return false;
  }
  return true;
}

Status encode_record(const ParsedRecord& record, const std::uint32_t seal,
                     const MutableByteView target) noexcept {
  ByteWriter writer(target);
  Status status = writer.write_u32(kLedgerMagic);
  if (status) status = writer.write_u16(kLedgerFormat);
  if (status) status = writer.write_u16(static_cast<std::uint16_t>(kAuthorityLedgerRecordSize));
  if (status) status = writer.write_u32(kAuthorityLedgerSchemaVersion);
  if (status) status = writer.write_u32(seal);
  if (status) status = writer.write_u64(record.revision);
  if (status) status = writer.write_u64(record.state.network);
  if (status) status = writer.write_u64(record.state.authority);
  if (status) status = writer.write_u32(record.state.generation);
  if (status) status = writer.write_u32(0);
  if (status) status = writer.write_u64(record.state.applied_sequence);
  if (status) status = writer.write_bytes(ByteView{record.state.state_hash.data(), 32});
  if (status) status = writer.write_bytes(ByteView{record.previous_state_hash.data(), 32});
  if (status) status = writer.write_bytes(ByteView{record.operation_hash.data(), 32});
  if (!status) return status;
  return writer.write_u32(crc32_iso_hdlc(ByteView{target.data, kCrcOffset}));
}

SlotContent decode_record(const ByteView raw, const NetworkId network,
                          const NodeId authority, ParsedRecord& parsed) noexcept {
  if (raw.data == nullptr || raw.size != kAuthorityLedgerRecordSize) {
    return SlotContent::Corrupt;
  }
  if (is_erased(raw.data, raw.size)) return SlotContent::Empty;
  ByteReader reader(raw);
  std::uint32_t magic = 0, schema = 0, seal = 0, reserved = 0, crc = 0;
  std::uint16_t format = 0, length = 0;
  Status status = reader.read_u32(magic);
  if (status) status = reader.read_u16(format);
  if (status) status = reader.read_u16(length);
  if (status) status = reader.read_u32(schema);
  if (status) status = reader.read_u32(seal);
  if (!status || magic != kLedgerMagic || format != kLedgerFormat ||
      length != kAuthorityLedgerRecordSize) {
    return SlotContent::Corrupt;
  }
  // A well-formed pending record was never committed, so discarding it is
  // always safe even if the rest of the slot was torn mid-write.
  if (seal == kSealPending) return SlotContent::Pending;
  if (seal != kSealCommitted) return SlotContent::Corrupt;
  if (status) status = reader.read_u64(parsed.revision);
  if (status) status = reader.read_u64(parsed.state.network);
  if (status) status = reader.read_u64(parsed.state.authority);
  if (status) status = reader.read_u32(parsed.state.generation);
  if (status) status = reader.read_u32(reserved);
  if (status) status = reader.read_u64(parsed.state.applied_sequence);
  if (status) status = reader.read_bytes(MutableByteView{parsed.state.state_hash.data(), 32});
  if (status) status = reader.read_bytes(MutableByteView{parsed.previous_state_hash.data(), 32});
  if (status) status = reader.read_bytes(MutableByteView{parsed.operation_hash.data(), 32});
  if (status) status = reader.read_u32(crc);
  if (!status || crc32_iso_hdlc(ByteView{raw.data, kCrcOffset}) != crc) {
    return SlotContent::Corrupt;
  }
  if (schema != kAuthorityLedgerSchemaVersion) return SlotContent::Unsupported;
  if (parsed.state.network != network || parsed.state.authority != authority) {
    return SlotContent::Foreign;
  }
  return SlotContent::Valid;
}

}  // namespace

Digest256 bind_operation_payload(const AuthorityOperationKind kind,
                                 const ByteView payload) noexcept {
  Digest256 out{};
  std::uint64_t lanes[4] = {0x9E3779B97F4A7C15ULL ^ (static_cast<std::uint8_t>(kind) + 1U),
                            0x243F6A8885A308D3ULL, 0x452821E638D01377ULL,
                            0xBF58476D1CE4E5B9ULL};
  for (std::size_t i = 0; i < payload.size; ++i) {
    std::uint64_t& lane = lanes[i % 4];
    lane ^= payload.data[i];
    lane *= 0x100000001B3ULL;
    lane ^= lane >> 29U;
  }
  for (int lane = 0; lane < 4; ++lane) {
    for (int byte = 0; byte < 8; ++byte) {
      out[lane * 8 + byte] = static_cast<std::uint8_t>(lanes[lane] >> (56 - byte * 8));
    }
  }
  return out;
}

SingleAuthority::SingleAuthority(const NetworkId network, const NodeId authority,
                                 LedgerStorage& storage) noexcept
    : network_(network), authority_(authority), storage_(storage) {}

Status SingleAuthority::initialize() noexcept {
  if (network_ == 0 || authority_ == kInvalidNodeId || authority_ == kBroadcastNodeId) {
    return Status::error(StatusCode::InvalidArgument, "invalid authority identity");
  }
  std::array<ParsedRecord, kAuthorityLedgerSlots> parsed{};
  std::array<SlotContent, kAuthorityLedgerSlots> content{};
  std::array<bool, kAuthorityLedgerSlots> unreadable{};
  Status read_error = Status::success();
  int valid = 0, foreign = 0, unsupported = 0, corrupt = 0;
  for (std::uint8_t slot = 0; slot < kAuthorityLedgerSlots; ++slot) {
    slot_reserved_[slot] = StatusCode::Ok;
    std::array<std::uint8_t, kAuthorityLedgerRecordSize> raw{};
    const Status status = storage_.read(slot, MutableByteView{raw.data(), raw.size()});
    if (!status) {
      unreadable[slot] = true;
      if (read_error.ok()) read_error = status;
      continue;
    }
    content[slot] =
        decode_record(ByteView{raw.data(), raw.size()}, network_, authority_, parsed[slot]);
    switch (content[slot]) {
      case SlotContent::Valid:
        ++valid;
        if (parsed[slot].revision > recovery_floor_) {
          recovery_floor_ = parsed[slot].revision;
        }
        if (parsed[slot].state.generation > max_generation_seen_) {
          max_generation_seen_ = parsed[slot].state.generation;
        }
        break;
      case SlotContent::Foreign:
        ++foreign;
        slot_reserved_[slot] = StatusCode::Conflict;
        break;
      case SlotContent::Unsupported:
        ++unsupported;
        slot_reserved_[slot] = StatusCode::Unsupported;
        // The record is CRC-intact, so its revision and generation are still
        // trustworthy bounds even though the schema itself is unreadable.
        if (parsed[slot].revision > recovery_floor_) {
          recovery_floor_ = parsed[slot].revision;
        }
        if (parsed[slot].state.generation > max_generation_seen_) {
          max_generation_seen_ = parsed[slot].state.generation;
        }
        break;
      case SlotContent::Corrupt:
        ++corrupt;
        break;
      default:
        break;
    }
  }

  auto quarantine = [&](const StatusCode code, const char* detail) {
    quarantined_ = true;
    initialized_ = true;
    has_active_ = false;
    state_ = AuthorityRecord{network_, authority_, 1, 0, Digest256{}};
    revision_ = recovery_floor_;
    return Status::error(code, detail);
  };

  if (valid == 2) {
    const std::uint8_t newer = parsed[1].revision >= parsed[0].revision ? 1 : 0;
    const std::uint8_t older = static_cast<std::uint8_t>(newer ^ 1U);
    bool consistent =
        parsed[newer].revision == parsed[older].revision + 1U &&
        parsed[newer].previous_state_hash == parsed[older].state.state_hash;
    if (!consistent && parsed[newer].revision == parsed[older].revision) {
      consistent =
          parsed[newer].state.applied_sequence == parsed[older].state.applied_sequence &&
          parsed[newer].state.state_hash == parsed[older].state.state_hash &&
          parsed[newer].state.generation == parsed[older].state.generation &&
          parsed[newer].previous_state_hash == parsed[older].previous_state_hash &&
          parsed[newer].operation_hash == parsed[older].operation_hash;
    }
    if (!consistent) {
      return quarantine(StatusCode::IntegrityError, "authority ledger chain inconsistent");
    }
    state_ = parsed[newer].state;
    revision_ = parsed[newer].revision;
    active_slot_ = newer;
    has_active_ = true;
  } else if (unreadable[0] || unreadable[1]) {
    // A slot that cannot be read might still hold a committed record newer
    // than a readable sibling, so booting the stale record is unsafe — and a
    // later commit could clobber the unreadable slot's possibly-newer data.
    return read_error.ok() ? Status::error(StatusCode::StorageFailure, "authority ledger unreadable")
                           : read_error;
  } else if (valid == 1) {
    const std::uint8_t slot = content[0] == SlotContent::Valid ? 0 : 1;
    state_ = parsed[slot].state;
    revision_ = parsed[slot].revision;
    active_slot_ = slot;
    has_active_ = true;
  } else if (foreign > 0) {
    return Status::error(StatusCode::Conflict, "authority ledger identity mismatch");
  } else if (unsupported > 0) {
    return quarantine(StatusCode::Unsupported, "authority ledger schema unsupported");
  } else if (corrupt > 0) {
    return quarantine(StatusCode::IntegrityError, "authority ledger corrupt");
  } else {
    state_ = AuthorityRecord{network_, authority_, 1, 0, Digest256{}};
    revision_ = 0;
    has_active_ = false;
  }
  initialized_ = true;
  return Status::success();
}

Status SingleAuthority::validate(const AuthorityOperation& operation,
                                 const bool cryptographic_signature_verified) const noexcept {
  if (!initialized_) return Status::error(StatusCode::InvalidState, "authority not initialized");
  if (quarantined_) return Status::error(StatusCode::IntegrityError, "authority ledger quarantined");
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
  if (operation.previous_state_hash != state_.state_hash) {
    return Status::error(StatusCode::Conflict, "authority previous-state hash mismatch");
  }
  return Status::success();
}

Status SingleAuthority::store_record(const std::uint8_t slot, const AuthorityRecord& record,
                                     const std::uint64_t revision,
                                     const Digest256& previous_state_hash,
                                     const Digest256& operation_hash) noexcept {
  const ParsedRecord parsed{revision, record, previous_state_hash, operation_hash};
  std::array<std::uint8_t, kAuthorityLedgerRecordSize> buffer{};
  const MutableByteView target{buffer.data(), buffer.size()};
  // Phase 1: land the record body unsealed. A power cut here leaves a pending
  // slot that recovery ignores, so the previous committed state survives.
  Status status = encode_record(parsed, kSealPending, target);
  if (!status) return status;
  status = storage_.write(slot, ByteView{buffer.data(), buffer.size()});
  if (!status) return status;
  // Phase 2: commit marker. The record is never used as active state before
  // this seal lands and the readback verifies.
  status = encode_record(parsed, kSealCommitted, target);
  if (!status) return status;
  status = storage_.write(slot, ByteView{buffer.data(), buffer.size()});
  if (!status) return status;
  std::array<std::uint8_t, kAuthorityLedgerRecordSize> verify{};
  status = storage_.read(slot, MutableByteView{verify.data(), verify.size()});
  if (!status) return status;
  if (std::memcmp(verify.data(), buffer.data(), buffer.size()) != 0) {
    return Status::error(StatusCode::StorageFailure, "authority ledger readback mismatch");
  }
  return Status::success();
}

Status SingleAuthority::commit(const AuthorityOperation& operation,
                               const Digest256& resulting_state_hash,
                               const bool cryptographic_signature_verified) noexcept {
  const Status status = validate(operation, cryptographic_signature_verified);
  if (!status) return status;
  const std::uint8_t target =
      has_active_ ? static_cast<std::uint8_t>(active_slot_ ^ 1U) : 0;
  if (slot_reserved_[target] != StatusCode::Ok) {
    return Status::error(slot_reserved_[target], "authority ledger slot owned by other data");
  }
  AuthorityRecord next = state_;
  next.applied_sequence = operation.sequence;
  next.state_hash = resulting_state_hash;
  const Status stored =
      store_record(target, next, revision_ + 1U, state_.state_hash, operation.operation_hash);
  if (!stored) return stored;
  state_ = next;
  ++revision_;
  active_slot_ = target;
  has_active_ = true;
  return Status::success();
}

Status SingleAuthority::commit_typed(const AuthorityOperationKind expected,
                                     const AuthorityOperation& operation,
                                     const Digest256& resulting_state_hash,
                                     const bool cryptographic_signature_verified) noexcept {
  if (operation.kind != expected) {
    return Status::error(StatusCode::InvalidArgument, "authority operation kind mismatch");
  }
  return commit(operation, resulting_state_hash, cryptographic_signature_verified);
}

Status SingleAuthority::apply_remote_config(const AuthorityOperation& operation,
                                            const Digest256& resulting_state_hash,
                                            const bool cryptographic_signature_verified) noexcept {
  return commit_typed(AuthorityOperationKind::RemoteConfig, operation, resulting_state_hash,
                      cryptographic_signature_verified);
}

Status SingleAuthority::apply_membership_approval(
    const AuthorityOperation& operation, const Digest256& resulting_state_hash,
    const bool cryptographic_signature_verified) noexcept {
  return commit_typed(AuthorityOperationKind::MembershipApproval, operation, resulting_state_hash,
                      cryptographic_signature_verified);
}

Status SingleAuthority::apply_membership_revocation(
    const AuthorityOperation& operation, const Digest256& resulting_state_hash,
    const bool cryptographic_signature_verified) noexcept {
  return commit_typed(AuthorityOperationKind::MembershipRevocation, operation,
                      resulting_state_hash, cryptographic_signature_verified);
}

Status SingleAuthority::recover() noexcept {
  if (!initialized_) return Status::error(StatusCode::InvalidState, "authority not initialized");
  if (!quarantined_) return Status::error(StatusCode::InvalidState, "authority not quarantined");
  // Disaster recovery establishes a NEW authority generation (control-plane
  // spec): pre-loss operations signed for an older generation can never
  // re-validate and re-apply against the recovered ledger.
  const AuthorityRecord genesis{network_, authority_, max_generation_seen_ + 1U, 0,
                                Digest256{}};
  const std::uint64_t revision = recovery_floor_ + 1U;
  // The identical genesis record goes to both slots so a stale valid record
  // cannot break the hash-chain check on the next boot.
  Status status = store_record(0, genesis, revision, Digest256{}, Digest256{});
  if (!status) return status;
  status = store_record(1, genesis, revision, Digest256{}, Digest256{});
  if (!status) return status;
  // Both slots now provably hold fresh records written by us; any reservation
  // markers from other-schema or foreign data are obsolete.
  slot_reserved_[0] = StatusCode::Ok;
  slot_reserved_[1] = StatusCode::Ok;
  state_ = genesis;
  revision_ = revision;
  active_slot_ = 0;
  has_active_ = true;
  quarantined_ = false;
  return Status::success();
}

}  // namespace routeloom
