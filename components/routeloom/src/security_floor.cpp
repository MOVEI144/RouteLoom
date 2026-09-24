#include "routeloom/security_floor.hpp"

#include "routeloom/crc32.hpp"

namespace routeloom {
namespace {

constexpr std::size_t kEntryBytes = 16;
constexpr std::uint8_t kKnownFlags = kSecurityFloorTrustManaged;

bool state_equal(const SecurityFloorState& a, const SecurityFloorState& b) noexcept {
  if (a.network != b.network || a.target != b.target ||
      a.trust_epoch_floor != b.trust_epoch_floor ||
      a.min_authority_generation != b.min_authority_generation ||
      a.namespace_count != b.namespace_count || a.flags != b.flags) {
    return false;
  }
  for (std::size_t i = 0; i < a.last_manifest_hash.size(); ++i) {
    if (a.last_manifest_hash[i] != b.last_manifest_hash[i]) return false;
  }
  for (std::size_t i = 0; i < kSecurityFloorMaxNamespaces; ++i) {
    const SecurityFloorEntry& x = a.entries[i];
    const SecurityFloorEntry& y = b.entries[i];
    if (x.config_namespace != y.config_namespace || x.schema != y.schema ||
        x.store_floor != y.store_floor || x.decision_floor != y.decision_floor) {
      return false;
    }
  }
  return true;
}

Status validate_table(const SecurityFloorState& state) noexcept {
  if (state.namespace_count == 0 ||
      state.namespace_count > kSecurityFloorMaxNamespaces) {
    return Status::error(StatusCode::InvalidArgument,
                         "security floor namespace count");
  }
  if ((state.flags & ~kKnownFlags) != 0) {
    return Status::error(StatusCode::InvalidArgument, "security floor flags");
  }
  for (std::size_t i = 0; i < state.namespace_count; ++i) {
    const SecurityFloorEntry& entry = state.entries[i];
    if (entry.config_namespace == 0 || entry.config_namespace == 0xFFFF) {
      return Status::error(StatusCode::InvalidArgument,
                           "security floor namespace id");
    }
    for (std::size_t j = 0; j < i; ++j) {
      if (state.entries[j].config_namespace == entry.config_namespace) {
        return Status::error(StatusCode::InvalidArgument,
                             "security floor namespace duplicated");
      }
    }
  }
  // Entries past namespace_count are padding and must read zero so two
  // images with the same deployed table always compare equal.
  for (std::size_t i = state.namespace_count; i < kSecurityFloorMaxNamespaces; ++i) {
    const SecurityFloorEntry& entry = state.entries[i];
    if (entry.config_namespace != 0 || entry.schema != 0 ||
        entry.store_floor != 0 || entry.decision_floor != 0) {
      return Status::error(StatusCode::InvalidArgument,
                           "security floor padding nonzero");
    }
  }
  return Status::success();
}

}  // namespace

Status security_floor_encode(const SecurityFloorState& state,
                             MutableByteView out) noexcept {
  if (out.size != kSecurityFloorBlobBytes) {
    return Status::error(StatusCode::InvalidArgument, "security floor size");
  }
  if (state.network == 0 || state.target == kInvalidNodeId ||
      state.target == kBroadcastNodeId) {
    return Status::error(StatusCode::InvalidArgument, "security floor identity");
  }
  Status status = validate_table(state);
  if (!status.ok()) return status;
  ByteWriter writer(out);
  status = writer.write_u32(kSecurityFloorMagic);
  if (status.ok()) status = writer.write_u16(kSecurityFloorFormat);
  if (status.ok()) status = writer.write_u16(kSecurityFloorBlobBytes);
  if (status.ok()) status = writer.write_u64(state.network);
  if (status.ok()) status = writer.write_u64(state.target);
  if (status.ok()) status = writer.write_u32(state.trust_epoch_floor);
  if (status.ok()) status = writer.write_u32(state.min_authority_generation);
  if (status.ok()) {
    status = writer.write_bytes(
        ByteView{state.last_manifest_hash.data(), state.last_manifest_hash.size()});
  }
  if (status.ok()) status = writer.write_u8(state.namespace_count);
  if (status.ok()) status = writer.write_u8(state.flags);
  if (status.ok()) status = writer.write_u16(0);
  for (std::size_t i = 0; status.ok() && i < kSecurityFloorMaxNamespaces; ++i) {
    const SecurityFloorEntry& entry = state.entries[i];
    status = writer.write_u16(entry.config_namespace);
    if (status.ok()) status = writer.write_u16(entry.schema);
    if (status.ok()) status = writer.write_u32(entry.store_floor);
    if (status.ok()) status = writer.write_u64(entry.decision_floor);
  }
  if (!status.ok()) return status;
  const std::uint32_t crc = crc32_iso_hdlc(
      ByteView{out.data, kSecurityFloorBlobBytes - 4});
  out.data[kSecurityFloorBlobBytes - 4] =
      static_cast<std::uint8_t>((crc >> 24) & 0xFFU);
  out.data[kSecurityFloorBlobBytes - 3] =
      static_cast<std::uint8_t>((crc >> 16) & 0xFFU);
  out.data[kSecurityFloorBlobBytes - 2] =
      static_cast<std::uint8_t>((crc >> 8) & 0xFFU);
  out.data[kSecurityFloorBlobBytes - 1] =
      static_cast<std::uint8_t>(crc & 0xFFU);
  return Status::success();
}

Status security_floor_decode(ByteView blob, SecurityFloorState& out) noexcept {
  if (blob.size != kSecurityFloorBlobBytes) {
    return Status::error(StatusCode::InvalidArgument, "security floor size");
  }
  const std::uint32_t want = crc32_iso_hdlc(
      ByteView{blob.data, kSecurityFloorBlobBytes - 4});
  const std::uint32_t have =
      (static_cast<std::uint32_t>(blob.data[kSecurityFloorBlobBytes - 4]) << 24) |
      (static_cast<std::uint32_t>(blob.data[kSecurityFloorBlobBytes - 3]) << 16) |
      (static_cast<std::uint32_t>(blob.data[kSecurityFloorBlobBytes - 2]) << 8) |
      static_cast<std::uint32_t>(blob.data[kSecurityFloorBlobBytes - 1]);
  if (want != have) {
    return Status::error(StatusCode::IntegrityError, "security floor crc");
  }
  ByteReader reader(blob);
  std::uint32_t magic = 0;
  std::uint16_t format = 0;
  std::uint16_t blob_len = 0;
  Status status = reader.read_u32(magic);
  if (status.ok()) status = reader.read_u16(format);
  if (status.ok()) status = reader.read_u16(blob_len);
  if (!status.ok() || magic != kSecurityFloorMagic ||
      format != kSecurityFloorFormat || blob_len != kSecurityFloorBlobBytes) {
    return Status::error(StatusCode::Unsupported, "security floor header");
  }
  SecurityFloorState state{};
  status = reader.read_u64(state.network);
  if (status.ok()) status = reader.read_u64(state.target);
  if (status.ok()) status = reader.read_u32(state.trust_epoch_floor);
  if (status.ok()) status = reader.read_u32(state.min_authority_generation);
  if (status.ok()) {
    MutableByteView hash{state.last_manifest_hash.data(),
                         state.last_manifest_hash.size()};
    status = reader.read_bytes(hash);
  }
  std::uint16_t reserved = 0;
  if (status.ok()) status = reader.read_u8(state.namespace_count);
  if (status.ok()) status = reader.read_u8(state.flags);
  if (status.ok()) status = reader.read_u16(reserved);
  if (!status.ok() || reader.remaining() !=
                            kSecurityFloorMaxNamespaces * kEntryBytes + 4 ||
      reserved != 0) {
    return Status::error(StatusCode::IntegrityError, "security floor header");
  }
  for (std::size_t i = 0; status.ok() && i < kSecurityFloorMaxNamespaces; ++i) {
    SecurityFloorEntry& entry = state.entries[i];
    status = reader.read_u16(entry.config_namespace);
    if (status.ok()) status = reader.read_u16(entry.schema);
    if (status.ok()) status = reader.read_u32(entry.store_floor);
    if (status.ok()) status = reader.read_u64(entry.decision_floor);
  }
  if (!status.ok()) {
    return Status::error(StatusCode::IntegrityError, "security floor entries");
  }
  status = validate_table(state);
  if (!status.ok()) return status;
  if (state.network == 0 || state.target == kInvalidNodeId ||
      state.target == kBroadcastNodeId) {
    return Status::error(StatusCode::InvalidArgument, "security floor identity");
  }
  out = state;
  return Status::success();
}

Status SecurityFloorStore::initialize() noexcept {
  return refresh();
}

Status SecurityFloorStore::refresh() noexcept {
  usable_ = false;
  std::array<std::uint8_t, kSecurityFloorBlobBytes> blob{};
  MutableByteView view{blob.data(), blob.size()};
  const Status status = storage_.read(view);
  if (!status.ok()) {
    // No auto-creation: without a provisioned floor the counters it must
    // bound are unknown, so privileged intake stops until managed
    // re-provisioning installs one.
    return Status::error(StatusCode::RecoveryRequired,
                         "security floor unreadable: managed reprovisioning required");
  }
  SecurityFloorState state{};
  const Status decoded = security_floor_decode(ByteView{blob.data(), blob.size()}, state);
  if (!decoded.ok()) return decoded;
  cached_ = state;
  usable_ = true;
  return Status::success();
}

Status SecurityFloorStore::read(SecurityFloorState& out) const noexcept {
  if (!usable_) {
    return Status::error(StatusCode::RecoveryRequired, "security floor unusable");
  }
  out = cached_;
  return Status::success();
}

Status SecurityFloorStore::advance(const SecurityFloorState& expected,
                                   const SecurityFloorState& next) noexcept {
  if (!usable_) {
    return Status::error(StatusCode::RecoveryRequired, "security floor unusable");
  }
  if (!state_equal(expected, cached_)) {
    return Status::error(StatusCode::Conflict, "security floor moved underneath");
  }
  // Identity, namespace table and flags are provisioning facts — advance
  // only moves the floors and the manifest binding.
  if (next.network != cached_.network || next.target != cached_.target ||
      next.namespace_count != cached_.namespace_count ||
      next.flags != cached_.flags) {
    return Status::error(StatusCode::InvalidArgument,
                         "security floor identity/table immutable");
  }
  for (std::size_t i = 0; i < kSecurityFloorMaxNamespaces; ++i) {
    if (next.entries[i].config_namespace != cached_.entries[i].config_namespace ||
        next.entries[i].schema != cached_.entries[i].schema) {
      return Status::error(StatusCode::InvalidArgument,
                           "security floor namespace immutable");
    }
  }
  if (next.trust_epoch_floor < cached_.trust_epoch_floor ||
      next.min_authority_generation < cached_.min_authority_generation) {
    return Status::error(StatusCode::InvalidArgument, "security floor regressed");
  }
  for (std::size_t i = 0; i < cached_.namespace_count; ++i) {
    if (next.entries[i].store_floor < cached_.entries[i].store_floor ||
        next.entries[i].decision_floor < cached_.entries[i].decision_floor) {
      return Status::error(StatusCode::InvalidArgument, "security floor regressed");
    }
  }
  if (state_equal(next, cached_)) return Status::success();  // idempotent resume
  return commit(next);
}

Status SecurityFloorStore::provision_seed(const SecurityFloorState& state) noexcept {
  usable_ = false;
  return commit(state);
}

const SecurityFloorEntry* SecurityFloorStore::entry_for(
    const SecurityFloorState& state, const std::uint16_t config_namespace) noexcept {
  for (std::size_t i = 0; i < state.namespace_count; ++i) {
    if (state.entries[i].config_namespace == config_namespace) {
      return &state.entries[i];
    }
  }
  return nullptr;
}

SecurityFloorEntry* SecurityFloorStore::entry_for_mut(
    SecurityFloorState& state, const std::uint16_t config_namespace) noexcept {
  for (std::size_t i = 0; i < state.namespace_count; ++i) {
    if (state.entries[i].config_namespace == config_namespace) {
      return &state.entries[i];
    }
  }
  return nullptr;
}

Status SecurityFloorStore::commit(const SecurityFloorState& state) noexcept {
  // The cache follows only bytes that read back identical — invalidate
  // first so any failure below stops intake until refresh() re-proves.
  usable_ = false;
  std::array<std::uint8_t, kSecurityFloorBlobBytes> blob{};
  MutableByteView view{blob.data(), blob.size()};
  Status status = security_floor_encode(state, view);
  if (!status.ok()) return status;
  status = storage_.write(ByteView{blob.data(), blob.size()});
  if (!status.ok()) return status;
  // Readback: a torn write must not become the floors the journal trusts.
  std::array<std::uint8_t, kSecurityFloorBlobBytes> check{};
  MutableByteView check_view{check.data(), check.size()};
  status = storage_.read(check_view);
  if (!status.ok()) return status;
  SecurityFloorState confirmed{};
  status = security_floor_decode(ByteView{check.data(), check.size()}, confirmed);
  if (!status.ok()) return status;
  if (!state_equal(confirmed, state)) {
    return Status::error(StatusCode::StorageFailure, "security floor readback");
  }
  cached_ = state;
  usable_ = true;
  return Status::success();
}

}  // namespace routeloom
