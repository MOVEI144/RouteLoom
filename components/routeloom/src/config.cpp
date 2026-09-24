// Small Remote Config portable core — see config.hpp for the contract map
// (04-remote-config.md + 05-wire-api.md §5.4/§5.5, contracts.json config.*,
// 06-acceptance.md §6.3).

#include "routeloom/config.hpp"

#include <cstring>

#include "routeloom/byte_io.hpp"
#include "routeloom/crc32.hpp"
#include "routeloom/discovery_scope.hpp"  // sha256, constant_time_equal

namespace routeloom {
namespace {

using endpoint::ConfigField;
using endpoint::ConfigFieldType;
using endpoint::ConfigPhase;
using endpoint::ConfigReason;

// --- Journal record layout ------------------------------------------------------
// Fixed 148-byte header + variable prev/next snapshots + permit + CRC32.
//   0   u32  magic "RCJ1"
//   4   u16  format version (1)
//   6   u16  record length (used bytes incl. CRC)
//   8   u32  schema_version (1)
//   12  u32  store generation (monotonic per namespace; never reused)
//   16  u32  commit seal (0 pending, kJournalSealCommitted committed)
//   20  u8   phase | u8 record kind (format 2; format 1 reserved=0) | u16 reason
//   24  u64  network | u64 target
//   40  u16  namespace | u16 schema | u32 issuer_generation
//   48  u64  issuer | u64 authority_sequence
//   64  16B  operation_id | 32B command_digest (SHA-256 of RCC1)
//   112 u64  decision_revision | u64 active_revision
//   128 u64  target_boot | u32 apply_within_ms
//   140 u16  prev_len | u16 next_len | u16 permit_len | u16 reserved
//   148 prev_snapshot | next_snapshot | permit | u32 crc32 over [0,len-4)
constexpr std::uint32_t kJournalMagic = 0x52434A31U;  // "RCJ1"
// Format 2 carries the record kind byte; format 1 images (reserved byte 0)
// still decode as Standard records so healthy pre-floor journals migrate.
constexpr std::uint16_t kJournalFormat = 2;
constexpr std::uint16_t kJournalFormatLegacy = 1;
constexpr std::uint32_t kJournalSchemaVersion = 1;
constexpr std::uint32_t kJournalSealCommitted = 0xC0A61E5EU;
constexpr std::size_t kJournalHeaderSize = 148;
constexpr std::size_t kJournalRecordMax =
    kJournalHeaderSize + endpoint::kConfigSnapshotMax +
    endpoint::kConfigSnapshotMax + kConfigPermitObjectMax + 4;
static_assert(kJournalRecordMax <= kConfigJournalSlotBytes,
              "journal record must fit its slot");

bool is_erased(const std::uint8_t* data, const std::size_t size) noexcept {
  const std::uint8_t fill = data[0];
  if (fill != 0x00U && fill != 0xFFU) return false;
  for (std::size_t i = 1; i < size; ++i) {
    if (data[i] != fill) return false;
  }
  return true;
}

bool all_zero(const ByteView view) noexcept {
  for (std::size_t i = 0; i < view.size; ++i) {
    if (view.data[i] != 0) return false;
  }
  return true;
}

// Expected value length for a TLV field type; SIZE_MAX marks "reject".
constexpr std::size_t tlv_value_length(const std::uint8_t type,
                                       const std::uint16_t declared) noexcept {
  switch (type) {
    case 1:  // bool
    case 2:  // u8
      return declared == 1 ? 1 : static_cast<std::size_t>(-1);
    case 3:  // u32
      return declared == 4 ? 4 : static_cast<std::size_t>(-1);
    case 4:  // bytes
      return declared <= endpoint::kConfigFieldValueMax ? declared
                                                      : static_cast<std::size_t>(-1);
    default:
      return static_cast<std::size_t>(-1);
  }
}

// Read one snapshot field's scalar value; false when absent/not a 1-byte
// field. Used only for maintenance-boundary transition detection.
bool field_u8(const endpoint::ConfigField* fields, const std::uint16_t count,
              const std::uint16_t field_id, std::uint8_t& value) noexcept {
  for (std::uint16_t i = 0; i < count; ++i) {
    if (fields[i].field_id != field_id) continue;
    if (fields[i].value_size != 1 ||
        (fields[i].type != ConfigFieldType::Bool && fields[i].type != ConfigFieldType::U8)) {
      return false;
    }
    value = fields[i].value[0];
    return true;
  }
  return false;
}

}  // namespace

// --- Schema / TLV layer ---------------------------------------------------------

Status config_tlv_decode(const ByteView tlv, ConfigField* const fields,
                         const std::uint16_t capacity, std::uint16_t& count) noexcept {
  count = 0;
  if (tlv.size > endpoint::kConfigSnapshotMax || (tlv.size > 0 && tlv.data == nullptr) ||
      (fields == nullptr && capacity > 0)) {
    return Status::error(StatusCode::InvalidArgument, "config tlv input invalid");
  }
  ByteReader reader(tlv);
  std::uint16_t previous_id = 0;
  while (reader.remaining() > 0) {
    if (count >= capacity || reader.remaining() < 5) {
      return Status::error(StatusCode::ProtocolError, "config tlv truncated/overflow");
    }
    ConfigField& field = fields[count];
    field = ConfigField{};
    std::uint8_t type = 0;
    std::uint16_t declared = 0;
    Status status = reader.read_u16(field.field_id);
    if (status) status = reader.read_u8(type);
    if (status) status = reader.read_u16(declared);
    if (!status) return status;
    const std::size_t value_len = tlv_value_length(type, declared);
    if (value_len == static_cast<std::size_t>(-1) || reader.remaining() < value_len) {
      return Status::error(StatusCode::ProtocolError, "config tlv field invalid");
    }
    if (count > 0 && field.field_id <= previous_id) {
      return Status::error(StatusCode::ProtocolError, "config tlv order violation");
    }
    previous_id = field.field_id;
    status = reader.read_bytes(MutableByteView{field.value.data(), value_len});
    if (!status) return status;
    field.value_size = static_cast<std::uint16_t>(value_len);
    field.type = static_cast<ConfigFieldType>(type);
    if (type == static_cast<std::uint8_t>(ConfigFieldType::Bool) && field.value[0] > 1) {
      return Status::error(StatusCode::ProtocolError, "config tlv bool out of range");
    }
    ++count;
  }
  return Status::success();
}

Status config_tlv_encode(const ConfigField* const fields, const std::uint16_t count,
                         ByteBuffer<endpoint::kConfigSnapshotMax>& out) noexcept {
  out.clear();
  if (count > endpoint::kConfigFieldCountMax || (fields == nullptr && count > 0)) {
    return Status::error(StatusCode::InvalidArgument, "config snapshot field count invalid");
  }
  ByteWriter writer(out.writable());
  std::uint16_t previous_id = 0;
  for (std::uint16_t i = 0; i < count; ++i) {
    const ConfigField& field = fields[i];
    if (tlv_value_length(static_cast<std::uint8_t>(field.type), field.value_size) ==
            static_cast<std::size_t>(-1) ||
        (i > 0 && field.field_id <= previous_id)) {
      return Status::error(StatusCode::InvalidArgument, "config snapshot field invalid");
    }
    previous_id = field.field_id;
    Status status = writer.write_u16(field.field_id);
    if (status) status = writer.write_u8(static_cast<std::uint8_t>(field.type));
    if (status) status = writer.write_u16(field.value_size);
    if (status) status = writer.write_bytes(ByteView{field.value.data(), field.value_size});
    if (!status) return status;
  }
  out.size = writer.size();
  return Status::success();
}

Status config_snapshot_hash(const std::uint16_t config_namespace, const std::uint16_t schema,
                            const ByteView snapshot_tlv, Digest256& out) noexcept {
  ByteBuffer<endpoint::kConfigSnapshotInputMax> input{};
  Status status =
      endpoint::config_snapshot_hash_input(config_namespace, schema, snapshot_tlv, input);
  if (!status) return status;
  sha256(input.view(), out);
  return Status::success();
}

namespace {

// The merge's two 16-field work areas (~3.3 KB) come from the caller so the
// journal's submit path can supply member scratch instead of task stack;
// the public config_patch_apply wrapper below keeps its own locals for
// issuer/test callers where stack is not constrained.
Status config_patch_merge(const ByteView base_tlv, const ConfigField* const patch,
                          const std::uint16_t patch_count, ConfigField* const merged,
                          ConfigField* const out_fields,
                          ByteBuffer<endpoint::kConfigSnapshotMax>& next,
                          bool& changed) noexcept {
  changed = false;
  std::uint16_t base_count = 0;
  Status status = config_tlv_decode(base_tlv, merged, endpoint::kConfigFieldCountMax,
                                    base_count);
  if (!status) return status;
  if (patch_count > endpoint::kConfigFieldCountMax ||
      (patch == nullptr && patch_count > 0)) {
    return Status::error(StatusCode::InvalidArgument, "config patch field count invalid");
  }
  // Validate the patch itself (strict ascending ids, exact lengths) before
  // merging — an invalid patch never produces a snapshot.
  std::uint16_t previous_id = 0;
  for (std::uint16_t i = 0; i < patch_count; ++i) {
    const ConfigField& field = patch[i];
    if (tlv_value_length(static_cast<std::uint8_t>(field.type), field.value_size) ==
            static_cast<std::size_t>(-1) ||
        (i > 0 && field.field_id <= previous_id) ||
        (field.type == ConfigFieldType::Bool && field.value_size == 1 &&
         field.value[0] > 1)) {
      return Status::error(StatusCode::InvalidArgument, "config patch field invalid");
    }
    previous_id = field.field_id;
  }
  // Merge: patch wins per id; result stays ascending.
  std::uint16_t out_count = 0;
  std::uint16_t base_i = 0, patch_i = 0;
  while (base_i < base_count || patch_i < patch_count) {
    const ConfigField* pick = nullptr;
    if (base_i < base_count &&
        (patch_i >= patch_count || merged[base_i].field_id < patch[patch_i].field_id)) {
      pick = &merged[base_i++];
    } else if (patch_i < patch_count &&
               (base_i >= base_count ||
                patch[patch_i].field_id < merged[base_i].field_id)) {
      pick = &patch[patch_i++];
    } else {
      // Same id in both: the patch value wins, the base entry is consumed.
      pick = &patch[patch_i++];
      ++base_i;
    }
    if (out_count >= endpoint::kConfigFieldCountMax) {
      return Status::error(StatusCode::InvalidArgument, "config snapshot overflow");
    }
    out_fields[out_count++] = *pick;
  }
  status = config_tlv_encode(out_fields, out_count, next);
  if (!status) return status;
  changed = !(next.size == base_tlv.size &&
              (base_tlv.size == 0 ||
               std::memcmp(next.bytes.data(), base_tlv.data, base_tlv.size) == 0));
  return Status::success();
}

}  // namespace

Status config_patch_apply(const ByteView base_tlv, const ConfigField* const patch,
                          const std::uint16_t patch_count,
                          ByteBuffer<endpoint::kConfigSnapshotMax>& next,
                          bool& changed) noexcept {
  ConfigField merged[endpoint::kConfigFieldCountMax]{};
  ConfigField out_fields[endpoint::kConfigFieldCountMax]{};
  return config_patch_merge(base_tlv, patch, patch_count, merged, out_fields, next,
                            changed);
}

Status config_permit_aad(const NetworkId network, const NodeId target,
                         const std::uint16_t config_namespace,
                         ByteBuffer<kConfigPermitAadSize>& out) noexcept {
  out.clear();
  ByteWriter writer(out.writable());
  Status status = writer.write_bytes(
      ByteView{reinterpret_cast<const std::uint8_t*>(kConfigPermitDomain),
               sizeof(kConfigPermitDomain)});
  if (status) status = writer.write_u64(network);
  if (status) status = writer.write_u64(target);
  if (status) status = writer.write_u16(config_namespace);
  if (!status) return status;
  out.size = writer.size();
  return Status::success();
}

Status config_recovery_aad(const NetworkId network, const NodeId target,
                           const std::uint16_t config_namespace,
                           ByteBuffer<kConfigRecoveryAadSize>& out) noexcept {
  out.clear();
  ByteWriter writer(out.writable());
  Status status = writer.write_bytes(
      ByteView{reinterpret_cast<const std::uint8_t*>(kConfigRecoveryDomain),
               sizeof(kConfigRecoveryDomain)});
  if (status) status = writer.write_u64(network);
  if (status) status = writer.write_u64(target);
  if (status) status = writer.write_u16(config_namespace);
  if (!status) return status;
  out.size = writer.size();
  return Status::success();
}

Status config_sdk_field_validate(const ConfigField& field) noexcept {
  switch (field.field_id) {
    case 1:  // diagnostics_level u8 0..2 — no payload/key-dump level exists
    case 4:  // migration_policy u8 0..2 — unimplemented policies never enable
      if (field.type != ConfigFieldType::U8 || field.value_size != 1 ||
          field.value[0] > 2) {
        return Status::error(StatusCode::InvalidArgument, "sdk config u8 field out of range");
      }
      return Status::success();
    case 2:  // discovery_enabled bool
    case 3:  // relay_allowed bool
      if (field.type != ConfigFieldType::Bool || field.value_size != 1 ||
          field.value[0] > 1) {
        return Status::error(StatusCode::InvalidArgument, "sdk config bool field invalid");
      }
      return Status::success();
    default:
      return Status::error(StatusCode::Unsupported, "sdk config field id unknown");
  }
}

ConfigNamespaceTable::ConfigNamespaceTable() noexcept {
  entries_[0] = ConfigNamespaceEntry{};
  size_ = 1;
}

Status ConfigNamespaceTable::register_namespace(const ConfigNamespaceEntry& entry) noexcept {
  if (!endpoint::config_namespace_valid(entry.config_namespace) || entry.schema == 0) {
    return Status::error(StatusCode::InvalidArgument, "config namespace/schema invalid");
  }
  if (entry.config_namespace != endpoint::kConfigNamespaceSdk &&
      entry.validator == nullptr) {
    // An app namespace without a registered schema validator cannot judge
    // its values — the design forbids silently accepting unknown options.
    return Status::error(StatusCode::InvalidArgument,
                        "app namespace requires a schema validator");
  }
  for (std::size_t i = 0; i < size_; ++i) {
    if (entries_[i].config_namespace == entry.config_namespace) {
      entries_[i] = entry;  // explicit re-registration updates the entry
      return Status::success();
    }
  }
  if (size_ >= kConfigNamespaceLimit) {
    return Status::error(StatusCode::NoCapacity, "config namespace table full");
  }
  entries_[size_++] = entry;
  return Status::success();
}

const ConfigNamespaceEntry* ConfigNamespaceTable::find(
    const std::uint16_t config_namespace) const noexcept {
  for (std::size_t i = 0; i < size_; ++i) {
    if (entries_[i].config_namespace == config_namespace) return &entries_[i];
  }
  return nullptr;
}

StatusCode config_reason_status(const ConfigReason reason) noexcept {
  switch (reason) {
    case ConfigReason::Ok:
      return StatusCode::Ok;
    case ConfigReason::InProgress:
    case ConfigReason::MaintenanceBusy:
      return StatusCode::Busy;
    case ConfigReason::StaleRevision:
    case ConfigReason::BaseHashMismatch:
      return StatusCode::Conflict;
    case ConfigReason::InvalidPatch:
      return StatusCode::ProtocolError;
    case ConfigReason::Deadline:
      return StatusCode::Expired;
    case ConfigReason::AuthorityDenied:
      return StatusCode::AuthorizationFailed;
    case ConfigReason::Unsupported:
      return StatusCode::Unsupported;
    case ConfigReason::Capacity:
      return StatusCode::NoCapacity;
    case ConfigReason::StorageFailure:
      return StatusCode::StorageFailure;
    case ConfigReason::ApplyInterrupted:
    case ConfigReason::VerifyFailed:
      return StatusCode::DriverResultUnknown;
    case ConfigReason::RecoveryRequired:
      return StatusCode::RecoveryRequired;
    case ConfigReason::NoChange:
      return StatusCode::AlreadyExists;
    case ConfigReason::ResultExpired:
      return StatusCode::NotFound;
  }
  return StatusCode::InternalError;
}

// --- ConfigJournal --------------------------------------------------------------

ConfigJournal::ConfigJournal(const ConfigJournalConfig& config,
                             ConfigJournalStorage& storage,
                             SecurityFloorStore& floor,
                             ConfigAuthorityVerifier& verifier, EntropySource& entropy,
                             ConfigRateLimiter& rate_limiter, ConfigProvider* provider,
                             const ConfigSchemaValidator* validator,
                             ConfigMaintenanceGate* gate) noexcept
    : config_(config),
      storage_(storage),
      floor_(floor),
      verifier_(verifier),
      entropy_(entropy),
      rate_limiter_(rate_limiter),
      provider_(provider),
      validator_(validator),
      gate_(gate) {}

Status ConfigJournal::decode_slot(const std::uint8_t slot, JournalRecord& record,
                                  SlotContent& content, bool& committed_fields) noexcept {
  committed_fields = false;
  auto& raw = scratch_a_;
  const Status status =
      storage_.read(slot, MutableByteView{raw.data(), raw.size()});
  if (!status) return status;
  if (is_erased(raw.data(), raw.size())) {
    content = SlotContent::Empty;
    return Status::success();
  }
  ByteReader reader(ByteView{raw.data(), raw.size()});
  std::uint32_t magic = 0, schema = 0, generation = 0, seal = 0;
  std::uint16_t format = 0, length = 0;
  Status st = reader.read_u32(magic);
  if (st) st = reader.read_u16(format);
  if (st) st = reader.read_u16(length);
  if (st) st = reader.read_u32(schema);
  if (st) st = reader.read_u32(generation);
  if (st) st = reader.read_u32(seal);
  if (!st || magic != kJournalMagic ||
      (format != kJournalFormat && format != kJournalFormatLegacy) ||
      length < kJournalHeaderSize + 4 || length > kJournalRecordMax) {
    content = SlotContent::Corrupt;
    return Status::success();
  }
  if (seal != kJournalSealCommitted) {
    // A well-formed pending record was never committed and is always safe
    // to discard; any other seal value is corruption.
    content = seal == 0 ? SlotContent::Pending : SlotContent::Corrupt;
    return Status::success();
  }
  if (length > raw.size()) {
    content = SlotContent::Corrupt;
    return Status::success();
  }
  record.store_generation = generation;
  std::uint8_t phase = 0, reserved8 = 0;
  std::uint16_t reason = 0;
  std::uint16_t ns = 0, schema_id = 0, prev_len = 0, next_len = 0, permit_len = 0,
                reserved16 = 0;
  std::uint32_t issuer_generation = 0, apply_within = 0;
  st = reader.read_u8(phase);
  if (st) st = reader.read_u8(reserved8);
  if (st) st = reader.read_u16(reason);
  if (st) st = reader.read_u64(record.network);
  if (st) st = reader.read_u64(record.target);
  if (st) st = reader.read_u16(ns);
  if (st) st = reader.read_u16(schema_id);
  if (st) st = reader.read_u32(issuer_generation);
  if (st) st = reader.read_u64(record.issuer);
  if (st) st = reader.read_u64(record.authority_sequence);
  if (st) st = reader.read_bytes(MutableByteView{record.operation_id.data(), 16});
  if (st) st = reader.read_bytes(MutableByteView{record.command_digest.data(), 32});
  if (st) st = reader.read_u64(record.decision_revision);
  if (st) st = reader.read_u64(record.active_revision);
  if (st) st = reader.read_u64(record.target_boot);
  if (st) st = reader.read_u32(apply_within);
  if (st) st = reader.read_u16(prev_len);
  if (st) st = reader.read_u16(next_len);
  if (st) st = reader.read_u16(permit_len);
  if (st) st = reader.read_u16(reserved16);
  const std::size_t expect =
      kJournalHeaderSize + static_cast<std::size_t>(prev_len) + next_len + permit_len + 4;
  // The kind byte: format 1 images keep reserved=0 (Standard); format 2
  // names Standard/Intent/Complete — anything else is noise.
  const bool kind_ok =
      format == kJournalFormatLegacy
          ? reserved8 == 0
          : reserved8 <= static_cast<std::uint8_t>(ConfigRecordKind::RecoveryComplete);
  if (!st || !kind_ok || reserved16 != 0 ||
      prev_len > endpoint::kConfigSnapshotMax || next_len > endpoint::kConfigSnapshotMax ||
      permit_len > kConfigPermitObjectMax || expect != length ||
      phase > static_cast<std::uint8_t>(ConfigPhase::Quarantined) ||
      reason > static_cast<std::uint16_t>(ConfigReason::ResultExpired)) {
    // A record that fails structural or semantic validation is
    // indistinguishable from noise: it cannot be proven to be a real
    // committed record, so it must NOT bound the generation/revision
    // floors — otherwise bitrot could mint an arbitrary floor and wedge
    // recovery forever (06 §6.3). Only the fully-parsed,
    // committed-seal record below that fails solely on CRC still bounds
    // the floors, mirroring the ledger's recovery_floor_.
    content = SlotContent::Corrupt;
    return Status::success();
  }
  record.phase = static_cast<ConfigPhase>(phase);
  record.reason = static_cast<ConfigReason>(reason);
  record.kind = format == kJournalFormatLegacy
                    ? ConfigRecordKind::Standard
                    : static_cast<ConfigRecordKind>(reserved8);
  record.config_namespace = ns;
  record.schema = schema_id;
  record.issuer_generation = issuer_generation;
  record.apply_within_ms = apply_within;
  st = reader.read_bytes(MutableByteView{record.prev_snapshot.bytes.data(), prev_len});
  if (st) record.prev_snapshot.size = prev_len;
  if (st) st = reader.read_bytes(MutableByteView{record.next_snapshot.bytes.data(), next_len});
  if (st) record.next_snapshot.size = next_len;
  if (st) st = reader.read_bytes(MutableByteView{record.permit.bytes.data(), permit_len});
  if (st) record.permit.size = permit_len;
  std::uint32_t crc = 0;
  if (st) st = reader.read_u32(crc);
  committed_fields = st.ok();
  if (!st || crc32_iso_hdlc(ByteView{raw.data(), static_cast<std::size_t>(length) - 4}) != crc) {
    content = SlotContent::Corrupt;
    return Status::success();
  }
  if (schema != kJournalSchemaVersion) {
    content = SlotContent::Unsupported;
    return Status::success();
  }
  if (record.network != config_.network || record.target != config_.target ||
      ns != config_.config_namespace) {
    content = SlotContent::Foreign;
    return Status::success();
  }
  content = SlotContent::Valid;
  return Status::success();
}

Status ConfigJournal::store_record(const JournalRecord& record) noexcept {
  const std::size_t record_len = kJournalHeaderSize + record.prev_snapshot.size +
                                 record.next_snapshot.size + record.permit.size + 4;
  if (record_len > kConfigJournalSlotBytes || record_len > kJournalRecordMax) {
    return Status::error(StatusCode::InvalidArgument, "config journal record oversize");
  }
  const std::uint8_t target_slot =
      has_active_ ? static_cast<std::uint8_t>(active_slot_ ^ 1U) : active_slot_;

  auto encode = [&](const std::uint32_t seal,
                    std::array<std::uint8_t, kConfigJournalSlotBytes>& image) {
    ByteWriter writer(MutableByteView{image.data(), image.size()});
    Status st = writer.write_u32(kJournalMagic);
    if (st) st = writer.write_u16(kJournalFormat);
    if (st) st = writer.write_u16(static_cast<std::uint16_t>(record_len));
    if (st) st = writer.write_u32(kJournalSchemaVersion);
    if (st) st = writer.write_u32(record.store_generation);
    if (st) st = writer.write_u32(seal);
    if (st) st = writer.write_u8(static_cast<std::uint8_t>(record.phase));
    if (st) st = writer.write_u8(static_cast<std::uint8_t>(record.kind));
    if (st) st = writer.write_u16(static_cast<std::uint16_t>(record.reason));
    if (st) st = writer.write_u64(record.network);
    if (st) st = writer.write_u64(record.target);
    if (st) st = writer.write_u16(record.config_namespace);
    if (st) st = writer.write_u16(record.schema);
    if (st) st = writer.write_u32(record.issuer_generation);
    if (st) st = writer.write_u64(record.issuer);
    if (st) st = writer.write_u64(record.authority_sequence);
    if (st) st = writer.write_bytes(ByteView{record.operation_id.data(), 16});
    if (st) st = writer.write_bytes(ByteView{record.command_digest.data(), 32});
    if (st) st = writer.write_u64(record.decision_revision);
    if (st) st = writer.write_u64(record.active_revision);
    if (st) st = writer.write_u64(record.target_boot);
    if (st) st = writer.write_u32(record.apply_within_ms);
    if (st) st = writer.write_u16(static_cast<std::uint16_t>(record.prev_snapshot.size));
    if (st) st = writer.write_u16(static_cast<std::uint16_t>(record.next_snapshot.size));
    if (st) st = writer.write_u16(static_cast<std::uint16_t>(record.permit.size));
    if (st) st = writer.write_u16(0);
    if (st) st = writer.write_bytes(record.prev_snapshot.view());
    if (st) st = writer.write_bytes(record.next_snapshot.view());
    if (st) st = writer.write_bytes(record.permit.view());
    if (st) st = writer.write_u32(crc32_iso_hdlc(ByteView{image.data(), record_len - 4}));
    return st;
  };

  auto& image = scratch_a_;
  // Phase 1: land the record unsealed; a power cut leaves a discardable
  // pending record and the previous committed state survives.
  Status status = encode(0, image);
  if (!status) return status;
  status = storage_.write(target_slot, ByteView{image.data(), record_len});
  if (!status) return status;
  // Phase 2: commit seal.
  status = encode(kJournalSealCommitted, image);
  if (!status) return status;
  status = storage_.write(target_slot, ByteView{image.data(), record_len});
  if (!status) return status;
  // Phase 3: readback verify before any phase advance.
  auto& verify = scratch_b_;
  status = storage_.read(target_slot, MutableByteView{verify.data(), verify.size()});
  if (!status) return status;
  if (std::memcmp(verify.data(), image.data(), record_len) != 0) {
    return Status::error(StatusCode::StorageFailure, "config journal readback mismatch");
  }
  // The committed record's slot becomes the active one; the next write
  // alternates to the sibling, preserving this record through the next
  // record's pre-commit window.
  active_slot_ = target_slot;
  has_active_ = true;
  // Every committed seal is durable proof of how far the journal advanced:
  // the floors move with it so a later recover() in the same boot can never
  // re-mint a generation this boot already consumed, nor regress a decided
  // revision (06 §6.3 — mirrors the ledger's recovery_floor_).
  if (record.store_generation > proven_floor_) {
    proven_floor_ = record.store_generation;
  }
  if (record.decision_revision > revision_floor_) {
    revision_floor_ = record.decision_revision;
  }
  return Status::success();
}

Status ConfigJournal::reserve_generation(const Transaction& txn,
                                         std::uint32_t& reserved_j) noexcept {
  SecurityFloorState current{};
  Status status = floor_.read(current);
  if (!status.ok()) return status;
  const SecurityFloorEntry* entry =
      SecurityFloorStore::entry_for(current, config_.config_namespace);
  if (entry == nullptr) {
    return Status::error(StatusCode::RecoveryRequired,
                         "config security floor has no namespace entry");
  }
  if (entry->store_floor == 0xFFFFFFFFU) {
    // The store axis is spent: no further generation can be named, so no
    // further record can be committed (a device-lifetime event the callers
    // report as quarantine, never as a silent stall).
    return Status::error(StatusCode::CounterExhausted,
                         "config store generation exhausted");
  }
  SecurityFloorState next = current;
  SecurityFloorEntry* slot =
      SecurityFloorStore::entry_for_mut(next, config_.config_namespace);
  slot->store_floor = entry->store_floor + 1;
  // The decision floor only ever rises to the transaction's revision: a
  // DECIDED moves it, later phases of the same transaction hold it, and a
  // revision below the floor (a consumed gap) never lowers it.
  if (txn.command.next_revision > slot->decision_floor) {
    slot->decision_floor = txn.command.next_revision;
  }
  status = floor_.advance(current, next);
  if (!status.ok()) return status;
  reserved_j = slot->store_floor;
  return Status::success();
}

Status ConfigJournal::persist_phase(const ConfigPhase phase, const ConfigReason reason,
                                    const Transaction& txn) noexcept {
  std::uint32_t reserved_j = 0;
  Status status = reserve_generation(txn, reserved_j);
  if (!status.ok()) return status;
  JournalRecord& record = record_scratch_;
  record = JournalRecord{};
  record.store_generation = reserved_j;
  record.phase = phase;
  record.reason = reason;
  record.network = config_.network;
  record.target = config_.target;
  record.config_namespace = config_.config_namespace;
  record.schema = config_.schema;
  record.issuer = txn.command.authority;
  // Which generation authorized this record (forensic metadata — the
  // decision-time policy lives in the verifier, not in the journal).
  record.issuer_generation = txn.command.authority_generation;
  record.authority_sequence = txn.command.authority_sequence;
  record.operation_id = txn.command.operation_id;
  record.command_digest = txn.command_digest;
  record.decision_revision = txn.command.next_revision;
  record.active_revision =
      phase == ConfigPhase::Active ? txn.command.next_revision : active_revision_;
  record.target_boot = txn.command.target_boot;
  record.apply_within_ms = txn.command.apply_within_ms;
  record.prev_snapshot = txn.prev_snapshot;
  record.next_snapshot = txn.next_snapshot;
  record.permit = txn.permit;
  // The RAM counters follow the reservation even when the journal store
  // below faults: the gap is consumed, never reused.
  store_generation_ = reserved_j;
  status = store_record(record);
  if (!status) return status;
  phase_ = phase;
  durable_ = record;
  return Status::success();
}

Status ConfigJournal::adopt_record(const JournalRecord& record) noexcept {
  durable_ = record;
  store_generation_ = record.store_generation;
  // No generation pin is inherited: the decision-time policy lives in the
  // verifier (fixed profiles pin to the deployed generation, the trust
  // view serves the live RLT1/RLF1 floor). The record's issuer_generation
  // is forensic metadata — which generation authorized it — not policy.
  decision_revision_ = record.decision_revision;
  active_revision_ = record.active_revision;
  phase_ = record.phase;
  // The "current" snapshot is the confirmed-active one: next on ACTIVE,
  // prev otherwise (Interrupted restores prev; Decided/Intent keep prev).
  active_snapshot_ = record.phase == ConfigPhase::Active ? record.next_snapshot
                                                       : record.prev_snapshot;
  return config_snapshot_hash(config_.config_namespace, config_.schema,
                              active_snapshot_.view(), active_hash_);
}

Status ConfigJournal::record_result(const Transaction& txn, const ConfigPhase phase,
                                    const ConfigReason reason,
                                    const MonotonicMs now_ms) noexcept {
  ResultRecord* slot = nullptr;
  ResultRecord* expired_slot = nullptr;
  for (ResultRecord& candidate : results_) {
    if (!candidate.used) {
      if (slot == nullptr) slot = &candidate;
      continue;
    }
    if (now_ms - candidate.stored_ms >= kConfigResultHoldMs && expired_slot == nullptr) {
      expired_slot = &candidate;
    }
  }
  if (slot == nullptr) slot = expired_slot;
  if (slot == nullptr) {
    return Status::error(StatusCode::NoCapacity, "config result table full");
  }
  *slot = ResultRecord{};
  slot->used = true;
  slot->operation_id = txn.command.operation_id;
  slot->command_digest = txn.command_digest;
  slot->phase = phase;
  slot->reason = reason;
  slot->decision_revision = txn.command.next_revision;
  slot->active_revision =
      phase == ConfigPhase::Active ? txn.command.next_revision : active_revision_;
  slot->active_hash = active_hash_;
  slot->stored_ms = now_ms;
  return Status::success();
}

bool ConfigJournal::find_result(const std::array<std::uint8_t, 16>& operation_id,
                                const ResultRecord*& out) noexcept {
  for (const ResultRecord& candidate : results_) {
    if (candidate.used && candidate.operation_id == operation_id) {
      out = &candidate;
      return true;
    }
  }
  return false;
}

void ConfigJournal::fill_verdict(ConfigVerdict& verdict, const ConfigPhase phase,
                                 const ConfigReason reason) const noexcept {
  verdict.phase = phase;
  verdict.reason = reason;
  verdict.decision_revision = decision_revision_;
  verdict.active_revision = active_revision_;
  verdict.active_hash = active_hash_;
}

Status ConfigJournal::initialize(const MonotonicMs now_ms) noexcept {
  if (config_.network == 0 || config_.target == kInvalidNodeId ||
      config_.target == kBroadcastNodeId || config_.boot_incarnation == 0 ||
      config_.authorized_issuer == kInvalidNodeId ||
      config_.challenge_valid_ms == 0 ||
      config_.challenge_valid_ms > kConfigChallengeMaxMs ||
      !endpoint::config_namespace_valid(config_.config_namespace)) {
    return Status::error(StatusCode::InvalidArgument, "config journal identity invalid");
  }
  // The floor bounds every counter below: without a usable floor for this
  // identity and namespace, no adoption and no intake can be safe — and a
  // journal newer than its floor proves the save order was violated.
  SecurityFloorState floor_state{};
  Status floor_status = floor_.read(floor_state);
  if (!floor_status.ok()) return floor_status;
  if (floor_state.network != config_.network ||
      floor_state.target != config_.target) {
    return Status::error(StatusCode::Conflict,
                         "config security floor identity mismatch");
  }
  const SecurityFloorEntry* floor_entry = SecurityFloorStore::entry_for(
      floor_state, config_.config_namespace);
  if (floor_entry == nullptr) {
    return Status::error(StatusCode::RecoveryRequired,
                         "config security floor has no namespace entry");
  }
  const std::uint32_t floor_j = floor_entry->store_floor;
  const std::uint64_t floor_r = floor_entry->decision_floor;
  auto& parsed = parsed_;
  std::array<SlotContent, kConfigJournalSlots> content{};
  std::array<bool, kConfigJournalSlots> unreadable{};
  std::array<bool, kConfigJournalSlots> committed_fields{};
  Status read_error = Status::success();
  int valid = 0, corrupt = 0, foreign = 0, unsupported = 0;
  for (std::uint8_t slot = 0; slot < kConfigJournalSlots; ++slot) {
    const Status status = decode_slot(slot, parsed[slot], content[slot],
                                      committed_fields[slot]);
    if (!status) {
      unreadable[slot] = true;
      if (read_error.ok()) read_error = status;
      continue;
    }
    switch (content[slot]) {
      case SlotContent::Valid:
        ++valid;
        if (parsed[slot].store_generation > proven_floor_) {
          proven_floor_ = parsed[slot].store_generation;
        }
        if (parsed[slot].decision_revision > revision_floor_) {
          revision_floor_ = parsed[slot].decision_revision;
        }
        break;
      case SlotContent::Corrupt:
        ++corrupt;
        // A committed-seal record whose fields still parse bounds how far
        // the journal advanced: recovery never reuses a lower generation
        // or revision even when the CRC is gone (06 §6.3).
        if (committed_fields[slot]) {
          if (parsed[slot].store_generation > proven_floor_) {
            proven_floor_ = parsed[slot].store_generation;
          }
          if (parsed[slot].decision_revision > revision_floor_) {
            revision_floor_ = parsed[slot].decision_revision;
          }
        }
        break;
      case SlotContent::Foreign:
        ++foreign;
        break;
      case SlotContent::Unsupported:
        ++unsupported;
        if (parsed[slot].store_generation > proven_floor_) {
          proven_floor_ = parsed[slot].store_generation;
        }
        if (parsed[slot].decision_revision > revision_floor_) {
          revision_floor_ = parsed[slot].decision_revision;
        }
        break;
      default:
        break;
    }
  }

  auto quarantine = [&](const StatusCode code, const char* detail) {
    quarantined_ = true;
    initialized_ = true;
    phase_ = ConfigPhase::Quarantined;
    return Status::error(code, detail);
  };

  const auto provably_absent = [&](const std::uint8_t slot) {
    return !unreadable[slot] &&
           (content[slot] == SlotContent::Empty || content[slot] == SlotContent::Pending);
  };

  if (unreadable[0] && unreadable[1]) {
    return read_error.ok()
               ? Status::error(StatusCode::StorageFailure, "config journal unreadable")
               : read_error;
  }

  if (valid == 2) {
    const std::uint8_t newer = parsed[1].store_generation >= parsed[0].store_generation ? 1 : 0;
    const std::uint8_t older = static_cast<std::uint8_t>(newer ^ 1U);
    // Twins at one generation must agree on the whole encoded content —
    // kind, issuer metadata, identity, phase/reason, opid, digest,
    // revisions, snapshots and the signed object — or the commit they
    // claim is ambiguous and bounds nothing.
    const auto same_record = [](const JournalRecord& a, const JournalRecord& b) {
      return a.phase == b.phase && a.reason == b.reason && a.kind == b.kind &&
             a.network == b.network && a.target == b.target &&
             a.config_namespace == b.config_namespace && a.schema == b.schema &&
             a.issuer == b.issuer && a.issuer_generation == b.issuer_generation &&
             a.authority_sequence == b.authority_sequence &&
             a.decision_revision == b.decision_revision &&
             a.active_revision == b.active_revision &&
             a.target_boot == b.target_boot &&
             a.apply_within_ms == b.apply_within_ms &&
             a.operation_id == b.operation_id &&
             a.command_digest == b.command_digest &&
             a.prev_snapshot.size == b.prev_snapshot.size &&
             a.next_snapshot.size == b.next_snapshot.size &&
             a.permit.size == b.permit.size &&
             std::memcmp(a.prev_snapshot.bytes.data(), b.prev_snapshot.bytes.data(),
                         a.prev_snapshot.size) == 0 &&
             std::memcmp(a.next_snapshot.bytes.data(), b.next_snapshot.bytes.data(),
                         a.next_snapshot.size) == 0 &&
             std::memcmp(a.permit.bytes.data(), b.permit.bytes.data(), a.permit.size) == 0;
    };
    if (parsed[newer].store_generation == parsed[older].store_generation &&
        !same_record(parsed[newer], parsed[older])) {
      // Equal generations with different content cannot be ordered: the
      // newer commit is ambiguous — known value only, no intake (06 §6.3).
      const Status adopted = adopt_record(parsed[newer]);
      if (!adopted) return adopted;
      active_slot_ = newer;
      has_active_ = true;
      uncertain_ = true;
      initialized_ = true;
      return Status::error(StatusCode::IntegrityError,
                          "config journal generation ambiguous");
    }
    active_slot_ = newer;
    const Status adopted = adopt_record(parsed[newer]);
    if (!adopted) return adopted;
    has_active_ = true;
    if (parsed[newer].store_generation > floor_j ||
        parsed[newer].decision_revision > floor_r) {
      // The journal claims counters the floor never reserved: a violated
      // save order or a mis-seeded floor — stop, never mint from unknown
      // counters. Recovery resumes after managed floor re-provisioning.
      return quarantine(StatusCode::IntegrityError,
                        "config journal newer than security floor");
    }
    initialized_ = true;
    return resolve_recovered(now_ms);
  }

  if (valid == 1) {
    const std::uint8_t slot = content[0] == SlotContent::Valid ? 0 : 1;
    active_slot_ = slot;
    const Status adopted = adopt_record(parsed[slot]);
    if (!adopted) return adopted;
    has_active_ = true;
    if (parsed[slot].store_generation > floor_j ||
        parsed[slot].decision_revision > floor_r) {
      return quarantine(StatusCode::IntegrityError,
                        "config journal newer than security floor");
    }
    initialized_ = true;
    if (!provably_absent(static_cast<std::uint8_t>(slot ^ 1U))) {
      // One slot lost without proof it was never committed: the survivor is
      // a "known value" only — no revision confirmation, no intake (06 §6.3).
      uncertain_ = true;
      return Status::error(StatusCode::IntegrityError, "config journal storage uncertain");
    }
    return resolve_recovered(now_ms);
  }

  // No valid record survives.
  if (unreadable[0] || unreadable[1]) {
    return read_error;  // a storage fault, not proven corruption — retryable
  }
  if (foreign > 0) {
    return Status::error(StatusCode::Conflict, "config journal identity mismatch");
  }
  if (unsupported > 0) {
    return quarantine(StatusCode::Unsupported, "config journal schema unsupported");
  }
  if (corrupt > 0) {
    // Both slots unverifiable: never auto-reset to revision 0 — explicit
    // re-provisioning / a new trust generation is required (04 §4.7, C09).
    return quarantine(StatusCode::IntegrityError, "config journal corrupt");
  }

  // Fresh journal: all slots empty or pending-only. When the floor still
  // names consumed generations, the journal lost everything it decided —
  // adopt nothing, quarantine, and let the recovery lane re-provision
  // from the floor's J/R (never a silent return to revision 0).
  if (floor_j > 0 || floor_r > 0) {
    return quarantine(StatusCode::RecoveryRequired,
                      "config journal lost: security floor holds the counters");
  }
  active_snapshot_.clear();
  Status status = config_snapshot_hash(config_.config_namespace, config_.schema,
                                     active_snapshot_.view(), active_hash_);
  if (!status) return status;
  phase_ = ConfigPhase::Idle;
  initialized_ = true;
  return Status::success();
}

Status ConfigJournal::resolve_recovered(const MonotonicMs now_ms) noexcept {
  switch (phase_) {
    case ConfigPhase::Active:
      // Continuation of a decided configuration — restore the confirmed
      // snapshot, never a re-execution of an expired command (04 §4.7, C08).
      if (provider_ != nullptr) {
        boot_.restore_snapshot = durable_.next_snapshot;
        boot_.restore_pending = true;
        boot_.resolve = false;
      }
      return Status::success();
    case ConfigPhase::Interrupted:
      // The previous boot already restored prev; re-issue the idempotent
      // restore so the provider's actual state is reconfirmed.
      if (provider_ != nullptr && durable_.prev_snapshot.size > 0) {
        boot_.restore_snapshot = durable_.prev_snapshot;
        boot_.restore_pending = true;
        boot_.resolve = false;
      }
      return Status::success();
    case ConfigPhase::Decided: {
      // Revision stays consumed; the challenge is dead across the boot
      // change, so the first apply never happens — record the interruption.
      Transaction& txn = boot_txn();
      const Status stored =
          persist_phase(ConfigPhase::Interrupted, ConfigReason::Deadline, txn);
      if (!stored) {
        if (stored.code == StatusCode::CounterExhausted) quarantine_ram();
        return stored;
      }
      stats_.interrupted++;
      const Status recorded =
          record_result(txn, ConfigPhase::Interrupted, ConfigReason::Deadline, now_ms);
      return recorded.ok() ? Status::success() : recorded;
    }
    case ConfigPhase::ApplyIntent:
    case ConfigPhase::Applying:
    case ConfigPhase::Verifying:
      // The APPLY_INTENT..ACTIVE window: whether the apply took effect is
      // undecidable — restore the previous confirmed snapshot idempotently,
      // then record APPLY_INTERRUPTED (or quarantine when unrestorable).
      if (provider_ == nullptr) {
        return Status::error(StatusCode::RecoveryRequired,
                            "config apply interrupted without provider");
      }
      boot_.restore_snapshot = durable_.prev_snapshot;
      boot_.restore_pending = true;
      boot_.resolve = true;
      boot_.interrupt_reason = ConfigReason::ApplyInterrupted;
      return Status::success();
    case ConfigPhase::Quarantined:
      quarantined_ = true;
      return Status::error(StatusCode::IntegrityError, "config journal quarantined");
    default:
      return Status::success();
  }
}

Status ConfigJournal::handle_challenge_query(
    const endpoint::ControlChallengeQuery& query, const MonotonicMs now_ms,
    endpoint::EncodedServicePayload& out) noexcept {
  last_now_ms_ = now_ms;
  if (!initialized_ || quarantined_) {
    return Status::error(StatusCode::InvalidState, "config journal not accepting");
  }
  if (uncertain_) {
    // Storage is not proven: minting fresh challenges invites acceptance
    // work the journal is not allowed to perform until recover() runs.
    return Status::error(StatusCode::RecoveryRequired,
                        "config journal storage uncertain");
  }
  if (query.config_namespace != config_.config_namespace ||
      query.schema != config_.schema) {
    return Status::error(StatusCode::Unsupported, "config challenge schema mismatch");
  }
  // A fresh nonce128 per query. Each requester owns one slot keyed by
  // client_nonce — its re-query supersedes only its own challenge; a full
  // table of live challenges refuses Busy rather than evicting another
  // requester's in-flight challenge, which would let any member lock out
  // configuration by churning queries (rate+sender binding is the wire
  // contract's only constraint on who may ask).
  Challenge* slot = nullptr;
  Challenge* free_slot = nullptr;
  for (Challenge& candidate : challenges_) {
    if (candidate.outstanding && candidate.client_nonce == query.client_nonce) {
      slot = &candidate;
      break;
    }
    const bool expired = !candidate.outstanding ||
                         now_ms < candidate.issued_ms ||
                         now_ms - candidate.issued_ms > candidate.valid_for_ms;
    if (expired && free_slot == nullptr) {
      free_slot = &candidate;
    }
  }
  if (slot == nullptr) {
    slot = free_slot;
  }
  if (slot == nullptr) {
    return Status::error(StatusCode::Busy, "config challenge table full");
  }
  std::array<std::uint8_t, 16> nonce{};
  bool filled = false;
  for (int attempt = 0; attempt < 4 && !filled; ++attempt) {
    const Status status = entropy_.fill(MutableByteView{nonce.data(), nonce.size()});
    if (!status) return status;
    filled = !all_zero(ByteView{nonce.data(), nonce.size()});
  }
  if (!filled) {
    return Status::error(StatusCode::InternalError, "config challenge entropy failed");
  }
  slot->outstanding = true;
  slot->nonce = nonce;
  slot->client_nonce = query.client_nonce;
  slot->schema = query.schema;
  slot->issued_ms = now_ms;
  slot->valid_for_ms = config_.challenge_valid_ms;
  stats_.challenges_issued++;

  endpoint::ControlChallenge challenge{};
  challenge.config_namespace = config_.config_namespace;
  challenge.schema = config_.schema;
  challenge.client_nonce = query.client_nonce;
  challenge.target_boot = config_.boot_incarnation;
  challenge.challenge_nonce = nonce;
  challenge.revision = decision_revision_;
  challenge.active_hash = active_hash_;
  challenge.valid_for_ms = slot->valid_for_ms;
  return endpoint::control_challenge_encode(challenge, out);
}

const ConfigJournal::Challenge* ConfigJournal::find_challenge(
    const std::array<std::uint8_t, 16>& nonce) const noexcept {
  for (const Challenge& candidate : challenges_) {
    if (candidate.outstanding && candidate.nonce == nonce) {
      return &candidate;
    }
  }
  return nullptr;
}

Status ConfigJournal::handle_status_query(const endpoint::ControlStatusQuery& query,
                                          const MonotonicMs now_ms,
                                          endpoint::EncodedServicePayload& out) noexcept {
  last_now_ms_ = now_ms;
  if (!initialized_) {
    return Status::error(StatusCode::InvalidState, "config journal not initialized");
  }
  if (query.config_namespace != config_.config_namespace) {
    return Status::error(StatusCode::Unsupported, "config status namespace mismatch");
  }
  endpoint::ControlStatus status{};
  status.config_namespace = config_.config_namespace;
  status.operation_id = query.operation_id;
  if (txn_.active && txn_.command.operation_id == query.operation_id) {
    status.phase = phase_;
    status.reason = ConfigReason::InProgress;
    status.decision_revision = txn_.command.next_revision;
    status.active_revision = active_revision_;
    status.active_hash = active_hash_;
    return endpoint::control_status_encode(status, out);
  }
  if (has_active_ && durable_.operation_id == query.operation_id) {
    status.phase = durable_.phase;
    status.reason = durable_.reason == ConfigReason::Ok &&
                            durable_.phase != ConfigPhase::Active
                        ? ConfigReason::InProgress
                        : durable_.reason;
    status.decision_revision = durable_.decision_revision;
    status.active_revision = durable_.active_revision;
    status.active_hash = active_hash_;
    return endpoint::control_status_encode(status, out);
  }
  const ResultRecord* record = nullptr;
  if (find_result(query.operation_id, record)) {
    if (now_ms - record->stored_ms >= kConfigResultHoldMs) {
      // The result window closed: RESULT_EXPIRED goes ON THE WIRE as the
      // response's reason — a non-success return would drop the encoded
      // payload and leave the requester with nothing (05 §5.x, 06 §6.2:
      // unknown is never turned into success, but expiry IS the answer).
      status.phase = ConfigPhase::Idle;
      status.reason = ConfigReason::ResultExpired;
      status.decision_revision = record->decision_revision;
      status.active_revision = record->active_revision;
      status.active_hash = record->active_hash;
      return endpoint::control_status_encode(status, out);
    }
    status.phase = record->phase;
    status.reason = record->reason;
    status.decision_revision = record->decision_revision;
    status.active_revision = record->active_revision;
    status.active_hash = record->active_hash;
    return endpoint::control_status_encode(status, out);
  }
  return Status::error(StatusCode::NotFound, "config operation unknown");
}

Status ConfigJournal::note_object_manifest(
    const autonomy::ControlObjectPayload& manifest, const MonotonicMs now_ms) noexcept {
  last_now_ms_ = now_ms;
  if (!initialized_ || quarantined_) {
    return Status::error(StatusCode::InvalidState, "config journal not accepting");
  }
  if (uncertain_) {
    // Storage is not proven: a reassembly would only feed a permit the
    // journal must refuse anyway — do not consume intake resources.
    return Status::error(StatusCode::RecoveryRequired,
                        "config journal storage uncertain");
  }
  if (manifest.kind != autonomy::ControlObjectKind::ConfigPermit ||
      manifest.total_len == 0 || manifest.total_len > kConfigPermitObjectMax ||
      all_zero(ByteView{manifest.object_hash.data(), manifest.object_hash.size()})) {
    ++stats_.reassembly_rejects;
    return Status::error(StatusCode::ProtocolError, "config manifest invalid");
  }
  if (reassembly_.active) {
    if (reassembly_.manifest.object_hash == manifest.object_hash) {
      if (reassembly_.manifest.total_len == manifest.total_len) {
        return Status::success();  // same manifest re-delivered: idempotent
      }
      // Same object hash with a different declared length contradicts the
      // assembly in progress — a protocol violation, never re-ACKed.
      ++stats_.reassembly_rejects;
      return Status::error(StatusCode::Conflict, "config manifest length conflict");
    }
    ++stats_.reassembly_rejects;
    return Status::error(StatusCode::Busy, "config reassembly busy");
  }
  reassembly_.active = true;
  reassembly_.manifest = manifest;
  reassembly_.received.fill(0);
  reassembly_.received_count = 0;
  reassembly_.started_ms = now_ms;
  return Status::success();
}

Status ConfigJournal::note_object_chunk(const autonomy::ObjectChunkPayload& chunk,
                                        const MonotonicMs now_ms) noexcept {
  last_now_ms_ = now_ms;
  if (uncertain_ || quarantined_) {
    // Same gate as the manifest path: no intake while storage is unproven.
    ++stats_.reassembly_rejects;
    return Status::error(StatusCode::RecoveryRequired,
                        "config journal storage uncertain");
  }
  if (!reassembly_.active) {
    ++stats_.reassembly_rejects;
    return Status::error(StatusCode::InvalidState, "config chunk without manifest");
  }
  if (now_ms - reassembly_.started_ms > kConfigReassemblyTimeoutMs) {
    reassembly_.active = false;
    ++stats_.reassembly_rejects;
    return Status::error(StatusCode::Expired, "config reassembly timed out");
  }
  if (chunk.object_hash != reassembly_.manifest.object_hash || chunk.data_size == 0 ||
      static_cast<std::uint32_t>(chunk.offset) + chunk.data_size >
          reassembly_.manifest.total_len) {
    reassembly_.active = false;  // conflicting bytes poison the assembly
    ++stats_.reassembly_rejects;
    return Status::error(StatusCode::ProtocolError, "config chunk out of bounds");
  }
  for (std::uint16_t i = 0; i < chunk.data_size; ++i) {
    const std::uint16_t at = static_cast<std::uint16_t>(chunk.offset + i);
    const std::uint8_t mask = static_cast<std::uint8_t>(1U << (at & 7U));
    if ((reassembly_.received[at >> 3U] & mask) != 0) {
      if (reassembly_.buffer[at] != chunk.data[i]) {
        // Same offset, different bytes — reject the whole assembly (05 §5.5).
        reassembly_.active = false;
        ++stats_.reassembly_rejects;
        return Status::error(StatusCode::Conflict, "config chunk content conflict");
      }
      continue;
    }
    reassembly_.received[at >> 3U] = static_cast<std::uint8_t>(
        reassembly_.received[at >> 3U] | mask);
    reassembly_.buffer[at] = chunk.data[i];
    ++reassembly_.received_count;
  }
  if (reassembly_.received_count < reassembly_.manifest.total_len) {
    return Status::success();  // still assembling; ACK Ok = assembly only
  }
  return reassemble_complete(now_ms);
}

Status ConfigJournal::reassemble_complete(const MonotonicMs now_ms) noexcept {
  const std::uint16_t total = reassembly_.manifest.total_len;
  Digest256 digest{};
  sha256(ByteView{reassembly_.buffer.data(), total}, digest);
  if (!constant_time_equal(ByteView{digest.data(), digest.size()},
                           ByteView{reassembly_.manifest.object_hash.data(),
                                    reassembly_.manifest.object_hash.size()})) {
    reassembly_.active = false;
    ++stats_.reassembly_rejects;
    return Status::error(StatusCode::IntegrityError, "config object digest mismatch");
  }
  const ByteView permit{reassembly_.buffer.data(), total};
  reassembly_.active = false;
  ConfigVerdict verdict{};
  // Assembly is done; whether the permit applies is the journal's decision.
  const Status status = submit_permit(permit, now_ms, true, verdict);
  static_cast<void>(verdict);
  return status;
}

Status ConfigJournal::note_recovery_manifest(
    const autonomy::ControlObjectPayload& manifest, const MonotonicMs now_ms) noexcept {
  last_now_ms_ = now_ms;
  if (!initialized_) {
    return Status::error(StatusCode::InvalidState, "config journal not initialized");
  }
  // Deliberately NOT gated on quarantined_/uncertain_: this is the lane an
  // impaired journal still serves — the signed command itself decides
  // admissibility at submit time, transport acceptance grants nothing.
  if (manifest.kind != autonomy::ControlObjectKind::ConfigRecovery ||
      manifest.total_len == 0 || manifest.total_len > kConfigPermitObjectMax ||
      all_zero(ByteView{manifest.object_hash.data(), manifest.object_hash.size()})) {
    ++stats_.reassembly_rejects;
    return Status::error(StatusCode::ProtocolError, "config recovery manifest invalid");
  }
  if (recovery_reassembly_.active) {
    if (recovery_reassembly_.manifest.object_hash == manifest.object_hash) {
      if (recovery_reassembly_.manifest.total_len == manifest.total_len) {
        return Status::success();  // same manifest re-delivered: idempotent
      }
      ++stats_.reassembly_rejects;
      return Status::error(StatusCode::Conflict, "config recovery manifest conflict");
    }
    ++stats_.reassembly_rejects;
    return Status::error(StatusCode::Busy, "config recovery reassembly busy");
  }
  recovery_reassembly_.active = true;
  recovery_reassembly_.manifest = manifest;
  recovery_reassembly_.received.fill(0);
  recovery_reassembly_.received_count = 0;
  recovery_reassembly_.started_ms = now_ms;
  return Status::success();
}

Status ConfigJournal::note_recovery_chunk(const autonomy::ObjectChunkPayload& chunk,
                                          const MonotonicMs now_ms) noexcept {
  last_now_ms_ = now_ms;
  if (!recovery_reassembly_.active) {
    ++stats_.reassembly_rejects;
    return Status::error(StatusCode::InvalidState,
                        "config recovery chunk without manifest");
  }
  if (now_ms - recovery_reassembly_.started_ms > kConfigReassemblyTimeoutMs) {
    recovery_reassembly_.active = false;
    ++stats_.reassembly_rejects;
    return Status::error(StatusCode::Expired, "config recovery reassembly timed out");
  }
  if (chunk.object_hash != recovery_reassembly_.manifest.object_hash ||
      chunk.data_size == 0 ||
      static_cast<std::uint32_t>(chunk.offset) + chunk.data_size >
          recovery_reassembly_.manifest.total_len) {
    recovery_reassembly_.active = false;  // conflicting bytes poison the assembly
    ++stats_.reassembly_rejects;
    return Status::error(StatusCode::ProtocolError, "config recovery chunk out of bounds");
  }
  for (std::uint16_t i = 0; i < chunk.data_size; ++i) {
    const std::uint16_t at = static_cast<std::uint16_t>(chunk.offset + i);
    const std::uint8_t mask = static_cast<std::uint8_t>(1U << (at & 7U));
    if ((recovery_reassembly_.received[at >> 3U] & mask) != 0) {
      if (recovery_reassembly_.buffer[at] != chunk.data[i]) {
        recovery_reassembly_.active = false;
        ++stats_.reassembly_rejects;
        return Status::error(StatusCode::Conflict,
                            "config recovery chunk content conflict");
      }
      continue;
    }
    recovery_reassembly_.received[at >> 3U] = static_cast<std::uint8_t>(
        recovery_reassembly_.received[at >> 3U] | mask);
    recovery_reassembly_.buffer[at] = chunk.data[i];
    ++recovery_reassembly_.received_count;
  }
  if (recovery_reassembly_.received_count < recovery_reassembly_.manifest.total_len) {
    return Status::success();  // still assembling; ACK Ok = assembly only
  }
  return recovery_reassemble_complete(now_ms);
}

Status ConfigJournal::recovery_reassemble_complete(const MonotonicMs now_ms) noexcept {
  const std::uint16_t total = recovery_reassembly_.manifest.total_len;
  Digest256 digest{};
  sha256(ByteView{recovery_reassembly_.buffer.data(), total}, digest);
  if (!constant_time_equal(
          ByteView{digest.data(), digest.size()},
          ByteView{recovery_reassembly_.manifest.object_hash.data(),
                   recovery_reassembly_.manifest.object_hash.size()})) {
    recovery_reassembly_.active = false;
    ++stats_.reassembly_rejects;
    return Status::error(StatusCode::IntegrityError,
                        "config recovery object digest mismatch");
  }
  const ByteView object{recovery_reassembly_.buffer.data(), total};
  recovery_reassembly_.active = false;
  ConfigVerdict verdict{};
  // Assembly is done; whether the recovery command applies is the
  // journal's decision — the ObjectAck Ok meant transport only.
  const Status status = submit_recovery(object, now_ms, verdict);
  static_cast<void>(verdict);
  return status;
}

Status ConfigJournal::submit_recovery(const ByteView object, const MonotonicMs now_ms,
                                      ConfigVerdict& verdict) noexcept {
  verdict = ConfigVerdict{};
  last_now_ms_ = now_ms;
  if (!initialized_) {
    return Status::error(StatusCode::InvalidState, "config journal not initialized");
  }
  if (object.size == 0 || object.size > kConfigPermitObjectMax || object.data == nullptr) {
    fill_verdict(verdict, phase_, ConfigReason::InvalidPatch);
    return Status::error(StatusCode::InvalidArgument, "config recovery size invalid");
  }

  ConfigPermitContext context{};
  context.network = config_.network;
  context.target = config_.target;
  context.config_namespace = config_.config_namespace;
  context.authorized_issuer = config_.authorized_issuer;
  // The deployed pin for fixed-profile verifiers; the trust view ignores
  // it and resolves the signer generation from the live image + floor.
  context.authority_generation = config_.authority_generation;
  endpoint::EncodedRecoveryCommand& canonical = recovery_canonical_;
  bool verified = false;
  // The shared expensive-verify intake gate — same device-level bound as
  // the permit path; a recovery storm cannot monopolize the Owner either.
  if (verifier_.verify_is_expensive() &&
      !rate_limiter_.consume_expensive_verify(now_ms)) {
    fill_verdict(verdict, phase_, ConfigReason::Capacity);
    ++stats_.verify_intake_refusals;
    return Status::error(StatusCode::Busy, "recovery verify intake budget");
  }
  Status status = verifier_.verify_recovery(context, object, canonical, verified);
  if (!status) {
    fill_verdict(verdict, phase_, ConfigReason::AuthorityDenied);
    ++stats_.permits_denied;
    return status;
  }
  if (!verified) {
    fill_verdict(verdict, phase_, ConfigReason::AuthorityDenied);
    ++stats_.permits_denied;
    return Status::error(StatusCode::AuthenticationFailed,
                        "config recovery unverified");
  }
  ++stats_.permits_verified;
  // The policy epoch this verdict was verified under — re-checked before
  // the floor reservation commits the recovery (same rotation race as the
  // permit path's DECIDED recheck).
  const std::uint32_t verify_epoch = verifier_.policy_epoch();

  endpoint::ConfigRecoveryCommand& command = recovery_command_;
  status = endpoint::config_recovery_decode(canonical.view(), command);
  if (!status) {
    fill_verdict(verdict, phase_, ConfigReason::InvalidPatch);
    return status;
  }
  Digest256 digest{};
  sha256(canonical.view(), digest);

  // Identity + authorization scope (04 §4.3): the journal checks these on
  // its own — the signature only proves the issuer signed the command.
  // The generation gate is the verifier's live policy (fixed profiles
  // pin to the deployed generation, the trust view serves the RLT1/RLF1
  // floor): a recovery signed under an unserved generation is denied.
  if (command.network != config_.network || command.target != config_.target ||
      command.config_namespace != config_.config_namespace ||
      command.schema != config_.schema ||
      command.authority != config_.authorized_issuer ||
      !verifier_.generation_permitted(command.authority_generation,
                                      config_.authority_generation)) {
    fill_verdict(verdict, phase_, ConfigReason::AuthorityDenied);
    ++stats_.permits_denied;
    return Status::error(StatusCode::AuthorizationFailed,
                        "config recovery scope denied");
  }

  // Idempotency: same operation id + same canonical digest returns the
  // recorded verdict; same id with different content is CONFLICT.
  const ResultRecord* prior = nullptr;
  if (find_result(command.operation_id, prior)) {
    if (prior->command_digest == digest) {
      fill_verdict(verdict, prior->phase, prior->reason);
      return Status::success();  // replayed delivery of an applied command
    }
    fill_verdict(verdict, prior->phase, prior->reason);
    ++stats_.conflicts;
    return Status::error(StatusCode::Conflict, "config recovery opid conflict");
  }
  // Result-table capacity — the same bound permit intake honors: a full
  // table refuses rather than evicting a verdict a status query still owes.
  bool any_free = false;
  for (const ResultRecord& record : results_) {
    if (!record.used || now_ms - record.stored_ms >= kConfigResultHoldMs) {
      any_free = true;
      break;
    }
  }
  if (!any_free) {
    fill_verdict(verdict, phase_, ConfigReason::Capacity);
    return Status::error(StatusCode::NoCapacity, "config result table full");
  }

  if (command.recovery_class == endpoint::ConfigRecoveryClass::StoreRecover) {
    // The store-recovery ceremony exists only for an impaired journal —
    // on a proven store it could mint a generation nobody needed.
    if (!uncertain_ && !quarantined_) {
      fill_verdict(verdict, phase_, ConfigReason::Unsupported);
      return Status::error(StatusCode::InvalidState,
                          "config store recovery needs an impaired journal");
    }
    // The policy must be the one the signature verified under.
    if (verifier_.policy_epoch() != verify_epoch || !verifier_.ready()) {
      fill_verdict(verdict, phase_, ConfigReason::AuthorityDenied);
      ++stats_.permits_denied;
      return Status::error(StatusCode::AuthorizationFailed,
                          "config authority policy moved during submit");
    }
    status = recover(command.new_store_generation, now_ms,
                     command.attest == endpoint::kRcr1AttestReprovision);
    if (!status) {
      fill_verdict(verdict, phase_, ConfigReason::RecoveryRequired);
      return status;
    }
    const Status recorded =
        record_recovery_result(command, digest, phase_, ConfigReason::Ok, now_ms);
    fill_verdict(verdict, phase_, ConfigReason::Ok);
    return recorded.ok() ? Status::success() : recorded;
  }

  // No other recovery class exists: authority generation changes arrive
  // as root-authorized trust updates (RTM1), never on this lane.
  fill_verdict(verdict, phase_, ConfigReason::Unsupported);
  return Status::error(StatusCode::Unsupported,
                      "config recovery class unsupported");
}

Status ConfigJournal::record_recovery_result(
    const endpoint::ConfigRecoveryCommand& command, const Digest256& digest,
    const endpoint::ConfigPhase phase, const endpoint::ConfigReason reason,
    const MonotonicMs now_ms) noexcept {
  ResultRecord* slot = nullptr;
  ResultRecord* expired_slot = nullptr;
  for (ResultRecord& candidate : results_) {
    if (!candidate.used) {
      if (slot == nullptr) slot = &candidate;
      continue;
    }
    if (now_ms - candidate.stored_ms >= kConfigResultHoldMs && expired_slot == nullptr) {
      expired_slot = &candidate;
    }
  }
  if (slot == nullptr) slot = expired_slot;
  if (slot == nullptr) {
    return Status::error(StatusCode::NoCapacity, "config result table full");
  }
  *slot = ResultRecord{};
  slot->used = true;
  slot->operation_id = command.operation_id;
  slot->command_digest = digest;
  slot->phase = phase;
  slot->reason = reason;
  slot->decision_revision = decision_revision_;
  slot->active_revision = active_revision_;
  slot->active_hash = active_hash_;
  slot->stored_ms = now_ms;
  return Status::success();
}

Status ConfigJournal::validate_command(const endpoint::ConfigCommand& command,
                                       const Digest256& digest, const MonotonicMs now_ms,
                                       const bool clock_known,
                                       ConfigVerdict& verdict) noexcept {
  static_cast<void>(digest);
  // Identity + authorization scope (04 §4.3): the target checks these on
  // its own — the permit signature only proves the issuer signed it. The
  // generation gate is the verifier's live policy (fixed profiles pin to
  // the deployed generation, the trust view serves the RLT1/RLF1 floor).
  if (command.network != config_.network || command.target != config_.target ||
      command.config_namespace != config_.config_namespace ||
      command.schema != config_.schema ||
      command.authority != config_.authorized_issuer ||
      !verifier_.generation_permitted(command.authority_generation,
                                      config_.authority_generation)) {
    fill_verdict(verdict, ConfigPhase::Idle, ConfigReason::AuthorityDenied);
    ++stats_.permits_denied;
    return Status::error(StatusCode::AuthorizationFailed, "config scope denied");
  }
  // Challenge binding (04 §4.4): nonce + this boot + local elapsed only.
  // The permit must match SOME outstanding challenge slot — the nonce is
  // unpredictable to anyone but the requester it was issued to.
  const Challenge* challenge = find_challenge(command.challenge_nonce);
  if (challenge == nullptr ||
      config_.boot_incarnation != command.target_boot) {
    fill_verdict(verdict, ConfigPhase::Idle, ConfigReason::AuthorityDenied);
    ++stats_.permits_denied;
    return Status::error(StatusCode::AuthorizationFailed, "config challenge mismatch");
  }
  const MonotonicMs elapsed = now_ms >= challenge->issued_ms
                                 ? now_ms - challenge->issued_ms
                                 : UINT64_MAX;
  if (!clock_known || elapsed > challenge->valid_for_ms ||
      elapsed > command.apply_within_ms) {
    fill_verdict(verdict, ConfigPhase::Idle, ConfigReason::Deadline);
    return Status::error(StatusCode::Expired, "config challenge expired");
  }
  // CAS on the per-target revision. The codec already guarantees
  // next_revision == expected_revision + 1 and expected != UINT64_MAX in
  // both encode and decode, so only the CAS needs checking here; the
  // authority_sequence is deliberately NOT enforced — §4.3 gives it no
  // target-side ordering semantics (the ledger's global sequence has
  // holes from other consumers; the issuer's signature already binds it).
  if (command.expected_revision != decision_revision_) {
    fill_verdict(verdict, ConfigPhase::Idle, ConfigReason::StaleRevision);
    ++stats_.stale_revision;
    return Status::error(StatusCode::Conflict,
                        command.expected_revision < decision_revision_
                            ? "config revision stale"
                            : "config revision from the future");
  }
  if (command.base_snapshot_hash != active_hash_) {
    fill_verdict(verdict, ConfigPhase::Idle, ConfigReason::BaseHashMismatch);
    return Status::error(StatusCode::Conflict, "config base hash mismatch");
  }
  return Status::success();
}

Status ConfigJournal::submit_permit(const ByteView permit, const MonotonicMs now_ms,
                                    const bool clock_known,
                                    ConfigVerdict& verdict) noexcept {
  verdict = ConfigVerdict{};
  last_now_ms_ = now_ms;
  if (!initialized_) {
    return Status::error(StatusCode::InvalidState, "config journal not initialized");
  }
  if (quarantined_) {
    fill_verdict(verdict, ConfigPhase::Quarantined, ConfigReason::RecoveryRequired);
    return Status::error(StatusCode::IntegrityError, "config journal quarantined");
  }
  if (uncertain_) {
    fill_verdict(verdict, phase_, ConfigReason::RecoveryRequired);
    return Status::error(StatusCode::RecoveryRequired, "config journal storage uncertain");
  }
  if (permit.size == 0 || permit.size > kConfigPermitObjectMax || permit.data == nullptr) {
    fill_verdict(verdict, ConfigPhase::Idle, ConfigReason::InvalidPatch);
    return Status::error(StatusCode::InvalidArgument, "config permit size invalid");
  }

  // The canonical decode buffer, the decoded command and the in-build
  // transaction are member scratch (~7 KB of .bss, not task stack);
  // submit_txn_ is reset here so every early return leaves txn_ untouched.
  submit_txn_ = Transaction{};
  ConfigPermitContext context{};
  context.network = config_.network;
  context.target = config_.target;
  context.config_namespace = config_.config_namespace;
  context.authorized_issuer = config_.authorized_issuer;
  // The deployed pin for fixed-profile verifiers; the trust view ignores
  // it and resolves the signer generation from the live image + floor.
  context.authority_generation = config_.authority_generation;
  endpoint::EncodedConfigCommand& canonical = submit_txn_.canonical;
  bool verified = false;
  // Pre-verification intake limiter (03-signing §3.3): one expensive
  // verification start per 5 s, burst 1 — charged before ANY signature work
  // so invalid-but-well-formed permits cannot monopolize the Owner. The
  // token lives in the SHARED rate limiter: this is a device-level gate
  // across every attached journal — no per-namespace bypass. A refusal is
  // CAPACITY, not a denial — it consumes no revision and no acceptance
  // budget.
  if (verifier_.verify_is_expensive() &&
      !rate_limiter_.consume_expensive_verify(now_ms)) {
    fill_verdict(verdict, ConfigPhase::Idle, ConfigReason::Capacity);
    ++stats_.verify_intake_refusals;
    return Status::error(StatusCode::Busy, "permit verify intake budget");
  }
  Status status = verifier_.verify_permit(context, permit, canonical, verified);
  if (!status) {
    fill_verdict(verdict, ConfigPhase::Idle, ConfigReason::AuthorityDenied);
    ++stats_.permits_denied;
    return status;
  }
  if (!verified) {
    fill_verdict(verdict, ConfigPhase::Idle, ConfigReason::AuthorityDenied);
    ++stats_.permits_denied;
    return Status::error(StatusCode::AuthenticationFailed, "config permit unverified");
  }
  ++stats_.permits_verified;
  // The policy epoch this verdict was verified under — re-checked before
  // the DECIDED commit so a rotation landing in between (a provider
  // callback reentering the trust store, a future async verifier) cannot
  // smuggle an old-epoch verdict into a new-epoch decision.
  const std::uint32_t verify_epoch = verifier_.policy_epoch();

  endpoint::ConfigCommand& command = submit_txn_.command;
  status = endpoint::config_command_decode(canonical.view(), command);
  if (!status) {
    fill_verdict(verdict, ConfigPhase::Idle, ConfigReason::InvalidPatch);
    return status;
  }
  Digest256 digest{};
  sha256(canonical.view(), digest);

  // Idempotency: same id + same canonical digest returns the stored
  // progress/result; same id + different content is CONFLICT.
  if (txn_.active && txn_.command.operation_id == command.operation_id) {
    if (digest == txn_.command_digest) {
      fill_verdict(verdict, phase_, ConfigReason::InProgress);
      return Status::success();
    }
    fill_verdict(verdict, phase_, ConfigReason::InProgress);
    ++stats_.conflicts;
    return Status::error(StatusCode::Conflict, "config operation id conflict");
  }
  const ResultRecord* prior = nullptr;
  if (find_result(command.operation_id, prior)) {
    if (prior->command_digest == digest) {
      if (now_ms - prior->stored_ms >= kConfigResultHoldMs) {
        fill_verdict(verdict, ConfigPhase::Idle, ConfigReason::ResultExpired);
        return Status::error(StatusCode::NotFound, "config result expired");
      }
      verdict.phase = prior->phase;
      verdict.reason = prior->reason;
      verdict.decision_revision = prior->decision_revision;
      verdict.active_revision = prior->active_revision;
      verdict.active_hash = prior->active_hash;
      return Status::success();
    }
    fill_verdict(verdict, prior->phase, prior->reason);
    ++stats_.conflicts;
    return Status::error(StatusCode::Conflict, "config operation id conflict");
  }
  // One active transaction per journal.
  if (txn_.active || boot_.restore_pending) {
    fill_verdict(verdict, ConfigPhase::Idle, ConfigReason::InProgress);
    return Status::error(StatusCode::Busy, "config transaction busy");
  }
  // Result-table capacity: full of unexpired records refuses new intake —
  // protected records are never evicted for acceptance rate (06 §6.2/9).
  bool any_free = false;
  for (const ResultRecord& record : results_) {
    if (!record.used || now_ms - record.stored_ms >= kConfigResultHoldMs) {
      any_free = true;
      break;
    }
  }
  if (!any_free) {
    fill_verdict(verdict, ConfigPhase::Idle, ConfigReason::Capacity);
    return Status::error(StatusCode::NoCapacity, "config result table full");
  }

  status = validate_command(command, digest, now_ms, clock_known, verdict);
  if (!status) return status;

  // Compute the next snapshot and re-check the signed hash claim.
  Transaction& txn = submit_txn_;
  bool changed = false;
  status = config_patch_merge(active_snapshot_.view(), command.fields.data(),
                              command.field_count, merge_a_.data(), merge_b_.data(),
                              txn.next_snapshot, changed);
  if (!status) {
    fill_verdict(verdict, ConfigPhase::Idle, ConfigReason::InvalidPatch);
    return Status::error(StatusCode::InvalidArgument, "config patch rejected");
  }
  status = config_snapshot_hash(config_.config_namespace, config_.schema,
                                txn.next_snapshot.view(), txn.next_hash);
  if (!status) return status;
  if (txn.next_hash != command.next_snapshot_hash) {
    fill_verdict(verdict, ConfigPhase::Idle, ConfigReason::InvalidPatch);
    return Status::error(StatusCode::Conflict, "config next hash mismatch");
  }
  if (!changed) {
    // A no-op patch never reaches DECIDED: no revision, no flash write.
    fill_verdict(verdict, ConfigPhase::Idle, ConfigReason::NoChange);
    ++stats_.no_change;
    return Status::error(StatusCode::AlreadyExists, "config patch no-op");
  }
  txn.active = true;
  txn.command_digest = digest;
  txn.permit.size = permit.size;
  std::memcpy(txn.permit.bytes.data(), permit.data, permit.size);
  txn.prev_snapshot = active_snapshot_;

  // Registered schema rules per patch field (SDK rules or the app schema).
  for (std::uint16_t i = 0; i < command.field_count; ++i) {
    const ConfigField& field = command.fields[i];
    const Status valid =
        validator_ != nullptr ? validator_->validate_field(field)
                              : config_sdk_field_validate(field);
    if (!valid) {
      fill_verdict(verdict, ConfigPhase::Idle, ConfigReason::InvalidPatch);
      return valid;
    }
  }

  if (provider_ == nullptr) {
    fill_verdict(verdict, ConfigPhase::Idle, ConfigReason::Unsupported);
    return Status::error(StatusCode::Unsupported, "config provider missing");
  }
  status = provider_->validate(config_.config_namespace, config_.schema,
                               txn.next_snapshot.view());
  if (!status) {
    fill_verdict(verdict, ConfigPhase::Idle, ConfigReason::InvalidPatch);
    return status;
  }
  status = provider_->prepare(config_.config_namespace, config_.schema,
                              txn.next_snapshot.view());
  if (!status) {
    fill_verdict(verdict, ConfigPhase::Idle, ConfigReason::InvalidPatch);
    return status;
  }

  // Maintenance/admission boundary for management-path-removing changes
  // (04 §4.8): detect transitions against the current snapshot.
  {
    ConfigField* const base_fields = fields_a_.data();
    ConfigField* const next_fields = fields_b_.data();
    std::uint16_t base_count = 0, next_count = 0;
    status = config_tlv_decode(active_snapshot_.view(), base_fields,
                               endpoint::kConfigFieldCountMax, base_count);
    if (!status) return status;
    status = config_tlv_decode(txn.next_snapshot.view(), next_fields,
                               endpoint::kConfigFieldCountMax, next_count);
    if (!status) return status;
    std::uint8_t base_v = 0, next_v = 0;
    ConfigMaintenanceCheck check{};
    check.config_namespace = config_.config_namespace;
    check.target = config_.target;
    check.now_ms = now_ms;
    // An absent field is treated as enabled: erring toward consulting the
    // gate is the safe side of the maintenance boundary.
    const bool base_disc = !field_u8(base_fields, base_count, 2, base_v) || base_v != 0;
    const bool next_disc = !field_u8(next_fields, next_count, 2, next_v) || next_v != 0;
    check.discovery_disabling = base_disc && !next_disc;
    const bool base_relay = !field_u8(base_fields, base_count, 3, base_v) || base_v != 0;
    const bool next_relay = !field_u8(next_fields, next_count, 3, next_v) || next_v != 0;
    check.relay_disabling = base_relay && !next_relay;
    const std::uint8_t base_mig =
        field_u8(base_fields, base_count, 4, base_v) ? base_v : 0;
    const std::uint8_t next_mig =
        field_u8(next_fields, next_count, 4, next_v) ? next_v : 0;
    check.migration_changing = base_mig != next_mig;
    if (check.discovery_disabling || check.relay_disabling ||
        check.migration_changing) {
      if (gate_ == nullptr) {
        // No boundary installed: a management-path-removing change is
        // refused by default — the initial profile never lets the only
        // admin path disappear (04 §4.8).
        fill_verdict(verdict, ConfigPhase::Idle, ConfigReason::AuthorityDenied);
        ++stats_.maintenance_refusals;
        return Status::error(StatusCode::AuthorizationFailed,
                            "config unsafe change without gate");
      }
      const Status allowed = gate_->check(check);
      if (!allowed) {
        const ConfigReason reason =
            allowed.code == StatusCode::Busy ? ConfigReason::MaintenanceBusy
            : allowed.code == StatusCode::NoCapacity ? ConfigReason::Capacity
                                                     : ConfigReason::AuthorityDenied;
        fill_verdict(verdict, ConfigPhase::Idle, reason);
        ++stats_.maintenance_refusals;
        return allowed;
      }
    }
  }

  // Acceptance budget: 1/min + burst 1 per target (last gate before DECIDED).
  if (!rate_limiter_.consume(now_ms)) {
    fill_verdict(verdict, ConfigPhase::Idle, ConfigReason::Capacity);
    ++stats_.rate_refusals;
    return Status::error(StatusCode::Busy, "config acceptance budget exhausted");
  }

  // The policy must be the one the signature verified under: re-check
  // the epoch (and liveness) captured above before the DECIDED commit.
  if (verifier_.policy_epoch() != verify_epoch || !verifier_.ready()) {
    rate_limiter_.refund();
    fill_verdict(verdict, ConfigPhase::Idle, ConfigReason::AuthorityDenied);
    ++stats_.permits_denied;
    return Status::error(StatusCode::AuthorizationFailed,
                        "config authority policy moved during submit");
  }
  // PREPARED -> DECIDED: persist before the phase is real. The revision is
  // consumed here and never returned, even if apply later fails.
  status = persist_phase(ConfigPhase::Decided, ConfigReason::Ok, txn);
  if (!status) {
    // The seal never landed: nothing was accepted, so the consumed token
    // goes back — a refusal consumes no budget.
    rate_limiter_.refund();
    if (status.code == StatusCode::CounterExhausted) {
      quarantine_ram();
      fill_verdict(verdict, ConfigPhase::Quarantined,
                   ConfigReason::RecoveryRequired);
      return status;
    }
    fill_verdict(verdict, ConfigPhase::Idle, ConfigReason::StorageFailure);
    ++stats_.storage_failures;
    return status;
  }
  decision_revision_ = command.next_revision;

  // APPLY_INTENT persistence and the provider apply defer to poll(): this
  // handler runs on the radio RX path, where a journal record is a full
  // write-seal-readback cycle and the apply itself must never execute.
  // The apply-window deadline is re-checked in poll at the true apply
  // time; a power cut in between leaves a durable DECIDED that a boot
  // interrupts — the same safe outcome.
  const Challenge* challenge = find_challenge(command.challenge_nonce);
  txn.challenge_issued_ms =
      challenge != nullptr ? challenge->issued_ms : UINT64_MAX;
  txn.intent_pending = true;
  txn_ = txn;
  ++stats_.accepted;
  fill_verdict(verdict, phase_, ConfigReason::InProgress);
  return Status::success();
}

Status ConfigJournal::start_restore(Transaction& txn, const ConfigReason reason) noexcept {
  txn.fail_reason = reason;
  if (provider_ == nullptr) {
    return finish_transaction(txn, ConfigPhase::Quarantined,
                              ConfigReason::RecoveryRequired);
  }
  OperationToken token{kInvalidOperationToken};
  const Status status =
      provider_->restore(config_.config_namespace, txn.prev_snapshot.view(), token);
  if (!status) {
    return finish_transaction(txn, ConfigPhase::Quarantined,
                              ConfigReason::RecoveryRequired);
  }
  txn.applying = false;
  txn.restoring = true;
  txn.token = token;
  phase_ = ConfigPhase::Applying;  // still inside the durable APPLY_INTENT record
  return Status::success();
}

Status ConfigJournal::finish_transaction(Transaction& txn, const ConfigPhase phase,
                                         const ConfigReason reason) noexcept {
  const Status stored = persist_phase(phase, reason, txn);
  if (!stored) {
    if (stored.code == StatusCode::CounterExhausted) {
      // No generation will ever be nameable again: retrying is pointless,
      // so the live state wedges honestly instead of spinning on poll().
      quarantine_ram();
      return stored;
    }
    // The durable record still says APPLY_INTENT (or DECIDED): a boot
    // restores and interrupts, which is the same safe outcome. For the
    // live transaction — AND for the boot-resolution scratch transaction —
    // retry the terminal write on the next poll rather than dropping it:
    // a dropped boot-resolution write would leave the durable record
    // forever APPLY_INTENT while in-memory phase already moved on.
    txn.pending_phase = phase;
    txn.pending_reason = reason;
    txn.pending_persist = true;
    ++stats_.storage_failures;
    return stored;
  }
  if (phase == ConfigPhase::Active) {
    active_revision_ = txn.command.next_revision;
    active_snapshot_ = txn.next_snapshot;
    active_hash_ = txn.next_hash;
    stats_.applies++;
  } else if (phase == ConfigPhase::Interrupted) {
    stats_.interrupted++;
  } else if (phase == ConfigPhase::Quarantined) {
    quarantined_ = true;
    ++stats_.quarantine_events;
  }
  const Status recorded = record_result(txn, phase, reason, last_now_ms_);
  txn.active = false;
  txn.applying = false;
  txn.restoring = false;
  txn.pending_persist = false;
  txn.intent_pending = false;
  return recorded.ok() ? Status::success() : recorded;
}

void ConfigJournal::quarantine_ram() noexcept {
  quarantined_ = true;
  phase_ = ConfigPhase::Quarantined;
  txn_.active = false;
  txn_.intent_pending = false;
  txn_.pending_persist = false;
  ++stats_.quarantine_events;
}

void ConfigJournal::poll(const MonotonicMs now_ms) noexcept {
  last_now_ms_ = now_ms;
  if (reassembly_.active &&
      now_ms - reassembly_.started_ms > kConfigReassemblyTimeoutMs) {
    reassembly_.active = false;
    ++stats_.reassembly_rejects;
  }
  if (recovery_reassembly_.active &&
      now_ms - recovery_reassembly_.started_ms > kConfigReassemblyTimeoutMs) {
    recovery_reassembly_.active = false;
    ++stats_.reassembly_rejects;
  }
  // Deferred terminal persist retry (storage fault at finish_transaction).
  if (txn_.active && txn_.pending_persist) {
    const ConfigPhase phase = txn_.pending_phase;
    const ConfigReason reason = txn_.pending_reason;
    txn_.pending_persist = false;
    const Status stored = finish_transaction(txn_, phase, reason);
    static_cast<void>(stored);
    return;
  }
  if (boot_txn_.active && boot_txn_.pending_persist) {
    // Same retry for the boot-resolution scratch transaction: its terminal
    // write faulted after restore_pending was already cleared.
    const ConfigPhase phase = boot_txn_.pending_phase;
    const ConfigReason reason = boot_txn_.pending_reason;
    boot_txn_.pending_persist = false;
    const Status stored = finish_transaction(boot_txn_, phase, reason);
    static_cast<void>(stored);
    return;
  }
  // Boot-time restore resolution.
  if (boot_.restore_pending && provider_ != nullptr) {
    if (!boot_.restore_started) {
      OperationToken token{kInvalidOperationToken};
      const Status started = provider_->restore(config_.config_namespace,
                                                boot_.restore_snapshot.view(), token);
      if (!started) {
        boot_.restore_pending = false;
        Transaction& txn = boot_txn();
        const Status stored = finish_transaction(
            txn, ConfigPhase::Quarantined, ConfigReason::RecoveryRequired);
        static_cast<void>(stored);
        return;
      }
      boot_.restore_started = true;
      boot_.token = token;
    }
    bool done = false;
    Status outcome = Status::success();
    const Status polled = provider_->poll(boot_.token, done, outcome);
    if (!polled || !done) return;
    boot_.restore_pending = false;
    auto& active = readback_;
    active.fill(0);
    std::size_t active_size = 0;
    const Status read = provider_->read_active(
        config_.config_namespace, MutableByteView{active.data(), active.size()},
        active_size);
    const bool restored =
        read.ok() && outcome.ok() && active_size == boot_.restore_snapshot.size &&
        std::memcmp(active.data(), boot_.restore_snapshot.bytes.data(), active_size) == 0;
    if (restored && boot_.resolve) {
      Transaction& txn = boot_txn();
      const Status stored = finish_transaction(
          txn, ConfigPhase::Interrupted, boot_.interrupt_reason);
      static_cast<void>(stored);
    } else if (!restored) {
      // Whether resolving an APPLY_INTENT window or reconfirming an ACTIVE
      // configuration, an unrestorable state is never silently continued.
      Transaction& txn = boot_txn();
      const Status stored = finish_transaction(
          txn, ConfigPhase::Quarantined, ConfigReason::RecoveryRequired);
      static_cast<void>(stored);
    }
    return;
  }
  if (!txn_.active || provider_ == nullptr) return;

  // Deferred APPLY_INTENT + apply kickoff (submit_permit returns right
  // after DECIDED — the radio RX path never performs the intent commit or
  // the provider call). The apply-window deadline is re-checked NOW, at
  // the true apply time, against the consumed challenge's issue instant.
  if (txn_.intent_pending) {
    const MonotonicMs elapsed = now_ms >= txn_.challenge_issued_ms
                                    ? now_ms - txn_.challenge_issued_ms
                                    : UINT64_MAX;
    if (elapsed > txn_.command.apply_within_ms) {
      const Status finished =
          finish_transaction(txn_, ConfigPhase::Interrupted, ConfigReason::Deadline);
      static_cast<void>(finished);
      return;
    }
    const Status stored =
        persist_phase(ConfigPhase::ApplyIntent, ConfigReason::Ok, txn_);
    if (!stored) {
      if (stored.code == StatusCode::CounterExhausted) {
        // The DECIDED record is durable but no further record can ever
        // commit: wedge honestly instead of retrying the intent forever.
        quarantine_ram();
        return;
      }
      // The DECIDED record is durable and safe — a later boot interrupts
      // it; the intent write retries on the next poll.
      ++stats_.storage_failures;
      return;
    }
    txn_.intent_pending = false;
    OperationToken token{kInvalidOperationToken};
    const Status applied = provider_->apply(config_.config_namespace,
                                            txn_.next_snapshot.view(), token);
    if (!applied) {
      const Status restore = start_restore(txn_, ConfigReason::ApplyInterrupted);
      static_cast<void>(restore);
      return;
    }
    txn_.applying = true;
    txn_.token = token;
    phase_ = ConfigPhase::Applying;
    return;
  }

  if (txn_.applying) {
    bool done = false;
    Status outcome = Status::success();
    const Status polled = provider_->poll(txn_.token, done, outcome);
    if (!polled || !done) return;
    if (!outcome) {
      const Status restore =
          start_restore(txn_, ConfigReason::ApplyInterrupted);
      static_cast<void>(restore);
      return;
    }
    // VERIFYING: real active values must match the desired snapshot —
    // log strings are never proof (04 §4.6).
    phase_ = ConfigPhase::Verifying;
    auto& active = readback_;
    active.fill(0);
    std::size_t active_size = 0;
    const Status read = provider_->read_active(
        config_.config_namespace, MutableByteView{active.data(), active.size()},
        active_size);
    const bool matched =
        read.ok() && active_size == txn_.next_snapshot.size &&
        std::memcmp(active.data(), txn_.next_snapshot.bytes.data(), active_size) == 0;
    if (matched) {
      const Status finished =
          finish_transaction(txn_, ConfigPhase::Active, ConfigReason::Ok);
      static_cast<void>(finished);
    } else {
      const Status restore = start_restore(txn_, ConfigReason::VerifyFailed);
      static_cast<void>(restore);
    }
    return;
  }

  if (txn_.restoring) {
    bool done = false;
    Status outcome = Status::success();
    const Status polled = provider_->poll(txn_.token, done, outcome);
    if (!polled || !done) return;
    auto& active = readback_;
    active.fill(0);
    std::size_t active_size = 0;
    const Status read = provider_->read_active(
        config_.config_namespace, MutableByteView{active.data(), active.size()},
        active_size);
    const bool restored =
        read.ok() && outcome.ok() && active_size == txn_.prev_snapshot.size &&
        std::memcmp(active.data(), txn_.prev_snapshot.bytes.data(), active_size) == 0;
    const Status finished = finish_transaction(
        txn_, restored ? ConfigPhase::Interrupted : ConfigPhase::Quarantined,
        restored ? txn_.fail_reason : ConfigReason::RecoveryRequired);
    static_cast<void>(finished);
  }
}

ConfigJournal::Transaction& ConfigJournal::boot_txn() noexcept {
  Transaction& txn = boot_txn_;
  txn = Transaction{};
  txn.active = true;
  txn.command.operation_id = durable_.operation_id;
  txn.command.authority = durable_.issuer;
  txn.command.authority_generation = durable_.issuer_generation;
  txn.command.authority_sequence = durable_.authority_sequence;
  txn.command.next_revision = durable_.decision_revision;
  txn.command_digest = durable_.command_digest;
  txn.prev_snapshot = durable_.prev_snapshot;
  txn.next_snapshot = durable_.next_snapshot;
  txn.permit = durable_.permit;
  return txn;
}

Status ConfigJournal::recover(const std::uint32_t new_store_generation,
                              const MonotonicMs now_ms,
                              const bool reprovision) noexcept {
  if (!initialized_) {
    return Status::error(StatusCode::InvalidState, "config journal not initialized");
  }
  if (!quarantined_ && !uncertain_) {
    return Status::error(StatusCode::InvalidState, "config journal not impaired");
  }
  if (new_store_generation <= proven_floor_ ||
      new_store_generation <= store_generation_) {
    // Below either bound the generation has already been consumed this
    // boot — re-minting it would make pre-loss artifacts indistinguishable
    // from recovered ones.
    return Status::error(StatusCode::InvalidArgument,
                        "config recovery must exceed the proven generation");
  }
  if (!has_active_ && !reprovision) {
    // No verifiable record survives: adopting an empty base would silently
    // fabricate state — an undelegated authority decision. The journal
    // stays quarantined/uncertain until the operator attests a
    // re-provisioning under a fresh trust generation (04 §4.7, 06 §6.3:
    // never an automatic return to revision 0). This refusal consumes no
    // floor generation — the reservation below runs only for recoveries
    // that may actually land.
    return Status::error(StatusCode::RecoveryRequired,
                        "config recovery needs re-provision attestation");
  }
  // The attested generation is exactly the floor's next: an old command
  // names a spent generation, a future one a gap nobody reserved — both
  // are refused, so only the operator's current recovery can land.
  SecurityFloorState current{};
  Status floor_status = floor_.read(current);
  if (!floor_status.ok()) return floor_status;
  const SecurityFloorEntry* floor_entry =
      SecurityFloorStore::entry_for(current, config_.config_namespace);
  if (floor_entry == nullptr) {
    return Status::error(StatusCode::RecoveryRequired,
                         "config security floor has no namespace entry");
  }
  if (floor_entry->store_floor == 0xFFFFFFFFU) {
    return Status::error(StatusCode::CounterExhausted,
                         "config store generation exhausted");
  }
  if (new_store_generation != floor_entry->store_floor + 1) {
    return Status::error(StatusCode::InvalidArgument,
                         "config recovery must name the floor's next generation");
  }
  // Reserve before the twins are written; a failed twin write consumes
  // the generation — the next recovery names the one after.
  SecurityFloorState next = current;
  SecurityFloorEntry* floor_slot =
      SecurityFloorStore::entry_for_mut(next, config_.config_namespace);
  floor_slot->store_floor = new_store_generation;
  floor_status = floor_.advance(current, next);
  if (!floor_status.ok()) return floor_status;
  store_generation_ = new_store_generation;
  // Re-provision: the surviving known value (if any) is adopted under the
  // new generation; the proven revision floor is never regressed.
  JournalRecord& record = record_scratch_;
  record = durable_;
  record.store_generation = new_store_generation;
  // A surviving ACTIVE record stays ACTIVE: the configuration it proved
  // was never interrupted, only the sibling evidence was lost — degrading
  // it to INTERRUPTED would roll the target back to the previous snapshot
  // for no reason. Any other survivor recovers as INTERRUPTED and
  // re-derives state through the normal boot restore path.
  record.phase = !has_active_
                     ? ConfigPhase::Idle
                     : (durable_.phase == ConfigPhase::Active
                            ? ConfigPhase::Active
                            : ConfigPhase::Interrupted);
  record.reason = ConfigReason::RecoveryRequired;
  record.decision_revision = revision_floor_ > decision_revision_
                                 ? revision_floor_
                                 : decision_revision_;
  record.network = config_.network;
  record.target = config_.target;
  record.config_namespace = config_.config_namespace;
  record.schema = config_.schema;
  // No generation evidence: this entry does not itself verify — the
  // verified signer generation is recorded by the recovery ceremony
  // that will replace this local entry, not asserted here.
  record.issuer_generation = 0;
  // Write BOTH slots with the same generation+content: the next boot then
  // sees two verifiable identical records rather than a valid sibling of
  // unverifiable garbage — storage-uncertain would otherwise persist
  // forever across recovery.
  Status stored = store_record(record);
  if (!stored) return stored;
  stored = store_record(record);
  if (!stored) return stored;
  proven_floor_ = new_store_generation;
  durable_ = record;
  uncertain_ = false;
  quarantined_ = false;
  phase_ = record.phase;
  txn_ = Transaction{};
  boot_ = Boot{};
  reassembly_.active = false;
  recovery_reassembly_.active = false;
  const Status adopted = adopt_record(record);
  if (!adopted) return adopted;
  // The adopted survivor's provider state must be re-issued for THIS boot:
  // an interrupted record re-restores its prev snapshot; an ACTIVE record
  // re-asserts its confirmed one. resolve stays false — the durable record
  // is already terminal, nothing further persists on success.
  if (provider_ != nullptr &&
      (record.phase == ConfigPhase::Interrupted ||
       record.phase == ConfigPhase::Active)) {
    const ByteBuffer<endpoint::kConfigSnapshotMax>& snapshot =
        record.phase == ConfigPhase::Active ? record.next_snapshot
                                            : record.prev_snapshot;
    if (snapshot.size > 0) {
      boot_.restore_snapshot = snapshot;
      boot_.restore_pending = true;
      boot_.restore_started = false;
      boot_.resolve = false;
    }
  }
  last_now_ms_ = now_ms;
  return Status::success();
}

}  // namespace routeloom
