#include "routeloom/trust_store.hpp"

#include <cstring>

#include "routeloom/byte_io.hpp"
#include "routeloom/crc32.hpp"
#include "routeloom/discovery_scope.hpp"  // sha256

extern "C" {
#include "uECC.h"
}

namespace routeloom {
namespace {

// RLT1 record byte layout (big-endian via ByteWriter; ≤2048-byte slot):
//   0   u32  magic "RLT1"
//   4   u16  format version (1)
//   6   u16  used_len (bytes incl. CRC, ≤2048)
//   8   u32  schema_version (1)
//   12  u32  commit seal (0 pending / kTrustSealCommitted committed)
//   16  u32  store_epoch
//   20  u32  min_authority_generation
//   24  u64  network (FULL NetworkId, deployment generation in upper bits)
//   32  u64  deployment_id
//   40  u8   flags | u8 anchor_count | u8 key_count | u8 revocation_count
//   44  u32  reserved = 0
//   48  anchors[anchor_count] × 80:
//         root_id u64 | pubkey X||Y 64 | status u8 | reserved 7
//       keys[key_count] × 80:
//         authority_id u64 | generation u32 | profile u8 | role u8 |
//         status u8 | scope u8 | pubkey X||Y 64
//       revocations[revocation_count] × 48:
//         node_id u64 | kid_fingerprint 32 | revoked_at_epoch u32 |
//         kind u8 | reserved 3
//   len-4 u32 crc32_iso_hdlc over [0, used_len-4)
// Entry tables pack contiguously in count order; the §4.3.1 column offsets
// (48/208/528) are the full-table bounds, not fixed offsets — used_len is
// what a variable-count image consumes.
constexpr std::uint32_t kTrustMagic = 0x524C5431U;  // "RLT1"
constexpr std::uint16_t kTrustFormat = 1;
constexpr std::uint32_t kTrustSealPending = 0U;
constexpr std::uint32_t kTrustSealCommitted = 0x7A51C9E2U;  // §4.3.1

bool is_erased(const std::uint8_t* data, const std::size_t size) noexcept {
  const std::uint8_t fill = data[0];
  if (fill != 0x00U && fill != 0xFFU) return false;
  for (std::size_t i = 1; i < size; ++i) {
    if (data[i] != fill) return false;
  }
  return true;
}

bool all_zero(const std::uint8_t* data, const std::size_t size) noexcept {
  for (std::size_t i = 0; i < size; ++i) {
    if (data[i] != 0) return false;
  }
  return true;
}

// Shared body codec — RLT1 bytes [16, used_len-4) == the RTM1 signed
// content. One truth for store persistence and manifest verification.
Status write_image_body(ByteWriter& writer, const TrustImage& image) noexcept {
  Status status = writer.write_u32(image.store_epoch);
  if (status) status = writer.write_u32(image.min_authority_generation);
  if (status) status = writer.write_u64(image.network);
  if (status) status = writer.write_u64(image.deployment_id);
  if (status) status = writer.write_u8(image.flags);
  if (status) status = writer.write_u8(image.anchor_count);
  if (status) status = writer.write_u8(image.key_count);
  if (status) status = writer.write_u8(image.revocation_count);
  if (status) status = writer.write_u32(0);  // reserved
  for (std::uint8_t i = 0; status && i < image.anchor_count; ++i) {
    const TrustAnchor& anchor = image.anchors[i];
    status = writer.write_u64(anchor.root_id);
    if (status) {
      status = writer.write_bytes(ByteView{anchor.pubkey.data(), anchor.pubkey.size()});
    }
    if (status) {
      status = writer.write_u8(static_cast<std::uint8_t>(anchor.status));
    }
    if (status) {
      const std::array<std::uint8_t, 7> reserved{};
      status = writer.write_bytes(ByteView{reserved.data(), reserved.size()});
    }
  }
  for (std::uint8_t i = 0; status && i < image.key_count; ++i) {
    const TrustKeyRecord& key = image.keys[i];
    status = writer.write_u64(key.authority_id);
    if (status) status = writer.write_u32(key.generation);
    if (status) status = writer.write_u8(static_cast<std::uint8_t>(key.profile));
    if (status) status = writer.write_u8(static_cast<std::uint8_t>(key.role));
    if (status) status = writer.write_u8(static_cast<std::uint8_t>(key.status));
    if (status) status = writer.write_u8(static_cast<std::uint8_t>(key.scope));
    if (status) {
      status = writer.write_bytes(ByteView{key.pubkey.data(), key.pubkey.size()});
    }
  }
  for (std::uint8_t i = 0; status && i < image.revocation_count; ++i) {
    const TrustRevocation& revocation = image.revocations[i];
    status = writer.write_u64(revocation.node_id);
    if (status) {
      status = writer.write_bytes(ByteView{revocation.kid_fingerprint.data(),
                                           revocation.kid_fingerprint.size()});
    }
    if (status) status = writer.write_u32(revocation.revoked_at_epoch);
    if (status) {
      status = writer.write_u8(static_cast<std::uint8_t>(revocation.kind));
    }
    if (status) {
      const std::array<std::uint8_t, 3> reserved{};
      status = writer.write_bytes(ByteView{reserved.data(), reserved.size()});
    }
  }
  return status;
}

// Structural read of the body: fields, caps, in-entry reserved bytes and
// enum ranges only — NOT the semantic layer (that is trust_image_validate,
// run after CRC+schema prove the record is real). `remaining` must consume
// exactly: the caller checks consumed == expected_len.
Status read_image_body(ByteReader& reader, TrustImage& image) noexcept {
  std::uint32_t reserved32 = 0;
  Status status = reader.read_u32(image.store_epoch);
  if (status) status = reader.read_u32(image.min_authority_generation);
  if (status) status = reader.read_u64(image.network);
  if (status) status = reader.read_u64(image.deployment_id);
  if (status) status = reader.read_u8(image.flags);
  if (status) status = reader.read_u8(image.anchor_count);
  if (status) status = reader.read_u8(image.key_count);
  if (status) status = reader.read_u8(image.revocation_count);
  if (status) status = reader.read_u32(reserved32);
  if (!status) return status;
  if (reserved32 != 0 || (image.flags & ~kTrustFlagMask) != 0 ||
      image.anchor_count > kTrustAnchorMax || image.key_count > kTrustKeyMax ||
      image.revocation_count > kTrustRevocationMax) {
    return Status::error(StatusCode::ProtocolError, "trust image head invalid");
  }
  for (std::uint8_t i = 0; status && i < image.anchor_count; ++i) {
    TrustAnchor& anchor = image.anchors[i];
    std::uint8_t raw_status = 0;
    std::array<std::uint8_t, 7> reserved{};
    status = reader.read_u64(anchor.root_id);
    if (status) {
      status = reader.read_bytes(
          MutableByteView{anchor.pubkey.data(), anchor.pubkey.size()});
    }
    if (status) status = reader.read_u8(raw_status);
    if (status) {
      status = reader.read_bytes(MutableByteView{reserved.data(), reserved.size()});
    }
    if (status && (!all_zero(reserved.data(), reserved.size()) ||
                   (raw_status != static_cast<std::uint8_t>(TrustAnchorStatus::Active) &&
                    raw_status != static_cast<std::uint8_t>(TrustAnchorStatus::Disabled)))) {
      return Status::error(StatusCode::ProtocolError, "trust anchor entry invalid");
    }
    anchor.status = static_cast<TrustAnchorStatus>(raw_status);
  }
  for (std::uint8_t i = 0; status && i < image.key_count; ++i) {
    TrustKeyRecord& key = image.keys[i];
    std::uint8_t profile = 0, role = 0, key_status = 0, scope = 0;
    status = reader.read_u64(key.authority_id);
    if (status) status = reader.read_u32(key.generation);
    if (status) status = reader.read_u8(profile);
    if (status) status = reader.read_u8(role);
    if (status) status = reader.read_u8(key_status);
    if (status) status = reader.read_u8(scope);
    if (status) {
      status = reader.read_bytes(MutableByteView{key.pubkey.data(), key.pubkey.size()});
    }
    if (status &&
        (profile != static_cast<std::uint8_t>(TrustKeyProfile::Rlcp1CoseEsp256) ||
         role != static_cast<std::uint8_t>(TrustKeyRole::ConfigIssuer) ||
         key_status < static_cast<std::uint8_t>(TrustKeyStatus::Staged) ||
         key_status > static_cast<std::uint8_t>(TrustKeyStatus::Revoked) ||
         scope != static_cast<std::uint8_t>(TrustKeyScope::WholeNetwork))) {
      return Status::error(StatusCode::ProtocolError, "trust key entry invalid");
    }
    key.profile = static_cast<TrustKeyProfile>(profile);
    key.role = static_cast<TrustKeyRole>(role);
    key.status = static_cast<TrustKeyStatus>(key_status);
    key.scope = static_cast<TrustKeyScope>(scope);
  }
  for (std::uint8_t i = 0; status && i < image.revocation_count; ++i) {
    TrustRevocation& revocation = image.revocations[i];
    std::uint8_t kind = 0;
    std::array<std::uint8_t, 3> reserved{};
    status = reader.read_u64(revocation.node_id);
    if (status) {
      status = reader.read_bytes(MutableByteView{revocation.kid_fingerprint.data(),
                                                 revocation.kid_fingerprint.size()});
    }
    if (status) status = reader.read_u32(revocation.revoked_at_epoch);
    if (status) status = reader.read_u8(kind);
    if (status) {
      status = reader.read_bytes(MutableByteView{reserved.data(), reserved.size()});
    }
    if (status && (!all_zero(reserved.data(), reserved.size()) ||
                   kind != static_cast<std::uint8_t>(TrustRevocationKind::DeviceCredential))) {
      return Status::error(StatusCode::ProtocolError, "trust revocation entry invalid");
    }
    revocation.kind = static_cast<TrustRevocationKind>(kind);
  }
  return status;
}

Status encode_record(const TrustImage& image, const std::uint32_t seal,
                     const std::size_t used_len,
                     const MutableByteView target) noexcept {
  ByteWriter writer(target);
  Status status = writer.write_u32(kTrustMagic);
  if (status) status = writer.write_u16(kTrustFormat);
  if (status) status = writer.write_u16(static_cast<std::uint16_t>(used_len));
  if (status) status = writer.write_u32(kTrustStoreSchemaVersion);
  if (status) status = writer.write_u32(seal);
  if (status) status = write_image_body(writer, image);
  if (!status) return status;
  if (writer.size() != used_len - 4) {
    return Status::error(StatusCode::InternalError, "trust image size drift");
  }
  return writer.write_u32(crc32_iso_hdlc(ByteView{target.data, used_len - 4}));
}

bool on_curve(const std::uint8_t* pubkey) noexcept {
  return uECC_valid_public_key(pubkey, uECC_secp256r1()) != 0;
}

}  // namespace

std::size_t trust_image_encoded_size(const TrustImage& image) noexcept {
  if (image.anchor_count > kTrustAnchorMax || image.key_count > kTrustKeyMax ||
      image.revocation_count > kTrustRevocationMax) {
    return 0;
  }
  return kTrustImageHeaderSize +
         image.anchor_count * kTrustAnchorEntrySize +
         image.key_count * kTrustKeyEntrySize +
         image.revocation_count * kTrustRevocationEntrySize + 4;
}

Status trust_image_validate(const TrustImage& image) noexcept {
  if (image.store_epoch == 0 || image.network == 0) {
    return Status::error(StatusCode::InvalidArgument, "trust image epoch/network zero");
  }
  if (image.anchor_count == 0 || image.anchor_count > kTrustAnchorMax ||
      image.key_count > kTrustKeyMax ||
      image.revocation_count > kTrustRevocationMax ||
      (image.flags & ~kTrustFlagMask) != 0) {
    return Status::error(StatusCode::InvalidArgument, "trust image counts/flags");
  }
  bool active_anchor = false;
  for (std::uint8_t i = 0; i < image.anchor_count; ++i) {
    const TrustAnchor& anchor = image.anchors[i];
    if (anchor.root_id == 0) {
      return Status::error(StatusCode::InvalidArgument, "trust anchor id zero");
    }
    for (std::uint8_t j = static_cast<std::uint8_t>(i + 1); j < image.anchor_count; ++j) {
      if (image.anchors[j].root_id == anchor.root_id) {
        return Status::error(StatusCode::InvalidArgument, "trust anchor id duplicated");
      }
    }
    if (anchor.status != TrustAnchorStatus::Active &&
        anchor.status != TrustAnchorStatus::Disabled) {
      return Status::error(StatusCode::InvalidArgument, "trust anchor status");
    }
    if (!on_curve(anchor.pubkey.data())) {
      return Status::error(StatusCode::InvalidArgument, "trust anchor key off curve");
    }
    if (anchor.status == TrustAnchorStatus::Active) active_anchor = true;
  }
  if (!active_anchor) {
    // An image that leaves zero active anchors can never break its own
    // signature chain — after commit, recovery becomes physical-only by
    // accident (§4.5.1 rule 5).
    return Status::error(StatusCode::InvalidArgument, "trust image no active anchor");
  }
  for (std::uint8_t i = 0; i < image.key_count; ++i) {
    const TrustKeyRecord& key = image.keys[i];
    if (key.authority_id == 0 || key.authority_id == kBroadcastNodeId ||
        key.generation == 0) {
      return Status::error(StatusCode::InvalidArgument, "trust key identity");
    }
    if (key.profile != TrustKeyProfile::Rlcp1CoseEsp256 ||
        key.role != TrustKeyRole::ConfigIssuer ||
        key.scope != TrustKeyScope::WholeNetwork ||
        key.status < TrustKeyStatus::Staged || key.status > TrustKeyStatus::Revoked) {
      return Status::error(StatusCode::InvalidArgument, "trust key fields");
    }
    for (std::uint8_t j = static_cast<std::uint8_t>(i + 1); j < image.key_count; ++j) {
      if (image.keys[j].authority_id == key.authority_id &&
          image.keys[j].generation == key.generation) {
        return Status::error(StatusCode::InvalidArgument, "trust key duplicated");
      }
    }
    if (!on_curve(key.pubkey.data())) {
      return Status::error(StatusCode::InvalidArgument, "trust key off curve");
    }
  }
  for (std::uint8_t i = 0; i < image.revocation_count; ++i) {
    const TrustRevocation& revocation = image.revocations[i];
    if (revocation.node_id == kInvalidNodeId ||
        revocation.node_id == kBroadcastNodeId ||
        revocation.kind != TrustRevocationKind::DeviceCredential ||
        all_zero(revocation.kid_fingerprint.data(),
                 revocation.kid_fingerprint.size())) {
      // A zero fingerprint would match nothing meaningful; a revocation
      // entry must name a real credential kid.
      return Status::error(StatusCode::InvalidArgument, "trust revocation entry");
    }
  }
  return Status::success();
}

Status trust_image_encode(const TrustImage& image, const std::uint32_t seal,
                          ByteBuffer<kTrustStoreSlotBytes>& out) noexcept {
  const Status valid = trust_image_validate(image);
  if (!valid) return valid;
  if (seal != kTrustSealPending && seal != kTrustSealCommitted) {
    return Status::error(StatusCode::InvalidArgument, "trust seal value");
  }
  const std::size_t used_len = trust_image_encoded_size(image);
  if (used_len == 0 || used_len > kTrustStoreSlotBytes) {
    return Status::error(StatusCode::InvalidArgument, "trust image oversize");
  }
  const Status status =
      encode_record(image, seal, used_len, MutableByteView{out.bytes.data(), out.bytes.size()});
  if (!status) return status;
  out.size = used_len;
  return Status::success();
}

Status trust_image_body_encode(const TrustImage& image,
                               ByteBuffer<kTrustImageContentMax>& out) noexcept {
  const std::size_t used_len = trust_image_encoded_size(image);
  if (used_len == 0 || used_len - 20 > kTrustImageContentMax) {
    return Status::error(StatusCode::InvalidArgument, "trust image oversize");
  }
  ByteWriter writer(out.writable());
  const Status status = write_image_body(writer, image);
  if (!status) return status;
  out.size = writer.size();
  return Status::success();
}

Status trust_image_body_decode(const ByteView content, TrustImage& out) noexcept {
  out = TrustImage{};
  // The content head alone is 32 bytes; whether the image must carry >=1
  // active anchor is a semantic rule (trust_image_validate), not a codec
  // bound — a structurally intact but anchorless image decodes fine and is
  // denied downstream.
  if (content.data == nullptr || content.size < 32 ||
      content.size > kTrustImageContentMax) {
    return Status::error(StatusCode::ProtocolError, "trust content bounds");
  }
  ByteReader reader(content);
  const Status status = read_image_body(reader, out);
  if (!status) return status;
  // Entry tables must be exactly sized: no trailing bytes (§4.5.1 rule 2).
  if (reader.remaining() != 0) {
    return Status::error(StatusCode::ProtocolError, "trust content trailing");
  }
  return Status::success();
}

Status trust_image_decode(const ByteView record, TrustImage& out) noexcept {
  out = TrustImage{};
  if (record.data == nullptr || record.size < kTrustImageHeaderSize + 4 ||
      record.size > kTrustStoreSlotBytes) {
    return Status::error(StatusCode::ProtocolError, "trust record bounds");
  }
  ByteReader reader(record);
  std::uint32_t magic = 0, schema = 0, seal = 0;
  std::uint16_t format = 0, used_len = 0;
  Status status = reader.read_u32(magic);
  if (status) status = reader.read_u16(format);
  if (status) status = reader.read_u16(used_len);
  if (status) status = reader.read_u32(schema);
  if (status) status = reader.read_u32(seal);
  if (!status || magic != kTrustMagic || format != kTrustFormat ||
      used_len < kTrustImageHeaderSize + 4 || used_len > record.size) {
    return Status::error(StatusCode::ProtocolError, "trust record head");
  }
  if (seal != kTrustSealCommitted) {
    return Status::error(StatusCode::ProtocolError, "trust record uncommitted");
  }
  status = read_image_body(reader, out);
  if (!status) return status;
  std::uint32_t crc = 0;
  status = reader.read_u32(crc);
  if (!status || reader.consumed() != used_len) {
    return Status::error(StatusCode::ProtocolError, "trust record length");
  }
  if (crc32_iso_hdlc(ByteView{record.data, static_cast<std::size_t>(used_len) - 4}) != crc) {
    return Status::error(StatusCode::IntegrityError, "trust record crc");
  }
  if (schema != kTrustStoreSchemaVersion) {
    return Status::error(StatusCode::Unsupported, "trust record schema");
  }
  return trust_image_validate(out);
}

Status trust_image_fingerprint(const ByteView record, Digest256& out) noexcept {
  if (record.data == nullptr || record.size < kTrustImageHeaderSize + 4 ||
      record.size > kTrustStoreSlotBytes) {
    return Status::error(StatusCode::InvalidArgument, "trust fingerprint input");
  }
  sha256(record, out);
  return Status::success();
}

// --- TrustStore --------------------------------------------------------------

TrustStore::TrustStore(TrustStoreStorage& storage) noexcept : storage_(storage) {}

Status TrustStore::decode_slot(const std::uint8_t slot, TrustImage& image,
                               std::size_t& used_len, SlotContent& content,
                               bool& committed_fields) noexcept {
  committed_fields = false;
  used_len = 0;
  auto& raw = scratch_a_;
  const Status status =
      storage_.read(slot, MutableByteView{raw.data(), raw.size()});
  if (!status) return status;
  if (is_erased(raw.data(), raw.size())) {
    content = SlotContent::Empty;
    return Status::success();
  }
  ByteReader reader(ByteView{raw.data(), raw.size()});
  std::uint32_t magic = 0, schema = 0, seal = 0;
  std::uint16_t format = 0, length = 0;
  Status st = reader.read_u32(magic);
  if (st) st = reader.read_u16(format);
  if (st) st = reader.read_u16(length);
  if (st) st = reader.read_u32(schema);
  if (st) st = reader.read_u32(seal);
  if (!st || magic != kTrustMagic || format != kTrustFormat ||
      length < kTrustImageHeaderSize + 4 || length > kTrustStoreSlotBytes) {
    content = SlotContent::Corrupt;
    return Status::success();
  }
  if (seal != kTrustSealCommitted) {
    // A well-formed pending record was never committed and is always safe
    // to discard; any other seal value is corruption.
    content = seal == kTrustSealPending ? SlotContent::Pending : SlotContent::Corrupt;
    return Status::success();
  }
  // Structural gate: every field must parse, counts/reserved/enum values
  // must be in range and the entry tables must consume exactly used_len.
  // A record that fails here is indistinguishable from noise and must NOT
  // bound the recovery floors — otherwise bitrot could mint an arbitrary
  // floor and wedge recovery forever (the journal's 06 §6.3 rule).
  const std::size_t declared_len = length;
  st = read_image_body(reader, image);
  std::uint32_t crc = 0;
  if (st) st = reader.read_u32(crc);
  committed_fields = st.ok() && reader.consumed() == declared_len;
  if (!committed_fields) {
    content = SlotContent::Corrupt;
    return Status::success();
  }
  used_len = declared_len;
  if (crc32_iso_hdlc(ByteView{raw.data(), declared_len - 4}) != crc) {
    // Committed fields still bound how far the store advanced even when
    // the CRC is gone (the ledger's recovery_floor_ rule, §4.3.1).
    content = SlotContent::Corrupt;
    return Status::success();
  }
  if (schema != kTrustStoreSchemaVersion) {
    content = SlotContent::Unsupported;
    return Status::success();
  }
  // CRC + schema prove this is a real committed record; the semantic layer
  // (on-curve points, >=1 active anchor, unique ids) decides whether it can
  // serve as trust state. A semantic failure is Corrupt but still bounds
  // the floors — the epoch it consumed is proven, never re-mintable.
  if (!trust_image_validate(image).ok()) {
    content = SlotContent::Corrupt;
    return Status::success();
  }
  sha256(ByteView{raw.data(), declared_len}, slot_fingerprint_[slot]);
  content = SlotContent::Valid;
  return Status::success();
}

Status TrustStore::initialize() noexcept {
  std::array<SlotContent, kTrustStoreSlots> content{};
  std::array<std::size_t, kTrustStoreSlots> used_len{};
  std::array<bool, kTrustStoreSlots> unreadable{};
  std::array<bool, kTrustStoreSlots> committed_fields{};
  Status read_error = Status::success();
  int valid = 0, corrupt = 0, unsupported = 0;
  for (std::uint8_t slot = 0; slot < kTrustStoreSlots; ++slot) {
    slot_reserved_[slot] = StatusCode::Ok;
    parsed_[slot] = TrustImage{};
    const Status status = decode_slot(slot, parsed_[slot], used_len[slot],
                                      content[slot], committed_fields[slot]);
    if (!status) {
      unreadable[slot] = true;
      if (read_error.ok()) read_error = status;
      continue;
    }
    switch (content[slot]) {
      case SlotContent::Valid:
        ++valid;
        if (parsed_[slot].store_epoch > epoch_floor_) {
          epoch_floor_ = parsed_[slot].store_epoch;
        }
        if (parsed_[slot].min_authority_generation > generation_floor_) {
          generation_floor_ = parsed_[slot].min_authority_generation;
        }
        break;
      case SlotContent::Unsupported:
        ++unsupported;
        slot_reserved_[slot] = StatusCode::Unsupported;
        // CRC-intact, committed — its floors are still trustworthy bounds.
        if (parsed_[slot].store_epoch > epoch_floor_) {
          epoch_floor_ = parsed_[slot].store_epoch;
        }
        if (parsed_[slot].min_authority_generation > generation_floor_) {
          generation_floor_ = parsed_[slot].min_authority_generation;
        }
        break;
      case SlotContent::Corrupt:
        ++corrupt;
        if (committed_fields[slot]) {
          if (parsed_[slot].store_epoch > epoch_floor_) {
            epoch_floor_ = parsed_[slot].store_epoch;
          }
          if (parsed_[slot].min_authority_generation > generation_floor_) {
            generation_floor_ = parsed_[slot].min_authority_generation;
          }
        }
        break;
      default:
        break;
    }
  }

  auto quarantine = [&](const StatusCode code, const char* detail) {
    quarantined_ = true;
    initialized_ = true;
    has_active_ = false;
    image_ = TrustImage{};
    fingerprint_ = Digest256{};
    return Status::error(code, detail);
  };

  const auto provably_absent = [&](const std::uint8_t slot) {
    return !unreadable[slot] &&
           (content[slot] == SlotContent::Empty || content[slot] == SlotContent::Pending);
  };

  const auto adopt = [&](const std::uint8_t slot) {
    image_ = parsed_[slot];
    fingerprint_ = slot_fingerprint_[slot];
    active_slot_ = slot;
    has_active_ = true;
    return Status::success();
  };

  if (unreadable[0] && unreadable[1]) {
    return read_error.ok()
               ? Status::error(StatusCode::StorageFailure, "trust store unreadable")
               : read_error;
  }

  if (valid == 2) {
    const TrustImage& a = parsed_[0];
    const TrustImage& b = parsed_[1];
    if (a.store_epoch != b.store_epoch) {
      const std::uint8_t newer = b.store_epoch > a.store_epoch ? 1 : 0;
      const Status adopted = adopt(newer);
      if (!adopted) return adopted;
      initialized_ = true;
      return Status::success();
    }
    // Equal epochs are only legitimate as the identical twin pair a
    // recover() writes; different content at one epoch cannot be ordered.
    // Compare the committed bytes directly (the codec is deterministic, so
    // byte-equality is content-equality).
    Status st = storage_.read(0, MutableByteView{scratch_a_.data(), scratch_a_.size()});
    if (st) {
      st = storage_.read(1, MutableByteView{scratch_b_.data(), scratch_b_.size()});
    }
    if (!st) return st;
    if (used_len[0] != used_len[1] ||
        std::memcmp(scratch_a_.data(), scratch_b_.data(), used_len[0]) != 0) {
      return quarantine(StatusCode::IntegrityError, "trust store epoch ambiguous");
    }
    const Status adopted = adopt(0);
    if (!adopted) return adopted;
    initialized_ = true;
    return Status::success();
  }

  if (valid == 1) {
    const std::uint8_t slot = content[0] == SlotContent::Valid ? 0 : 1;
    const Status adopted = adopt(slot);
    if (!adopted) return adopted;
    initialized_ = true;
    if (!provably_absent(static_cast<std::uint8_t>(slot ^ 1U))) {
      // The lost sibling may have held a NEWER image: the survivor is a
      // known value only — commits refuse until recover() (06 §6.3 rule,
      // same posture as the config journal's storage-uncertain).
      uncertain_ = true;
      return Status::error(StatusCode::IntegrityError,
                         "trust store sibling state unproven");
    }
    return Status::success();
  }

  // No valid record survives.
  if (unreadable[0] || unreadable[1]) {
    return read_error;  // a storage fault, not proven corruption — retryable
  }
  if (unsupported > 0) {
    return quarantine(StatusCode::Unsupported, "trust store schema unsupported");
  }
  if (corrupt > 0) {
    // Both slots unverifiable: SECURITY_RECOVERY_REQUIRED quarantine
    // (§4.3.1) — the config verifier reports not-ready, privileged intake
    // refuses, routing continues degraded. Never an implicit reset.
    return quarantine(StatusCode::IntegrityError, "trust store corrupt");
  }

  // Fresh store: all slots empty or pending-only — normal pre-provisioning
  // state awaiting the physical install path (§4.4), not an impairment.
  initialized_ = true;
  return Status::success();
}

Status TrustStore::store_image(const std::uint8_t slot, const TrustImage& image,
                               Digest256* fingerprint) noexcept {
  const std::size_t used_len = trust_image_encoded_size(image);
  if (used_len == 0 || used_len > kTrustStoreSlotBytes) {
    return Status::error(StatusCode::InvalidArgument, "trust image oversize");
  }
  auto& buffer = scratch_a_;
  // Phase 1: land the record unsealed. A power cut here leaves a pending
  // slot the boot classifier discards, so the previous committed image
  // survives untouched.
  Status status =
      encode_record(image, kTrustSealPending, used_len,
                    MutableByteView{buffer.data(), buffer.size()});
  if (!status) return status;
  status = storage_.write(slot, ByteView{buffer.data(), used_len});
  if (!status) return status;
  // Phase 2: commit marker. The image is never active state before this
  // seal lands and the readback verifies.
  status = encode_record(image, kTrustSealCommitted, used_len,
                         MutableByteView{buffer.data(), buffer.size()});
  if (!status) return status;
  status = storage_.write(slot, ByteView{buffer.data(), used_len});
  if (!status) return status;
  auto& verify = scratch_b_;
  status = storage_.read(slot, MutableByteView{verify.data(), verify.size()});
  if (!status) return status;
  if (std::memcmp(verify.data(), buffer.data(), used_len) != 0) {
    return Status::error(StatusCode::StorageFailure, "trust store readback mismatch");
  }
  if (fingerprint != nullptr) {
    sha256(ByteView{buffer.data(), used_len}, *fingerprint);
  }
  return Status::success();
}

Status TrustStore::commit_image(const TrustImage& image) noexcept {
  if (!initialized_) {
    return Status::error(StatusCode::InvalidState, "trust store not initialized");
  }
  if (quarantined_) {
    return Status::error(StatusCode::IntegrityError, "trust store quarantined");
  }
  if (uncertain_) {
    // The lost sibling may hold a newer image; overwriting on a stale base
    // could clobber it — operator recovery decides (journal intake rule).
    return Status::error(StatusCode::RecoveryRequired,
                        "trust store storage uncertain");
  }
  const Status valid = trust_image_validate(image);
  if (!valid) return valid;
  // Ordinal compare only: a store_epoch at or below the proven floor —
  // including one a committed-but-CRC-failed record proved — is a stale or
  // replayed image, never modular wraparound (§4.5.1 rule 3).
  if (image.store_epoch <= epoch_floor_) {
    return Status::error(StatusCode::Conflict, "trust image epoch not newer");
  }
  if (image.min_authority_generation < generation_floor_) {
    // Floors never regress: a lower bound would re-admit permits signed
    // under already-excluded key generations.
    return Status::error(StatusCode::AuthorizationFailed,
                        "authority generation floor regressed");
  }
  const std::uint8_t target =
      has_active_ ? static_cast<std::uint8_t>(active_slot_ ^ 1U) : 0;
  if (slot_reserved_[target] != StatusCode::Ok) {
    return Status::error(slot_reserved_[target],
                        "trust store slot owned by other data");
  }
  const Status stored = store_image(target, image, &fingerprint_);
  if (!stored) return stored;
  image_ = image;
  epoch_floor_ = image.store_epoch;
  if (image.min_authority_generation > generation_floor_) {
    generation_floor_ = image.min_authority_generation;
  }
  active_slot_ = target;
  has_active_ = true;
  return Status::success();
}

Status TrustStore::recover(const TrustImage& image) noexcept {
  if (!initialized_) {
    return Status::error(StatusCode::InvalidState, "trust store not initialized");
  }
  if (!quarantined_ && !uncertain_) {
    return Status::error(StatusCode::InvalidState, "trust store not impaired");
  }
  const Status valid = trust_image_validate(image);
  if (!valid) return valid;
  // The operator attests a fresh image; its epoch must clear EVERY epoch a
  // committed record proved this boot (including CRC-failed ones) or a
  // pre-loss image could replay — the attestation is the safety mechanism.
  if (image.store_epoch <= epoch_floor_) {
    return Status::error(StatusCode::InvalidArgument,
                        "recovery epoch must exceed the proven floor");
  }
  if (image.min_authority_generation < generation_floor_) {
    return Status::error(StatusCode::AuthorizationFailed,
                        "authority generation floor regressed");
  }
  // The identical image goes to both slots: the next boot then sees two
  // verifiable identical records rather than a valid sibling of
  // unverifiable data (the ledger/journal recovery pattern).
  Status status = store_image(0, image, &fingerprint_);
  if (!status) return status;
  status = store_image(1, image, nullptr);
  if (!status) return status;
  slot_reserved_[0] = StatusCode::Ok;
  slot_reserved_[1] = StatusCode::Ok;
  image_ = image;
  epoch_floor_ = image.store_epoch;
  if (image.min_authority_generation > generation_floor_) {
    generation_floor_ = image.min_authority_generation;
  }
  active_slot_ = 0;
  has_active_ = true;
  quarantined_ = false;
  uncertain_ = false;
  return Status::success();
}

const TrustAnchor* TrustStore::find_anchor(const std::uint64_t root_id) const noexcept {
  if (!has_active_) return nullptr;
  for (std::uint8_t i = 0; i < image_.anchor_count; ++i) {
    if (image_.anchors[i].root_id == root_id) return &image_.anchors[i];
  }
  return nullptr;
}

const TrustKeyRecord* TrustStore::find_key(const std::uint64_t authority_id,
                                           const std::uint32_t generation) const noexcept {
  if (!has_active_) return nullptr;
  for (std::uint8_t i = 0; i < image_.key_count; ++i) {
    const TrustKeyRecord& key = image_.keys[i];
    if (key.authority_id == authority_id && key.generation == generation) {
      return &key;
    }
  }
  return nullptr;
}

bool TrustStore::is_credential_revoked(const Digest256& kid_fingerprint) const noexcept {
  if (!has_active_) return false;
  for (std::uint8_t i = 0; i < image_.revocation_count; ++i) {
    const TrustRevocation& revocation = image_.revocations[i];
    if (revocation.kind == TrustRevocationKind::DeviceCredential &&
        revocation.kid_fingerprint == kid_fingerprint) {
      return true;
    }
  }
  return false;
}

}  // namespace routeloom
