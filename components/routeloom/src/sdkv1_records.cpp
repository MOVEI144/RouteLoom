#include "routeloom/sdkv1_records.hpp"

#include <cstring>

#include "routeloom/byte_io.hpp"
#include "routeloom/crc32.hpp"
#include "routeloom/discovery_scope.hpp"  // sha256

extern "C" {
#include "uECC.h"
}

namespace routeloom::sdkv1 {
namespace {

constexpr std::uint64_t kAllOnes = ~std::uint64_t{0};

bool id_valid(const std::uint64_t id) noexcept { return id != 0 && id != kAllOnes; }

template <std::size_t N>
bool all_zero(const std::array<std::uint8_t, N>& bytes) noexcept {
  std::uint8_t acc = 0;
  for (const auto byte : bytes) acc |= byte;
  return acc == 0;
}

template <std::size_t N>
Status write_array(ByteWriter& writer, const std::array<std::uint8_t, N>& bytes) noexcept {
  return writer.write_bytes(ByteView{bytes.data(), bytes.size()});
}

template <std::size_t N>
Status read_array(ByteReader& reader, std::array<std::uint8_t, N>& bytes) noexcept {
  return reader.read_bytes(MutableByteView{bytes.data(), bytes.size()});
}

Status write_zeros(ByteWriter& writer, const std::size_t count) noexcept {
  Status status = Status::success();
  for (std::size_t i = 0; status && i < count; ++i) status = writer.write_u8(0);
  return status;
}

Status read_zeros(ByteReader& reader, const std::size_t count, const char* what) noexcept {
  for (std::size_t i = 0; i < count; ++i) {
    std::uint8_t byte = 0;
    const Status status = reader.read_u8(byte);
    if (!status) return status;
    if (byte != 0) return Status::error(StatusCode::ProtocolError, what);
  }
  return Status::success();
}

Status write_head(ByteWriter& writer, const std::uint32_t magic, const std::size_t used_len,
                  const std::uint32_t seal) noexcept {
  Status status = writer.write_u32(magic);
  if (status) status = writer.write_u16(kRecordFormat);
  if (status) status = writer.write_u16(static_cast<std::uint16_t>(used_len));
  if (status) status = writer.write_u32(kRecordSchema);
  if (status) status = writer.write_u32(seal);
  return status;
}

// Strict committed-record head check shared by the *_record_decode entry
// points (the stores classify slots themselves).
Status read_head(ByteReader& reader, const ByteView record, const std::uint32_t magic,
                 const std::uint32_t seal_committed, const std::size_t min_len,
                 const std::size_t max_len, std::uint16_t& used_len) noexcept {
  std::uint32_t got_magic = 0, schema = 0, seal = 0;
  std::uint16_t format = 0;
  Status status = reader.read_u32(got_magic);
  if (status) status = reader.read_u16(format);
  if (status) status = reader.read_u16(used_len);
  if (status) status = reader.read_u32(schema);
  if (status) status = reader.read_u32(seal);
  if (!status || got_magic != magic || format != kRecordFormat || used_len < min_len ||
      used_len > max_len || used_len != record.size) {
    return Status::error(StatusCode::ProtocolError, "record head");
  }
  if (seal != seal_committed) {
    return Status::error(StatusCode::ProtocolError, "record uncommitted");
  }
  if (crc32_iso_hdlc(ByteView{record.data, record.size - 4U}) !=
      ((static_cast<std::uint32_t>(record.data[record.size - 4]) << 24U) |
       (static_cast<std::uint32_t>(record.data[record.size - 3]) << 16U) |
       (static_cast<std::uint32_t>(record.data[record.size - 2]) << 8U) |
       static_cast<std::uint32_t>(record.data[record.size - 1]))) {
    return Status::error(StatusCode::IntegrityError, "record crc");
  }
  if (schema != kRecordSchema) {
    return Status::error(StatusCode::Unsupported, "record schema");
  }
  return Status::success();
}

Status finish_crc(ByteWriter& writer, const MutableByteView target,
                  const std::size_t used_len) noexcept {
  if (writer.size() != used_len - 4) {
    return Status::error(StatusCode::InternalError, "record size drift");
  }
  return writer.write_u32(crc32_iso_hdlc(ByteView{target.data, used_len - 4}));
}

// --- RLI1 helpers ------------------------------------------------------------

Status identity_body_write(ByteWriter& writer, const IdentityRecord& record) noexcept {
  Status status = writer.write_u64(record.node_id);
  if (status) status = writer.write_u8(static_cast<std::uint8_t>(record.key_location));
  if (status) status = writer.write_u8(record.flags);
  if (status) status = writer.write_u8(record.anchor_count);
  if (status) status = write_zeros(writer, 1 + 4);
  if (status) status = write_array(writer, record.kid);
  if (status) status = write_array(writer, record.pubkey);
  if (status) status = write_array(writer, record.key_material);
  for (std::uint8_t i = 0; status && i < record.anchor_count; ++i) {
    const IdentityAnchor& anchor = record.anchors[i];
    status = writer.write_u64(anchor.anchor_id);
    if (status) status = writer.write_u8(static_cast<std::uint8_t>(anchor.kind));
    if (status) status = writer.write_u8(static_cast<std::uint8_t>(anchor.status));
    if (status) status = write_zeros(writer, 6);
    if (status) status = write_array(writer, anchor.pubkey);
  }
  if (status) status = writer.write_u16(static_cast<std::uint16_t>(record.devcert.size));
  if (status) status = writer.write_u16(0);
  if (status) status = writer.write_bytes(record.devcert.view());
  return status;
}

// Structural body read (fields, counts, reserved zero, enum ranges,
// exact length). Semantic checks are identity_validate.
Status identity_body_read(ByteReader& reader, IdentityRecord& record) noexcept {
  std::uint8_t location = 0;
  Status status = reader.read_u64(record.node_id);
  if (status) status = reader.read_u8(location);
  if (status) status = reader.read_u8(record.flags);
  if (status) status = reader.read_u8(record.anchor_count);
  if (status) status = read_zeros(reader, 1 + 4, "rli1 reserved");
  if (!status) return status;
  if (location > static_cast<std::uint8_t>(CredentialKeyLocation::SecureElement) ||
      record.anchor_count == 0 || record.anchor_count > kIdentityAnchorMax) {
    return Status::error(StatusCode::ProtocolError, "rli1 head fields");
  }
  record.key_location = static_cast<CredentialKeyLocation>(location);
  status = read_array(reader, record.kid);
  if (status) status = read_array(reader, record.pubkey);
  if (status) status = read_array(reader, record.key_material);
  for (std::uint8_t i = 0; status && i < record.anchor_count; ++i) {
    IdentityAnchor& anchor = record.anchors[i];
    std::uint8_t kind = 0, anchor_status = 0;
    status = reader.read_u64(anchor.anchor_id);
    if (status) status = reader.read_u8(kind);
    if (status) status = reader.read_u8(anchor_status);
    if (status) status = read_zeros(reader, 6, "rli1 anchor reserved");
    if (status) status = read_array(reader, anchor.pubkey);
    if (status && (kind < 1 || kind > 2 || anchor_status < 1 || anchor_status > 2)) {
      return Status::error(StatusCode::ProtocolError, "rli1 anchor enum");
    }
    anchor.kind = static_cast<AnchorKind>(kind);
    anchor.status = static_cast<AnchorStatus>(anchor_status);
  }
  std::uint16_t devcert_len = 0, reserved = 0;
  if (status) status = reader.read_u16(devcert_len);
  if (status) status = reader.read_u16(reserved);
  if (!status) return status;
  if (reserved != 0 || devcert_len == 0 || devcert_len > kRlcw1CertMax ||
      reader.remaining() != static_cast<std::size_t>(devcert_len) + 4U) {
    return Status::error(StatusCode::ProtocolError, "rli1 devcert length");
  }
  status = reader.read_bytes(MutableByteView{record.devcert.bytes.data(), devcert_len});
  if (!status) return status;
  record.devcert.size = devcert_len;
  return Status::success();
}

// --- RLS1 helpers ------------------------------------------------------------

Status site_body_write(ByteWriter& writer, const SiteRecord& record) noexcept {
  Status status = writer.write_u64(record.site_id);
  if (status) status = writer.write_u64(record.network);
  if (status) status = writer.write_u32(record.assignment_generation);
  if (status) status = writer.write_u32(record.rs_epoch_floor);
  if (status) status = writer.write_u32(record.gk_epoch_current);
  if (status) status = writer.write_u32(record.gk_epoch_next);
  if (status) status = write_array(writer, record.gk_current);
  if (status) status = write_array(writer, record.gk_next);
  if (status) status = write_array(writer, record.dams);
  if (status) status = writer.write_u8(static_cast<std::uint8_t>(record.state));
  if (status) status = writer.write_u8(record.role);
  if (status) status = writer.write_u8(record.gateway_count);
  if (status) status = writer.write_u8(record.channel);
  if (status) status = writer.write_u32(record.channel_epoch);
  if (status) status = writer.write_u32(record.boot_witness);
  for (std::size_t i = 0; status && i < kSiteGatewayMax; ++i) {
    status = writer.write_u64(record.gateways[i]);
  }
  if (status) status = writer.write_u16(static_cast<std::uint16_t>(record.site_cert.size));
  if (status) status = writer.write_u16(static_cast<std::uint16_t>(record.member_cert.size));
  if (status) status = writer.write_bytes(record.site_cert.view());
  if (status) status = writer.write_bytes(record.member_cert.view());
  return status;
}

Status site_body_read(ByteReader& reader, SiteRecord& record) noexcept {
  std::uint8_t state = 0;
  Status status = reader.read_u64(record.site_id);
  if (status) status = reader.read_u64(record.network);
  if (status) status = reader.read_u32(record.assignment_generation);
  if (status) status = reader.read_u32(record.rs_epoch_floor);
  if (status) status = reader.read_u32(record.gk_epoch_current);
  if (status) status = reader.read_u32(record.gk_epoch_next);
  if (status) status = read_array(reader, record.gk_current);
  if (status) status = read_array(reader, record.gk_next);
  if (status) status = read_array(reader, record.dams);
  if (status) status = reader.read_u8(state);
  if (status) status = reader.read_u8(record.role);
  if (status) status = reader.read_u8(record.gateway_count);
  if (status) status = reader.read_u8(record.channel);
  if (status) status = reader.read_u32(record.channel_epoch);
  if (status) status = reader.read_u32(record.boot_witness);
  for (std::size_t i = 0; status && i < kSiteGatewayMax; ++i) {
    status = reader.read_u64(record.gateways[i]);
  }
  std::uint16_t site_len = 0, member_len = 0;
  if (status) status = reader.read_u16(site_len);
  if (status) status = reader.read_u16(member_len);
  if (!status) return status;
  if (state > static_cast<std::uint8_t>(SiteState::Member) || site_len > kRlcw1CertMax ||
      member_len > kRlcw1CertMax ||
      reader.remaining() != static_cast<std::size_t>(site_len) + member_len + 4U) {
    return Status::error(StatusCode::ProtocolError, "rls1 structure");
  }
  record.state = static_cast<SiteState>(state);
  status = reader.read_bytes(MutableByteView{record.site_cert.bytes.data(), site_len});
  if (status) {
    status = reader.read_bytes(MutableByteView{record.member_cert.bytes.data(), member_len});
  }
  if (!status) return status;
  record.site_cert.size = site_len;
  record.member_cert.size = member_len;
  return Status::success();
}

// --- RRS1 helpers ------------------------------------------------------------

std::size_t revocation_payload_size(const std::uint8_t count) noexcept {
  return kRevocationHeadSize + static_cast<std::size_t>(count) * kRevocationEntrySize;
}

}  // namespace

// === RLI1 ======================================================================

std::size_t identity_encoded_size(const IdentityRecord& record) noexcept {
  if (record.anchor_count == 0 || record.anchor_count > kIdentityAnchorMax ||
      record.devcert.size == 0 || record.devcert.size > kRlcw1CertMax) {
    return 0;
  }
  return kIdentityFixedSize + record.anchor_count * kIdentityAnchorEntrySize + 4 +
         record.devcert.size + 4;
}

Status identity_validate(const IdentityRecord& record) noexcept {
  if (!id_valid(record.node_id)) {
    return Status::error(StatusCode::InvalidArgument, "rli1 node id");
  }
  if (record.key_location > CredentialKeyLocation::SecureElement ||
      (record.flags & ~kIdentityFlagMask) != 0 || record.anchor_count == 0 ||
      record.anchor_count > kIdentityAnchorMax || record.devcert.size == 0 ||
      record.devcert.size > kRlcw1CertMax) {
    return Status::error(StatusCode::InvalidArgument, "rli1 fields");
  }
  if (!p256_public_key_valid(record.pubkey)) {
    return Status::error(StatusCode::InvalidArgument, "rli1 pubkey off curve");
  }
  Digest256 kid{};
  Status status = credential_kid(ByteView{record.pubkey.data(), record.pubkey.size()}, kid);
  if (!status) return status;
  if (kid != record.kid) {
    return Status::error(StatusCode::IntegrityError, "rli1 kid mismatch");
  }
  switch (record.key_location) {
    case CredentialKeyLocation::None:
      if (!all_zero(record.key_material)) {
        return Status::error(StatusCode::InvalidArgument, "rli1 key residue");
      }
      break;
    case CredentialKeyLocation::NvsPlaintext: {
      P256PublicKey computed{};
      if (uECC_compute_public_key(record.key_material.data(), computed.data(),
                                  uECC_secp256r1()) == 0 ||
          computed != record.pubkey) {
        return Status::error(StatusCode::IntegrityError, "rli1 keypair mismatch");
      }
      break;
    }
    default:
      break;  // opaque handle: no local check possible
  }
  bool site_ca = false, verifier = false;
  for (std::uint8_t i = 0; i < record.anchor_count; ++i) {
    const IdentityAnchor& anchor = record.anchors[i];
    if (!id_valid(anchor.anchor_id) ||
        (anchor.kind != AnchorKind::SiteCa && anchor.kind != AnchorKind::AssignmentVerifier) ||
        (anchor.status != AnchorStatus::Active && anchor.status != AnchorStatus::Disabled)) {
      return Status::error(StatusCode::InvalidArgument, "rli1 anchor fields");
    }
    for (std::uint8_t j = static_cast<std::uint8_t>(i + 1); j < record.anchor_count; ++j) {
      if (record.anchors[j].anchor_id == anchor.anchor_id) {
        return Status::error(StatusCode::InvalidArgument, "rli1 anchor duplicated");
      }
    }
    if (!p256_public_key_valid(anchor.pubkey)) {
      return Status::error(StatusCode::InvalidArgument, "rli1 anchor off curve");
    }
    if (anchor.status == AnchorStatus::Active) {
      if (anchor.kind == AnchorKind::SiteCa) site_ca = true;
      if (anchor.kind == AnchorKind::AssignmentVerifier) verifier = true;
    }
  }
  if (!site_ca) {
    return Status::error(StatusCode::InvalidArgument, "rli1 no active site ca");
  }
  if ((record.flags & kIdentityFlagStrictAssignment) != 0 && !verifier) {
    return Status::error(StatusCode::InvalidArgument, "rli1 strict without verifier");
  }
  CertClaims devcert{};
  status = cert_decode(record.devcert.view(), devcert);
  if (!status) return status;
  if (devcert.type != CertType::Device || devcert.subject != record.node_id ||
      devcert.pubkey != record.pubkey) {
    return Status::error(StatusCode::IntegrityError, "rli1 devcert mismatch");
  }
  return Status::success();
}

Status identity_record_encode(const IdentityRecord& record, const std::uint32_t seal,
                              ByteBuffer<kIdentitySlotBytes>& out) noexcept {
  out.clear();
  const Status valid = identity_validate(record);
  if (!valid) return valid;
  if (seal != kSealPending && seal != kIdentitySealCommitted) {
    return Status::error(StatusCode::InvalidArgument, "rli1 seal value");
  }
  const std::size_t used_len = identity_encoded_size(record);
  ByteWriter writer(out.writable());
  Status status = write_head(writer, kIdentityMagic, used_len, seal);
  if (status) status = identity_body_write(writer, record);
  if (status) status = finish_crc(writer, out.writable(), used_len);
  if (!status) return status;
  out.size = used_len;
  return Status::success();
}

Status identity_record_decode(const ByteView record, IdentityRecord& out) noexcept {
  out = IdentityRecord{};
  if (record.data == nullptr) return Status::error(StatusCode::ProtocolError, "rli1 null");
  ByteReader reader(record);
  std::uint16_t used_len = 0;
  Status status = read_head(reader, record, kIdentityMagic, kIdentitySealCommitted,
                            kIdentityRecordMin, kIdentityRecordMax, used_len);
  if (!status) return status;
  status = identity_body_read(reader, out);
  if (!status) return status;
  const Status valid = identity_validate(out);
  if (!valid) {
    return Status::error(valid.code == StatusCode::InvalidArgument ? StatusCode::ProtocolError
                                                                   : valid.code,
                         valid.detail);
  }
  return Status::success();
}

const IdentityAnchor* identity_active_anchor(const IdentityRecord& record,
                                             const std::uint64_t anchor_id,
                                             const AnchorKind kind) noexcept {
  for (std::uint8_t i = 0; i < record.anchor_count && i < kIdentityAnchorMax; ++i) {
    const IdentityAnchor& anchor = record.anchors[i];
    if (anchor.anchor_id == anchor_id && anchor.kind == kind &&
        anchor.status == AnchorStatus::Active) {
      return &anchor;
    }
  }
  return nullptr;
}

Status identity_verify_site_cert(const IdentityRecord& record, const ByteView site_cert,
                                 CertClaims& out, bool& verified,
                                 const Es256Verifier& verifier) noexcept {
  verified = false;
  out = CertClaims{};
  const Status decoded = cert_decode(site_cert, out);
  if (!decoded) return decoded;
  if (out.type != CertType::Site) {
    return Status::success();  // not a SiteCert: denied
  }
  const IdentityAnchor* anchor =
      identity_active_anchor(record, out.issuer, AnchorKind::SiteCa);
  if (anchor == nullptr) return Status::success();  // foreign/disabled CA: denied
  CertClaims again{};
  return cert_verify(site_cert, anchor->pubkey, again, verified, verifier);
}

// === RLS1 ======================================================================

std::size_t site_encoded_size(const SiteRecord& record) noexcept {
  if (record.site_cert.size > kRlcw1CertMax || record.member_cert.size > kRlcw1CertMax) {
    return 0;
  }
  return kSiteFixedSize + record.site_cert.size + record.member_cert.size + 4;
}

Status site_validate(const SiteRecord& record) noexcept {
  if (record.state == SiteState::Cleared) {
    const bool zero =
        record.site_id == 0 && record.network == 0 && record.assignment_generation == 0 &&
        record.rs_epoch_floor == 0 && record.gk_epoch_current == 0 &&
        record.gk_epoch_next == 0 && all_zero(record.gk_current) &&
        all_zero(record.gk_next) && all_zero(record.dams) && record.role == 0 &&
        record.gateway_count == 0 && record.channel == 0 && record.channel_epoch == 0 &&
        record.boot_witness == 0 && record.site_cert.size == 0 &&
        record.member_cert.size == 0;
    bool gateways_zero = true;
    for (const NodeId gateway : record.gateways) gateways_zero = gateways_zero && gateway == 0;
    if (!zero || !gateways_zero) {
      return Status::error(StatusCode::InvalidArgument, "rls1 tombstone not empty");
    }
    return Status::success();
  }
  if (record.state != SiteState::Member) {
    return Status::error(StatusCode::InvalidArgument, "rls1 state");
  }
  if (!id_valid(record.site_id) || record.network == 0 ||
      (record.network & 0xFFFFFFFFULL) == 0 || record.assignment_generation == 0) {
    return Status::error(StatusCode::InvalidArgument, "rls1 identity");
  }
  if (record.gk_epoch_current == 0 || all_zero(record.gk_current) || all_zero(record.dams)) {
    return Status::error(StatusCode::InvalidArgument, "rls1 keys");
  }
  if (record.gk_epoch_next == 0) {
    if (!all_zero(record.gk_next)) {
      return Status::error(StatusCode::InvalidArgument, "rls1 gk_next residue");
    }
  } else if (record.gk_epoch_next <= record.gk_epoch_current || all_zero(record.gk_next)) {
    return Status::error(StatusCode::InvalidArgument, "rls1 gk_next");
  }
  if (record.role == 0 || (record.role & ~kMemberRoleMask) != 0 ||
      record.channel < 1 || record.channel > 14 || record.gateway_count < 1 ||
      record.gateway_count > kSiteGatewayMax) {
    return Status::error(StatusCode::InvalidArgument, "rls1 fields");
  }
  for (std::size_t i = 0; i < kSiteGatewayMax; ++i) {
    const NodeId gateway = record.gateways[i];
    if (i < record.gateway_count) {
      if (!id_valid(gateway)) {
        return Status::error(StatusCode::InvalidArgument, "rls1 gateway id");
      }
      for (std::size_t j = i + 1; j < record.gateway_count; ++j) {
        if (record.gateways[j] == gateway) {
          return Status::error(StatusCode::InvalidArgument, "rls1 gateway duplicated");
        }
      }
    } else if (gateway != 0) {
      return Status::error(StatusCode::InvalidArgument, "rls1 gateway tail");
    }
  }
  if (record.site_cert.size == 0 || record.site_cert.size > kRlcw1CertMax ||
      record.member_cert.size == 0 || record.member_cert.size > kRlcw1CertMax) {
    return Status::error(StatusCode::InvalidArgument, "rls1 cert lengths");
  }
  CertClaims site{}, member{};
  Status status = cert_decode(record.site_cert.view(), site);
  if (status) status = cert_decode(record.member_cert.view(), member);
  if (!status) return status;
  const std::uint32_t site_epoch = static_cast<std::uint32_t>(record.network >> 32U);
  if (site.type != CertType::Site || member.type != CertType::Member ||
      site.subject != record.site_id ||
      site.network_low32 != static_cast<std::uint32_t>(record.network & 0xFFFFFFFFULL) ||
      site.site_epoch != site_epoch || member.issuer != record.site_id ||
      member.network != record.network ||
      member.assignment_generation != record.assignment_generation ||
      member.role != record.role) {
    return Status::error(StatusCode::IntegrityError, "rls1 certificate mismatch");
  }
  return Status::success();
}

Status site_record_encode(const SiteRecord& record, const std::uint32_t seal,
                          const std::uint32_t commit_seq,
                          ByteBuffer<kSiteSlotBytes>& out) noexcept {
  out.clear();
  const Status valid = site_validate(record);
  if (!valid) return valid;
  if (seal != kSealPending && seal != kSiteSealCommitted) {
    return Status::error(StatusCode::InvalidArgument, "rls1 seal value");
  }
  const std::size_t used_len = site_encoded_size(record);
  ByteWriter writer(out.writable());
  Status status = write_head(writer, kSiteMagic, used_len, seal);
  if (status) status = writer.write_u32(commit_seq);
  if (status) status = site_body_write(writer, record);
  if (status) status = finish_crc(writer, out.writable(), used_len);
  if (!status) return status;
  out.size = used_len;
  return Status::success();
}

Status site_record_decode(const ByteView record, SiteRecord& out,
                          std::uint32_t* commit_seq) noexcept {
  out = SiteRecord{};
  if (record.data == nullptr) return Status::error(StatusCode::ProtocolError, "rls1 null");
  ByteReader reader(record);
  std::uint16_t used_len = 0;
  Status status = read_head(reader, record, kSiteMagic, kSiteSealCommitted, kSiteRecordMin,
                            kSiteRecordMax, used_len);
  std::uint32_t seq = 0;
  if (status) status = reader.read_u32(seq);
  if (status) status = site_body_read(reader, out);
  if (!status) return status;
  const Status valid = site_validate(out);
  if (!valid) {
    return Status::error(valid.code == StatusCode::InvalidArgument ? StatusCode::ProtocolError
                                                                   : valid.code,
                         valid.detail);
  }
  if (commit_seq != nullptr) *commit_seq = seq;
  return Status::success();
}

Status site_matches_identity(const SiteRecord& site, const IdentityRecord& identity) noexcept {
  if (site.state != SiteState::Member) {
    return Status::error(StatusCode::InvalidState, "rls1 not member");
  }
  CertClaims member{}, site_claims{};
  Status status = cert_decode(site.member_cert.view(), member);
  if (status) status = cert_decode(site.site_cert.view(), site_claims);
  if (!status) return status;
  return member_cert_matches(member, site_claims, identity.node_id, identity.pubkey);
}

// === RRS1 ======================================================================

Status revocation_validate(const RevocationSet& set) noexcept {
  if (!id_valid(set.site_id) || set.network == 0 || (set.network & 0xFFFFFFFFULL) == 0 ||
      set.rs_epoch == 0 || set.count > kRevocationEntryMax ||
      set.site_epoch_floor > static_cast<std::uint32_t>(set.network >> 32U)) {
    return Status::error(StatusCode::InvalidArgument, "rrs1 head");
  }
  for (std::uint8_t i = 0; i < set.count; ++i) {
    const RevocationEntry& entry = set.entries[i];
    if (!id_valid(entry.node_id) || entry.min_generation == 0 ||
        entry.reason < RevocationReason::Removed || entry.reason > RevocationReason::Blocked) {
      return Status::error(StatusCode::InvalidArgument, "rrs1 entry");
    }
    if (i > 0 && set.entries[i - 1].node_id >= entry.node_id) {
      return Status::error(StatusCode::InvalidArgument, "rrs1 entries not ascending");
    }
  }
  return Status::success();
}

Status revocation_payload_encode(const RevocationSet& set,
                                 ByteBuffer<kRevocationPayloadMax>& out) noexcept {
  out.clear();
  const Status valid = revocation_validate(set);
  if (!valid) return valid;
  ByteWriter writer(out.writable());
  Status status = writer.write_u8(kRevocationVersion);
  if (status) status = writer.write_u8(0);  // flags
  if (status) status = writer.write_u16(set.count);
  if (status) status = writer.write_u64(set.site_id);
  if (status) status = writer.write_u64(set.network);
  if (status) status = writer.write_u32(set.rs_epoch);
  if (status) status = writer.write_u32(set.site_epoch_floor);
  for (std::uint8_t i = 0; status && i < set.count; ++i) {
    const RevocationEntry& entry = set.entries[i];
    status = writer.write_u64(entry.node_id);
    if (status) status = writer.write_u32(entry.min_generation);
    if (status) status = writer.write_u8(static_cast<std::uint8_t>(entry.reason));
    if (status) status = write_zeros(writer, 3);
  }
  if (!status) return status;
  out.size = writer.size();
  return Status::success();
}

Status revocation_payload_decode(const ByteView payload, RevocationSet& out) noexcept {
  out = RevocationSet{};
  if (payload.data == nullptr || payload.size < kRevocationHeadSize ||
      payload.size > kRevocationPayloadMax) {
    return Status::error(StatusCode::ProtocolError, "rrs1 payload bounds");
  }
  ByteReader reader(payload);
  std::uint8_t version = 0, flags = 0;
  std::uint16_t count = 0;
  Status status = reader.read_u8(version);
  if (status) status = reader.read_u8(flags);
  if (status) status = reader.read_u16(count);
  if (status) status = reader.read_u64(out.site_id);
  if (status) status = reader.read_u64(out.network);
  if (status) status = reader.read_u32(out.rs_epoch);
  if (status) status = reader.read_u32(out.site_epoch_floor);
  if (!status) return status;
  if (version != kRevocationVersion) {
    return Status::error(StatusCode::Unsupported, "rrs1 version");
  }
  if (flags != 0 || count > kRevocationEntryMax ||
      payload.size != revocation_payload_size(static_cast<std::uint8_t>(count))) {
    return Status::error(StatusCode::ProtocolError, "rrs1 payload shape");
  }
  out.count = static_cast<std::uint8_t>(count);
  for (std::uint8_t i = 0; status && i < out.count; ++i) {
    RevocationEntry& entry = out.entries[i];
    std::uint8_t reason = 0;
    status = reader.read_u64(entry.node_id);
    if (status) status = reader.read_u32(entry.min_generation);
    if (status) status = reader.read_u8(reason);
    if (status) status = read_zeros(reader, 3, "rrs1 entry reserved");
    entry.reason = static_cast<RevocationReason>(reason);
  }
  if (!status) return status;
  const Status valid = revocation_validate(out);
  if (!valid) return Status::error(StatusCode::ProtocolError, valid.detail);
  return Status::success();
}

Status revocation_aad(const NetworkId network, ByteBuffer<kRevocationAadSize>& out) noexcept {
  out.clear();
  ByteWriter writer(out.writable());
  // Domain string including its NUL terminator, then the network.
  Status status = writer.write_bytes(ByteView{
      reinterpret_cast<const std::uint8_t*>(kRevocationDomain), sizeof(kRevocationDomain)});
  if (status) status = writer.write_u64(network);
  if (!status) return status;
  out.size = writer.size();
  return Status::success();
}

Status revocation_object_assemble(const ByteView payload, const ByteView signature,
                                  ByteBuffer<kRevocationObjectMax>& out) noexcept {
  out.clear();
  RevocationSet set{};
  const Status decoded = revocation_payload_decode(payload, set);
  if (!decoded) return decoded;
  return cose_es256_assemble(payload, signature, out.writable(), out.size);
}

Status revocation_object_decode(const ByteView object, RevocationSet& out) noexcept {
  out = RevocationSet{};
  CoseEs256Parts parts{};
  const Status parsed = cose_es256_parse(object, kRevocationHeadSize, kRevocationPayloadMax,
                                         kRevocationObjectMax, parts);
  if (!parsed) return parsed;
  return revocation_payload_decode(parts.payload, out);
}

Status revocation_object_verify(const ByteView object, const P256PublicKey& sak_pubkey,
                                const std::uint64_t expected_site_id,
                                const NetworkId expected_network, RevocationSet& out,
                                bool& verified, const Es256Verifier& verifier) noexcept {
  verified = false;
  out = RevocationSet{};
  CoseEs256Parts parts{};
  Status status = cose_es256_parse(object, kRevocationHeadSize, kRevocationPayloadMax,
                                   kRevocationObjectMax, parts);
  if (status) status = revocation_payload_decode(parts.payload, out);
  if (!status) return status;
  if (out.site_id != expected_site_id || out.network != expected_network) {
    return Status::success();  // another site/network: denied
  }
  ByteBuffer<kRevocationAadSize> aad{};
  status = revocation_aad(expected_network, aad);
  if (!status) return status;
  return cose_es256_verify(parts.payload, aad.view(), parts.signature, sak_pubkey, verifier,
                           verified);
}

bool revocation_rejects(const RevocationSet& set, const NodeId node,
                        const std::uint32_t generation, const std::uint32_t site_epoch) noexcept {
  if (site_epoch < set.site_epoch_floor) return true;
  for (std::uint8_t i = 0; i < set.count && i < kRevocationEntryMax; ++i) {
    if (set.entries[i].node_id == node) return generation < set.entries[i].min_generation;
  }
  return false;
}

Status revocation_record_encode(const ByteView object, const std::uint32_t seal,
                                const std::uint32_t commit_seq,
                                ByteBuffer<kRevocationSlotBytes>& out) noexcept {
  out.clear();
  if (seal != kSealPending && seal != kRevocationSealCommitted) {
    return Status::error(StatusCode::InvalidArgument, "rrs1 seal value");
  }
  if (object.size > 0) {
    RevocationSet set{};
    const Status decoded = revocation_object_decode(object, set);
    if (!decoded) return decoded;
  }
  const std::size_t used_len = kSequencedHeadSize + object.size + 4;
  ByteWriter writer(out.writable());
  Status status = write_head(writer, kRevocationMagic, used_len, seal);
  if (status) status = writer.write_u32(commit_seq);
  if (status && object.size > 0) status = writer.write_bytes(object);
  if (status) status = finish_crc(writer, out.writable(), used_len);
  if (!status) return status;
  out.size = used_len;
  return Status::success();
}

Status revocation_record_decode(const ByteView record, RevocationSet& out, ByteView& object,
                                std::uint32_t* commit_seq) noexcept {
  out = RevocationSet{};
  object = ByteView{};
  if (record.data == nullptr) return Status::error(StatusCode::ProtocolError, "rrs1 null");
  ByteReader reader(record);
  std::uint16_t used_len = 0;
  Status status = read_head(reader, record, kRevocationMagic, kRevocationSealCommitted,
                            kRevocationRecordMin, kRevocationRecordMax, used_len);
  std::uint32_t seq = 0;
  if (status) status = reader.read_u32(seq);
  if (!status) return status;
  const ByteView body{record.data + kSequencedHeadSize,
                      record.size - kSequencedHeadSize - 4U};
  if (body.size > 0) {
    status = revocation_object_decode(body, out);
    if (!status) return status;
    object = body;
  }
  if (commit_seq != nullptr) *commit_seq = seq;
  return Status::success();
}

// === Structure-only gates =====================================================

namespace {

std::uint16_t be16_at(const ByteView record, const std::size_t offset) noexcept {
  return static_cast<std::uint16_t>((record.data[offset] << 8U) | record.data[offset + 1]);
}

Status structure_head(const ByteView record, const std::uint32_t magic,
                      const std::size_t min_len, const std::size_t max_len) noexcept {
  if (record.data == nullptr || record.size < min_len || record.size > max_len) {
    return Status::error(StatusCode::ProtocolError, "record bounds");
  }
  ByteReader reader(record);
  std::uint32_t got_magic = 0;
  std::uint16_t format = 0, used_len = 0;
  Status status = reader.read_u32(got_magic);
  if (status) status = reader.read_u16(format);
  if (status) status = reader.read_u16(used_len);
  if (!status || got_magic != magic || format != kRecordFormat || used_len != record.size) {
    return Status::error(StatusCode::ProtocolError, "record head");
  }
  return Status::success();
}

}  // namespace

Status identity_record_structure(const ByteView record) noexcept {
  const Status head =
      structure_head(record, kIdentityMagic, kIdentityRecordMin, kIdentityRecordMax);
  if (!head) return head;
  const std::size_t anchors = record.data[26];
  if (anchors == 0 || anchors > kIdentityAnchorMax || record.data[27] != 0 ||
      record.data[28] != 0 || record.data[29] != 0 || record.data[30] != 0 ||
      record.data[31] != 0) {
    return Status::error(StatusCode::ProtocolError, "rli1 structure");
  }
  const std::size_t len_at = kIdentityFixedSize + anchors * kIdentityAnchorEntrySize;
  if (len_at + 4 > record.size) return Status::error(StatusCode::ProtocolError, "rli1 structure");
  const std::size_t devcert_len = be16_at(record, len_at);
  if (be16_at(record, len_at + 2) != 0 || devcert_len == 0 || devcert_len > kRlcw1CertMax ||
      len_at + 4 + devcert_len + 4 != record.size) {
    return Status::error(StatusCode::ProtocolError, "rli1 structure");
  }
  return Status::success();
}

Status site_record_structure(const ByteView record) noexcept {
  const Status head = structure_head(record, kSiteMagic, kSiteRecordMin, kSiteRecordMax);
  if (!head) return head;
  const std::size_t site_len = be16_at(record, 192);
  const std::size_t member_len = be16_at(record, 194);
  if (record.data[148] > static_cast<std::uint8_t>(SiteState::Member) ||
      site_len > kRlcw1CertMax || member_len > kRlcw1CertMax ||
      kSiteFixedSize + site_len + member_len + 4 != record.size) {
    return Status::error(StatusCode::ProtocolError, "rls1 structure");
  }
  return Status::success();
}

Status revocation_record_structure(const ByteView record) noexcept {
  return structure_head(record, kRevocationMagic, kRevocationRecordMin, kRevocationRecordMax);
}

// === RLP1 ======================================================================

Status resume_validate(const ResumeSlot& slot) noexcept {
  if (!slot.valid) {
    const bool zero = slot.flags == 0 && slot.peer == 0 && slot.network == 0 &&
                      all_zero(slot.peer_cert_id) && slot.peer_generation == 0 &&
                      slot.created_gk_epoch == 0 && slot.last_used_boot == 0 &&
                      all_zero(slot.rms);
    return zero ? Status::success()
                : Status::error(StatusCode::InvalidArgument, "rlp1 empty residue");
  }
  if ((slot.purpose != ResumePurpose::Link && slot.purpose != ResumePurpose::End) ||
      (slot.flags & ~kResumeFlagPinned) != 0 || !id_valid(slot.peer) || slot.network == 0 ||
      slot.peer_generation == 0 || slot.created_gk_epoch == 0 || all_zero(slot.rms)) {
    return Status::error(StatusCode::InvalidArgument, "rlp1 fields");
  }
  return Status::success();
}

Status resume_slot_encode(const ResumeSlot& slot,
                          std::array<std::uint8_t, kResumeSlotBytes>& out) noexcept {
  out.fill(0);
  const Status valid = resume_validate(slot);
  if (!valid) return valid;
  const MutableByteView target{out.data(), out.size()};
  ByteWriter writer(target);
  Status status = writer.write_u32(kResumeMagic);
  if (status) status = writer.write_u8(kResumeFormat);
  if (status) status = writer.write_u8(slot.valid ? static_cast<std::uint8_t>(slot.purpose) : 0);
  if (status) status = writer.write_u8(slot.valid ? 1 : 0);
  if (status) status = writer.write_u8(slot.flags);
  if (status) status = writer.write_u64(slot.peer);
  if (status) status = writer.write_u64(slot.network);
  if (status) status = write_array(writer, slot.peer_cert_id);
  if (status) status = writer.write_u32(slot.peer_generation);
  if (status) status = writer.write_u32(slot.created_gk_epoch);
  if (status) status = writer.write_u32(slot.last_used_boot);
  if (status) status = writer.write_u32(0);
  if (status) status = write_array(writer, slot.rms);
  if (status) status = finish_crc(writer, target, kResumeSlotBytes);
  return status;
}

Status resume_slot_decode(const ByteView bytes, ResumeSlot& out) noexcept {
  out = ResumeSlot{};
  if (bytes.data == nullptr || bytes.size != kResumeSlotBytes) {
    return Status::error(StatusCode::ProtocolError, "rlp1 size");
  }
  ByteReader reader(bytes);
  std::uint32_t magic = 0, reserved = 0, crc = 0;
  std::uint8_t format = 0, purpose = 0, state = 0;
  Status status = reader.read_u32(magic);
  if (status) status = reader.read_u8(format);
  if (status) status = reader.read_u8(purpose);
  if (status) status = reader.read_u8(state);
  if (status) status = reader.read_u8(out.flags);
  if (status) status = reader.read_u64(out.peer);
  if (status) status = reader.read_u64(out.network);
  if (status) status = read_array(reader, out.peer_cert_id);
  if (status) status = reader.read_u32(out.peer_generation);
  if (status) status = reader.read_u32(out.created_gk_epoch);
  if (status) status = reader.read_u32(out.last_used_boot);
  if (status) status = reader.read_u32(reserved);
  if (status) status = read_array(reader, out.rms);
  if (status) status = reader.read_u32(crc);
  if (!status) return status;
  if (magic != kResumeMagic || format != kResumeFormat) {
    return Status::error(StatusCode::ProtocolError, "rlp1 head");
  }
  if (crc32_iso_hdlc(ByteView{bytes.data, kResumeSlotBytes - 4}) != crc) {
    return Status::error(StatusCode::IntegrityError, "rlp1 crc");
  }
  if (reserved != 0 || state > 1 || (state == 0 && purpose != 0)) {
    return Status::error(StatusCode::ProtocolError, "rlp1 fields");
  }
  out.valid = state == 1;
  out.purpose = static_cast<ResumePurpose>(state == 1 ? purpose : 1);
  const Status valid = resume_validate(out);
  if (!valid) return Status::error(StatusCode::ProtocolError, valid.detail);
  return Status::success();
}

void resume_peer_cert_id(const ByteView member_cert, std::array<std::uint8_t, 8>& out) noexcept {
  Digest256 digest{};
  sha256(member_cert, digest);
  std::memcpy(out.data(), digest.data(), out.size());
}

}  // namespace routeloom::sdkv1
