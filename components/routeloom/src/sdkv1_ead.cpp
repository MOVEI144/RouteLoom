#include "routeloom/sdkv1_ead.hpp"

#include <cstring>

#include "routeloom/byte_io.hpp"
#include "routeloom/discovery_scope.hpp"  // Sha256

namespace routeloom::sdkv1 {
namespace {

constexpr std::uint64_t kAllOnes = ~std::uint64_t{0};

bool id_valid(const std::uint64_t id) noexcept { return id != 0 && id != kAllOnes; }

Status malformed(const char* what) noexcept {
  return Status::error(StatusCode::ProtocolError, what);
}

Status denied(const char* what) noexcept {
  return Status::error(StatusCode::AuthorizationFailed, what);
}

// Read the fixed ver | flags prefix every join value starts with. An
// unknown version is Unsupported (a newer peer), anything else malformed.
Status read_version_flags(ByteReader& reader, const char* what) noexcept {
  std::uint8_t version = 0, flags = 0;
  Status status = reader.read_u8(version);
  if (status) status = reader.read_u8(flags);
  if (!status) return malformed(what);
  if (version != kJoinEadVersion) return Status::error(StatusCode::Unsupported, what);
  if (flags != 0) return malformed(what);
  return Status::success();
}

Status expect_zero16(ByteReader& reader, const char* what) noexcept {
  std::uint16_t value = 0;
  const Status status = reader.read_u16(value);
  if (!status || value != 0) return malformed(what);
  return Status::success();
}

Status expect_end(const ByteReader& reader, const char* what) noexcept {
  return reader.remaining() == 0 ? Status::success() : malformed(what);
}

std::uint32_t first4_be(const Digest256& digest) noexcept {
  return (static_cast<std::uint32_t>(digest[0]) << 24U) |
         (static_cast<std::uint32_t>(digest[1]) << 16U) |
         (static_cast<std::uint32_t>(digest[2]) << 8U) | digest[3];
}

template <std::size_t N>
std::uint32_t domain_hint(const char (&domain)[N], const ByteView tail) noexcept {
  Sha256 sha;
  // Domain string including its NUL terminator (the "\0" of 02 §5).
  sha.update(ByteView{reinterpret_cast<const std::uint8_t*>(domain), N});
  sha.update(tail);
  Digest256 digest{};
  sha.finish(digest);
  return first4_be(digest);
}

inline constexpr char kOrgHintDomain[] = "RouteLoom/org-hint/v1";
inline constexpr char kSiteHintDomain[] = "RouteLoom/site-hint/v1";

// --- canonical CBOR for the EAD sequence ---------------------------------------

// Major type 0/1 integer head with the shortest-form rule. `negative`
// reports major type 1; `argument` is the raw argument (value = -1 - arg).
Status read_int(const ByteView body, std::size_t& pos, bool& negative,
                std::uint64_t& argument) noexcept {
  if (pos >= body.size) return malformed("ead label");
  const std::uint8_t ib = body.data[pos++];
  const std::uint8_t major = ib >> 5U;
  if (major != 0 && major != 1) return malformed("ead label");
  negative = major == 1;
  const std::uint8_t info = ib & 0x1FU;
  argument = 0;
  if (info <= 23) {
    argument = info;
    return Status::success();
  }
  std::size_t bytes = 0;
  std::uint64_t minimum = 0;
  switch (info) {
    case 24: bytes = 1; minimum = 24; break;
    case 25: bytes = 2; minimum = 0x100; break;
    case 26: bytes = 4; minimum = 0x10000; break;
    case 27: bytes = 8; minimum = 0x100000000ULL; break;
    default: return malformed("ead label");
  }
  if (pos + bytes > body.size) return malformed("ead label");
  for (std::size_t i = 0; i < bytes; ++i) argument = (argument << 8U) | body.data[pos + i];
  pos += bytes;
  if (argument < minimum) return malformed("ead label non-canonical");
  return Status::success();
}

// Definite bstr with the minimal length form (values here are < 64 KiB).
Status read_bstr(const ByteView body, std::size_t& pos, ByteView& out) noexcept {
  out = ByteView{};
  if (pos >= body.size) return malformed("ead value");
  const std::uint8_t ib = body.data[pos++];
  std::size_t len = 0;
  if (ib >= 0x40 && ib <= 0x57) {
    len = ib - 0x40U;
  } else if (ib == 0x58) {
    if (pos >= body.size) return malformed("ead value");
    len = body.data[pos++];
    if (len <= 23) return malformed("ead value non-canonical");
  } else if (ib == 0x59) {
    if (pos + 2 > body.size) return malformed("ead value");
    len = (static_cast<std::size_t>(body.data[pos]) << 8U) | body.data[pos + 1];
    pos += 2;
    if (len <= 0xFF) return malformed("ead value non-canonical");
  } else {
    return malformed("ead value");
  }
  if (pos + len > body.size) return malformed("ead value");
  out = ByteView{body.data + pos, len};
  pos += len;
  return Status::success();
}

bool join_ead_known(const std::uint64_t label) noexcept {
  return label >= static_cast<std::uint32_t>(JoinEad::Intent) &&
         label <= static_cast<std::uint32_t>(JoinEad::Result);
}



bool retry_ok(const JoinVerdict verdict, const std::uint32_t retry) noexcept {
  switch (verdict) {
    case JoinVerdict::PendingAssignment:
      return retry >= kPendingRetryMinS && retry <= kRetryAfterMaxS;
    case JoinVerdict::AuthorityBusy: return retry >= 1 && retry <= kRetryAfterMaxS;
    case JoinVerdict::Allow:
    case JoinVerdict::DenyNotHere:
    case JoinVerdict::DenyBlocked:
    case JoinVerdict::Removed: return retry == 0;
  }
  return false;
}

bool package_empty(const SitePackage& package) noexcept {
  std::uint8_t acc = 0;
  for (const auto byte : package.gk) acc |= byte;
  for (const auto gateway : package.gateways) acc |= gateway != 0 ? 1 : 0;
  return acc == 0 && package.site_id == 0 && package.network == 0 && package.rs_epoch == 0 &&
         package.gk_epoch == 0 && package.channel == 0 && package.role == 0 &&
         package.gateway_count == 0 && package.channel_epoch == 0 &&
         package.authority_time_s == 0 && package.time_uncertainty_ms == 0 &&
         package.membership_revision == 0;
}

bool verdict_known(const std::uint8_t verdict) noexcept {
  return verdict >= static_cast<std::uint8_t>(JoinVerdict::Allow) &&
         verdict <= static_cast<std::uint8_t>(JoinVerdict::AuthorityBusy);
}

}  // namespace

bool join_ead_value_size_ok(const JoinEad label, const std::size_t size) noexcept {
  switch (label) {
    case JoinEad::Intent: return size == kJoinIntentSize;
    case JoinEad::Offer: return size == kSiteOfferSize;
    case JoinEad::Request: return size == kJoinRequestSize;
    case JoinEad::Result: return size >= kJoinResultHeadSize && size <= kJoinResultMax;
    case JoinEad::Credential: return size >= 1 && size <= kRlcw1CertMax;
  }
  return false;
}

// === JoinIntent ====================================================================

Status join_intent_validate(const JoinIntent& intent) noexcept {
  if ((intent.profile_bits & kJoinProfileRljoin1) == 0 ||
      (intent.profile_bits & ~kJoinProfileMask) != 0) {
    return malformed("join intent profile_bits");
  }
  return Status::success();
}

Status join_intent_encode(const JoinIntent& intent, ByteBuffer<kJoinIntentSize>& out) noexcept {
  out.clear();
  const Status valid = join_intent_validate(intent);
  if (!valid) return Status::error(StatusCode::InvalidArgument, valid.detail);
  ByteWriter writer(out.writable());
  Status status = writer.write_u8(kJoinEadVersion);
  if (status) status = writer.write_u8(0);
  if (status) status = writer.write_u32(intent.org_hint);
  if (status) status = writer.write_u32(intent.profile_bits);
  if (status) status = writer.write_u16(0);
  if (!status) return status;
  out.size = writer.size();
  return Status::success();
}

Status join_intent_decode(const ByteView value, JoinIntent& out) noexcept {
  out = JoinIntent{};
  if (value.data == nullptr || value.size != kJoinIntentSize) {
    return malformed("join intent size");
  }
  ByteReader reader(value);
  Status status = read_version_flags(reader, "join intent head");
  if (status) status = reader.read_u32(out.org_hint);
  if (status) status = reader.read_u32(out.profile_bits);
  if (status) status = expect_zero16(reader, "join intent reserved");
  if (status) status = expect_end(reader, "join intent trailing");
  if (status) status = join_intent_validate(out);
  if (!status) out = JoinIntent{};
  return status;
}

std::uint32_t join_org_hint(const P256PublicKey& site_ca_pubkey) noexcept {
  return domain_hint(kOrgHintDomain, ByteView{site_ca_pubkey.data(), site_ca_pubkey.size()});
}

std::uint32_t join_site_hint(const std::uint64_t site_id) noexcept {
  std::array<std::uint8_t, 8> bytes{};
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    bytes[i] = static_cast<std::uint8_t>(site_id >> (56U - 8U * i));
  }
  return domain_hint(kSiteHintDomain, ByteView{bytes.data(), bytes.size()});
}

// === SiteOffer =====================================================================

Status site_offer_validate(const SiteOffer& offer) noexcept {
  if (!id_valid(offer.site_id)) return malformed("site offer site_id");
  if (offer.network_low32 == 0) return malformed("site offer network_low32");
  if (offer.decision_timeout_ms < kDecisionTimeoutMinMs ||
      offer.decision_timeout_ms > kDecisionTimeoutMaxMs) {
    return malformed("site offer decision_timeout_ms");
  }
  return Status::success();
}

Status site_offer_encode(const SiteOffer& offer, ByteBuffer<kSiteOfferSize>& out) noexcept {
  out.clear();
  const Status valid = site_offer_validate(offer);
  if (!valid) return Status::error(StatusCode::InvalidArgument, valid.detail);
  ByteWriter writer(out.writable());
  Status status = writer.write_u8(kJoinEadVersion);
  if (status) status = writer.write_u8(0);
  if (status) status = writer.write_u64(offer.site_id);
  if (status) status = writer.write_u32(offer.network_low32);
  if (status) status = writer.write_u32(offer.site_epoch);
  if (status) status = writer.write_u16(offer.decision_timeout_ms);
  if (status) status = writer.write_u16(0);
  if (!status) return status;
  out.size = writer.size();
  return Status::success();
}

Status site_offer_decode(const ByteView value, SiteOffer& out) noexcept {
  out = SiteOffer{};
  if (value.data == nullptr || value.size != kSiteOfferSize) {
    return malformed("site offer size");
  }
  ByteReader reader(value);
  Status status = read_version_flags(reader, "site offer head");
  if (status) status = reader.read_u64(out.site_id);
  if (status) status = reader.read_u32(out.network_low32);
  if (status) status = reader.read_u32(out.site_epoch);
  if (status) status = reader.read_u16(out.decision_timeout_ms);
  if (status) status = expect_zero16(reader, "site offer reserved");
  if (status) status = expect_end(reader, "site offer trailing");
  if (status) status = site_offer_validate(out);
  if (!status) out = SiteOffer{};
  return status;
}

Status site_offer_matches_site_cert(const SiteOffer& offer, const CertClaims& site_cert) noexcept {
  if (site_cert.type != CertType::Site) {
    return Status::error(StatusCode::InvalidArgument, "site offer: not a SiteCert");
  }
  if (offer.site_id != site_cert.subject || offer.network_low32 != site_cert.network_low32 ||
      offer.site_epoch != site_cert.site_epoch) {
    return denied("site offer disagrees with SiteCert");
  }
  return Status::success();
}

// === JoinRequest ===================================================================

Status join_request_validate(const JoinRequest& request) noexcept {
  if ((request.capability & ~kJoinCapabilityMask) != 0) {
    return malformed("join request capability");
  }
  const std::uint32_t role = request.requested_role;
  if (role == 0 || (role & ~kMemberRoleMask) != 0) return malformed("join request role");
  if ((role & kMemberRoleRelay) != 0 && (request.capability & kJoinCapabilityRelay) == 0) {
    return malformed("join request relay role without capability");
  }
  if ((role & kMemberRoleGateway) != 0 && (request.capability & kJoinCapabilityGateway) == 0) {
    return malformed("join request gateway role without capability");
  }
  if (request.last_site_id == 0) {
    if (request.last_generation != 0) return malformed("join request last_generation");
  } else if (!id_valid(request.last_site_id) || request.last_generation == 0) {
    return malformed("join request last site");
  }
  return Status::success();
}

Status join_request_encode(const JoinRequest& request,
                           ByteBuffer<kJoinRequestSize>& out) noexcept {
  out.clear();
  const Status valid = join_request_validate(request);
  if (!valid) return Status::error(StatusCode::InvalidArgument, valid.detail);
  ByteWriter writer(out.writable());
  Status status = writer.write_u8(kJoinEadVersion);
  if (status) status = writer.write_u8(0);
  if (status) status = writer.write_u16(request.model);
  if (status) status = writer.write_u32(request.fw_version);
  if (status) status = writer.write_u32(request.capability);
  if (status) status = writer.write_u8(request.requested_role);
  if (status) status = writer.write_u8(0);
  if (status) status = writer.write_u64(request.last_site_id);
  if (status) status = writer.write_u32(request.last_generation);
  if (!status) return status;
  out.size = writer.size();
  return Status::success();
}

Status join_request_decode(const ByteView value, JoinRequest& out) noexcept {
  out = JoinRequest{};
  if (value.data == nullptr || value.size != kJoinRequestSize) {
    return malformed("join request size");
  }
  ByteReader reader(value);
  std::uint8_t reserved = 0;
  Status status = read_version_flags(reader, "join request head");
  if (status) status = reader.read_u16(out.model);
  if (status) status = reader.read_u32(out.fw_version);
  if (status) status = reader.read_u32(out.capability);
  if (status) status = reader.read_u8(out.requested_role);
  if (status) status = reader.read_u8(reserved);
  if (status && reserved != 0) status = malformed("join request reserved");
  if (status) status = reader.read_u64(out.last_site_id);
  if (status) status = reader.read_u32(out.last_generation);
  if (status) status = expect_end(reader, "join request trailing");
  if (status) status = join_request_validate(out);
  if (!status) out = JoinRequest{};
  return status;
}

Status join_request_matches_dev_cert(const JoinRequest& request,
                                     const CertClaims& dev_cert) noexcept {
  if (dev_cert.type != CertType::Device) {
    return Status::error(StatusCode::InvalidArgument, "join request: not a DevCert");
  }
  if (request.model != dev_cert.model) return denied("join request model disagrees with DevCert");
  return Status::success();
}

// === SitePackage ===================================================================

Status site_package_validate(const SitePackage& package) noexcept {
  if (!id_valid(package.site_id)) return malformed("site package site_id");
  if ((package.network & 0xFFFFFFFFULL) == 0) return malformed("site package network");
  if (package.gk_epoch == 0) return malformed("site package gk_epoch");
  std::uint8_t acc = 0;
  for (const auto byte : package.gk) acc |= byte;
  if (acc == 0) return malformed("site package gk");
  if (package.channel < 1 || package.channel > 14) return malformed("site package channel");
  if (package.role == 0 || (package.role & ~kMemberRoleMask) != 0) {
    return malformed("site package role");
  }
  if (package.gateway_count < 1 || package.gateway_count > kSitePackageGatewayMax) {
    return malformed("site package gateway_count");
  }
  for (std::size_t i = 0; i < kSitePackageGatewayMax; ++i) {
    const NodeId gateway = package.gateways[i];
    if (i < package.gateway_count) {
      if (!id_valid(gateway)) return malformed("site package gateway id");
      for (std::size_t j = 0; j < i; ++j) {
        if (package.gateways[j] == gateway) return malformed("site package gateway duplicate");
      }
    } else if (gateway != 0) {
      return malformed("site package gateway tail");
    }
  }
  return Status::success();
}

Status site_package_encode(const SitePackage& package,
                           ByteBuffer<kSitePackageSize>& out) noexcept {
  out.clear();
  const Status valid = site_package_validate(package);
  if (!valid) return Status::error(StatusCode::InvalidArgument, valid.detail);
  ByteWriter writer(out.writable());
  Status status = writer.write_u8(kJoinEadVersion);
  if (status) status = writer.write_u8(0);
  if (status) status = writer.write_u16(0);
  if (status) status = writer.write_u64(package.site_id);
  if (status) status = writer.write_u64(package.network);
  if (status) status = writer.write_u32(package.rs_epoch);
  if (status) status = writer.write_u32(package.gk_epoch);
  if (status) status = writer.write_bytes(ByteView{package.gk.data(), package.gk.size()});
  if (status) status = writer.write_u8(package.channel);
  if (status) status = writer.write_u8(package.role);
  if (status) status = writer.write_u8(package.gateway_count);
  if (status) status = writer.write_u8(0);
  if (status) status = writer.write_u32(package.channel_epoch);
  for (std::size_t i = 0; status && i < kSitePackageGatewayMax; ++i) {
    status = writer.write_u64(package.gateways[i]);
  }
  if (status) status = writer.write_u64(package.authority_time_s);
  if (status) status = writer.write_u32(package.time_uncertainty_ms);
  if (status) status = writer.write_u32(package.membership_revision);
  if (status) status = writer.write_u32(0);
  if (!status) return status;
  out.size = writer.size();
  return Status::success();
}

Status site_package_decode(const ByteView bytes, SitePackage& out) noexcept {
  out = SitePackage{};
  if (bytes.data == nullptr || bytes.size != kSitePackageSize) {
    return malformed("site package size");
  }
  ByteReader reader(bytes);
  std::uint8_t reserved8 = 0;
  std::uint32_t reserved32 = 0;
  Status status = read_version_flags(reader, "site package head");
  if (status) status = expect_zero16(reader, "site package reserved");
  if (status) status = reader.read_u64(out.site_id);
  if (status) status = reader.read_u64(out.network);
  if (status) status = reader.read_u32(out.rs_epoch);
  if (status) status = reader.read_u32(out.gk_epoch);
  if (status) status = reader.read_bytes(MutableByteView{out.gk.data(), out.gk.size()});
  if (status) status = reader.read_u8(out.channel);
  if (status) status = reader.read_u8(out.role);
  if (status) status = reader.read_u8(out.gateway_count);
  if (status) status = reader.read_u8(reserved8);
  if (status && reserved8 != 0) status = malformed("site package reserved");
  if (status) status = reader.read_u32(out.channel_epoch);
  for (std::size_t i = 0; status && i < kSitePackageGatewayMax; ++i) {
    status = reader.read_u64(out.gateways[i]);
  }
  if (status) status = reader.read_u64(out.authority_time_s);
  if (status) status = reader.read_u32(out.time_uncertainty_ms);
  if (status) status = reader.read_u32(out.membership_revision);
  if (status) status = reader.read_u32(reserved32);
  if (status && reserved32 != 0) status = malformed("site package reserved");
  if (status) status = expect_end(reader, "site package trailing");
  if (status) status = site_package_validate(out);
  if (!status) out = SitePackage{};
  return status;
}

// === RemovalNotice =================================================================

Status removal_notice_validate(const RemovalNotice& notice) noexcept {
  const auto reason = static_cast<std::uint8_t>(notice.reason);
  if (reason < 1 || reason > 4) return malformed("removal notice reason");
  if (!id_valid(notice.site_id)) return malformed("removal notice site_id");
  if (!id_valid(notice.node_id)) return malformed("removal notice node_id");
  if (notice.generation == 0) return malformed("removal notice generation");
  if (notice.rs_epoch == 0) return malformed("removal notice rs_epoch");
  return Status::success();
}

Status removal_notice_payload_encode(const RemovalNotice& notice,
                                     ByteBuffer<kRemovalNoticePayloadSize>& out) noexcept {
  out.clear();
  const Status valid = removal_notice_validate(notice);
  if (!valid) return Status::error(StatusCode::InvalidArgument, valid.detail);
  ByteWriter writer(out.writable());
  Status status = writer.write_u8(kJoinEadVersion);
  if (status) status = writer.write_u8(static_cast<std::uint8_t>(notice.reason));
  if (status) status = writer.write_u16(0);
  if (status) status = writer.write_u64(notice.site_id);
  if (status) status = writer.write_u64(notice.node_id);
  if (status) status = writer.write_u32(notice.generation);
  if (status) status = writer.write_u32(notice.rs_epoch);
  if (!status) return status;
  out.size = writer.size();
  return Status::success();
}

Status removal_notice_payload_decode(const ByteView payload, RemovalNotice& out) noexcept {
  out = RemovalNotice{};
  if (payload.data == nullptr || payload.size != kRemovalNoticePayloadSize) {
    return malformed("removal notice payload size");
  }
  ByteReader reader(payload);
  std::uint8_t version = 0, reason = 0;
  Status status = reader.read_u8(version);
  if (status) status = reader.read_u8(reason);
  if (!status) return malformed("removal notice head");
  if (version != kJoinEadVersion) {
    return Status::error(StatusCode::Unsupported, "removal notice version");
  }
  status = expect_zero16(reader, "removal notice reserved");
  if (status) status = reader.read_u64(out.site_id);
  if (status) status = reader.read_u64(out.node_id);
  if (status) status = reader.read_u32(out.generation);
  if (status) status = reader.read_u32(out.rs_epoch);
  if (status) status = expect_end(reader, "removal notice trailing");
  out.reason = static_cast<RevocationReason>(reason);
  if (status) status = removal_notice_validate(out);
  if (!status) out = RemovalNotice{};
  return status;
}

Status removal_notice_aad(const NetworkId network,
                          ByteBuffer<kRemovalNoticeAadSize>& out) noexcept {
  out.clear();
  ByteWriter writer(out.writable());
  Status status = writer.write_bytes(ByteView{
      reinterpret_cast<const std::uint8_t*>(kRemovalNoticeDomain), sizeof(kRemovalNoticeDomain)});
  if (status) status = writer.write_u64(network);
  if (!status) return status;
  out.size = writer.size();
  return Status::success();
}

Status removal_notice_assemble(const ByteView payload, const ByteView signature,
                               ByteBuffer<kRemovalNoticeObjectSize>& out) noexcept {
  out.clear();
  RemovalNotice notice{};
  const Status decoded = removal_notice_payload_decode(payload, notice);
  if (!decoded) return Status::error(StatusCode::InvalidArgument, decoded.detail);
  return cose_es256_assemble(payload, signature, out.writable(), out.size);
}

Status removal_notice_decode(const ByteView object, RemovalNotice& out) noexcept {
  out = RemovalNotice{};
  CoseEs256Parts parts{};
  const Status parsed = cose_es256_parse(object, kRemovalNoticePayloadSize,
                                         kRemovalNoticePayloadSize, kRemovalNoticeObjectSize,
                                         parts);
  if (!parsed) return parsed;
  return removal_notice_payload_decode(parts.payload, out);
}

Status removal_notice_verify(const ByteView object, const P256PublicKey& sak_pubkey,
                             const std::uint64_t own_site_id, const NetworkId own_network,
                             const NodeId own_node, const std::uint32_t own_generation,
                             RemovalNotice& out, bool& verified,
                             const Es256Verifier& verifier) noexcept {
  verified = false;
  out = RemovalNotice{};
  CoseEs256Parts parts{};
  Status status = cose_es256_parse(object, kRemovalNoticePayloadSize, kRemovalNoticePayloadSize,
                                   kRemovalNoticeObjectSize, parts);
  if (status) status = removal_notice_payload_decode(parts.payload, out);
  if (!status) return status;
  if (out.site_id != own_site_id || out.node_id != own_node ||
      out.generation < own_generation) {
    return Status::success();  // not addressed to this membership: denied
  }
  ByteBuffer<kRemovalNoticeAadSize> aad{};
  status = removal_notice_aad(own_network, aad);
  if (!status) return status;
  return cose_es256_verify(parts.payload, aad.view(), parts.signature, sak_pubkey, verifier,
                           verified);
}

// === JoinResult ====================================================================

Status join_result_validate(const JoinResult& result) noexcept {
  const auto verdict = static_cast<std::uint8_t>(result.verdict);
  if (!verdict_known(verdict)) return malformed("join result verdict");
  if (!retry_ok(result.verdict, result.retry_after_s)) {
    return malformed("join result retry_after_s");
  }
  const bool allow = result.verdict == JoinVerdict::Allow;
  const bool pending = result.verdict == JoinVerdict::PendingAssignment;
  const bool removed = result.verdict == JoinVerdict::Removed;
  if (!allow && (result.member_cert.size != 0 || result.assignment_ticket.size != 0 ||
                 !package_empty(result.site_package))) {
    return malformed("join result allow fields on another verdict");
  }
  if (!pending && result.pending_ticket.size != 0) {
    return malformed("join result pending ticket on another verdict");
  }
  if (!removed && result.removal_notice.size != 0) {
    return malformed("join result removal notice on another verdict");
  }
  if (allow) {
    if (result.member_cert.data == nullptr || result.member_cert.size == 0 ||
        result.member_cert.size > kRlcw1CertMax) {
      return malformed("join result membercert length");
    }
    CertClaims member{};
    const Status cert = cert_decode(result.member_cert, member);
    if (!cert) return cert;
    if (member.type != CertType::Member) return malformed("join result not a MemberCert");
    const Status package = site_package_validate(result.site_package);
    if (!package) return package;
    if (result.assignment_ticket.size > kAssignmentTicketMax ||
        (result.assignment_ticket.size > 0 && result.assignment_ticket.data == nullptr)) {
      return malformed("join result assignment ticket length");
    }
  }
  if (pending && (result.pending_ticket.data == nullptr || result.pending_ticket.size == 0 ||
                  result.pending_ticket.size > kPendingTicketMax)) {
    return malformed("join result pending ticket length");
  }
  if (removed) {
    RemovalNotice notice{};
    const Status decoded = removal_notice_decode(result.removal_notice, notice);
    if (!decoded) return decoded;
  }
  return Status::success();
}

std::size_t join_result_encoded_size(const JoinResult& result) noexcept {
  switch (result.verdict) {
    case JoinVerdict::Allow:
      return kJoinResultHeadSize + 2 + result.member_cert.size + kSitePackageSize + 2 +
             result.assignment_ticket.size;
    case JoinVerdict::PendingAssignment:
      return kJoinResultHeadSize + result.pending_ticket.size;
    case JoinVerdict::Removed: return kJoinResultHeadSize + result.removal_notice.size;
    case JoinVerdict::DenyNotHere:
    case JoinVerdict::DenyBlocked:
    case JoinVerdict::AuthorityBusy: return kJoinResultHeadSize;
  }
  return 0;
}

Status join_result_encode(const JoinResult& result, ByteBuffer<kJoinResultMax>& out) noexcept {
  out.clear();
  const Status valid = join_result_validate(result);
  if (!valid) return Status::error(StatusCode::InvalidArgument, valid.detail);
  const std::size_t total = join_result_encoded_size(result);
  if (total > kJoinResultMax) return Status::error(StatusCode::InvalidArgument, "join result size");
  ByteWriter writer(out.writable());
  Status status = writer.write_u8(kJoinEadVersion);
  if (status) status = writer.write_u8(static_cast<std::uint8_t>(result.verdict));
  if (status) status = writer.write_u16(0);
  if (status) status = writer.write_u32(result.retry_after_s);
  if (status) status = writer.write_u16(static_cast<std::uint16_t>(total - kJoinResultHeadSize));
  if (status) status = writer.write_u16(0);
  switch (result.verdict) {
    case JoinVerdict::Allow: {
      ByteBuffer<kSitePackageSize> package{};
      if (status) status = writer.write_u16(static_cast<std::uint16_t>(result.member_cert.size));
      if (status) status = writer.write_bytes(result.member_cert);
      if (status) status = site_package_encode(result.site_package, package);
      if (status) status = writer.write_bytes(package.view());
      if (status) {
        status = writer.write_u16(static_cast<std::uint16_t>(result.assignment_ticket.size));
      }
      if (status && result.assignment_ticket.size > 0) {
        status = writer.write_bytes(result.assignment_ticket);
      }
      break;
    }
    case JoinVerdict::PendingAssignment:
      if (status) status = writer.write_bytes(result.pending_ticket);
      break;
    case JoinVerdict::Removed:
      if (status) status = writer.write_bytes(result.removal_notice);
      break;
    case JoinVerdict::DenyNotHere:
    case JoinVerdict::DenyBlocked:
    case JoinVerdict::AuthorityBusy: break;
  }
  if (!status) return status;
  out.size = writer.size();
  return Status::success();
}

Status join_result_decode(const ByteView value, JoinResult& out) noexcept {
  out = JoinResult{};
  if (value.data == nullptr || value.size < kJoinResultHeadSize || value.size > kJoinResultMax) {
    return malformed("join result size");
  }
  ByteReader reader(value);
  std::uint8_t version = 0, verdict = 0;
  std::uint16_t reason = 0, body_len = 0, reserved = 0;
  std::uint32_t retry = 0;
  Status status = reader.read_u8(version);
  if (status) status = reader.read_u8(verdict);
  if (status) status = reader.read_u16(reason);
  if (status) status = reader.read_u32(retry);
  if (status) status = reader.read_u16(body_len);
  if (status) status = reader.read_u16(reserved);
  if (!status) return malformed("join result head");
  if (version != kJoinEadVersion) {
    return Status::error(StatusCode::Unsupported, "join result version");
  }
  if (!verdict_known(verdict) || reason != 0 || reserved != 0 ||
      body_len != value.size - kJoinResultHeadSize) {
    return malformed("join result head");
  }
  JoinResult result{};
  result.verdict = static_cast<JoinVerdict>(verdict);
  result.retry_after_s = retry;
  const ByteView body{value.data + kJoinResultHeadSize, body_len};
  switch (result.verdict) {
    case JoinVerdict::Allow: {
      if (body.size < kJoinAllowBodyMin) return malformed("join result allow body");
      const std::size_t cert_len = (static_cast<std::size_t>(body.data[0]) << 8U) | body.data[1];
      if (cert_len == 0 || cert_len > kRlcw1CertMax ||
          2 + cert_len + kSitePackageSize + 2 > body.size) {
        return malformed("join result membercert length");
      }
      result.member_cert = ByteView{body.data + 2, cert_len};
      std::size_t pos = 2 + cert_len;
      status = site_package_decode(ByteView{body.data + pos, kSitePackageSize},
                                   result.site_package);
      if (!status) return status;
      pos += kSitePackageSize;
      const std::size_t ticket_len =
          (static_cast<std::size_t>(body.data[pos]) << 8U) | body.data[pos + 1];
      pos += 2;
      if (ticket_len > kAssignmentTicketMax || pos + ticket_len != body.size) {
        return malformed("join result assignment ticket length");
      }
      if (ticket_len > 0) result.assignment_ticket = ByteView{body.data + pos, ticket_len};
      break;
    }
    case JoinVerdict::PendingAssignment: result.pending_ticket = body; break;
    case JoinVerdict::Removed: result.removal_notice = body; break;
    case JoinVerdict::DenyNotHere:
    case JoinVerdict::DenyBlocked:
    case JoinVerdict::AuthorityBusy:
      if (body.size != 0) return malformed("join result body on an empty verdict");
      break;
  }
  status = join_result_validate(result);
  if (!status) return status.code == StatusCode::InvalidArgument ? malformed(status.detail)
                                                                   : status;
  out = result;
  return Status::success();
}

Status join_allow_verify(const JoinResult& result, const CertClaims& site_cert, const NodeId node,
                         const P256PublicKey& device_pubkey, const bool strict_assignment,
                         CertClaims& member_out, bool& verified,
                         const Es256Verifier& verifier) noexcept {
  verified = false;
  member_out = CertClaims{};
  if (result.verdict != JoinVerdict::Allow || site_cert.type != CertType::Site) {
    return Status::error(StatusCode::InvalidArgument, "join allow verify arguments");
  }
  const Status valid = join_result_validate(result);
  if (!valid) return valid;
  bool signature_ok = false;
  Status status = cert_verify(result.member_cert, site_cert.pubkey, member_out, signature_ok,
                              verifier);
  if (!status) return status;
  if (!signature_ok) return Status::success();                                   // step 1
  if (!member_cert_matches(member_out, site_cert, node, device_pubkey).ok()) {   // steps 2-4
    return Status::success();
  }
  const SitePackage& package = result.site_package;
  if (package.site_id != site_cert.subject || package.network != member_out.network ||
      package.role != member_out.role) {                                          // steps 3-4
    return Status::success();
  }
  if (strict_assignment) {                                                        // step 5
    if (result.assignment_ticket.size == 0) return Status::success();
    return Status::error(StatusCode::Unsupported, "assignment ticket format not pinned");
  }
  verified = true;
  return Status::success();
}

// === EAD field =====================================================================

Status join_ead_item_encode(const JoinEad label, const ByteView value,
                            ByteBuffer<kJoinEadItemMax>& out) noexcept {
  out.clear();
  if (!join_ead_value_size_ok(label, value.size) || value.data == nullptr) {
    return Status::error(StatusCode::InvalidArgument, "ead value size");
  }
  const std::uint32_t argument = static_cast<std::uint32_t>(label) - 1U;  // -label
  ByteWriter writer(out.writable());
  Status status = writer.write_u8(0x3A);
  if (status) status = writer.write_u32(argument);
  if (status) {
    if (value.size <= 23) {
      status = writer.write_u8(static_cast<std::uint8_t>(0x40 + value.size));
    } else if (value.size <= 0xFF) {
      status = writer.write_u8(0x58);
      if (status) status = writer.write_u8(static_cast<std::uint8_t>(value.size));
    } else {
      status = writer.write_u8(0x59);
      if (status) status = writer.write_u16(static_cast<std::uint16_t>(value.size));
    }
  }
  if (status) status = writer.write_bytes(value);
  if (!status) return status;
  out.size = writer.size();
  return Status::success();
}

Status join_ead_find(const ByteView ead, const JoinEad expected, ByteView& value) noexcept {
  value = ByteView{};
  if (ead.data == nullptr || ead.size == 0 || ead.size > kJoinEadFieldMax) {
    return malformed("ead field bounds");
  }
  bool found = false;
  ByteView found_value{};
  std::size_t pos = 0;
  while (pos < ead.size) {
    bool negative = false;
    std::uint64_t argument = 0;
    Status status = read_int(ead, pos, negative, argument);
    if (!status) return status;
    // An optional bstr value follows the label.
    ByteView item_value{};
    bool has_value = false;
    if (pos < ead.size && (ead.data[pos] >> 5U) == 2) {
      status = read_bstr(ead, pos, item_value);
      if (!status) return status;
      has_value = true;
    }
    if (!negative && argument == 0) continue;  // padding: ignored (RFC 9528 §3.8.1)
    const std::uint64_t label = negative ? argument + 1U : argument;
    if (!negative || !join_ead_known(label) ||
        label != static_cast<std::uint32_t>(expected)) {
      return malformed(negative ? "ead unexpected critical item" : "ead unexpected item");
    }
    if (found) return malformed("ead item duplicated");
    if (!has_value || !join_ead_value_size_ok(expected, item_value.size)) {
      return malformed("ead value size");
    }
    found = true;
    found_value = item_value;
  }
  if (!found) return malformed("ead item missing");
  value = found_value;
  return Status::success();
}

Status join_ead_find_with_credential(const ByteView ead, const JoinEad expected,
                                     ByteView& credential, ByteView& value) noexcept {
  credential = ByteView{};
  value = ByteView{};
  if (expected != JoinEad::Offer && expected != JoinEad::Request) {
    return Status::error(StatusCode::InvalidArgument, "credential rides EAD_2/EAD_3 only");
  }
  if (ead.data == nullptr || ead.size == 0 || ead.size > kJoinEadFieldMax) {
    return malformed("ead field bounds");
  }
  // 0: nothing yet, 1: message item seen, 2: message item then Credential.
  int seen = 0;
  ByteView found_credential{};
  ByteView found_value{};
  std::size_t pos = 0;
  while (pos < ead.size) {
    bool negative = false;
    std::uint64_t argument = 0;
    Status status = read_int(ead, pos, negative, argument);
    if (!status) return status;
    ByteView item_value{};
    bool has_value = false;
    if (pos < ead.size && (ead.data[pos] >> 5U) == 2) {
      status = read_bstr(ead, pos, item_value);
      if (!status) return status;
      has_value = true;
    }
    if (!negative && argument == 0) continue;  // padding: ignored (RFC 9528 §3.8.1)
    if (!negative) return malformed("ead unexpected item");
    const std::uint64_t label = argument + 1U;
    const JoinEad want = seen == 0 ? expected : JoinEad::Credential;
    if (seen == 2 || label != static_cast<std::uint32_t>(want)) {
      return malformed(seen == 2 ? "ead item after the credential"
                                 : "ead message item or credential out of order");
    }
    if (!has_value || !join_ead_value_size_ok(want, item_value.size)) return malformed("ead value size");
    if (seen == 0) {
      found_value = item_value;
    } else {
      found_credential = item_value;
    }
    ++seen;
  }
  if (seen != 2) return malformed("ead item missing");
  credential = found_credential;
  value = found_value;
  return Status::success();
}

Status join_credential_check(const ByteView credential, const CertType type, const ByteView kid,
                             CertClaims& out) noexcept {
  out = CertClaims{};
  CertClaims claims{};
  Status status = cert_decode(credential, claims);
  if (!status) return status;
  if (claims.type != type) {
    return Status::error(StatusCode::AuthenticationFailed, "credential certificate type");
  }
  Digest256 computed{};
  status = cert_subject_kid(claims, computed);
  if (!status) return status;
  if (kid.data == nullptr || kid.size != computed.size() ||
      std::memcmp(kid.data, computed.data(), computed.size()) != 0) {
    return Status::error(StatusCode::AuthenticationFailed, "credential does not match the kid");
  }
  out = claims;
  return Status::success();
}

// === DAMS exporter context =========================================================

namespace {

// CBOR unsigned integer, shortest form — byte-identical to the Rust twin's
// write_uint (host/routeloom-join/src/lib.rs).
Status dams_uint(const std::uint64_t value, ByteWriter& writer) noexcept {
  if (value < 24) return writer.write_u8(static_cast<std::uint8_t>(value));
  Status status = Status::success();
  if (value <= 0xFF) {
    status = writer.write_u8(0x18);
    if (status) status = writer.write_u8(static_cast<std::uint8_t>(value));
  } else if (value <= 0xFFFF) {
    status = writer.write_u8(0x19);
    if (status) status = writer.write_u16(static_cast<std::uint16_t>(value));
  } else if (value <= 0xFFFFFFFFULL) {
    status = writer.write_u8(0x1A);
    if (status) status = writer.write_u32(static_cast<std::uint32_t>(value));
  } else {
    status = writer.write_u8(0x1B);
    if (status) status = writer.write_u64(value);
  }
  return status;
}

}  // namespace

Status dams_exporter_context(const NetworkId network, const NodeId node,
                             const std::uint64_t site_id, const Digest256& device_kid,
                             const Digest256& sak_kid,
                             ByteBuffer<kJoinDamsContextMax>& out) noexcept {
  out.clear();
  if (network == 0 || (network & 0xFFFFFFFFULL) == 0 || !id_valid(node) ||
      !id_valid(site_id)) {
    return Status::error(StatusCode::InvalidArgument, "dams context ids");
  }
  // ["RouteLoom", 1, 4, network, node_id, site_id, device_kid, sak_kid]
  static const std::array<std::uint8_t, 9> kDamsTag{'R', 'o', 'u', 't', 'e',
                                                  'L', 'o', 'o', 'm'};
  ByteWriter writer(out.writable());
  Status status = writer.write_u8(0x88);  // array(8)
  if (status) status = writer.write_u8(0x69);  // text(9)
  if (status) status = writer.write_bytes(ByteView{kDamsTag.data(), kDamsTag.size()});
  if (status) status = dams_uint(1, writer);  // context version
  if (status) status = dams_uint(kJoinDamsExporterPurpose, writer);
  if (status) status = dams_uint(network, writer);
  if (status) status = dams_uint(node, writer);
  if (status) status = dams_uint(site_id, writer);
  for (const Digest256* kid : {&device_kid, &sak_kid}) {
    if (status) status = writer.write_u8(0x58);  // bstr(32)
    if (status) status = writer.write_u8(0x20);
    if (status) status = writer.write_bytes(ByteView{kid->data(), kid->size()});
  }
  if (!status) return status;
  out.size = writer.size();
  return Status::success();
}

}  // namespace routeloom::sdkv1
