#include "routeloom/rlcw1.hpp"

#include <cstring>
#include <initializer_list>

#include "routeloom/byte_io.hpp"
#include "routeloom/config_cose.hpp"      // kSecp256r1Order/HalfOrder, cose_be32_cmp
#include "routeloom/device_credential.hpp"  // credential_kid (canonical COSE_Key)
#include "routeloom/discovery_scope.hpp"    // Sha256

extern "C" {
#include "uECC.h"
}

namespace routeloom::sdkv1 {
namespace {

constexpr std::uint64_t kAllOnes = ~std::uint64_t{0};

// Restricted envelope head: tag 18, array(4), protected bstr {1:-7},
// empty unprotected map.
constexpr std::array<std::uint8_t, 7> kSign1Head{{0xD2, 0x84, 0x43, 0xA1, 0x01, 0x26, 0xA0}};
constexpr std::array<std::uint8_t, 3> kProtectedEs256{{0xA1, 0x01, 0x26}};
// "Signature1" text(10).
constexpr std::array<std::uint8_t, 11> kSignature1{
    {0x6A, 'S', 'i', 'g', 'n', 'a', 't', 'u', 'r', 'e', '1'}};
// -65537 = major type 1, argument 65536 in the 4-byte form.
constexpr std::array<std::uint8_t, 5> kPrivateLabel{{0x3A, 0x00, 0x01, 0x00, 0x00}};
// cnf = {1: COSE_Key}; the COSE_Key head matches credential_cose_key_encode.
constexpr std::array<std::uint8_t, 12> kCnfHead{
    {0xA1, 0x01, 0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20}};
constexpr std::array<std::uint8_t, 3> kCnfY{{0x22, 0x58, 0x20}};

Status expect_bytes(const ByteView body, std::size_t& pos, const std::uint8_t* bytes,
                    const std::size_t size, const char* what) noexcept {
  if (pos + size > body.size || std::memcmp(body.data + pos, bytes, size) != 0) {
    return Status::error(StatusCode::ProtocolError, what);
  }
  pos += size;
  return Status::success();
}

// Canonical unsigned integer (major type 0, shortest form) with a width cap.
Status read_uint(const ByteView body, std::size_t& pos, const std::uint64_t max,
                 std::uint64_t& out, const char* what) noexcept {
  out = 0;
  if (pos >= body.size) return Status::error(StatusCode::ProtocolError, what);
  const std::uint8_t ib = body.data[pos++];
  std::size_t bytes = 0;
  std::uint64_t minimum = 0;
  if (ib <= 0x17) {
    out = ib;
  } else {
    switch (ib) {
      case 0x18: bytes = 1; minimum = 24; break;
      case 0x19: bytes = 2; minimum = 0x100; break;
      case 0x1A: bytes = 4; minimum = 0x10000; break;
      case 0x1B: bytes = 8; minimum = 0x100000000ULL; break;
      default: return Status::error(StatusCode::ProtocolError, what);
    }
    if (pos + bytes > body.size) return Status::error(StatusCode::ProtocolError, what);
    for (std::size_t i = 0; i < bytes; ++i) out = (out << 8U) | body.data[pos + i];
    pos += bytes;
    if (out < minimum) return Status::error(StatusCode::ProtocolError, what);
  }
  if (out > max) return Status::error(StatusCode::ProtocolError, what);
  return Status::success();
}

Status write_uint(ByteWriter& writer, const std::uint64_t value) noexcept {
  if (value <= 0x17U) return writer.write_u8(static_cast<std::uint8_t>(value));
  Status status;
  if (value <= 0xFFU) {
    status = writer.write_u8(0x18);
    if (status) status = writer.write_u8(static_cast<std::uint8_t>(value));
  } else if (value <= 0xFFFFU) {
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

// Definite bstr head, minimal length form (payloads here never exceed
// 0xFFFF).
Status write_bstr_head(ByteWriter& writer, const std::size_t size) noexcept {
  if (size <= 23) return writer.write_u8(static_cast<std::uint8_t>(0x40 + size));
  Status status;
  if (size <= 0xFF) {
    status = writer.write_u8(0x58);
    if (status) status = writer.write_u8(static_cast<std::uint8_t>(size));
  } else if (size <= 0xFFFF) {
    status = writer.write_u8(0x59);
    if (status) status = writer.write_u16(static_cast<std::uint16_t>(size));
  } else {
    return Status::error(StatusCode::InvalidArgument, "bstr too long");
  }
  return status;
}

Status read_bstr(const ByteView body, std::size_t& pos, ByteView& out,
                 const char* what) noexcept {
  out = ByteView{};
  if (pos >= body.size) return Status::error(StatusCode::ProtocolError, what);
  const std::uint8_t ib = body.data[pos++];
  std::size_t len = 0;
  if (ib >= 0x40 && ib <= 0x57) {
    len = ib - 0x40U;
  } else if (ib == 0x58) {
    if (pos >= body.size) return Status::error(StatusCode::ProtocolError, what);
    len = body.data[pos++];
    if (len <= 23) return Status::error(StatusCode::ProtocolError, what);
  } else if (ib == 0x59) {
    if (pos + 2 > body.size) return Status::error(StatusCode::ProtocolError, what);
    len = (static_cast<std::size_t>(body.data[pos]) << 8U) | body.data[pos + 1];
    pos += 2;
    if (len <= 0xFF) return Status::error(StatusCode::ProtocolError, what);
  } else {
    return Status::error(StatusCode::ProtocolError, what);
  }
  if (pos + len > body.size) return Status::error(StatusCode::ProtocolError, what);
  out = ByteView{body.data + pos, len};
  pos += len;
  return Status::success();
}

bool id_valid(const std::uint64_t id) noexcept { return id != 0 && id != kAllOnes; }

std::uint8_t private_array_head(const CertType type) noexcept {
  switch (type) {
    case CertType::Device: return 0x84;
    case CertType::Site: return 0x85;
    case CertType::Member: return 0x86;
  }
  return 0;
}

class MicroEccEs256Verifier final : public Es256Verifier {
 public:
  bool verify_digest(const P256PublicKey& pubkey, const Digest256& digest,
                     const Es256Signature& signature) const noexcept override {
    return uECC_verify(pubkey.data(), digest.data(),
                       static_cast<unsigned>(digest.size()), signature.data(),
                       uECC_secp256r1()) != 0;
  }
};

const MicroEccEs256Verifier kMicroEccVerifier{};

}  // namespace

const Es256Verifier& default_es256_verifier() noexcept { return kMicroEccVerifier; }

bool p256_public_key_valid(const P256PublicKey& pubkey) noexcept {
  return uECC_valid_public_key(pubkey.data(), uECC_secp256r1()) != 0;
}

bool es256_signature_canonical(const ByteView signature) noexcept {
  if (signature.data == nullptr || signature.size != kEs256SignatureSize) return false;
  std::array<std::uint8_t, 32> r{}, s{};
  std::memcpy(r.data(), signature.data, 32);
  std::memcpy(s.data(), signature.data + 32, 32);
  return !cose_be32_is_zero(r) && !cose_be32_is_zero(s) &&
         cose_be32_cmp(r, kSecp256r1Order) < 0 &&
         cose_be32_cmp(s, kSecp256r1HalfOrder) <= 0;
}

bool p256_scalar_valid(const ByteView scalar) noexcept {
  if (scalar.data == nullptr || scalar.size != 32) return false;
  std::array<std::uint8_t, 32> value{};
  std::memcpy(value.data(), scalar.data, 32);
  return !cose_be32_is_zero(value) && cose_be32_cmp(value, kSecp256r1Order) < 0;
}

void es256_signature_normalize_low_s(Es256Signature& signature) noexcept {
  std::array<std::uint8_t, 32> s{};
  std::memcpy(s.data(), signature.data() + 32, 32);
  if (cose_be32_is_zero(s) || cose_be32_cmp(s, kSecp256r1Order) >= 0 ||
      cose_be32_cmp(s, kSecp256r1HalfOrder) <= 0) {
    return;
  }
  // s is in (n/2, n): n - s is the low-S twin of the same signature.
  std::uint16_t borrow = 0;
  for (std::size_t i = 32; i-- > 0;) {
    const std::uint16_t diff = static_cast<std::uint16_t>(kSecp256r1Order[i]) -
                               static_cast<std::uint16_t>(s[i]) - borrow;
    signature[i + 32] = static_cast<std::uint8_t>(diff & 0xFFU);
    borrow = (diff >> 8) & 1U;
  }
}

Status cert_claims_validate(const CertClaims& claims) noexcept {
  if (!id_valid(claims.issuer) || !id_valid(claims.subject)) {
    return Status::error(StatusCode::InvalidArgument, "cert issuer/subject");
  }
  if (!p256_public_key_valid(claims.pubkey)) {
    return Status::error(StatusCode::InvalidArgument, "cert key off curve");
  }
  switch (claims.type) {
    case CertType::Device:
      if (claims.network_low32 != 0 || claims.usage != 0 || claims.network != 0 ||
          claims.role != 0 || claims.assignment_generation != 0 ||
          claims.site_epoch != 0) {
        return Status::error(StatusCode::InvalidArgument, "devcert foreign field");
      }
      return Status::success();
    case CertType::Site:
      if (claims.model != 0 || claims.hw_rev != 0 || claims.network != 0 ||
          claims.role != 0 || claims.assignment_generation != 0) {
        return Status::error(StatusCode::InvalidArgument, "sitecert foreign field");
      }
      if (claims.network_low32 == 0 || claims.usage == 0 ||
          (claims.usage & ~kSiteUsageMask) != 0) {
        return Status::error(StatusCode::InvalidArgument, "sitecert fields");
      }
      return Status::success();
    case CertType::Member:
      if (claims.model != 0 || claims.hw_rev != 0 || claims.network_low32 != 0 ||
          claims.usage != 0) {
        return Status::error(StatusCode::InvalidArgument, "membercert foreign field");
      }
      if ((claims.network & 0xFFFFFFFFULL) == 0 ||
          (claims.network >> 32U) != claims.site_epoch || claims.role == 0 ||
          (claims.role & ~kMemberRoleMask) != 0 || claims.assignment_generation == 0) {
        return Status::error(StatusCode::InvalidArgument, "membercert fields");
      }
      return Status::success();
  }
  return Status::error(StatusCode::InvalidArgument, "cert type");
}

Status cert_payload_encode(const CertClaims& claims,
                           ByteBuffer<kRlcw1PayloadMax>& out) noexcept {
  out.clear();
  const Status valid = cert_claims_validate(claims);
  if (!valid) return valid;
  ByteWriter writer(out.writable());
  Status status = writer.write_u8(0xA4);
  if (status) status = writer.write_u8(0x01);
  if (status) status = write_uint(writer, claims.issuer);
  if (status) status = writer.write_u8(0x02);
  if (status) status = write_uint(writer, claims.subject);
  if (status) status = writer.write_u8(0x08);
  if (status) status = writer.write_bytes(ByteView{kCnfHead.data(), kCnfHead.size()});
  if (status) status = writer.write_bytes(ByteView{claims.pubkey.data(), 32});
  if (status) status = writer.write_bytes(ByteView{kCnfY.data(), kCnfY.size()});
  if (status) status = writer.write_bytes(ByteView{claims.pubkey.data() + 32, 32});
  if (status) {
    status = writer.write_bytes(ByteView{kPrivateLabel.data(), kPrivateLabel.size()});
  }
  if (status) status = writer.write_u8(private_array_head(claims.type));
  if (status) status = write_uint(writer, static_cast<std::uint8_t>(claims.type));
  switch (claims.type) {
    case CertType::Device:
      if (status) status = write_uint(writer, claims.model);
      if (status) status = write_uint(writer, claims.hw_rev);
      break;
    case CertType::Site:
      if (status) status = write_uint(writer, claims.network_low32);
      if (status) status = write_uint(writer, claims.site_epoch);
      if (status) status = write_uint(writer, claims.usage);
      break;
    case CertType::Member:
      if (status) status = write_uint(writer, claims.network);
      if (status) status = write_uint(writer, claims.role);
      if (status) status = write_uint(writer, claims.assignment_generation);
      if (status) status = write_uint(writer, claims.site_epoch);
      break;
  }
  if (status) status = write_uint(writer, claims.serial);
  if (!status) return status;
  out.size = writer.size();
  return Status::success();
}

Status cert_payload_decode(const ByteView payload, CertClaims& out) noexcept {
  out = CertClaims{};
  if (payload.data == nullptr || payload.size > kRlcw1PayloadMax) {
    return Status::error(StatusCode::ProtocolError, "cert payload bounds");
  }
  std::size_t pos = 0;
  static constexpr std::uint8_t kMap4 = 0xA4, kIss = 0x01, kSub = 0x02, kCnf = 0x08;
  Status status = expect_bytes(payload, pos, &kMap4, 1, "cert claims map");
  if (status) status = expect_bytes(payload, pos, &kIss, 1, "cert iss label");
  if (status) status = read_uint(payload, pos, kAllOnes, out.issuer, "cert iss");
  if (status) status = expect_bytes(payload, pos, &kSub, 1, "cert sub label");
  if (status) status = read_uint(payload, pos, kAllOnes, out.subject, "cert sub");
  if (status) status = expect_bytes(payload, pos, &kCnf, 1, "cert cnf label");
  if (status) status = expect_bytes(payload, pos, kCnfHead.data(), kCnfHead.size(), "cert cnf key");
  if (status && pos + 32 <= payload.size) {
    std::memcpy(out.pubkey.data(), payload.data + pos, 32);
    pos += 32;
  } else if (status) {
    status = Status::error(StatusCode::ProtocolError, "cert cnf x");
  }
  if (status) status = expect_bytes(payload, pos, kCnfY.data(), kCnfY.size(), "cert cnf y label");
  if (status && pos + 32 <= payload.size) {
    std::memcpy(out.pubkey.data() + 32, payload.data + pos, 32);
    pos += 32;
  } else if (status) {
    status = Status::error(StatusCode::ProtocolError, "cert cnf y");
  }
  if (status) {
    status = expect_bytes(payload, pos, kPrivateLabel.data(), kPrivateLabel.size(),
                          "cert private label");
  }
  if (!status) return status;
  if (pos + 2 > payload.size) {
    return Status::error(StatusCode::ProtocolError, "cert private claim");
  }
  const std::uint8_t array_head = payload.data[pos];
  const std::uint8_t type_byte = payload.data[pos + 1];
  if (type_byte < 1 || type_byte > 3 ||
      array_head != private_array_head(static_cast<CertType>(type_byte))) {
    return Status::error(StatusCode::ProtocolError, "cert private claim type");
  }
  pos += 2;
  out.type = static_cast<CertType>(type_byte);
  std::uint64_t a = 0, b = 0, c = 0, d = 0;
  switch (out.type) {
    case CertType::Device:
      status = read_uint(payload, pos, 0xFFFFU, a, "devcert model");
      if (status) status = read_uint(payload, pos, 0xFFU, b, "devcert hw_rev");
      out.model = static_cast<std::uint16_t>(a);
      out.hw_rev = static_cast<std::uint8_t>(b);
      break;
    case CertType::Site:
      status = read_uint(payload, pos, 0xFFFFFFFFULL, a, "sitecert network_low32");
      if (status) status = read_uint(payload, pos, 0xFFFFFFFFULL, b, "sitecert site_epoch");
      if (status) status = read_uint(payload, pos, 0xFFU, c, "sitecert usage");
      out.network_low32 = static_cast<std::uint32_t>(a);
      out.site_epoch = static_cast<std::uint32_t>(b);
      out.usage = static_cast<std::uint8_t>(c);
      break;
    case CertType::Member:
      status = read_uint(payload, pos, kAllOnes, out.network, "membercert network");
      if (status) status = read_uint(payload, pos, 0xFFFFFFFFULL, a, "membercert role");
      if (status) status = read_uint(payload, pos, 0xFFFFFFFFULL, b, "membercert generation");
      if (status) status = read_uint(payload, pos, 0xFFFFFFFFULL, c, "membercert site_epoch");
      out.role = static_cast<std::uint32_t>(a);
      out.assignment_generation = static_cast<std::uint32_t>(b);
      out.site_epoch = static_cast<std::uint32_t>(c);
      break;
  }
  if (status) status = read_uint(payload, pos, 0xFFFFFFFFULL, d, "cert serial");
  if (!status) return status;
  out.serial = static_cast<std::uint32_t>(d);
  if (pos != payload.size) {
    return Status::error(StatusCode::ProtocolError, "cert payload trailing");
  }
  const Status valid = cert_claims_validate(out);
  if (!valid) return Status::error(StatusCode::ProtocolError, valid.detail);
  return Status::success();
}

Status cose_es256_parse(const ByteView object, const std::size_t payload_min,
                        const std::size_t payload_max, const std::size_t object_max,
                        CoseEs256Parts& out) noexcept {
  out = CoseEs256Parts{};
  if (object.data == nullptr || object.size > object_max) {
    return Status::error(StatusCode::ProtocolError, "cose object bounds");
  }
  std::size_t pos = 0;
  Status status = expect_bytes(object, pos, kSign1Head.data(), kSign1Head.size(),
                               "cose sign1 head");
  ByteView payload{};
  if (status) status = read_bstr(object, pos, payload, "cose payload");
  ByteView signature{};
  if (status) status = read_bstr(object, pos, signature, "cose signature");
  if (!status) return status;
  if (payload.size < payload_min || payload.size > payload_max ||
      signature.size != kEs256SignatureSize || pos != object.size) {
    return Status::error(StatusCode::ProtocolError, "cose shape");
  }
  out.payload = payload;
  out.signature = signature;
  return Status::success();
}

void cose_es256_digest(const ByteView payload, const ByteView external_aad,
                       Digest256& out) noexcept {
  std::array<std::uint8_t, 3> head{};
  Sha256 sha;
  const std::uint8_t array4 = 0x84;
  sha.update(ByteView{&array4, 1});
  sha.update(ByteView{kSignature1.data(), kSignature1.size()});
  const std::uint8_t protected_head = 0x43;
  sha.update(ByteView{&protected_head, 1});
  sha.update(ByteView{kProtectedEs256.data(), kProtectedEs256.size()});
  for (const ByteView item : {external_aad, payload}) {
    ByteWriter writer(MutableByteView{head.data(), head.size()});
    (void)write_bstr_head(writer, item.size);
    sha.update(ByteView{head.data(), writer.size()});
    if (item.size > 0) sha.update(item);
  }
  sha.finish(out);
}

Status cose_es256_sig_structure(const ByteView payload, const ByteView external_aad,
                                const MutableByteView out, std::size_t& size) noexcept {
  size = 0;
  if (payload.size > 0xFFFF || external_aad.size > 0xFFFF ||
      (payload.size > 0 && payload.data == nullptr) ||
      (external_aad.size > 0 && external_aad.data == nullptr)) {
    return Status::error(StatusCode::InvalidArgument, "sig_structure fields");
  }
  ByteWriter writer(out);
  Status status = writer.write_u8(0x84);
  if (status) status = writer.write_bytes(ByteView{kSignature1.data(), kSignature1.size()});
  if (status) status = writer.write_u8(0x43);
  if (status) {
    status = writer.write_bytes(ByteView{kProtectedEs256.data(), kProtectedEs256.size()});
  }
  if (status) status = write_bstr_head(writer, external_aad.size);
  if (status && external_aad.size > 0) status = writer.write_bytes(external_aad);
  if (status) status = write_bstr_head(writer, payload.size);
  if (status && payload.size > 0) status = writer.write_bytes(payload);
  if (!status) return status;
  size = writer.size();
  return Status::success();
}

Status cose_es256_assemble(const ByteView payload, const ByteView signature,
                           const MutableByteView out, std::size_t& size) noexcept {
  size = 0;
  if (payload.data == nullptr || payload.size == 0 || payload.size > 0xFFFF ||
      signature.data == nullptr || signature.size != kEs256SignatureSize) {
    return Status::error(StatusCode::InvalidArgument, "cose assemble fields");
  }
  ByteWriter writer(out);
  Status status = writer.write_bytes(ByteView{kSign1Head.data(), kSign1Head.size()});
  if (status) status = write_bstr_head(writer, payload.size);
  if (status) status = writer.write_bytes(payload);
  if (status) status = write_bstr_head(writer, signature.size);
  if (status) status = writer.write_bytes(signature);
  if (!status) return status;
  size = writer.size();
  return Status::success();
}

Status cose_es256_verify(const ByteView payload, const ByteView external_aad,
                         const ByteView signature, const P256PublicKey& pubkey,
                         const Es256Verifier& verifier, bool& verified) noexcept {
  verified = false;
  if (payload.data == nullptr || signature.data == nullptr) {
    return Status::error(StatusCode::InvalidArgument, "cose verify input");
  }
  // Range + low-S before the point multiply; a non-canonical signature is
  // a denial, not a parse error (mirrors the RTM1/permit verifiers).
  if (!es256_signature_canonical(signature) || !p256_public_key_valid(pubkey)) {
    return Status::success();
  }
  Digest256 digest{};
  cose_es256_digest(payload, external_aad, digest);
  Es256Signature sig{};
  std::memcpy(sig.data(), signature.data, sig.size());
  verified = verifier.verify_digest(pubkey, digest, sig);
  return Status::success();
}

Status cert_parse(const ByteView cert, CoseEs256Parts& out) noexcept {
  return cose_es256_parse(cert, 1, kRlcw1PayloadMax, kRlcw1CertMax, out);
}

Status cert_decode(const ByteView cert, CertClaims& out) noexcept {
  out = CertClaims{};
  CoseEs256Parts parts{};
  const Status parsed = cert_parse(cert, parts);
  if (!parsed) return parsed;
  return cert_payload_decode(parts.payload, out);
}

Status cert_sig_structure(const ByteView payload,
                          ByteBuffer<kRlcw1SigStructureMax>& out) noexcept {
  out.clear();
  if (payload.size > kRlcw1PayloadMax) {
    return Status::error(StatusCode::InvalidArgument, "cert payload oversize");
  }
  return cose_es256_sig_structure(payload, ByteView{}, out.writable(), out.size);
}

Status cert_assemble(const ByteView payload, const ByteView signature,
                     ByteBuffer<kRlcw1CertMax>& out) noexcept {
  out.clear();
  if (payload.size > kRlcw1PayloadMax) {
    return Status::error(StatusCode::InvalidArgument, "cert payload oversize");
  }
  CertClaims claims{};
  const Status decoded = cert_payload_decode(payload, claims);
  if (!decoded) return decoded;
  return cose_es256_assemble(payload, signature, out.writable(), out.size);
}

Status cert_verify(const ByteView cert, const P256PublicKey& issuer_pubkey,
                   CertClaims& out, bool& verified,
                   const Es256Verifier& verifier) noexcept {
  verified = false;
  out = CertClaims{};
  CoseEs256Parts parts{};
  Status status = cert_parse(cert, parts);
  if (status) status = cert_payload_decode(parts.payload, out);
  if (!status) return status;
  return cose_es256_verify(parts.payload, ByteView{}, parts.signature, issuer_pubkey,
                           verifier, verified);
}

Status cert_subject_kid(const CertClaims& claims, Digest256& out) noexcept {
  return credential_kid(ByteView{claims.pubkey.data(), claims.pubkey.size()}, out);
}

Status member_cert_matches(const CertClaims& member, const CertClaims& site,
                           const NodeId node, const P256PublicKey& device_pubkey) noexcept {
  if (member.type != CertType::Member || site.type != CertType::Site) {
    return Status::error(StatusCode::InvalidArgument, "cert types");
  }
  const Status member_ok = cert_claims_validate(member);
  if (!member_ok) return member_ok;
  const Status site_ok = cert_claims_validate(site);
  if (!site_ok) return site_ok;
  if (member.subject != node || member.pubkey != device_pubkey) {
    return Status::error(StatusCode::AuthorizationFailed, "membercert not ours");
  }
  if (member.issuer != site.subject ||
      static_cast<std::uint32_t>(member.network & 0xFFFFFFFFULL) != site.network_low32 ||
      member.site_epoch != site.site_epoch) {
    return Status::error(StatusCode::AuthorizationFailed, "membercert not this site");
  }
  return Status::success();
}

}  // namespace routeloom::sdkv1
