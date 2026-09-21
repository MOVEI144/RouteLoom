#include "routeloom/config_cose.hpp"

#include <cstring>

#include "routeloom/byte_io.hpp"
#include "routeloom/discovery_scope.hpp"  // sha256

extern "C" {
#include "uECC.h"
}

namespace routeloom {
namespace {

// secp256r1 group order n =
// FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
// and (n-1)/2 = 7FFFFFFF80000000FFFFFFFFFFFFFFFFDE737D56D38CF4279DCE5617E3195A88
// (byte arrays defined at namespace scope below for the header externs).

Status cbor_expect_u8(ByteView body, std::size_t& pos,
                      const std::uint8_t value, const char* what) noexcept {
  if (pos >= body.size || body.data[pos] != value) {
    return Status::error(StatusCode::ProtocolError, what);
  }
  ++pos;
  return Status::success();
}

// Definite-length byte string only: 0x40..0x57 inline, 0x58 u8, 0x59 u16.
// Indefinite (0x5f) and non-minimal forms are rejected — canonical only.
Status cbor_read_bstr(ByteView body, std::size_t& pos, ByteView& out,
                      const char* what) noexcept {
  out = ByteView{};
  if (pos >= body.size) {
    return Status::error(StatusCode::ProtocolError, what);
  }
  const std::uint8_t ib = body.data[pos++];
  std::size_t len = 0;
  if (ib >= 0x40 && ib <= 0x57) {
    len = ib - 0x40;
  } else if (ib == 0x58) {
    if (pos >= body.size) return Status::error(StatusCode::ProtocolError, what);
    len = body.data[pos++];
    if (len <= 23) return Status::error(StatusCode::ProtocolError, what);
  } else if (ib == 0x59) {
    if (pos + 2 > body.size) {
      return Status::error(StatusCode::ProtocolError, what);
    }
    len = (static_cast<std::size_t>(body.data[pos]) << 8U) | body.data[pos + 1];
    pos += 2;
    if (len <= 255) return Status::error(StatusCode::ProtocolError, what);
  } else {
    return Status::error(StatusCode::ProtocolError, what);
  }
  if (pos + len > body.size) {
    return Status::error(StatusCode::ProtocolError, what);
  }
  out = ByteView{body.data + pos, len};
  pos += len;
  return Status::success();
}

Status cbor_write_bstr(ByteWriter& writer, const ByteView data) noexcept {
  Status status;
  if (data.size <= 23) {
    status = writer.write_u8(static_cast<std::uint8_t>(0x40 + data.size));
  } else if (data.size <= 255) {
    status = writer.write_u8(0x58);
    if (status) status = writer.write_u8(static_cast<std::uint8_t>(data.size));
  } else {
    status = writer.write_u8(0x59);
    if (status) {
      status = writer.write_u16(static_cast<std::uint16_t>(data.size));
    }
  }
  if (!status) return status;
  return writer.write_bytes(data);
}

// The protected header is byte-exact by profile: a2 {1:-9, 4:h'kid8'}.
constexpr std::size_t kProtectedBstrSize = 13;
constexpr std::array<std::uint8_t, 5> kProtectedHead{{0xa2, 0x01, 0x28, 0x04, 0x48}};

}  // namespace

const std::array<std::uint8_t, 32> kSecp256r1Order{{
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
    0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51}};

const std::array<std::uint8_t, 32> kSecp256r1HalfOrder{{
    0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xDE, 0x73, 0x7D, 0x56, 0xD3, 0x8C, 0xF4, 0x27,
    0x9D, 0xCE, 0x56, 0x17, 0xE3, 0x19, 0x5A, 0x88}};

int cose_be32_cmp(const std::array<std::uint8_t, 32>& a,
                  const std::array<std::uint8_t, 32>& b) noexcept {
  for (std::size_t i = 0; i < 32; ++i) {
    if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
  }
  return 0;
}

bool cose_be32_is_zero(const std::array<std::uint8_t, 32>& v) noexcept {
  std::uint8_t acc = 0;
  for (const auto byte : v) acc |= byte;
  return acc == 0;
}

Status cose_permit_parse(const ByteView permit, CosePermitParts& out) noexcept {
  out = CosePermitParts{};
  if (permit.size < 24 || permit.size > kCosePermitMax) {
    return Status::error(StatusCode::ProtocolError, "cose permit size");
  }
  std::size_t pos = 0;
  Status status = cbor_expect_u8(permit, pos, 0xD2, "cose tag18");
  if (status) status = cbor_expect_u8(permit, pos, 0x84, "cose array4");
  ByteView protected_bstr{};
  if (status) {
    status = cbor_read_bstr(permit, pos, protected_bstr, "cose protected");
  }
  if (!status) return status;
  // Byte-exact protected header: map2 {alg:-9, kid:bstr8} canonical order.
  if (protected_bstr.size != kProtectedBstrSize ||
      std::memcmp(protected_bstr.data, kProtectedHead.data(),
                  kProtectedHead.size()) != 0) {
    return Status::error(StatusCode::ProtocolError, "cose protected shape");
  }
  std::uint64_t kid = 0;
  for (int i = 0; i < 8; ++i) {
    kid = (kid << 8U) | protected_bstr.data[5 + i];
  }
  status = cbor_expect_u8(permit, pos, 0xA0, "cose unprotected empty");
  if (!status) return status;
  ByteView payload{};
  status = cbor_read_bstr(permit, pos, payload, "cose payload");
  if (!status) return status;
  if (payload.size < endpoint::kRcc1HeaderSize ||
      payload.size > endpoint::kRcc1MaxTotal) {
    return Status::error(StatusCode::ProtocolError, "cose payload bounds");
  }
  ByteView signature{};
  status = cbor_read_bstr(permit, pos, signature, "cose signature");
  if (!status) return status;
  if (signature.size != kCoseSignatureSize || pos != permit.size) {
    return Status::error(StatusCode::ProtocolError, "cose signature/trailer");
  }
  out.protected_bytes = protected_bstr;
  out.kid = kid;
  out.payload = payload;
  out.signature = signature;
  return Status::success();
}

Status cose_sig_structure(const ByteView protected_bytes,
                          const ByteView external_aad, const ByteView payload,
                          ByteBuffer<kCosePermitMax + 64>& out) noexcept {
  out.clear();
  if (protected_bytes.size != kProtectedBstrSize ||
      external_aad.size != kConfigPermitAadSize ||
      payload.size > endpoint::kRcc1MaxTotal) {
    return Status::error(StatusCode::InvalidArgument, "sig_structure fields");
  }
  ByteWriter writer(out.writable());
  Status status = writer.write_u8(0x84);  // array(4)
  if (status) {
    status = writer.write_u8(0x60 + 10);  // "Signature1" text(10)
  }
  if (status) {
    status = writer.write_bytes(ByteView{
        reinterpret_cast<const std::uint8_t*>("Signature1"), 10});
  }
  if (status) status = cbor_write_bstr(writer, protected_bytes);
  if (status) status = cbor_write_bstr(writer, external_aad);
  if (status) status = cbor_write_bstr(writer, payload);
  if (!status) return status;
  out.size = writer.size();
  return Status::success();
}

void CoseEsp256AuthorityVerifier::provision(const std::uint64_t authority_id,
                                          const ByteView public_key) noexcept {
  provisioned_ = false;
  if (public_key.size != kCosePublicKeySize || authority_id == 0 ||
      authority_id == kInvalidNodeId || authority_id == kBroadcastNodeId) {
    return;
  }
  std::array<std::uint8_t, kCosePublicKeySize> key{};
  std::memcpy(key.data(), public_key.data, key.size());
  // Off-curve / identity points must never reach the verify path.
  if (uECC_valid_public_key(key.data(), uECC_secp256r1()) == 0) {
    return;
  }
  public_key_ = key;
  authority_id_ = authority_id;
  provisioned_ = true;
}

Status CoseEsp256AuthorityVerifier::verify_permit(
    const ConfigPermitContext& context, const ByteView permit,
    endpoint::EncodedConfigCommand& payload, bool& verified) noexcept {
  verified = false;
  if (!provisioned_) {
    return Status::error(StatusCode::InvalidState, "cose key unprovisioned");
  }
  CosePermitParts parts{};
  const Status parsed = cose_permit_parse(permit, parts);
  if (!parsed.ok()) return parsed;
  // kid is a lookup hint bound by the signature — it must name BOTH the
  // provisioned key and the context's authorized issuer.
  if (parts.kid != authority_id_ || parts.kid != context.authorized_issuer) {
    return Status::success();  // foreign authority: denied, never verified
  }

  // R/S range + low-S canonicality before the expensive point multiply.
  std::array<std::uint8_t, 32> r{}, s{};
  std::memcpy(r.data(), parts.signature.data, 32);
  std::memcpy(s.data(), parts.signature.data + 32, 32);
  if (cose_be32_is_zero(r) || cose_be32_is_zero(s) ||
      cose_be32_cmp(r, kSecp256r1Order) >= 0 ||
      cose_be32_cmp(s, kSecp256r1Order) >= 0 ||
      cose_be32_cmp(s, kSecp256r1HalfOrder) > 0) {
    return Status::success();  // out-of-range / non-canonical: denied
  }

  ByteBuffer<kConfigPermitAadSize> aad{};
  const Status aad_ok = config_permit_aad(context.network, context.target,
                                        context.config_namespace, aad);
  if (!aad_ok.ok()) return aad_ok;
  ByteBuffer<kCosePermitMax + 64> to_verify{};
  const Status built = cose_sig_structure(parts.protected_bytes, aad.view(),
                                          parts.payload, to_verify);
  if (!built.ok()) return built;
  ScopeDigest digest{};
  sha256(to_verify.view(), digest);
  if (uECC_verify(public_key_.data(), digest.data(),
                  static_cast<unsigned>(digest.size()),
                  parts.signature.data, uECC_secp256r1()) == 0) {
    return Status::success();  // bad signature: denied
  }

  // Authentic envelope — decode RCC1 and apply the same identity policy the
  // dev verifier enforces (network/target/namespace/authority/generation).
  const Status decoded =
      endpoint::config_command_decode(parts.payload, command_);
  if (!decoded.ok()) return decoded;
  if (command_.network != context.network || command_.target != context.target ||
      command_.config_namespace != context.config_namespace ||
      command_.authority != context.authorized_issuer ||
      command_.authority_generation != context.authority_generation) {
    return Status::success();  // not the configured authority: denied
  }
  if (parts.payload.size > payload.bytes.size()) {
    return Status::error(StatusCode::NoCapacity, "cose payload");
  }
  std::memcpy(payload.bytes.data(), parts.payload.data, parts.payload.size);
  payload.size = parts.payload.size;
  verified = true;
  return Status::success();
}

}  // namespace routeloom
