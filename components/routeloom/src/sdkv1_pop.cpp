#include "routeloom/sdkv1_pop.hpp"

#include <cstring>

#include "routeloom/byte_io.hpp"
#include "routeloom/discovery_scope.hpp"  // Sha256 (deterministic-sign DRBG)
#include "routeloom/secure_clear.hpp"

extern "C" {
#include "uECC.h"
}

namespace routeloom::sdkv1 {
namespace {

// "RouteLoom/device-key-pop/v1" 00 (28 bytes, no trailing NUL in the AAD).
constexpr char kPopAadText[] = "RouteLoom/device-key-pop/v1";
constexpr std::uint64_t kAllOnes = ~std::uint64_t{0};

bool node_valid(const NodeId node) noexcept { return node != 0 && node != kAllOnes; }

bool location_valid(const CredentialKeyLocation location) noexcept {
  return location == CredentialKeyLocation::NvsPlaintext ||
         location == CredentialKeyLocation::EfuseDsBound ||
         location == CredentialKeyLocation::SecureElement;
}

Status write_payload(const PopClaims& claims, std::uint8_t* out) noexcept {
  ByteWriter writer(MutableByteView{out, kPopPayloadSize});
  Status status = writer.write_u8(kPopVersion);
  if (status) status = writer.write_u8(static_cast<std::uint8_t>(claims.key_location));
  if (status) status = writer.write_u16(0);
  if (status) status = writer.write_u64(claims.node);
  if (status) {
    status = writer.write_bytes(
        ByteView{claims.challenge.data(), claims.challenge.size()});
  }
  if (status) {
    status = writer.write_bytes(ByteView{claims.pubkey.data(), claims.pubkey.size()});
  }
  if (!status || writer.size() != kPopPayloadSize) {
    return Status::error(StatusCode::InternalError, "pop encode");
  }
  return Status::success();
}

// SHA-256 uECC_HashContext for uECC_sign_deterministic (same shape as the
// EDHOC backend's: `base` first, tmp sized per the uECC.h contract
// 2 * result_size + block_size — the HMAC pads live past 2 * result_size).
struct DeterministicSha256 {
  uECC_HashContext base;
  Sha256 sha;
  std::array<std::uint8_t, 2 * 32 + 64> tmp{};
};

DeterministicSha256* det_cast(const uECC_HashContext* context) noexcept {
  return const_cast<DeterministicSha256*>(
      reinterpret_cast<const DeterministicSha256*>(context));
}
void det_init(const uECC_HashContext* context) { det_cast(context)->sha.reset(); }
void det_update(const uECC_HashContext* context, const std::uint8_t* message,
                const unsigned size) {
  det_cast(context)->sha.update(ByteView{message, size});
}
void det_finish(const uECC_HashContext* context, std::uint8_t* result) {
  ScopeDigest digest{};
  det_cast(context)->sha.finish(digest);
  std::memcpy(result, digest.data(), digest.size());
  secure_clear(digest);
}

}  // namespace

Status pop_aad(ByteBuffer<kPopAadSize>& out) noexcept {
  out.clear();
  constexpr std::size_t kText = sizeof(kPopAadText) - 1;
  static_assert(kText + 1 == kPopAadSize, "pop AAD is domain + 00");
  std::memcpy(out.bytes.data(), kPopAadText, kText);
  out.bytes[kText] = 0;
  out.size = kPopAadSize;
  return Status::success();
}

Status pop_payload_encode(const NodeId node, const CredentialKeyLocation key_location,
                          const ByteView challenge, const P256PublicKey& pubkey,
                          ByteBuffer<kPopPayloadSize>& out) noexcept {
  out.clear();
  if (!node_valid(node)) {
    return Status::error(StatusCode::InvalidArgument, "pop node id");
  }
  if (!location_valid(key_location)) {
    return Status::error(StatusCode::InvalidArgument, "pop key location");
  }
  if (challenge.data == nullptr || challenge.size != kPopChallengeSize) {
    return Status::error(StatusCode::InvalidArgument, "pop challenge");
  }
  if (!p256_public_key_valid(pubkey)) {
    return Status::error(StatusCode::InvalidArgument, "pop key off curve");
  }
  PopClaims claims{};
  claims.node = node;
  claims.key_location = key_location;
  std::memcpy(claims.challenge.data(), challenge.data, kPopChallengeSize);
  claims.pubkey = pubkey;
  const Status status = write_payload(claims, out.bytes.data());
  if (!status) return status;
  out.size = kPopPayloadSize;
  return Status::success();
}

Status pop_payload_decode(const ByteView payload, PopClaims& out) noexcept {
  out = PopClaims{};
  if (payload.data == nullptr || payload.size != kPopPayloadSize) {
    return Status::error(StatusCode::ProtocolError, "pop payload length");
  }
  ByteReader reader(payload);
  std::uint8_t version = 0;
  std::uint8_t location = 0;
  std::uint16_t reserved = 0;
  Status status = reader.read_u8(version);
  if (status) status = reader.read_u8(location);
  if (status) status = reader.read_u16(reserved);
  if (status) status = reader.read_u64(out.node);
  if (!status || version != kPopVersion || reserved != 0) {
    return Status::error(StatusCode::ProtocolError, "pop head");
  }
  switch (static_cast<CredentialKeyLocation>(location)) {
    case CredentialKeyLocation::NvsPlaintext:
    case CredentialKeyLocation::EfuseDsBound:
    case CredentialKeyLocation::SecureElement:
      out.key_location = static_cast<CredentialKeyLocation>(location);
      break;
    default:
      return Status::error(StatusCode::ProtocolError, "pop key location");
  }
  if (!node_valid(out.node)) {
    return Status::error(StatusCode::ProtocolError, "pop node id");
  }
  status = reader.read_bytes(
      MutableByteView{out.challenge.data(), out.challenge.size()});
  if (!status) return Status::error(StatusCode::ProtocolError, "pop challenge");
  std::array<std::uint8_t, kP256PublicKeySize> pubkey{};
  status = reader.read_bytes(MutableByteView{pubkey.data(), pubkey.size()});
  if (!status || reader.remaining() != 0) {
    return Status::error(StatusCode::ProtocolError, "pop pubkey");
  }
  out.pubkey = pubkey;
  if (!p256_public_key_valid(out.pubkey)) {
    return Status::error(StatusCode::ProtocolError, "pop key off curve");
  }
  return Status::success();
}

Status pop_parse(const ByteView object, PopClaims& out) noexcept {
  out = PopClaims{};
  CoseEs256Parts parts{};
  const Status status =
      cose_es256_parse(object, kPopPayloadSize, kPopPayloadSize, kPopObjectSize, parts);
  if (!status) return status;
  return pop_payload_decode(parts.payload, out);
}

Status pop_verify(const ByteView object, const NodeId expected_node,
                  const ByteView expected_challenge, PopClaims& out,
                  bool& verified, const Es256Verifier& verifier) noexcept {
  out = PopClaims{};
  verified = false;
  CoseEs256Parts parts{};
  Status status =
      cose_es256_parse(object, kPopPayloadSize, kPopPayloadSize, kPopObjectSize, parts);
  if (!status) return status;
  status = pop_payload_decode(parts.payload, out);
  if (!status) return status;
  if (expected_challenge.data == nullptr ||
      expected_challenge.size != kPopChallengeSize) {
    return Status::error(StatusCode::InvalidArgument, "pop challenge");
  }
  if (out.node != expected_node) return Status::success();
  // Not secret, but compare in full anyway (no early exit on the nonce).
  if (!constant_time_equal(ByteView{out.challenge.data(), kPopChallengeSize},
                           expected_challenge)) {
    return Status::success();
  }
  ByteBuffer<kPopAadSize> aad{};
  status = pop_aad(aad);
  if (!status) return status;
  return cose_es256_verify(parts.payload, aad.view(), parts.signature, out.pubkey,
                            verifier, verified);
}

Status pop_sign(const NodeId node, const CredentialKeyLocation key_location,
                const ByteView challenge, const ByteView scalar,
                ByteBuffer<kPopObjectSize>& out, P256PublicKey& pubkey) noexcept {
  out.clear();
  pubkey = P256PublicKey{};
  if (!p256_scalar_valid(scalar)) {
    return Status::error(StatusCode::InvalidArgument, "pop scalar range");
  }
  if (uECC_compute_public_key(scalar.data, pubkey.data(), uECC_secp256r1()) == 0 ||
      !p256_public_key_valid(pubkey)) {
    pubkey = P256PublicKey{};
    return Status::error(StatusCode::InternalError, "pop pubkey derive");
  }
  ByteBuffer<kPopPayloadSize> payload{};
  Status status = pop_payload_encode(node, key_location, challenge, pubkey, payload);
  if (!status) {
    pubkey = P256PublicKey{};
    return status;
  }
  ByteBuffer<kPopAadSize> aad{};
  status = pop_aad(aad);
  if (!status) {
    pubkey = P256PublicKey{};
    return status;
  }
  Digest256 digest{};
  cose_es256_digest(payload.view(), aad.view(), digest);
  DeterministicSha256 context{};
  context.base = {&det_init, &det_update, &det_finish, 64, 32, context.tmp.data()};
  Es256Signature signature{};
  const int ok = uECC_sign_deterministic(scalar.data, digest.data(),
                                         static_cast<unsigned>(digest.size()),
                                         &context.base, signature.data(),
                                         uECC_secp256r1());
  secure_clear(context.tmp);
  secure_clear(digest);
  if (ok == 0) {
    pubkey = P256PublicKey{};
    return Status::error(StatusCode::InternalError, "pop sign");
  }
  es256_signature_normalize_low_s(signature);
  std::size_t size = 0;
  status = cose_es256_assemble(payload.view(),
                               ByteView{signature.data(), signature.size()},
                               MutableByteView{out.bytes.data(), out.bytes.size()}, size);
  secure_clear(signature);
  if (!status || size != kPopObjectSize) {
    pubkey = P256PublicKey{};
    return Status::error(StatusCode::InternalError, "pop assemble");
  }
  out.size = size;
  return Status::success();
}

}  // namespace routeloom::sdkv1
