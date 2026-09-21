#pragma once

// RLCP1_COSE_ESP256 config permit profile (m1-completion/03-signing.md).
// Tagged COSE_Sign1 with attached RCC1 payload, ECDSA P-256/SHA-256,
// fully-specified algorithm ESP256 (-9, RFC 9864). The dev-HMAC envelope
// (config_dev.hpp) stays a separate EXPERIMENTAL profile — a target
// configured for this verifier accepts ONLY the fixed COSE shape; unknown
// alg/kid, malformed CBOR or a failed signature never falls through to
// another verifier.
//
// Envelope (exactly 774 bytes at the maximum RCC1 size):
//   18( COSE_Sign1 ) = d2 84
//     protected_bstr  = 4d a2 01 28 04 48 <authority_id:8>   (13 B)
//     unprotected     = a0                                    (1 B)
//     payload_bstr    = 59 hilo <RCC1 canonical>              (≤688 B)
//     signature_bstr  = 58 40 <R:32 || S:32>                  (64 B)
//
// Signed bytes are the COSE Sig_structure — never the transport claims:
//   Sig_structure = 84 6a "Signature1" 4d <protected:13>
//                   58 2d <external_aad:45> 59 hilo <RCC1>
//   external_aad  = config_permit_aad() — the target's EXPECTED context
//                   (network, target, namespace), not wire bytes.
//
// Canonicality is enforced: definite/minimal-length CBOR only, protected
// labels exactly {1,4} in order, no detached payload, no trailing data,
// kid is the 8-byte authority id and must equal the context's authorized
// issuer, R and S in [1,n-1] with low-S required. The P-256 verify runs on
// vendored micro-ecc so host tests and firmware run identical arithmetic.

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/config.hpp"
#include "routeloom/endpoint_wire.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom {

// secp256r1 group order n (big-endian), used for the R/S range and the
// low-S canonicality rule — the verifier rejects high-S signatures.
extern const std::array<std::uint8_t, 32> kSecp256r1Order;
// (n-1)/2 — maximum accepted S value under the low-S rule.
extern const std::array<std::uint8_t, 32> kSecp256r1HalfOrder;

constexpr std::size_t kCoseKidSize = 8;
constexpr std::size_t kCosePublicKeySize = 64;   // X || Y, no SEC1 prefix
constexpr std::size_t kCoseSignatureSize = 64;   // R || S raw
constexpr std::size_t kCosePermitMax = 774;      // design's fixed envelope cap
constexpr std::int32_t kCoseAlgEsp256 = -9;

// Result of the cheap CBOR/envelope parse — kept separate from the crypto
// verdict so a malformed envelope is an ERROR while a well-formed bad
// signature is verified=false (mirrors DevConfigAuthorityVerifier).
struct CosePermitParts {
  ByteView protected_bytes{};  // the exact signed protected bstr content
  std::uint64_t kid{0};        // authority id lookup hint (8 bytes)
  ByteView payload{};          // RCC1 canonical bytes (borrowed from permit)
  ByteView signature{};        // R || S, 64 bytes
};

// Parse the fixed RLCP1 envelope shape. Cheap checks only — no crypto.
// Returns InvalidArgument/ProtocolError on ANY deviation from the profile.
Status cose_permit_parse(ByteView permit, CosePermitParts& out) noexcept;

// Encode the Sig_structure for verification: caller provides the target's
// expected external_aad (45 bytes from config_permit_aad) — wire-supplied
// AAD is never accepted here.
Status cose_sig_structure(ByteView protected_bytes, ByteView external_aad,
                          ByteView payload,
                          ByteBuffer<kCosePermitMax + 64>& out) noexcept;

// Big-endian 32-byte compare helpers shared by the R/S range and low-S
// checks. Returns -1/0/1.
int cose_be32_cmp(const std::array<std::uint8_t, 32>& a,
                  const std::array<std::uint8_t, 32>& b) noexcept;
bool cose_be32_is_zero(const std::array<std::uint8_t, 32>& v) noexcept;

// Target-side verifier: provisioned with ONE authority public key and its
// 8-byte authority id. ready() is false until a valid on-curve key is
// provisioned — an unprovisioned verifier fails closed.
class CoseEsp256AuthorityVerifier final : public ConfigAuthorityVerifier {
 public:
  CoseEsp256AuthorityVerifier() noexcept = default;
  // `public_key` is the 64-byte X||Y encoding; `authority_id` is the kid
  // the permit must name AND the ConfigPermitContext must authorize.
  void provision(std::uint64_t authority_id, ByteView public_key) noexcept;

  bool ready() const noexcept override { return provisioned_; }
  SecurityProfile security_profile() const noexcept override {
    return SecurityProfile::Production;
  }
  std::uint32_t permit_profile_bit() const noexcept override { return 1u << 1; }
  // P-256 ECDSA on the radio Owner is the expensive path the intake limiter
  // exists for (03-signing §3.3).
  bool verify_is_expensive() const noexcept override { return true; }
  Status verify_permit(const ConfigPermitContext& context, ByteView permit,
                       endpoint::EncodedConfigCommand& payload,
                       bool& verified) noexcept override;

 private:
  std::uint64_t authority_id_{0};
  std::array<std::uint8_t, kCosePublicKeySize> public_key_{};
  bool provisioned_{false};
  endpoint::ConfigCommand command_{};
};

}  // namespace routeloom
