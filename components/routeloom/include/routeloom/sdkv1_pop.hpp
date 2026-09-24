#pragma once

// Device-key proof of possession (docs/design/sdk-v1/07 §6 steps 2-3,
// 08 P7-1): the office issues a fresh 32-byte challenge; the device
// (maintenance verb, after on-device key generation with entropy READY)
// answers with a restricted ES256 COSE_Sign1 signed by the key it wants
// certified. Mirror of host/routeloom-provision sdkv1::pop; every byte is
// pinned by the `pop` codec in protocol/sdkv1-golden/ (independent
// tools/gen_sdkv1_vectors.py).
//
//   d2 84 43 a1 01 26 a0 58 6c <payload 108 B> 58 40 <R || S>      (183 B)
//   payload:
//     0 u8  version = 1
//     1 u8  key_location (RLC1 values: 1 nvs-plaintext, 2 efuse-ds-bound,
//           3 secure-element; 0 is refused — no key, nothing to prove)
//     2 u16 reserved = 0
//     4 u64 node_id
//    12 32B challenge (office nonce, echoed)
//    44 64B pubkey X || Y (the key being certified; it also verifies this)
//   external AAD = "RouteLoom/device-key-pop/v1" 00   (28 B)
//
// Same COSE profile as RLCW1/RRS1 (tag 18, {1:-7}, empty unprotected map,
// low-S only). The device signs with the vendored micro-ecc deterministic
// signer (not RFC 6979, unlike the host) and normalizes to low-S, so the
// office accepts the signature while the C++ golden harness stays
// verify-only like the certificate one.

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/device_credential.hpp"  // CredentialKeyLocation
#include "routeloom/rlcw1.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom::sdkv1 {

constexpr std::uint8_t kPopVersion = 1;
constexpr std::size_t kPopChallengeSize = 32;
constexpr std::size_t kPopPayloadSize = 108;
constexpr std::size_t kPopObjectSize = 183;
constexpr std::size_t kPopAadSize = 28;  // "RouteLoom/device-key-pop/v1" 00
using PopChallenge = std::array<std::uint8_t, kPopChallengeSize>;

struct PopClaims {
  NodeId node{kInvalidNodeId};
  CredentialKeyLocation key_location{CredentialKeyLocation::None};
  PopChallenge challenge{};
  P256PublicKey pubkey{};
};

// The 28-byte domain-separated external AAD.
Status pop_aad(ByteBuffer<kPopAadSize>& out) noexcept;
// Strict payload encode: node not 0/all-ones, location not None/unknown,
// challenge exactly 32 bytes, pubkey on P-256.
Status pop_payload_encode(NodeId node, CredentialKeyLocation key_location,
                          ByteView challenge, const P256PublicKey& pubkey,
                          ByteBuffer<kPopPayloadSize>& out) noexcept;
// Strict payload decode (exact 108 bytes, then the same field rules).
Status pop_payload_decode(ByteView payload, PopClaims& out) noexcept;
// Envelope + payload decode (no signature check).
Status pop_parse(ByteView object, PopClaims& out) noexcept;
// Full office-side check, RRS1-style: malformed objects are errors; a
// well-formed object naming another node, echoing another challenge, or
// failing the signature is verified=false.
Status pop_verify(ByteView object, NodeId expected_node,
                  ByteView expected_challenge, PopClaims& out, bool& verified,
                  const Es256Verifier& verifier = default_es256_verifier()) noexcept;
// Device signing (maintenance verb): the pubkey is derived from the
// 32-byte scalar (must be in [1, n-1]), the signature is deterministic
// ECDSA normalized to low-S. The office accepts any valid low-S encoding.
Status pop_sign(NodeId node, CredentialKeyLocation key_location,
                ByteView challenge, ByteView scalar,
                ByteBuffer<kPopObjectSize>& out, P256PublicKey& pubkey) noexcept;

}  // namespace routeloom::sdkv1
