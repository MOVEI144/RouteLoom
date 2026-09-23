#pragma once

// HKDF-SHA-256 (RFC 5869) over the portable SHA-256 / HMAC-SHA-256 in
// discovery_scope.hpp. First building block of the SDK v1 key hierarchy
// (docs/design/sdk-v1/03-key-hierarchy.md §3): resumption, group sender
// keys and the authority channel derive their keys with Extract-then-Expand.
//
// Scope, honestly: this is the standard KDF only, pinned by the RFC 5869
// SHA-256 test cases in tests/cpp/test_kdf.cpp. The RouteLoom derivation
// LABELS and info encodings are NOT fixed here — they stay design proposals
// until the key-schedule golden vectors land (08-implementation-plan.md).
// No heap, no globals; intermediate blocks are zeroized before return.

#include <cstddef>

#include "routeloom/discovery_scope.hpp"  // ScopeDigest, hmac_sha256
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom {

constexpr std::size_t kHkdfSha256HashSize = 32;
// RFC 5869 §2.3: L <= 255 * HashLen.
constexpr std::size_t kHkdfSha256OutputMax = 255 * kHkdfSha256HashSize;

// PRK = HMAC-SHA-256(salt, IKM). An empty salt is the RFC's "string of
// HashLen zeros" (HMAC zero-pads the key, so both spellings are equal).
void hkdf_sha256_extract(ByteView salt, ByteView ikm, ScopeDigest& prk) noexcept;

// OKM = T(1) || T(2) || ... truncated to out.size, with
// T(i) = HMAC-SHA-256(PRK, T(i-1) || info || i). Refuses (InvalidArgument)
// a PRK shorter than HashLen, an empty or >8160-byte output and null
// buffers; on any refusal `out` is left zero-filled, never partial.
Status hkdf_sha256_expand(ByteView prk, ByteView info, MutableByteView out) noexcept;

// Extract-then-Expand convenience; the PRK never leaves this function.
Status hkdf_sha256(ByteView salt, ByteView ikm, ByteView info,
                   MutableByteView out) noexcept;

}  // namespace routeloom
