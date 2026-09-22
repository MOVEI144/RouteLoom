#pragma once

// Trust manifest (RTM1) portable core (issue #10;
// sdk-completion/04-provisioning-lifecycle.md §4.3.3, §4.5.1). The in-band
// trust-update unit is a COMPLETE replacement image: the signed payload is
// byte-for-byte the RLT1 semantic content — RLT1 bytes [16, used_len-4) —
// so verification, persistence and catch-up share one codec (the
// trust_store.hpp body functions) and one truth.
//
// Envelope: the same restricted COSE_Sign1 shape as the RLCP1_COSE_ESP256
// permit profile (tag 18, array(4), canonical protected {1:-9, 4:bstr8},
// empty unprotected map, raw R||S signature with the low-S rule), with two
// differences: the kid names a deployment ROOT ANCHOR (root_id) rather
// than a config authority, and the external AAD is the trust-manifest
// domain bound to the device's own committed network — never transport
// claims.
//
// Implemented + host-tested here: content codec reuse, the restricted
// envelope parse/assemble, the Sig_structure/AAD construction, and the
// full §4.5.1 acceptance pipeline INCLUDING the P-256 verify leg (vendored
// micro-ecc, same as the permit verifier).
// NOT implemented (separate checklist items): the kind-4 ControlObject
// demux / TrustManager endpoint consumer, the shared 10 s reassembly slot,
// the consume_expensive_verify() intake gate (callers must charge it —
// a manifest is the same P-256 cost as a permit), TrustStatus subtypes
// 5/6, and the host RootSigner tooling.

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/autonomy_wire.hpp"  // kAuthenticatedObjectMax
#include "routeloom/config_cose.hpp"    // R/S range + low-S helpers
#include "routeloom/status.hpp"
#include "routeloom/trust_store.hpp"
#include "routeloom/types.hpp"

namespace routeloom {

// --- Bounds (§4.3.3/§4.3.4) ----------------------------------------------------
// Maximum object: ≤ kAuthenticatedObjectMax (2048). Maximum signed content
// 1664 B + ~86 B COSE overhead ≈ 1750 B on the wire.
constexpr std::size_t kTrustManifestObjectMax = autonomy::kAuthenticatedObjectMax;
inline constexpr char kTrustManifestDomain[] = "RouteLoom/trust-manifest/v1";
// "RouteLoom/trust-manifest/v1" (27) || NUL || network u64 — 36 bytes.
constexpr std::size_t kTrustManifestAadSize = sizeof(kTrustManifestDomain) + 8;
// Sig_structure: array4 + "Signature1" + bstr(13) + bstr(36) + bstr(<=1664).
constexpr std::size_t kTrustManifestSigMax = kTrustImageContentMax + 96;
constexpr std::size_t kTrustManifestProtectedSize = 13;  // {1:-9, 4:bstr8}

// The device's expected external AAD: the domain string + NUL + the
// COMMITTED network (§4.3.3 — supplied from the store, never transport).
Status trust_manifest_aad(NetworkId network,
                          ByteBuffer<kTrustManifestAadSize>& out) noexcept;

// The canonical protected header for a root_id (a2 01 28 04 48 <id:8>):
// the only protected shape the restricted profile admits.
Status trust_manifest_protected(std::uint64_t root_id,
                                ByteBuffer<kTrustManifestProtectedSize>& out) noexcept;

// Result of the cheap envelope parse — kept separate from the crypto
// verdict so a malformed object is an ERROR while a well-formed object
// that fails authorization is a denial.
struct TrustManifestParts {
  ByteView protected_bytes{};  // exact signed protected bstr content (13 B)
  std::uint64_t root_id{0};    // kid — must name an ACTIVE anchor
  ByteView payload{};          // RLT1 content bytes (borrowed from object)
  ByteView signature{};        // R || S, 64 bytes
};

// Parse the restricted RTM1 envelope shape. Cheap checks only — no crypto.
// Any deviation from the fixed profile is ProtocolError.
Status trust_manifest_parse(ByteView object, TrustManifestParts& out) noexcept;

// Sig_structure = 84 6a "Signature1" bstr(protected) bstr(external_aad)
// bstr(payload). The AAD must be exactly the kTrustManifestAadSize value
// from trust_manifest_aad() — wire-supplied context is never accepted.
Status trust_manifest_sig_structure(
    ByteView protected_bytes, ByteView external_aad, ByteView payload,
    ByteBuffer<kTrustManifestSigMax>& out) noexcept;

// Assemble a complete RTM1 object: envelope around already-computed
// content + signature. The host RootSigner / test path uses this after
// signing sha256(sig_structure) with the root private key; the device
// never signs manifests.
Status trust_manifest_assemble(ByteView content, std::uint64_t root_id,
                               ByteView signature,
                               ByteBuffer<kTrustManifestObjectMax>& out) noexcept;

// The §4.5.1 acceptance pipeline, in the design's parse order:
//   1. restricted envelope shape, object <= kTrustManifestObjectMax;
//   2. content-head decode: network equals the committed image's network,
//      nonzero epoch, counts within caps, tables exactly sized;
//   3. store_epoch strictly greater than the committed epoch (ordinal —
//      u32 wrap is a re-provision event, never modular);
//   4. kid names an anchor ACTIVE in the current image and the signature
//      verifies under it (R/S range + low-S + uECC_verify);
//   5-6. semantic floor + >=1-active-anchor retention, then the two-phase
//      dual-slot commit with readback — inside TrustStore::commit_image.
//
// Failure classes (§4.5.1): ProtocolError = malformed (assembly released);
// Conflict = stale/replayed epoch; AuthorizationFailed = wrong network,
// unknown/disabled anchor, bad signature or regressed generation floor —
// the wire-facing reason is generic by contract; IntegrityError /
// RecoveryRequired / InvalidState = store not in an accepting state;
// StorageFailure = commit fault (the old image stays authoritative).
//
// Preconditions the CALLER owns: the object arrived reassembled under the
// shared 10 s bound on the member-only lane, and intake was charged
// through ConfigRateLimiter::consume_expensive_verify (1-per-5 s
// device-wide) BEFORE calling — signature verification is the expensive
// leg and must stay bounded.
Status trust_manifest_accept(TrustStore& store, ByteView object) noexcept;

}  // namespace routeloom
