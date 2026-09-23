#pragma once

// RLCW1 certificate profile (docs/design/sdk-v1/02-zero-touch-join.md §3):
// DevCert / SiteCert / MemberCert as CWTs (RFC 8392) carried in a tagged
// COSE_Sign1 (ES256, protected {1:-7}, empty unprotected map), plus the
// restricted ES256 COSE_Sign1 helpers the SAK-signed RRS1 revocation set
// reuses (04-removal-revocation.md §2).
//
// Byte shape (canonical CBOR, integers in shortest form, every length
// definite and minimal; anything else is a ProtocolError):
//
//   cert    = d2 84 43 a1 01 26 a0 58 <len> <payload> 58 40 <R:32 || S:32>
//   payload = a4                                   map(4), keys in
//             01 <uint iss>                        bytewise order
//             02 <uint sub>
//             08 a1 01 <COSE_Key 77 B>             cnf = {1: COSE_Key}
//             3a 00 01 00 00 <private claim array> label -65537
//   COSE_Key = a5 01 02 03 26 20 01 21 58 20 <x:32> 22 58 20 <y:32>
//              (the same canonical key the RLC1/RLI1 kid hashes)
//   private  = DevCert    [1, model u16, hw_rev u8, serial u32]
//              SiteCert   [2, network_low32 u32, site_epoch u32, usage u8, serial u32]
//              MemberCert [3, network u64, role u32, assignment_generation u32,
//                          site_epoch u32, serial u32]
//
// Unknown claims, exp/nbf, a detached payload, CWT tag 61, an untagged
// Sign1, trailing bytes or a certificate above kRlcw1CertMax are all
// rejected. The signature is ECDSA P-256 over SHA-256(Sig_structure) with
// Sig_structure = ["Signature1", h'a10126', h'', payload] (empty external
// AAD, the plain CWT rule). Verification additionally requires R,S in
// [1, n-1] and the low-S form, so each certificate has exactly one valid
// encoding (the RLP1 peer_cert_id and the ledger MemberCert digest hash
// the certificate bytes).
//
// Scope, honestly: codec + field rules + a verification hook. Chain
// policy (which anchor may issue what, A2 assignment tickets, revocation)
// is enforced by the callers named in 02 §10.2 / 04 §5; the helpers
// below implement the field comparisons those steps name.

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/authority.hpp"  // Digest256
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom::sdkv1 {

constexpr std::size_t kP256PublicKeySize = 64;  // X || Y, no SEC1 prefix
constexpr std::size_t kEs256SignatureSize = 64;  // R || S raw
using P256PublicKey = std::array<std::uint8_t, kP256PublicKeySize>;
using Es256Signature = std::array<std::uint8_t, kEs256SignatureSize>;

constexpr std::int32_t kCoseAlgEs256 = -7;
// Storage/transport bound for one certificate (RLI1 devcert_len, RLS1
// sitecert_len/membercert_len). The largest encodable certificate is
// kRlcw1CertLargest; the bound leaves the design's 256 B headroom.
constexpr std::size_t kRlcw1CertMax = 256;
constexpr std::size_t kRlcw1PayloadMax = 137;  // role encoded as a full u32
constexpr std::size_t kRlcw1CertLargest = 208;  // with the v1 role bits (<= 7)
// "Signature1" Sig_structure over a certificate payload (empty AAD).
constexpr std::size_t kRlcw1SigStructureMax = 1 + 11 + 4 + 1 + 2 + kRlcw1PayloadMax;

enum class CertType : std::uint8_t {
  Device = 1,  // DevCert, signed by the Device CA
  Site = 2,    // SiteCert, signed by the Site CA
  Member = 3,  // MemberCert (= Grant), signed by the SAK
};

// SiteCert usage bits. Only the Site Authority usage is defined.
constexpr std::uint8_t kSiteUsageAuthority = 0x01;
constexpr std::uint8_t kSiteUsageMask = 0x01;

// MemberCert role bits (the API1 join.decide roles). Nonzero, known bits
// only; RLS1 stores the same value in its u8 role field.
constexpr std::uint32_t kMemberRoleEndpoint = 1u << 0;
constexpr std::uint32_t kMemberRoleRelay = 1u << 1;
constexpr std::uint32_t kMemberRoleGateway = 1u << 2;
constexpr std::uint32_t kMemberRoleMask = 0x7u;

// One decoded certificate. Fields the certificate type does not carry
// must be zero (cert_claims_validate enforces it) so a claims value has
// exactly one encoding.
struct CertClaims {
  CertType type{CertType::Device};
  std::uint64_t issuer{0};   // claim 1: Device CA id / Site CA id / site_id
  std::uint64_t subject{0};  // claim 2: node_id / site_id / node_id
  P256PublicKey pubkey{};    // claim 8: cnf COSE_Key (device key / SAK)
  std::uint16_t model{0};                 // Device
  std::uint8_t hw_rev{0};                 // Device
  std::uint32_t network_low32{0};         // Site
  std::uint8_t usage{0};                  // Site
  NetworkId network{0};                   // Member (full 64-bit network)
  std::uint32_t role{0};                  // Member
  std::uint32_t assignment_generation{0}; // Member
  std::uint32_t site_epoch{0};            // Site, Member
  std::uint32_t serial{0};                // all
};

// Field rules: issuer/subject not 0 or all-ones; pubkey on P-256; per type:
//  Device — only model/hw_rev/serial set;
//  Site   — network_low32 != 0, usage nonzero and known bits only;
//  Member — network low32 != 0, network>>32 == site_epoch, role nonzero
//           and known bits only, assignment_generation >= 1.
Status cert_claims_validate(const CertClaims& claims) noexcept;

// Canonical claims-map payload (validated first).
Status cert_payload_encode(const CertClaims& claims,
                           ByteBuffer<kRlcw1PayloadMax>& out) noexcept;
// Strict payload decode: exact shape, shortest-form integers, per-field
// width limits, no trailing bytes, then cert_claims_validate.
Status cert_payload_decode(ByteView payload, CertClaims& out) noexcept;

// Envelope-only parse (cheap, no crypto): payload and signature views
// borrowed from `cert`.
struct CoseEs256Parts {
  ByteView payload{};
  ByteView signature{};  // 64 bytes
};
Status cert_parse(ByteView cert, CoseEs256Parts& out) noexcept;
// Envelope + payload decode.
Status cert_decode(ByteView cert, CertClaims& out) noexcept;

Status cert_sig_structure(ByteView payload,
                          ByteBuffer<kRlcw1SigStructureMax>& out) noexcept;
// Wrap a payload and an already-computed signature (host issuers / tests;
// the device never issues certificates).
Status cert_assemble(ByteView payload, ByteView signature,
                     ByteBuffer<kRlcw1CertMax>& out) noexcept;

// --- Verification hook ---------------------------------------------------------
// The P-256 primitive behind every RLCW1/RRS1 check. The default is the
// vendored micro-ecc (identical arithmetic on host and firmware); a
// hardware/PSA backend can be substituted without touching the codecs.
// Implementations verify an ECDSA signature over a 32-byte digest and
// must return false for any failure; the range/low-S gate runs before
// the hook is called.
class Es256Verifier {
 public:
  virtual ~Es256Verifier() = default;
  virtual bool verify_digest(const P256PublicKey& pubkey, const Digest256& digest,
                             const Es256Signature& signature) const noexcept = 0;
};
const Es256Verifier& default_es256_verifier() noexcept;

// R and S in [1, n-1] and S <= (n-1)/2.
bool es256_signature_canonical(ByteView signature) noexcept;
bool p256_public_key_valid(const P256PublicKey& pubkey) noexcept;

// Restricted ES256 COSE_Sign1 profile shared by RLCW1 and RRS1:
// d2 84 43 a1 01 26 a0 <bstr payload> 58 40 <sig>, payload length in
// [payload_min, payload_max], nothing trailing, object <= object_max.
Status cose_es256_parse(ByteView object, std::size_t payload_min,
                        std::size_t payload_max, std::size_t object_max,
                        CoseEs256Parts& out) noexcept;
// SHA-256 over ["Signature1", h'a10126', external_aad, payload] computed
// streaming (no Sig_structure buffer).
void cose_es256_digest(ByteView payload, ByteView external_aad,
                       Digest256& out) noexcept;
// Full Sig_structure bytes for vectors/diagnostics.
Status cose_es256_sig_structure(ByteView payload, ByteView external_aad,
                                MutableByteView out, std::size_t& size) noexcept;
Status cose_es256_assemble(ByteView payload, ByteView signature,
                           MutableByteView out, std::size_t& size) noexcept;
// verified=false (with Ok status) for a non-canonical or bad signature;
// errors are reserved for malformed arguments.
Status cose_es256_verify(ByteView payload, ByteView external_aad,
                         ByteView signature, const P256PublicKey& pubkey,
                         const Es256Verifier& verifier, bool& verified) noexcept;

// Verify a certificate's signature under `issuer_pubkey`. A malformed
// certificate is an error; a well-formed certificate that fails the
// signature is verified=false. `out` is filled whenever decode succeeds.
Status cert_verify(ByteView cert, const P256PublicKey& issuer_pubkey,
                   CertClaims& out, bool& verified,
                   const Es256Verifier& verifier = default_es256_verifier()) noexcept;

// kid = SHA-256(canonical COSE_Key(pubkey)) — the RLC1 rule, reused.
Status cert_subject_kid(const CertClaims& claims, Digest256& out) noexcept;

// 02 §10.2 steps 1-4 (field part; step 1's signature check is
// cert_verify under site.pubkey): MemberCert sub == node, cnf == own
// pubkey, iss == SiteCert sub, network low32 == SiteCert network_low32,
// site_epoch == SiteCert site_epoch, generation >= 1, known role bits.
Status member_cert_matches(const CertClaims& member, const CertClaims& site,
                           NodeId node, const P256PublicKey& device_pubkey) noexcept;

}  // namespace routeloom::sdkv1
