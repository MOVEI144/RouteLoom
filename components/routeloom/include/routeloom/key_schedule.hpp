#pragma once

// SDK v1 key schedule — the FROZEN RouteLoom derivation labels and info
// encodings (docs/design/sdk-v1/03-key-hierarchy.md §2.2, §3, §5.3, §6.1 and
// 06-fast-rejoin.md §2.1; plan P1-4). Every function here is pinned
// byte-for-byte by protocol/sdkv1-golden/derivations/, produced by the
// independent Python generator tools/gen_sdkv1_derivation_vectors.py and
// checked by tests/cpp/test_key_schedule.cpp and host/routeloom-keysched.
//
// Encoding rule (frozen): info / MAC input = ASCII label || 0x00 ||
// fixed-width big-endian fields. Every label is "RouteLoom/v1/<name>".
// A 28-byte expansion is key16 || iv12. Changing any label, field order or
// width is a protocol change and must regenerate the vectors.
//
// Scope, honestly: derivations only. No AEAD is implemented here (AES-GCM
// stays with the SecurityProvider); the EDHOC Exporter labels are listed as
// constants for P2 but cannot be exercised without EDHOC. RouteLoom's own
// constructions (RLRES1, the group-key use) are unreviewed until P8-2.
// No heap, no globals; intermediate secrets are zeroized before return.

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/discovery_scope.hpp"  // ScopeDigest
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom::keys {

// --- Frozen labels ------------------------------------------------------------
inline constexpr char kLabelGroupSalt[] = "RouteLoom/v1/group";
inline constexpr char kLabelBcastLink[] = "RouteLoom/v1/bcast-link";
inline constexpr char kLabelGroupEnd[] = "RouteLoom/v1/group-end";
inline constexpr char kLabelDskMember[] = "RouteLoom/v1/dsk-member";
inline constexpr char kLabelResumeId[] = "RouteLoom/v1/rid";
inline constexpr char kLabelResumeAuth[] = "RouteLoom/v1/resume-auth";
inline constexpr char kLabelResumeBinding[] = "RouteLoom/v1/resume-binding";
inline constexpr char kLabelResumeR1[] = "RouteLoom/v1/R1";
inline constexpr char kLabelResumeR2[] = "RouteLoom/v1/R2";
inline constexpr char kLabelResumeR3[] = "RouteLoom/v1/R3";
inline constexpr char kLabelResumeConfirm[] = "RouteLoom/v1/resume-confirm";
inline constexpr char kLabelResumeKey[] = "RouteLoom/v1/resume-key";
// P4 member handshake (frozen with the same rule as above).
inline constexpr char kLabelLinkCarrier[] = "RouteLoom/v1/link-carrier";
inline constexpr char kLabelEndCarrier[] = "RouteLoom/v1/end-carrier";
inline constexpr char kLabelSessionProfile[] = "RouteLoom/v1/session-profile";
inline constexpr char kLabelContextConfirm[] = "RouteLoom/v1/context-confirm";
// Authority channel (03 §5.3, G-SEC P5): GK-id binds (network, epoch, GK)
// for ACK key confirmation. Never a raw-GK export.
inline constexpr char kLabelGkId[] = "RouteLoom/v1/gk-id";
inline constexpr char kLabelDevRam[] = "RouteLoom/v1/dev-ram";
inline constexpr char kLabelDevRms[] = "RouteLoom/v1/dev-rms";
inline constexpr char kLabelDevGroupKey[] = "RouteLoom/v1/dev-group-key";
inline constexpr char kLabelDevGroupIv[] = "RouteLoom/v1/dev-group-iv";

// EDHOC Exporter labels (private use, 03 §2.1). Consumed by P2; listed here so
// the whole RouteLoom label space is frozen in one place.
inline constexpr std::uint32_t kExporterAeadKey = 32768;   // 16B, per direction
inline constexpr std::uint32_t kExporterBaseIv = 32769;    // 12B, per direction
inline constexpr std::uint32_t kExporterResumeMaster = 32770;  // RMS 32B
inline constexpr std::uint32_t kExporterDams = 32771;      // DAMS 32B (join only)
inline constexpr std::uint32_t kExporterPending = 32772;   // pending secret 32B

// Exporter-context / RLRES1 purpose values (03 §2 rule 3). usb=3 exists for
// the Exporter context only; it is never an RLRES1 purpose.
enum class Purpose : std::uint8_t {
  Link = 1,
  End = 2,
  Usb = 3,
  Authority = 4,
  PendingJoin = 5,
};

// RLRES1 traffic direction byte in the resume-key info.
enum class Direction : std::uint8_t {
  InitiatorToResponder = 1,
  ResponderToInitiator = 2,
};

constexpr std::size_t kSecretSize = 32;       // GK, RMS, DAMS, pending secret
constexpr std::size_t kAeadKeySize = 16;      // AES-GCM-128
constexpr std::size_t kAeadIvSize = 12;
constexpr std::size_t kKeyIvSize = kAeadKeySize + kAeadIvSize;  // 28
constexpr std::size_t kResumeIdSize = 8;
constexpr std::size_t kResumeNonceSize = 16;
constexpr std::size_t kResumeMacSize = 16;
constexpr std::uint64_t kMaxAeadCounter = (std::uint64_t{1} << 48) - 1;

using Secret = std::array<std::uint8_t, kSecretSize>;
using ResumeId = std::array<std::uint8_t, kResumeIdSize>;
using ResumeNonce = std::array<std::uint8_t, kResumeNonceSize>;
using AeadNonce = std::array<std::uint8_t, kAeadIvSize>;

struct TrafficKey {
  std::array<std::uint8_t, kAeadKeySize> key{};
  std::array<std::uint8_t, kAeadIvSize> iv{};
};

void clear(TrafficKey& key) noexcept;

// --- AEAD nonce (03 §3) ----------------------------------------------------
// nonce = iv XOR (zero6 || counter u48). Refuses counter > 2^48-1 (the key
// must be retired before, never wrapped); `out` is zeroed on refusal.
Status aead_nonce(const std::array<std::uint8_t, kAeadIvSize>& iv, std::uint64_t counter,
                  AeadNonce& out) noexcept;

// --- Network group key (03 §6.1) ---------------------------------------------
// PRK_g = HKDF-Extract(salt = "RouteLoom/v1/group" 0x00 || network u64, GK_g)
void group_prk(NetworkId network, const Secret& gk, ScopeDigest& prk) noexcept;
// K_bcast = Expand(PRK_g, "RouteLoom/v1/bcast-link" 0x00 || g u32 || tx u64 ||
//                  tx_boot u32, 28)
Status group_bcast_key(const ScopeDigest& prk, std::uint32_t gk_epoch, NodeId tx,
                       std::uint32_t tx_boot, TrafficKey& out) noexcept;
// K_gend = Expand(PRK_g, "RouteLoom/v1/group-end" 0x00 || g u32 || group_id u64 ||
//                 origin u64 || session u32, 28)
Status group_end_key(const ScopeDigest& prk, std::uint32_t gk_epoch, std::uint64_t group_id,
                     NodeId origin, std::uint32_t session, TrafficKey& out) noexcept;
// K_dsk(g) = Expand(PRK_g, "RouteLoom/v1/dsk-member" 0x00 || g u32, 32)
Status group_dsk_key(const ScopeDigest& prk, std::uint32_t gk_epoch, Secret& out) noexcept;

// Development profile only (§10.1): the shared PSK roots per-network,
// per-pair RLRES1 secrets; group keys are separate and boot-scoped. Callers
// must reserve the durable boot epoch before deriving a group sender key.
Status dev_pair_rms(const Secret& psk, NetworkId network, NodeId a, NodeId b,
                    Purpose purpose, Secret& out) noexcept;
Status dev_group_key(const Secret& psk, NetworkId network, NodeId origin,
                     std::uint32_t boot, TrafficKey& out) noexcept;

// --- RLRES1 (06 §2.1) -----------------------------------------------------------
// rid = first8(HMAC(RMS, "RouteLoom/v1/rid" 0x00 || purpose u8))
void resume_id(const Secret& rms, Purpose purpose, ResumeId& out) noexcept;

// K_auth = HKDF(salt = "RouteLoom/v1/resume-auth", IKM = RMS,
//               info = "RouteLoom/v1/resume-auth" 0x00 || purpose u8 || network u64 ||
//                      node_I u64 || node_R u64, 32)
// node_R is the responder's NodeId for link/end and the site_id for
// authority/pending-join (the Site Authority is not a mesh node).
Status resume_auth_key(const Secret& rms, Purpose purpose, NetworkId network, NodeId node_i,
                       NodeId node_r, Secret& out) noexcept;

// binding (32B) folded into mac_I / mac_R:
//  routed (end/authority/pending): SHA-256("RouteLoom/v1/resume-binding" 0x00 ||
//                                  purpose u8 || node_I u64 || node_R u64)
//  link: SHA-256("RouteLoom/v1/resume-binding" 0x00 || 0x01 || mac_I 6B || mac_R 6B ||
//                carrier_digest 32B)  — MACs in initiator→responder orientation;
//        carrier_digest is the RLD1 transaction digest the P4-2 carrier defines.
void resume_binding_routed(Purpose purpose, NodeId node_i, NodeId node_r,
                           ScopeDigest& out) noexcept;
void resume_binding_link(const MacAddress& mac_i, const MacAddress& mac_r,
                         const ScopeDigest& carrier_digest, ScopeDigest& out) noexcept;

// PRK = HKDF-Extract(salt = nonce_I || nonce_R, IKM = RMS)
void resume_prk(const ResumeNonce& nonce_i, const ResumeNonce& nonce_r, const Secret& rms,
                ScopeDigest& prk) noexcept;
// K_conf = Expand(PRK, "RouteLoom/v1/resume-confirm" 0x00 || TH, 32)
Status resume_confirm_key(const ScopeDigest& prk, const ScopeDigest& th, Secret& out) noexcept;

struct ResumeKeyContext {
  Purpose purpose{Purpose::Link};
  NetworkId network{0};
  NodeId node_i{kInvalidNodeId};
  NodeId node_r{kInvalidNodeId};
  std::uint32_t cid_i{0};
  std::uint32_t cid_r{0};
};
// key/iv(dir) = Expand(PRK, "RouteLoom/v1/resume-key" 0x00 || purpose u8 || dir u8 ||
//               network u64 || node_I u64 || node_R u64 || cid_I u32 || cid_R u32 ||
//               TH 32B, 28)
Status resume_traffic_key(const ScopeDigest& prk, const ResumeKeyContext& context,
                          Direction direction, const ScopeDigest& th, TrafficKey& out) noexcept;

// first16(HMAC(key, label 0x00 || a || b || c)); used for mac_I / mac_R / mac_I3.
// `a` is at most 32 bytes (binding or TH). On refusal `out` is zero and the
// caller must treat the MAC as failed (never compare against it).
Status resume_mac(ByteView key, const char* label, ByteView a, ByteView b, ByteView c,
                  std::array<std::uint8_t, kResumeMacSize>& out) noexcept;

// --- Member link carrier (P4 §5.2) ------------------------------------------------
// carrier_digest binds the EDHOC/RLRES1 exchange to the exact RLD1
// DISCOVER/OFFER exchange that carried it (frozen bytes, both nonces, the
// cookie, both capability words and the scope binding):
//   SHA-256("RouteLoom/v1/link-carrier" 0x00 || rld1_version u8(1) ||
//           full_network u64 || node_I u64 || node_R u64 ||
//           requester_nonce16 || responder_nonce16 || cookie16 ||
//           capability_I u32 || capability_R u32 || scope_binding32)
// I is the DISCOVER requester, R the OFFER responder. A re-sent DISCOVER
// refreshes nonces/cookie/digest together; nothing re-binds mid-exchange.
struct LinkCarrier {
  NetworkId network{0};  // full64
  NodeId node_i{kInvalidNodeId};
  NodeId node_r{kInvalidNodeId};
  std::array<std::uint8_t, 16> requester_nonce{};
  std::array<std::uint8_t, 16> responder_nonce{};
  std::array<std::uint8_t, 16> cookie{};
  std::uint32_t capability_i{0};
  std::uint32_t capability_r{0};
  ScopeDigest scope_binding{};
};
void link_carrier_digest(const LinkCarrier& carrier, ScopeDigest& out) noexcept;

// End-to-end carrier binding for the member EDHOC profile (P4 §5.3, NOT
// the RLRES1 routed binding above):
//   SHA-256("RouteLoom/v1/end-carrier" 0x00 || full_network u64 ||
//           node_I u64 || node_R u64 || exchange_id u32)
void end_carrier_binding(NetworkId network, NodeId node_i, NodeId node_r,
                         std::uint32_t exchange_id, ScopeDigest& out) noexcept;

// Binds the negotiated session profile into the Exporter context (P4 §5.4):
//   SHA-256("RouteLoom/v1/session-profile" 0x00 || Intent44 || State_R24 ||
//           State_I24)
// Refuses anything but the exact EAD value widths (44/24/24).
Status session_capability_digest(ByteView intent44, ByteView state_r24, ByteView state_i24,
                                 ScopeDigest& out) noexcept;

// Confirms both ends derived identical Exporter contexts (P4 §5.4; a hash
// of the public context encodings, never of secrets):
//   SHA-256("RouteLoom/v1/context-confirm" 0x00 || len16(C_1) || C_1 ||
//           len16(C_2) || C_2 || len16(C_RMS) || C_RMS)
Status session_contexts_digest(ByteView context_dir1, ByteView context_dir2, ByteView context_rms,
                               ScopeDigest& out) noexcept;

// --- AuthorityEnvelope (03 §5.3) ----------------------------------------------
// ver u8 | type u8 | ctx_id u32 | counter u48 | ciphertext n | tag 16B.
// The 12-byte header is the AEAD AAD; keys are the RLRES1 purpose=authority
// traffic keys (DAMS as RMS); nonce = aead_nonce(iv(dir), counter).
enum class AuthorityEnvelopeType : std::uint8_t {
  JoinConfirm = 1,
  GroupKeyUpdate = 2,
  GroupKeyActivate = 3,
  GroupKeyPull = 4,
  RevocationNotify = 5,
  RemovalNotice = 6,
  GrantRenew = 7,
  TimeSample = 8,
};
constexpr std::uint8_t kAuthorityEnvelopeVersion = 1;
constexpr std::size_t kAuthorityEnvelopeHeaderSize = 12;
constexpr std::size_t kAuthorityEnvelopeMin = kAuthorityEnvelopeHeaderSize + kAeadTagSize;
// Resolved in implementation: the envelope rides a ControlObject when >128B,
// so it inherits the 2048-byte authenticated-object ceiling.
constexpr std::size_t kAuthorityEnvelopeMax = 2048;

struct AuthorityEnvelopeHeader {
  std::uint8_t version{kAuthorityEnvelopeVersion};
  AuthorityEnvelopeType type{AuthorityEnvelopeType::GroupKeyPull};
  std::uint32_t ctx_id{0};
  std::uint64_t counter{0};
};

// Decode refusal reasons shared with the Rust mirror and the golden vectors.
enum class DecodeError : std::uint8_t {
  None = 0,
  Truncated,
  Oversized,
  LengthMismatch,
  BadPurpose,
  UnsupportedFlags,
  ReservedNonZero,
  ZeroContextId,
  TicketLength,
  BadStatus,
  BadVersion,
  BadType,
};
const char* decode_error_name(DecodeError error) noexcept;

Status authority_envelope_header_encode(const AuthorityEnvelopeHeader& header,
                                        std::array<std::uint8_t, kAuthorityEnvelopeHeaderSize>& out)
    noexcept;
// Validates a whole envelope (header + ciphertext + tag) and returns its header.
DecodeError authority_envelope_decode(ByteView envelope, AuthorityEnvelopeHeader& out) noexcept;

}  // namespace routeloom::keys
