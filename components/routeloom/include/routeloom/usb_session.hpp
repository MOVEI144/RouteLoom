#pragma once

// EXPERIMENTAL development-profile session authentication for the USB
// bridge. Like DevelopmentPskSecurityProvider it exercises the real state
// machine, transcript binding, per-direction counters and tag verification,
// but the MAC is a documented deterministic mixer, NOT a cryptographic
// primitive. The production profile is G-SEC's job; do not ship this as a
// security boundary. The identical construction is implemented in
// host/routeloom-protocol/src/dev_session.rs so C++ and Rust agree on every
// byte (see protocol/usb-golden).

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/status.hpp"
#include "routeloom/types.hpp"
#include "routeloom/usb_codec.hpp"

namespace routeloom::usb {

// Shared-mixer step (same family as the wire v1 test cipher):
//   s ^= v + 0x9e3779b97f4a7c15 + (s<<6) + (s>>2);  s *= 0xbf58476d1ce4e5b9
// All arithmetic wraps in u64. Byte-exact port of dev_mix in Rust.
constexpr std::uint64_t dev_mix(std::uint64_t state, const std::uint64_t value) noexcept {
  state ^= value + 0x9E3779B97F4A7C15ULL + (state << 6U) + (state >> 2U);
  state *= 0xBF58476D1CE4E5B9ULL;
  return state;
}

constexpr std::uint64_t kDevMacSeed = 0x524C553144455631ULL;  // "RLU1DEV1"
constexpr std::size_t kDevTagSize = 16;
constexpr std::size_t kSessionKeySize = 16;
constexpr std::size_t kMaxPrincipalSize = 32;
constexpr std::size_t kProtectedBodyOverhead = 8 + kDevTagSize;  // counter || tag

using DevTag = std::array<std::uint8_t, kDevTagSize>;
using SessionKey = std::array<std::uint8_t, kSessionKeySize>;

// Deterministic dev MAC. init(secret) absorbs the secret then its length;
// absorb* appends fields big-endian; tag() finalizes two independent lanes:
//   left  = mix(state, 0x4c454654)  emitted MSB-first into tag[0..8]
//   right = mix(state, 0x52474854)  emitted MSB-first into tag[8..16]
class DevMac {
 public:
  void init(ByteView secret) noexcept;
  void absorb(ByteView data) noexcept;
  void absorb_u8(std::uint8_t value) noexcept;
  void absorb_u16(std::uint16_t value) noexcept;
  void absorb_u32(std::uint32_t value) noexcept;
  void absorb_u64(std::uint64_t value) noexcept;
  DevTag tag() const noexcept;

 private:
  std::uint64_t state_{kDevMacSeed};
};

// proof = DevMac(secret).absorb(label).absorb(message).absorb_u64(len).tag()
DevTag dev_proof(ByteView secret, ByteView label, ByteView message) noexcept;

// Transcript bound into the session proof (spec section 2): host nonce,
// device nonce, selected protocol version, Node ID, Boot ID, Network ID,
// capability digest and host principal.
struct SessionTranscript {
  std::uint64_t host_nonce{0};
  std::uint64_t device_nonce{0};
  std::uint8_t version{kProtocolVersion};
  NodeId node{kInvalidNodeId};
  std::uint64_t boot_id{0};
  NetworkId network{0};
  std::uint32_t capability{0};
  std::array<std::uint8_t, kMaxPrincipalSize> principal{};
  std::uint8_t principal_len{0};
};

constexpr std::size_t kTranscriptSize =
    8 + 8 + 8 + 1 + 8 + 8 + 8 + 4 + 1 + kMaxPrincipalSize;

// Canonical encoding: "RLU1TRN1" || host_nonce || device_nonce || version ||
// node || boot || network || capability || plen || principal (zero-padded).
Status encode_transcript(const SessionTranscript& transcript, MutableByteView out,
                         std::size_t& written) noexcept;

struct SessionProof {
  std::uint64_t session_id{0};
  SessionKey key{};
  DevTag hello_tag{};    // device proves the secret inside HelloAck
  DevTag auth_tag{};     // host proves the secret in the AUTH Hello
  DevTag auth_ok_tag{};  // device confirms session establishment
};

// Derives all session values from one transcript:
//   key         = proof("session-key")
//   hello_tag   = proof("hello")
//   auth_tag    = proof("auth")
//   auth_ok_tag = proof("auth-ok")
//   session_id  = u64 BE of proof("session-id")[0..8]
SessionProof derive_session_proof(ByteView secret, ByteView transcript) noexcept;

// Direction byte bound into every protected frame tag.
constexpr std::uint8_t kDirHostToDevice = 0;
constexpr std::uint8_t kDirDeviceToHost = 1;

// frame_tag = DevMac(key).absorb_u8(dir).absorb_u64(counter).absorb_u8(kind)
//             .absorb_u16(flags).absorb_u64(request).absorb(inner)
//             .absorb_u64(inner.len).tag()
DevTag frame_tag(const SessionKey& key, std::uint8_t direction, std::uint64_t counter,
                 FrameKind kind, std::uint16_t flags, std::uint64_t request,
                 ByteView inner) noexcept;

// Protected body layout: counter(8 BE) || tag(16) || inner.
Status seal_body(const SessionKey& key, std::uint8_t direction, std::uint64_t counter,
                 FrameKind kind, std::uint16_t flags, std::uint64_t request,
                 ByteView inner, MutableByteView out, std::size_t& written) noexcept;

// Verifies the tag over the frame's own kind/flags/request, then returns the
// embedded counter and the inner view (aliases frame.body). Does not check
// the counter value itself; the caller enforces replay policy.
Status open_body(const SessionKey& key, std::uint8_t direction, const UsbFrame& frame,
                 std::uint64_t& counter, ByteView& inner) noexcept;

// Deterministic non-cryptographic hash for idempotency payload comparison.
// Same construction as dev_proof with a fixed public label.
DevTag payload_hash(ByteView canonical_request) noexcept;

// Fixed-capacity idempotency record set scoped by
// (principal, network, operation_class, key). Same identity + same payload
// hash returns the stored result; same identity + different hash conflicts.
struct IdempotencyRecord {
  std::array<std::uint8_t, kMaxPrincipalSize> principal{};
  std::uint8_t principal_len{0};
  NetworkId network{0};
  std::uint8_t operation_class{0};
  std::uint64_t key{0};
  DevTag hash{};
  // Stored outcome to replay on identical resubmission.
  bool accepted{false};
  std::uint16_t error_code{0};
  std::uint32_t message_session{0};
  std::uint64_t message_sequence{0};
  // Last identity touch; drives retention expiry (never evicted earlier —
  // evicting a live record would silently re-execute a resubmitted key).
  MonotonicMs last_use_ms{0};
};

enum class IdempotencyResult : std::uint8_t { Accepted, Existing, Conflict, NoCapacity };

class IdempotencyTable {
 public:
  static constexpr std::size_t kCapacity = 16;
  // Mirrors the host retention contract (docs/spec/host.md §operation
  // identity): results are replayable for 24h. Records are NEVER evicted
  // before expiry — a full table of unexpired records rejects with
  // NoCapacity (IDEMPOTENCY_FULL), which is the specified backpressure
  // signal. Expired records are evictable; a resubmitted expired key is
  // treated as a fresh operation (per-principal acceptance epochs and
  // IDEMPOTENCY_WINDOW_EXPIRED remain host-side future work).
  static constexpr MonotonicMs kRetentionMs = 24ULL * 3600ULL * 1000ULL;

  // Finds or creates the record for this identity. On Existing/Conflict,
  // `record` points at the stored entry. On Accepted the caller must fill the
  // result fields; records persist across sessions (host identity scope).
  IdempotencyResult submit(ByteView principal, NetworkId network,
                           std::uint8_t operation_class, std::uint64_t key,
                           const DevTag& hash, MonotonicMs now_ms,
                           IdempotencyRecord*& record) noexcept;

  std::size_t size() const noexcept;

 private:
  std::array<IdempotencyRecord, kCapacity> records_{};
  std::array<bool, kCapacity> used_{};
};

}  // namespace routeloom::usb
