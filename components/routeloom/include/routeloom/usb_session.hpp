#pragma once

// HostLink v2 (RLU1 protocol 2) session authentication for the USB bridge
// (docs/spec/usb-protocol.md §2). Both ends hold the per-bridge hostlink
// secret; every session value is keyed by
//   K = HKDF-SHA-256(salt = empty, IKM = secret, info = "RouteLoom/v2/hostlink", 32)
// and bound to the canonical transcript. The identical construction is
// implemented in host/routeloom-protocol/src/session.rs; protocol/usb-golden
// pins both to the same bytes. The link is authenticated, not encrypted.

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/status.hpp"
#include "routeloom/types.hpp"
#include "routeloom/usb_codec.hpp"

namespace routeloom::usb {

constexpr std::size_t kTagSize = 16;  // HMAC-SHA-256 truncated to 128 bits
constexpr std::size_t kSessionKeySize = 32;
constexpr std::size_t kBindingSize = 32;
constexpr std::size_t kMaxPrincipalSize = 32;
constexpr std::size_t kProtectedBodyOverhead = 8 + kTagSize;  // counter || tag

// Transcript carrier byte; USB/serial is 0. The 32-byte channel binding that
// follows it is reserved for carriers that bind a secure channel and is
// all zero on USB.
constexpr std::uint8_t kCarrierUsbSerial = 0;

using SessionTag = std::array<std::uint8_t, kTagSize>;
using SessionKey = std::array<std::uint8_t, kSessionKeySize>;

// Transcript bound into every session value: both nonces, the version range
// the host offered and the version selected (downgrade binding), carrier and
// channel binding, Node ID, Boot ID, full 64-bit Network ID, capability
// bitmap and host principal.
struct SessionTranscript {
  std::uint64_t host_nonce{0};
  std::uint64_t device_nonce{0};
  std::uint8_t min_version{kProtocolVersion};
  std::uint8_t max_version{kProtocolVersion};
  std::uint8_t version{kProtocolVersion};
  std::uint8_t carrier{kCarrierUsbSerial};
  NodeId node{kInvalidNodeId};
  std::uint64_t boot_id{0};
  NetworkId network{0};
  std::uint32_t capability{0};
  std::array<std::uint8_t, kMaxPrincipalSize> principal{};
  std::uint8_t principal_len{0};
};

constexpr std::size_t kTranscriptSize =
    8 + 8 + 8 + 1 + 1 + 1 + 1 + kBindingSize + 8 + 8 + 8 + 4 + 1 + kMaxPrincipalSize;

// Canonical encoding: "RLU1TRN2" || host_nonce || device_nonce ||
// min_version || max_version || version || carrier || binding(32, zero) || node ||
// boot || network || capability || plen || principal (zero-padded).
Status encode_transcript(const SessionTranscript& transcript, MutableByteView out,
                         std::size_t& written) noexcept;

struct SessionProof;
// Overwrites every key and tag (compiler-proof) and resets the id.
void clear_session_proof(SessionProof& proof) noexcept;

struct SessionProof {
  std::uint64_t session_id{0};
  SessionKey key_h2d{};      // host→device frame MAC key
  SessionKey key_d2h{};      // device→host frame MAC key
  SessionTag hello_tag{};    // device proves the secret inside HelloAck
  SessionTag auth_tag{};     // host proves the secret in the AUTH Hello
  SessionTag auth_ok_tag{};  // device confirms session establishment

  ~SessionProof() noexcept { clear_session_proof(*this); }
};

// Every value is HMAC-SHA-256(K, label || 0x00 || transcript):
//   key_h2d = "key-h2d", key_d2h = "key-d2h" (32 B each),
//   hello_tag = "hello", auth_tag = "auth", auth_ok_tag = "auth-ok" (first 16 B),
//   session_id = u64 BE of "session-id"[0..8].
SessionProof derive_session_proof(ByteView secret, ByteView transcript) noexcept;

// What a device keeps for the life of a session. The one-shot handshake tags
// are recomputed from the stored transcript when needed, not held.
struct SessionKeys;
// Overwrites both keys (compiler-proof) and resets the id.
void clear_session_keys(SessionKeys& keys) noexcept;

struct SessionKeys {
  std::uint64_t session_id{0};
  SessionKey key_h2d{};
  SessionKey key_d2h{};

  ~SessionKeys() noexcept { clear_session_keys(*this); }
};

// Direction byte bound into every protected frame tag.
constexpr std::uint8_t kDirHostToDevice = 0;
constexpr std::uint8_t kDirDeviceToHost = 1;

// frame_tag = HMAC-SHA-256(key, dir || counter u64 || kind u8 || flags u16 ||
//             request u64 || inner)[0..16], with the direction's own key.
SessionTag frame_tag(const SessionKey& key, std::uint8_t direction, std::uint64_t counter,
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

// Idempotency payload identity: SHA-256 of the canonical request, first 16 B.
SessionTag payload_hash(ByteView canonical_request) noexcept;

// Fixed-capacity idempotency record set scoped by
// (principal, network, operation_class, key). Same identity + same payload
// hash returns the stored result; same identity + different hash conflicts.
struct IdempotencyRecord {
  std::array<std::uint8_t, kMaxPrincipalSize> principal{};
  std::uint8_t principal_len{0};
  NetworkId network{0};
  std::uint8_t operation_class{0};
  std::uint64_t key{0};
  SessionTag hash{};
  // Stored outcome to replay on identical resubmission.
  bool accepted{false};
  std::uint16_t error_code{0};
  std::uint32_t message_session{0};
  std::uint64_t message_sequence{0};
  // Last identity touch; drives retention expiry and the settled hold.
  MonotonicMs last_use_ms{0};
  // The stored result is final and already reported to the host: admission
  // refused, or the mesh delivery reached a terminal state. Settled records
  // are the only unexpired ones a full table may evict.
  bool settled{false};
};

enum class IdempotencyResult : std::uint8_t {
  Accepted, Existing, Conflict, WindowExpired, NoCapacity
};

class IdempotencyTable {
 public:
  static constexpr std::size_t kCapacity = 16;
  // A full table may evict settled records only after leaving an identity
  // tombstone. A retry of an evicted identity fails closed instead of
  // executing the mesh operation again. In-flight records stay replayable;
  // a full tombstone set returns NoCapacity until its 24h retention expires.
  // Longer send streams require a durable idempotency design above this
  // bounded gateway cache (docs/spec/host.md §8).
  static constexpr MonotonicMs kRetentionMs = 24ULL * 3600ULL * 1000ULL;
  // A settled record stays replayable this long after its last use before
  // a full table may evict it: a host retry of a just-finished request
  // still replays instead of re-executing.
  static constexpr MonotonicMs kSettledHoldMs = 5000;
  static constexpr std::size_t kTombstoneCapacity = 96;

  // Finds or creates the record for this identity. On Existing/Conflict,
  // `record` points at the stored entry. On Accepted the caller must fill the
  // result fields; records persist across sessions (host identity scope).
  IdempotencyResult submit(ByteView principal, NetworkId network,
                           std::uint8_t operation_class, std::uint64_t key,
                           const SessionTag& hash, MonotonicMs now_ms,
                           IdempotencyRecord*& record) noexcept;

  std::size_t size() const noexcept;
  // Marks the accepted record carrying this mesh message id as settled
  // (its delivery reached a terminal state). Unknown ids are ignored.
  void settle(std::uint32_t message_session, std::uint64_t message_sequence) noexcept;

 private:
  struct Tombstone {
    std::uint64_t identity_hash{0};
    MonotonicMs last_use_ms{0};
  };
  std::array<IdempotencyRecord, kCapacity> records_{};
  std::array<bool, kCapacity> used_{};
  std::array<Tombstone, kTombstoneCapacity> tombstones_{};
  std::size_t tombstone_count_{0};
};

}  // namespace routeloom::usb
