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

// Legacy DataToMesh records scoped by authenticated HostLink incarnation
// and key. The incarnation already binds the principal and network.
// Same identity and payload hash replays; different hash conflicts.
struct IdempotencyRecord {
  std::uint64_t key{0};
  SessionTag hash{};
  // Stored outcome to replay on identical resubmission.
  bool accepted{false};
  std::uint16_t error_code{0};
  std::uint32_t message_session{0};
  std::uint64_t message_sequence{0};
  // Terminal time; orders reclamation without extending it on replay.
  MonotonicMs settled_ms{0};
  // HostLink session and USB request the terminal outcome is owed to (the
  // submission of this identity; request ids are session-scoped).
  std::uint64_t usb_session{0};
  std::uint64_t request{0};
  // Terminal outcome: admission refused (`error_code`), or the mesh
  // delivery reached `final_state`; the reason is an id plus the static
  // text it came from (nullptr for id-only reasons).
  bool settled{false};
  DeliveryState final_state{DeliveryState::Empty};
  std::uint16_t reason_id{0};
  const char* reason_detail{nullptr};
  // The terminal outcome reached the TX queue of `usb_session`. A settled
  // record is reclaimable once reported or once its session is gone.
  bool reported{false};
  bool replay{false};
};

enum class IdempotencyResult : std::uint8_t {
  Accepted, Existing, Conflict, ResultExpired, NoCapacity
};

class IdempotencyTable {
 public:
  static constexpr std::size_t kCapacity = 16;
  // Only terminal, reported records are reclaimed. Keys are monotonic in
  // the authenticated HostLink session: absent keys at/below its floor
  // never execute. A new incarnation starts a new key space; old sealed
  // frames are rejected by UsbBridge before they reach this table.
  IdempotencyResult submit(std::uint64_t key,
                           const SessionTag& hash, std::uint64_t usb_session,
                           MonotonicMs now_ms, IdempotencyRecord*& record) noexcept;

  // Each outstanding USB request reserves one of the same 16 records.
  // Refuses before changing the original request if all slots are owed.
  bool repeat(IdempotencyRecord*& record, std::uint64_t request) noexcept;
  std::size_t size() const noexcept;
  // The accepted record carrying this mesh message id, or nullptr.
  IdempotencyRecord* find_message(std::uint32_t message_session,
                                  std::uint64_t message_sequence,
                                  bool unsettled_only = false) noexcept;
  // Settled records whose outcome is still owed to `usb_session`, oldest
  // first through `record`; nullptr when none remain.
  IdempotencyRecord* next_unreported(std::uint64_t usb_session) noexcept;

 private:
  std::size_t reclaim_slot(std::uint64_t usb_session) noexcept;
  std::array<IdempotencyRecord, kCapacity> records_{};
  std::array<bool, kCapacity> used_{};
  std::uint64_t floor_session_{0};
  std::uint64_t floor_{0};
  bool has_floor_{false};
};

}  // namespace routeloom::usb
