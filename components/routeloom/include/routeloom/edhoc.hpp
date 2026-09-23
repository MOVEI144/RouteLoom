#pragma once

// EDHOC (RFC 9528) session with RouteLoom's bounded-memory crypto backend.
//
// docs/design/sdk-v1/08-implementation-plan.md P2-1. The protocol engine is
// the vendored libedhoc (components/routeloom/third_party/libedhoc, pinned in
// NOTICE); this header is the RouteLoom side of its callback boundary:
//
//   - crypto: cipher suite 2 only (P-256 ECDH / ES256 / SHA-256 /
//     AES-CCM-16-64-128). P-256 is the vendored micro-ecc, SHA-256 / HMAC /
//     HKDF are routeloom/kdf.hpp, AES-CCM is an injected `AeadCcm` (host
//     builds: the vendored TF-PSA-Crypto builtin AES+CCM, `builtin_aead_ccm()`;
//     ESP-IDF: supplied by the adapter — PSA, see routeloom/psa_edhoc_aead.hpp).
//   - memory: libedhoc's custom memory backend. Every working buffer the
//     library allocates comes from the calling session's fixed `Arena`; there
//     is no heap and no VLA, and an exhausted arena fails the call cleanly.
//   - keys: 4-byte handles into the session's fixed `KeyStore`; key material
//     never leaves the session and is wiped on destroy and on end().
//   - credentials: kid-referenced (ID_CRED_x = {4: kid}); `CredentialProvider`
//     returns the local CRED_x and private key, and authenticates the peer.
//
// Everything is statically sized per session (see sizeof(Session) and the
// constants below); nothing here is global except a thread-local pointer to
// the arena of the session currently inside a libedhoc call.
//
// libedhoc's public headers are C11 and stay out of this header: the C
// context lives in `context_storage_` (size checked at compile time by
// src/edhoc/edhoc_port.c) and is reachable through native() for tests and
// integrations that need the raw API.
//
// EAD: an optional EadHandler composes/processes the items of each message
// (P3-1; the join items and their strict walkers are sdkv1_ead.hpp). Not
// claimed: the rest of the RouteLoom application profile (Exporter context,
// ContextConfirm) — that is P4-2. Test vectors: protocol/edhoc-rfc9529/.

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/discovery_scope.hpp"  // Sha256
#include "routeloom/edhoc_storage.h"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

struct edhoc_context;

namespace routeloom::edhoc {

constexpr std::int32_t kCipherSuite2 = 2;
constexpr std::size_t kP256ScalarSize = 32;
constexpr std::size_t kP256CoordinateSize = 32;  // G_X / G_Y wire form (x only)
constexpr std::size_t kP256PublicKeySize = 64;   // X || Y, no SEC1 prefix
constexpr std::size_t kEs256SignatureSize = 64;  // R || S
constexpr std::size_t kSuite2HashSize = 32;
constexpr std::size_t kSuite2AeadKeySize = 16;
constexpr std::size_t kSuite2AeadNonceSize = 13;
constexpr std::size_t kSuite2AeadTagSize = 8;
// Largest kid RouteLoom uses: SHA-256 of the canonical public COSE_Key
// (docs/design/host-security-readiness/05-production-security.md §3).
constexpr std::size_t kKidMaxSize = 32;
constexpr std::size_t kConnectionIdMaxSize = ROUTELOOM_EDHOC_CONN_ID_MAX;

enum class Role : std::uint8_t { Initiator = 0, Responder = 1 };

// RFC 9528 §3.2. RouteLoom's profile uses SignatureSignature (method 0); the
// RFC 9529 §3 trace uses StaticStatic (method 3). Methods 1/2 work with the
// same callbacks; method 4 (PSK, draft) is refused.
enum class Method : std::uint8_t {
  SignatureSignature = 0,
  SignatureStatic = 1,
  StaticSignature = 2,
  StaticStatic = 3,
};

// ---------------------------------------------------------------------------
// Bounded scratch arena (libedhoc CONFIG_LIBEDHOC_MEM_BACKEND = custom).
// First-fit over a fixed byte array with a fixed block table, so frees in any
// order are reclaimed. Blocks are 8-byte aligned and zeroed on allocation;
// released blocks are wiped (they held transcript and key-schedule scratch).
class Arena {
 public:
  static constexpr std::size_t kCapacity = ROUTELOOM_EDHOC_ARENA_BYTES;
  static constexpr std::size_t kMaxBlocks = ROUTELOOM_EDHOC_ARENA_BLOCKS;
  static constexpr std::size_t kAlignment = 8;

  void* allocate(std::size_t size) noexcept;
  void release(void* block) noexcept;
  void reset() noexcept;  // wipes everything, keeps the statistics

  std::size_t in_use() const noexcept;
  std::size_t live_blocks() const noexcept { return count_; }
  std::size_t high_water() const noexcept { return high_water_; }
  std::size_t max_live_blocks() const noexcept { return max_live_blocks_; }
  std::size_t failures() const noexcept { return failures_; }

 private:
  struct Block {
    std::uint32_t offset;
    std::uint32_t size;
  };
  alignas(8) std::array<std::uint8_t, kCapacity> bytes_{};
  std::array<Block, kMaxBlocks> blocks_{};  // sorted by offset
  std::size_t count_{0};
  std::size_t high_water_{0};
  std::size_t max_live_blocks_{0};
  std::size_t failures_{0};
};

// ---------------------------------------------------------------------------
// Bounded key store behind libedhoc's opaque 4-byte key handles.
enum class KeyUsage : std::uint8_t {
  None = 0,
  Kdf = 1,           // PRKs and ECDH shared secrets (HKDF input)
  Aead = 2,          // K_3 / K_4 (AES-128)
  Ephemeral = 3,     // own ephemeral P-256 scalar (ECDH only)
  Authentication = 4 // own long-term P-256 scalar (ES256 or static DH)
};

class KeyStore {
 public:
  static constexpr std::size_t kSlots = ROUTELOOM_EDHOC_KEY_SLOTS;
  static constexpr std::size_t kMaxKeySize = 32;
  static constexpr std::size_t kHandleSize = 4;

  // Stores `material` and writes its handle (little-endian u32: index+1 in
  // the low byte, a generation counter above it; all-zero is the null
  // handle). Fails when full or on a bad size.
  bool import(KeyUsage usage, ByteView material, void* handle_out) noexcept;
  // Material of a live handle of that usage; empty view otherwise.
  ByteView find(const void* handle, KeyUsage usage) const noexcept;
  // Material of a live handle of any usage (test/diagnostic access).
  ByteView peek(const void* handle) const noexcept;
  // Destroying the null handle is a successful no-op (libedhoc relies on it);
  // a stale or unknown handle fails.
  bool destroy(const void* handle) noexcept;
  void clear() noexcept;

  std::size_t live() const noexcept;
  std::size_t high_water() const noexcept { return high_water_; }

 private:
  struct Slot {
    std::array<std::uint8_t, kMaxKeySize> bytes{};
    std::uint8_t size{0};
    KeyUsage usage{KeyUsage::None};
    std::uint16_t generation{0};
  };
  const Slot* resolve(const void* handle) const noexcept;
  std::array<Slot, kSlots> slots_{};
  std::size_t high_water_{0};
};

// ---------------------------------------------------------------------------
// AES-CCM-16-64-128 (RFC 9528 cipher suite 2; 16-byte key, 13-byte nonce,
// 8-byte tag). `seal` writes ciphertext || tag (plaintext.size + 8 bytes);
// `open` takes ciphertext || tag and returns true only when the tag verified;
// on a bad tag the output is left zeroed. Both return false on any failure.
struct AeadCcm {
  bool (*seal)(void* ctx, const std::uint8_t* key, const std::uint8_t* nonce,
               ByteView aad, ByteView plaintext, std::uint8_t* out) noexcept;
  bool (*open)(void* ctx, const std::uint8_t* key, const std::uint8_t* nonce,
               ByteView aad, ByteView ciphertext_and_tag,
               std::uint8_t* out) noexcept;
  void* ctx;
};

// Host builds: the vendored TF-PSA-Crypto builtin AES + CCM. ESP-IDF builds
// do not compile that subset (the firmware links ESP-IDF's own Mbed TLS), so
// this returns nullptr there and the adapter passes its PSA implementation.
const AeadCcm* builtin_aead_ccm() noexcept;

// Fills `out` with `size` bytes from a CSPRNG. Only ephemeral key generation
// draws randomness; ES256 signatures are deterministic (micro-ecc's
// HMAC-DRBG nonce over SHA-256), so a signature never depends on the RNG.
using RandomFn = bool (*)(void* ctx, std::uint8_t* out, std::size_t size) noexcept;

// ---------------------------------------------------------------------------
// Credentials (kid only: ID_CRED_x = {4: kid}).
struct LocalCredential {
  ByteView kid;         // at most kKidMaxSize bytes
  ByteView credential;  // CRED_x as a CBOR data item (CCS, RLCW1 MemberCert…)
  std::array<std::uint8_t, kP256ScalarSize> private_key{};  // ES256 or static DH
};

struct PeerCredential {
  ByteView credential;  // peer CRED_x as a CBOR data item
  std::array<std::uint8_t, kP256PublicKeySize> public_key{};  // X || Y
};

// Both views returned by the provider must stay valid until the session ends
// (libedhoc keeps pointers to CRED_x across messages). `peer` is the trust
// decision: it must resolve the kid, validate the credential (chain,
// revocation, role) and only then return Ok.
class CredentialProvider {
 public:
  virtual ~CredentialProvider() = default;
  virtual Status local(Role role, LocalCredential& out) noexcept = 0;
  virtual Status peer(Role role, ByteView kid, PeerCredential& out) noexcept = 0;
};

// ---------------------------------------------------------------------------
// External Authorization Data (RFC 9528 §3.8). The zero-touch join profile
// (sdkv1_ead.hpp) rides here. libedhoc hands a message's items to process()
// BEFORE it authenticates the peer (message_2: step 9 before step 10;
// message_3: step 6 before authenticate_peer), so a handler can stage the
// certificate of the join Credential item (label 65541) for the
// CredentialProvider to match against the kid in the same message.
constexpr std::size_t kEadItemsMax = 3;  // CONFIG_LIBEDHOC_MAX_NR_OF_EAD_TOKENS

struct EadItem {
  std::int32_t label{0};  // negative = critical
  // compose: owned by the handler, valid until the composing call returns;
  // process: points into the session's arena, valid during the call only.
  ByteView value{};
};

class EadHandler {
 public:
  virtual ~EadHandler() = default;
  // `message` is 1..4. Fill up to `capacity` items for the outgoing message.
  virtual Status compose(int message, EadItem* items, std::size_t capacity,
                         std::size_t& count) noexcept = 0;
  // The items received in `message`; an error aborts the session (the join
  // profile rejects unknown critical items and any item out of place).
  virtual Status process(int message, const EadItem* items, std::size_t count) noexcept = 0;
};

struct SessionConfig {
  Role role{Role::Initiator};
  Method method{Method::SignatureSignature};
  // SUITES_I / supported suites in preference order, selected (own) suite
  // last. Only suite 2 can actually run; other values are only for
  // negotiation (RFC 9529 §3 lists [6, 2]).
  std::array<std::int32_t, ROUTELOOM_EDHOC_SUITES_MAX> suites{{kCipherSuite2}};
  std::size_t suite_count{1};
  ByteView connection_id;  // C_I or C_R, 1..kConnectionIdMaxSize bytes
  CredentialProvider* credentials{nullptr};
  const AeadCcm* aead{nullptr};  // nullptr: builtin_aead_ccm()
  RandomFn random{nullptr};
  void* random_ctx{nullptr};
  // Optional. nullptr keeps P2-1 behaviour: nothing is composed and libedhoc
  // ignores received EAD — the join profile always binds a handler.
  EadHandler* ead{nullptr};
};

// ---------------------------------------------------------------------------
// One EDHOC exchange. Not copyable or movable (libedhoc keeps a pointer to
// it as the callback user context). All methods return a RouteLoom Status;
// the libedhoc return code of the last call is in last_error().
class Session {
 public:
  Session() noexcept = default;
  ~Session();
  Session(const Session&) = delete;
  Session& operator=(const Session&) = delete;

  Status begin(const SessionConfig& config) noexcept;
  // Deinitialises the libedhoc context and wipes keys, arena, and hashes.
  void end() noexcept;
  bool active() const noexcept { return active_; }

  Status compose_message_1(MutableByteView out, std::size_t& length) noexcept;
  Status process_message_1(ByteView message) noexcept;
  Status compose_message_2(MutableByteView out, std::size_t& length) noexcept;
  Status process_message_2(ByteView message) noexcept;
  Status compose_message_3(MutableByteView out, std::size_t& length) noexcept;
  Status process_message_3(ByteView message) noexcept;
  Status compose_message_4(MutableByteView out, std::size_t& length) noexcept;
  Status process_message_4(ByteView message) noexcept;

  // EDHOC error message (RFC 9528 §6). `code` is ERR_CODE; for
  // wrong-selected-cipher-suite (2) `suites` is SUITES_R.
  Status compose_error(std::int32_t code, const std::int32_t* suites,
                       std::size_t suite_count, MutableByteView out,
                       std::size_t& length) noexcept;
  // Returns ERR_CODE; for code 2 copies SUITES_R into `suites`.
  Status process_error(ByteView message, std::int32_t& code,
                       std::int32_t* suites, std::size_t suites_capacity,
                       std::size_t& suite_count) noexcept;

  // EDHOC_Exporter (RFC 9528 §4.2.1) into raw bytes. RouteLoom's
  // application labels are private-use (>= 32768).
  Status exporter(std::size_t label, ByteView context, MutableByteView out) noexcept;
  // EDHOC_KeyUpdate (RFC 9528 Appendix H).
  Status key_update(ByteView context) noexcept;
  // OSCORE master secret/salt and sender/recipient ids (RFC 9528 Appendix A).
  Status oscore_context(MutableByteView master_secret,
                        MutableByteView master_salt, MutableByteView sender_id,
                        std::size_t& sender_id_length,
                        MutableByteView recipient_id,
                        std::size_t& recipient_id_length) noexcept;

  int last_error() const noexcept { return last_error_; }
  edhoc_context* native() noexcept;
  const KeyStore& keys() const noexcept { return keys_; }
  const Arena& arena() const noexcept { return arena_; }

  // Backend internals, public only so the C callback trampolines in
  // edhoc_session.cpp can reach them.
  struct Backend;
  friend struct Backend;

 private:
  static constexpr std::size_t kHashOps = 2;
  struct HashOp {
    Sha256 sha;
    bool busy{false};
  };

  Status finish_call(int result, const char* detail) noexcept;

  alignas(ROUTELOOM_EDHOC_CONTEXT_ALIGN)
      std::array<unsigned char, ROUTELOOM_EDHOC_CONTEXT_BYTES> context_storage_{};
  Arena arena_{};
  KeyStore keys_{};
  std::array<HashOp, kHashOps> hashes_{};
  // The local long-term key lives in this dedicated handle (libedhoc does not
  // destroy credential keys); re-imported by every select_local.
  std::array<std::uint8_t, KeyStore::kHandleSize> local_key_{};
  // Public key of the authenticated peer (libedhoc keeps a pointer to it
  // while it verifies Signature_or_MAC / computes the static-DH secret).
  std::array<std::uint8_t, kP256PublicKeySize> peer_public_key_{};
  SessionConfig config_{};
  const AeadCcm* aead_{nullptr};
  int last_error_{0};
  bool active_{false};
};

}  // namespace routeloom::edhoc
