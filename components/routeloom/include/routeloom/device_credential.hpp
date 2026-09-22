#pragma once

// Device credential record portable core (issue #10;
// sdk-completion/04-provisioning-lifecycle.md §4.3.2, §4.8). The RLC1
// DeviceCredentialRecord binds this node's identity: the full-u64 network
// (deployment generation in the upper bits per §4.8), the NodeId, the
// generation_base_session the u16 wire-epoch window counts from, the P-256
// RPK (public half + location-tagged private material), the kid fingerprint
// and the authority-issued MembershipGrant.
//
// Same dual-slot seal/write/readback/commit discipline as the trust store
// and the authority ledger. RLC1 carries no ordinal: a commit writes the
// SAME record to both slots (§4.9 budgets 2 slots x 2 phases per
// re-credential), so two surviving valid records must be byte-identical —
// different-but-valid siblings cannot be ordered and quarantine.
//
// Implemented and host-tested here: codec, kid/keypair/grant-field
// consistency checks, dual-slot store, the §4.8 epoch-window helper.
// NOT implemented (later checklist items): grant signature verification
// (needs authority key resolution — the membership workstream), the NVS
// adapter (rlcred/d0/d1), on-device key generation and the host-side
// registration flow.

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/authority.hpp"  // Digest256
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom {

// --- Bounds (§4.3.2) -----------------------------------------------------------
constexpr std::uint8_t kCredentialSlots = 2;
constexpr std::size_t kCredentialSlotBytes = 1024;    // NVS blob bound per slot
constexpr std::size_t kCredentialGrantMax = 256;      // grant_max_bytes
constexpr std::size_t kCredentialHeaderSize = 40;
constexpr std::size_t kCredentialFixedBody = 128;     // kid 32 + pubkey 64 + key 32
// 40 + 128 + grant_len + 4; max 428 bytes, inside the 1024 slot bound.
constexpr std::size_t kCredentialRecordMax = 428;
constexpr std::uint32_t kCredentialSchemaVersion = 1;
constexpr std::size_t kCredentialKeyMaterialSize = 32;
constexpr std::size_t kCredentialPubkeySize = 64;

enum class CredentialKeyLocation : std::uint8_t {
  None = 0,           // no private key on device (dev/zero material)
  NvsPlaintext = 1,   // private key in the record; consistency-checked
  EfuseDsBound = 2,   // key_material is an opaque handle
  SecureElement = 3,  // key_material is an opaque handle
};

enum class CredentialStatus : std::uint8_t {
  PendingRegistration = 1,
  Active = 2,
  // Sticky operator state, not a wire verdict (§4.3.2): the credential is
  // retained but locally suspended.
  SuspendedLocal = 3,
};

struct DeviceCredential {
  NetworkId network{0};                 // full NetworkId (§4.8 split)
  NodeId node_id{kInvalidNodeId};
  std::uint32_t generation_base_session{0};  // rlboot session of cutover
  CredentialKeyLocation key_location{CredentialKeyLocation::None};
  CredentialStatus cred_status{CredentialStatus::PendingRegistration};
  // SHA-256 over the canonical public COSE_Key (host-security §3: kty=EC2,
  // alg=ES256, crv=P-256, x/y bstr32 — never the private half).
  Digest256 kid{};
  std::array<std::uint8_t, kCredentialPubkeySize> pubkey{};  // X || Y
  // key_location 1: the P-256 private scalar; >=2: opaque key handle;
  // 0: zero-filled.
  std::array<std::uint8_t, kCredentialKeyMaterialSize> key_material{};
  ByteBuffer<kCredentialGrantMax> grant{};
};

// Canonical public COSE_Key for the kid computation (deterministic CBOR,
// host-security-readiness §3): {1:2 (kty EC2), 3:-7 (alg ES256), -1:1
// (crv P-256), -2:x, -3:y} — 75 bytes. kid = SHA-256 over those bytes.
// `pubkey` is the 64-byte X||Y encoding. Distinct from the permit
// envelope's alg: ESP256 (-9) is the envelope profile; the credential
// COSE_Key's `alg` label is ES256 (-7) per the host-security contract.
Status credential_cose_key_encode(ByteView pubkey,
                                  ByteBuffer<80>& out) noexcept;
Status credential_kid(ByteView pubkey, Digest256& out) noexcept;

// Record-level consistency checks (§4.3.2 boot checks):
//  - fields in range; nonzero network/node_id;
//  - kid == SHA-256(canonical COSE_Key(pubkey)) and pubkey on-curve;
//  - key_location 0 -> key_material all-zero; 1 -> uECC compute_public_key
//    reproduces pubkey; >=2 -> opaque handle, no local check possible;
//  - when grant bytes are present, the grant envelope's signed payload
//    (deterministic CBOR array [1, network_u32, node_u64, kid_bstr32, ...]
//    per host-security §3) must parse and its network/node/kid must equal
//    the record's. This is FIELD CONSISTENCY ONLY — the grant's COSE
//    signature is not verified here (no authority key resolution exists
//    yet; pending the membership workstream).
// Any mismatch is corruption — never a cue to re-derive a credential.
Status credential_validate(const DeviceCredential& credential) noexcept;

// RLC1 record codec. encode validates first (credential_validate) so no
// path persists a record boot would reject. seal: kCredentialSealPending
// while a write is in flight, kCredentialSealCommitted for the commit
// marker. out.size = used_len; stores write only [0, size).
Status credential_record_encode(const DeviceCredential& credential,
                                std::uint32_t seal,
                                ByteBuffer<kCredentialSlotBytes>& out) noexcept;
// Decode + fully validate a committed RLC1 record (tooling/tests; the
// store's slot classifier distinguishes Empty/Pending/Corrupt/Unsupported
// internally).
Status credential_record_decode(ByteView record, DeviceCredential& out) noexcept;

// §4.8 epoch window: wire epochs derive as ((session - base - 1) % 0xFFFF)
// + 1 where `base` is generation_base_session — the existing (session-1)
// mapping with the window origin moved. `session` must be strictly greater
// than `base` (the cutover session itself predates the window).
//
// The u16 space is finite: when (session - base) reaches the 0xFFF0
// threshold the next boots would walk into the wrap that reuses epoch 1
// under peer floors that can never accept it. Instead of silently
// wrapping, the helper fails with RecoveryRequired — the design's
// REPROVISION_REQUIRED wedge: refuse network bring-up, leave a diagnostic,
// recover via a deployment-generation cutover (or literal re-provisioning
// on the dev bench).
constexpr std::uint32_t kCredentialEpochWindowMax = 0xFFF0;
Status credential_epoch_for_session(std::uint32_t session,
                                    std::uint32_t generation_base_session,
                                    std::uint16_t& epoch_out) noexcept;

// Raw two-slot persistence for the credential record. read() fills the
// whole kCredentialSlotBytes slot view (a missing blob reads uniformly
// erased); write() lands a record of <=1024 bytes. Implementations must
// tolerate power loss at any byte boundary and must never erase or
// reformat storage on error.
class CredentialStorage {
 public:
  virtual ~CredentialStorage() = default;
  virtual Status read(std::uint8_t slot, MutableByteView target) noexcept = 0;
  virtual Status write(std::uint8_t slot, ByteView data) noexcept = 0;
};

// Dual-slot credential store. RLC1 has no ordinal, so commit_record writes
// the identical record to BOTH slots; boot adopts only a byte-identical
// pair or a lone survivor whose sibling is provably absent — anything else
// (conflicting valid records, or a survivor whose sibling may hold
// different committed data) marks the store quarantined/uncertain and
// waits for explicit recover(), mirroring the trust store's rules.
class DeviceCredentialStore {
 public:
  explicit DeviceCredentialStore(CredentialStorage& storage) noexcept;

  Status initialize() noexcept;

  // Commit a credential (provisioning or re-credentialing): validates,
  // then writes the same sealed record to both slots with readback —
  // all-or-nothing across the pair as far as a single fault admits.
  Status commit_record(const DeviceCredential& credential) noexcept;

  // Explicit operator recovery from quarantine/uncertain: the operator
  // attests a complete credential, written to both slots. RLC1 has no
  // epoch floor to clear; the attestation is the safety mechanism.
  Status recover(const DeviceCredential& credential) noexcept;

  bool initialized() const noexcept { return initialized_; }
  bool has_active() const noexcept { return has_active_; }
  bool quarantined() const noexcept { return quarantined_; }
  bool uncertain() const noexcept { return uncertain_; }
  const DeviceCredential& credential() const noexcept { return credential_; }

 private:
  enum class SlotContent : std::uint8_t {
    Empty,
    Pending,
    Corrupt,
    Unsupported,
    Valid,
  };

  Status decode_slot(std::uint8_t slot, DeviceCredential& credential,
                     std::size_t& used_len, SlotContent& content) noexcept;
  Status store_record(std::uint8_t slot, const DeviceCredential& credential,
                      std::size_t used_len) noexcept;

  CredentialStorage& storage_;
  DeviceCredential credential_{};
  std::array<DeviceCredential, kCredentialSlots> parsed_{};
  std::array<std::uint8_t, kCredentialSlotBytes> scratch_a_{};
  std::array<std::uint8_t, kCredentialSlotBytes> scratch_b_{};
  std::array<StatusCode, kCredentialSlots> slot_reserved_{};
  std::uint8_t active_slot_{0};
  bool has_active_{false};
  bool initialized_{false};
  bool quarantined_{false};
  bool uncertain_{false};
};

}  // namespace routeloom
