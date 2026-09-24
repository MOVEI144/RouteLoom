#pragma once

// Trust store portable core (issue #10; sdk-completion/
// 04-provisioning-lifecycle.md §4.2-§4.5). The RLT1 TrustStoreImage is the
// device's root-of-trust state: up to 2 deployment root anchors, up to 4
// config-authority key records, a <=24-entry device-credential revocation
// set, the monotonic store_epoch and the min_authority_generation floor.
//
// Persistence is dual-slot under the same discipline as the authority
// ledger and the config journal: seal -> write -> readback -> commit,
// every accepted image lands in BOTH slots as a twin pair (a power cut
// leaves a discardable pending record or a new/old split the next boot
// orders by epoch), committed-but-CRC-failed records still bounding the
// recovery floors, both slots lost -> quarantine, and an explicit
// recover() as the only way back (never an implicit reset, never an
// erase).
//
// Scope of this file: record codec + slot state machine + accessors.
// COSE manifest verification lives in trust_manifest.hpp; NVS adapters,
// the maintenance-console install verb and the TrustManager endpoint
// demux are separate checklist items and are NOT implemented here.

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/authority.hpp"  // Digest256
#include "routeloom/security_floor.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom {

// --- Bounds and wire constants (04-provisioning-lifecycle.md §4.3.1) ---------
constexpr std::uint8_t kTrustStoreSlots = 2;
constexpr std::size_t kTrustStoreSlotBytes = 2048;   // NVS blob bound per slot
constexpr std::size_t kTrustAnchorMax = 2;
constexpr std::size_t kTrustKeyMax = 4;
constexpr std::size_t kTrustRevocationMax = 24;
constexpr std::size_t kTrustAnchorEntrySize = 80;
constexpr std::size_t kTrustKeyEntrySize = 80;
constexpr std::size_t kTrustRevocationEntrySize = 48;
constexpr std::size_t kTrustImageHeaderSize = 48;
// Maximum committed image: 48 + 2*80 + 4*80 + 24*48 + 4 = 1684 bytes,
// inside the 2048-byte slot bound 03-signing §3.4 already budgeted.
constexpr std::size_t kTrustImageMax = 1684;
// Signed manifest content = RLT1 bytes [16, used_len-4) — the semantic
// image without the storage-local head (magic/format/used_len/schema/seal)
// and CRC tail. The codec below is the single truth for both (§4.3.3).
constexpr std::size_t kTrustImageContentMax = kTrustImageMax - 16 - 4;  // 1664
constexpr std::uint32_t kTrustStoreSchemaVersion = 1;

// flags bits (§4.3.1); all other bits are reserved-zero.
constexpr std::uint8_t kTrustFlagProvisioningConsoleLocked = 0x01;
constexpr std::uint8_t kTrustFlagRequiresProductionProfile = 0x02;
constexpr std::uint8_t kTrustFlagMask = 0x03;

enum class TrustAnchorStatus : std::uint8_t {
  Active = 1,    // may sign trust manifests
  Disabled = 2,  // signs nothing; retained for inventory/audit
};

enum class TrustKeyProfile : std::uint8_t {
  Rlcp1CoseEsp256 = 1,  // the only defined profile
};

enum class TrustKeyRole : std::uint8_t {
  ConfigIssuer = 1,  // other roles reserved (membership signing reuses
                     // this record kind when that workstream lands)
};

enum class TrustKeyStatus : std::uint8_t {
  Staged = 1,    // present, verifies nothing yet
  Active = 2,    // may verify permits
  Retired = 3,   // verifies nothing
  Revoked = 4,   // verifies nothing
};

enum class TrustKeyScope : std::uint8_t {
  WholeNetwork = 0,  // other values reserved
};

enum class TrustRevocationKind : std::uint8_t {
  DeviceCredential = 1,  // kid fingerprint of the canonical COSE_Key
};

struct TrustAnchor {
  // Administrative 8-byte identifier assigned at key creation — the value a
  // manifest's protected-header kid names. NOT a truncated key hash (§4.3.1).
  std::uint64_t root_id{0};
  std::array<std::uint8_t, 64> pubkey{};  // X || Y, no SEC1 prefix
  TrustAnchorStatus status{TrustAnchorStatus::Active};
};

struct TrustKeyRecord {
  std::uint64_t authority_id{0};  // the kid permits name
  std::uint32_t generation{0};
  TrustKeyProfile profile{TrustKeyProfile::Rlcp1CoseEsp256};
  TrustKeyRole role{TrustKeyRole::ConfigIssuer};
  TrustKeyStatus status{TrustKeyStatus::Staged};
  TrustKeyScope scope{TrustKeyScope::WholeNetwork};
  std::array<std::uint8_t, 64> pubkey{};  // X || Y, no SEC1 prefix
};

struct TrustRevocation {
  // The entry names the CREDENTIAL — the kid fingerprint — not merely the
  // claimed NodeId: a revoked device re-presenting the same NodeId under a
  // different kid is a different credential and a different decision.
  NodeId node_id{kInvalidNodeId};
  Digest256 kid_fingerprint{};
  std::uint32_t revoked_at_epoch{0};  // store_epoch of the adding image
  TrustRevocationKind kind{TrustRevocationKind::DeviceCredential};
};

// The semantic content of one trust image (RLT1 bytes [16, used_len-4)).
struct TrustImage {
  std::uint32_t store_epoch{0};   // ordinal, starts at 1, strictly increases
  std::uint32_t min_authority_generation{0};  // floor; never regresses
  NetworkId network{0};           // FULL NetworkId incl. deployment generation
  std::uint64_t deployment_id{0}; // operator audit label, not a credential
  std::uint8_t flags{0};          // kTrustFlag* bits only
  std::array<TrustAnchor, kTrustAnchorMax> anchors{};
  std::uint8_t anchor_count{0};
  std::array<TrustKeyRecord, kTrustKeyMax> keys{};
  std::uint8_t key_count{0};
  std::array<TrustRevocation, kTrustRevocationMax> revocations{};
  std::uint8_t revocation_count{0};
};

// Semantic validation of a candidate image (shared by commit_image,
// recover() and the boot-time slot classifier): nonzero epoch/network,
// counts within caps, flags restricted to defined bits, all enum fields
// in range, unique root_ids and (authority_id, generation) pairs, every
// pubkey on the P-256 curve (uECC_valid_public_key — the same check the
// permit verifier runs), and >=1 ACTIVE anchor so the image can never
// break the manifest signature chain (§4.5.1 rule 5). Pure function of
// the image; the state-dependent floors are enforced by the store.
Status trust_image_validate(const TrustImage& image) noexcept;

// Structural size of an image encoding (used_len incl. CRC), or 0 when the
// counts are out of range. Useful to size buffers before encode.
std::size_t trust_image_encoded_size(const TrustImage& image) noexcept;

// Encode a complete RLT1 record (head + content + CRC) with `seal` in the
// seal field — kTrustSealPending while a write is in flight,
// kTrustSealCommitted for the commit marker. `out.size` is the used_len;
// the buffer is the full 2048-byte slot image (tail beyond size is
// whatever the caller left; stores write only [0, size)).
// Validates the image semantically first — an invalid image is never
// encodable, so no path can persist a store that wedges boot validation.
Status trust_image_encode(const TrustImage& image, std::uint32_t seal,
                          ByteBuffer<kTrustStoreSlotBytes>& out) noexcept;

// Decode and fully validate a committed RLT1 record (magic, format,
// used_len, seal == committed, counts/reserved/enum structure, CRC,
// schema, trust_image_validate). For host-side tooling and tests; the
// slot classifier inside TrustStore does NOT use this (it must classify
// Empty/Pending/Corrupt/Unsupported distinctly).
Status trust_image_decode(ByteView record, TrustImage& out) noexcept;

// The RTM1 signed content — RLT1 bytes [16, used_len-4). Shared with the
// store's own codec so verification, persistence and catch-up share one
// truth (§4.3.3). body_decode is structural only (fields, caps, exact
// length); trust_image_validate() applies the semantic layer.
Status trust_image_body_encode(const TrustImage& image,
                               ByteBuffer<kTrustImageContentMax>& out) noexcept;
Status trust_image_body_decode(ByteView content, TrustImage& out) noexcept;

// SHA-256 over a committed RLT1 record's bytes [0, used_len) — the
// image_fingerprint the TrustStatus reply exports (§4.3.4). Diagnostics
// carry only the fingerprint; never keys, never grant bytes.
Status trust_image_fingerprint(ByteView record, Digest256& out) noexcept;

// Raw two-slot persistence for the trust store. read() fills the whole
// kTrustStoreSlotBytes slot view (a missing blob reads uniformly erased —
// the NvsTrustStore convention); write() lands a record of <=2048 bytes.
// Implementations must tolerate power loss at any byte boundary and must
// never erase or reformat storage on error.
class TrustStoreStorage {
 public:
  virtual ~TrustStoreStorage() = default;
  virtual Status read(std::uint8_t slot, MutableByteView target) noexcept = 0;
  virtual Status write(std::uint8_t slot, ByteView data) noexcept = 0;
};

// The dual-slot trust store state machine. Not thread-safe — the Owner
// serializes calls.
//
// Boot classification per slot: Empty / Pending (discardable) / Corrupt /
// Unsupported (intact, other schema) / Valid. Adoption rules mirror the
// config journal: two valid slots -> the higher epoch wins, equal epochs
// must be byte-identical (a recover() twin pair) or the store quarantines;
// one valid + sibling provably absent -> clean adopt; one valid + sibling
// corrupt/unsupported/unreadable -> adopt as a "known value" but mark
// uncertain (commits refused until recover(), since the lost sibling may
// have held a newer image); no valid slot -> corrupt means quarantine,
// unreadable means a retryable StorageFailure, all-empty/pending is a
// fresh store awaiting first (physical) provisioning — NOT quarantine.
class TrustStore {
 public:
  explicit TrustStore(TrustStoreStorage& storage) noexcept;

  Status initialize() noexcept;

  // Bind the RLF1 floor this store's E/G counters reserve from. While
  // attached, commit/recover/install refuse any image below the floor's
  // E/G — the floor is the reservation ledger, this store its mirror.
  // The floor must outlive the store; trust-managed deployments attach.
  void attach_floor(const SecurityFloorStore* floor) noexcept { floor_ = floor; }

  // The single write path for accepted trust images — used by the physical
  // provisioning channel (first install) and by trust_manifest_accept()
  // after a signature verifies and the RLF1 E/G reservation lands.
  // Enforces: store initialized and not quarantined/uncertain; image
  // semantically valid; store_epoch strictly greater than the proven
  // epoch floor (ordinal compare — u32 wrap is a re-provision event,
  // never modular arithmetic); min_authority_generation never below the
  // proven floor; E/G never below the attached security floor. The image
  // lands in BOTH slots (each two-phase with readback) so the next boot
  // sees a verifiable twin pair instead of a new/old split.
  Status commit_image(const TrustImage& image) noexcept;

  // Explicit operator recovery from quarantine or storage-uncertain: the
  // operator attests a complete fresh image whose store_epoch exceeds
  // EVERY epoch any committed (or committed-but-CRC-damaged) record proved
  // this boot — so a pre-loss image can never replay. The same image lands
  // in both slots so the next boot sees a verifiable twin pair. Never
  // invoked implicitly; storage errors never trigger erase or reformat.
  Status recover(const TrustImage& image) noexcept;

  // Install a floor-reserved image: the trust_manifest_accept() path for
  // re-delivering the exact RTM1 original the floor already binds
  // (same bytes hash + E/G) after the commit was interrupted or the
  // slots were lost. Unlike recover() this is available on any store
  // state — the floor reservation (made only after a verified accept)
  // is the authorization — but the epoch/floor rules still apply, so a
  // stale or foreign image can never install.
  Status install_reserved(const TrustImage& image) noexcept;

  bool initialized() const noexcept { return initialized_; }
  bool has_active() const noexcept { return has_active_; }
  bool quarantined() const noexcept { return quarantined_; }
  // Adopted image is a "known value" only — the sibling slot's loss is
  // unproven, so commits refuse until recover(). Consumers decide whether
  // the possibly-stale image still serves (mirrors the journal's rule:
  // state readable, intake refused).
  bool uncertain() const noexcept { return uncertain_; }

  // Accessors over the committed image — all zero/empty when !has_active_.
  const TrustImage& image() const noexcept { return image_; }
  std::uint32_t store_epoch() const noexcept {
    return has_active_ ? image_.store_epoch : 0;
  }
  std::uint32_t min_authority_generation() const noexcept {
    return has_active_ ? image_.min_authority_generation : 0;
  }
  NetworkId network() const noexcept { return has_active_ ? image_.network : 0; }
  std::uint64_t deployment_id() const noexcept {
    return has_active_ ? image_.deployment_id : 0;
  }
  std::uint8_t flags() const noexcept { return has_active_ ? image_.flags : 0; }

  // Anchor lookup by manifest kid (root_id); nullptr when absent.
  const TrustAnchor* find_anchor(std::uint64_t root_id) const noexcept;
  // Exact (authority_id, generation) key lookup — the resolution primitive
  // the §4.6.2 TrustView composes with min_authority_generation() and a
  // status==Active check. Staged/retired/revoked records ARE returned; the
  // caller enforces the status policy (a staged or retired key verifies
  // nothing).
  const TrustKeyRecord* find_key(std::uint64_t authority_id,
                                 std::uint32_t generation) const noexcept;
  // Revocation check on the credential fingerprint (kind DeviceCredential).
  bool is_credential_revoked(const Digest256& kid_fingerprint) const noexcept;

  // Highest epochs/floors proven by ANY committed-seal record this boot —
  // including CRC-failed ones (committed fields still bound how far the
  // store advanced; the authority ledger's recovery_floor_ rule).
  std::uint32_t epoch_floor() const noexcept { return epoch_floor_; }
  std::uint32_t generation_floor() const noexcept { return generation_floor_; }
  // SHA-256 over the committed image bytes; zero digest when !has_active_.
  const Digest256& image_fingerprint() const noexcept { return fingerprint_; }

 private:
  enum class SlotContent : std::uint8_t {
    Empty,
    Pending,
    Corrupt,
    Unsupported,
    Valid,
  };

  Status decode_slot(std::uint8_t slot, TrustImage& image,
                     std::size_t& used_len, SlotContent& content,
                     bool& committed_fields) noexcept;
  Status store_image(std::uint8_t slot, const TrustImage& image,
                     Digest256* fingerprint) noexcept;
  // The attached floor's E/G must not exceed the candidate's — the
  // store never commits below its reservation ledger.
  Status check_floor(const TrustImage& image) const noexcept;

  TrustStoreStorage& storage_;
  const SecurityFloorStore* floor_{nullptr};
  TrustImage image_{};
  Digest256 fingerprint_{};
  // Per-slot committed-image digests, computed at decode so adoption never
  // needs to re-read storage.
  std::array<Digest256, kTrustStoreSlots> slot_fingerprint_{};
  std::array<TrustImage, kTrustStoreSlots> parsed_{};
  std::array<std::uint8_t, kTrustStoreSlotBytes> scratch_a_{};
  std::array<std::uint8_t, kTrustStoreSlotBytes> scratch_b_{};
  std::uint32_t epoch_floor_{0};
  std::uint32_t generation_floor_{0};
  std::array<StatusCode, kTrustStoreSlots> slot_reserved_{};
  std::uint8_t active_slot_{0};
  bool has_active_{false};
  bool initialized_{false};
  bool quarantined_{false};
  bool uncertain_{false};
};

}  // namespace routeloom
