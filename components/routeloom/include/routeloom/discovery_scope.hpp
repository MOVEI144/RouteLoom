#pragma once

// Discovery Scope Key layer (docs/design/scope-gateway-config/
// 02-discovery-scope.md and 05-wire-api.md §5.2). A filter in front of the
// existing RLD1 exchange: it suppresses wrong-scope and replayed DISCOVERs
// before they can consume candidate/transient/auth slots. It is NOT identity,
// admission or membership proof — a scope match never issues an
// AuthenticatedPeerProof and never grants membership.
//
// The raw 32-byte scope key is opaque to this layer and to everything above
// it: config, diagnostics and these interfaces carry only a ScopeRef handle
// plus u32 generations. Portable code only — the production PSA adapter is a
// later component and dev/test providers live in tests (marked EXPERIMENTAL).

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/endpoint_wire.hpp"
#include "routeloom/fixed_containers.hpp"
#include "routeloom/security.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom {

// --- Bounds (contracts.json scope.*) -----------------------------------------
constexpr std::size_t kScopeKeyBytes = 32;
constexpr std::size_t kScopeTagBytes = 16;
constexpr std::size_t kScopeKeyGenerations = 2;
constexpr std::uint32_t kScopePreviousOverlapMaxMs = 1800000;
constexpr std::uint64_t kScopeLegacyMigrationMaxMs = 86400000;
constexpr std::uint32_t kScopeRawRatePerSecond = 32;
constexpr std::uint32_t kScopeRawBurst = 16;
constexpr std::size_t kScopeMacsPerPoll = 2;
constexpr std::size_t kScopeDedupCapacity = 32;
constexpr std::uint32_t kScopeDedupTtlMs = 8000;
constexpr std::size_t kScopePendingCapacity = 8;
// contracts.json scope.key_bytes/tag_bytes/hint domain are re-pinned by
// endpoint_wire.hpp; MAC-input scratch stays under the 256B budget (01 §1.5).

using ScopeTag = std::array<std::uint8_t, kScopeTagBytes>;
using ScopeDigest = std::array<std::uint8_t, 32>;

// Opaque provider-owned handle to a scope key set. NEVER raw key material;
// safe to hold in config and pass across API/log/diagnostic boundaries.
struct ScopeRef {
  std::uint64_t handle{0};

  friend constexpr bool operator==(const ScopeRef a, const ScopeRef b) noexcept {
    return a.handle == b.handle;
  }
  friend constexpr bool operator!=(const ScopeRef a, const ScopeRef b) noexcept {
    return !(a == b);
  }
};
constexpr ScopeRef kInvalidScopeRef{0};
// The member-discovery scope handle (G-SEC P5): the Owner's GK-backed
// scope provider serves this handle, and the member discovery is
// configured with it. Distinct from any legacy/dev scope handle the
// firmware configures for other providers.
constexpr ScopeRef kMemberScopeRef{1};

// §2.2 mode registry. Off/OpenLegacy are explicit non-scoped configurations;
// nothing may silently move a Required deployment into them on key loss.
enum class ScopeMode : std::uint8_t {
  Off = 0,                // existing non-scoped behavior, explicit config
  OpenLegacy = 1,         // explicit opt-in body-empty / v1 advertisement
  OptionalMigration = 2,  // scoped first, bounded legacy fallback
  Required = 3,           // v2 + valid scope tag only; silent drops otherwise
};

constexpr bool scope_mode_scoped(const ScopeMode mode) noexcept {
  return mode == ScopeMode::OptionalMigration || mode == ScopeMode::Required;
}

// --- Portable SHA-256 / HMAC-SHA-256 ------------------------------------------
// FIPS 180-4 / RFC 2104. No heap, no globals — safe for the Owner task.
// Pinned by the standard vectors in tests (RFC 4231).

class Sha256 {
 public:
  Sha256() noexcept { reset(); }
  void reset() noexcept;
  void update(ByteView data) noexcept;
  void finish(ScopeDigest& out) noexcept;

 private:
  void block(const std::uint8_t* data) noexcept;

  std::uint32_t state_[8]{};
  std::array<std::uint8_t, 64> buffer_{};
  std::size_t buffered_{0};
  std::uint64_t total_bytes_{0};
};

void sha256(ByteView input, ScopeDigest& out) noexcept;
void hmac_sha256(ByteView key, ByteView input, ScopeDigest& out) noexcept;
// Multi-part variant: MACs part_a||part_b||part_c without a staging buffer
// (callers on 8 KiB task stacks cannot afford a kConfigPermitObjectMax local).
void hmac_sha256(ByteView key, ByteView part_a, ByteView part_b, ByteView part_c,
                 ScopeDigest& out) noexcept;
// Fixed-time whole-buffer compare; different lengths never equal.
bool constant_time_equal(ByteView a, ByteView b) noexcept;

// --- Provider boundary ---------------------------------------------------------
//
// The provider owns scope key material and key-generation state. The engine
// assembles the canonical MAC inputs (endpoint_wire.hpp) and never sees a
// key. Generation semantics (02 §2.6): u32 monotonic, never 0, never wrap;
// a demoted previous generation is acceptable for at most
// kScopePreviousOverlapMaxMs measured from demotion — never extended.
class DiscoveryScopeProvider {
 public:
  virtual ~DiscoveryScopeProvider() = default;

  // EXPERIMENTAL unless the qualified production adapter lands (01 §1.4).
  virtual SecurityProfile security_profile() const noexcept {
    return SecurityProfile::Development;
  }

  // Current generation used for new transmissions. False = current key
  // unavailable: callers must stop new discovery, never downgrade to Open.
  virtual bool current_generation(ScopeRef scope, std::uint32_t& out) noexcept = 0;

  // True while `generation` may still authenticate inbound traffic: current
  // always, previous only inside its overlap window. Generation 0 and
  // unknown/wrapped generations are never accepted.
  virtual bool accepted_generation(ScopeRef scope, std::uint32_t generation,
                                   MonotonicMs now_ms) noexcept = 0;

  // HMAC-SHA-256 left 128 bits over `input` under `generation`'s key.
  // Implementations must fail for generations they would not accept and must
  // never expose key material through the out parameter on failure.
  virtual Status scope_tag(ScopeRef scope, std::uint32_t generation,
                           ByteView input, ScopeTag& out) noexcept = 0;
};

// Constant-time tag check: compute under `generation` and compare.
Status scope_tag_verify(DiscoveryScopeProvider& provider, ScopeRef scope,
                        std::uint32_t generation, ByteView input,
                        const ScopeTag& expected) noexcept;

// first4(HMAC(K, domain_hint || class u8 || Network u64 || generation u32))
// as a BE u32 (02 §2.4). A cheap filter only — never cryptographic evidence.
Status scope_hint(DiscoveryScopeProvider& provider, ScopeRef scope,
                  std::uint32_t generation, endpoint::ScopeClass scope_class,
                  NetworkId network, std::uint32_t& out) noexcept;

// scope_binding = SHA256(domain_binding || class || generation || scheme ||
// scoped || discover_digest32 || offer_digest32) (02 §2.4, 05 §5.2). A
// legacy exchange passes scoped=false: class/generation/scheme/scoped are
// then encoded as 0 while both digests stay the real exchanged-frame values.
ScopeDigest scope_binding_digest(bool scoped, endpoint::ScopeClass scope_class,
                                 std::uint32_t generation,
                                 const ScopeDigest& discover_digest,
                                 const ScopeDigest& offer_digest) noexcept;

// What one exchange contributes to AuthTranscript::scope_binding. Both ends
// derive identical digests from the exact frames they exchanged, so the
// binding is symmetric without transmitting anything extra.
struct ScopeExchangeContext {
  bool scoped{false};
  endpoint::ScopeClass scope_class{endpoint::ScopeClass::Member};
  std::uint32_t generation{0};
  ScopeDigest discover_digest{};
  ScopeDigest offer_digest{};

  ScopeDigest binding() const noexcept {
    return scope_binding_digest(scoped, scope_class, generation,
                                discover_digest, offer_digest);
  }
};

// --- Generation window (02 §2.6) ----------------------------------------------
// Providers embed this to get the contract semantics for free: at most two
// generations (current + previous), strictly increasing u32, no wrap, no 0.
class ScopeKeyRing {
 public:
  // First generation for a fresh scope. Fails if a current already exists.
  Status install(std::uint32_t generation, MonotonicMs now_ms) noexcept;
  // Demote current -> previous (accepted kScopePreviousOverlapMaxMs from
  // `now_ms`) and promote `next_generation`, which must be strictly greater
  // than current. Monotonicity also forbids u32 wrap.
  Status rotate(std::uint32_t next_generation, MonotonicMs now_ms) noexcept;
  bool current(std::uint32_t& out) const noexcept;
  std::uint32_t previous() const noexcept { return previous_; }
  // current always; previous only while now < previous_until_ms.
  bool accepted(std::uint32_t generation, MonotonicMs now_ms) const noexcept;
  // Restart with unprovable elapsed overlap: keep current, drop previous.
  void drop_previous() noexcept {
    previous_ = 0;
    previous_until_ms_ = 0;
  }

 private:
  std::uint32_t current_{0};
  std::uint32_t previous_{0};
  MonotonicMs previous_until_ms_{0};
};

// --- Raw ingress budget (02 §2.5) ---------------------------------------------
// Token bucket: kScopeRawRatePerSecond refills, kScopeRawBurst burst. Bounds
// bootstrap-lane CPU/airtime consumption independent of in-scope resources.
class ScopeRawBudget {
 public:
  bool consume(MonotonicMs now_ms) noexcept {
    if (now_ms > last_ms_) {
      const std::uint64_t refill =
          ((now_ms - last_ms_) * kScopeRawRatePerSecond) / 1000;
      if (refill > 0) {
        const std::uint64_t tokens = tokens_ + refill;
        tokens_ = tokens > kScopeRawBurst ? kScopeRawBurst
                                          : static_cast<std::uint32_t>(tokens);
        last_ms_ = now_ms;
      }
    }
    if (tokens_ == 0) return false;
    --tokens_;
    return true;
  }

 private:
  std::uint32_t tokens_{kScopeRawBurst};
  MonotonicMs last_ms_{0};
};

// --- Replay dedup (02 §2.5) -----------------------------------------------------
// Key: (source MAC, txn nonce, class, generation); legacy entries use
// class/generation 0. TTL is 8s from FIRST sight — a re-receive refreshes
// nothing. Records are retained past TTL purely as replay tombstones: an
// exact-key match always answers Duplicate/Conflict (a post-TTL replay is
// a replay, never fresh density). Same key + different content is Conflict.
// Victim order when the table is full: expired records first (legacy before
// verified); a MAC-verified scoped record may additionally evict the oldest
// LIVE legacy record. Verified records are never evicted by unauthenticated
// traffic, and a live verified record is never evicted at all.
enum class ScopeDedupResult : std::uint8_t {
  New = 0,
  Duplicate,
  Conflict,
  Full,
};

class ScopeDedupTable {
 public:
  ScopeDedupResult check(const MacAddress& source,
                         const std::array<std::uint8_t, 16>& nonce,
                         std::uint8_t scope_class, std::uint32_t generation,
                         const std::array<std::uint8_t, 16>& content,
                         MonotonicMs now_ms) noexcept;
  std::size_t size() const noexcept { return records_.size(); }

 private:
  struct Record {
    MacAddress source{};
    std::array<std::uint8_t, 16> nonce{};
    std::array<std::uint8_t, 16> content{};
    std::uint32_t generation{0};
    std::uint8_t scope_class{0};
    MonotonicMs first_seen_ms{0};
  };
  FixedPool<Record, kScopeDedupCapacity> records_{};
};

// --- Diagnostics (02 §2.7) -----------------------------------------------------
// Aggregate counters only — never keys, tags or per-source detail.
struct ScopeStats {
  std::uint32_t raw_rx{0};              // every RLD1 Discover/Offer seen
  std::uint32_t hint_mismatch{0};       // hint matches no accepted candidate
  std::uint32_t mac_rejected{0};        // tag verify failed / required tag absent
  std::uint32_t unknown_generation{0};  // generation not current/previous-in-window
  std::uint32_t duplicate{0};           // dedup same key, same content
  std::uint32_t scope_accepted{0};      // verified scoped frames admitted
  std::uint32_t legacy_used{0};         // legacy-path admissions
  std::uint32_t candidate_full{0};      // admitted discover found no slot
  std::uint32_t key_unavailable{0};     // scope required but unusable
  std::uint32_t budget_dropped{0};      // raw budget or verify queue overflow
  std::uint32_t dedup_conflict{0};      // dedup same key, different content
  std::uint32_t dedup_full{0};          // dedup table full of protected records
};

}  // namespace routeloom
