#pragma once

// Dev RAM session policy (G-SEC P4 §10.1/§10.2, V1-N01/V1-K10): the NVS-free
// pair resume lookup, the boot-scoped group sender, and the
// maintenance-domain fingerprints behind the `security legacy-state`
// console verb. Nothing here touches counter/replay stores: the lookup
// takes no store at all, so development churn cannot create c/f/r records
// (#37). A matching lookup only proves "someone with the PSK" — never a
// device identity (auth_kind=DevPsk, generation 0, role from local config).

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/discovery_scope.hpp"
#include "routeloom/group_replay.hpp"
#include "routeloom/key_schedule.hpp"
#include "routeloom/rlres1.hpp"
#include "routeloom/security.hpp"
#include "routeloom/session_bank.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom::sdkv1 {

// Responder-side lookup for one RLRES1 attempt: derives the pair RMS from
// the dev PSK and the claimed peer and checks the R1 rid. Link/End only.
// Mismatch returns NotFound with `out` cleared; malformed input returns
// InvalidArgument, also cleared.
Status dev_find_slot(const keys::Secret& psk, NetworkId network, keys::Purpose purpose,
                     NodeId self, NodeId claimed_peer, const keys::ResumeId& rid,
                     rlres1::Slot& out) noexcept;

// One group sender under a boot-scoped key (P4 §10.1): the key comes from
// keys::dev_group_key, the TX counter lives in RAM only. The durable boot
// must be reserved (boot_hi) BEFORE configure(); configuring the same boot
// twice refuses Conflict — the same key never restarts its counter — and a
// lower boot refuses as well. No heap, no exceptions.
class DevGroupSender {
 public:
  // Use budget shared with the pairwise bank: TX stops at 2^32, never wraps.
  static constexpr std::uint64_t kMaxUseCounter = std::uint64_t{1} << 32;
  static constexpr bool counter_admissible(const std::uint64_t counter) noexcept {
    return counter < kMaxUseCounter;
  }

  DevGroupSender() noexcept = default;
  DevGroupSender(const DevGroupSender&) = delete;
  DevGroupSender& operator=(const DevGroupSender&) = delete;
  ~DevGroupSender() noexcept { clear(); }

  Status configure(const keys::Secret& psk, NetworkId network, NodeId origin,
                   std::uint32_t boot) noexcept;
  bool configured() const noexcept { return configured_; }
  std::uint32_t boot() const noexcept { return boot_; }
  // Next counter the sender would issue (for the provider's issued-check).
  std::uint64_t tx_next() const noexcept { return tx_next_; }
  // Issues the next TX counter, stopping at kMaxUseCounter (CounterExhausted).
  Status next_counter(std::uint64_t& counter) noexcept;
  // Copies the current sender key (InvalidState before configure).
  Status material(keys::TrafficKey& out) const noexcept;
  void clear() noexcept;

 private:
  keys::TrafficKey key_{};
  std::uint64_t tx_next_{0};
  std::uint32_t boot_{0};
  std::uint32_t last_boot_{0};
  bool configured_{false};
};

// Fixed dev group wire epoch (P4 §10.1): dev senders version by boot (the
// key epoch), so the epoch field is always this.
constexpr std::uint32_t kDevGroupEpoch = 1;
// Fixed dev discovery generation (P4 §10.1): the dev scope key is
// boot-independent (pairwise sessions do not version by boot), so the
// discovery scope has exactly one generation, never rotated.
constexpr std::uint32_t kDevScopeGeneration = 1;

// Dev discovery scope provider (P4 §10.1): serves kDevScopeRef for the
// dev discovery (Required) from the PSK-derived scope key
// (keys::dev_scope_key). Tags only filter DISCOVER/OFFER to "same PSK on
// this network" — they prove no identity and gate no traffic. The PSK is
// derived, never stored; the key wipes on wipe()/destruction. No heap,
// no exceptions.
class DevScopeProvider final : public DiscoveryScopeProvider {
 public:
  DevScopeProvider() noexcept = default;
  DevScopeProvider(const DevScopeProvider&) = delete;
  DevScopeProvider& operator=(const DevScopeProvider&) = delete;
  ~DevScopeProvider() noexcept { wipe(); }

  // Derives and holds the scope key. Refuses network 0; a second adopt
  // re-derives (same inputs) or replaces (the Owner adopts once per boot).
  Status adopt(const keys::Secret& psk, NetworkId network) noexcept;
  void wipe() noexcept;
  bool active() const noexcept { return active_; }

  bool current_generation(ScopeRef scope, std::uint32_t& out) noexcept override;
  bool accepted_generation(ScopeRef scope, std::uint32_t generation,
                           MonotonicMs now_ms) noexcept override;
  Status scope_tag(ScopeRef scope, std::uint32_t generation, ByteView input,
                   ScopeTag& out) noexcept override;

 private:
  keys::Secret key_{};
  NetworkId network_{0};
  bool active_{false};
  bool in_call_{false};
};

// Dev group provider (P4 §10.1, V1-N01/V1-K10): SecurityProvider over
// boot-scoped dev group keys. TX draws DevGroupSender counters (RAM,
// stops at 2^32); RX derives per-sender keys and enforces replay per
// (sender, boot) in RAM — no NVS counter/replay state anywhere, the #37
// root fix for the dev profile. Group scope only: pairwise scopes refuse
// (pairwise dev sessions need the coordinator route), as does GroupLink.
// A matching frame only proves "someone with the PSK" — never a device
// identity. No heap, no exceptions.
class DevGroupProvider final : public SecurityProvider {
 public:
  // The PSK is COPIED (wiped in the destructor); the sender and AEAD are
  // borrowed and must outlive the provider.
  DevGroupProvider(DevGroupSender& sender, const keys::Secret& psk, NetworkId network,
                   const AeadGcm& aead, NodeId self) noexcept;
  DevGroupProvider(const DevGroupProvider&) = delete;
  DevGroupProvider& operator=(const DevGroupProvider&) = delete;
  ~DevGroupProvider() noexcept override;

  bool ready() const noexcept override { return sender_.configured(); }
  Status tx_epoch(SecurityScope scope, NodeId peer, std::uint32_t& epoch) noexcept override;
  ContextState context_state(SecurityScope scope, NodeId peer) const noexcept override;
  bool accepts_group_epoch(std::uint32_t g) const noexcept override {
    return g == kDevGroupEpoch;
  }
  Status next_counter(const SecurityContext& c, std::uint64_t& counter) noexcept override;
  Status seal(const SecurityContext& c, std::uint64_t counter, ByteView aad,
              ByteView plaintext, MutableByteView ciphertext,
              std::array<std::uint8_t, kAeadTagSize>& tag) noexcept override;
  Status open(const SecurityContext& c, std::uint64_t counter, ByteView aad,
              ByteView ciphertext, const std::array<std::uint8_t, kAeadTagSize>& tag,
              MutableByteView plaintext) noexcept override;

 private:
  Status material(const SecurityContext& c, keys::TrafficKey& out, bool transmit) noexcept;

  DevGroupSender& sender_;
  keys::Secret psk_{};
  NetworkId network_{0};
  const AeadGcm& aead_;
  NodeId self_{kInvalidNodeId};
  GroupReplayTable replay_{};
  std::array<std::uint8_t, kMaxEspNowBody> staging_{};
  std::uint64_t sealed_{0};
  bool has_sealed_{false};
  std::uint32_t sealed_boot_{0};
  bool in_call_{false};
};

// --- Maintenance-domain fingerprints (P4 §10.2) ------------------------------
// domain = "RouteLoom/v1/maintenance-domain" || 00 || profile_u8 ||
//          network_u64be || self_u64be (integers BE, profile 1=Member/2=DevRam).
// Dev prints first16(HMAC-SHA256(psk, domain)); member prints
// first16(SHA-256(domain || site_id_u64be || sak_kid_32B)). The secret itself
// is never displayed. A NetworkId of 0 refuses: no fingerprint for network 0.
using MaintenanceFingerprint = std::array<std::uint8_t, 16>;
Status dev_maintenance_fingerprint(const keys::Secret& psk, std::uint8_t profile,
                                   NetworkId network, NodeId self,
                                   MaintenanceFingerprint& out) noexcept;
Status member_maintenance_fingerprint(std::uint8_t profile, NetworkId network, NodeId self,
                                      std::uint64_t site_id,
                                      const std::array<std::uint8_t, 32>& sak_kid,
                                      MaintenanceFingerprint& out) noexcept;
// The SAK kid is the SiteCert subject public-key kid, not a hash of the
// certificate envelope. The caller has already validated the adopted site.
Status member_maintenance_fingerprint_for_site_cert(
    std::uint8_t profile, NetworkId network, NodeId self, std::uint64_t site_id,
    ByteView site_cert, MaintenanceFingerprint& out) noexcept;
// Lowercase 32 hex chars plus NUL into `text[33]`.
Status format_fingerprint_hex(const MaintenanceFingerprint& print, char text[33]) noexcept;
// Exactly 32 hex chars (case-insensitive); anything else refuses with `out`
// cleared. Callers compare the parsed bytes exactly.
Status parse_fingerprint_hex(ByteView text, MaintenanceFingerprint& out) noexcept;

}  // namespace routeloom::sdkv1
