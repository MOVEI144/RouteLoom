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

#include "routeloom/key_schedule.hpp"
#include "routeloom/rlres1.hpp"
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
