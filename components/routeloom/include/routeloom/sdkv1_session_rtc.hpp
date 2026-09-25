#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/security.hpp"
#include "routeloom/session_bank.hpp"
#include "routeloom/status.hpp"

namespace routeloom::sdkv1 {

// An integrity-checked snapshot, not an authority to resume by itself.
// The caller must invalidate the physical RTC marker before publishing any
// restored key, and must advance the image before each subsequent radio TX.
constexpr std::size_t kRtcSessionRecordSize = 346;
constexpr std::size_t kRtcSessionMaxContexts = 2;  // index 0 Link, index 1 EndToEnd
struct RtcSessionContext {
  SecurityScope scope{SecurityScope::Link};
  SessionBankEntry entry{};
};
struct RtcSessionImage {
  std::uint32_t source_boot{0};
  NetworkId network{0};
  std::uint32_t local_generation{0};
  std::uint32_t site_commit{0};
  std::uint32_t gk_epoch{0};
  std::uint32_t rs_floor{0};
  std::array<std::uint8_t, 16> kid_digest{};
  std::array<std::uint8_t, 6> parent_mac{};
  std::uint32_t parent_binding{0};
  std::uint8_t count{0};
  std::array<RtcSessionContext, kRtcSessionMaxContexts> contexts{};
};

struct RtcWakeCheck {
  bool deep_sleep{false};
  bool sleep_marker{false};
  // Zero means unknown; a remaining lifetime cannot be trusted then.
  std::uint32_t trusted_elapsed_ms{0};
  std::uint32_t next_boot{0};
  NetworkId network{0};
  std::uint32_t local_generation{0};
  std::uint32_t site_commit{0};
  std::uint32_t gk_epoch{0};
  std::uint32_t rs_floor{0};
  std::array<std::uint8_t, 16> kid_digest{};
};

// Physical RTC adapter: invalidate must make the committed marker unreadable
// before returning, including across reset. Writes must not revive a previous
// valid slot on failure. The caller still gates radio/parent binding separately.
class RtcSessionPort {
 public:
  virtual ~RtcSessionPort() = default;
  virtual Status read(MutableByteView out) noexcept = 0;
  virtual Status invalidate() noexcept = 0;
  virtual Status write(ByteView image) noexcept = 0;
};

// Buffer-backed port: firmware can bind RTC slow memory, host tests a plain
// array. Reads and writes
// are exact-size only — a short buffer is a caller bug and leaves the
// backing untouched. invalidate() wipes the whole backing (marker and any
// retained keys): stale key material must not linger in RTC after the
// image is consumed or superseded.
class BufferRtcSessionPort final : public RtcSessionPort {
 public:
  explicit BufferRtcSessionPort(MutableByteView backing) noexcept : backing_(backing) {}
  Status read(MutableByteView out) noexcept override;
  Status invalidate() noexcept override;
  Status write(ByteView image) noexcept override;

 private:
  MutableByteView backing_{};
};

Status encode_rtc_session(const RtcSessionImage& image, MutableByteView out) noexcept;
// On failure does not expose a partially decoded image or any key bytes.
Status decode_rtc_session(ByteView bytes, const RtcWakeCheck& wake,
                          RtcSessionImage& out) noexcept;
// One-shot wake: the old marker is cleared and checked before any key leaves
// the scratch image. Never hand a decoded image to a callback before this.
Status consume_rtc_session(RtcSessionPort& port, const RtcWakeCheck& wake,
                           RtcSessionImage& out) noexcept;
// Deep-sleep warm gate (P4 §9.3, V1-F07): the consumed image's parent MAC
// must equal the re-observed radio peer and a live post-wake binding must
// exist for the parent. Binding ids are re-minted every boot, so id
// equality is NOT part of this gate — rtc_parent_binding_ok above stays
// the RAM-continuity check for retained wakes.
bool rtc_parent_warm_ok(const RtcSessionImage& image, const MacAddress& observed_parent,
                        bool parent_bound) noexcept;

// Retained TX counter write-ahead (V1-F07): a SecurityProvider that
// delegates everything to the bank provider except next_counter on
// restored contexts, which advance the RTC image BEFORE the counter may
// reach radio. A power cut between radio TX and the next save can then
// never rewind to an issued counter: the retained image always leads the
// bank by exactly the in-flight reservation.
//
// Lockstep: every guarded issue draws the bank counter first, then the
// RTC counter, and the two must agree — a reinstall (live tx id differs
// from the armed one) disarms the slot and delegates fresh bank counters
// instead. A failed RTC update retires the bank entry and refuses: no
// counter may fall back to RAM-only issue after durability is lost. When
// the last slot disarms, the dead image is wiped from the port.
class RtcWriteAheadProvider final : public SecurityProvider {
 public:
  RtcWriteAheadProvider(SecurityProvider& inner, SessionInstaller& installer) noexcept;
  ~RtcWriteAheadProvider() noexcept override;
  RtcWriteAheadProvider(const RtcWriteAheadProvider&) = delete;
  RtcWriteAheadProvider& operator=(const RtcWriteAheadProvider&) = delete;

  // Arms the guard over a consumed image: commits the image to the port
  // (write + readback) and starts write-ahead for its contexts. The port
  // and the image must outlive the armed period: the guard borrows the
  // image (no second retained copy — bridge DRAM has no room for one)
  // and advances it in place on every guarded issue. Refuses InvalidState
  // when already armed, InvalidArgument when the image is not
  // restorable-shaped (leaving the port untouched and borrowing nothing).
  // Never consults the bank: bank/image lockstep is verified on every
  // issue instead. The caller must not touch the image while armed.
  Status arm(RtcSessionPort& port, RtcSessionImage& image) noexcept;
  // Disarms every slot, wipes the borrowed image, and best-effort
  // invalidates the port (a dead image must not linger in RTC or RAM).
  void disarm() noexcept;
  bool armed() const noexcept;

  SecurityProfile security_profile() const noexcept override;
  bool ready() const noexcept override;
  ContextState context_state(SecurityScope scope, NodeId peer) const noexcept override;
  Status tx_epoch(SecurityScope scope, NodeId peer, std::uint32_t& epoch) noexcept override;
  Status current_rx_epoch(SecurityScope scope, NodeId peer,
                          std::uint32_t& epoch) const noexcept override;
  Status tx_group_link_epochs(std::uint32_t& boot, std::uint32_t& g) noexcept override;
  bool accepts_group_epoch(std::uint32_t g) const noexcept override;
  bool group_promotion_pending() const noexcept override {
    return inner_.group_promotion_pending();
  }
  Status next_counter(const SecurityContext& context, std::uint64_t& counter) noexcept override;
  Status seal(const SecurityContext& context, std::uint64_t counter, ByteView aad,
              ByteView plaintext, MutableByteView ciphertext,
              std::array<std::uint8_t, kAeadTagSize>& tag) noexcept override;
  Status open(const SecurityContext& context, std::uint64_t counter, ByteView aad,
              ByteView ciphertext, const std::array<std::uint8_t, kAeadTagSize>& tag,
              MutableByteView plaintext) noexcept override;

 private:
  void disarm_slot(std::size_t index) noexcept;

  SecurityProvider& inner_;
  SessionInstaller& installer_;
  RtcSessionPort* port_{nullptr};
  // Borrowed armed image (see arm): non-null exactly while armed. Points
  // at caller-stable storage — the coordinator's held restore image — and
  // is wiped through on disarm/destruction.
  RtcSessionImage* image_{nullptr};
  bool slot_armed_[kRtcSessionMaxContexts]{false, false};
};

// Retained TX counter write-ahead. The caller must not give the counter to
// radio until the advanced image has been read back. A failed update discards
// the RTC image; no fallback to an earlier key/counter pair is permitted.
Status advance_rtc_tx(RtcSessionPort& port, RtcSessionImage& current,
                      std::size_t context, std::uint64_t& counter) noexcept;
// Warm-send gate: the restored parent MAC must equal the observed radio peer
// and the stored binding the live neighbor binding id. A context alone never
// means "ready to send".
bool rtc_parent_binding_ok(const RtcSessionImage& image, const MacAddress& observed_parent,
                           std::uint32_t live_binding) noexcept;

}  // namespace routeloom::sdkv1
