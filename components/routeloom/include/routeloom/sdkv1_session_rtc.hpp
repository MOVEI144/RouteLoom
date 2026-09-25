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
  std::array<RtcSessionContext, 2> contexts{};
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
