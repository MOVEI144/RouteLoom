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

Status encode_rtc_session(const RtcSessionImage& image, MutableByteView out) noexcept;
// On failure does not expose a partially decoded image or any key bytes.
Status decode_rtc_session(ByteView bytes, const RtcWakeCheck& wake,
                          RtcSessionImage& out) noexcept;

}  // namespace routeloom::sdkv1
