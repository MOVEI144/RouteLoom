#pragma once

// RTC slow-memory binding for the retained session image (G-SEC P4 §9.3).
// The firmware owns one RtcSessionBacking in RTC slow memory
// (RTC_DATA_ATTR — the only RAM that survives deep sleep) and binds the
// portable BufferRtcSessionPort over it for the sleep save, the wake
// consume and the retained-TX write-ahead. The backing holds no validity
// claim of its own: only a deep-sleep wake with the sleep marker, a
// trusted elapsed interval and a fully verifying record may consume it
// (consume_rtc_session enforces all of that). No IDF includes here, so
// host tests bind the same struct from plain RAM.

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/sdkv1_session_rtc.hpp"
#include "routeloom/types.hpp"

namespace routeloom::espnow {

struct RtcSessionBacking {
  std::array<std::uint8_t, sdkv1::kRtcSessionRecordSize> bytes{};
};
static_assert(sizeof(RtcSessionBacking) == sdkv1::kRtcSessionRecordSize,
              "RTC session backing is exactly one record");

// Binds the portable port over firmware-owned RTC backing. The backing
// must outlive the port; both are single-threaded on the pump task.
inline sdkv1::BufferRtcSessionPort bind_rtc_session_port(
    RtcSessionBacking& backing) noexcept {
  return sdkv1::BufferRtcSessionPort(
      MutableByteView{backing.bytes.data(), backing.bytes.size()});
}

}  // namespace routeloom::espnow
