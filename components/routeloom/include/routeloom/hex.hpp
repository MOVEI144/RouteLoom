#pragma once

// Small hex helper shared by every image class: the D03 readback
// contract renders digests as text in boot/console logs, and field
// builds have no console — the serial boot lines are the evidence
// channel. Kept in the base routeloom component so fixture and field
// builds can both reach it without pulling in espnow headers.

#include <cstddef>
#include <cstdint>

namespace routeloom {

inline void hex_encode(const std::uint8_t* data, std::size_t size, char* out) noexcept {
  static constexpr char kHex[] = "0123456789abcdef";
  for (std::size_t i = 0; i < size; ++i) {
    out[i * 2] = kHex[data[i] >> 4];
    out[i * 2 + 1] = kHex[data[i] & 0xf];
  }
  out[size * 2] = '\0';
}

}  // namespace routeloom
