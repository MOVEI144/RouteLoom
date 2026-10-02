#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace routeloom::espnow {

struct HilRxAllowList {
  std::array<std::array<std::uint8_t, 6>, 8> macs{};
  std::uint8_t count{0};
  bool valid{true};

  constexpr bool allows(const std::uint8_t* source) const noexcept {
    if (!valid) return false;
    if (count == 0) return true;
    for (std::size_t i = 0; i < count; ++i) {
      bool matches = true;
      for (std::size_t j = 0; j < 6; ++j) {
        if (macs[i][j] != source[j]) matches = false;
      }
      if (matches) return true;
    }
    return false;
  }
};

constexpr int hil_mac_hex(const char value) noexcept {
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return value - 'a' + 10;
  if (value >= 'A' && value <= 'F') return value - 'A' + 10;
  return -1;
}

// Strict comma-separated EUI-48 list; an empty setting disables filtering.
constexpr HilRxAllowList parse_hil_rx_allow_list(const char* text) noexcept {
  HilRxAllowList result{};
  while (*text != '\0') {
    if (result.count == result.macs.size()) {
      result.valid = false;
      return result;
    }
    for (std::size_t i = 0; i < 6; ++i) {
      const int upper = hil_mac_hex(*text);
      if (upper < 0) {
        result.valid = false;
        return result;
      }
      ++text;
      const int lower = hil_mac_hex(*text);
      if (lower < 0) {
        result.valid = false;
        return result;
      }
      ++text;
      result.macs[result.count][i] = static_cast<std::uint8_t>((upper << 4) | lower);
      if (i < 5) {
        if (*text != ':') {
          result.valid = false;
          return result;
        }
        ++text;
      }
    }
    ++result.count;
    if (*text == '\0') break;
    if (*text != ',' || *++text == '\0') {
      result.valid = false;
      return result;
    }
  }
  return result;
}

}  // namespace routeloom::espnow
