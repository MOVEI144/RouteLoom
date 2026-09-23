#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace routeloom {

// Zeroization the compiler may not elide: stores through a volatile pointer
// are observable side effects, so unlike std::fill/std::memset on a dead
// local buffer they cannot be optimized out. Use for key material and other
// secrets whose residence must end at a known point.
inline void secure_clear(void* data, std::size_t size) noexcept {
  auto* bytes = static_cast<volatile std::uint8_t*>(data);
  for (std::size_t i = 0; i < size; ++i) {
    bytes[i] = 0;
  }
}

template <std::size_t N>
inline void secure_clear(std::array<std::uint8_t, N>& data) noexcept {
  secure_clear(data.data(), N);
}

}  // namespace routeloom
