#include "routeloom/crc32.hpp"

namespace routeloom {

std::uint32_t crc32_iso_hdlc(const ByteView data) noexcept {
  std::uint32_t crc = 0xFFFFFFFFU;
  for (std::size_t i = 0; i < data.size; ++i) {
    crc ^= data.data[i];
    for (int bit = 0; bit < 8; ++bit) {
      crc = (crc >> 1U) ^ (0xEDB88320U & (0U - (crc & 1U)));
    }
  }
  return ~crc;
}

}  // namespace routeloom
