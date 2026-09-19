#pragma once

#include <cstdint>

#include "routeloom/types.hpp"

namespace routeloom {

// CRC-32/ISO-HDLC: reflected polynomial 0xEDB88320, init 0xFFFFFFFF,
// reflected input/output, xorout 0xFFFFFFFF. Byte-identical to
// host/routeloom-protocol crc32_iso_hdlc so host and firmware agree.
// Integrity only; it is not an authentication or anti-rollback proof.
std::uint32_t crc32_iso_hdlc(ByteView data) noexcept;

}  // namespace routeloom
