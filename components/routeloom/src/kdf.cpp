#include "routeloom/kdf.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>

#include "routeloom/secure_clear.hpp"

namespace routeloom {

void hkdf_sha256_extract(const ByteView salt, const ByteView ikm,
                         ScopeDigest& prk) noexcept {
  hmac_sha256(salt, ikm, prk);
}

Status hkdf_sha256_expand(const ByteView prk, const ByteView info,
                          const MutableByteView out) noexcept {
  if (out.data == nullptr || out.size == 0 || out.size > kHkdfSha256OutputMax) {
    return Status::error(StatusCode::InvalidArgument, "hkdf output length");
  }
  std::memset(out.data, 0, out.size);
  if (prk.data == nullptr || prk.size < kHkdfSha256HashSize) {
    return Status::error(StatusCode::InvalidArgument, "hkdf prk shorter than HashLen");
  }
  if (info.size != 0 && info.data == nullptr) {
    return Status::error(StatusCode::InvalidArgument, "hkdf info");
  }

  ScopeDigest block{};
  std::size_t previous_size = 0;  // T(0) is the empty string
  std::size_t written = 0;
  std::uint8_t counter = 1;
  while (written < out.size) {
    const std::uint8_t counter_byte = counter;
    hmac_sha256(prk, ByteView{block.data(), previous_size}, info,
                ByteView{&counter_byte, 1}, block);
    previous_size = block.size();
    const std::size_t take = std::min(block.size(), out.size - written);
    std::memcpy(out.data + written, block.data(), take);
    written += take;
    ++counter;  // at most 255 blocks: out.size <= 255 * HashLen
  }
  secure_clear(block);
  return Status::success();
}

Status hkdf_sha256(const ByteView salt, const ByteView ikm, const ByteView info,
                   const MutableByteView out) noexcept {
  ScopeDigest prk{};
  hkdf_sha256_extract(salt, ikm, prk);
  const Status status = hkdf_sha256_expand(ByteView{prk.data(), prk.size()}, info, out);
  secure_clear(prk);
  return status;
}

}  // namespace routeloom
