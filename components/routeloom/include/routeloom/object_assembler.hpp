#pragma once

#include "routeloom/types.hpp"
#include "routeloom/status.hpp"

namespace routeloom {

// Non-owning bounded reassembly. A cell of 1 preserves byte-offset protocols;
// larger cells require a fixed grid, including the exact final-cell length.
// Storage and bitmap belong to the caller and must have disjoint lifetimes
// from other protocol assemblies. Duplicate bytes never extend the deadline.
class ObjectAssembler {
 public:
  Status begin(MutableByteView storage, MutableByteView bitmap, std::uint16_t total,
               std::uint16_t cell, MonotonicMs deadline_ms) noexcept;
  Status insert(std::uint16_t offset, ByteView data, MonotonicMs now_ms) noexcept;
  Status verify(ByteView digest) const noexcept;
  void reset() noexcept;
  bool active() const noexcept { return total_ != 0; }
  bool complete() const noexcept { return active() && received_ == total_; }
  bool expired(MonotonicMs now_ms) const noexcept {
    return active() && deadline_ms_ != 0 && now_ms >= deadline_ms_;
  }
  std::uint16_t received() const noexcept { return received_; }
  std::uint16_t total() const noexcept { return total_; }
  ByteView data() const noexcept { return {storage_.data, total_}; }
  ByteView bitmap() const noexcept { return {bitmap_.data, bitmap_.size}; }

 private:
  MutableByteView storage_{};
  MutableByteView bitmap_{};
  MonotonicMs deadline_ms_{0};
  std::uint16_t total_{0};
  std::uint16_t cell_{0};
  std::uint16_t received_{0};
};

}  // namespace routeloom
