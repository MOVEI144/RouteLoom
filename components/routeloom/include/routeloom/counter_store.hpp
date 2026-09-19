#pragma once

#include <cstdint>

#include "routeloom/status.hpp"

namespace routeloom {

struct CounterRecord {
  std::uint32_t context_id{0};
  std::uint16_t key_epoch{0};
  std::uint8_t direction{0};
  std::uint8_t reserved{0};
  std::uint64_t high_water_exclusive{0};
  std::uint32_t generation{0};
  // crc32_iso_hdlc over the preceding bytes. A corrupted high-water must
  // never be adopted silently: rewinding the counter would reuse AES-GCM
  // nonces under the same key.
  std::uint32_t crc{0};
};

class CounterStore {
 public:
  virtual ~CounterStore() = default;
  virtual Status load(std::uint32_t slot, CounterRecord& record, bool& found) noexcept = 0;
  virtual Status commit(std::uint32_t slot, const CounterRecord& record) noexcept = 0;
};

class CounterLease {
 public:
  CounterLease(CounterStore& store, std::uint32_t slot, std::uint32_t context_id,
               std::uint16_t key_epoch, std::uint8_t direction,
               std::uint32_t block_size = 256) noexcept;

  Status initialize() noexcept;
  Status next(std::uint64_t& value) noexcept;
  bool initialized() const noexcept { return initialized_; }

 private:
  Status reserve_block() noexcept;

  CounterStore& store_;
  std::uint32_t slot_{0};
  std::uint32_t context_id_{0};
  std::uint16_t key_epoch_{0};
  std::uint8_t direction_{0};
  std::uint32_t block_size_{256};
  std::uint64_t cursor_{0};
  std::uint64_t end_{0};
  std::uint32_t generation_{0};
  bool initialized_{false};
};

}  // namespace routeloom
