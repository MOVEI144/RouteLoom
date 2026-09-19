#pragma once

// Shared in-memory two-slot LedgerStorage with byte-granular power-cut
// injection for the authority ledger tests. Writes are counted globally; each
// call either lands fully, lands only a byte prefix then reports failure
// (mid-write cut), or lands nothing and reports failure (power lost between
// write phases).

#include <array>
#include <cstdint>
#include <cstring>
#include <limits>

#include "routeloom/authority.hpp"
#include "routeloom/status.hpp"

namespace routeloom_test {

class FaultyLedgerStorage final : public routeloom::LedgerStorage {
 public:
  routeloom::Status read(const std::uint8_t slot,
                         const routeloom::MutableByteView target) noexcept override {
    if (slot >= routeloom::kAuthorityLedgerSlots || target.data == nullptr ||
        target.size != routeloom::kAuthorityLedgerRecordSize) {
      return routeloom::Status::error(routeloom::StatusCode::InvalidArgument, "bad ledger read");
    }
    if (read_error || slot == read_error_slot) {
      return routeloom::Status::error(routeloom::StatusCode::StorageFailure, "injected read error");
    }
    std::memcpy(target.data, slots_[slot].data(), target.size);
    return routeloom::Status::success();
  }

  routeloom::Status write(const std::uint8_t slot,
                          const routeloom::ByteView data) noexcept override {
    if (slot >= routeloom::kAuthorityLedgerSlots || data.data == nullptr ||
        data.size != routeloom::kAuthorityLedgerRecordSize) {
      return routeloom::Status::error(routeloom::StatusCode::InvalidArgument, "bad ledger write");
    }
    const std::size_t call = write_calls++;
    if (call == cut_call) {
      std::memcpy(slots_[slot].data(), data.data, cut_bytes);
      return routeloom::Status::error(routeloom::StatusCode::StorageFailure, "power cut mid write");
    }
    if (call == drop_call) {
      return routeloom::Status::error(routeloom::StatusCode::StorageFailure,
                                    "power lost before write");
    }
    std::memcpy(slots_[slot].data(), data.data, data.size);
    return routeloom::Status::success();
  }

  std::array<std::uint8_t, routeloom::kAuthorityLedgerRecordSize>& slot_bytes(
      const std::uint8_t slot) noexcept {
    return slots_[slot];
  }
  void corrupt(const std::uint8_t slot, const std::size_t offset) noexcept {
    slots_[slot][offset] ^= 0xFFU;
  }
  void fill(const std::uint8_t slot, const std::uint8_t value) noexcept {
    slots_[slot].fill(value);
  }

  std::size_t write_calls{0};
  std::size_t cut_call{std::numeric_limits<std::size_t>::max()};
  std::size_t cut_bytes{0};
  std::size_t drop_call{std::numeric_limits<std::size_t>::max()};
  bool read_error{false};
  std::uint8_t read_error_slot{0xFF};

 private:
  std::array<std::array<std::uint8_t, routeloom::kAuthorityLedgerRecordSize>,
             routeloom::kAuthorityLedgerSlots>
      slots_{};
};

}  // namespace routeloom_test
