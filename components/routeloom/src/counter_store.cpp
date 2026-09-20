#include "routeloom/counter_store.hpp"

#include <cstddef>
#include <limits>

#include "routeloom/crc32.hpp"

namespace routeloom {

namespace {

std::uint32_t counter_record_crc(const CounterRecord& record) noexcept {
  return crc32_iso_hdlc(
      ByteView{reinterpret_cast<const std::uint8_t*>(&record),
               offsetof(CounterRecord, crc)});
}

}  // namespace

CounterLease::CounterLease(CounterStore& store, const std::uint32_t slot,
                           const std::uint32_t context_id, const std::uint16_t key_epoch,
                           const std::uint8_t direction, const std::uint32_t block_size) noexcept
    : store_(store), slot_(slot), context_id_(context_id), key_epoch_(key_epoch),
      direction_(direction), block_size_(block_size) {}

Status CounterLease::initialize() noexcept {
  if (block_size_ == 0) {
    return Status::error(StatusCode::InvalidArgument, "counter block size is zero");
  }
  CounterRecord record{};
  bool found = false;
  auto status = store_.load(slot_, record, found);
  if (!status) return status;
  if (found) {
    if (record.crc != counter_record_crc(record)) {
      return Status::error(StatusCode::IntegrityError,
                           "counter record integrity check failed");
    }
    if (record.context_id != context_id_ || record.key_epoch != key_epoch_ ||
        record.direction != direction_) {
      return Status::error(StatusCode::Conflict, "counter store context mismatch");
    }
    cursor_ = record.high_water_exclusive;
    end_ = record.high_water_exclusive;
    generation_ = record.generation;
  }
  initialized_ = true;
  return Status::success();
}

Status CounterLease::reserve_block() noexcept {
  if (!initialized_) {
    return Status::error(StatusCode::InvalidState, "counter lease is not initialized");
  }
  if (end_ > std::numeric_limits<std::uint64_t>::max() - block_size_) {
    return Status::error(StatusCode::CounterExhausted, "counter range exhausted");
  }
  CounterRecord next{};
  next.context_id = context_id_;
  next.key_epoch = key_epoch_;
  next.direction = direction_;
  next.high_water_exclusive = end_ + block_size_;
  next.generation = generation_ + 1;
  next.crc = counter_record_crc(next);
  const auto status = store_.commit(slot_, next);
  if (!status) return status;
  cursor_ = end_;
  end_ = next.high_water_exclusive;
  generation_ = next.generation;
  return Status::success();
}

Status CounterLease::next(std::uint64_t& value) noexcept {
  if (!initialized_) {
    return Status::error(StatusCode::InvalidState, "counter lease is not initialized");
  }
  if (cursor_ == end_) {
    const auto status = reserve_block();
    if (!status) return status;
  }
  value = cursor_++;
  return Status::success();
}

}  // namespace routeloom
