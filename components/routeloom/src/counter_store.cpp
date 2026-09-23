#include "routeloom/counter_store.hpp"

#include <cstddef>

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
                           const std::uint32_t context_id, const std::uint32_t key_epoch,
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
    if (record.layout != kCounterRecordLayout) {
      return Status::error(StatusCode::IntegrityError,
                           "counter record layout is not Wire v2");
    }
    if (record.context_id != context_id_ || record.direction != direction_) {
      return Status::error(StatusCode::Conflict, "counter store context mismatch");
    }
    if (record.key_epoch > key_epoch_) {
      // A newer persisted epoch belongs to a context we must not rewind.
      return Status::error(StatusCode::Conflict, "counter store epoch regression");
    }
    if (record.key_epoch == key_epoch_) {
      cursor_ = record.high_water_exclusive;
      end_ = record.high_water_exclusive;
    }
    // Older persisted epoch: the same slot is re-keyed for the new epoch —
    // counters restart because the nonce space is epoch-scoped. The record
    // generation stays monotonic across the re-key.
    generation_ = record.generation;
  }
  initialized_ = true;
  return Status::success();
}

Status CounterLease::resume(const CounterLeaseCheckpoint& checkpoint) noexcept {
  const auto status = initialize();
  if (!status) return status;
  // initialize() leaves cursor_ == end_ == the persisted high-water and
  // generation_ == the persisted generation for a same-epoch record (end_
  // stays 0 otherwise). A match proves the checkpoint's block is still the
  // newest reservation: any other lease would have committed a new block,
  // and so a new generation, before issuing a single counter from it.
  if (same_lease_identity(this->checkpoint(), checkpoint) &&
      checkpoint.cursor < checkpoint.end &&
      end_ != 0 && end_ == checkpoint.end &&
      generation_ == checkpoint.generation) {
    cursor_ = checkpoint.cursor;
  }
  return Status::success();
}

CounterLeaseCheckpoint CounterLease::checkpoint() const noexcept {
  CounterLeaseCheckpoint result{};
  result.slot = slot_;
  result.context_id = context_id_;
  result.key_epoch = key_epoch_;
  result.direction = direction_;
  result.cursor = cursor_;
  result.end = end_;
  result.generation = generation_;
  return result;
}

Status CounterLease::reserve_block() noexcept {
  if (!initialized_) {
    return Status::error(StatusCode::InvalidState, "counter lease is not initialized");
  }
  // The slot is shared per peer pair and this lease may be cached across an
  // epoch advance: re-validate the persisted record before overwriting it.
  // A newer persisted epoch owns the slot now — committing our stale block
  // would rewind the newer context's counter space into nonce reuse.
  {
    CounterRecord persisted{};
    bool found = false;
    const auto load_status = store_.load(slot_, persisted, found);
    if (!load_status) return load_status;
    if (found) {
      if (persisted.crc != counter_record_crc(persisted)) {
        return Status::error(StatusCode::IntegrityError,
                             "counter record integrity check failed");
      }
      if (persisted.layout != kCounterRecordLayout) {
        return Status::error(StatusCode::IntegrityError,
                             "counter record layout is not Wire v2");
      }
      if (persisted.key_epoch > key_epoch_) {
        return Status::error(StatusCode::Conflict,
                             "counter slot superseded by newer epoch");
      }
      if (persisted.key_epoch == key_epoch_ &&
          persisted.high_water_exclusive > end_) {
        // Another lease for this same context reserved ahead — adopt the
        // newer water mark forward, never rewind it.
        cursor_ = persisted.high_water_exclusive;
        end_ = persisted.high_water_exclusive;
        generation_ = persisted.generation;
      } else if (persisted.key_epoch == key_epoch_ &&
                 persisted.high_water_exclusive < end_) {
        return Status::error(StatusCode::IntegrityError,
                             "counter record rewound");
      }
    }
  }
  // Exhaustion is checked AFTER adopting the persisted mark: the adopted
  // water mark may sit closer to the limit than the cached end_ did. Issued
  // values must stay <= kMaxCryptoCounter (u48 on the wire); past it the
  // context needs a new epoch — never a wrap under the same key.
  // block_size_ is u32, so kMaxCryptoCounter + 1 - block_size_ cannot wrap.
  if (end_ > kMaxCryptoCounter + 1 - block_size_) {
    return Status::error(StatusCode::CounterExhausted, "counter range exhausted");
  }
  CounterRecord next{};
  next.context_id = context_id_;
  next.key_epoch = key_epoch_;
  next.direction = direction_;
  next.layout = kCounterRecordLayout;
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
