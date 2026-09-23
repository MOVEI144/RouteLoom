#pragma once

#include <cstddef>
#include <cstdint>

#include "routeloom/fixed_containers.hpp"
#include "routeloom/security.hpp"
#include "routeloom/status.hpp"

namespace routeloom {

struct CounterRecord {
  std::uint32_t context_id{0};
  std::uint32_t key_epoch{0};
  std::uint8_t direction{0};
  std::uint8_t layout{0};  // kCounterRecordLayout; a v1 (u16 epoch) record is refused
  std::uint8_t reserved[6]{};
  std::uint64_t high_water_exclusive{0};
  std::uint32_t generation{0};
  // crc32_iso_hdlc over the preceding bytes. A corrupted high-water must
  // never be adopted silently: rewinding the counter would reuse AES-GCM
  // nonces under the same key.
  std::uint32_t crc{0};
};
// Wire v2 record (32-bit key epoch). Stores refuse records of any other
// layout: a v1 record cannot be widened safely by guesswork, and the
// counter space must never be re-derived from an unverified image.
constexpr std::uint8_t kCounterRecordLayout = 2;
static_assert(sizeof(CounterRecord) == 32, "counter record layout");

class CounterStore {
 public:
  virtual ~CounterStore() = default;
  virtual Status load(std::uint32_t slot, CounterRecord& record, bool& found) noexcept = 0;
  virtual Status commit(std::uint32_t slot, const CounterRecord& record) noexcept = 0;
};

// RAM-only resume point of a lease that is dropped from a bounded cache
// while its durably reserved block still has unissued counters (issue #57).
// Without it, re-creating the evicted context would forfeit the remainder
// and commit a fresh block on its first next() — up to one flash commit per
// TX frame when more contexts are active than the cache holds.
// A checkpoint never survives a reboot and is single-use (see
// CounterCheckpointCache::take).
struct CounterLeaseCheckpoint {
  // Lease identity: resume() ignores a checkpoint cut from another lease.
  std::uint32_t slot{0};
  std::uint32_t context_id{0};
  std::uint32_t key_epoch{0};
  std::uint8_t direction{0};
  // Unissued remainder [cursor, end) of the block reserved as `generation`.
  std::uint64_t cursor{0};
  std::uint64_t end{0};
  std::uint32_t generation{0};
};

inline bool same_lease_identity(const CounterLeaseCheckpoint& left,
                                const CounterLeaseCheckpoint& right) noexcept {
  return left.slot == right.slot && left.context_id == right.context_id &&
         left.key_epoch == right.key_epoch && left.direction == right.direction;
}

class CounterLease {
 public:
  CounterLease(CounterStore& store, std::uint32_t slot, std::uint32_t context_id,
               std::uint32_t key_epoch, std::uint8_t direction,
               std::uint32_t block_size = 256) noexcept;

  Status initialize() noexcept;
  // initialize(), then continue inside the checkpoint's block instead of
  // reserving a new one — but only while the persisted record is still
  // exactly the reservation the checkpoint was cut from (same identity,
  // high-water and generation). Every other lease reserves (and so bumps
  // the generation) before issuing anything, so an unchanged generation
  // proves nothing in [cursor, end) was issued since the checkpoint.
  // Otherwise it behaves exactly as initialize(). The caller must not
  // resume the same checkpoint twice.
  Status resume(const CounterLeaseCheckpoint& checkpoint) noexcept;
  Status next(std::uint64_t& value) noexcept;
  bool initialized() const noexcept { return initialized_; }

  // Identity plus the unissued remainder. Cut it only from a lease that is
  // being dropped: a lease that keeps issuing after the cut would reuse the
  // same counters if the checkpoint were later resumed.
  CounterLeaseCheckpoint checkpoint() const noexcept;

 private:
  Status reserve_block() noexcept;

  CounterStore& store_;
  std::uint32_t slot_{0};
  std::uint32_t context_id_{0};
  std::uint32_t key_epoch_{0};
  std::uint8_t direction_{0};
  std::uint32_t block_size_{256};
  std::uint64_t cursor_{0};
  std::uint64_t end_{0};
  std::uint32_t generation_{0};
  bool initialized_{false};
};

// Bounded RAM cache of checkpoints of evicted leases. take() removes the
// entry, so a checkpoint is resumed at most once; when full, park() drops
// the oldest checkpoint, which only forfeits that block's remainder (the
// designed crash-recovery behaviour — counters never rewind).
template <std::size_t Capacity>
class CounterCheckpointCache {
 public:
  void park(const CounterLeaseCheckpoint& checkpoint) noexcept {
    if (checkpoint.cursor >= checkpoint.end) return;  // nothing to resume
    Entry* entry = entries_.find([&](const Entry& value) {
      return same_lease_identity(value.checkpoint, checkpoint);
    });
    if (entry == nullptr) entry = entries_.allocate();
    if (entry == nullptr) {
      Entry* oldest = nullptr;
      entries_.for_each([&](Entry& value) {
        if (oldest == nullptr || value.stamp < oldest->stamp) oldest = &value;
      });
      if (oldest == nullptr || !entries_.release(oldest)) return;
      entry = entries_.allocate();
      if (entry == nullptr) return;
    }
    entry->checkpoint = checkpoint;
    entry->stamp = ++stamp_;
  }

  // Removes and returns the checkpoint whose lease identity (slot,
  // context_id, key_epoch, direction) matches `identity`.
  bool take(const CounterLeaseCheckpoint& identity,
            CounterLeaseCheckpoint& out) noexcept {
    Entry* entry = entries_.find([&](const Entry& value) {
      return same_lease_identity(value.checkpoint, identity);
    });
    if (entry == nullptr) return false;
    out = entry->checkpoint;
    entries_.release(entry);
    return true;
  }

  void clear() noexcept { entries_.clear(); }
  std::size_t size() const noexcept { return entries_.size(); }

 private:
  struct Entry {
    CounterLeaseCheckpoint checkpoint{};
    std::uint64_t stamp{0};
  };

  FixedPool<Entry, Capacity> entries_{};
  std::uint64_t stamp_{0};
};

}  // namespace routeloom
