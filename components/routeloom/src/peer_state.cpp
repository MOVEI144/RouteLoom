#include "routeloom/peer_state.hpp"

#include <array>

namespace routeloom {
namespace {

// Dead records erased per enumeration pass. The inventory must not be
// modified while it is being enumerated, so each pass collects at most this
// many slots, commits the witness covering them, erases them and rescans.
constexpr std::size_t kSweepBatch = 16;
// Every pass either erases at least one record or ends the sweep; the cap
// only guards against an inventory whose erase() reports success without
// removing anything.
constexpr std::uint32_t kMaxSweepPasses = 4096;

class SweepCollector final : public SlotVisitor {
 public:
  SweepCollector(CounterInventory& inner, const std::uint32_t tx_epoch) noexcept
      : inner_(inner), tx_epoch_(tx_epoch) {}

  bool visit(const std::uint32_t slot) noexcept override {
    CounterRecord record{};
    bool found = false;
    const Status load_status = inner_.load(slot, record, found);
    if (load_status.code == StatusCode::IntegrityError) {
      // Unreadable (e.g. wrong blob size): its epoch is unknown, keep it.
      ++unreadable;
      return true;
    }
    if (!load_status) {
      status = load_status;
      return false;
    }
    if (!found) return true;
    if (!counter_record_intact(record)) {
      // A corrupt record's epoch cannot be trusted, so it is never swept:
      // it keeps wedging its slot (IntegrityError), the fail-closed outcome.
      ++unreadable;
      return true;
    }
    if (record.key_epoch < tx_epoch_) {
      if (batch_size < batch.size()) {
        batch[batch_size++] = slot;
        if (record.key_epoch > batch_max_epoch) batch_max_epoch = record.key_epoch;
      } else {
        more = true;
      }
      return true;
    }
    if (record.key_epoch == tx_epoch_) {
      ++current;
    } else {
      ++future;
    }
    return true;
  }

  std::array<std::uint32_t, kSweepBatch> batch{};
  std::size_t batch_size{0};
  std::uint32_t batch_max_epoch{0};
  bool more{false};
  std::uint32_t current{0};
  std::uint32_t future{0};
  std::uint32_t unreadable{0};
  Status status{};

 private:
  CounterInventory& inner_;
  std::uint32_t tx_epoch_{0};
};

class SlotCounter final : public SlotVisitor {
 public:
  bool visit(std::uint32_t) noexcept override {
    ++count;
    return true;
  }
  std::uint32_t count{0};
};

}  // namespace

// --- BoundedCounterStore -----------------------------------------------------

Status BoundedCounterStore::open(CounterInventory& inner,
                                 const std::uint32_t max_records,
                                 const std::uint32_t tx_epoch) noexcept {
  close();
  if (tx_epoch == 0) {
    // 0 is the "unset" epoch sentinel; a sweep below it would be a no-op and
    // the node would not know which epochs are dead.
    return Status::error(StatusCode::InvalidArgument, "TX epoch unset");
  }
  std::uint32_t witness = 0;
  bool witness_found = false;
  const Status witness_status = inner.load_witness(witness, witness_found);
  if (!witness_status) {
    // Without the witness the node cannot tell which epochs were swept:
    // every commit could land on an erased key. Fail closed.
    return witness_status;
  }
  if (witness_found && tx_epoch <= witness) {
    // The boot session went backwards (e.g. the system NVS was erased while
    // the security partition was kept): records at or below the witness may
    // be gone, so this epoch's keys may already have issued counters.
    ++witness_rejects_;
    return Status::error(StatusCode::Conflict, kTxEpochWitnessDetail);
  }
  inner_ = &inner;
  max_records_ = max_records;
  tx_epoch_ = tx_epoch;
  witness_ = witness;
  witness_found_ = witness_found;
  sweep_status_ = sweep();
  return Status::success();
}

void BoundedCounterStore::close() noexcept {
  inner_ = nullptr;
  max_records_ = 0;
  tx_epoch_ = 0;
  witness_ = 0;
  witness_found_ = false;
  records_ = 0;
  records_known_ = false;
  report_ = CounterSweepReport{};
  sweep_status_ = Status::success();
  // Reject counters are lifetime diagnostics; they survive close/re-open.
}

Status BoundedCounterStore::sweep() noexcept {
  records_known_ = false;
  for (std::uint32_t pass = 0; pass < kMaxSweepPasses; ++pass) {
    report_.passes = pass + 1U;
    SweepCollector collector(*inner_, tx_epoch_);
    const Status enumerate_status = inner_->for_each_slot(collector);
    if (!enumerate_status) return enumerate_status;
    if (!collector.status) return collector.status;

    if (collector.batch_size != 0) {
      // C1 ordering: the witness covering every record of this batch is
      // durable BEFORE the first erase, so no power cut can leave an erased
      // record whose epoch a later commit would still accept.
      if (!witness_found_ || collector.batch_max_epoch > witness_) {
        const Status witness_status =
            inner_->commit_witness(collector.batch_max_epoch);
        if (!witness_status) return witness_status;
        witness_ = collector.batch_max_epoch;
        witness_found_ = true;
      }
      for (std::size_t index = 0; index < collector.batch_size; ++index) {
        const Status erase_status = inner_->erase(collector.batch[index]);
        if (!erase_status) return erase_status;
        ++report_.erased;
      }
    }
    if (collector.batch_size == 0 || !collector.more) {
      // This enumeration saw every record: the kept ones are the census.
      report_.retained_current = collector.current;
      report_.retained_future = collector.future;
      report_.retained_unreadable = collector.unreadable;
      records_ = collector.current + collector.future + collector.unreadable;
      records_known_ = true;
      return Status::success();
    }
  }
  return Status::error(StatusCode::InternalError, "counter sweep did not converge");
}

Status BoundedCounterStore::load(const std::uint32_t slot, CounterRecord& record,
                                 bool& found) noexcept {
  found = false;
  if (inner_ == nullptr) {
    return Status::error(StatusCode::InvalidState, "counter store not open");
  }
  return inner_->load(slot, record, found);
}

Status BoundedCounterStore::commit(const std::uint32_t slot,
                                   const CounterRecord& record) noexcept {
  if (inner_ == nullptr) {
    return Status::error(StatusCode::InvalidState, "counter store not open");
  }
  if (witness_found_ && record.key_epoch <= witness_) {
    // Every lease reserves (commits) before it issues a counter, so this
    // single gate keeps any key whose records were swept from ever being
    // used again.
    ++witness_rejects_;
    return Status::error(StatusCode::Conflict, kTxEpochWitnessDetail);
  }
  CounterRecord existing{};
  bool found = false;
  Status status = inner_->load(slot, existing, found);
  if (!status) return status;
  if (found) return inner_->commit(slot, record);

  if (!records_known_ || records_ >= max_records_) {
    ++capacity_rejects_;
    return Status::error(StatusCode::NoCapacity, kPeerStateCapacityDetail);
  }
  status = inner_->commit(slot, record);
  if (status) {
    ++records_;
    return status;
  }
  // A failed commit may still have landed (e.g. the store wrote the value
  // but reported an error afterwards). Count it if it is there so the cap
  // is never undercounted.
  bool landed = false;
  if (inner_->load(slot, existing, landed) && landed) ++records_;
  return status;
}

// --- BoundedReplayStore ------------------------------------------------------

Status BoundedReplayStore::open(ReplayInventory& inner,
                                const std::uint32_t max_peers) noexcept {
  close();
  inner_ = &inner;
  max_peers_ = max_peers;
  SlotCounter counter;
  count_status_ = inner.for_each_floor_slot(counter);
  peers_known_ = count_status_.ok();
  peers_ = peers_known_ ? counter.count : 0U;
  return Status::success();
}

void BoundedReplayStore::close() noexcept {
  inner_ = nullptr;
  max_peers_ = 0;
  peers_ = 0;
  peers_known_ = false;
  count_status_ = Status::success();
}

Status BoundedReplayStore::load_window(const std::uint32_t slot,
                                       ReplayWindowRecord& record,
                                       bool& found) noexcept {
  found = false;
  if (inner_ == nullptr) {
    return Status::error(StatusCode::InvalidState, "replay store not open");
  }
  return inner_->load_window(slot, record, found);
}

Status BoundedReplayStore::load_floor(const std::uint32_t slot,
                                      ReplayFloorRecord& record,
                                      bool& found) noexcept {
  found = false;
  if (inner_ == nullptr) {
    return Status::error(StatusCode::InvalidState, "replay store not open");
  }
  return inner_->load_floor(slot, record, found);
}

Status BoundedReplayStore::commit_window(
    const std::uint32_t slot, const ReplayWindowRecord& record) noexcept {
  if (inner_ == nullptr) {
    return Status::error(StatusCode::InvalidState, "replay store not open");
  }
  // ReplayGuard ratchets the floor before any window commit and re-checks it
  // on every accept, so a window never legitimately exists without its
  // pair's floor. Refusing one keeps windows inside the floor cap.
  ReplayFloorRecord floor{};
  bool floor_found = false;
  const Status status = inner_->load_floor(slot, floor, floor_found);
  if (!status) return status;
  if (!floor_found) {
    return Status::error(StatusCode::IntegrityError,
                         "replay window without floor");
  }
  return inner_->commit_window(slot, record);
}

Status BoundedReplayStore::commit_floor(
    const std::uint32_t slot, const ReplayFloorRecord& record) noexcept {
  if (inner_ == nullptr) {
    return Status::error(StatusCode::InvalidState, "replay store not open");
  }
  ReplayFloorRecord existing{};
  bool found = false;
  Status status = inner_->load_floor(slot, existing, found);
  if (!status) return status;
  if (found) return inner_->commit_floor(slot, record);

  // A new peer pair. Its floor can never be deleted again (C2), so the cap
  // is the only bound on RX state: refuse beyond it, never evict.
  if (!peers_known_ || peers_ >= max_peers_) {
    ++capacity_rejects_;
    return Status::error(StatusCode::NoCapacity, kPeerStateCapacityDetail);
  }
  status = inner_->commit_floor(slot, record);
  if (status) {
    ++peers_;
    return status;
  }
  bool landed = false;
  if (inner_->load_floor(slot, existing, landed) && landed) ++peers_;
  return status;
}

}  // namespace routeloom
