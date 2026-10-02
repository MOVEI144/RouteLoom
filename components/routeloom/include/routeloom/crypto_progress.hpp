#pragma once

#include <cassert>

#include "routeloom/crypto_worker.hpp"

namespace routeloom {

// Owner-side loan tracking. Cancellation invalidates adoption immediately;
// drain still has to return the borrowed context before its storage is reused.
class CryptoProgress final {
 public:
  CryptoProgress() noexcept = default;
  CryptoProgress(const CryptoProgress&) = delete;
  CryptoProgress& operator=(const CryptoProgress&) = delete;
  ~CryptoProgress() { assert(!pending_); }
  Status bind(CryptoWorker* worker) noexcept {
    if (pending_) return Status::error(StatusCode::Busy, "crypto loan active");
    worker_ = worker;
    return Status::success();
  }
  Status start(void* context, CryptoWorker::Run run) noexcept {
    if (context == nullptr || run == nullptr) {
      return Status::error(StatusCode::InvalidArgument, "crypto job identity");
    }
    if (pending_) return Status::error(StatusCode::Busy, "crypto loan active");
    if (generation_ == UINT64_MAX) {
      return Status::error(StatusCode::CounterExhausted, "crypto generation exhausted");
    }
    const CryptoWorker::Ticket ticket{context, generation_ + 1};
    if (worker_ == nullptr) return run(context);
    const Status admitted = worker_->submit(ticket, run);
    if (!admitted) return admitted;
    ticket_ = ticket;
    ++generation_;
    pending_ = true;
    cancelled_ = false;
    return Status::error(StatusCode::WouldBlock, "crypto computing");
  }
  Status poll(Status& result) noexcept {
    if (!pending_) return Status::error(StatusCode::NotFound, "crypto no loan");
    const Status returned = worker_->take(ticket_, result);
    if (!returned) return returned;
    pending_ = false;
    ticket_ = CryptoWorker::Ticket{};
    if (cancelled_) result = Status::error(StatusCode::Expired, "crypto result cancelled");
    return Status::success();
  }
  void cancel() noexcept {
    if (pending_) cancelled_ = true;
  }
  void clear_cancelled() noexcept {
    assert(!pending_);
    cancelled_ = false;
  }
  bool pending() const noexcept { return pending_; }
  bool cancelled() const noexcept { return cancelled_; }
  bool ready() const noexcept { return pending_ && worker_->ready(); }
  bool asynchronous() const noexcept { return worker_ != nullptr; }

 private:
  CryptoWorker* worker_{nullptr};
  CryptoWorker::Ticket ticket_{};
  std::uint64_t generation_{0};
  bool pending_{false};
  bool cancelled_{false};
};

}  // namespace routeloom
