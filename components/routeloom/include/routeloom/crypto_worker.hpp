#pragma once

#include <atomic>
#include <cstdint>

#include "routeloom/status.hpp"

namespace routeloom {

// One Owner submits and takes results; one worker executes. The job borrows
// its context until take() succeeds, including after cancellation. Only the
// Owner may adopt results or write stores. Callbacks must not enter the Owner.
class CryptoWorker final {
 public:
  using Run = Status (*)(void* context) noexcept;
  using Wake = void (*)(void* context) noexcept;
  struct Ticket {
    void* context{nullptr};
    std::uint64_t generation{0};
  };

  CryptoWorker() noexcept = default;
  CryptoWorker(const CryptoWorker&) = delete;
  CryptoWorker& operator=(const CryptoWorker&) = delete;

  // Bind before either thread starts. Wake only posts a notification.
  void bind(Wake work, void* work_context, Wake completion, void* completion_context) noexcept {
    work_wake_ = work;
    work_context_ = work_context;
    completion_wake_ = completion;
    completion_context_ = completion_context;
  }

  Status submit(Ticket ticket, Run run) noexcept {
    if (ticket.context == nullptr || ticket.generation == 0 || run == nullptr) {
      return Status::error(StatusCode::InvalidArgument, "crypto job identity");
    }
    if (state_.load(std::memory_order_acquire) != State::Idle) {
      return Status::error(StatusCode::Busy, "crypto mailbox full");
    }
    ticket_ = ticket;
    run_ = run;
    state_.store(State::Queued, std::memory_order_release);
    if (work_wake_ != nullptr) work_wake_(work_context_);
    return Status::success();
  }

  // Bounded drain: at most one job, never a loop over newly submitted work.
  bool execute() noexcept {
    State expected = State::Queued;
    if (!state_.compare_exchange_strong(expected, State::Running, std::memory_order_acquire))
      return false;
    result_ = run_(ticket_.context);
    state_.store(State::Ready, std::memory_order_release);
    if (completion_wake_ != nullptr) completion_wake_(completion_context_);
    return true;
  }

  Status take(Ticket expected, Status& result) noexcept {
    if (state_.load(std::memory_order_acquire) != State::Ready) {
      return Status::error(StatusCode::WouldBlock, "crypto result pending");
    }
    if (expected.context != ticket_.context || expected.generation != ticket_.generation) {
      return Status::error(StatusCode::Conflict, "crypto result identity");
    }
    result = result_;
    result_ = Status::success();
    ticket_ = Ticket{};
    run_ = nullptr;
    state_.store(State::Idle, std::memory_order_release);
    return Status::success();
  }

  bool idle() const noexcept { return state_.load(std::memory_order_acquire) == State::Idle; }
  bool ready() const noexcept { return state_.load(std::memory_order_acquire) == State::Ready; }

 private:
  enum class State : std::uint8_t { Idle, Queued, Running, Ready };
  std::atomic<State> state_{State::Idle};
  Ticket ticket_{};
  Run run_{nullptr};
  Status result_{};
  Wake work_wake_{nullptr};
  void* work_context_{nullptr};
  Wake completion_wake_{nullptr};
  void* completion_context_{nullptr};
};

}  // namespace routeloom
