#pragma once

// Test fixtures for the autonomous-mesh contract tests:
//   - FakeRadioPort: a scripted RadioPort with recorded calls, controlled
//     delay/loss and a single-radio channel-visit model (a radio visiting a
//     survey channel cannot receive on its home channel — the model D5 tests
//     build on; it does not claim to reproduce real CCA or capture effects).
//   - ScriptedEntropy: a deterministic entropy source for nonce/fuzz inputs.

#include <cstdint>
#include <deque>
#include <utility>
#include <vector>

#include "routeloom/node.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom_test {

class FakeRadioPort final : public routeloom::RadioPort {
 public:
  struct SentFrame {
    routeloom::NodeId peer{routeloom::kInvalidNodeId};
    std::uint64_t token{0};
    std::vector<std::uint8_t> bytes;
  };

  routeloom::Status send(routeloom::NodeId peer, std::uint64_t token,
                         routeloom::ByteView frame) noexcept override {
    sent.push_back(SentFrame{peer, token,
                             std::vector<std::uint8_t>(frame.data, frame.data + frame.size)});
    if (!send_statuses_.empty()) {
      const routeloom::Status scripted = send_statuses_.front();
      send_statuses_.pop_front();
      return scripted;  // driver-level rejection: no completion is ever delivered
    }
    if (drops_ > 0) {
      --drops_;
      return routeloom::Status::success();  // accepted, lost in flight: result never arrives
    }
    pending_.push_back(PendingResult{token, next_success_, next_delay_ms_});
    next_success_ = true;
    next_delay_ms_ = default_delay_ms_;
    return routeloom::Status::success();
  }

  routeloom::Status recover() noexcept override {
    ++recover_calls;
    if (!recover_statuses_.empty()) {
      const routeloom::Status scripted = recover_statuses_.front();
      recover_statuses_.pop_front();
      return scripted;
    }
    return routeloom::Status::success();
  }

  // The next send() returns `status` instead of being accepted.
  void script_send_status(routeloom::Status status) { send_statuses_.push_back(status); }
  // The next accepted send reports `success` after `delay_ms`.
  void script_tx_result(bool success, routeloom::MonotonicMs delay_ms) {
    next_success_ = success;
    next_delay_ms_ = delay_ms;
  }
  // The next `count` sends are accepted but never produce a TX result.
  void drop_tx_results(int count) { drops_ = count; }
  void script_recover(routeloom::Status status) { recover_statuses_.push_back(status); }

  // --- single-radio model ---
  void set_home_channel(std::uint8_t channel) { home_channel_ = channel; }
  // Move the radio to `channel` until `until_ms`. While visiting, inject_rx
  // on any other channel is dropped — the radio physically cannot hear home.
  void visit_channel(std::uint8_t channel, routeloom::MonotonicMs until_ms) {
    visit_channel_ = channel;
    visit_until_ms_ = until_ms;
  }
  void return_home() { visit_channel_ = 0; }
  std::uint8_t current_channel(routeloom::MonotonicMs now_ms) const {
    if (visit_channel_ != 0 && now_ms < visit_until_ms_) return visit_channel_;
    return home_channel_;
  }
  bool on_channel(std::uint8_t channel, routeloom::MonotonicMs now_ms) const {
    return current_channel(now_ms) == channel;
  }

  // Deliver due TX results to `node`. Returns how many fired this call.
  std::size_t pump(routeloom::MonotonicMs now_ms, routeloom::MeshNode& node) {
    std::size_t fired = 0;
    while (!pending_.empty() && pending_.front().due_ms <= now_ms) {
      const PendingResult result = pending_.front();
      pending_.pop_front();
      node.on_radio_tx_result(result.token, result.success, now_ms);
      ++fired;
    }
    return fired;
  }

  // Inject an inbound frame on `channel`. Returns false (and counts a miss)
  // when the radio is parked on a different channel.
  bool inject_rx(std::uint8_t channel, routeloom::NodeId from, routeloom::ByteView frame,
                 const routeloom::RadioRxMetadata& metadata, routeloom::MonotonicMs now_ms,
                 routeloom::MeshNode& node) {
    if (!on_channel(channel, now_ms)) {
      ++missed_rx;
      return false;
    }
    node.on_radio_receive(from, frame, metadata, now_ms);
    return true;
  }

  std::vector<SentFrame> sent;
  std::size_t missed_rx{0};
  std::size_t recover_calls{0};

 private:
  struct PendingResult {
    std::uint64_t token{0};
    bool success{true};
    routeloom::MonotonicMs due_ms{0};
  };

  std::deque<PendingResult> pending_;
  std::deque<routeloom::Status> send_statuses_;
  std::deque<routeloom::Status> recover_statuses_;
  int drops_{0};
  bool next_success_{true};
  routeloom::MonotonicMs next_delay_ms_{1};
  routeloom::MonotonicMs default_delay_ms_{1};
  std::uint8_t home_channel_{1};
  std::uint8_t visit_channel_{0};
  routeloom::MonotonicMs visit_until_ms_{0};
};

// Deterministic entropy for tests (splitmix64). Can be scripted to fail so
// callers exercise the no-entropy path without a real RNG.
class ScriptedEntropy {
 public:
  explicit ScriptedEntropy(std::uint64_t seed = 0x726f7574656c6f6fULL) : state_(seed) {}

  std::uint64_t next_u64() noexcept {
    state_ += 0x9e3779b97f4a7c15ULL;
    std::uint64_t z = state_;
    z = (z ^ (z >> 30U)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27U)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31U);
  }

  routeloom::Status fill(routeloom::MutableByteView out) noexcept {
    if (failures_ > 0) {
      --failures_;
      return routeloom::Status::error(routeloom::StatusCode::InternalError,
                                    "scripted entropy failure");
    }
    std::size_t offset = 0;
    while (offset < out.size) {
      const std::uint64_t value = next_u64();
      for (int i = 0; i < 8 && offset < out.size; ++i) {
        out.data[offset++] = static_cast<std::uint8_t>(value >> (i * 8));
      }
    }
    return routeloom::Status::success();
  }

  void fail_next(int count) { failures_ = count; }

 private:
  std::uint64_t state_;
  int failures_{0};
};

}  // namespace routeloom_test
