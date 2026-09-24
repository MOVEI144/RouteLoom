#pragma once

// Test fixtures for the autonomous-mesh contract tests:
//   - FakeRadioPort: a scripted RadioPort with recorded calls, controlled
//     delay/loss and a single-radio channel-visit model (a radio visiting a
//     survey channel cannot receive on its home channel — the model D5 tests
//     build on; it does not claim to reproduce real CCA or capture effects).
//   - OwnerPump: the firmware owner-task model — driver callbacks post
//     events (or stage a completion on the queue-full path), the task
//     waits through the shared owner wait routine
//     (routeloom/owner_pump.hpp — staged work skips the wait, otherwise
//     the event or the poll tick wakes it), drains staged-then-queued
//     events, then polls.
//   - ScriptedEntropy: a deterministic entropy source for nonce/fuzz inputs.

#include <cstdint>
#include <deque>
#include <utility>
#include <vector>

#include "routeloom/node.hpp"
#include "routeloom/owner_pump.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom_test {

class FakeRadioPort final : public routeloom::RadioPort {
 public:
  struct SentFrame {
    routeloom::NodeId peer{routeloom::kInvalidNodeId};
    std::uint64_t token{0};
    std::vector<std::uint8_t> bytes;
    // Submission stamp — the host-side equivalent of the driver's
    // submitted_us: this fake's clock at the moment send() ran.
    routeloom::MonotonicMs at_ms{0};
  };

  routeloom::Status send(routeloom::NodeId peer, std::uint64_t token,
                         routeloom::ByteView frame) noexcept override {
    sent.push_back(SentFrame{peer, token,
                             std::vector<std::uint8_t>(frame.data, frame.data + frame.size),
                             now_ms});
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
  // The fake driver's clock — tests advance it like the runtime's
  // monotonic source so SentFrame.at_ms records submission times.
  routeloom::MonotonicMs now_ms{0};

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

// Owner-task pump model — mirrors EspNowRuntime::task_entry. Driver
// callbacks only POST events (or stage a completion when the queue is
// full); the owner task waits through the shared owner wait routine
// (routeloom/owner_pump.hpp — staged work skips the wait, otherwise the
// earlier of the next queued event and the periodic tick wakes it),
// drains the staged slot and the whole queue through the node handlers,
// then polls — the ordering poll_once uses, so control replies raised by
// inbound frames keep their lane over queued DATA (issue #60-3).
class OwnerPump {
 public:
  struct Event {
    enum class Kind : std::uint8_t { TxResult, Rx };
    Kind kind{Kind::TxResult};
    routeloom::MonotonicMs posted_ms{0};
    std::uint64_t token{0};
    bool success{false};
    routeloom::NodeId peer{routeloom::kInvalidNodeId};
    std::int8_t rssi_dbm{-60};
    std::vector<std::uint8_t> frame;
  };

  // Driver-callback side: stage the event exactly like
  // EspNowRuntime::enqueue_tx / receive_callback — never touches the node.
  void post_tx_result(std::uint64_t token, bool success,
                      routeloom::MonotonicMs posted_ms) {
    Event event{};
    event.kind = Event::Kind::TxResult;
    event.posted_ms = posted_ms;
    event.token = token;
    event.success = success;
    events_.push_back(std::move(event));
  }
  void post_rx(routeloom::NodeId peer, std::vector<std::uint8_t> frame,
               std::int8_t rssi_dbm, routeloom::MonotonicMs posted_ms) {
    Event event{};
    event.kind = Event::Kind::Rx;
    event.posted_ms = posted_ms;
    event.peer = peer;
    event.rssi_dbm = rssi_dbm;
    event.frame = std::move(frame);
    events_.push_back(std::move(event));
  }
  // Queue-full path twin: firmware's TX callback stages a completion into
  // lost_node_tx_ when the driver queue is full — AFTER the pass's entry
  // check — while the queue itself drains empty. run_once drains the slot
  // first (firmware order) and the wait must skip through the shared gate.
  void post_staged_tx_result(std::uint64_t token, bool success,
                             routeloom::MonotonicMs posted_ms) {
    staged_.kind = Event::Kind::TxResult;
    staged_.posted_ms = posted_ms;
    staged_.token = token;
    staged_.success = success;
    staged_valid_ = true;
  }
  std::size_t pending() const {
    return events_.size() + (staged_valid_ ? 1 : 0);
  }

  // Fake driver queue: the xQueuePeek model for the shared owner wait
  // — a wait releases at the first posted event when one lands inside
  // the timeout, otherwise at the timeout. Only the blocking primitive
  // is modeled here; the wait procedure itself (staged skips, else the
  // bounded event wait) is the shared routine in owner_pump.hpp.
  struct FakeEventQueue {
    const std::deque<Event>& events;
    routeloom::MonotonicMs now_ms;
    void wait_until_posted(const routeloom::MonotonicMs timeout_ms) noexcept {
      const routeloom::MonotonicMs deadline = now_ms + timeout_ms;
      const routeloom::MonotonicMs next =
          events.empty() ? UINT64_MAX : events.front().posted_ms;
      now_ms = next <= deadline ? next : deadline;
    }
  };

  // Task side: going idle at `idle_since_ms`, run the SAME shared wait
  // firmware's wait_for_event runs (owner_pump.hpp) against the fake
  // driver queue — staged work returns NOW, otherwise the wait releases
  // at the earlier of the next posted event and the periodic tick. No
  // local copy of the rule: a fixed-delay regression in the shared wait
  // wakes here at the tick and fails the issue #60-3 assertions.
  routeloom::MonotonicMs wake_at(routeloom::MonotonicMs idle_since_ms) const {
    FakeEventQueue queue{events_, idle_since_ms};
    routeloom::owner_wait_for_event(queue, routeloom::kOwnerPollPeriodMs,
                                    staged_valid_);
    return queue.now_ms;
  }

  // One owner pass at `now_ms`: drain the staged slot first (firmware
  // order — the reserved completion resolves the node's outstanding job),
  // then every event the driver posted up to now (a real queue only holds
  // what already arrived), then poll — all completions and RX before the
  // next dispatch.
  void run_once(routeloom::MonotonicMs now_ms, routeloom::MeshNode& node) {
    if (staged_valid_) {
      staged_valid_ = false;
      node.on_radio_tx_result(staged_.token, staged_.success, now_ms);
    }
    while (!events_.empty() && events_.front().posted_ms <= now_ms) {
      const Event event = std::move(events_.front());
      events_.pop_front();
      if (event.kind == Event::Kind::TxResult) {
        node.on_radio_tx_result(event.token, event.success, now_ms);
      } else {
        node.on_radio_receive(
            event.peer,
            routeloom::ByteView{event.frame.data(), event.frame.size()},
            routeloom::RadioRxMetadata{event.rssi_dbm}, now_ms);
      }
    }
    node.poll(now_ms);
  }

 private:
  std::deque<Event> events_;
  Event staged_{};
  bool staged_valid_{false};
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
