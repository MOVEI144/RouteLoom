#include <condition_variable>
#include <cstdio>
#include <mutex>
#include <thread>

#include "freertos/task.h"
#include "idf_stubs.hpp"
#include "routeloom/espnow_security_owner.hpp"

// The caller boots a real Member Owner and submits a real EDHOC job. The
// worker thread may execute only after Owner reaches its blocking RTOS wait.
// No second security engine or polling thread is substituted for Owner.
int run_owner_crypto_wait_scenario(routeloom::espnow::EspNowSecurityOwner& owner,
                                   routeloom::espnow::EspNowRuntime& runtime,
                                   routeloom::CryptoWorker& worker,
                                   routeloom::MonotonicMs now, bool cancel) {
  using namespace routeloom;
  int failures = 0;
  const auto check = [&](bool ok, const char* detail) {
    if (!ok) {
      std::fprintf(stderr, "crypto wait (%s): %s\n", cancel ? "cancel" : "normal", detail);
      ++failures;
    }
  };
  if (cancel) {
    sdkv1::CoordinatorEvent stop{};
    stop.kind = sdkv1::CoordinatorEventKind::StopForLifecycle;
    stop.now = now;
    check(owner.coordinator().step(stop).code == StatusCode::Busy, "cancel retains loan");
  }
  // Drain any startup notification, then make one normal Owner pass.
  (void)ulTaskNotifyTake(pdTRUE, 0);
  owner.poll(now);
  const auto deadline = owner.next_deadline(now);
  check(deadline > now + 2, "pending crypto has no result-polling deadline");
  check(cancel ? deadline == UINT64_MAX : deadline <= now + sdkv1::HandshakeEngine::kLinkTimeoutMs,
        "real security deadline is retained");
  // Repeated queries must not re-arm a periodic wait while the job is held.
  bool stable_deadline = true;
  for (unsigned i = 0; i < 100; ++i)
    stable_deadline = stable_deadline && owner.next_deadline(now + i) == deadline;
  check(stable_deadline, "unfinished job does not re-arm wake");
  runtime.wait_for_event(1000);
  check(idf_stub::last_peek_ticks() == configTICK_RATE_HZ, "Owner released CPU");

  struct Gate {
    CryptoWorker& worker;
    std::mutex mutex;
    std::condition_variable cv;
    bool released{false};
    std::thread thread;
    unsigned waits{0};
    bool executed{false};
    explicit Gate(CryptoWorker& w) : worker(w), thread([this] {
      std::unique_lock<std::mutex> lock(mutex);
      cv.wait(lock, [this] { return released; });
      lock.unlock();
      executed = worker.execute();
    }) {}
    void release() {
      {
        std::lock_guard<std::mutex> lock(mutex);
        released = true;
      }
      cv.notify_one();
      thread.join();
    }
  } gate(worker);
  idf_stub::set_notify_wait_hook(+[](void* context) {
    auto& waiting = *static_cast<Gate*>(context);
    ++waiting.waits;
    waiting.release();
  }, &gate);
  // This is the firmware's atomic wait. Completion arriving exactly here
  // must be consumed without clearing or losing the worker notification.
  runtime.wait_for_event(deadline > now ? deadline - now : 0);
  if (gate.thread.joinable()) gate.release();  // bounded cleanup on failure
  check(gate.waits == 1 && gate.executed, "one blocking wait releases worker");
  check(worker.ready(), "real job completed on worker thread");
  check(owner.next_deadline(now) == now, "completion makes Owner runnable");
  check(idf_stub::last_peek_ticks() == 0, "racing completion wakes the atomic wait");
  owner.poll(now);
  check(worker.idle(), "Owner collects the loan, including cancellation");
  check(owner.coordinator().snapshot().link_sessions == 0, "no unauthenticated link adopted");
  return failures;
}
