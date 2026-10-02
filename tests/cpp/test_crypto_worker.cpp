#include <atomic>
#include <cstdio>
#include <initializer_list>
#include <thread>

#include "routeloom/crypto_progress.hpp"

namespace {
int failures = 0;
#define CHECK(expr)                                \
  do {                                             \
    if (!(expr)) {                                 \
      std::fprintf(stderr, "failed: %s\n", #expr); \
      ++failures;                                  \
    }                                              \
  } while (false)
using namespace routeloom;
struct Job {
  std::atomic<bool> entered{false};
  std::atomic<bool> release{false};
  unsigned value{0};
};
Status run(void* context) noexcept {
  auto& job = *static_cast<Job*>(context);
  job.entered.store(true, std::memory_order_release);
  while (!job.release.load(std::memory_order_acquire)) std::this_thread::yield();
  job.value = 42;
  return Status::success();
}
void test_mailbox_identity() {
  CryptoWorker worker;
  Job job;
  job.release = true;
  const CryptoWorker::Ticket ticket{&job, 1};
  CHECK(worker.submit(ticket, &run));
  CHECK(worker.submit({&job, 2}, &run).code == StatusCode::Busy);
  CHECK(worker.execute());
  CHECK(!worker.execute());
  CHECK(worker.submit({&job, 2}, &run).code == StatusCode::Busy);
  Status result{};
  for (const auto bad : {CryptoWorker::Ticket{&job, 0}, CryptoWorker::Ticket{&job, 2},
                         CryptoWorker::Ticket{&worker, 1}}) {
    CHECK(worker.take(bad, result).code == StatusCode::Conflict);
    CHECK(worker.ready());
  }
  CHECK(worker.take(ticket, result));
  CHECK(result && job.value == 42 && worker.idle());
}
void test_running_cancellation() {
  CryptoWorker worker;
  CryptoProgress progress;
  Job job;
  CHECK(progress.bind(&worker));
  CHECK(progress.start(&job, &run).code == StatusCode::WouldBlock);
  bool executed = false;
  std::thread thread([&] {
    executed = worker.execute();
    job.entered.store(true, std::memory_order_release);
  });
  while (!job.entered.load(std::memory_order_acquire)) std::this_thread::yield();
  progress.cancel();
  CHECK(progress.start(&job, &run).code == StatusCode::Busy);
  Status result{};
  CHECK(progress.poll(result).code == StatusCode::WouldBlock);
  job.release.store(true, std::memory_order_release);
  thread.join();
  CHECK(executed);
  CHECK(progress.poll(result));
  CHECK(result.code == StatusCode::Expired && job.value == 42);
  CHECK(progress.start(&job, &run).code == StatusCode::WouldBlock);
  CHECK(worker.execute());
  CHECK(progress.poll(result) && result);
}
}  // namespace
int main() {
  test_mailbox_identity();
  test_running_cancellation();
  return failures == 0 ? 0 : 1;
}
