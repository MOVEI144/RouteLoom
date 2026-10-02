#include <csetjmp>
#include <cstdio>
#include <cstring>
#include <initializer_list>

#include "freertos/task.h"
#include "routeloom/crypto_progress.hpp"
#include "routeloom/espnow_crypto_worker.hpp"

namespace {
int failures = 0;
#define CHECK(expr)                                \
  do {                                             \
    if (!(expr)) {                                 \
      std::fprintf(stderr, "failed: %s\n", #expr); \
      ++failures;                                  \
    }                                              \
  } while (false)

// Drive the production task until it blocks again. There are no objects
// with non-trivial destructors between this boundary and the blocking take.
std::jmp_buf blocked;
TaskFunction_t entry = nullptr;
void* argument = nullptr;
TaskHandle_t worker_task = nullptr;
unsigned worker_notifications = 0;
unsigned owner_notifications = 0;
unsigned owner_handle = 0;
unsigned replacement_handle = 0;
unsigned replacement_notifications = 0;
UBaseType_t owner_priority = 1;
UBaseType_t worker_priority = 0;
unsigned creates = 0;
unsigned executions = 0;
bool fail_create = true;

routeloom::Status run_job(void*) noexcept {
  ++executions;
  return routeloom::Status::success();
}
void completed(void* context) noexcept { xTaskNotifyGive(context); }
void dispatch_worker() {
  if (setjmp(blocked) == 0) entry(argument);
}
}  // namespace

TaskHandle_t xTaskCreateStatic(TaskFunction_t fn, const char* name, uint32_t depth, void* param,
                             UBaseType_t priority, StackType_t* stack, StaticTask_t* storage) {
  ++creates;
  CHECK(std::strcmp(name, "rl_crypto") == 0);
  // Both C3/C6 use IDF's byte-count stack API. Crypto must be runnable
  // above IDLE, alongside the default priority-1 Owner.
  CHECK(depth == 4096 && stack != nullptr && storage != nullptr);
  CHECK(priority == owner_priority && priority > tskIDLE_PRIORITY);
  worker_priority = priority;
  if (fail_create) return nullptr;
  entry = fn;
  argument = param;
  worker_task = storage;
  return worker_task;
}

UBaseType_t uxTaskPriorityGet(TaskHandle_t task) {
  CHECK(task == nullptr);
  return owner_priority;
}
void vTaskPrioritySet(TaskHandle_t task, UBaseType_t priority) {
  CHECK(task == worker_task && priority == owner_priority);
  worker_priority = priority;
}

void xTaskNotifyGive(TaskHandle_t task) {
  if (task == worker_task && task != nullptr)
    ++worker_notifications;
  else if (task == &owner_handle)
    ++owner_notifications;
  else if (task == &replacement_handle)
    ++replacement_notifications;
  else
    CHECK(false);
}

uint32_t ulTaskNotifyTake(BaseType_t clear, TickType_t ticks) {
  CHECK(clear == pdTRUE && ticks == portMAX_DELAY);
  if (worker_notifications == 0) std::longjmp(blocked, 1);
  const auto count = worker_notifications;
  worker_notifications = 0;
  return count;
}

int main() {
  using namespace routeloom;
  CHECK(espnow::start_crypto_worker(&completed, &owner_handle) == nullptr);
  fail_create = false;
  CryptoWorker* worker = espnow::start_crypto_worker(&completed, &owner_handle);
  CHECK(worker != nullptr && creates == 2);
  if (worker == nullptr) return 1;
  CHECK(espnow::start_crypto_worker(&completed, &owner_handle) == worker && creates == 2);
  CryptoProgress progress;
  CHECK(progress.bind(worker));
  for (const bool cancel : {false, true, false}) {
    CHECK(progress.start(&owner_handle, &run_job).code == StatusCode::WouldBlock);
    CHECK(worker_notifications == 1 && !worker->ready());
    Status result{};
    CHECK(progress.poll(result).code == StatusCode::WouldBlock);
    if (cancel) progress.cancel();
    dispatch_worker();
    CHECK(worker->ready() && worker_notifications == 0 && owner_notifications == 1);
    CHECK(progress.poll(result));
    CHECK(result.code == (cancel ? StatusCode::Expired : StatusCode::Ok));
    CHECK(worker->idle());
    owner_notifications = 0;
  }
  CHECK(executions == 3);
  espnow::detach_crypto_worker(&owner_handle);
  owner_priority = 3;
  CHECK(espnow::start_crypto_worker(&completed, &replacement_handle) == worker);
  CHECK(worker_priority == owner_priority && creates == 2);
  // An old Owner's destructor must not detach its replacement.
  espnow::detach_crypto_worker(&owner_handle);
  CHECK(progress.start(&replacement_handle, &run_job).code == StatusCode::WouldBlock);
  CHECK(espnow::start_crypto_worker(&completed, &owner_handle) == nullptr);
  dispatch_worker();
  CHECK(owner_notifications == 0 && replacement_notifications == 1);
  Status result{};
  CHECK(progress.poll(result));
  espnow::detach_crypto_worker(&replacement_handle);
  CHECK(progress.start(&replacement_handle, &run_job).code == StatusCode::WouldBlock);
  dispatch_worker();
  CHECK(replacement_notifications == 1);
  CHECK(progress.poll(result));
  return failures == 0 ? 0 : 1;
}
