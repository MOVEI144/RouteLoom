#include "routeloom/espnow_crypto_worker.hpp"

#include "sdkconfig.h"

#if CONFIG_FREERTOS_SUPPORT_STATIC_ALLOCATION
#include <array>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

namespace routeloom::espnow {
namespace {

constexpr std::size_t kStackBytes = 6144;
CryptoWorker mailbox;
StaticTask_t task_storage;
std::array<StackType_t, kStackBytes / sizeof(StackType_t)> stack;
TaskHandle_t task = nullptr;

void wake_worker(void*) noexcept { xTaskNotifyGive(task); }

void run(void*) noexcept {
  for (;;) {
    (void)ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
    (void)mailbox.execute();
  }
}

}  // namespace

CryptoWorker* start_crypto_worker(CryptoWorker::Wake completion,
                                  void* completion_context) noexcept {
  if (task != nullptr) return &mailbox;
  mailbox.bind(&wake_worker, nullptr, completion, completion_context);
  task = xTaskCreateStatic(&run, "rl_crypto", kStackBytes, nullptr, tskIDLE_PRIORITY, stack.data(),
                           &task_storage);
  if (task == nullptr) return nullptr;
  return &mailbox;
}

}  // namespace routeloom::espnow
#else
namespace routeloom::espnow {
CryptoWorker* start_crypto_worker(CryptoWorker::Wake, void*) noexcept { return nullptr; }
}  // namespace routeloom::espnow
#endif
