#include "routeloom/espnow_crypto_worker.hpp"

#include "sdkconfig.h"

#if CONFIG_FREERTOS_SUPPORT_STATIC_ALLOCATION
#include <array>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#if CONFIG_ROUTELOOM_HIL_EDHOC_TIMING
#include "esp_log.h"
#endif

namespace routeloom::espnow {
namespace {

constexpr std::size_t kStackBytes = 4096;
CryptoWorker mailbox;
StaticTask_t task_storage;
std::array<StackType_t, kStackBytes / sizeof(StackType_t)> stack;
TaskHandle_t task = nullptr;
portMUX_TYPE completion_lock = portMUX_INITIALIZER_UNLOCKED;
CryptoWorker::Wake completion_wake = nullptr;
void* completion_context = nullptr;

void wake_worker(void*) noexcept { xTaskNotifyGive(task); }

void wake_owner(void*) noexcept {
  // Serialize notification with registration/detachment. No callback may
  // retain an Owner context after detachment returns.
  portENTER_CRITICAL(&completion_lock);
  if (completion_wake != nullptr) completion_wake(completion_context);
  portEXIT_CRITICAL(&completion_lock);
}

void run(void*) noexcept {
  for (;;) {
    (void)ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
    (void)mailbox.execute();
#if CONFIG_ROUTELOOM_HIL_EDHOC_TIMING
    ESP_LOGI("rl_crypto", "HIL CRYPTO stack_free_bytes=%u",
             static_cast<unsigned>(uxTaskGetStackHighWaterMark(nullptr)));
#endif
  }
}

}  // namespace

CryptoWorker* start_crypto_worker(CryptoWorker::Wake completion, void* context) noexcept {
  if (!mailbox.idle()) return nullptr;
  portENTER_CRITICAL(&completion_lock);
  completion_wake = completion;
  completion_context = context;
  portEXIT_CRITICAL(&completion_lock);
  const UBaseType_t priority = uxTaskPriorityGet(nullptr);
  if (task != nullptr) {
    vTaskPrioritySet(task, priority);
    return &mailbox;
  }
  mailbox.bind(&wake_worker, nullptr, &wake_owner, nullptr);
  // Match the Owner: crypto must progress even if forwarding keeps Owner
  // runnable, without outranking the forwarding task. IDF time-slices
  // equal priorities; priority 0 can instead sleep in the IDLE hook.
  task = xTaskCreateStatic(&run, "rl_crypto", kStackBytes, nullptr, priority,
                          stack.data(), &task_storage);
  if (task == nullptr) return nullptr;
  return &mailbox;
}

void detach_crypto_worker(void* context) noexcept {
  portENTER_CRITICAL(&completion_lock);
  if (completion_context == context) {
    completion_wake = nullptr;
    completion_context = nullptr;
  }
  portEXIT_CRITICAL(&completion_lock);
}

}  // namespace routeloom::espnow
#else
namespace routeloom::espnow {
CryptoWorker* start_crypto_worker(CryptoWorker::Wake, void*) noexcept { return nullptr; }
void detach_crypto_worker(void*) noexcept {}
}  // namespace routeloom::espnow
#endif
