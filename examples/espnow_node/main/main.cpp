// RouteLoom ESP-NOW node example: an application on routeloom::Device.
// The Device boots the node on its own Owner task (NVS, boot session,
// security owner, ESP-NOW runtime) from the component Kconfig. The app
// logs what arrives and, from another task, posts one greeting a minute to
// EXAMPLE_DESTINATION through Device::post(), the only call that may come
// from outside the Owner task.

#include <cinttypes>
#include <cstdint>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "routeloom/device.hpp"

namespace {
constexpr char kTag[] = "RouteLoomExample";

class ExampleApp final : public routeloom::NodeObserver {
 public:
  void on_message(const routeloom::MessageKey& key, const routeloom::NodeId source,
                  const routeloom::ByteView payload) noexcept override {
    ESP_LOGI(kTag, "received %u bytes from 0x%" PRIx64 " (session %lu)",
             static_cast<unsigned>(payload.size), source,
             static_cast<unsigned long>(key.id.session));
  }
  void on_delivery(const routeloom::DeliveryResult& result) noexcept override {
    ESP_LOGI(kTag, "delivery %llu: state %u %s",
             static_cast<unsigned long long>(result.id.sequence),
             static_cast<unsigned>(result.state), result.reason);
  }
  void on_diagnostic(const char*, routeloom::NodeId, const routeloom::MessageId*) noexcept override {}
};

routeloom::Device s_device;
ExampleApp s_app;

// Runs on the Owner task: the only place that may call send().
void send_greeting(routeloom::Device& device, void*) {
  static constexpr std::uint8_t kGreeting[] = {'h', 'e', 'l', 'l', 'o'};
  routeloom::MessageId id{};
  const routeloom::Status sent =
      device.send(CONFIG_EXAMPLE_DESTINATION, routeloom::ByteView{kGreeting, sizeof kGreeting},
                  routeloom::SendOptions{}, id);
  ESP_LOGI(kTag, "greeting from 0x%" PRIx64 ": %s", device.node_id(),
           sent ? "queued" : sent.detail);
}

void app_task(void*) {
  if (CONFIG_EXAMPLE_DESTINATION == 0) vTaskDelete(nullptr);
  for (;;) {
    vTaskDelay(pdMS_TO_TICKS(60000));
    if (!s_device.post(send_greeting, nullptr)) ESP_LOGW(kTag, "post queue full");
  }
}

}  // namespace

extern "C" void app_main(void) {
  s_device.observe(&s_app);
  s_device.start(routeloom::device_config_from_kconfig());
  xTaskCreate(app_task, "example", 3072, nullptr, 1, nullptr);
}
