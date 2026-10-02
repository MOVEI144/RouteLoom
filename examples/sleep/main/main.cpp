// Device's deep-sleep Kconfig cycle owns drain, persistence and timer wake.
#include "esp_log.h"
#include "routeloom/device.hpp"

namespace {
constexpr char kTag[] = "RouteLoomSleep";
routeloom::Device s_device;

class App final : public routeloom::DeviceObserver {
 public:
  void on_sleep_pending_result(const routeloom::PendingDeliveryRecord&,
                         routeloom::StatusCode result) noexcept override {
    ESP_LOGI(kTag, "pending recovery status=%u", static_cast<unsigned>(result));
  }
};
App s_app;
}  // namespace

extern "C" void app_main(void) {
  ESP_LOGI(kTag, "Development: sleep cycle, wake timing/current unqualified");
  s_device.observe_device(&s_app);
  auto config = routeloom::device_config_from_kconfig();
  s_device.start(config);
}
