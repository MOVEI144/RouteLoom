// DevRam standalone root: ALL delivery through the scoped group tree.
#include <cstdint>

#include "esp_log.h"
#include "routeloom/device.hpp"

namespace {
constexpr char kTag[] = "RouteLoomGroup";
routeloom::Device s_device;

class App final : public routeloom::NodeObserver {
 public:
  void on_message(const routeloom::MessageKey&, routeloom::NodeId,
                  routeloom::ByteView) noexcept override {}
  void on_delivery(const routeloom::DeliveryResult&) noexcept override {}
  void on_diagnostic(const char* reason, routeloom::NodeId,
                     const routeloom::MessageId*) noexcept override {
    ESP_LOGW(kTag, "%s", reason);
  }
  void on_group_message(const routeloom::GroupMessageInfo& info,
                        routeloom::ByteView payload) noexcept override {
    ESP_LOGI(kTag, "group %u: %u bytes, late=%d", info.group,
             static_cast<unsigned>(payload.size), info.late);
  }
  void on_group_delivery(const routeloom::GroupDeliveryResult& result) noexcept override {
    ESP_LOGI(kTag, "state=%u delivered=%u missing=%u unaccounted=%u %s",
             static_cast<unsigned>(result.state), result.delivered, result.missing_total,
             result.unaccounted, result.reason);
  }
};
App s_app;

// A poll hook runs on the Owner; observer callbacks only report results.
void poll(routeloom::Device& device, routeloom::MonotonicMs now, void*) {
  static routeloom::MonotonicMs next = 60000;
  if (now < next || !device.capabilities().group_send) return;
  next = now + 60000;
  // Peers use this same sample, but only the standalone root sends.
  if (device.capabilities().role != routeloom::profile::Role::Gateway) return;
  static constexpr std::uint8_t kPayload[] = {'h', 'e', 'l', 'l', 'o'};
  routeloom::MessageId id{};
  const auto sent = device.send_group(routeloom::kGroupAll, {kPayload, sizeof kPayload},
                                      routeloom::GroupSendOptions{}, id);
  ESP_LOGI(kTag, "ALL: %s", sent ? "queued" : sent.detail);
}
}  // namespace

extern "C" void app_main(void) {
  s_device.observe(&s_app);
  s_device.on_poll(poll, nullptr);
  auto config = routeloom::device_config_from_kconfig();
  s_device.start(config);
}
