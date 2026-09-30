// RouteLoom standalone gateway example: a gateway-role image whose own
// application serves the members through routeloom::Device, with no host
// attached in operation. Each message from a member is answered with "ok".
// The answer is sent from the poll hook, because Device calls made inside
// a callback return Busy; the pending origins wait in a bounded ring and a
// full ring drops the answer, not the message.

#include <cinttypes>
#include <cstdint>

#include "esp_log.h"
#include "app.hpp"

namespace {
using routeloom_example::StandaloneApp;

routeloom::Device s_device;
StandaloneApp s_app;

void on_poll(routeloom::Device& device, routeloom::MonotonicMs, void*) { s_app.answer(device); }

}  // namespace

extern "C" void app_main(void) {
  s_device.observe(&s_app);
  s_device.on_poll(on_poll, nullptr);
  routeloom::DeviceConfig config = routeloom::device_config_from_kconfig();
  config.log_tag = "RouteLoomSa";
  s_device.start(config);
}
