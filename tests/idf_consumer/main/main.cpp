// The smallest RouteLoom application: boot the node from the component
// Kconfig and let the Device run it.

#include "routeloom/device.hpp"

namespace {
routeloom::Device s_device;
}  // namespace

extern "C" void app_main(void) {
  routeloom::DeviceConfig config = routeloom::device_config_from_kconfig();
  s_device.start(config);
}
