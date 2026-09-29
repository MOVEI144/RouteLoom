// firmware/bridge_node: the USB gateway image. Boot, the USB bridge and the
// Owner loop are the shared routeloom_device path (role gateway); this file
// only names the image.

#include "routeloom/device.hpp"

namespace {
routeloom::Device s_device;
}  // namespace

extern "C" void app_main(void) {
  routeloom::DeviceConfig config = routeloom::device_config_from_kconfig();
  config.log_tag = "RouteLoomBr";
  s_device.start(config);
}
