// The consumer's C++ translation unit: routeloom/device.hpp and the C API
// header from C++, called by main.c once the node runs.

#include <cinttypes>

#include "esp_log.h"
#include "routeloom/device.h"
#include "routeloom/device.hpp"

extern "C" void consumer_log_capabilities(rl_dev_t* device) {
  rl_dev_capabilities_t caps{};
  rl_dev_struct_init(&caps, sizeof caps);
  if (rl_dev_capabilities(device, &caps) != RL_STATUS_OK) return;
  static_assert(RL_MAX_APPLICATION_PAYLOAD == routeloom::kMaxApplicationPayload,
                "one payload bound for C and C++");
  ESP_LOGI("consumer", "node 0x%" PRIx64 " role %u profile %u max payload %u",
           rl_dev_node_id(device), static_cast<unsigned>(caps.role),
           static_cast<unsigned>(caps.security_profile), static_cast<unsigned>(caps.max_payload));
}
