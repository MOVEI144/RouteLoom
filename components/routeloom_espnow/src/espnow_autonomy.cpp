#include "routeloom/espnow_autonomy.hpp"

#include "esp_log.h"

namespace routeloom::espnow {

void EspNowDiscoveryObserver::on_discovery_event(const char* reason,
                                                 const NodeId peer) noexcept {
  ESP_LOGI(tag_ != nullptr ? tag_ : "RouteLoom",
           "discovery event=%s peer=%llu", reason != nullptr ? reason : "?",
           static_cast<unsigned long long>(peer));
  // The same bounded reason rides the device→host diagnostic lane.
  if (runtime_ != nullptr && reason != nullptr) {
    runtime_->note_diagnostic(reason, peer);
  }
}

}  // namespace routeloom::espnow
