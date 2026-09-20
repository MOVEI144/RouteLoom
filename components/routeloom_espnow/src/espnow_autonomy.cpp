#include "routeloom/espnow_autonomy.hpp"

#include <cstring>

#include "esp_log.h"
#include "esp_random.h"

namespace routeloom::espnow {

Status EspNowEntropySource::fill(const MutableByteView out) noexcept {
  if (out.data == nullptr && out.size != 0) {
    return Status::error(StatusCode::InvalidArgument, "entropy output invalid");
  }
  std::size_t written = 0;
  while (written < out.size) {
    const std::uint32_t value = esp_random();
    const std::size_t chunk =
        out.size - written < sizeof(value) ? out.size - written : sizeof(value);
    std::memcpy(out.data + written, &value, chunk);
    written += chunk;
  }
  return Status::success();
}

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
