#include "routeloom/espnow_power.hpp"

#include <algorithm>
#include <cstring>

#include "esp_err.h"
#include "esp_now.h"
#include "esp_sleep.h"
#include "esp_wifi.h"
#include "soc/soc_caps.h"

namespace routeloom::espnow {

Status EspNowPowerPort::capture_cache(PowerImage& image) noexcept {
  image.channel = runtime_.channel();
  runtime_.for_each_peer(
      [&](const NodeId node, const MacAddress& mac, const RouteMetric metric,
          const bool autonomy_managed) {
        // Discovery-managed leases are never persisted: bindings and driver
        // peers are re-established by the engine after resume. Persisting
        // them would smuggle un-reauthenticated peers back in as static.
        if (autonomy_managed) return;
        PowerPeerRecord* slot = nullptr;
        for (auto& candidate : image.peers) {
          if (candidate.used && candidate.node == node) {
            slot = &candidate;
            break;
          }
        }
        if (slot == nullptr) {
          for (auto& candidate : image.peers) {
            if (!candidate.used) {
              slot = &candidate;
              break;
            }
          }
        }
        if (slot == nullptr) return;
        *slot = PowerPeerRecord{};
        slot->used = true;
        slot->node = node;
        slot->metric = metric;
        slot->address_size = static_cast<std::uint8_t>(mac.bytes.size());
        std::copy(mac.bytes.begin(), mac.bytes.end(), slot->address.begin());
      });
  return Status::success();
}

Status EspNowPowerPort::quiesce_radio() noexcept {
  // Stop the event path so no new RX/TX work can be delivered to MeshNode.
  // The driver itself is stopped later by enter_sleep()'s esp_wifi_stop().
  const esp_err_t rx = esp_now_unregister_recv_cb();
  const esp_err_t tx = esp_now_unregister_send_cb();
  if (rx != ESP_OK || tx != ESP_OK) {
    return Status::error(StatusCode::RadioFailure,
                        "ESP-NOW callback unregister failed");
  }
  quiesced_ = true;
  return Status::success();
}

Status EspNowPowerPort::start_radio(const PowerImage* image) noexcept {
  if (image != nullptr) {
    for (const auto& peer : image->peers) {
      if (!peer.used || peer.address_size != 6U) continue;
      MacAddress mac{};
      std::copy_n(peer.address.data(), mac.bytes.size(), mac.bytes.begin());
      // register_neighbor re-adds the driver peer and re-applies the LR250
      // rate config; node-level neighbors are rebuilt by the coordinator.
      const auto status =
          runtime_.register_neighbor(peer.node, mac, peer.metric);
      if (!status) return status;
    }
  }
  if (quiesced_) {
    const auto status = runtime_.recover();
    if (!status) return status;
    quiesced_ = false;
  }
  return Status::success();
}

Status EspNowPowerPort::configure_wake(const WakePlan& plan) noexcept {
  if (plan.wake_after_ms != 0) {
    const esp_err_t error =
        esp_sleep_enable_timer_wakeup(plan.wake_after_ms * 1000ULL);
    if (error != ESP_OK) {
      return Status::error(StatusCode::InvalidArgument,
                          "timer wakeup configuration failed");
    }
  }
  if (plan.gpio_mask != 0) {
#if SOC_GPIO_SUPPORT_HP_PERIPH_PD_SLEEP_WAKEUP
    // C3/C5 wake deep sleep through the HP-peripheral powerdown GPIO path.
    // Targets without it (for example S3, which uses EXT1) are reported
    // unsupported rather than guessed.
    const esp_err_t error = esp_sleep_enable_gpio_wakeup_on_hp_periph_powerdown(
        plan.gpio_mask, ESP_GPIO_WAKEUP_GPIO_HIGH);
    if (error != ESP_OK) {
      return Status::error(StatusCode::InvalidArgument,
                          "GPIO wakeup configuration failed");
    }
#else
    return Status::error(StatusCode::Unsupported,
                        "GPIO deep-sleep wakeup unsupported on this target");
#endif
  }
  return Status::success();
}

Status EspNowPowerPort::enter_sleep() noexcept {
  // ESP-IDF expects Wi-Fi stopped before deep sleep: a live driver keeps
  // RF calibration/phy state across the boundary, with target-dependent
  // sleep-current and resume side effects. The stop lives here rather than
  // in quiesce_radio() because the coordinator's abort path
  // (start_radio() -> runtime_.recover()) never restarts Wi-Fi.
  (void)esp_wifi_stop();
  // Point of no return: every fallible step of the sleep path (image
  // commits, ticket validation, wake configuration) is already behind
  // this call, so the hook is the firmware's proof that a coordinated
  // sleep is actually entering.
  if (pre_sleep_hook_ != nullptr) {
    pre_sleep_hook_->on_pre_sleep();
  }
  esp_deep_sleep_start();
  // esp_deep_sleep_start does not return on success; if it did, no sleep
  // happened, so restore the driver the stop above took down.
  (void)esp_wifi_start();
  return Status::error(StatusCode::InternalError,
                      "esp_deep_sleep_start returned");
}

Status EspNowPowerPort::start_discovery(const PowerImage& image) noexcept {
  (void)image;
  // Bounded discovery (same channel -> saved candidates -> limited scan) is
  // not implemented on the ESP-NOW port yet; the failure is explicit so the
  // coordinator can log it instead of scanning unboundedly.
  return Status::error(StatusCode::Unsupported,
                      "bounded discovery not implemented");
}

Status NvsSleepStorage::read(const std::uint8_t slot,
                             const MutableByteView target) noexcept {
  if (slot >= kPowerImageSlots || target.data == nullptr ||
      target.size != kPowerImageRecordSize) {
    return Status::error(StatusCode::InvalidArgument,
                        "invalid sleep image read");
  }
  bool found = false;
  const auto status =
      store_.load_blob(slot == 0 ? "img0" : "img1", target.data, target.size,
                       found);
  if (!status) return status;
  if (!found) std::memset(target.data, 0, target.size);
  return Status::success();
}

Status NvsSleepStorage::write(const std::uint8_t slot,
                              const ByteView data) noexcept {
  if (slot >= kPowerImageSlots || data.data == nullptr ||
      data.size != kPowerImageRecordSize) {
    return Status::error(StatusCode::InvalidArgument,
                        "invalid sleep image write");
  }
  return store_.commit_blob(slot == 0 ? "img0" : "img1", data.data, data.size);
}

}  // namespace routeloom::espnow
