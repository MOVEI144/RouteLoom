#include "routeloom/espnow_power.hpp"
#include "routeloom/espnow_security_owner.hpp"

#include <algorithm>

#include "esp_err.h"
#include "esp_now.h"
#include "esp_sleep.h"
#include "esp_wifi.h"
#include "soc/soc_caps.h"

namespace routeloom::espnow {

Status EspNowPowerPort::prepare_sleep(const MonotonicMs now_ms) noexcept {
  if (!runtime_.sleep_quiescent()) return Status::error(StatusCode::Busy, "radio has sleep work");
  if (owner_ == nullptr || parked_) return Status::success();
  sdkv1::CoordinatorEvent event{};
  event.kind = sdkv1::CoordinatorEventKind::PrepareSleep;
  event.now = now_ms;
  const Status status = owner_->coordinator().step(event);
  if (status) parked_ = true;
  return status;
}

void EspNowPowerPort::abort_sleep(const MonotonicMs now_ms) noexcept {
  const Status radio = start_radio(nullptr);
  if (!radio) runtime_.note_diagnostic(radio.detail, kInvalidNodeId);
  if (rtc_ != nullptr) (void)rtc_->invalidate();
  if (parked_) {
    (void)owner_->wake(now_ms);
    parked_ = false;
  }
}

bool EspNowPowerPort::matches_context(const PowerImage& image, NetworkId network) const noexcept {
#if CONFIG_ROUTELOOM_SECURITY_MODE_DEV_RAM
  return PowerPort::matches_context(image, network);
#else
  if (owner_ == nullptr || owner_->coordinator().mode() == sdkv1::CoordinatorMode::Dev)
    return PowerPort::matches_context(image, network);
  NetworkId member_network = 0;
  std::uint32_t generation = 0;
  return owner_->coordinator().member_context(member_network, generation) &&
         image.network == member_network && image.config_revision == generation;
#endif
}

Status EspNowPowerPort::capture_cache(PowerImage& image) noexcept {
#if !CONFIG_ROUTELOOM_SECURITY_MODE_DEV_RAM
  if (owner_ != nullptr && owner_->coordinator().mode() != sdkv1::CoordinatorMode::Dev &&
      !owner_->coordinator().member_context(image.network, image.config_revision))
    return Status::error(StatusCode::InvalidState, "sleep membership unavailable");
#endif
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
  // An abort must repair even a partially unregistered callback pair.
  quiesced_ = true;
  if (rx != ESP_OK || tx != ESP_OK) {
    return Status::error(StatusCode::RadioFailure,
                        "ESP-NOW callback unregister failed");
  }
  if (!runtime_.sleep_quiescent()) return Status::error(StatusCode::Busy, "queued sleep ingress");
#if !CONFIG_ROUTELOOM_SECURITY_MODE_DEV_RAM
  if (parked_ && rtc_ != nullptr &&
      owner_->coordinator().mode() == sdkv1::CoordinatorMode::Member) {
    NodeId parent = kInvalidNodeId;
    routeloom::MacAddress mac{};
    BindingId binding{kInvalidBindingId};
    if (owner_->coordinator().first_live_peer(SecurityScope::Link, parent) &&
        owner_->discovery() != nullptr && owner_->discovery()->binding_of(parent, binding) &&
        owner_->discovery()->mac_of(parent, mac)) {
      return owner_->coordinator().save_sleep_image(*rtc_, parent, mac, binding.value,
                                                    runtime_.now_ms());
    }
    // Isolation is a cold sleep; no old parent/session image may survive.
    return rtc_->invalidate();
  }
#endif
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
  if (parked_) {
    const Status status = owner_->wake(runtime_.now_ms());
    if (!status) return status;
    parked_ = false;
  }
  return Status::success();
}

Status EspNowPowerPort::configure_wake(const WakePlan& plan) noexcept {
  if (plan.wake_after_ms > UINT64_MAX / 1000ULL) {
    return Status::error(StatusCode::InvalidArgument, "timer wakeup overflow");
  }
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
  wake_after_ms_ = plan.wake_after_ms;
  return Status::success();
}

Status EspNowPowerPort::enter_sleep() noexcept {
  // ESP-IDF expects Wi-Fi stopped before deep sleep: a live driver keeps
  // RF calibration/phy state across the boundary, with target-dependent
  // sleep-current and resume side effects. The stop lives here rather than
  // in quiesce_radio() because the coordinator's abort path
  // (start_radio() -> runtime_.recover()) never restarts Wi-Fi.
  if (esp_wifi_stop() != ESP_OK) {
    return Status::error(StatusCode::RadioFailure, "sleep radio stop failed");
  }
  // Point of no return: every fallible step of the sleep path (image
  // commits, ticket validation, wake configuration) is already behind
  // this call, so the hook is the firmware's proof that a coordinated
  // sleep is actually entering.
  if (pre_sleep_hook_ != nullptr) {
    pre_sleep_hook_->on_pre_sleep(wake_after_ms_);
  }
  esp_deep_sleep_start();
  // esp_deep_sleep_start does not return on success; if it did, no sleep
  // happened, so restore the driver the stop above took down.
  (void)esp_wifi_start();
  return Status::error(StatusCode::InternalError,
                      "esp_deep_sleep_start returned");
}

Status EspNowPowerPort::start_discovery(const PowerImage& image) noexcept {
  auto* discovery = runtime_.discovery();
  if (discovery == nullptr) {
    return Status::error(StatusCode::Unsupported, "discovery engine not attached");
  }
  if (image.channel != 0 && image.channel != runtime_.channel()) {
    return Status::error(StatusCode::Conflict, "sleep discovery channel changed");
  }
  // The existing engine owns the attempt count, backoff and channel scope.
  // Resume never starts a separate scanner or bypasses authentication.
  return discovery->begin_discovery(runtime_.now_ms());
}

}  // namespace routeloom::espnow
