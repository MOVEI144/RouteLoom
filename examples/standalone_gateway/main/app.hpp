#pragma once

#include <cinttypes>
#include <cstdint>

#include "esp_log.h"
#include "routeloom/device.hpp"

namespace routeloom_example {
constexpr std::uint8_t kPendingMax = 8;

class StandaloneApp final : public routeloom::NodeObserver {
 public:
  void on_message(const routeloom::MessageKey&, const routeloom::NodeId source,
                  const routeloom::ByteView payload) noexcept override {
    ESP_LOGI("RouteLoomStandalone", "received %u bytes from 0x%" PRIx64, static_cast<unsigned>(payload.size),
             source);
    if (count_ == kPendingMax) {
      ESP_LOGW("RouteLoomStandalone", "answer to 0x%" PRIx64 " dropped: %u pending", source,
               static_cast<unsigned>(count_));
      return;
    }
    pending_[(head_ + count_) % kPendingMax] = source;
    ++count_;
  }
  void on_delivery(const routeloom::DeliveryResult& result) noexcept override {
    ESP_LOGI("RouteLoomStandalone", "answer %llu: state %u %s",
             static_cast<unsigned long long>(result.id.sequence),
             static_cast<unsigned>(result.state), result.reason);
  }
  void on_diagnostic(const char*, routeloom::NodeId, const routeloom::MessageId*) noexcept override {}

  // Owner task, outside any callback: answer what arrived since last pass.
  void answer(routeloom::Device& device) noexcept {
    static constexpr std::uint8_t kOk[] = {'o', 'k'};
    while (count_ > 0) {
      routeloom::MessageId id{};
      const routeloom::Status sent = device.send(
          pending_[head_], routeloom::ByteView{kOk, sizeof kOk}, routeloom::SendOptions{}, id);
      if (!sent) ESP_LOGW("RouteLoomStandalone", "answer to 0x%" PRIx64 ": %s", pending_[head_], sent.detail);
      head_ = static_cast<std::uint8_t>((head_ + 1) % kPendingMax);
      --count_;
    }
  }

 private:
  routeloom::NodeId pending_[kPendingMax]{};
  std::uint8_t head_{0};
  std::uint8_t count_{0};
};

}  // namespace routeloom_example
