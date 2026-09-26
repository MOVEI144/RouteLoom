// firmware/reference_node: the reference RouteLoom node on the shared node
// boot (design-devflow.md §5.1). All bring-up — NVS, boot session, sdkv1
// stores, security owner, runtime, discovery/migration/config opt-ins and
// the pump loops — lives in components/routeloom_node_boot and is shared
// verbatim with firmware/bench_node. This image ships no application
// observer: the shared observer logs traffic exactly as before.

#include <array>
#include <cstdint>

#include "esp_log.h"
#include "routeloom/node_boot.hpp"
#include "sdkconfig.h"

#if CONFIG_ROUTELOOM_HIL_SEND_DESTINATION != 0 && \
    !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
#include "routeloom/espnow_runtime.hpp"

namespace {

void poll_hil_send(const routeloom::MonotonicMs now_ms, void* ctx) {
  auto& runtime = **static_cast<routeloom::espnow::EspNowRuntime**>(ctx);
  static routeloom::MonotonicMs next_ms = 0;
  static std::uint32_t attempt = 0;
  if (next_ms == 0) next_ms = now_ms + 10000;
  if (attempt >= CONFIG_ROUTELOOM_HIL_SEND_COUNT || now_ms < next_ms) return;

  const std::array<std::uint8_t, 8> payload{
      'R', 'L', 'H', 'I', 'L', 'D',
      static_cast<std::uint8_t>(attempt >> 8),
      static_cast<std::uint8_t>(attempt)};
  routeloom::MessageId id{};
  const auto sent = runtime.node().send(
      CONFIG_ROUTELOOM_HIL_SEND_DESTINATION,
      routeloom::ByteView{payload.data(), payload.size()},
      routeloom::SendOptions{}, now_ms, id);
  ESP_LOGI("RouteLoomRef", "HIL DEVICE SEND attempt=%lu dest=%llu admitted=%u detail=%s",
           static_cast<unsigned long>(attempt),
           static_cast<unsigned long long>(CONFIG_ROUTELOOM_HIL_SEND_DESTINATION),
           static_cast<unsigned>(static_cast<bool>(sent)), sent.detail);
  ++attempt;
  next_ms = now_ms + 2000;
}

void attach_hil_send(routeloom::espnow::EspNowRuntime& runtime,
                     routeloom::espnow::EspNowSecurityOwner*,
                     routeloom::espnow::Sdkv1Stores*, void* ctx) {
  *static_cast<routeloom::espnow::EspNowRuntime**>(ctx) = &runtime;
}

}  // namespace
#endif

extern "C" void app_main(void) {
  routeloom::espnow::NodeBootHooks hooks{};
  hooks.log_tag = "RouteLoomRef";
#if CONFIG_ROUTELOOM_HIL_SEND_DESTINATION != 0 && \
    !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
  routeloom::espnow::EspNowRuntime* runtime = nullptr;
  hooks.attach = attach_hil_send;
  hooks.poll = poll_hil_send;
  hooks.ctx = &runtime;
#endif
  routeloom::espnow::run_node(hooks);
}
