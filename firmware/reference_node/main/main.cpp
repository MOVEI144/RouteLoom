// firmware/reference_node: the reference node image on the shared
// routeloom_device path. The app adds the HIL observation console
// ("obs1 health" on the ROM console) and the optional HIL device send.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "esp_log.h"
#include "esp_rom_serial_output.h"
#include "routeloom/device.hpp"
#include "routeloom/observation.hpp"
#include "sdkconfig.h"

namespace {
using routeloom::NodeId;

// One bounded read-only request per line, at most once per second. The
// active console channel is polled in the owner loop, never an RF callback.
class ReferenceObsConsole final {
 public:
  void poll(const routeloom::ObservationSource& source, const NodeId observer,
            const routeloom::MonotonicMs now_ms) noexcept {
    for (unsigned i = 0; i < 32; ++i) {
      std::uint8_t byte = 0;
      if (esp_rom_output_rx_one_char(&byte) != 0) break;
      if (byte == '\n') {
        if (!overflow_ && length_ > 0 && line_[length_ - 1] == '\r') --length_;
        if (!overflow_ && length_ == 11 &&
            std::memcmp(line_, "obs1 health", 11) == 0) {
          if (answered_ && (now_ms < last_answer_ms_ ||
                            now_ms - last_answer_ms_ < 1000)) {
            emit("OBS1 {\"error\":\"rate_limited\"}\n");
          } else {
            routeloom::ObservationSystem system{};
            char response[512]{};
            std::size_t used = 0;
            if (source.fill_system(now_ms, system) &&
                routeloom::format_observation_console_system(
                    observer, system, response, sizeof(response), used)) {
              for (std::size_t j = 0; j < used; ++j) {
                esp_rom_output_putc(response[j]);
              }
              last_answer_ms_ = now_ms;
              answered_ = true;
            } else {
              emit("OBS1 {\"error\":\"unavailable\"}\n");
            }
          }
        } else if (length_ >= 4 && std::memcmp(line_, "obs1", 4) == 0) {
          emit("OBS1 {\"error\":\"invalid_request\"}\n");
        }
        length_ = 0;
        overflow_ = false;
      } else if (length_ < sizeof(line_)) {
        line_[length_++] = static_cast<char>(byte);
      } else {
        overflow_ = true;  // drain to newline before accepting another command
      }
    }
  }

 private:
  static void emit(const char* line) noexcept {
    for (const char* p = line; *p != '\0'; ++p) esp_rom_output_putc(*p);
  }
  char line_[32]{};
  std::size_t length_{0};
  routeloom::MonotonicMs last_answer_ms_{0};
  bool answered_{false};
  bool overflow_{false};
};

struct ReferenceApp {
  ReferenceObsConsole console{};
#if CONFIG_ROUTELOOM_HIL_SEND_DESTINATION != 0
  routeloom::MonotonicMs hil_next_ms{0};
  std::uint32_t hil_attempt{0};
#endif
};

#if CONFIG_ROUTELOOM_HIL_SEND_DESTINATION != 0
void poll_hil_send(routeloom::Device& device, ReferenceApp& app,
                   routeloom::MonotonicMs now_ms) {
  if (app.hil_next_ms == 0) app.hil_next_ms = now_ms + 10000;
  if (app.hil_attempt >= CONFIG_ROUTELOOM_HIL_SEND_COUNT || now_ms < app.hil_next_ms) return;

  const std::array<std::uint8_t, 8> payload{
      'R', 'L', 'H', 'I', 'L', 'D',
      static_cast<std::uint8_t>(app.hil_attempt >> 8),
      static_cast<std::uint8_t>(app.hil_attempt)};
  routeloom::MessageId id{};
  const auto sent = device.send(CONFIG_ROUTELOOM_HIL_SEND_DESTINATION,
                                routeloom::ByteView{payload.data(), payload.size()},
                                routeloom::SendOptions{}, id);
  ESP_LOGI("RouteLoomRef", "HIL DEVICE SEND attempt=%lu dest=%llu admitted=%u detail=%s",
           static_cast<unsigned long>(app.hil_attempt),
           static_cast<unsigned long long>(CONFIG_ROUTELOOM_HIL_SEND_DESTINATION),
           static_cast<unsigned>(static_cast<bool>(sent)), sent.detail);
  ++app.hil_attempt;
  app.hil_next_ms = now_ms + 2000;
}
#endif

void reference_poll(routeloom::Device& device, routeloom::MonotonicMs now_ms, void* ctx) {
  auto& app = *static_cast<ReferenceApp*>(ctx);
  if (device.observation() != nullptr) {
    app.console.poll(*device.observation(), device.node_id(), now_ms);
  }
#if CONFIG_ROUTELOOM_HIL_SEND_DESTINATION != 0
  poll_hil_send(device, app, now_ms);
#endif
}

routeloom::Device s_device;
ReferenceApp s_app;

}  // namespace

extern "C" void app_main(void) {
  routeloom::DeviceConfig config = routeloom::device_config_from_kconfig();
  config.log_tag = "RouteLoomRef";
  s_device.enable_observation();  // the "obs1 health" console
  s_device.on_poll(reference_poll, &s_app);
  s_device.start(config);
}
