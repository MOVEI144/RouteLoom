#include <array>
#include <cstdio>
#include <cstring>

#include "esp_sleep.h"
#include "idf_stubs.hpp"
#include "routeloom/device.hpp"
#include "routeloom/espnow_power.hpp"
#include "test_security.hpp"
#include "test_sim.hpp"

esp_err_t esp_sleep_enable_timer_wakeup(std::uint64_t) { return ESP_OK; }
esp_err_t esp_sleep_enable_gpio_wakeup_on_hp_periph_powerdown(std::uint64_t,
                                                              esp_sleep_gpio_wake_up_mode_t) {
  return ESP_OK;
}
void esp_deep_sleep_start() {}

void bind_device_sleep_runtime(routeloom::Device&, routeloom::espnow::EspNowRuntime&) noexcept;

namespace {
using namespace routeloom;
int failures = 0;
#define CHECK(expr)                                                                 \
  do {                                                                              \
    if (!(expr)) {                                                                  \
      std::fprintf(stderr, "device sleep: %s:%d: %s\n", __FILE__, __LINE__, #expr); \
      ++failures;                                                                   \
    }                                                                               \
  } while (false)

class Hook final : public espnow::PreSleepHook {
 public:
  void on_pre_sleep() noexcept override { ++calls; }
  unsigned calls{0};
};

class Storage final : public PowerStorage {
 public:
  Status read(std::uint8_t slot, MutableByteView out) noexcept override {
    if (!used[slot]) return Status::error(StatusCode::NotFound, "empty");
    std::memcpy(out.data, images[slot].data(), out.size);
    return Status::success();
  }
  Status write(std::uint8_t slot, ByteView bytes) noexcept override {
    std::memcpy(images[slot].data(), bytes.data, bytes.size);
    used[slot] = true;
    ++writes;
    return Status::success();
  }
  std::array<std::array<std::uint8_t, kPowerImageRecordSize>, 2> images{};
  std::array<bool, 2> used{};
  unsigned writes{0};
};

// Only the platform handoff is simulated; Device, runtime, MeshNode and
// durable pending/tickets execute their production implementations.
class Port final : public PowerPort {
 public:
  Status capture_cache(PowerImage& image) noexcept override {
    image.channel = 6;
    return Status::success();
  }
  Status prepare_sleep(MonotonicMs) noexcept override { return park; }
  void abort_sleep(MonotonicMs) noexcept override { ++aborts; }
  Status quiesce_radio() noexcept override { return Status::success(); }
  Status start_radio(const PowerImage*) noexcept override { return Status::success(); }
  Status configure_wake(const WakePlan&) noexcept override { return Status::success(); }
  Status enter_sleep() noexcept override {
    ++enters;
    return Status::success();
  }
  Status start_discovery(const PowerImage&) noexcept override { return Status::success(); }
  Status park{};
  unsigned aborts{0};
  unsigned enters{0};
};

class Events final : public PowerEvents {
 public:
  explicit Events(Device& device) : device_(device) {}
  void on_transition(PowerState, PowerState, const char*) noexcept override {
    CHECK(device_.abort_sleep().code == StatusCode::Busy);
  }
  void on_pending_result(const PendingDeliveryRecord&, StatusCode) noexcept override {}
  void on_diagnostic(const char*) noexcept override {}

 private:
  Device& device_;
};
void posted(Device&, void* ctx) { ++*static_cast<unsigned*>(ctx); }
}  // namespace

int run_device_sleep_scenarios() {
  using namespace routeloom;
  idf_stub::reset();
  espnow::EspNowRuntimeConfig config{};
  config.node.network = 1;
  config.node.node = 1;
  config.node.message_session = 10;
  config.node.boot_incarnation = 0xB001;
  config.node.link_epoch = 1;
  config.node.end_epoch = 1;
  config.node.route_advertisement_period_ms = 100;
  config.node.route_lifetime_ms = 1000;
  config.max_tx_power_qdbm = 80;
  config.channel = 6;
  routeloom_test::TestSecurity security;
  routeloom_test::CapturingObserver observer;
  espnow::EspNowRuntime runtime(config, security, observer);
  const auto initialized = runtime.initialize();
  if (!initialized) std::fprintf(stderr, "runtime init: %s\n", initialized.detail);
  CHECK(initialized);
  CHECK(runtime.start());
  espnow::EspNowPowerPort adapter(runtime);
  Hook hook;
  adapter.set_pre_sleep_hook(&hook);
  idf_stub::fail_wifi_stop(true);
  CHECK(adapter.enter_sleep().code == StatusCode::RadioFailure);
  CHECK(hook.calls == 0);
  idf_stub::fail_wifi_stop(false);
  WakePlan too_long{};
  too_long.wake_after_ms = UINT64_MAX;
  CHECK(adapter.configure_wake(too_long).code == StatusCode::InvalidArgument);
  Device device;
  bind_device_sleep_runtime(device, runtime);
  Storage storage;
  Port port;
  Events events(device);
  PowerCoordinator power(PowerConfig{}, runtime.node(), port, storage, events);
  const auto drive = [&](const MonotonicMs now) {
    idf_stub::set_now_us(static_cast<std::int64_t>(now) * 1000);
    device.step(now);
  };
  CHECK(device.bind_sleep(power, ResetCause::ColdBoot, {}, 0));
  CHECK(device.bind_sleep(power, ResetCause::ColdBoot, {}, 0).code == StatusCode::InvalidState);
  for (unsigned cycle = 0; cycle < 3; ++cycle) {
    const auto now = static_cast<MonotonicMs>(cycle * 1000);
    idf_stub::set_now_us(static_cast<std::int64_t>(now) * 1000);
    CHECK(device.prepare_sleep(SleepRequest{}));
    drive(now);
    const auto ticket = device.sleep_ticket();
    CHECK(ticket.issued);
    CHECK(device.enter_sleep(ticket));
    CHECK(device.enter_sleep(ticket).code == StatusCode::InvalidState);
    idf_stub::set_now_us(static_cast<std::int64_t>(now + 100) * 1000);
    CHECK(device.wake(ResetCause::DeepSleepWake, {100, 100, true}, now + 100));
    CHECK(!runtime.node().draining());
    CHECK(device.wake_info() == ResumeOutcome::ColdStart);
  }
  CHECK(port.enters == 3);
  idf_stub::set_now_us(4000000);
  CHECK(device.prepare_sleep(SleepRequest{}));
  drive(4000);
  const auto ticket = device.sleep_ticket();
  unsigned ran = 0;
  CHECK(device.post(posted, &ran));
  CHECK(device.enter_sleep(ticket).code == StatusCode::InvalidState);
  drive(4000);
  CHECK(ran == 1 && port.enters == 3 && !runtime.node().draining());
  // A busy security leg reaches the drain bound without writing or
  // settling the delivery; abort restores admission and the park.
  port.park = Status::error(StatusCode::Busy, "security busy");
  const auto writes = storage.writes;
  CHECK(device.prepare_sleep(SleepRequest{}));
  drive(4499);
  CHECK(storage.writes == writes && runtime.node().draining());
  drive(4500);
  CHECK(storage.writes == writes && !runtime.node().draining());
  runtime.stop();
  return failures;
}
