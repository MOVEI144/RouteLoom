#include <array>
#include <cstdio>
#include <cstring>
#include <thread>

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

routeloom::PowerEvents& device_sleep_events(routeloom::Device&) noexcept;

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
  void on_pre_sleep(std::uint64_t timer_ms) noexcept override {
    last_timer_ms = timer_ms;
    on_pre_sleep();
  }
  unsigned calls{0};
  std::uint64_t last_timer_ms{0};
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
    if (post_at_handoff != nullptr) {
      std::thread producer([&] {
        handoff_post_status = post_at_handoff->post(
            +[](Device&, void* ctx) { ++*static_cast<unsigned*>(ctx); }, &handoff_jobs_run);
      });
      producer.join();
      post_at_handoff = nullptr;
    }
    return enter_result;
  }
  Status start_discovery(const PowerImage&) noexcept override { return Status::success(); }
  Status park{};
  unsigned aborts{0};
  unsigned enters{0};
  Device* post_at_handoff{nullptr};
  Status handoff_post_status{};
  Status enter_result{};
  unsigned handoff_jobs_run{0};
};

class PendingObserver final : public DeviceObserver {
 public:
  explicit PendingObserver(Device& device) : device_(device) {}
  void on_sleep_pending_result(const PendingDeliveryRecord& pending,
                               StatusCode status) noexcept override {
    ++calls;
    id = pending.original_id;
    result = status;
    CHECK(device_.abort_sleep().code == StatusCode::Busy);
  }
  unsigned calls{0};
  MessageId id{};
  StatusCode result{StatusCode::Ok};

 private:
  Device& device_;
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
  WakePlan custom_wake{};
  custom_wake.wake_after_ms = 1234567;
  CHECK(adapter.configure_wake(custom_wake));
  CHECK(adapter.enter_sleep().code == StatusCode::InternalError);
  CHECK(hook.calls == 1 && hook.last_timer_ms == custom_wake.wake_after_ms);
  custom_wake.wake_after_ms = static_cast<std::uint64_t>(UINT32_MAX) + 1;
  CHECK(adapter.configure_wake(custom_wake));
  CHECK(adapter.enter_sleep().code == StatusCode::InternalError);
  CHECK(hook.calls == 2 && hook.last_timer_ms == custom_wake.wake_after_ms);

  Device device;
  bind_device_sleep_runtime(device, runtime);
  Storage storage;
  Port port;
  Events events(device);
  port.post_at_handoff = &device;
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
    drive(now + 100);
  }
  CHECK(port.handoff_post_status.code == StatusCode::Busy && port.handoff_jobs_run == 0);
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
  port.park = Status::success();
  port.enter_result = Status::error(StatusCode::RadioFailure, "entry refused");
  idf_stub::set_now_us(5000000);
  CHECK(device.prepare_sleep(SleepRequest{}));
  drive(5000);
  CHECK(device.enter_sleep(device.sleep_ticket()).code == StatusCode::RadioFailure);
  CHECK(device.post(posted, &ran));
  drive(5001);
  CHECK(ran == 2);
  runtime.stop();
  espnow::EspNowRuntime pending_runtime(config, security, observer);
  CHECK(pending_runtime.initialize());
  CHECK(pending_runtime.start());
  Device pending_device;
  bind_device_sleep_runtime(pending_device, pending_runtime);
  PendingObserver pending_observer(pending_device);
  pending_device.observe_device(&pending_observer);
  Storage pending_storage;
  Port pending_port;
  PowerCoordinator pending_power(PowerConfig{}, pending_runtime.node(), pending_port,
                                 pending_storage, device_sleep_events(pending_device));
  idf_stub::set_now_us(0);
  CHECK(pending_device.bind_sleep(pending_power, ResetCause::ColdBoot, {}, 0));
  const std::uint8_t payload = 42;
  SendOptions options{};
  options.delivery = DeliveryClass::Reliable;
  options.lifetime_ms = 10000;
  options.persist_across_sleep = true;
  MessageId original{};
  CHECK(pending_device.send(2, {&payload, 1}, options, original));
  CHECK(pending_device.prepare_sleep(SleepRequest{}));
  idf_stub::set_now_us(500000);
  pending_device.step(500);
  const auto saved_ticket = pending_device.sleep_ticket();
  CHECK(saved_ticket.issued);
  CHECK(pending_device.enter_sleep(saved_ticket));
  idf_stub::set_now_us(600000);
  CHECK(pending_device.wake(ResetCause::DeepSleepWake, {}, 600));
  CHECK(pending_observer.calls == 1 && pending_observer.id == original &&
        pending_observer.result == StatusCode::TimeUncertain);
  pending_runtime.stop();
  return failures;
}
