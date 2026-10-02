#include <array>
#include <cstdint>
#include <cstdio>

#include "routeloom/espnow_runtime.hpp"
#include "idf_stubs.hpp"
#include "test_security.hpp"
#include "test_sim.hpp"

namespace routeloom::espnow {
struct EspNowRuntimeTestAccess {
  static void receive(const esp_now_recv_info_t& info, const bool bootstrap) noexcept {
    std::array<std::uint8_t, autonomy::kRld1HeaderSize> frame{};
    if (bootstrap) {
      frame[0] = 'R';
      frame[1] = 'L';
      frame[2] = 'D';
      frame[3] = '1';
      frame[4] = autonomy::kRld1Version;
      frame[5] = static_cast<std::uint8_t>(FrameType::Discover);
      frame[7] = frame[9] = static_cast<std::uint8_t>(frame.size());
    }
    EspNowRuntime::receive_callback(&info, frame.data(), static_cast<int>(frame.size()));
  }
  static unsigned queued(const EspNowRuntime& runtime, const bool bootstrap) noexcept {
    return uxQueueMessagesWaiting(bootstrap ? runtime.bootstrap_queue_ : runtime.event_queue_);
  }
  static void drain(EspNowRuntime& runtime) noexcept {
    EspNowRuntime::Event event{};
    EspNowRuntime::BootstrapEvent bootstrap{};
    (void)xQueueReceive(runtime.event_queue_, &event, 0);
    (void)xQueueReceive(runtime.bootstrap_queue_, &bootstrap, 0);
  }
#if CONFIG_ROUTELOOM_HIL_RX_MIN_RSSI != 0 || CONFIG_ROUTELOOM_HIL_RX_DROP_PERMILLE != 0
  static std::uint32_t rssi_drops(const EspNowRuntime& runtime) noexcept {
    return runtime.hil_rx_rssi_dropped_;
  }
  static std::uint32_t random_drops(const EspNowRuntime& runtime) noexcept {
    return runtime.hil_rx_random_dropped_;
  }
  static std::uint32_t rssi_bin(const EspNowRuntime& runtime, const std::size_t bin) noexcept {
    return runtime.hil_rx_rssi_bins_[bin];
  }
  static std::uint32_t missing(const EspNowRuntime& runtime) noexcept {
    return runtime.hil_rx_missing_rssi_;
  }
#endif
};
}  // namespace routeloom::espnow

namespace {
int failures = 0;
#define CHECK(expr)                                                                    \
  do {                                                                                 \
    if (!(expr)) {                                                                     \
      std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__, #expr);         \
      ++failures;                                                                      \
    }                                                                                  \
  } while (false)

using routeloom::espnow::EspNowRuntime;
using routeloom::espnow::EspNowRuntimeConfig;
using Access = routeloom::espnow::EspNowRuntimeTestAccess;

EspNowRuntimeConfig config() {
  EspNowRuntimeConfig result{};
  result.node.network = 7;
  result.node.node = 1;
  result.node.message_session = 1;
  result.node.boot_incarnation = 1;
  result.channel = 6;
  result.max_tx_power_qdbm = 8;
  return result;
}

void test_receive_boundaries(const bool bootstrap) {
  idf_stub::reset();
  routeloom_test::TestSecurity security;
  routeloom_test::CapturingObserver observer;
  EspNowRuntime runtime(config(), security, observer);
  CHECK(runtime.initialize().ok());
  if (!bootstrap) CHECK(runtime.start().ok());
  routeloom::espnow::MacAddress mac{{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x02}};
  CHECK(runtime.register_neighbor(2, mac, 1).ok());
  std::uint8_t dest[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  wifi_pkt_rx_ctrl_t ctrl{};
  ctrl.channel = 6;
  esp_now_recv_info_t info{mac.bytes.data(), dest, &ctrl};
  const int threshold = CONFIG_ROUTELOOM_HIL_RX_MIN_RSSI;
  const int samples[] = {threshold == 0 ? -128 : threshold - 1,
                        threshold == 0 ? -80 : threshold,
                        threshold == 0 ? -1 : threshold + 1};
  unsigned expected_rssi_drops = 0;
  unsigned expected_random_drops = 0;
  [[maybe_unused]] std::array<std::uint32_t, 16> expected_bins{};
  for (const int rssi : samples) {
    ++expected_bins[static_cast<std::size_t>((rssi + 128) / 8)];
    ctrl.rssi = static_cast<std::int8_t>(rssi);
    idf_stub::set_random(UINT32_MAX);
    const unsigned calls = idf_stub::random_calls();
    Access::receive(info, bootstrap);
    const bool rssi_drop = threshold != 0 && rssi < threshold;
    const bool random_drop = !rssi_drop && CONFIG_ROUTELOOM_HIL_RX_DROP_PERMILLE == 1000;
    expected_rssi_drops += rssi_drop;
    expected_random_drops += random_drop;
    CHECK(Access::queued(runtime, bootstrap) == (rssi_drop || random_drop ? 0u : 1u));
    CHECK(idf_stub::random_calls() - calls ==
          (!rssi_drop && CONFIG_ROUTELOOM_HIL_RX_DROP_PERMILLE != 0 ? 1u : 0u));
    Access::drain(runtime);
  }
  // Absent RX metadata bypasses RSSI only; probability still applies.
  info.rx_ctrl = nullptr;
  Access::receive(info, bootstrap);
  CHECK(Access::queued(runtime, bootstrap) ==
        (CONFIG_ROUTELOOM_HIL_RX_DROP_PERMILLE == 1000 ? 0u : 1u));
  expected_random_drops += CONFIG_ROUTELOOM_HIL_RX_DROP_PERMILLE == 1000;
  Access::drain(runtime);
#if CONFIG_ROUTELOOM_HIL_RX_DROP_PERMILLE != 0
  constexpr std::uint64_t boundary =
      ((std::uint64_t{CONFIG_ROUTELOOM_HIL_RX_DROP_PERMILLE} << 32) + 999) / 1000;
  const std::uint32_t random_samples[] = {
      0, static_cast<std::uint32_t>(boundary - 1),
      static_cast<std::uint32_t>(boundary), UINT32_MAX};
  for (std::size_t i = 0; i < std::size(random_samples); ++i) {
    idf_stub::set_random(random_samples[i]);
    Access::receive(info, bootstrap);
    const bool drop = CONFIG_ROUTELOOM_HIL_RX_DROP_PERMILLE == 1000 || i < 2;
    expected_random_drops += drop;
    CHECK(Access::queued(runtime, bootstrap) == (drop ? 0u : 1u));
    Access::drain(runtime);
  }
#endif
  CHECK(runtime.rx_dropped() == 0);
  CHECK(runtime.bootstrap_rx_dropped() == 0);
#if CONFIG_ROUTELOOM_HIL_RX_MIN_RSSI != 0 || CONFIG_ROUTELOOM_HIL_RX_DROP_PERMILLE != 0
  CHECK(Access::rssi_drops(runtime) == expected_rssi_drops);
  CHECK(Access::random_drops(runtime) == expected_random_drops);
  for (std::size_t i = 0; i < expected_bins.size(); ++i) {
    CHECK(Access::rssi_bin(runtime, i) == expected_bins[i]);
  }
  CHECK(Access::missing(runtime) == (CONFIG_ROUTELOOM_HIL_RX_DROP_PERMILLE != 0 ? 5u : 1u));
  CHECK(!idf_stub::log_contains("HIL RX"));
  idf_stub::advance_ms(60000);
  runtime.poll_once();
  CHECK(idf_stub::log_contains("HIL RX"));
  CHECK(idf_stub::log_contains("HIL RSSI low=-128 high=-121"));
#else
  CHECK(expected_rssi_drops == 0 && expected_random_drops == 0);
  CHECK(idf_stub::random_calls() == 0);
  idf_stub::advance_ms(60000);
  runtime.poll_once();
  CHECK(!idf_stub::log_contains("HIL RX"));
#endif
  runtime.stop();
}
}  // namespace

int main() {
  test_receive_boundaries(false);
  test_receive_boundaries(true);
  return failures == 0 ? 0 : 1;
}
