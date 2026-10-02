#include <array>
#include <cstdio>

#include "hil_rx_allow_list.hpp"
#include "routeloom/espnow_runtime.hpp"
#include "routeloom/autonomy_wire.hpp"
#include "idf_stubs.hpp"
#include "test_security.hpp"
#include "test_sim.hpp"

namespace routeloom::espnow {
struct EspNowRuntimeTestAccess {
  static unsigned queued(const EspNowRuntime& runtime, bool bootstrap) noexcept {
    return uxQueueMessagesWaiting(bootstrap ? runtime.bootstrap_queue_ : runtime.event_queue_);
  }
};
}  // namespace routeloom::espnow

namespace {
int failures = 0;
#define CHECK(expr)                                                        \
  do {                                                                    \
    if (!(expr)) {                                                        \
      std::fprintf(stderr, "CHECK failed at %d: %s\n", __LINE__, #expr);     \
      ++failures;                                                         \
    }                                                                     \
  } while (false)

void test_parse() {
  using routeloom::espnow::parse_hil_rx_allow_list;
  constexpr auto list = parse_hil_rx_allow_list("AA:bb:CC:dd:EE:ff,11:22:33:44:55:66");
  static_assert(list.valid && list.count == 2 && list.macs[0][0] == 0xaa);
  static_assert(parse_hil_rx_allow_list("").valid);
  static_assert(!parse_hil_rx_allow_list("aa:bb:cc:dd:ee:f").valid);
  constexpr auto full = parse_hil_rx_allow_list(
      "00:00:00:00:00:01,00:00:00:00:00:02,00:00:00:00:00:03,00:00:00:00:00:04,"
      "00:00:00:00:00:05,00:00:00:00:00:06,00:00:00:00:00:07,00:00:00:00:00:08");
  static_assert(full.valid && full.count == 8);
  CHECK(list.allows(list.macs[0].data()));
  CHECK(list.allows(list.macs[1].data()));
  CHECK(full.allows(full.macs[7].data()));
  for (const char* invalid : {"a", "aa:bb:cc:dd:ee:f", "aa-bb:cc:dd:ee:ff",
                              "gg:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff,",
                              ",aa:bb:cc:dd:ee:ff", " aa:bb:cc:dd:ee:ff",
                              "aa:bb:cc:dd:ee:ff:00",
                              "00:00:00:00:00:01,00:00:00:00:00:02,00:00:00:00:00:03,"
                              "00:00:00:00:00:04,00:00:00:00:00:05,00:00:00:00:00:06,"
                              "00:00:00:00:00:07,00:00:00:00:00:08,00:00:00:00:00:09"}) {
    CHECK(!parse_hil_rx_allow_list(invalid).valid);
  }
}

void test_receive() {
  using namespace routeloom::espnow;
  idf_stub::reset();
  routeloom_test::TestSecurity security;
  routeloom_test::CapturingObserver observer;
  EspNowRuntimeConfig config{};
  config.node.network = 1;
  config.node.node = 1;
  config.node.message_session = 1;
  config.node.boot_incarnation = 1;
  config.node.link_epoch = 1;
  config.node.end_epoch = 1;
  config.channel = 6;
  config.max_tx_power_qdbm = 80;
  EspNowRuntime runtime(config, security, observer);
  CHECK(runtime.initialize().ok());
  const std::array<std::array<std::uint8_t, 6>, 3> sources{{
      {{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01}},
      {{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x02}},
      {{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x03}},
  }};
  const std::array<std::array<std::uint8_t, 6>, 2> destinations{{
      {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}}, {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
  }};
  std::array<std::uint8_t, routeloom::autonomy::kRld1HeaderSize> rld1{};
  rld1[0] = 'R'; rld1[1] = 'L'; rld1[2] = 'D'; rld1[3] = '1';
  rld1[4] = routeloom::autonomy::kRld1Version;
  rld1[5] = static_cast<std::uint8_t>(routeloom::FrameType::Discover);
  rld1[7] = rld1.size();
  rld1[9] = rld1.size();
  const std::uint8_t wire = 0;
  unsigned bootstrap_count = 0;
  unsigned wire_count = 0;
  for (std::size_t i = 0; i < sources.size(); ++i) {
    MacAddress mac{};
    mac.bytes = sources[i];
    CHECK(runtime.register_neighbor(i + 2, mac, 1).ok());
    // Sender 2 is allowed but blocked by the legacy drop setting.
    const bool accepted = sizeof(CONFIG_ROUTELOOM_HIL_RX_ALLOW_MACS) == 1 || i == 0;
    for (const auto& destination : destinations) {
      CHECK(idf_stub::inject_rx(sources[i].data(), destination.data(), rld1.data(), rld1.size()));
      CHECK(idf_stub::inject_rx(sources[i].data(), destination.data(), &wire, 1));
      if (accepted) { ++bootstrap_count; ++wire_count; }
      CHECK(EspNowRuntimeTestAccess::queued(runtime, true) == bootstrap_count);
      CHECK(EspNowRuntimeTestAccess::queued(runtime, false) == wire_count);
    }
  }
  runtime.stop();
}
}  // namespace

int main() {
  test_parse();
  test_receive();
  return failures == 0 ? 0 : 1;
}
