#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <new>

#include "driver/usb_serial_jtag.h"
#include "esp_app_desc.h"
#include "esp_heap_caps.h"
#include "esp_random.h"
#include "esp_rom_sys.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "soc/reset_reasons.h"
#include "esp_attr.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_sleep.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "routeloom/nvs_boot_session.hpp"
#include "routeloom/nvs_legacy_purge.hpp"
#include "sdkconfig.h"
// LegacyFixture keeps its own remote-config wiring until its removal
// (V2-10); the Owner profiles use Device's (device_config.cpp).
#define ROUTELOOM_LEGACY_CONFIG \
  (CONFIG_ROUTELOOM_CONFIG && CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE)
// The same for channel migration (MemberEdhoc: device_migration.cpp).
#define ROUTELOOM_LEGACY_MIGRATION \
  (CONFIG_ROUTELOOM_MIGRATION && CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE)
#if CONFIG_ROUTELOOM_DISCOVERY || ROUTELOOM_LEGACY_CONFIG
#include "routeloom/espnow_autonomy.hpp"
#endif
#if CONFIG_ROUTELOOM_DISCOVERY
#include "routeloom/espnow_scope_provider.hpp"
#endif
#if ROUTELOOM_LEGACY_MIGRATION
#include "routeloom/espnow_migration.hpp"
#include "routeloom/nvs_ledger_store.hpp"
#endif
#if ROUTELOOM_LEGACY_CONFIG
#include "device_config_provider.hpp"
#include "routeloom/config.hpp"
#include "routeloom/config_cose.hpp"
#include "routeloom/config_dev.hpp"
#include "routeloom/config_wire.hpp"
#include "routeloom/discovery_scope.hpp"  // sha256
#include "routeloom/nvs_config_store.hpp"
#include "routeloom/nvs_security_floor.hpp"
#endif
#if CONFIG_ROUTELOOM_TRUST_STORE
#include "routeloom/device_credential.hpp"
#include "routeloom/nvs_cred_store.hpp"
#include "routeloom/nvs_trust_store.hpp"
#include "routeloom/trust_view.hpp"
#endif
#include "routeloom/espnow_power.hpp"
#include "routeloom/espnow_flash_layout.hpp"
#include "routeloom/espnow_runtime.hpp"
#include "routeloom/espnow_sdkv1.hpp"
#include "routeloom/rlcw1.hpp"
#include "routeloom/profile.hpp"
#include "routeloom/sdkv1_session_rtc.hpp"
#include "routeloom/fail_policy.hpp"
#include "routeloom/hex.hpp"
#include "routeloom/nvs_counter_store.hpp"
#include "routeloom/power.hpp"
#if !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
#include "routeloom/board_secrets.hpp"
#include "routeloom/espnow_board_config.hpp"
#include "routeloom/espnow_sdkv1_entropy.hpp"
#include "routeloom/espnow_security_owner.hpp"
#include "routeloom/owner_pump.hpp"
#else
#include "routeloom/psk_security.hpp"
#endif
#include "routeloom/device.hpp"
#include "routeloom/observation.hpp"
#include "routeloom/secure_clear.hpp"

namespace {
// The app supplies its tag through DeviceConfig::log_tag so a site mixing
// images can tell them apart in a captured log.
const char* kTag = "RouteLoomNode";

// NVS codec state uses CPU-only reads and writes, so C5 Owner profiles
// keep it in LP SRAM while HP SRAM remains available to radio traffic.
#if (CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC || \
     CONFIG_ROUTELOOM_SECURITY_MODE_DEV_RAM) && \
    CONFIG_IDF_TARGET_ESP32C5
#define ROUTELOOM_OWNER_C5_LP RTC_DATA_ATTR
#else
#define ROUTELOOM_OWNER_C5_LP
#endif

#if (CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC || \
     CONFIG_ROUTELOOM_SECURITY_MODE_DEV_RAM) && CONFIG_IDF_TARGET_ESP32C3
#define ROUTELOOM_MEMBER_SMALL_LP RTC_DATA_ATTR
#else
#define ROUTELOOM_MEMBER_SMALL_LP
#endif

using routeloom::ByteView;
using routeloom::DeliveryResult;
using routeloom::MessageId;
using routeloom::MessageKey;
using routeloom::NodeId;
using routeloom::NodeObserver;
using routeloom::Status;
using routeloom::StatusCode;
#if !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
using routeloom::espnow::EspNowSecurityOwner;
using routeloom::espnow::EspOwnerEntropy;
#else
using routeloom::espnow::DevelopmentPskSecurityProvider;
#endif
using routeloom::espnow::EspNowPowerPort;
using routeloom::espnow::EspNowRuntime;
using routeloom::espnow::EspNowRuntimeConfig;
using routeloom::espnow::MacAddress;
using routeloom::espnow::NvsCounterStore;
using routeloom::espnow::NvsSleepStorage;

[[maybe_unused]] int hex_value(const char value) noexcept {
  if (value >= '0' && value <= '9') return value - '0';
  const char lower =
      static_cast<char>(std::tolower(static_cast<unsigned char>(value)));
  if (lower >= 'a' && lower <= 'f') return lower - 'a' + 10;
  return -1;
}

template <std::size_t Size>
[[maybe_unused]] bool parse_hex(const char* text,
                                std::array<std::uint8_t, Size>& output) noexcept {
  if (text == nullptr || std::strlen(text) != Size * 2U) return false;
  for (std::size_t i = 0; i < Size; ++i) {
    const int high = hex_value(text[i * 2]);
    const int low = hex_value(text[i * 2 + 1]);
    if (high < 0 || low < 0) return false;
    output[i] = static_cast<std::uint8_t>((high << 4) | low);
  }
  return true;
}

[[maybe_unused]] bool parse_mac(const char* text, MacAddress& mac) noexcept {
  if (text == nullptr) return false;
  unsigned values[6]{};
  if (std::sscanf(text, "%2x:%2x:%2x:%2x:%2x:%2x", &values[0],
                  &values[1], &values[2], &values[3], &values[4],
                  &values[5]) != 6) {
    return false;
  }
  for (std::size_t i = 0; i < mac.bytes.size(); ++i) {
    if (values[i] > 0xffU) return false;
    mac.bytes[i] = static_cast<std::uint8_t>(values[i]);
  }
  return true;
}

// .rtc_noinit is the only RAM the boot path never re-initializes, so it is
// what actually survives esp_restart and the deep-sleep wake used below
// (.rtc.data is re-copied from the image on every non-deep-sleep reset).
// Power-on leaves it garbage, so a magic word tells a real streak from
// random RAM. The streak drives routeloom::fail_action — backoff restarts
// first, a long deep sleep once the fault proves persistent. It clears
// only on a stability proof — the runtime task starting on the always-on
// build, an actually-entered coordinated sleep (the port's pre-sleep
// hook) on the DEEP_SLEEP build — or on power-on, never mid-boot: a fault
// late in the awake window must keep the count. The routeloom
// fail_streak_* calls are its only writers.
RTC_NOINIT_ATTR routeloom::FailStreak s_fail;

[[noreturn]] void fail(const char* detail) {
  const std::uint32_t streak = routeloom::fail_streak_consume(s_fail);
  const routeloom::FailAction action = routeloom::fail_action(streak);
  if (action.deep_sleep) {
    // Persistent fault: every further restart is one more NVS session write
    // with no recovery evidence. Stop the radio first — sleeping with the
    // Wi-Fi driver live is the contract violation enter_sleep() guards
    // against — then halt at deep-sleep current; the streak survives in
    // .rtc_noinit so each timer wake keeps the same bounded cadence. The
    // marker stays clear: this is a fault halt, not a coordinated sleep,
    // so the DEEP_SLEEP profile's classify_boot() reports the wake as
    // OtherReset rather than a resume.
    const bool wake_armed = esp_sleep_enable_timer_wakeup(
        static_cast<std::uint64_t>(action.delay_ms) * 1000ULL) == ESP_OK;
    ESP_LOGE(kTag, "fatal: %s (streak=%lu, deep sleep %lu ms%s)", detail,
             static_cast<unsigned long>(streak + 1U),
             static_cast<unsigned long>(action.delay_ms),
             wake_armed ? "" : "; wake timer arm FAILED");
    (void)esp_wifi_stop();
    vTaskDelay(pdMS_TO_TICKS(100));  // let the fatal line reach the UART
    esp_deep_sleep_start();
  }
  ESP_LOGE(kTag, "fatal: %s (streak=%lu, restart in %lu ms)", detail,
           static_cast<unsigned long>(streak + 1U),
           static_cast<unsigned long>(action.delay_ms));
  vTaskDelay(pdMS_TO_TICKS(action.delay_ms));
  esp_restart();
}

#if !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE && !CONFIG_ROUTELOOM_DEV_KCONFIG_IDENTITY
// CONFIG_REQUIRED is an operator step, not a transient fault: it never
// feeds the fail streak, whose deep sleep would hide the USB port for
// 30 minutes. RF has not started; the board stays awake and repeats the
// line so the setup image and BoardConfig can be written over USB.
[[noreturn]] void config_required(const char* detail) {
  for (;;) {
    ESP_LOGE(kTag, "CONFIG_REQUIRED: %s", detail);
    vTaskDelay(pdMS_TO_TICKS(10000));
  }
}
#endif

// Used by the CONFIG and DEEP_SLEEP opt-in paths only; in a default build it
// has no caller, so it is marked maybe_unused rather than deleted.
[[maybe_unused]] routeloom::MonotonicMs monotonic_now_ms() noexcept {
  return static_cast<routeloom::MonotonicMs>(esp_timer_get_time() / 1000);
}

#if CONFIG_ROUTELOOM_DEEP_SLEEP

// RTC slow-memory marker: written right before esp_deep_sleep_start and
// cleared on boot. Lost on a full power cut — exactly the cases that must
// not be classified as a sleep resume. The programmed timer duration rides
// alongside so the wake can prove a trusted slept-time lower bound (P4
// §9.3); it is one-shot — a reset without a new sleep must not reuse it.
RTC_DATA_ATTR std::uint32_t s_sleep_marker = 0;
RTC_DATA_ATTR std::uint32_t s_sleep_programmed_ms = 0;
constexpr std::uint32_t kSleepMarkerValue = 0x524c5057;  // "RLPW"

#if CONFIG_ROUTELOOM_DEEP_SLEEP && CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC
// Owner sleep tail (P4 §9.3, V1-F07): the retained session image in RTC
// slow memory, the only RAM surviving deep sleep. Zero after any
// non-sleep reset (re-copied from the image) — decode refuses those, so
// no validity claim rides on the backing itself.
RTC_DATA_ATTR std::array<std::uint8_t, routeloom::sdkv1::kRtcSessionRecordSize>
    s_rtc_session{};
// The consumed image waits here until the parent binds; the always-on
// security Owner does not reserve this space in gateway HP SRAM.
RTC_DATA_ATTR routeloom::sdkv1::RtcSessionImage s_rtc_hold{};
#endif

class LogPowerEvents final : public routeloom::PowerEvents {
 public:
  void on_transition(const routeloom::PowerState from,
                     const routeloom::PowerState to,
                     const char* reason) noexcept override {
    ESP_LOGI(kTag, "power %s -> %s (%s)", routeloom::power_state_name(from),
             routeloom::power_state_name(to), reason);
  }
  void on_pending_result(const routeloom::PendingDeliveryRecord& record,
                         const routeloom::StatusCode result) noexcept override {
    ESP_LOGI(kTag, "pending %lu/%llu -> %u",
             static_cast<unsigned long>(record.original_id.session),
             static_cast<unsigned long long>(record.original_id.sequence),
             static_cast<unsigned>(result));
  }
  void on_diagnostic(const char* reason) noexcept override {
    ESP_LOGW(kTag, "power diagnostic: %s", reason);
  }
};

// The boot-fault streak's only stability proof in this profile: an
// actually-entered coordinated sleep. The port fires the hook after the
// Wi-Fi driver is stopped, immediately before esp_deep_sleep_start() —
// every fallible step of the awake window (boot, drain, image commit,
// wake configuration) is already behind it, so a persistent late-boot
// fault keeps the count and escalates to the bounded halt instead of
// re-arming the fast restart every ~40 s cycle.
class FailStreakClearOnSleep final : public routeloom::espnow::PreSleepHook {
 public:
  void on_pre_sleep() noexcept override {
    routeloom::fail_streak_pre_sleep(s_fail);
  }
};

routeloom::ResetCause classify_boot(bool& marked) noexcept {
  const esp_reset_reason_t reason = esp_reset_reason();
  marked = s_sleep_marker == kSleepMarkerValue;
  s_sleep_marker = 0;
  if (routeloom::trusted_deep_sleep_reset(reason == ESP_RST_DEEPSLEEP, marked)) {
    return routeloom::ResetCause::DeepSleepWake;
  }
  if (reason == ESP_RST_POWERON || reason == ESP_RST_BROWNOUT ||
      reason == ESP_RST_UNKNOWN) {
    return routeloom::ResetCause::ColdBoot;
  }
  return routeloom::ResetCause::OtherReset;
}

// A marked timer wake proves the wake source, not an elapsed-time upper
// bound: RTC slow-clock drift and time spent rebooting are not bounded by
// the programmed duration. Park durable pendings TIME_UNCERTAIN until an
// independently bounded elapsed interval is available.
routeloom::ElapsedInterval classify_wake_elapsed(const routeloom::ResetCause cause,
                                                 const bool marked) noexcept {
  const std::uint32_t programmed = s_sleep_programmed_ms;
  s_sleep_programmed_ms = 0;
  return routeloom::classify_sleep_elapsed(
      cause == routeloom::ResetCause::DeepSleepWake,
      esp_sleep_get_wakeup_cause() == ESP_SLEEP_WAKEUP_TIMER, marked,
      programmed, /*trusted_upper_ms=*/0);
}

#endif  // CONFIG_ROUTELOOM_DEEP_SLEEP



// --- Read-only device observation (observation_v1) -------------------------------
// System health from ESP-IDF, table occupancy from the MeshNode, sessions and
// join milestones from the security coordinator (LegacyFixture reports them
// unknown). Served to the USB host on a gateway and to end-protected remote
// queries elsewhere. Lives on the Owner task frame: no static RAM.
class EspSystemHealthPort final : public routeloom::SystemHealthPort {
 public:
  std::uint32_t heap_free_bytes() const noexcept override {
    return static_cast<std::uint32_t>(esp_get_free_heap_size());
  }
  std::uint32_t heap_min_bytes() const noexcept override {
    return static_cast<std::uint32_t>(esp_get_minimum_free_heap_size());
  }
  std::uint32_t heap_largest_bytes() const noexcept override {
    return static_cast<std::uint32_t>(heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT));
  }
  std::uint8_t reset_code() const noexcept override {
    // Mask-ROM reason, never esp_reset_reason(): the cached IDF API pulls
    // reset_reason.c (IRAM .text + .data + assert literals, about 164 B of
    // guarded DRAM) for no extra evidence here.
    switch (esp_rom_get_reset_reason(0)) {
      case RESET_REASON_CHIP_POWER_ON:
        return routeloom::kResetPowerOn;
      case RESET_REASON_CORE_SW:
      case RESET_REASON_CPU0_SW:
        return routeloom::kResetSoftware;
      case RESET_REASON_CORE_MWDT0:
      case RESET_REASON_CORE_MWDT1:
      case RESET_REASON_CORE_RTC_WDT:
      case RESET_REASON_CPU0_MWDT0:
      case RESET_REASON_CPU0_MWDT1:
      case RESET_REASON_CPU0_RTC_WDT:
      case RESET_REASON_SYS_RTC_WDT:
      case RESET_REASON_SYS_SUPER_WDT:
        return routeloom::kResetWatchdog;
      case RESET_REASON_CORE_DEEP_SLEEP:
        return routeloom::kResetDeepSleepWake;
      case RESET_REASON_SYS_BROWN_OUT:
        return routeloom::kResetBrownout;
      case RESET_REASON_CORE_EFUSE_CRC:
      case RESET_REASON_CORE_USB_UART:
      case RESET_REASON_CORE_USB_JTAG:
#if CONFIG_IDF_TARGET_ESP32C3 || CONFIG_IDF_TARGET_ESP32S3
      case RESET_REASON_SYS_CLK_GLITCH:
      case RESET_REASON_CORE_PWR_GLITCH:
#endif
#if CONFIG_IDF_TARGET_ESP32C5
      case RESET_REASON_CPU0_JTAG:
      case RESET_REASON_CORE_PWR_GLITCH:
      case RESET_REASON_CPU0_LOCKUP:
#endif
        return routeloom::kResetOther;
      default:
        return routeloom::kResetUnknown;
    }
  }
};

class DeviceObservationSource final : public routeloom::ObservationSource {
 public:
  DeviceObservationSource(const routeloom::MeshNode& node,
                          const routeloom::sdkv1::SecurityCoordinator* coordinator,
                          const std::uint64_t boot_id, const std::uint8_t profile) noexcept
      : node_(node), coordinator_(coordinator), boot_id_(boot_id), profile_(profile) {}

  bool fill_system(routeloom::MonotonicMs now_ms,
                   routeloom::ObservationSystem& out) const noexcept override {
    std::uint8_t power = routeloom::kPowerRunning;
    std::uint8_t mode = routeloom::kCoordModeUnknown;
#if !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
    if (coordinator_ != nullptr) {
      const routeloom::sdkv1::CoordinatorSnapshot snapshot = coordinator_->snapshot();
      power = snapshot.sleeping ? routeloom::kPowerSleeping : routeloom::kPowerRunning;
      mode = map_mode(snapshot.mode);
    }
#endif
    routeloom::fill_observation_system(boot_id_, now_ms, port_, power, mode, profile_, out);
    return true;
  }

  bool fill_tables(routeloom::MonotonicMs now_ms,
                   routeloom::ObservationTables& out) const noexcept override {
    std::uint16_t link = 0, link_cap = 0, end = 0, end_cap = 0;
#if !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
    if (coordinator_ != nullptr) {
      const routeloom::sdkv1::CoordinatorSnapshot snapshot = coordinator_->snapshot();
      link = snapshot.link_sessions > UINT16_MAX
                 ? UINT16_MAX
                 : static_cast<std::uint16_t>(snapshot.link_sessions);
      end = snapshot.end_sessions > UINT16_MAX ? UINT16_MAX
                                               : static_cast<std::uint16_t>(snapshot.end_sessions);
      link_cap = static_cast<std::uint16_t>(routeloom::sdkv1::ProfileSessionBank::link_capacity());
      end_cap = static_cast<std::uint16_t>(routeloom::sdkv1::ProfileSessionBank::end_capacity());
    }
#endif
    routeloom::fill_observation_tables(node_, now_ms, link, link_cap, end, end_cap, out);
    return true;
  }

  bool fill_milestones(routeloom::MonotonicMs now_ms,
                       routeloom::JoinMilestones& out) const noexcept override {
#if !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
    out = coordinator_ != nullptr ? coordinator_->milestones(now_ms) : routeloom::JoinMilestones{};
#else
    static_cast<void>(now_ms);
    out = routeloom::JoinMilestones{};
#endif
    return true;
  }

  bool fill_summary(routeloom::MonotonicMs now_ms,
                    routeloom::ObservationSummary& out) const noexcept override {
    // A gateway's bridge overwrites the zero milestone generation it owns.
    routeloom::fill_observation_summary(node_, now_ms, 0, out);
    out.neighbor_digest = routeloom::observation_neighbor_source_digest(*this, now_ms);
    return true;
  }

  std::size_t route_detail_page(routeloom::NodeId after, routeloom::RouteDetailEntry* out,
                                std::size_t capacity, routeloom::MonotonicMs now_ms,
                                bool& more) const noexcept override {
    return node_.route_detail_page(after, out, capacity, now_ms, more);
  }

  bool route_detail_exact(routeloom::NodeId destination, routeloom::MonotonicMs now_ms,
                          routeloom::RouteDetailEntry& out) const noexcept override {
    return node_.route_detail(destination, now_ms, out);
  }

  std::size_t neighbor_detail_page(routeloom::NodeId after, routeloom::NeighborDetailEntry* out,
                                   std::size_t capacity, routeloom::MonotonicMs now_ms,
                                   bool& more) const noexcept override {
    return routeloom::neighbor_detail_page(node_, live_discovery(), after, out, capacity, now_ms,
                                           more);
  }

  bool neighbor_detail_exact(routeloom::NodeId peer, routeloom::MonotonicMs now_ms,
                             routeloom::NeighborDetailEntry& out) const noexcept override {
    return routeloom::neighbor_detail_exact(node_, live_discovery(), peer, now_ms, out);
  }

 private:
#if !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
  static std::uint8_t map_mode(routeloom::sdkv1::CoordinatorMode mode) noexcept {
    switch (mode) {
      case routeloom::sdkv1::CoordinatorMode::Fresh:
        return routeloom::kCoordModeFresh;
      case routeloom::sdkv1::CoordinatorMode::ZeroTouch:
        return routeloom::kCoordModeZeroTouch;
      case routeloom::sdkv1::CoordinatorMode::Member:
        return routeloom::kCoordModeMember;
      case routeloom::sdkv1::CoordinatorMode::Dev:
        return routeloom::kCoordModeDev;
      case routeloom::sdkv1::CoordinatorMode::Removed:
        return routeloom::kCoordModeRemoved;
      case routeloom::sdkv1::CoordinatorMode::Recovery:
        return routeloom::kCoordModeRecovery;
    }
    return routeloom::kCoordModeUnknown;
  }
#endif

  // Live discovery for neighbor phase/lease (null without a coordinator).
  const routeloom::NeighborDiscovery* live_discovery() const noexcept {
#if !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
    if (coordinator_ != nullptr) return coordinator_->discovery();
#endif
    return nullptr;
  }

  const routeloom::MeshNode& node_;
  [[maybe_unused]] const routeloom::sdkv1::SecurityCoordinator* coordinator_;
  EspSystemHealthPort port_;
  std::uint64_t boot_id_;
  std::uint8_t profile_;
};

// Reached only through Device::enable_observation(), so an image that serves
// no observation links none of the code above.
const routeloom::ObservationSource* build_observation(void* slot, routeloom::Device& device,
                                                      const std::uint8_t profile) noexcept {
  const routeloom::MeshNode& node = *device.mesh();
  return new (slot) DeviceObservationSource(node, device.security(),
                                            node.config().boot_incarnation, profile);
}

#if CONFIG_ROUTELOOM_ROLE_GATEWAY
// The USB bridge frames COBS+CRC32 through this stream. The write never
// blocks: the Owner task pumps the mesh RX path too, so a host that stopped
// draining must not stall it. A full TX buffer reports written=0 and the
// bridge resumes from where it stopped on the next poll.
class UsbSerialStream final : public routeloom::usb::ByteStream {
 public:
  Status write(ByteView data, std::size_t& written) noexcept override {
    written = 0;
    if (data.data == nullptr || data.size == 0) return Status::success();
    const int result = usb_serial_jtag_write_bytes(data.data, data.size, 0);
    if (result < 0) return Status::error(StatusCode::RadioFailure, "usb jtag write failed");
    written = static_cast<std::size_t>(result);
    return Status::success();
  }
};
#endif

}  // namespace

namespace routeloom {

DeviceConfig device_config_from_kconfig() noexcept {
  DeviceConfig config{};
  config.role = profile::kRole;
#if CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC
  config.security = DeviceSecurity::Member;
#else
  config.security = DeviceSecurity::DevRam;
#endif
  // Kconfig identity: field images replace it from the verified BoardConfig.
  config.radio.node.network = CONFIG_ROUTELOOM_NETWORK_ID;
  config.radio.node.node = CONFIG_ROUTELOOM_NODE_ID;
  config.radio.channel = CONFIG_ROUTELOOM_CHANNEL;
  config.radio.max_tx_power_qdbm = CONFIG_ROUTELOOM_TX_POWER_QDBM;
#if CONFIG_ROUTELOOM_ROUTE_GATEWAY_SCOPED
  // Gateway-scoped routing profile (routing-scale.md, issue #41). A
  // violating lease would only surface at boot as
  // ROUTE_LIFETIME_BELOW_REFRESH_BOUND; refuse the build instead.
  static_assert(scoped_lifetime_sufficient(
                    static_cast<std::uint32_t>(CONFIG_ROUTELOOM_ROUTE_PERIOD_MS),
                    static_cast<std::uint32_t>(CONFIG_ROUTELOOM_ROUTE_LIFETIME_MS),
                    kScopedDefaultRefreshTicks),
                "ROUTELOOM_ROUTE_LIFETIME_MS below (2 * 6 + 2) * ROUTELOOM_ROUTE_PERIOD_MS");
#if CONFIG_ROUTELOOM_ROLE_GATEWAY
  // The gateway lists itself first (its verified NodeId, set at boot).
  static_assert(CONFIG_ROUTELOOM_ROUTE_GATEWAY_2 != CONFIG_ROUTELOOM_NODE_ID,
                "ROUTELOOM_ROUTE_GATEWAY_2 must differ from this gateway's NODE_ID");
  config.radio.node.route_gateways[0] = config.radio.node.node;
#else
  static_assert(CONFIG_ROUTELOOM_ROUTE_GATEWAY_1 != 0,
                "ROUTELOOM_ROUTE_GATEWAY_1 must name the site gateway");
  static_assert(CONFIG_ROUTELOOM_ROUTE_GATEWAY_2 != CONFIG_ROUTELOOM_ROUTE_GATEWAY_1,
                "ROUTELOOM_ROUTE_GATEWAY_2 must differ from GATEWAY_1");
  config.radio.node.route_gateways[0] = static_cast<NodeId>(CONFIG_ROUTELOOM_ROUTE_GATEWAY_1);
#endif
  config.radio.node.route_gateways[1] = static_cast<NodeId>(CONFIG_ROUTELOOM_ROUTE_GATEWAY_2);
  config.radio.node.route_advertisement_period_ms =
      static_cast<std::uint32_t>(CONFIG_ROUTELOOM_ROUTE_PERIOD_MS);
  config.radio.node.route_lifetime_ms =
      static_cast<std::uint32_t>(CONFIG_ROUTELOOM_ROUTE_LIFETIME_MS);
#if CONFIG_ROUTELOOM_ROUTE_BROADCAST
  config.radio.node.route_broadcast = true;
#endif
#endif
#if CONFIG_ROUTELOOM_GROUP_TREE_FLAT
  config.flat_group_routing = true;
#endif
#if CONFIG_ROUTELOOM_ROLE_GATEWAY
  config.usb_capability = CONFIG_ROUTELOOM_CAPABILITY;
#endif
#if ROUTELOOM_DEVICE_MIGRATION
  config.channel_plan = CONFIG_ROUTELOOM_MIGRATION;
  config.plan_rtt_p99_ms = CONFIG_ROUTELOOM_MIGRATION_RTT_P99_MS;
  config.plan_delivery_bound_ms = CONFIG_ROUTELOOM_MIGRATION_DELIVERY_BOUND_MS;
  config.plan_transfer_bound_ms = CONFIG_ROUTELOOM_MIGRATION_TRANSFER_BOUND_MS;
  config.plan_switch_bound_ms = CONFIG_ROUTELOOM_MIGRATION_SWITCH_BOUND_MS;
#endif
#if ROUTELOOM_DEVICE_REMOTE_CONFIG
  config.remote_config = true;
#if CONFIG_ROUTELOOM_SECURITY_MODE_DEV_RAM
  config.config_authority = static_cast<NodeId>(CONFIG_ROUTELOOM_CONFIG_AUTHORITY);
  config.config_authority_generation =
      static_cast<std::uint32_t>(CONFIG_ROUTELOOM_CONFIG_AUTHORITY_GENERATION);
#endif
#endif
  return config;
}

void Device::enable_observation() noexcept { observation_build_ = &build_observation; }

namespace {
struct OwnerHandoff {
  Device* device;
  DeviceConfig* config;
  std::atomic<bool> copied{false};
};
}  // namespace

void Device::start(DeviceConfig& config) noexcept {
  // Task creation can fail before the Owner reaches its boot path; fail()
  // must always consume an initialized RTC streak.
  fail_streak_boot(s_fail);
  OwnerHandoff handoff{this, &config};
  if (xTaskCreate(&Device::task_entry, "rl_owner", CONFIG_ROUTELOOM_OWNER_TASK_STACK_SIZE,
                  &handoff, CONFIG_ROUTELOOM_OWNER_TASK_PRIORITY, nullptr) != pdPASS) {
    secure_clear(config.dev_psk);
    fail("owner task create failed");
  }
  // The Owner task copies the configuration onto its own stack; the
  // caller's frame (normally app_main) may end after that.
  while (!handoff.copied.load()) vTaskDelay(1);
  secure_clear(config.dev_psk);
}

void Device::task_entry(void* argument) noexcept {
  OwnerHandoff& handoff = *static_cast<OwnerHandoff*>(argument);
  Device& device = *handoff.device;
  DeviceConfig config = *handoff.config;
  handoff.copied.store(true);
  // One tick lets app_main return and the idle task reclaim its stack
  // before the boot allocates the radio heap.
  vTaskDelay(1);
  device.boot_and_run(config);
}

void Device::boot_and_run(DeviceConfig& config) noexcept {
  kTag = config.log_tag;
  tag_ = config.log_tag;
  // PT-4M-v2 is checked before NVS: on another table the NVS labels could
  // point at foreign data.
  Status status = espnow::verify_flash_layout();
  if (!status) fail(status.detail);
  // Identity, nonce reservations, replay state and message sessions live in
  // NVS. Never erase it automatically after a version/capacity error: that
  // would silently turn a recoverable storage problem into key/counter
  // rollback.
  const esp_err_t nvs_error = nvs_flash_init();
  if (nvs_error != ESP_OK) {
    ESP_LOGE(kTag, "NVS init failed (%s); automatic erase is disabled, explicit recovery is required",
             esp_err_to_name(nvs_error));
    fail("NVS initialization failed");
  }
  status = open_storage(config.role, config.security);
  if (!status) fail(status.detail);
  const std::uint32_t message_session = boot_session_;
#if CONFIG_ROUTELOOM_MAINTENANCE_CONSOLE
  // Factory maintenance console (sdk-v1/07 §6): runs pre-RF and owns the
  // device and its USB from here — no radio, no mesh. Returns only when the
  // USB console itself cannot be set up.
  status = espnow::run_maintenance_console(*stores_);
  fail(status.detail);
#endif
  // 07 §6 shipping marker: this line only runs in the field build. The
  // office matches fw= against the flashed image's project_description.json,
  // app_sha256= against the signed bundle's application image, and the
  // `sdkv1 identity` node= above against the inventory row.
  const esp_app_desc_t* app_desc = esp_app_get_description();
  char app_sha256_hex[sizeof(app_desc->app_elf_sha256) * 2 + 1];
  hex_encode(app_desc->app_elf_sha256, sizeof(app_desc->app_elf_sha256), app_sha256_hex);
  ESP_LOGI(kTag, "routeloom field boot: fw=%s app_sha256=%s", app_desc->version, app_sha256_hex);

  if (esp_read_mac(config.mac.data(), ESP_MAC_WIFI_STA) != ESP_OK) {
    fail("station MAC unreadable");
  }
#if !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE && !CONFIG_ROUTELOOM_DEV_KCONFIG_IDENTITY
  // Generic field image (design-devflow §4.1): the durable BoardConfig in
  // `rlcfg` (and the `rlkeys` secrets it binds) is the only source of
  // NodeId/network/channel/secrets. The gate runs before anything that can
  // start the radio: a missing, impaired or mismatched record is refused,
  // never defaulted.
  static ROUTELOOM_OWNER_C5_LP ROUTELOOM_MEMBER_SMALL_LP espnow::BoardStores board_stores;
  status = board_stores.open(/*writable=*/false);
  if (status.code == routeloom::StatusCode::NotFound) config_required(status.detail);
  if (!status) fail(status.detail);
  status = board_stores.initialize();
  if (!status) fail(status.detail);
  BoardBootIdentity board_identity{};
  board_identity.chip = espnow::board_chip();
  board_identity.role =
      config.role == profile::Role::Gateway ? BoardRole::Bridge : BoardRole::Reference;
  if (config.security == DeviceSecurity::DevRam) {
    board_identity.security = BoardSecurity::DevRam;
  } else {
    board_identity.security = BoardSecurity::Member;
    // The bound RLI1 node is provable only from a healthy sealed store.
    if (stores_->identity().has_identity() && !stores_->identity().uncertain() &&
        !stores_->identity().quarantined()) {
      board_identity.rli_node = stores_->identity().identity().node_id;
    }
  }
  board_identity.sta_mac = config.mac;
  const BoardSecrets* board_secrets = nullptr;
  status = resolve_field_identity(board_stores.config(), board_stores.secrets(), board_identity,
                                  board_secrets);
  if (!status) config_required(status.detail);
  const BoardConfig& board = board_stores.config().config();
  ESP_LOGI(kTag, "board config: gen=%lu node=0x%llx secrets_gen=%lu mac=%02x%02x%02x%02x%02x%02x",
           static_cast<unsigned long>(board.generation),
           static_cast<unsigned long long>(board.node),
           static_cast<unsigned long>(board.secrets_generation), board.sta_mac[0],
           board.sta_mac[1], board.sta_mac[2], board.sta_mac[3], board.sta_mac[4],
           board.sta_mac[5]);
  config.radio.node.node = board.node;
  config.radio.node.network = board.network;
  config.radio.channel = board.channel;
#if CONFIG_ROUTELOOM_ROLE_GATEWAY
  // The USB session secret is the committed rlkeys value the gate bound.
  config.usb_secret = ByteView{board_secrets->usb_secret.data(), board_secrets->usb_len};
#endif
#endif
#if CONFIG_ROUTELOOM_ROLE_GATEWAY && CONFIG_ROUTELOOM_ROUTE_GATEWAY_SCOPED
  config.radio.node.route_gateways[0] = config.radio.node.node;
#endif
#if CONFIG_ROUTELOOM_ROUTE_GATEWAY_SCOPED
  ESP_LOGI(kTag,
           "routing profile: gateway-scoped gateways=0x%" PRIx64 ",0x%" PRIx64 " tick=%" PRIu32
           "ms lease=%" PRIu32 "ms broadcast=%d",
           config.radio.node.route_gateways[0], config.radio.node.route_gateways[1],
           config.radio.node.route_advertisement_period_ms, config.radio.node.route_lifetime_ms,
           config.radio.node.route_broadcast ? 1 : 0);
#endif

  if (espnow::nvs_namespace_in_use(NVS_DEFAULT_PART_NAME, "rlcounter") ||
      espnow::nvs_namespace_in_use(NVS_DEFAULT_PART_NAME, "rlreplay")) {
    ESP_LOGW(kTag,
             "legacy rlcounter/rlreplay state in the default NVS partition is orphaned "
             "(pre-rlsec layout); an explicit NVS erase reclaims it");
  }
#if CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
  status = espnow::refuse_legacy_boot_after_migration();
  if (!status) fail(status.detail);
  std::uint32_t peer_capacity = 0;
  status = espnow::nvs_partition_peer_capacity(
      espnow::kSecurityNvsPartition,
      config.role == profile::Role::Gateway ? espnow::kGatewayMaxPersistedPeers
                                            : espnow::kNodeMaxPersistedPeers,
      peer_capacity);
  if (!status) fail(status.detail);
  static NvsCounterStore counter_store;
  status = counter_store.open("rlcounter", espnow::kSecurityNvsPartition);
  if (!status) fail(status.detail);
  std::array<std::uint8_t, DevelopmentPskSecurityProvider::kMasterKeySize> key{};
  if (!parse_hex(CONFIG_ROUTELOOM_DEVELOPMENT_KEY_HEX, key)) fail("invalid development key");
  static DevelopmentPskSecurityProvider security;
  espnow::PeerStateConfig peer_state{};
  peer_state.replay_namespace = "rlreplay";
  peer_state.partition = espnow::kSecurityNvsPartition;
  // TX link/end epochs are the boot session: records of older epochs are
  // dead and swept (witness first); a session at or below the witness fails
  // closed here.
  peer_state.tx_epoch = message_session;
  peer_state.max_persisted_peers = peer_capacity;
  status = security.initialize(key, counter_store, peer_state);
  if (!status) fail(status.detail);
  espnow::log_peer_state(kTag, security, espnow::kSecurityNvsPartition);
  // The development PSK profile is pinned to SecurityProfile::Development;
  // this firmware can never report itself as production-secure.
  ESP_LOGW(kTag,
           "EXPERIMENTAL CORE_FIXED_250 started; development PSK is not a production identity "
           "profile");
  config.legacy_security = &security;
#if CONFIG_ROUTELOOM_ROLE_GATEWAY
  const char* usb_dev_secret = CONFIG_ROUTELOOM_USB_DEV_SECRET;
  config.usb_secret = ByteView{reinterpret_cast<const std::uint8_t*>(usb_dev_secret),
                               std::strlen(usb_dev_secret)};
#endif
#elif CONFIG_ROUTELOOM_DEEP_SLEEP && CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC
  config.sleep_image = &s_rtc_hold;
#endif

#if ROUTELOOM_LEGACY_MIGRATION
  // Channel migration (issue #5): the plan store opens before the runtime so
  // a committed channel can pick the boot channel — a blob alone never
  // switches the radio, and restart() still runs the participant's resume
  // checks.
  static espnow::NvsPlanStore plan_store;
  status = plan_store.open("rlplan");
  if (!status) fail(status.detail);
  std::uint8_t boot_channel = 0;
  if (plan_store.boot_channel(boot_channel).ok()) {
    ESP_LOGW(kTag, "migration boot channel %u overrides static %u",
             static_cast<unsigned>(boot_channel), static_cast<unsigned>(config.radio.channel));
    config.radio.channel = boot_channel;
  }
#endif

#if CONFIG_ROUTELOOM_TRUST_STORE
  // Production trust stores (sdk-completion/04-provisioning-lifecycle.md
  // §4.2.2/§4.4): the RLT1 trust image ("rltrust" t0/t1) and the RLC1 device
  // credential ("rlcred" d0/d1) are validated at boot before the config
  // verifier below is exposed. Impairment is never node-fatal and never
  // erases: a quarantined/uncertain store leaves the TrustView verifier
  // !ready() (permit intake refuses) and the node keeps routing. First
  // install is a deployment act owned by the host tooling (routeloom-provision).
  static espnow::NvsTrustStore trust_store_storage;
  auto trust_status = trust_store_storage.open("rltrust");
  if (!trust_status) ESP_LOGE(kTag, "trust store open failed: %s", trust_status.detail);
  static espnow::NvsCredStore cred_store_storage;
  auto cred_status = cred_store_storage.open("rlcred");
  if (!cred_status) ESP_LOGE(kTag, "credential store open failed: %s", cred_status.detail);
  static TrustStore trust_store(trust_store_storage);
  static DeviceCredentialStore credential_store(cred_store_storage);
  trust_status = trust_store.initialize();
  if (!trust_status) ESP_LOGE(kTag, "trust store init: %s", trust_status.detail);
  cred_status = credential_store.initialize();
  if (!cred_status) ESP_LOGE(kTag, "credential store init: %s", cred_status.detail);
  if (trust_store.quarantined() || credential_store.quarantined()) {
    ESP_LOGE(kTag,
             "REPROVISION_REQUIRED: trust/credential store quarantined — recovery is an explicit "
             "operator act, never an implicit reset");
  } else if (trust_store.uncertain() || credential_store.uncertain()) {
    ESP_LOGE(kTag,
             "REPROVISION_REQUIRED: trust/credential sibling state unproven — possibly-stale "
             "state is refused until recover()");
  }
  ESP_LOGI(kTag,
           "trust store: epoch=%lu gen_floor=%lu anchors=%u keys=%u revocations=%u flags=0x%02x "
           "active=%d uncertain=%d quarantined=%d",
           static_cast<unsigned long>(trust_store.store_epoch()),
           static_cast<unsigned long>(trust_store.min_authority_generation()),
           static_cast<unsigned>(trust_store.image().anchor_count),
           static_cast<unsigned>(trust_store.image().key_count),
           static_cast<unsigned>(trust_store.image().revocation_count),
           static_cast<unsigned>(trust_store.flags()), trust_store.has_active() ? 1 : 0,
           trust_store.uncertain() ? 1 : 0, trust_store.quarantined() ? 1 : 0);
  if (credential_store.has_active()) {
    const DeviceCredential& credential = credential_store.credential();
    ESP_LOGI(kTag, "credential: node=%llu key_location=%u status=%u grant=%uB generation_base=%lu",
             static_cast<unsigned long long>(credential.node_id),
             static_cast<unsigned>(credential.key_location),
             static_cast<unsigned>(credential.cred_status),
             static_cast<unsigned>(credential.grant.size),
             static_cast<unsigned long>(credential.generation_base_session));
    // §4.8 epoch-window check: at the 0xFFF0 threshold the next boots would
    // wrap the u16 wire epoch under peer floors that can never accept it —
    // reported as REPROVISION_REQUIRED.
    std::uint16_t credential_epoch = 0;
    const Status epoch_status = credential_epoch_for_session(
        message_session, credential.generation_base_session, credential_epoch);
    if (!epoch_status) {
      ESP_LOGE(kTag, "REPROVISION_REQUIRED: credential epoch window — %s (session=%lu base=%lu)",
               epoch_status.detail, static_cast<unsigned long>(message_session),
               static_cast<unsigned long>(credential.generation_base_session));
    }
  } else {
    ESP_LOGI(kTag, "credential: none provisioned (uncertain=%d quarantined=%d)",
             credential_store.uncertain() ? 1 : 0, credential_store.quarantined() ? 1 : 0);
  }
  // §4.8: the provisioned NetworkId carries the deployment generation in the
  // upper 32 bits; the wire carries only the low 32, the FULL u64 binds the
  // permit AAD/journal below.
  const NetworkId static_network = config.radio.node.network;
  if (trust_store.has_active()) {
    config.radio.node.network = trust_store.network() & 0xFFFFFFFFULL;
    if (config.radio.node.network != static_network) {
      ESP_LOGW(kTag, "trust image network low32 0x%08lx overrides static 0x%08lx",
               static_cast<unsigned long>(config.radio.node.network),
               static_cast<unsigned long>(static_network));
    }
  }
  // §4.9 wear instrumentation: committed-write counters (boot baseline).
  const auto trust_writes = trust_store_storage.write_stats();
  const auto cred_writes = cred_store_storage.write_stats();
  ESP_LOGI(kTag, "store writes: trust=%llu/%lluB cred=%llu/%lluB",
           static_cast<unsigned long long>(trust_writes.commits),
           static_cast<unsigned long long>(trust_writes.bytes),
           static_cast<unsigned long long>(cred_writes.commits),
           static_cast<unsigned long long>(cred_writes.bytes));
#endif

#if ROUTELOOM_LEGACY_MIGRATION
  espnow::EspNowMigrationConfig migration_config{};
#if CONFIG_ROUTELOOM_MIGRATION_SELF_AUTHORITY
  constexpr bool self_authority = true;
#else
  constexpr bool self_authority = false;
#endif
  migration_config.mode =
      CONFIG_ROUTELOOM_MIGRATION == 1 ? MigrationMode::Observe : MigrationMode::Manual;
  migration_config.authority_role = self_authority;
  migration_config.agent.authority_role = self_authority;
  migration_config.agent.participant.node = config.radio.node.node;
  migration_config.agent.participant.network = config.radio.node.network;
  migration_config.agent.participant.authority =
      self_authority ? config.radio.node.node
                     : static_cast<NodeId>(CONFIG_ROUTELOOM_MIGRATION_AUTHORITY);
  migration_config.agent.participant.home_channel = config.radio.channel;
  migration_config.agent.self_rediscovery_capable = true;
  // Measurement inputs are deployment parameters, not firmware guesses.
  migration_config.agent.measurements.management_rtt_p99_ms = CONFIG_ROUTELOOM_MIGRATION_RTT_P99_MS;
  migration_config.agent.measurements.control_delivery_bound_ms =
      CONFIG_ROUTELOOM_MIGRATION_DELIVERY_BOUND_MS;
  migration_config.agent.measurements.required_transfer_ms =
      CONFIG_ROUTELOOM_MIGRATION_TRANSFER_BOUND_MS;
  migration_config.agent.measurements.measured_switch_bound_ms =
      CONFIG_ROUTELOOM_MIGRATION_SWITCH_BOUND_MS;
  migration_config.coordinator.node = config.radio.node.node;
  migration_config.coordinator.home_channel = config.radio.channel;
  // Commit evidence derives from the same dev-PSK master key, domain
  // separated inside the verifier — Development profile only.
  static espnow::DevPskCommitVerifier commit_verifier;
  status = commit_verifier.initialize(key);
  if (!status) fail(status.detail);
#endif

#if ROUTELOOM_LEGACY_CONFIG && !CONFIG_ROUTELOOM_TRUST_STORE
  // Derive the dev permit key before the link master key is wiped:
  // config_dev_key = SHA256("RouteLoom/config-dev/v1" || master_key). The host
  // mirror derives the same bytes — never the raw link key.
  constexpr char kConfigDevDomain[] = "RouteLoom/config-dev/v1";
  static ScopeDigest config_dev_key{};
  {
    std::array<std::uint8_t, 64> material{};
    std::memcpy(material.data(), kConfigDevDomain, sizeof(kConfigDevDomain) - 1);
    std::memcpy(material.data() + sizeof(kConfigDevDomain) - 1, key.data(), key.size());
    sha256(ByteView{material.data(), sizeof(kConfigDevDomain) - 1 + key.size()},
           config_dev_key);
    secure_clear(material);
  }
#endif
#if CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
  secure_clear(key);
#endif

#if CONFIG_ROUTELOOM_ROLE_GATEWAY
  // The bridge protocol owns USB Serial/JTAG exclusively; the console is on
  // UART0 (sdkconfig.defaults) so log text never interleaves the COBS stream.
  usb_serial_jtag_driver_config_t usb_config{};
  usb_config.rx_buffer_size = 1024;
  usb_config.tx_buffer_size = 1024;
  if (usb_serial_jtag_driver_install(&usb_config) != ESP_OK) {
    fail("usb serial jtag install failed");
  }
  static UsbSerialStream usb_stream;
  config.usb = &usb_stream;
#endif

#if CONFIG_ROUTELOOM_SECURITY_MODE_DEV_RAM
  // Keep no extra copy of the link key across earlier fallible boot steps.
#if CONFIG_ROUTELOOM_DEV_KCONFIG_IDENTITY
  if (!parse_hex(CONFIG_ROUTELOOM_DEVELOPMENT_KEY_HEX, config.dev_psk)) {
    secure_clear(config.dev_psk);
    fail("invalid development key");
  }
#else
  config.dev_psk = board_secrets->psk;
#endif
#endif
  status = begin(config, monotonic_now_ms());
  if (!status) fail(status.detail);
  EspNowRuntime& runtime = *runtime_;
  MeshNode& node = runtime.node();
#if CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
#if CONFIG_ROUTELOOM_ROLE_GATEWAY
  // Post-RF entropy seeds the USB transcript nonce before a HELLO is served.
  bridge_->set_device_nonce((static_cast<std::uint64_t>(esp_random()) << 32U) | esp_random());
#endif
  if (CONFIG_ROUTELOOM_PEER_NODE_ID != 0) {
    espnow::MacAddress mac{};
    if (!parse_mac(CONFIG_ROUTELOOM_PEER_MAC, mac)) fail("invalid peer MAC");
    status = runtime.register_neighbor(CONFIG_ROUTELOOM_PEER_NODE_ID, mac, 1);
    if (!status) fail(status.detail);
  }
  constexpr std::uint8_t observation_profile = kProfileLegacyFixture;
#elif CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC
  constexpr std::uint8_t observation_profile = kProfileMemberEdhoc;
#else
  constexpr std::uint8_t observation_profile = kProfileDevRam;
#endif

  // Read-only observation on the Owner task frame (no static RAM).
#if CONFIG_ROUTELOOM_ROLE_GATEWAY || CONFIG_ROUTELOOM_OBSERVATION_REMOTE
  enable_observation();
#endif
  alignas(DeviceObservationSource) unsigned char observation_slot[sizeof(DeviceObservationSource)];
  if (observation_build_ != nullptr) {
    observation_ = observation_build_(observation_slot, *this, observation_profile);
  }
#if CONFIG_ROUTELOOM_ROLE_GATEWAY
  // The gateway and config endpoints were attached in begin().
  if ((config.usb_capability & usb::kCapM1DiagnosticsV1) != 0) {
    status = bridge_->attach_diagnostics();
    if (!status) fail(status.detail);
  }
  if ((config.usb_capability & usb::kCapNodeStatusV1) != 0) {
    status = bridge_->attach_node_status();
    if (!status) fail(status.detail);
  }
  if ((config.usb_capability & usb::kCapObservationV1) != 0) {
    status = bridge_->attach_observation(*observation_);
    if (!status) fail(status.detail);
  }
  // Receive assurance rides the observation profile id.
  status = bridge_->set_rx_assurance_profile(observation_profile);
  if (!status) fail(status.detail);
  if ((config.usb_capability & usb::kCapGroupDeliveryV1) != 0) {
    status = bridge_->attach_group();
    if (!status) fail(status.detail);
  }
#else
  // Subtype-7 remote observation answers from the same source; the
  // responder opens per coordinator mode on every pass (update_observation_remote).
  if (observation_ != nullptr) {
    status = node.set_observation_source(observation_);
    if (!status) fail(status.detail);
  }
#if CONFIG_ROUTELOOM_OBSERVATION_REMOTE && CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
  // LegacyFixture has no enrollment: the build opt-in is the membership claim.
  status = node.set_observation_remote(true);
  if (!status) fail(status.detail);
#endif
#endif

#if CONFIG_ROUTELOOM_DISCOVERY
  // Autonomous discovery (issue #3): the RLD1 bootstrap lane plus the
  // portable NeighborDiscovery engine on the runtime's DiscoveryPort.
  // Dev-PSK possession authentication only — EXPERIMENTAL.
  MacAddress self_mac{};
  status = runtime.local_mac(self_mac);
  if (!status) fail(status.detail);
  DiscoveryConfig discovery_config{};
  discovery_config.node = config.radio.node.node;
  discovery_config.mac = self_mac;
  discovery_config.network = config.radio.node.network;
  // The 4-byte hint is a discovery filter only, never membership evidence.
  discovery_config.network_hint = static_cast<std::uint32_t>(config.radio.node.network);
  discovery_config.capability_bits = CONFIG_ROUTELOOM_CAPABILITY;
#if CONFIG_ROUTELOOM_DISCOVERY_SCOPE != 0
  // Discovery Scope Key (issue #14): a scoped mode whose key cannot install
  // fails boot — never a silent Off downgrade.
  static espnow::DevScopeProvider scope_provider(ScopeRef{CONFIG_ROUTELOOM_DISCOVERY_SCOPE_REF});
  std::array<std::uint8_t, kScopeKeyBytes> scope_key{};
  if (!parse_hex(CONFIG_ROUTELOOM_DISCOVERY_SCOPE_KEY_HEX, scope_key)) {
    fail("invalid ROUTELOOM_DISCOVERY_SCOPE_KEY_HEX");
  }
  status = scope_provider.install(ByteView{scope_key.data(), scope_key.size()},
                                  CONFIG_ROUTELOOM_DISCOVERY_SCOPE_GENERATION, 0);
  secure_clear(scope_key);
  if (!status) fail(status.detail);
  discovery_config.scope_mode = static_cast<ScopeMode>(CONFIG_ROUTELOOM_DISCOVERY_SCOPE);
  discovery_config.scope_provider = &scope_provider;
  discovery_config.scope = scope_provider.ref();
#endif
  espnow::EspNowAutonomyPolicy autonomy_policy{};
  autonomy_policy.self_member = CONFIG_ROUTELOOM_DISCOVERY_MEMBER != 0;
  autonomy_policy.auto_approve = CONFIG_ROUTELOOM_DISCOVERY_AUTO_APPROVE != 0;
  autonomy_policy.initiate = CONFIG_ROUTELOOM_DISCOVERY_INITIATE != 0;
  static espnow::EspNowAutonomy autonomy(discovery_config, autonomy_policy, runtime,
                                         *config.legacy_security, kTag);
  status = autonomy.start();
  if (!status) fail(status.detail);
  ESP_LOGW(kTag, "EXPERIMENTAL discovery active: dev-PSK possession proof is not a production "
                 "identity");
#endif

#if ROUTELOOM_LEGACY_MIGRATION
  // Participant + coordinator over the authenticated control-object lane,
  // with durable plan/commit/active records in "rlplan". The authority role
  // needs a durable ledger before it may issue; nothing local mints a plan.
  static espnow::NvsLedgerStore authority_ledger;
  if (self_authority) {
    status = authority_ledger.open("rlmauth");
    if (!status) fail(status.detail);
  }
  static espnow::EspNowMigration migration(migration_config, runtime, plan_store, commit_verifier,
                                           self_authority ? &authority_ledger : nullptr);
  status = migration.start();
  if (!status) fail(status.detail);
  ESP_LOGW(kTag,
           "EXPERIMENTAL migration lane active (mode=%d): dev-PSK commit evidence is not a "
           "production identity",
           CONFIG_ROUTELOOM_MIGRATION);
#endif

#if ROUTELOOM_LEGACY_CONFIG
  // Remote-config target (P5): durable NVS-backed ConfigJournal plus the
  // permit verifier, exposed to the routed end-protected lane through
  // ConfigTarget.
  static espnow::NvsConfigStore config_store;
  status = config_store.open("rlcfg");
  if (!status) {
    // Not fatal: the journal's initialize() reports the storage fault and
    // the node stays up degraded rather than halting the mesh.
    ESP_LOGE(kTag, "config store open failed: %s", status.detail);
  }
  static DeviceConfigProvider config_provider;
  status = config_provider.open("rlcfgv", kTag);
  if (!status) ESP_LOGE(kTag, "config provider open failed: %s", status.detail);
  // The RLF1 security floor bounds every protected counter the journal and
  // the trust store mint (04 §4.7). It is never auto-created: a missing floor
  // means managed re-provisioning has not run, so privileged intake refuses.
  static espnow::NvsSecurityFloorStore config_floor_store;
  status = config_floor_store.open("rlfloor", espnow::kSecurityNvsPartition);
  if (!status) ESP_LOGE(kTag, "security floor open failed: %s", status.detail);
  static SecurityFloorStore config_floor(config_floor_store);
  status = config_floor.initialize();
  if (!status) {
    ESP_LOGE(kTag,
             "security floor unavailable: %s — config intake refuses until managed "
             "re-provisioning installs one",
             status.detail);
  }
  static DeviceMaintenanceGate config_gate(/*independent_admin_path=*/false);
  static ConfigRateLimiter config_limiter;
  static espnow::EspNowEntropySource config_entropy;
#if CONFIG_ROUTELOOM_TRUST_STORE
  // Production provenance (04-provisioning §4.4 step 5): the verifier
  // resolves authority key records from the committed RLT1 trust image, the
  // only accepted key source in this build. An absent/impaired store leaves
  // the view !ready() — intake refused, routing continues.
  trust_store.attach_floor(&config_floor);
  static TrustView config_verifier(trust_store);
  config_verifier.attach_floor(&config_floor);
  config_verifier.require_authority(static_cast<std::uint64_t>(CONFIG_ROUTELOOM_CONFIG_AUTHORITY));
  ESP_LOGW(kTag, "config profile: trust-store RLCP1_COSE_ESP256 (verifier %s)",
           config_verifier.ready() ? "ready" : "NOT READY — store unprovisioned/impaired");
#elif CONFIG_ROUTELOOM_CONFIG_PROFILE == 1
  // RLCP1_COSE_ESP256: the single provisioned authority P-256 key; a
  // dev-HMAC permit is rejected by profile, never by fallback.
  static CoseEsp256AuthorityVerifier config_verifier;
  {
    std::array<std::uint8_t, kCosePublicKeySize> pubkey{};
    if (!parse_hex(CONFIG_ROUTELOOM_CONFIG_COSE_KEY_HEX, pubkey)) {
      fail("invalid COSE authority key hex");
    }
    config_verifier.provision(static_cast<std::uint64_t>(CONFIG_ROUTELOOM_CONFIG_AUTHORITY),
                              ByteView{pubkey.data(), pubkey.size()});
    if (!config_verifier.ready()) fail("COSE authority key is not a valid P-256 point");
    secure_clear(pubkey);
  }
  ESP_LOGW(kTag, "config profile: RLCP1_COSE_ESP256 (asymmetric permit)");
#else
  static DevConfigAuthorityVerifier config_verifier(
      ByteView{config_dev_key.data(), config_dev_key.size()});
#endif
  ConfigJournalConfig journal_config{};
  // §4.8: the RCC1 network field and the permit AAD bind the full u64
  // NetworkId of a committed trust image.
  journal_config.network = config.radio.node.network;
#if CONFIG_ROUTELOOM_TRUST_STORE
  if (trust_store.has_active()) journal_config.network = trust_store.network();
#endif
  journal_config.target = config.radio.node.node;
  journal_config.config_namespace = endpoint::kConfigNamespaceSdk;
  journal_config.boot_incarnation = message_session;
  journal_config.authorized_issuer = static_cast<NodeId>(CONFIG_ROUTELOOM_CONFIG_AUTHORITY);
  journal_config.authority_generation =
      static_cast<std::uint32_t>(CONFIG_ROUTELOOM_CONFIG_AUTHORITY_GENERATION);
  static ConfigJournal config_journal(journal_config, config_store, config_floor, config_verifier,
                                      config_entropy, config_limiter, &config_provider,
                                      /*validator=*/nullptr, &config_gate);
  status = config_journal.initialize(monotonic_now_ms());
  if (!status) {
    // Journal impairment is not node-fatal (04 §4.7, 06 §6.3): the impaired
    // journal refuses intake with honest verdicts and still answers status
    // and signed recovery objects, while the node keeps routing.
    ESP_LOGE(kTag,
             "config journal init failed: %s — running degraded (routing continues, config "
             "intake refuses)",
             status.detail);
  }
  static MeshConfigPort config_port(node);
  static ConfigTarget config_target(config_port, config_limiter);
  status = config_target.add_journal(endpoint::kConfigNamespaceSdk, config_journal);
  if (!status) fail(status.detail);
#if CONFIG_ROUTELOOM_TRUST_STORE
  // Kind-5 trust-manifest intake and trust-status answer from the store the
  // verifier reads.
  config_target.attach_trust_store(trust_store, config_floor);
#endif
  node.set_config_sink(&config_target);
  // The committed config image drives the live relay gate from now on.
  config_provider.attach_node(&node, /*role_gated=*/false);
  ESP_LOGW(kTag, "EXPERIMENTAL config target active (not a production identity)");
  const auto cfg_writes = config_store.write_stats();
  ESP_LOGI(kTag, "config store writes=%llu bytes=%llu",
           static_cast<unsigned long long>(cfg_writes.commits),
           static_cast<unsigned long long>(cfg_writes.bytes));
#endif

#if CONFIG_ROUTELOOM_TELEMETRY_REMOTE
  // Bench surface (02-telemetry §4.2): answer routed Diagnostic(48)
  // telemetry queries. Local collection is unconditional.
  node.set_telemetry_remote(true);
#endif

#if !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
  ESP_LOGI(kTag, "security owner started; node start deferred to membership");
#if CONFIG_ROUTELOOM_DEEP_SLEEP
  // Owner sleep tail (P4 §9.3, V1-F07): one-shot wake evidence for the
  // restore below. The marker/programmed reads clear the RTC cells, so a
  // reset without a new sleep never reuses them.
  bool owner_boot_marked = false;
  const ResetCause owner_boot_cause = classify_boot(owner_boot_marked);
  const std::uint32_t owner_programmed_ms = s_sleep_programmed_ms;
  s_sleep_programmed_ms = 0;
  const bool owner_deep_wake = owner_boot_cause == ResetCause::DeepSleepWake;
  const bool owner_timer_wake = esp_sleep_get_wakeup_cause() == ESP_SLEEP_WAKEUP_TIMER;
  sdkv1::BufferRtcSessionPort owner_rtc_port(
      MutableByteView{s_rtc_session.data(), s_rtc_session.size()});
  static EspNowPowerPort owner_power_port(runtime);
  static FailStreakClearOnSleep owner_streak_clear;
  owner_power_port.set_pre_sleep_hook(&owner_streak_clear);
  bool owner_restore_settled = false;
  bool owner_sleep_parked = false;
  const std::int64_t owner_prepare_at_us =
      esp_timer_get_time() + static_cast<std::int64_t>(CONFIG_ROUTELOOM_SLEEP_AFTER_MS) * 1000LL;
  const std::int64_t owner_stop_at_us = owner_prepare_at_us + 30000000LL;
  sdkv1::SecurityCoordinator& coordinator = owner_->coordinator();
#endif
  // Boot complete — the pump loop below is the node's main loop.
  fail_streak_runtime_started(s_fail);
#elif CONFIG_ROUTELOOM_DEEP_SLEEP
  // LegacyFixture sleep: PowerCoordinator driven from the Owner pass, a
  // two-slot NVS sleep image, RTC-marker + wake-cause classification and a
  // timer wake. The timer cause alone cannot bound elapsed time, so durable
  // pendings park TIME_UNCERTAIN. GPIO wake and bounded rediscovery are not
  // wired (EspNowPowerPort::start_discovery reports Unsupported). Sleep
  // images are system state and stay in the default partition.
  static NvsCounterStore sleep_store;
  status = sleep_store.open("rlsleep");
  if (!status) fail(status.detail);
  static NvsSleepStorage sleep_storage(sleep_store);
  static EspNowPowerPort power_port(runtime);
  static LogPowerEvents power_events;
  static FailStreakClearOnSleep streak_clear;
  power_port.set_pre_sleep_hook(&streak_clear);
  PowerConfig power_config{};
  static PowerCoordinator power(power_config, node, power_port, sleep_storage, power_events);
  bool boot_marked = false;
  const ResetCause boot_cause = classify_boot(boot_marked);
  status = power.begin(boot_cause, classify_wake_elapsed(boot_cause, boot_marked),
                       monotonic_now_ms());
  if (!status) fail(status.detail);
  runtime.mark_started();
  // The streak holds here: the pump still runs fallible work (drain, image
  // commit, wake configuration, sleep_enter). This profile's only clear is
  // FailStreakClearOnSleep at the point of no return inside enter_sleep().
  fail_streak_mark_started(s_fail);
  SleepRequest request{};
  request.pending_policy = SleepWorkPolicy::Fail;
  request.wake.wake_after_ms = CONFIG_ROUTELOOM_SLEEP_DURATION_MS;
  bool prepared = false;
  const std::int64_t prepare_at_us =
      esp_timer_get_time() + static_cast<std::int64_t>(CONFIG_ROUTELOOM_SLEEP_AFTER_MS) * 1000LL;
  const std::int64_t stop_at_us = prepare_at_us + 30000000LL;
#else
  status = runtime.start();
  if (!status) fail(status.detail);
  fail_streak_runtime_started(s_fail);
#endif

#if CONFIG_ROUTELOOM_ROLE_GATEWAY
  static std::array<std::uint8_t, 512> usb_rx{};
#endif
#if CONFIG_ROUTELOOM_TRACE && CONFIG_ROUTELOOM_ROLE_GATEWAY
  MonotonicMs last_usb_trace_ms = 0;
#endif
#if CONFIG_ROUTELOOM_TRACE && ROUTELOOM_LEGACY_CONFIG
  MonotonicMs last_config_trace_ms = 0;
#endif
  for (;;) {
#if CONFIG_ROUTELOOM_ROLE_GATEWAY
    const int received = usb_serial_jtag_read_bytes(usb_rx.data(), usb_rx.size(), 0);
    if (received > 0) {
      usb_receive(ByteView{usb_rx.data(), static_cast<std::size_t>(received)},
                  monotonic_now_ms());
    }
#endif
    const MonotonicMs now_ms = monotonic_now_ms();
    step(now_ms);
#if CONFIG_ROUTELOOM_TRACE && CONFIG_ROUTELOOM_ROLE_GATEWAY
    if (now_ms - last_usb_trace_ms >= 2000) {
      last_usb_trace_ms = now_ms;
      const auto& s = bridge_->stats();
      ESP_LOGI(kTag, "usb state=%u rx=%llu tx=%llu drop=%llu credit_denied=%llu write_err=%llu",
               static_cast<unsigned>(bridge_->state()),
               static_cast<unsigned long long>(s.rx_frames),
               static_cast<unsigned long long>(s.tx_frames),
               static_cast<unsigned long long>(s.dropped_frames),
               static_cast<unsigned long long>(s.credit_denied),
               static_cast<unsigned long long>(s.tx_write_errors));
    }
#endif
#if CONFIG_ROUTELOOM_TRACE && ROUTELOOM_LEGACY_CONFIG
    if (now_ms - last_config_trace_ms >= 5000) {
      last_config_trace_ms = now_ms;
      ESP_LOGI(kTag, "config jobs accepted=%lu failed=%lu",
               static_cast<unsigned long>(config_target.jobs_accepted()),
               static_cast<unsigned long>(config_target.jobs_failed()));
    }
#endif
#if CONFIG_ROUTELOOM_DEEP_SLEEP && !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
    // Warm restore: retried while the parent re-binds (Busy) with a freshly
    // bounded elapsed upper bound each round; terminal (warm or refused)
    // settles once and a refusal resumes cold.
    if (!owner_restore_settled) {
      const MonotonicMs awake_ms = monotonic_now_ms();
      const std::uint32_t awake32 =
          awake_ms > 0xFFFFFFFFULL ? 0xFFFFFFFFU : static_cast<std::uint32_t>(awake_ms);
      const std::uint32_t elapsed = bound_sleep_elapsed_upper_ms(
          owner_deep_wake, owner_timer_wake, owner_boot_marked, owner_programmed_ms, awake32);
      const Status restored = coordinator.restore_sleep_image(
          owner_rtc_port, message_session, elapsed, owner_deep_wake, owner_boot_marked);
      if (restored.code != StatusCode::Busy) {
        owner_restore_settled = true;
        if (restored) {
          ESP_LOGI(kTag, "sleep restore: warm (elapsed bound %lu ms)",
                   static_cast<unsigned long>(elapsed));
        } else {
          ESP_LOGW(kTag, "sleep restore refused (%s): cold resume", restored.detail);
        }
      }
    }
    // Sleep entry: park the security leg, save the retained image over the
    // live parent binding, then enter deep sleep through the power port
    // (radio stop + pre-sleep hook). Busy re-pumps against the drain
    // deadline; a save refusal without an image sleeps cold with the marker
    // clear. The Owner admits sleep only after node deliveries, group holds
    // and radio work drained as well as its security workspace.
    if (esp_timer_get_time() >= owner_prepare_at_us) {
      if (!owner_sleep_parked &&
          owner_->prepare_sleep(monotonic_now_ms(), esp_timer_get_time() >= owner_stop_at_us)) {
        owner_sleep_parked = true;
      }
      if (owner_sleep_parked) {
        NodeId parent = kInvalidNodeId;
        routeloom::MacAddress parent_mac{};
        BindingId parent_binding{kInvalidBindingId};
        Status saved = Status::error(StatusCode::NotFound, "no parent link");
        if (node.sleep_work_pending()) {
          saved = Status::error(StatusCode::Busy, "node has sleep work");
        } else if (coordinator.first_live_peer(SecurityScope::Link, parent) &&
                   owner_->discovery() != nullptr &&
                   owner_->discovery()->binding_of(parent, parent_binding) &&
                   owner_->discovery()->mac_of(parent, parent_mac)) {
          saved = coordinator.save_sleep_image(owner_rtc_port, parent, parent_mac,
                                               parent_binding.value, monotonic_now_ms());
        }
        if (saved.code == StatusCode::Busy) {
          // New work landed after the park: unpark and keep pumping.
          owner_sleep_parked = false;
          (void)owner_->wake(monotonic_now_ms());
        } else {
          if (saved) {
            s_sleep_marker = kSleepMarkerValue;
            s_sleep_programmed_ms = CONFIG_ROUTELOOM_SLEEP_DURATION_MS;
          }
          WakePlan plan{};
          plan.wake_after_ms = CONFIG_ROUTELOOM_SLEEP_DURATION_MS;
          if (!owner_power_port.configure_wake(plan)) fail("owner sleep wakeup refused");
          (void)owner_power_port.enter_sleep();
          // enter_sleep does not return on silicon; a return means no sleep
          // happened — never leave the marker armed for the reset path.
          s_sleep_marker = 0;
          s_sleep_programmed_ms = 0;
          fail("owner sleep entry returned");
        }
      }
    }
#elif CONFIG_ROUTELOOM_DEEP_SLEEP
    power.poll(monotonic_now_ms());
    if (!prepared && power.state() == PowerState::Running &&
        esp_timer_get_time() >= prepare_at_us) {
      status = power.sleep_prepare(request, monotonic_now_ms());
      if (!status) fail(status.detail);
      prepared = true;
    }
    if (power.state() == PowerState::ReadyToSleep) {
      // The radio is quiesced. Tighten the RX replay ceilings before the
      // planned power loss, or the next live peer counters fall inside the
      // crash reservation and are rejected after wake.
      status = security.prepare_sleep();
      if (!status) fail(status.detail);
      s_sleep_marker = kSleepMarkerValue;
      s_sleep_programmed_ms = CONFIG_ROUTELOOM_SLEEP_DURATION_MS;
      status = power.sleep_enter(power.ticket(), monotonic_now_ms());
      // The marker claims "sleep in progress" only while sleep_enter runs.
      s_sleep_marker = 0;
      s_sleep_programmed_ms = 0;
      if (!status) fail(status.detail);
    }
    if (power.state() != PowerState::Sleeping && esp_timer_get_time() >= stop_at_us) {
      fail("sleep deadline exceeded");
    }
#endif
    runtime.wait_for_event(next_deadline(now_ms) - now_ms);
  }
}

}  // namespace routeloom
