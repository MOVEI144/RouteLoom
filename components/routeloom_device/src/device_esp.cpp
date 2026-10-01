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
#include "sdkconfig.h"
#include "routeloom/espnow_power.hpp"
#include "routeloom/espnow_flash_layout.hpp"
#include "routeloom/espnow_runtime.hpp"
#include "routeloom/espnow_sdkv1.hpp"
#include "routeloom/rlcw1.hpp"
#include "routeloom/profile.hpp"
#include "routeloom/sdkv1_session_rtc.hpp"
#include "routeloom/fail_policy.hpp"
#include "routeloom/hex.hpp"
#include "routeloom/power.hpp"
#include "routeloom/board_secrets.hpp"
#include "routeloom/espnow_board_config.hpp"
#include "routeloom/espnow_sdkv1_entropy.hpp"
#include "routeloom/espnow_security_owner.hpp"
#include "routeloom/owner_pump.hpp"
#include "routeloom/device.hpp"
#include "routeloom/observation.hpp"
#include "routeloom/secure_clear.hpp"

namespace {
// The app supplies its tag through DeviceConfig::log_tag so a site mixing
// images can tell them apart in a captured log.
const char* kTag = "RouteLoomNode";

#if CONFIG_ROUTELOOM_ROLE_GATEWAY
struct UsbInput {
  std::uint8_t size{0};
  std::array<std::uint8_t, 64> bytes{};
};
struct UsbReader {
  QueueHandle_t queue{nullptr};
  routeloom::espnow::EspNowRuntime* runtime{nullptr};
};
#endif

// NVS codec state uses CPU-only reads and writes, so C5 Owner profiles
// keep it in LP SRAM while HP SRAM remains available to radio traffic.
#if CONFIG_IDF_TARGET_ESP32C5
#define ROUTELOOM_OWNER_C5_LP RTC_DATA_ATTR
#else
#define ROUTELOOM_OWNER_C5_LP
#endif

#if CONFIG_IDF_TARGET_ESP32C3
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
using routeloom::espnow::EspNowSecurityOwner;
using routeloom::espnow::EspOwnerEntropy;
using routeloom::espnow::EspNowPowerPort;
using routeloom::espnow::EspNowRuntime;
using routeloom::espnow::EspNowRuntimeConfig;
using routeloom::espnow::MacAddress;

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

#if !CONFIG_ROUTELOOM_DEV_KCONFIG_IDENTITY
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

// Owner sleep tail (P4 §9.3, V1-F07): the retained session image in RTC
// slow memory, the only RAM surviving deep sleep. Zero after any
// non-sleep reset (re-copied from the image) — decode refuses those, so
// no validity claim rides on the backing itself.
RTC_DATA_ATTR std::array<std::uint8_t, routeloom::sdkv1::kRtcSessionRecordSize>
    s_rtc_session{};
// The consumed image waits here until the parent binds; the always-on
// security Owner does not reserve this space in gateway HP SRAM.
RTC_DATA_ATTR routeloom::sdkv1::RtcSessionImage s_rtc_hold{};

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
    s_sleep_marker = kSleepMarkerValue;
    s_sleep_programmed_ms = CONFIG_ROUTELOOM_SLEEP_DURATION_MS;
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

#endif  // CONFIG_ROUTELOOM_DEEP_SLEEP



// --- Read-only device observation (observation_v1) -------------------------------
// System health from ESP-IDF, table occupancy from the MeshNode, sessions and
// join milestones from the security coordinator. Served to the USB host on a gateway and to end-protected remote
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
    if (coordinator_ != nullptr) {
      const routeloom::sdkv1::CoordinatorSnapshot snapshot = coordinator_->snapshot();
      power = snapshot.sleeping ? routeloom::kPowerSleeping : routeloom::kPowerRunning;
      mode = map_mode(snapshot.mode);
    }
    routeloom::fill_observation_system(boot_id_, now_ms, port_, power, mode, profile_, out);
    return true;
  }

  bool fill_tables(routeloom::MonotonicMs now_ms,
                   routeloom::ObservationTables& out) const noexcept override {
    std::uint16_t link = 0, link_cap = 0, end = 0, end_cap = 0;
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
    routeloom::fill_observation_tables(node_, now_ms, link, link_cap, end, end_cap, out);
    return true;
  }

  bool fill_milestones(routeloom::MonotonicMs now_ms,
                       routeloom::JoinMilestones& out) const noexcept override {
    out = coordinator_ != nullptr ? coordinator_->milestones(now_ms) : routeloom::JoinMilestones{};
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

  // Live discovery for neighbor phase/lease (null without a coordinator).
  const routeloom::NeighborDiscovery* live_discovery() const noexcept {
    return coordinator_ != nullptr ? coordinator_->discovery() : nullptr;
  }

  const routeloom::MeshNode& node_;
  const routeloom::sdkv1::SecurityCoordinator* coordinator_;
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
  // Identity, site state, and the boot session live in NVS. Never erase it
  // automatically after a version/capacity error: that would silently turn
  // a recoverable storage problem into credential or boot counter rollback.
  const esp_err_t nvs_error = nvs_flash_init();
  if (nvs_error != ESP_OK) {
    ESP_LOGE(kTag, "NVS init failed (%s); automatic erase is disabled, explicit recovery is required",
             esp_err_to_name(nvs_error));
    fail("NVS initialization failed");
  }
  status = open_storage(config.role, config.security);
  if (!status) fail(status.detail);
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
#if !CONFIG_ROUTELOOM_DEV_KCONFIG_IDENTITY
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

#if CONFIG_ROUTELOOM_DEEP_SLEEP
  config.sleep_image = &s_rtc_hold;
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
#if CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC
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
  // The gateway and config endpoints were attached in begin(). A requested
  // bit whose feature this image compiled out is a build choice, not a
  // fault: the bit stays unadvertised and the node runs without it.
  const auto optional = [](const Status& attached) {
    if (attached.code == StatusCode::Unsupported) {
      ESP_LOGW(kTag, "capability not advertised: %s", attached.detail);
    } else if (!attached) {
      fail(attached.detail);
    }
  };
  if ((config.usb_capability & usb::kCapM1DiagnosticsV1) != 0) {
    status = bridge_->attach_diagnostics();
    if (!status) fail(status.detail);
  }
  if ((config.usb_capability & usb::kCapNodeStatusV1) != 0) {
    optional(bridge_->attach_node_status());
  }
  if ((config.usb_capability & usb::kCapObservationV1) != 0) {
    optional(bridge_->attach_observation(*observation_));
  }
  // Receive assurance rides the observation profile id.
  status = bridge_->set_rx_assurance_profile(observation_profile);
  if (!status) fail(status.detail);
  if ((config.usb_capability & usb::kCapGroupDeliveryV1) != 0) {
    optional(bridge_->attach_group());
  }
#else
  // Subtype-7 remote observation answers from the same source; the
  // responder opens per coordinator mode on every pass (update_observation_remote).
  if (observation_ != nullptr) {
    status = node.set_observation_source(observation_);
    if (!status) fail(status.detail);
  }
#endif

  ESP_LOGI(kTag, "security owner started; node start deferred to membership");
#if CONFIG_ROUTELOOM_DEEP_SLEEP
  // Owner sleep tail (P4 §9.3, V1-F07): one-shot wake evidence for the
  // restore below. The marker/programmed reads clear the RTC cells, so a
  // reset without a new sleep never reuses them.
  const std::uint32_t message_session = boot_session_;
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
  bool owner_restore_settled = config.security == DeviceSecurity::DevRam;
  bool power_bound = false;
  bool sleep_requested = false;
  static espnow::NvsBlobNamespace power_namespace;
  const Status power_open =
      power_namespace.open(espnow::kSecurityNvsPartition,
                           config.security == DeviceSecurity::DevRam ? "rlpower" : "rlpwrmem");
  if (!power_open) fail(power_open.detail);
  static sdkv1::BlobPowerStorage power_storage(power_namespace);
  static PowerCoordinator power(PowerConfig{30000}, node, owner_power_port, power_storage,
                                observer());
  owner_power_port.bind_owner(*owner_, &owner_rtc_port);
  const std::int64_t owner_prepare_at_us =
      esp_timer_get_time() + static_cast<std::int64_t>(CONFIG_ROUTELOOM_SLEEP_AFTER_MS) * 1000LL;
  const std::int64_t owner_stop_at_us = owner_prepare_at_us + 30000000LL;
  sdkv1::SecurityCoordinator& coordinator = owner_->coordinator();
#endif
#if CONFIG_ROUTELOOM_ROLE_GATEWAY
  // A bounded byte carrier; decoding and all bridge state stay on Owner.
  static UsbReader usb_reader;
  usb_reader.queue = xQueueCreate(4, sizeof(UsbInput));
  usb_reader.runtime = &runtime;
  if (usb_reader.queue == nullptr) fail("USB reader queue allocation failed");
  const auto read_usb = [](void* context) {
    auto& reader = *static_cast<UsbReader*>(context);
    for (;;) {
      UsbInput input{};
      const int received =
          usb_serial_jtag_read_bytes(input.bytes.data(), input.bytes.size(), portMAX_DELAY);
      if (received <= 0) continue;
      input.size = static_cast<std::uint8_t>(received);
      if (xQueueSend(reader.queue, &input, portMAX_DELAY) == pdTRUE) reader.runtime->notify_owner();
    }
  };
  if (xTaskCreate(read_usb, "rl_usb_rx", 2048, &usb_reader, tskIDLE_PRIORITY + 1, nullptr) !=
      pdPASS) {
    fail("USB reader task allocation failed");
  }
#endif
  // Boot complete: every fallible startup allocation precedes this mark.
#if !CONFIG_ROUTELOOM_DEEP_SLEEP
  fail_streak_runtime_started(s_fail);
#endif
#if CONFIG_ROUTELOOM_TRACE && CONFIG_ROUTELOOM_ROLE_GATEWAY
  MonotonicMs last_usb_trace_ms = 0;
#endif
  for (;;) {
#if CONFIG_ROUTELOOM_ROLE_GATEWAY
    UsbInput input{};
    for (unsigned i = 0; i < 4 && xQueueReceive(usb_reader.queue, &input, 0) == pdTRUE; ++i) {
      usb_receive(ByteView{input.bytes.data(), input.size}, monotonic_now_ms());
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
#if CONFIG_ROUTELOOM_DEEP_SLEEP
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
    if (!power_bound && owner_restore_settled && node.started()) {
      const MonotonicMs awake_ms = monotonic_now_ms();
      const std::uint32_t awake32 =
          awake_ms > UINT32_MAX ? UINT32_MAX : static_cast<std::uint32_t>(awake_ms);
      const auto elapsed = classify_sleep_elapsed(
          owner_deep_wake, owner_timer_wake, owner_boot_marked, owner_programmed_ms,
          bound_sleep_elapsed_upper_ms(owner_deep_wake, owner_timer_wake, owner_boot_marked,
                                       owner_programmed_ms, awake32));
      const Status bound = bind_sleep(power, owner_boot_cause, elapsed, awake_ms);
      if (!bound) fail(bound.detail);
      power_bound = true;
    }
    // The demo has a finite radio-on window even when no parent/adoption
    // completes. A failed drain or commit takes the bounded fault backoff.
    if (esp_timer_get_time() >= owner_stop_at_us) fail("sleep radio-on budget exhausted");
    if (power_bound && esp_timer_get_time() >= owner_prepare_at_us) {
      if (!sleep_requested) {
        SleepRequest request{};
        request.wake.wake_after_ms = CONFIG_ROUTELOOM_SLEEP_DURATION_MS;
        const Status prepared = prepare_sleep(request);
        if (!prepared) fail(prepared.detail);
        sleep_requested = true;
      } else if (power.state() == PowerState::Running) {
        fail(power.stats().last_abort);
      }
      const SleepTicket ticket = sleep_ticket();
      if (ticket.issued) {
        const Status entered = enter_sleep(ticket);
        s_sleep_marker = 0;
        s_sleep_programmed_ms = 0;
        fail(entered ? "sleep entry returned" : entered.detail);
      }
    }
#endif
    const MonotonicMs wait_now_ms = monotonic_now_ms();
    runtime.wait_for_event(next_deadline(wait_now_ms) - wait_now_ms);
  }
}

}  // namespace routeloom
