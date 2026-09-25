#include <algorithm>
#include <array>
#include <cctype>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "driver/usb_serial_jtag.h"
#include "esp_attr.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_random.h"
#include "esp_sleep.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "routeloom/nvs_boot_session.hpp"
#include "routeloom/nvs_legacy_purge.hpp"
#include "sdkconfig.h"
#if CONFIG_ROUTELOOM_DISCOVERY
#include "routeloom/espnow_autonomy.hpp"
#include "routeloom/espnow_scope_provider.hpp"
#endif
#if CONFIG_ROUTELOOM_MIGRATION
#include "routeloom/espnow_migration.hpp"
#include "routeloom/nvs_ledger_store.hpp"
#endif
#if CONFIG_ROUTELOOM_TRUST_STORE
#include "routeloom/device_credential.hpp"
#include "routeloom/nvs_cred_store.hpp"
#include "routeloom/nvs_trust_store.hpp"
#endif
#include "routeloom/config_wire.hpp"
#include "routeloom/espnow_runtime.hpp"
#include "routeloom/espnow_sdkv1.hpp"
#include "routeloom/fail_policy.hpp"
#include "routeloom/rlcw1.hpp"
#include "routeloom/nvs_counter_store.hpp"
#if !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
#include "routeloom/espnow_sdkv1_entropy.hpp"
#include "routeloom/espnow_security_owner.hpp"
#include "routeloom/owner_pump.hpp"
#else
#include "routeloom/psk_security.hpp"
#endif
#include "routeloom/secure_clear.hpp"
#include "routeloom/usb_bridge.hpp"

namespace {
constexpr char kTag[] = "RouteLoomBr";

// Long-lived CPU-only state can reside in LP SRAM on the C5; radio and USB
// driver buffers stay in their normal HP memory. The smaller gateway config
// state also fits the C3 RTC bank.
#if CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC && CONFIG_IDF_TARGET_ESP32C5
#define ROUTELOOM_MEMBER_C5_LP RTC_DATA_ATTR
#else
#define ROUTELOOM_MEMBER_C5_LP
#endif
#if CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC && \
    (CONFIG_IDF_TARGET_ESP32C3 || CONFIG_IDF_TARGET_ESP32C5)
#define ROUTELOOM_MEMBER_SMALL_LP RTC_DATA_ATTR
#else
#define ROUTELOOM_MEMBER_SMALL_LP
#endif

using routeloom::ByteView;
using routeloom::NodeId;
using routeloom::Status;
using routeloom::StatusCode;
#if !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
using routeloom::espnow::EspNowSecurityOwner;
using routeloom::espnow::EspOwnerEntropy;
#else
using routeloom::espnow::DevelopmentPskSecurityProvider;
#endif
using routeloom::espnow::EspNowRuntime;
using routeloom::espnow::EspNowRuntimeConfig;
using routeloom::espnow::MacAddress;
using routeloom::espnow::NvsCounterStore;

// UsbBridge emits COBS+CRC32 frames through this stream. Partial writes are
// expected: the bridge retries the remainder on the next poll. The write is
// deliberately nonblocking — app_main is the single pump task, so a blocked
// write here (host stopped draining without a disconnect) would starve
// runtime.poll_once() and the mesh RX path beneath it. A full TX buffer
// reports written=0; the bridge resumes from tx_wire_sent_ next poll.
class UsbSerialStream final : public routeloom::usb::ByteStream {
 public:
  Status write(ByteView data, std::size_t& written) noexcept override {
    written = 0;
    if (data.data == nullptr || data.size == 0) {
      return Status::success();
    }
    const int result = usb_serial_jtag_write_bytes(
        data.data, data.size, pdMS_TO_TICKS(0));
    if (result < 0) {
      return Status::error(StatusCode::RadioFailure, "usb jtag write failed");
    }
    written = static_cast<std::size_t>(result);
    return Status::success();
  }
};

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
  if (std::sscanf(text, "%2x:%2x:%2x:%2x:%2x:%2x", &values[0], &values[1],
                  &values[2], &values[3], &values[4], &values[5]) != 6) {
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
// first, a long deep sleep once the fault proves persistent — and is
// cleared only on a stability proof (the runtime pump starting, the last
// fallible step below) or on power-on. The routeloom fail_streak_* calls
// are its only writers.
RTC_NOINIT_ATTR routeloom::FailStreak s_fail;

[[noreturn]] void fail(const char* detail) {
  const std::uint32_t streak = routeloom::fail_streak_consume(s_fail);
  const routeloom::FailAction action = routeloom::fail_action(streak);
  if (action.deep_sleep) {
    // Persistent fault: every further restart is one more NVS session write
    // with no recovery evidence. Stop the radio first — sleeping with the
    // Wi-Fi driver live is the contract violation enter_sleep() guards
    // against — then halt at deep-sleep current; the streak survives in
    // .rtc_noinit so each timer wake keeps the same bounded cadence.
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

routeloom::MonotonicMs monotonic_now_ms() noexcept {
  return static_cast<routeloom::MonotonicMs>(esp_timer_get_time() / 1000);
}

}  // namespace

extern "C" void app_main(void) {
  // A matching magic is the only thing that distinguishes a streak that
  // survived esp_restart from power-on garbage in .rtc_noinit.
  routeloom::fail_streak_boot(s_fail);
  // Identity, nonce reservations, replay state and message sessions live in
  // NVS. Never erase it automatically after a version/capacity error: that
  // would silently turn a recoverable storage problem into key/counter
  // rollback.
  const esp_err_t nvs_error = nvs_flash_init();
  if (nvs_error != ESP_OK) {
    ESP_LOGE(kTag,
             "NVS init failed (%s); automatic erase is disabled, explicit "
             "recovery is required",
             esp_err_to_name(nvs_error));
    fail("NVS initialization failed");
  }

  // The boot session (default "nvs" partition) advances before any
  // per-peer security state is touched: that state lives in its own
  // partition (issue #37, sdk-v1/05 §4 D2-a), so exhausting it can never
  // block this write. Every boot — even one that fails below — consumes a
  // session, which keeps TX epochs strictly fresh.
  std::uint32_t message_session = 0;
  auto status = routeloom::next_boot_session(message_session);
  if (!status) fail(status.detail);

  const esp_err_t sec_nvs_error =
      nvs_flash_init_partition(routeloom::espnow::kSecurityNvsPartition);
  if (sec_nvs_error != ESP_OK) {
    ESP_LOGE(kTag,
             "security NVS partition '%s' init failed (%s); automatic erase "
             "is disabled: flash the partition table (partitions.csv) and "
             "erase NVS explicitly",
             routeloom::espnow::kSecurityNvsPartition,
             esp_err_to_name(sec_nvs_error));
    fail("security NVS initialization failed");
  }

  // SDK v1 stores (sdk-v1/05 §5): the `rlsec` namespaces rlident/rlsite/
  // rlrevo/rlres behind the dual-slot discipline; the gateway keeps 160
  // resume slots. Impairment is never node-fatal and never triggers an
  // erase: a quarantined/uncertain store is reported and its consumers
  // fail closed while the node keeps routing.
  static ROUTELOOM_MEMBER_C5_LP routeloom::espnow::Sdkv1Stores sdkv1_stores(
      routeloom::sdkv1::kResumeGatewaySlots);
  status = sdkv1_stores.open(routeloom::espnow::kSecurityNvsPartition);
  if (!status) {
#if CONFIG_ROUTELOOM_MAINTENANCE_CONSOLE || !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
    // A factory console without NVS provisions nothing, and the security
    // owner cannot join without stores — continuing would run a dead node.
    fail(status.detail);
#else
    ESP_LOGE(kTag, "sdkv1 stores open failed: %s", status.detail);
#endif
  } else {
    const routeloom::Status sdkv1_status = sdkv1_stores.initialize();
    if (!sdkv1_status) {
      ESP_LOGE(kTag, "sdkv1 stores init: %s", sdkv1_status.detail);
    }
    sdkv1_stores.log_state(kTag);
#if !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
#if CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC
    // Member boot binds the already advanced token to the adopted RLS1.
    status = routeloom::reconcile_boot_session(sdkv1_stores.site(), message_session);
    if (!status) fail(status.detail);
#endif
#if CONFIG_ROUTELOOM_SECURITY_MODE_DEV_RAM && !CONFIG_ROUTELOOM_MAINTENANCE_CONSOLE
    status = routeloom::reserve_dev_group_boot_session(message_session, message_session);
    if (!status) fail(status.detail);
#endif
#endif
  }
#if CONFIG_ROUTELOOM_MAINTENANCE_CONSOLE
  // Factory maintenance console (sdk-v1/07 §6): runs pre-RF and owns the
  // device — and the USB — from here, instead of the bridge protocol below.
  // Returns only when the USB console itself cannot be set up.
  status = routeloom::espnow::run_maintenance_console(sdkv1_stores);
  fail(status.detail);
#endif

  if (routeloom::espnow::nvs_namespace_in_use(NVS_DEFAULT_PART_NAME,
                                              "rlcounter") ||
      routeloom::espnow::nvs_namespace_in_use(NVS_DEFAULT_PART_NAME,
                                              "rlreplay")) {
    ESP_LOGW(kTag,
             "legacy rlcounter/rlreplay state in the default NVS partition "
             "is orphaned (pre-rlsec layout); an explicit NVS erase reclaims "
             "it");
  }
#if CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
  status = routeloom::espnow::refuse_legacy_boot_after_migration();
  if (!status) fail(status.detail);
  std::uint32_t peer_capacity = 0;
  status = routeloom::espnow::nvs_partition_peer_capacity(
      routeloom::espnow::kSecurityNvsPartition,
      routeloom::espnow::kGatewayMaxPersistedPeers, peer_capacity);
  if (!status) fail(status.detail);

  static NvsCounterStore counter_store;
  status = counter_store.open("rlcounter",
                              routeloom::espnow::kSecurityNvsPartition);
  if (!status) fail(status.detail);

  std::array<std::uint8_t,
             DevelopmentPskSecurityProvider::kMasterKeySize>
      key{};
  if (!parse_hex(CONFIG_ROUTELOOM_DEVELOPMENT_KEY_HEX, key)) {
    fail("invalid development key");
  }
  static DevelopmentPskSecurityProvider security;
  routeloom::espnow::PeerStateConfig peer_state{};
  peer_state.replay_namespace = "rlreplay";
  peer_state.partition = routeloom::espnow::kSecurityNvsPartition;
  // TX link/end epochs below are the boot session: records of older epochs
  // are dead and swept (witness first); a session at or below the witness
  // fails closed here.
  peer_state.tx_epoch = message_session;
  peer_state.max_persisted_peers = peer_capacity;
  status = security.initialize(key, counter_store, peer_state);
  if (!status) fail(status.detail);
  routeloom::espnow::log_peer_state(kTag, security,
                                    routeloom::espnow::kSecurityNvsPartition);
  routeloom::SecurityProvider& session_security = security;
#else
  // Owner profile (G-SEC P4 §8.4): the shared security owner runs over
  // the sdkv1 stores above; the dev-PSK path is compiled out. The owner
  // boots after radio-up (entropy + attach + boot below); the node start
  // stays deferred to ApplyMemberConfig.
  static EspOwnerEntropy entropy;
  static EspNowSecurityOwner owner;
  EspNowSecurityOwner::Config owner_config{};
  owner_config.local_node = CONFIG_ROUTELOOM_NODE_ID;
  // Pre-radio station MAC from eFuse: no custom MAC is ever set, so this
  // is the address the runtime will read back after Wi-Fi init.
  if (esp_read_mac(owner_config.local_mac.data(), ESP_MAC_WIFI_STA) != ESP_OK) {
    fail("station MAC unreadable");
  }
  owner_config.joiner.node = owner_config.local_node;
  owner_config.joiner.mac = owner_config.local_mac;
  owner_config.log_tag = kTag;
  owner_config.gateway = true;  // USB-attached: relay + direct local channel
  status = owner.begin(sdkv1_stores, entropy, owner_config);
  if (!status) fail(status.detail);
  routeloom::SecurityProvider& session_security = owner.session_provider();
#endif

#if CONFIG_ROUTELOOM_MIGRATION
  // Channel migration (issue #5): durable plan/commit/active state. The
  // plan store opens BEFORE the runtime so a committed channel can pick the
  // radio's boot channel — a blob alone never switches the radio, and
  // restart() still runs the participant's resume checks.
  static routeloom::espnow::NvsPlanStore plan_store;
  status = plan_store.open("rlplan");
  if (!status) fail(status.detail);
  std::uint8_t boot_channel = 0;
  const bool have_boot_channel = plan_store.boot_channel(boot_channel).ok();
#endif

#if CONFIG_ROUTELOOM_TRUST_STORE
  // Production trust stores (sdk-completion/04-provisioning-lifecycle.md
  // §4.2.2/§4.4): the RLT1 trust image ("rltrust" t0/t1) and the RLC1
  // device credential ("rlcred" d0/d1) are validated at boot. Impairment
  // is never node-fatal and never triggers an erase or reformat — a
  // quarantined store logs REPROVISION_REQUIRED and the node keeps
  // routing degraded.
  //
  // Scope honesty: this profile is the USB host-side gateway — it has NO
  // config-target permit verifier (that lives on the target node's
  // ConfigJournal, e.g. reference_node). The store here supplies boot
  // diagnostics plus the mesh network identity; nothing consumes the
  // credential yet (the membership/EDHOC workstream owns that). There is
  // NO install verb and no manufactured provisioning flow in this
  // firmware — first install is a physical/deployment act owned by the
  // host tooling workstream (routeloom-provision).
  static routeloom::espnow::NvsTrustStore trust_store_storage;
  auto trust_status = trust_store_storage.open("rltrust");
  if (!trust_status) {
    ESP_LOGE(kTag, "trust store open failed: %s", trust_status.detail);
  }
  static routeloom::espnow::NvsCredStore cred_store_storage;
  auto cred_status = cred_store_storage.open("rlcred");
  if (!cred_status) {
    ESP_LOGE(kTag, "credential store open failed: %s", cred_status.detail);
  }
  static routeloom::TrustStore trust_store(trust_store_storage);
  static routeloom::DeviceCredentialStore credential_store(
      cred_store_storage);
  trust_status = trust_store.initialize();
  if (!trust_status) {
    ESP_LOGE(kTag, "trust store init: %s", trust_status.detail);
  }
  cred_status = credential_store.initialize();
  if (!cred_status) {
    ESP_LOGE(kTag, "credential store init: %s", cred_status.detail);
  }
  if (trust_store.quarantined() || credential_store.quarantined()) {
    ESP_LOGE(kTag,
             "REPROVISION_REQUIRED: trust/credential store quarantined — "
             "recovery is an explicit operator act, never an implicit reset");
  } else if (trust_store.uncertain() || credential_store.uncertain()) {
    ESP_LOGE(kTag,
             "REPROVISION_REQUIRED: trust/credential sibling state unproven "
             "— possibly-stale state is refused until recover()");
  }
  ESP_LOGI(kTag,
           "trust store: epoch=%lu gen_floor=%lu anchors=%u keys=%u "
           "revocations=%u flags=0x%02x active=%d uncertain=%d quarantined=%d",
           static_cast<unsigned long>(trust_store.store_epoch()),
           static_cast<unsigned long>(trust_store.min_authority_generation()),
           static_cast<unsigned>(trust_store.image().anchor_count),
           static_cast<unsigned>(trust_store.image().key_count),
           static_cast<unsigned>(trust_store.image().revocation_count),
           static_cast<unsigned>(trust_store.flags()),
           trust_store.has_active() ? 1 : 0,
           trust_store.uncertain() ? 1 : 0,
           trust_store.quarantined() ? 1 : 0);
  if (credential_store.has_active()) {
    const routeloom::DeviceCredential& credential =
        credential_store.credential();
    ESP_LOGI(kTag,
             "credential: node=%llu key_location=%u status=%u grant=%uB "
             "generation_base=%lu",
             static_cast<unsigned long long>(credential.node_id),
             static_cast<unsigned>(credential.key_location),
             static_cast<unsigned>(credential.cred_status),
             static_cast<unsigned>(credential.grant.size),
             static_cast<unsigned long>(credential.generation_base_session));
    // §4.8 epoch-window check: when (session - generation_base_session)
    // reaches the 0xFFF0 threshold the next boots would wrap the u16 wire
    // epoch under peer floors that can never accept it — the design's
    // REPROVISION_REQUIRED wedge, reported as a diagnostic (the dev link
    // profile still brings the mesh up; the production credential epoch
    // has no consumer wired yet).
    std::uint16_t credential_epoch = 0;
    const routeloom::Status epoch_status =
        routeloom::credential_epoch_for_session(
            message_session, credential.generation_base_session,
            credential_epoch);
    if (!epoch_status) {
      ESP_LOGE(kTag,
               "REPROVISION_REQUIRED: credential epoch window — %s "
               "(session=%lu base=%lu)",
               epoch_status.detail,
               static_cast<unsigned long>(message_session),
               static_cast<unsigned long>(
                   credential.generation_base_session));
    }
  } else {
    ESP_LOGI(kTag,
             "credential: none provisioned (uncertain=%d quarantined=%d)",
             credential_store.uncertain() ? 1 : 0,
             credential_store.quarantined() ? 1 : 0);
  }
  // §4.8: the provisioned NetworkId carries the deployment generation in
  // the upper 32 bits. Wire v1 encodes only the low 32 (wire.cpp rejects
  // >u32), so the radio/mesh identity is the low half. Building
  // SecurityContexts from the provisioned u64 rather than the wire field
  // is the membership/endpoint workstream — deliberately NOT wired here.
  const routeloom::NetworkId provisioned_network =
      trust_store.has_active()
          ? (trust_store.network() & 0xFFFFFFFFULL)
          : static_cast<routeloom::NetworkId>(CONFIG_ROUTELOOM_NETWORK_ID);
  if (trust_store.has_active() &&
      provisioned_network !=
          static_cast<routeloom::NetworkId>(CONFIG_ROUTELOOM_NETWORK_ID)) {
    ESP_LOGW(kTag,
             "trust image network low32 0x%08lx overrides static 0x%08x",
             static_cast<unsigned long>(provisioned_network),
             static_cast<unsigned>(CONFIG_ROUTELOOM_NETWORK_ID));
  }
  // §4.9 wear instrumentation: committed-write counters, same WriteStats
  // shape as the config-journal adapter (boot baseline; nothing below
  // commits to these stores yet).
  const auto trust_writes = trust_store_storage.write_stats();
  const auto cred_writes = cred_store_storage.write_stats();
  ESP_LOGI(kTag, "store writes: trust=%llu/%lluB cred=%llu/%lluB",
           static_cast<unsigned long long>(trust_writes.commits),
           static_cast<unsigned long long>(trust_writes.bytes),
           static_cast<unsigned long long>(cred_writes.commits),
           static_cast<unsigned long long>(cred_writes.bytes));
#endif

  // The bridge protocol owns USB Serial/JTAG exclusively; the console was
  // moved to UART0 in sdkconfig.defaults so log text can never interleave
  // into the COBS stream.
  usb_serial_jtag_driver_config_t usb_config{};
  usb_config.rx_buffer_size = 1024;
  usb_config.tx_buffer_size = 1024;
  if (usb_serial_jtag_driver_install(&usb_config) != ESP_OK) {
    fail("usb serial jtag install failed");
  }

  static UsbSerialStream stream;
  static routeloom::usb::UsbBridge::Config bridge_config;
  const char* secret = CONFIG_ROUTELOOM_USB_DEV_SECRET;
  bridge_config.secret =
      ByteView{reinterpret_cast<const std::uint8_t*>(secret),
               std::strlen(secret)};
  bridge_config.node = CONFIG_ROUTELOOM_NODE_ID;
#if CONFIG_ROUTELOOM_TRUST_STORE
  // The bridge reports the same provisioned mesh identity as the radio.
  bridge_config.network = provisioned_network;
#else
  bridge_config.network = CONFIG_ROUTELOOM_NETWORK_ID;
#endif
  // Boot ID doubles as the persisted boot session: a host can tell a reboot
  // apart from a reconnect and must never see the value regress.
  bridge_config.boot_id = message_session;
  bridge_config.capability = CONFIG_ROUTELOOM_CAPABILITY;

  static routeloom::usb::UsbBridge bridge(bridge_config, stream);

  EspNowRuntimeConfig config{};
#if CONFIG_ROUTELOOM_TRUST_STORE
  // The committed trust image owns the deployment's network identity;
  // only the low 32 bits are wire-visible on Wire v1 (see above).
  config.node.network = provisioned_network;
#else
  config.node.network = CONFIG_ROUTELOOM_NETWORK_ID;
#endif
  config.node.node = CONFIG_ROUTELOOM_NODE_ID;
  config.node.message_session = message_session;
  // Explicit durable boot token (G-SEC P4 §9.1): identical to the compat
  // init for the legacy provider, explicit-nonzero for session providers.
  config.node.boot_session = message_session;
  config.node.boot_incarnation = message_session;
  // Origin generation must rise every boot so peers discard the previous
  // incarnation's route state. It is derived from the persisted monotonic
  // boot session itself (Wire v2: 32-bit, never wraps in a device lifetime;
  // the session is already >= 1, 0 stays the "unset" sentinel).
  config.node.route_generation = message_session;
  // Replay epochs advance with every boot (see reference_node): a reused
  // epoch can never re-establish a lost replay window — the persisted floor
  // would reject it forever (replay.cpp REPLAY_STATE_LOST wedge).
  config.node.link_epoch = config.node.route_generation;
  config.node.end_epoch = config.node.route_generation;
#if CONFIG_ROUTELOOM_ROUTE_GATEWAY_SCOPED
  // Gateway-scoped routing profile (docs/design/sdk-v1/routing-scale.md,
  // issue #41). The bridge is the site gateway and lists itself first; a
  // violating lease would only surface at boot as
  // ROUTE_LIFETIME_BELOW_REFRESH_BOUND, so refuse the build instead.
  static_assert(CONFIG_ROUTELOOM_ROUTE_GATEWAY_2 != CONFIG_ROUTELOOM_NODE_ID,
                "ROUTELOOM_ROUTE_GATEWAY_2 must differ from this bridge's NODE_ID");
  static_assert(routeloom::scoped_lifetime_sufficient(
                    static_cast<std::uint32_t>(CONFIG_ROUTELOOM_ROUTE_PERIOD_MS),
                    static_cast<std::uint32_t>(CONFIG_ROUTELOOM_ROUTE_LIFETIME_MS),
                    routeloom::kScopedDefaultRefreshTicks),
                "ROUTELOOM_ROUTE_LIFETIME_MS below (2 * 6 + 2) * ROUTELOOM_ROUTE_PERIOD_MS");
  config.node.route_gateways[0] = config.node.node;
  config.node.route_gateways[1] =
      static_cast<routeloom::NodeId>(CONFIG_ROUTELOOM_ROUTE_GATEWAY_2);
  config.node.route_advertisement_period_ms =
      static_cast<std::uint32_t>(CONFIG_ROUTELOOM_ROUTE_PERIOD_MS);
  config.node.route_lifetime_ms =
      static_cast<std::uint32_t>(CONFIG_ROUTELOOM_ROUTE_LIFETIME_MS);
  ESP_LOGI(kTag,
           "routing profile: gateway-scoped gateways=0x%" PRIx64 ",0x%" PRIx64
           " tick=%" PRIu32 "ms lease=%" PRIu32 "ms",
           config.node.route_gateways[0], config.node.route_gateways[1],
           config.node.route_advertisement_period_ms, config.node.route_lifetime_ms);
#endif
  config.channel = CONFIG_ROUTELOOM_CHANNEL;
#if CONFIG_ROUTELOOM_MIGRATION
  if (have_boot_channel) {
    ESP_LOGW(kTag, "migration boot channel %u overrides static %u",
             static_cast<unsigned>(boot_channel),
             static_cast<unsigned>(config.channel));
    config.channel = boot_channel;
  }
#endif
  config.max_tx_power_qdbm = CONFIG_ROUTELOOM_TX_POWER_QDBM;

#if CONFIG_ROUTELOOM_MIGRATION
  routeloom::espnow::EspNowMigrationConfig migration_config{};
  const bool self_authority =
#if CONFIG_ROUTELOOM_MIGRATION_SELF_AUTHORITY
      true;
#else
      false;
#endif
  migration_config.mode = CONFIG_ROUTELOOM_MIGRATION == 1
                              ? routeloom::MigrationMode::Observe
                              : routeloom::MigrationMode::Manual;
  migration_config.authority_role = self_authority;
  migration_config.agent.authority_role = self_authority;
  migration_config.agent.participant.node = config.node.node;
  migration_config.agent.participant.network = config.node.network;
  migration_config.agent.participant.authority =
      self_authority ? config.node.node
                     : static_cast<NodeId>(CONFIG_ROUTELOOM_MIGRATION_AUTHORITY);
  migration_config.agent.participant.home_channel = config.channel;
  migration_config.agent.self_rediscovery_capable = true;
  // Measurement inputs are deployment parameters, not firmware guesses.
  migration_config.agent.measurements.management_rtt_p99_ms =
      CONFIG_ROUTELOOM_MIGRATION_RTT_P99_MS;
  migration_config.agent.measurements.control_delivery_bound_ms =
      CONFIG_ROUTELOOM_MIGRATION_DELIVERY_BOUND_MS;
  migration_config.agent.measurements.required_transfer_ms =
      CONFIG_ROUTELOOM_MIGRATION_TRANSFER_BOUND_MS;
  migration_config.agent.measurements.measured_switch_bound_ms =
      CONFIG_ROUTELOOM_MIGRATION_SWITCH_BOUND_MS;
  migration_config.coordinator.node = config.node.node;
  migration_config.coordinator.home_channel = config.channel;
  // Commit evidence derives from the same dev-PSK master key, domain
  // separated inside the verifier — Development profile only.
  static routeloom::espnow::DevPskCommitVerifier commit_verifier;
  status = commit_verifier.initialize(key);
  if (!status) fail(status.detail);
#endif
#if CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
  routeloom::secure_clear(key);
#endif

  // The bridge is the node's observer: mesh deliveries and diagnostics are
  // reported to the host as DataFromMesh/Delivery/Diag frames.
  static EspNowRuntime runtime(config, session_security, bridge);
  status = runtime.initialize();
  if (!status) fail(status.detail);
#if !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
  // Owner profile: boot after radio-up — entropy.begin() draws post-RF
  // randomness, then boot() arms the cookie sealer from it. usb_direct
  // selects the gateway's USB local-join transport (G-SEC P4 §8.2); an
  // already-provisioned gateway resumes its membership either way.
  status = entropy.begin();
  if (!status) fail(status.detail);
  status = owner.attach_runtime(runtime);
  if (!status) fail(status.detail);
  status = owner.attach_usb(bridge);
  if (!status) fail(status.detail);
#if CONFIG_ROUTELOOM_SECURITY_MODE_DEV_RAM
  // Dev route (P4 §10.1): adoption without joining — the reserved dev
  // boot plus the static PSK/network/node/channel adopt the node
  // directly; group send/receive serves from here on.
  routeloom::keys::Secret dev_psk{};
  if (!parse_hex(CONFIG_ROUTELOOM_DEVELOPMENT_KEY_HEX, dev_psk)) {
    fail("invalid development key");
  }
  EspNowSecurityOwner::DevGroupConfig dev_config{};
  dev_config.psk = dev_psk;
  routeloom::secure_clear(dev_psk);
  dev_config.network = static_cast<routeloom::NetworkId>(CONFIG_ROUTELOOM_NETWORK_ID);
  dev_config.node = CONFIG_ROUTELOOM_NODE_ID;
  dev_config.channel = static_cast<std::uint8_t>(CONFIG_ROUTELOOM_CHANNEL);
  dev_config.boot = message_session;
  dev_config.role = routeloom::sdkv1::kMemberRoleEndpoint | routeloom::sdkv1::kMemberRoleRelay;
  status = owner.adopt_dev(dev_config, monotonic_now_ms());
  if (!status) fail(status.detail);
#else
  status = owner.boot(message_session, /*rlboot_prepared=*/true,
                      /*usb_direct=*/true, monotonic_now_ms());
  if (!status) fail(status.detail);
  // Authority lane (G-SEC P5): the relay demux serves terminal 22/49/50/51
  // for USB-bound devices plus the gateway's own channel.
  runtime.node().set_config_sink(owner.authority_mesh_sink());
#endif
#endif
  bridge.set_mesh(&runtime.node());
  // Device nonce seeds the session transcript; sampling esp_random only
  // once the radio is up follows the entropy contract (security spec §9):
  // pre-RF hardware RNG draws weaker entropy. Set before the pump loop so
  // no HELLO can observe a zero nonce; per-boot uniqueness still holds
  // even if the same host nonce recurs.
  bridge.set_device_nonce(
      (static_cast<std::uint64_t>(esp_random()) << 32U) | esp_random());

  // Gateway endpoint (scope-gateway-config P3): one component owns the mesh
  // responder role AND the host-originated send path. The USB capability
  // bit gates both — a build that does not advertise it never answers a
  // Query and never accepts a registration. The node's own poll drives the
  // sink through the service-sink interface (attach() installs it).
  static ROUTELOOM_MEMBER_C5_LP routeloom::GatewayDelivery gateway(runtime.node());
  if ((bridge_config.capability & routeloom::usb::kCapGatewayEndpointV1) !=
      0) {
    status = bridge.attach_gateway(gateway);
    if (!status) fail(status.detail);
  }

  // Config endpoint (scope-gateway-config P5): the bridge issues Config
  // challenge/status queries and kind-3 permit transfers toward a target on
  // the host's behalf over the routed end-protected lane. The bridge is the
  // component's ConfigHostSink — each async outcome is framed back to the
  // host under the 0x21/0x22/0x23 subcommand it was requested with. The
  // CAP_CONFIG_ENDPOINT_V1 bit gates admission; without it the ops answer
  // Unsupported. The node poll drives the component's bounded retries.
  static routeloom::MeshConfigPort config_port(runtime.node());
  static ROUTELOOM_MEMBER_SMALL_LP routeloom::ConfigGateway config_gateway(config_port, bridge);
  if ((bridge_config.capability & routeloom::usb::kCapConfigEndpointV1) != 0) {
    status = bridge.attach_config(config_gateway);
    if (!status) fail(status.detail);
  }

  // M1 diagnostics (m1-completion D1d): the bridge answers HostOps 0x30
  // diagnostic requests — local capabilities inline, remote telemetry via
  // the routed type-48 lane — and streams 0x31 replies back. Without the
  // bit the subcommands answer Unsupported; no mesh sink is installed.
  if ((bridge_config.capability & routeloom::usb::kCapM1DiagnosticsV1) != 0) {
    status = bridge.attach_diagnostics();
    if (!status) fail(status.detail);
  }

  // Node status (node_status_v1): the bridge answers HostOps 0x40 paginated
  // per-node link/route snapshots and, once the host subscribes, streams
  // 0x42 join/leave/route-change events. Read-only over the node's tables;
  // without the bit the query answers Unsupported and no event is emitted.
  if ((bridge_config.capability & routeloom::usb::kCapNodeStatusV1) != 0) {
    status = bridge.attach_node_status();
    if (!status) fail(status.detail);
  }

  // Group delivery (group_delivery_v1): the bridge answers HostOps 0x50
  // GROUP_SEND / 0x52 GROUP_QUERY with 0x51 summaries. The node itself
  // refuses a send unless it is a route gateway of the gateway-scoped
  // profile; without the bit every group op answers Unsupported.
  if ((bridge_config.capability & routeloom::usb::kCapGroupDeliveryV1) != 0) {
    status = bridge.attach_group();
    if (!status) fail(status.detail);
  }

#if CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
  if (CONFIG_ROUTELOOM_PEER_NODE_ID != 0) {
    MacAddress mac{};
    if (!parse_mac(CONFIG_ROUTELOOM_PEER_MAC, mac)) {
      fail("invalid peer MAC");
    }
    status =
        runtime.register_neighbor(CONFIG_ROUTELOOM_PEER_NODE_ID, mac, 1);
    if (!status) fail(status.detail);
  }
#endif

#if CONFIG_ROUTELOOM_DISCOVERY
  // Autonomous discovery (issue #3): the RLD1 bootstrap lane plus the
  // portable NeighborDiscovery engine, attached to the runtime's
  // DiscoveryPort. Dev-PSK possession authentication only — EXPERIMENTAL.
  // The USB bridge path is unaffected: bridge stays the NodeObserver and the
  // single-threaded pump loop drives the engine via runtime.poll_once().
  routeloom::MacAddress self_mac{};
  status = runtime.local_mac(self_mac);
  if (!status) fail(status.detail);
  routeloom::DiscoveryConfig discovery_config{};
  discovery_config.node = config.node.node;
  discovery_config.mac = self_mac;
  discovery_config.network = config.node.network;
  // The 4-byte hint is a discovery filter only, never membership evidence.
  discovery_config.network_hint =
      static_cast<std::uint32_t>(config.node.network);
  discovery_config.capability_bits = CONFIG_ROUTELOOM_CAPABILITY;
#if CONFIG_ROUTELOOM_DISCOVERY_SCOPE != 0
  // Discovery Scope Key (issue #14): the dev-profile provider derives
  // per-generation keys from the configured base key. A scoped mode whose
  // key cannot install fails boot — never a silent Off downgrade.
  static routeloom::espnow::DevScopeProvider scope_provider(
      routeloom::ScopeRef{CONFIG_ROUTELOOM_DISCOVERY_SCOPE_REF});
  std::array<std::uint8_t, routeloom::kScopeKeyBytes> scope_key{};
  if (!parse_hex(CONFIG_ROUTELOOM_DISCOVERY_SCOPE_KEY_HEX, scope_key)) {
    fail("invalid ROUTELOOM_DISCOVERY_SCOPE_KEY_HEX");
  }
  status = scope_provider.install(
      routeloom::ByteView{scope_key.data(), scope_key.size()},
      CONFIG_ROUTELOOM_DISCOVERY_SCOPE_GENERATION, 0);
  routeloom::secure_clear(scope_key);
  if (!status) fail(status.detail);
  discovery_config.scope_mode =
      static_cast<routeloom::ScopeMode>(CONFIG_ROUTELOOM_DISCOVERY_SCOPE);
  discovery_config.scope_provider = &scope_provider;
  discovery_config.scope = scope_provider.ref();
#endif
  routeloom::espnow::EspNowAutonomyPolicy autonomy_policy{};
#if CONFIG_ROUTELOOM_DISCOVERY_MEMBER
  autonomy_policy.self_member = true;
#else
  autonomy_policy.self_member = false;
#endif
#if CONFIG_ROUTELOOM_DISCOVERY_AUTO_APPROVE
  autonomy_policy.auto_approve = true;
#else
  autonomy_policy.auto_approve = false;
#endif
#if CONFIG_ROUTELOOM_DISCOVERY_INITIATE
  autonomy_policy.initiate = true;
#else
  autonomy_policy.initiate = false;
#endif
  static routeloom::espnow::EspNowAutonomy autonomy(
      discovery_config, autonomy_policy, runtime, security, kTag);
  status = autonomy.start();
  if (!status) fail(status.detail);
  ESP_LOGW(kTag,
           "EXPERIMENTAL discovery active: dev-PSK possession proof is not "
           "a production identity");
#endif

#if CONFIG_ROUTELOOM_MIGRATION
  // Channel migration (issue #5): participant + coordinator over the
  // authenticated control-object lane. The single-threaded pump below drives
  // the agent through runtime.poll_once(). The authority role additionally
  // needs a durable authority ledger before it may issue.
  // Wired vs host-only: this node executes inbound verified commits and runs
  // surveys/cutover; nothing local mints a plan — MigrationAuthority::
  // commit_plan() has no firmware/USB caller today and is exercised by host
  // tests only.
  static routeloom::espnow::NvsLedgerStore authority_ledger;
  if (self_authority) {
    status = authority_ledger.open("rlmauth");
    if (!status) fail(status.detail);
  }
  static routeloom::espnow::EspNowMigration migration(
      migration_config, runtime, plan_store, commit_verifier,
      self_authority ? &authority_ledger : nullptr);
  status = migration.start();
  if (!status) fail(status.detail);
  ESP_LOGW(kTag,
           "EXPERIMENTAL migration lane active (mode=%d): dev-PSK commit "
           "evidence is not a production identity",
           CONFIG_ROUTELOOM_MIGRATION);
#endif

#if CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
  status = runtime.start();
  if (!status) fail(status.detail);
#else
  ESP_LOGI(kTag,
           "security owner started; node start deferred to membership");
#endif
  // Boot complete — the pump loop below is the node's main loop, so a
  // later fatal is a runtime fault rather than a boot-loop streak.
  routeloom::fail_streak_runtime_started(s_fail);

#if CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
  if (security.security_profile() != routeloom::SecurityProfile::Production) {
    ESP_LOGW(
        kTag,
        "EXPERIMENTAL bridge started; development PSK is not a production "
        "identity profile");
  }
#endif

  // Power management is deliberately unwired on this profile: the bridge is
  // a USB-powered always-on gateway — deep sleep would sever the USB
  // Serial/JTAG session and its mesh presence, and no HostOps verb requests
  // sleep, so there is no real sleep/wake integration point to hook. The
  // PowerCoordinator/EspNowPowerPort path is wired (and CI-compiled) only on
  // the reference node under CONFIG_ROUTELOOM_DEEP_SLEEP; for this firmware
  // it remains host-tested only.
  // Single-threaded pump: app_main owns serial RX, the bridge's periodic
  // work (handshake/credit/partial-frame timeouts, TX pump) and the runtime
  // event drain, so no extra task can interleave bridge polls.
  static std::array<std::uint8_t, 512> rx{};
  for (;;) {
    const int received = usb_serial_jtag_read_bytes(
        rx.data(), rx.size(), pdMS_TO_TICKS(0));
    if (received > 0) {
      bridge.on_bytes(
          ByteView{rx.data(), static_cast<std::size_t>(received)},
          monotonic_now_ms());
    }
    bridge.poll(monotonic_now_ms());
    runtime.poll_once();
#if !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
    owner.poll(monotonic_now_ms());
#endif
    runtime.wait_for_event(routeloom::kOwnerPollPeriodMs);
  }
}
