#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "driver/usb_serial_jtag.h"
#include "esp_attr.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_sleep.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "sdkconfig.h"
#if CONFIG_ROUTELOOM_DISCOVERY
#include "routeloom/espnow_autonomy.hpp"
#include "routeloom/espnow_scope_provider.hpp"
#endif
#if CONFIG_ROUTELOOM_MIGRATION
#include "routeloom/espnow_migration.hpp"
#include "routeloom/nvs_ledger_store.hpp"
#endif
#include "routeloom/config_wire.hpp"
#include "routeloom/espnow_runtime.hpp"
#include "routeloom/nvs_counter_store.hpp"
#include "routeloom/psk_security.hpp"
#include "routeloom/usb_bridge.hpp"

namespace {
constexpr char kTag[] = "RouteLoomBr";

using routeloom::ByteView;
using routeloom::NodeId;
using routeloom::Status;
using routeloom::StatusCode;
using routeloom::espnow::DevelopmentPskSecurityProvider;
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

int hex_value(const char value) noexcept {
  if (value >= '0' && value <= '9') return value - '0';
  const char lower =
      static_cast<char>(std::tolower(static_cast<unsigned char>(value)));
  if (lower >= 'a' && lower <= 'f') return lower - 'a' + 10;
  return -1;
}

template <std::size_t Size>
bool parse_hex(const char* text,
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

bool parse_mac(const char* text, MacAddress& mac) noexcept {
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

Status next_boot_session(std::uint32_t& session) noexcept {
  nvs_handle_t handle = 0;
  esp_err_t error = nvs_open("rlboot", NVS_READWRITE, &handle);
  if (error != ESP_OK) {
    return Status::error(StatusCode::StorageFailure,
                         "boot nvs_open failed");
  }
  std::uint32_t stored = 0;
  error = nvs_get_u32(handle, "session", &stored);
  if (error != ESP_OK && error != ESP_ERR_NVS_NOT_FOUND) {
    nvs_close(handle);
    return Status::error(StatusCode::StorageFailure,
                         "boot session read failed");
  }
  session = stored + 1U;
  if (session == 0) {
    nvs_close(handle);
    return Status::error(StatusCode::CounterExhausted,
                         "boot session exhausted");
  }
  error = nvs_set_u32(handle, "session", session);
  if (error == ESP_OK) error = nvs_commit(handle);
  nvs_close(handle);
  return error == ESP_OK
             ? Status::success()
             : Status::error(StatusCode::StorageFailure,
                             "boot session commit failed");
}

[[noreturn]] void fail(const char* detail) {
  ESP_LOGE(kTag, "fatal: %s", detail);
  for (;;) vTaskDelay(pdMS_TO_TICKS(1000));
}

routeloom::MonotonicMs monotonic_now_ms() noexcept {
  return static_cast<routeloom::MonotonicMs>(esp_timer_get_time() / 1000);
}

}  // namespace

extern "C" void app_main(void) {
  // Identity, nonce reservations, replay state and message sessions share NVS.
  // Never erase it automatically after a version/capacity error: that would
  // silently turn a recoverable storage problem into key/counter rollback.
  const esp_err_t nvs_error = nvs_flash_init();
  if (nvs_error != ESP_OK) {
    ESP_LOGE(kTag,
             "NVS init failed (%s); automatic erase is disabled, explicit "
             "recovery is required",
             esp_err_to_name(nvs_error));
    fail("NVS initialization failed");
  }

  static NvsCounterStore counter_store;
  auto status = counter_store.open("rlcounter");
  if (!status) fail(status.detail);

  std::array<std::uint8_t,
             DevelopmentPskSecurityProvider::kMasterKeySize>
      key{};
  if (!parse_hex(CONFIG_ROUTELOOM_DEVELOPMENT_KEY_HEX, key)) {
    fail("invalid development key");
  }
  static DevelopmentPskSecurityProvider security;
  status = security.initialize(key, counter_store, "rlreplay");
  if (!status) fail(status.detail);

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

  std::uint32_t message_session = 0;
  status = next_boot_session(message_session);
  if (!status) fail(status.detail);

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
  bridge_config.network = CONFIG_ROUTELOOM_NETWORK_ID;
  // Boot ID doubles as the persisted boot session: a host can tell a reboot
  // apart from a reconnect and must never see the value regress.
  bridge_config.boot_id = message_session;
  bridge_config.capability = CONFIG_ROUTELOOM_CAPABILITY;
  // Device nonce seeds the session transcript; hardware RNG makes every
  // boot's handshake unique even if the same host nonce recurs.
  bridge_config.device_nonce =
      (static_cast<std::uint64_t>(esp_random()) << 32U) | esp_random();

  static routeloom::usb::UsbBridge bridge(bridge_config, stream);

  EspNowRuntimeConfig config{};
  config.node.network = CONFIG_ROUTELOOM_NETWORK_ID;
  config.node.node = CONFIG_ROUTELOOM_NODE_ID;
  config.node.message_session = message_session;
  config.node.boot_incarnation = message_session;
  // Origin generation must rise every boot so peers discard the previous
  // incarnation's route state. It is derived from the persisted monotonic
  // boot session, mapped into 1..0xFFFF (0 is the "unset" sentinel).
  config.node.route_generation = static_cast<std::uint16_t>(
      ((message_session - 1U) % 0xFFFFU) + 1U);
  // Replay epochs advance with every boot (see reference_node): a reused
  // epoch can never re-establish a lost replay window — the persisted floor
  // would reject it forever (replay.cpp REPLAY_STATE_LOST wedge).
  config.node.link_epoch = config.node.route_generation;
  config.node.end_epoch = config.node.route_generation;
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
  std::fill(key.begin(), key.end(), 0);

  // The bridge is the node's observer: mesh deliveries and diagnostics are
  // reported to the host as DataFromMesh/Delivery/Diag frames.
  static EspNowRuntime runtime(config, security, bridge);
  status = runtime.initialize();
  if (!status) fail(status.detail);
  bridge.set_mesh(&runtime.node());

  // Gateway endpoint (scope-gateway-config P3): one component owns the mesh
  // responder role AND the host-originated send path. The USB capability
  // bit gates both — a build that does not advertise it never answers a
  // Query and never accepts a registration. The node's own poll drives the
  // sink through the service-sink interface (attach() installs it).
  static routeloom::GatewayDelivery gateway(runtime.node());
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
  static routeloom::ConfigGateway config_gateway(config_port, bridge);
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

  if (CONFIG_ROUTELOOM_PEER_NODE_ID != 0) {
    MacAddress mac{};
    if (!parse_mac(CONFIG_ROUTELOOM_PEER_MAC, mac)) {
      fail("invalid peer MAC");
    }
    status =
        runtime.register_neighbor(CONFIG_ROUTELOOM_PEER_NODE_ID, mac, 1);
    if (!status) fail(status.detail);
  }

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
  scope_key.fill(0);
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

  status = runtime.start();
  if (!status) fail(status.detail);

  if (security.security_profile() != routeloom::SecurityProfile::Production) {
    ESP_LOGW(
        kTag,
        "EXPERIMENTAL bridge started; development PSK is not a production "
        "identity profile");
  }

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
    vTaskDelay(pdMS_TO_TICKS(2));
  }
}
