#include "routeloom/espnow_sdkv1.hpp"

#include <cinttypes>
#include <cstring>

#include "driver/usb_serial_jtag.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include "routeloom/espnow_sdkv1_entropy.hpp"
#include "routeloom/nvs_legacy_purge.hpp"
#include "routeloom/sdkv1_dev_session.hpp"
#include "routeloom/sdkv1_legacy_purge.hpp"
#include "routeloom/sdkv1_maintenance.hpp"
#include "routeloom/secure_clear.hpp"
#include "sdkconfig.h"

namespace routeloom::espnow {
namespace {

constexpr char kTag[] = "RouteLoomSdkv1";
// The console task owns the engine's worst-case ~4 KiB frame plus the USB
// driver calls; 8 KiB leaves headroom without touching the main task.
constexpr std::uint32_t kConsoleTaskStack = 8192;

int hex_value(const char value) noexcept {
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return value - 'a' + 10;
  if (value >= 'A' && value <= 'F') return value - 'A' + 10;
  return -1;
}

// Resolve the maintenance domain for the running profile. A stale site
// record in a DevRam image cannot change the fingerprint away from the
// configured PSK domain; an unadopted Member image has no purge domain.
bool resolve_legacy_domain(Sdkv1Stores& stores,
                           sdkv1::MaintenanceFingerprint& out) noexcept {
  out = sdkv1::MaintenanceFingerprint{};
#if CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC
  if (stores.site().has_site() && stores.identity().has_identity()) {
    const sdkv1::SiteRecord& site = stores.site().site();
    const sdkv1::IdentityRecord& identity = stores.identity().identity();
    if (!sdkv1::site_matches_identity(site, identity)) return false;
    const ByteView cert = site.site_cert.view();
    if (cert.size == 0) return false;
    const Status ok = sdkv1::member_maintenance_fingerprint_for_site_cert(
        1, site.network, identity.node_id, site.site_id, cert, out);
    return ok.ok();
  }
  return false;
#else
  (void)stores;
#ifdef CONFIG_ROUTELOOM_DEVELOPMENT_KEY_HEX
  const char* hex = CONFIG_ROUTELOOM_DEVELOPMENT_KEY_HEX;
  keys::Secret psk{};
  if (hex == nullptr || std::strlen(hex) != psk.size() * 2) return false;
  for (std::size_t i = 0; i < psk.size(); ++i) {
    const int high = hex_value(hex[i * 2]);
    const int low = hex_value(hex[i * 2 + 1]);
    if (high < 0 || low < 0) {
      secure_clear(psk);
      return false;
    }
    psk[i] = static_cast<std::uint8_t>((high << 4) | low);
  }
  const Status ok = sdkv1::dev_maintenance_fingerprint(
      psk, 2, static_cast<NetworkId>(CONFIG_ROUTELOOM_NETWORK_ID),
      static_cast<NodeId>(CONFIG_ROUTELOOM_NODE_ID), out);
  secure_clear(psk);
  return ok.ok();
#else
  return false;
#endif
#endif
}

// Exact `status` match for the unknown-domain fallback (see above): kept
// next to the router so a future console verb cannot silently slip past
// the purge gate — any new mutating verb must extend this predicate.
bool is_legacy_status_only(const ByteView rest) noexcept {
  static constexpr char kStatus[] = "status";
  return rest.size == sizeof(kStatus) - 1 &&
         std::memcmp(rest.data, kStatus, rest.size) == 0;
}

// Pre-P4 images kept RLP1 resume slots in the `rlres` namespace; no live
// code uses it anymore. Probe read-only so a fresh device never creates
// that namespace. Erase before opening the live stores to reclaim space
// needed for their namespaces. Failure is logged; stale blobs cannot
// be used as RLP2 slots.
void purge_legacy_rlres(const char* partition) noexcept {
  nvs_handle_t handle = 0;
  const esp_err_t opened =
      nvs_open_from_partition(partition, sdkv1::kResumeNamespace, NVS_READONLY, &handle);
  if (opened == ESP_ERR_NVS_NOT_FOUND) return;  // nothing ever written
  if (opened != ESP_OK) {
    ESP_LOGW(kTag, "rlres purge: open failed (%s)", esp_err_to_name(opened));
    return;
  }
  std::size_t used = 0;
  const esp_err_t counted = nvs_get_used_entry_count(handle, &used);
  if (counted != ESP_OK) {
    ESP_LOGW(kTag, "rlres purge: count failed (%s)", esp_err_to_name(counted));
    nvs_close(handle);
    return;
  }
  if (used == 0) {
    nvs_close(handle);
    return;
  }
  nvs_close(handle);
  handle = 0;
  const esp_err_t writable =
      nvs_open_from_partition(partition, sdkv1::kResumeNamespace, NVS_READWRITE, &handle);
  if (writable != ESP_OK) {
    ESP_LOGW(kTag, "rlres purge: writable open failed (%s)", esp_err_to_name(writable));
    return;
  }
  esp_err_t erased = nvs_erase_all(handle);
  if (erased == ESP_OK) erased = nvs_commit(handle);
  if (erased != ESP_OK) {
    ESP_LOGW(kTag, "rlres purge: erase failed (%s)", esp_err_to_name(erased));
  } else {
    ESP_LOGI(kTag, "rlres purge: erased %u stale RLP1 entries", static_cast<unsigned>(used));
  }
  nvs_close(handle);
}

void console_task(void* arg) {
  Sdkv1Stores* stores = static_cast<Sdkv1Stores*>(arg);
  EspMaintenanceEntropy entropy;
  const Status entropy_status = entropy.begin();
  if (!entropy_status) {
    ESP_LOGE(kTag, "maintenance entropy unavailable: %s", entropy_status.detail);
  }
  sdkv1::MaintenanceConsole console(stores->identity(), entropy);
  // The `security legacy-state` verb rides the same exclusive physical
  // console (P4 §10.2): the maintenance boot never starts radio, USB
  // lanes or the Node, so `stopped` below is structural, not polled.
  NvsLegacyPurgePort purge_port;
  static char line[sdkv1::kMaintenanceLineMax + 2];
  static char response[sdkv1::kMaintenanceResponseMax];
  static const char kBanner[] = "routeloom-maintenance v1 ready\n";
  usb_serial_jtag_write_bytes(kBanner, sizeof(kBanner) - 1, portMAX_DELAY);
  for (;;) {
    std::size_t length = 0;
    bool overflow = false;
    for (;;) {
      char byte = 0;
      const int received = usb_serial_jtag_read_bytes(&byte, 1, portMAX_DELAY);
      if (received <= 0) continue;
      if (byte == '\n') break;
      if (length < sizeof(line)) {
        line[length++] = byte;
      } else {
        overflow = true;  // drain to the newline, then refuse as too long
      }
    }
    if (length > 0 && line[length - 1] == '\r') --length;
    std::size_t response_size = 0;
    const ByteView raw_line{reinterpret_cast<const std::uint8_t*>(line), length};
    ByteView legacy_rest{};
    if (overflow) {
      const char refused[] = "ERR invalid_argument";
      std::memcpy(response, refused, sizeof(refused));
      response_size = sizeof(refused) - 1;
    } else if (sdkv1::strip_legacy_state_prefix(raw_line, legacy_rest).ok()) {
      // console_locked refuses every verb on this console (same rule and
      // tokens as the factory side): the identity store is re-read per
      // line, so a seal committed earlier in this session takes effect
      // immediately, and an unreadable store fails closed.
      const Status identity_status = stores->identity().initialize();
      if (!identity_status.ok() || stores->identity().quarantined() ||
          stores->identity().uncertain()) {
        const char refused[] = "ERR store_unavailable";
        std::memcpy(response, refused, sizeof(refused));
        response_size = sizeof(refused) - 1;
      } else if (stores->identity().has_identity() &&
                 (stores->identity().identity().flags &
                  sdkv1::kIdentityFlagConsoleLocked) != 0) {
        const char refused[] = "ERR locked";
        std::memcpy(response, refused, sizeof(refused));
        response_size = sizeof(refused) - 1;
      } else {
        sdkv1::MaintenanceFingerprint legacy_domain{};
        const bool known = resolve_legacy_domain(*stores, legacy_domain);
        if (!known && !is_legacy_status_only(legacy_rest)) {
          const char refused[] = "ERR domain";
          std::memcpy(response, refused, sizeof(refused));
          response_size = sizeof(refused) - 1;
        } else {
          sdkv1::LegacyStateConsole legacy(
              purge_port, legacy_domain,
#if CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
              false
#else
              true
#endif
          );
          const Status status = legacy.process_line(legacy_rest, /*stopped=*/true,
                                                     response, sizeof(response),
                                                     response_size);
          if (!status) {
            ESP_LOGE(kTag, "legacy console fault: %s", status.detail);
            continue;
          }
        }
      }
    } else {
      const Status status =
          console.process_line(raw_line, response, sizeof(response), response_size);
      if (!status) {
        ESP_LOGE(kTag, "console fault: %s", status.detail);
        continue;  // caller-side bug only; the line is dropped, console stays
      }
    }
    usb_serial_jtag_write_bytes(response, response_size, portMAX_DELAY);
    usb_serial_jtag_write_bytes("\n", 1, portMAX_DELAY);
  }
}

}  // namespace

Sdkv1Stores::Sdkv1Stores(const std::size_t resume_slots) noexcept
    : resume_slots_(resume_slots),
      ident_storage_(ident_ns_, sdkv1::kIdentityKey0, sdkv1::kIdentityKey1,
                     sdkv1::kIdentitySlotBytes),
      site_storage_(site_ns_, sdkv1::kSiteKey0, sdkv1::kSiteKey1,
                    sdkv1::kSiteSlotBytes),
      revo_storage_(revo_ns_, sdkv1::kRevocationKey0, sdkv1::kRevocationKey1,
                    sdkv1::kRevocationSlotBytes),
      local_revocation_storage_(local_revocation_ns_, sdkv1::kLocalRevocationKey0,
                                sdkv1::kLocalRevocationKey1, sdkv1::kLocalRevocationSlotBytes),
      resume2_storage_(resume2_ns_, resume_slots),
      lifecycle_storage_(lifecycle_ns_, sdkv1::kLifecycleKey0, sdkv1::kLifecycleKey1,
                         sdkv1::kLifecycleSlotBytes),
      identity_(ident_storage_),
      site_(site_storage_),
      revocation_(revo_storage_),
      resume_cache_(resume2_storage_,
                    resume_slots ==
                            sdkv1::kResume2GatewayLinkQuota + sdkv1::kResume2GatewayEndQuota
                        ? sdkv1::kResume2GatewayLinkQuota
                        : sdkv1::kResume2NodeLinkQuota,
                    resume_slots ==
                            sdkv1::kResume2GatewayLinkQuota + sdkv1::kResume2GatewayEndQuota
                        ? sdkv1::kResume2GatewayEndQuota
                        : sdkv1::kResume2NodeEndQuota),
      local_revocation_(local_revocation_storage_),
      lifecycle_(lifecycle_storage_) {}

Status Sdkv1Stores::open(const char* partition) noexcept {
  purge_legacy_rlres(partition);
  Status status = ident_ns_.open(partition, sdkv1::kIdentityNamespace);
  if (status) status = site_ns_.open(partition, sdkv1::kSiteNamespace);
  if (status) status = revo_ns_.open(partition, sdkv1::kRevocationNamespace);
  if (status) status = local_revocation_ns_.open(partition, sdkv1::kLocalRevocationNamespace);
  if (status) status = resume2_ns_.open(partition, sdkv1::kResume2Namespace);
  if (status) status = lifecycle_ns_.open(partition, sdkv1::kLifecycleNamespace);
  if (!status) {
    ident_ns_.close();
    site_ns_.close();
    revo_ns_.close();
    local_revocation_ns_.close();
    resume2_ns_.close();
    lifecycle_ns_.close();
  }
  return status;
}

Status Sdkv1Stores::initialize() noexcept {
  const Status identity = identity_.initialize();
  const Status site = site_.initialize();
  const Status revocation = revocation_.initialize();
  const Status local_revocation = local_revocation_.initialize();
  const Status lifecycle = lifecycle_.initialize();
  if (!identity.ok()) return identity;
  if (!site.ok()) return site;
  if (!revocation.ok()) return revocation;
  if (!local_revocation.ok()) return local_revocation;
  return lifecycle;
}

void Sdkv1Stores::log_state(const char* tag) const noexcept {
  if (identity_.has_identity()) {
    const sdkv1::IdentityRecord& identity = identity_.identity();
    ESP_LOGI(tag, "sdkv1 identity: node=%llu key_location=%u flags=0x%02x anchors=%u "
                  "devcert=%uB",
             static_cast<unsigned long long>(identity.node_id),
             static_cast<unsigned>(identity.key_location),
             static_cast<unsigned>(identity.flags),
             static_cast<unsigned>(identity.anchor_count),
             static_cast<unsigned>(identity.devcert.size));
  } else {
    ESP_LOGI(tag, "sdkv1 identity: none provisioned");
  }
  if (site_.has_site()) {
    const sdkv1::SiteRecord& site = site_.site();
    ESP_LOGI(tag, "sdkv1 site: site=%llu network=0x%llx generation=%lu gk=%lu",
             static_cast<unsigned long long>(site.site_id),
             static_cast<unsigned long long>(site.network),
             static_cast<unsigned long>(site.assignment_generation),
             static_cast<unsigned long>(site.gk_epoch_current));
  } else {
    ESP_LOGI(tag, "sdkv1 site: not a member");
  }
  ESP_LOGI(tag, "sdkv1 revocation: %s rs_epoch=%lu resume_slots=%u",
           revocation_.has_set() ? "adopted" : "none",
           static_cast<unsigned long>(revocation_.rs_epoch()),
           static_cast<unsigned>(resume_slots_));
  ESP_LOGI(tag, "sdkv1 local_revocation: %s",
           !local_revocation_.has_record()
               ? "none"
               : (local_revocation_.record().state == sdkv1::LocalRevocationState::Blocked
                      ? "blocked"
                      : "cleaned"));
  ESP_LOGI(tag, "sdkv1 lifecycle: %s",
           !lifecycle_.has_record() ? "none"
                                    : (lifecycle_.quarantined() ? "quarantined" : "journaled"));
  if (identity_.quarantined() || site_.quarantined() || revocation_.quarantined() ||
      local_revocation_.quarantined() || lifecycle_.quarantined()) {
    ESP_LOGE(tag, "REPROVISION_REQUIRED: sdkv1 store quarantined — recovery is an "
                  "explicit operator act, never an implicit reset");
  } else if (identity_.uncertain() || site_.uncertain() || revocation_.uncertain() ||
             local_revocation_.uncertain() || lifecycle_.uncertain()) {
    ESP_LOGE(tag, "REPROVISION_REQUIRED: sdkv1 sibling state unproven — "
                  "possibly-stale state is refused until recover()");
  }
}

Status run_maintenance_console(Sdkv1Stores& stores) noexcept {
  usb_serial_jtag_driver_config_t config{};
  config.rx_buffer_size = sdkv1::kMaintenanceLineMax + 2;
  config.tx_buffer_size = 1024;
  if (usb_serial_jtag_driver_install(&config) != ESP_OK) {
    return Status::error(StatusCode::InternalError, "maintenance usb install failed");
  }
  if (xTaskCreate(console_task, "rl_maint", kConsoleTaskStack, &stores,
                  tskIDLE_PRIORITY + 1, nullptr) != pdPASS) {
    return Status::error(StatusCode::NoCapacity, "maintenance task create failed");
  }
  vTaskSuspend(nullptr);
  for (;;) {
    vTaskDelay(pdMS_TO_TICKS(1000));  // unreachable: the console owns the device
  }
}

}  // namespace routeloom::espnow
