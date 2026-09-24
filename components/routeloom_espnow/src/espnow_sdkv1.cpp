#include "routeloom/espnow_sdkv1.hpp"

#include <cinttypes>
#include <cstring>

#include "driver/usb_serial_jtag.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "routeloom/espnow_sdkv1_entropy.hpp"
#include "routeloom/sdkv1_maintenance.hpp"

namespace routeloom::espnow {
namespace {

constexpr char kTag[] = "RouteLoomSdkv1";
// The console task owns the engine's worst-case ~4 KiB frame plus the USB
// driver calls; 8 KiB leaves headroom without touching the main task.
constexpr std::uint32_t kConsoleTaskStack = 8192;

void console_task(void* arg) {
  Sdkv1Stores* stores = static_cast<Sdkv1Stores*>(arg);
  EspMaintenanceEntropy entropy;
  const Status entropy_status = entropy.begin();
  if (!entropy_status) {
    ESP_LOGE(kTag, "maintenance entropy unavailable: %s", entropy_status.detail);
  }
  sdkv1::MaintenanceConsole console(stores->identity(), entropy);
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
    if (overflow) {
      const char refused[] = "ERR invalid_argument";
      std::memcpy(response, refused, sizeof(refused));
      response_size = sizeof(refused) - 1;
    } else {
      const Status status = console.process_line(
          ByteView{reinterpret_cast<const std::uint8_t*>(line), length}, response,
          sizeof(response), response_size);
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
      resume_storage_(resume_ns_, resume_slots),
      identity_(ident_storage_),
      site_(site_storage_),
      revocation_(revo_storage_),
      resume_(resume_storage_) {}

Status Sdkv1Stores::open(const char* partition) noexcept {
  Status status = ident_ns_.open(partition, sdkv1::kIdentityNamespace);
  if (status) status = site_ns_.open(partition, sdkv1::kSiteNamespace);
  if (status) status = revo_ns_.open(partition, sdkv1::kRevocationNamespace);
  if (status) status = resume_ns_.open(partition, sdkv1::kResumeNamespace);
  if (!status) {
    ident_ns_.close();
    site_ns_.close();
    revo_ns_.close();
    resume_ns_.close();
  }
  return status;
}

Status Sdkv1Stores::initialize() noexcept {
  const Status identity = identity_.initialize();
  const Status site = site_.initialize();
  const Status revocation = revocation_.initialize();
  if (!identity.ok()) return identity;
  if (!site.ok()) return site;
  return revocation;
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
  if (identity_.quarantined() || site_.quarantined() || revocation_.quarantined()) {
    ESP_LOGE(tag, "REPROVISION_REQUIRED: sdkv1 store quarantined — recovery is an "
                  "explicit operator act, never an implicit reset");
  } else if (identity_.uncertain() || site_.uncertain() || revocation_.uncertain()) {
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
