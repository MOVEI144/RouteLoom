#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "esp_flash.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "routeloom/espnow_flash_layout.hpp"

namespace {

std::array<esp_partition_t, 10> partitions{};
std::size_t partition_count = 0;
esp_ota_img_states_t ota_state = ESP_OTA_IMG_VALID;
esp_err_t ota_state_error = ESP_OK;
int mark_calls = 0;

void check(bool condition, const char* message) {
  if (!condition) {
    std::fprintf(stderr, "%s\n", message);
    std::abort();
  }
}

void reset_partitions() {
  partition_count = std::size(routeloom::espnow::kPt4mV2);
  for (std::size_t i = 0; i < partition_count; ++i) {
    const auto& row = routeloom::espnow::kPt4mV2[i];
    auto& found = partitions[i];
    found = {};
    found.type = (i == 6 || i == 7) ? 0 : 1;
    constexpr std::uint8_t subtypes[] = {2, 1, 0, 2, 2, 2, 0x10, 0x11, 3};
    found.subtype = subtypes[i];
    found.address = row.offset;
    found.size = row.size;
    std::strcpy(found.label, row.label);
  }
}

}  // namespace

struct PartitionIterator { std::size_t index; };
PartitionIterator iterator{};
esp_flash_t flash_chip{0x400000};
esp_flash_t* esp_flash_default_chip = &flash_chip;

const char* esp_err_to_name(esp_err_t) { return "stub"; }

const esp_partition_t* esp_partition_find_first(esp_partition_type_t,
                                                 esp_partition_subtype_t,
                                                 const char* label) {
  for (std::size_t i = 0; i < partition_count; ++i) {
    if (std::strcmp(partitions[i].label, label) == 0) return &partitions[i];
  }
  return nullptr;
}

esp_partition_iterator_t esp_partition_find(esp_partition_type_t,
                                            esp_partition_subtype_t,
                                            const char*) {
  iterator.index = 0;
  return partition_count ? &iterator : nullptr;
}

const esp_partition_t* esp_partition_get(esp_partition_iterator_t it) {
  return &partitions[it->index];
}

esp_partition_iterator_t esp_partition_next(esp_partition_iterator_t it) {
  ++it->index;
  return it->index < partition_count ? it : nullptr;
}

void esp_partition_iterator_release(esp_partition_iterator_t) {}

const esp_partition_t* esp_ota_get_running_partition() { return &partitions[6]; }

esp_err_t esp_ota_get_state_partition(const esp_partition_t*,
                                      esp_ota_img_states_t* state) {
  *state = ota_state;
  return ota_state_error;
}

esp_err_t esp_ota_mark_app_valid_cancel_rollback() {
  ++mark_calls;
  return ESP_OK;
}

int main() {
  reset_partitions();
  check(routeloom::espnow::verify_flash_layout().ok(), "valid table refused");

  partitions[partition_count] = {1, 2, 0x3f0000, 0x10000, "extra"};
  ++partition_count;
  check(!routeloom::espnow::verify_flash_layout().ok(), "extra row accepted");

  reset_partitions();
  partitions[5].subtype = 0;
  check(!routeloom::espnow::verify_flash_layout().ok(), "wrong subtype accepted");

  reset_partitions();
  flash_chip.size = 0x200000;
  check(!routeloom::espnow::verify_flash_layout().ok(), "small flash accepted");

  ota_state = ESP_OTA_IMG_VALID;
  mark_calls = 0;
  routeloom::espnow::mark_app_valid();
  check(mark_calls == 0, "valid image confirmed again");
  ota_state = ESP_OTA_IMG_PENDING_VERIFY;
  routeloom::espnow::mark_app_valid();
  check(mark_calls == 1, "pending image not confirmed once");
}
