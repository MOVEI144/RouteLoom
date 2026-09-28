#pragma once

#include <cstdint>

using esp_partition_type_t = std::uint8_t;
using esp_partition_subtype_t = std::uint8_t;
constexpr esp_partition_type_t ESP_PARTITION_TYPE_ANY = 0xff;
constexpr esp_partition_subtype_t ESP_PARTITION_SUBTYPE_ANY = 0xff;

struct esp_partition_t {
  esp_partition_type_t type;
  esp_partition_subtype_t subtype;
  std::uint32_t address;
  std::uint32_t size;
  char label[17];
};

struct PartitionIterator;
using esp_partition_iterator_t = PartitionIterator*;
const esp_partition_t* esp_partition_find_first(esp_partition_type_t,
                                                 esp_partition_subtype_t,
                                                 const char*);
esp_partition_iterator_t esp_partition_find(esp_partition_type_t,
                                            esp_partition_subtype_t,
                                            const char*);
const esp_partition_t* esp_partition_get(esp_partition_iterator_t);
esp_partition_iterator_t esp_partition_next(esp_partition_iterator_t);
void esp_partition_iterator_release(esp_partition_iterator_t);
