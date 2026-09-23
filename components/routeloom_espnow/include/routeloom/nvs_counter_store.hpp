#pragma once

#include <cstddef>
#include <cstdint>

#include "nvs.h"
#include "routeloom/counter_store.hpp"
#include "routeloom/peer_state.hpp"

namespace routeloom::espnow {

// Label of the dedicated NVS partition holding per-peer security state
// (rlcounter/rlreplay, issue #37, sdk-v1/05 §4 D2-a). Keeping it apart from
// the default "nvs" partition means exhausting it can never block the boot
// session (rlboot) or any other system write. Firmware partition tables
// declare it; nvs_flash_init_partition(kSecurityNvsPartition) mounts it.
inline constexpr char kSecurityNvsPartition[] = "rlsec";

// CounterStore/CounterInventory over one NVS namespace. Counter records live
// under "c%08lx" keys, the sweep witness under "cmax" (u32). The generic
// blob accessors are also used by other stores sharing the adapter.
class NvsCounterStore final : public CounterInventory {
 public:
  NvsCounterStore() = default;
  ~NvsCounterStore() override;

  NvsCounterStore(const NvsCounterStore&) = delete;
  NvsCounterStore& operator=(const NvsCounterStore&) = delete;

  // `partition` selects the NVS partition label (nullptr: default "nvs").
  // The partition must already be initialized (nvs_flash_init[_partition]).
  Status open(const char* name_space, const char* partition = nullptr) noexcept;
  void close() noexcept;
  Status load(std::uint32_t slot, CounterRecord& record, bool& found) noexcept override;
  Status commit(std::uint32_t slot, const CounterRecord& record) noexcept override;
  Status for_each_slot(SlotVisitor& visitor) noexcept override;
  Status erase(std::uint32_t slot) noexcept override;
  Status load_witness(std::uint32_t& witness, bool& found) noexcept override;
  Status commit_witness(std::uint32_t witness) noexcept override;

  Status load_blob(const char* key, void* value, std::size_t size, bool& found) noexcept;
  Status commit_blob(const char* key, const void* value, std::size_t size) noexcept;
  // Visits the slot of every blob key of the form <prefix>%08lx.
  Status for_each_key_slot(char prefix, SlotVisitor& visitor) noexcept;

 private:
  nvs_handle_t handle_{0};
  bool open_{false};
};

// Caps `configured` peers by what the initialized NVS partition can hold
// (max_persisted_peers_for_entries over nvs_get_stats().total_entries).
Status nvs_partition_peer_capacity(const char* partition, std::uint32_t configured,
                                   std::uint32_t& effective) noexcept;

// True when `name_space` holds at least one entry in `partition`. Firmware
// uses it to report legacy (pre-rlsec) peer state left in the default
// partition, which only an explicit NVS erase reclaims.
bool nvs_namespace_in_use(const char* partition, const char* name_space) noexcept;

}  // namespace routeloom::espnow
