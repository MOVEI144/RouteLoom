#pragma once

#include <cstdint>

#include "routeloom/nvs_counter_store.hpp"
#include "routeloom/peer_state.hpp"
#include "routeloom/replay.hpp"

namespace routeloom::espnow {

// ReplayStore backed by NvsCounterStore blob access. Window records live
// under "r%08lx" keys and per-peer epoch floors under "f%08lx" keys inside
// one dedicated NVS namespace (in the kSecurityNvsPartition partition on the
// reference firmware). Floors can be enumerated for the peer cap; nothing
// here erases RX state (sdk-v1/05 §4 D2-d).
class NvsReplayStore final : public ReplayInventory {
 public:
  NvsReplayStore() = default;
  ~NvsReplayStore() override { close(); }

  NvsReplayStore(const NvsReplayStore&) = delete;
  NvsReplayStore& operator=(const NvsReplayStore&) = delete;

  // `partition`: NVS partition label, nullptr for the default "nvs".
  Status open(const char* name_space, const char* partition = nullptr) noexcept {
    return store_.open(name_space, partition);
  }
  void close() noexcept { store_.close(); }

  Status load_window(std::uint32_t slot, ReplayWindowRecord& record,
                     bool& found) noexcept override;
  Status commit_window(std::uint32_t slot,
                       const ReplayWindowRecord& record) noexcept override;
  Status load_floor(std::uint32_t slot, ReplayFloorRecord& record,
                    bool& found) noexcept override;
  Status commit_floor(std::uint32_t slot,
                      const ReplayFloorRecord& record) noexcept override;
  Status for_each_floor_slot(SlotVisitor& visitor) noexcept override {
    return store_.for_each_key_slot('f', visitor);
  }

 private:
  NvsCounterStore store_;
};

}  // namespace routeloom::espnow
