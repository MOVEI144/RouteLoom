#pragma once

#include <cstdint>

#include "routeloom/nvs_counter_store.hpp"
#include "routeloom/replay.hpp"

namespace routeloom::espnow {

// ReplayStore backed by NvsCounterStore blob access. Window records live
// under "r%08lx" keys and per-peer epoch floors under "f%08lx" keys inside
// one dedicated NVS namespace.
class NvsReplayStore final : public ReplayStore {
 public:
  NvsReplayStore() = default;
  ~NvsReplayStore() override { close(); }

  NvsReplayStore(const NvsReplayStore&) = delete;
  NvsReplayStore& operator=(const NvsReplayStore&) = delete;

  Status open(const char* name_space) noexcept { return store_.open(name_space); }
  void close() noexcept { store_.close(); }

  Status load_window(std::uint32_t slot, ReplayWindowRecord& record,
                     bool& found) noexcept override;
  Status commit_window(std::uint32_t slot,
                       const ReplayWindowRecord& record) noexcept override;
  Status load_floor(std::uint32_t slot, ReplayFloorRecord& record,
                    bool& found) noexcept override;
  Status commit_floor(std::uint32_t slot,
                      const ReplayFloorRecord& record) noexcept override;

 private:
  NvsCounterStore store_;
};

}  // namespace routeloom::espnow
