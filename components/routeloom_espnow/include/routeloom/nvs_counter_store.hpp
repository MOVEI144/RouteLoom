#pragma once

#include <cstdint>

#include "nvs.h"
#include "routeloom/counter_store.hpp"

namespace routeloom::espnow {

class NvsCounterStore final : public CounterStore {
 public:
  NvsCounterStore() = default;
  ~NvsCounterStore() override;

  NvsCounterStore(const NvsCounterStore&) = delete;
  NvsCounterStore& operator=(const NvsCounterStore&) = delete;

  Status open(const char* name_space) noexcept;
  void close() noexcept;
  Status load(std::uint32_t slot, CounterRecord& record, bool& found) noexcept override;
  Status commit(std::uint32_t slot, const CounterRecord& record) noexcept override;

  Status load_blob(const char* key, void* value, std::size_t size, bool& found) noexcept;
  Status commit_blob(const char* key, const void* value, std::size_t size) noexcept;

 private:
  nvs_handle_t handle_{0};
  bool open_{false};
};

}  // namespace routeloom::espnow
