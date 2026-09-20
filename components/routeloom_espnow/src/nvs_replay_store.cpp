#include "routeloom/nvs_replay_store.hpp"

#include <cstdio>

namespace routeloom::espnow {
namespace {

void window_key(char out[12], const std::uint32_t slot) noexcept {
  std::snprintf(out, 12, "r%08lx", static_cast<unsigned long>(slot));
}

void floor_key(char out[12], const std::uint32_t slot) noexcept {
  std::snprintf(out, 12, "f%08lx", static_cast<unsigned long>(slot));
}

}  // namespace

Status NvsReplayStore::load_window(const std::uint32_t slot,
                                   ReplayWindowRecord& record,
                                   bool& found) noexcept {
  char key[12]{};
  window_key(key, slot);
  return store_.load_blob(key, &record, sizeof(record), found);
}

Status NvsReplayStore::commit_window(
    const std::uint32_t slot, const ReplayWindowRecord& record) noexcept {
  char key[12]{};
  window_key(key, slot);
  return store_.commit_blob(key, &record, sizeof(record));
}

Status NvsReplayStore::load_floor(const std::uint32_t slot,
                                  ReplayFloorRecord& record,
                                  bool& found) noexcept {
  char key[12]{};
  floor_key(key, slot);
  return store_.load_blob(key, &record, sizeof(record), found);
}

Status NvsReplayStore::commit_floor(
    const std::uint32_t slot, const ReplayFloorRecord& record) noexcept {
  char key[12]{};
  floor_key(key, slot);
  return store_.commit_blob(key, &record, sizeof(record));
}

}  // namespace routeloom::espnow
