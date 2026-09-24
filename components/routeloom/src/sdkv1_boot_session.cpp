#include "routeloom/sdkv1_boot_session.hpp"

#include <cstdint>

namespace routeloom::sdkv1 {

Status BootSessionStore::advance(const bool has_site, const std::uint32_t witness,
                                 std::uint32_t& session) noexcept {
  std::uint32_t stored = 0;
  bool found = false;
  const Status read = port_.read(stored, found);
  if (!read) return read;
  if (has_site && witness == 0) {
    return Status::error(StatusCode::RecoveryRequired, "missing site boot witness");
  }
  const std::uint64_t next = static_cast<std::uint64_t>(found ? stored : 0) + 1;
  std::uint64_t proposed = next;
  if (has_site && (!found || stored < witness)) {
    const std::uint64_t repaired = static_cast<std::uint64_t>(witness) + (1ULL << 20);
    if (repaired > proposed) proposed = repaired;
  }
  if (proposed > UINT32_MAX) {
    return Status::error(StatusCode::CounterExhausted, "boot session exhausted");
  }
  const auto value = static_cast<std::uint32_t>(proposed);
  const Status committed = port_.commit(value);
  if (!committed) return committed;
  std::uint32_t durable = 0;
  bool durable_found = false;
  const Status checked = port_.read(durable, durable_found);
  if (!checked) return checked;
  if (!durable_found || durable != value) {
    return Status::error(StatusCode::StorageFailure, "boot session readback failed");
  }
  session = value;  // Never expose an unconfirmed session to the radio.
  return Status::success();
}

}  // namespace routeloom::sdkv1
