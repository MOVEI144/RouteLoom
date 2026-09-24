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

Status BootSessionStore::reconcile_site(const std::uint32_t witness,
                                        std::uint32_t& session) noexcept {
  if (witness == 0) {
    return Status::error(StatusCode::RecoveryRequired, "missing site boot witness");
  }
  std::uint32_t stored = 0;
  bool found = false;
  const Status read = port_.read(stored, found);
  if (!read) return read;
  // A previously advanced system counter must still be durable. Never
  // publish a token from an in-memory candidate or a rolled-back value.
  if (!found || stored != session || session == 0) {
    return Status::error(StatusCode::StorageFailure, "boot session changed after advance");
  }
  if (stored > witness) return Status::success();
  const std::uint64_t repaired = static_cast<std::uint64_t>(witness) + (1ULL << 20);
  if (repaired > UINT32_MAX) {
    return Status::error(StatusCode::CounterExhausted, "boot witness repair exhausted");
  }
  const auto value = static_cast<std::uint32_t>(repaired);
  const Status committed = port_.commit(value);
  if (!committed) return committed;
  std::uint32_t durable = 0;
  bool durable_found = false;
  const Status checked = port_.read(durable, durable_found);
  if (!checked) return checked;
  if (!durable_found || durable != value) {
    return Status::error(StatusCode::StorageFailure, "boot witness readback failed");
  }
  session = value;
  return Status::success();
}

Status BootSessionStore::advance_dev_group(DevBootHighWaterPort& high_water,
                                            std::uint32_t& session) noexcept {
  std::uint32_t system_value = 0;
  bool system_found = false;
  Status status = port_.read(system_value, system_found);
  if (!status) return status;
  std::uint32_t high = 0;
  bool high_found = false;
  status = high_water.read(high, high_found);
  if (!status) return status;
  if ((system_found && system_value == 0) || (high_found && high == 0)) {
    return Status::error(StatusCode::RecoveryRequired, "invalid boot high water");
  }
  const std::uint64_t next = static_cast<std::uint64_t>(
      (system_found && (!high_found || system_value > high)) ? system_value : high) + 1;
  if (next > UINT32_MAX) {
    return Status::error(StatusCode::CounterExhausted, "dev boot high water exhausted");
  }
  const auto value = static_cast<std::uint32_t>(next);
  // Commit the group-key ceiling before the system boot token: interruption
  // can skip epochs, but can never reuse an epoch for the same dev PSK.
  status = high_water.commit(value);
  if (!status) return status;
  std::uint32_t checked = 0;
  bool found = false;
  status = high_water.read(checked, found);
  if (!status) return status;
  if (!found || checked != value) {
    return Status::error(StatusCode::StorageFailure, "dev boot high water readback failed");
  }
  status = port_.commit(value);
  if (!status) return status;
  status = port_.read(checked, found);
  if (!status) return status;
  if (!found || checked != value) {
    return Status::error(StatusCode::StorageFailure, "dev boot session readback failed");
  }
  session = value;
  return Status::success();
}

}  // namespace routeloom::sdkv1
