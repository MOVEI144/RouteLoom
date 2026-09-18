#pragma once

#include <cstdint>

#include "routeloom/status.hpp"

namespace routeloom {

enum class DeadlinePolicy : std::uint8_t {
  WallElapsedValidity = 0,
  RunningTimeOnly = 1,
};

struct ElapsedInterval {
  std::uint64_t lower_ms{0};
  std::uint64_t upper_ms{0};
  bool known{false};
};

inline Status resume_remaining_lifetime(const DeadlinePolicy policy,
                                        const std::uint32_t stored_remaining_ms,
                                        const ElapsedInterval elapsed,
                                        std::uint32_t& remaining_ms) noexcept {
  if (stored_remaining_ms == 0) {
    remaining_ms = 0;
    return Status::error(StatusCode::Expired, "DEADLINE_EXPIRED");
  }
  if (policy == DeadlinePolicy::RunningTimeOnly) {
    remaining_ms = stored_remaining_ms;
    return Status::success();
  }
  if (!elapsed.known || elapsed.upper_ms < elapsed.lower_ms) {
    remaining_ms = 0;
    return Status::error(StatusCode::TimeUncertain, "TIME_UNCERTAIN");
  }
  if (elapsed.upper_ms >= stored_remaining_ms) {
    remaining_ms = 0;
    return Status::error(StatusCode::Expired, "DEADLINE_EXPIRED");
  }
  remaining_ms = static_cast<std::uint32_t>(stored_remaining_ms - elapsed.upper_ms);
  return Status::success();
}

}  // namespace routeloom
