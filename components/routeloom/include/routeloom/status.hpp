#pragma once

#include <cstdint>

namespace routeloom {

enum class StatusCode : std::uint16_t {
  Ok = 0,
  InvalidArgument,
  InvalidState,
  NotFound,
  AlreadyExists,
  Unsupported,
  WouldBlock,
  NoCapacity,
  NoRoute,
  Expired,
  TimeUncertain,
  AuthenticationFailed,
  AuthorizationFailed,
  ReplayRejected,
  CounterExhausted,
  StorageFailure,
  RadioFailure,
  DriverResultUnknown,
  ProtocolError,
  IntegrityError,
  Conflict,
  Busy,
  InternalError,
};

struct Status {
  StatusCode code{StatusCode::Ok};
  const char* detail{"ok"};

  constexpr bool ok() const noexcept { return code == StatusCode::Ok; }
  constexpr explicit operator bool() const noexcept { return ok(); }

  static constexpr Status success() noexcept { return {}; }
  static constexpr Status error(StatusCode code, const char* detail) noexcept {
    return Status{code, detail};
  }
};

const char* status_code_name(StatusCode code) noexcept;

}  // namespace routeloom
