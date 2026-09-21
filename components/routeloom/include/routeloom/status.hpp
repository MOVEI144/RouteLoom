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
  // Autonomous-mesh reason codes (docs/design/autonomous-mesh/01-integration.md
  // §8). Appended after the v1 set — existing values are never renumbered.
  DiscoveryBudgetExhausted,
  AuthRequired,
  ApprovalRequired,
  BindingConflict,
  PeerCapacity,
  Congested,
  RemoteBusy,
  NoFeasibleAlternative,
  SurveyRequiresOutagePermission,
  LegacyParticipant,
  ClockUncertain,
  PlanNotCommitted,
  RecoveryRequired,
  // The production auth profile has no qualified provider; reported instead
  // of a stub that would claim security (02-discovery.md §5).
  AuthProfileUnavailable,
  // Broad Commissioning-scope discovery requires a real Network; Network 0
  // is never valid for it (02-discovery-scope.md §2.2).
  NetworkRequired,
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
