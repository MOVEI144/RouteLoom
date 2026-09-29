#include "routeloom/status.hpp"

#include <cstring>

#include "routeloom/version.h"

namespace routeloom {

const char* status_code_name(const StatusCode code) noexcept {
  switch (code) {
    case StatusCode::Ok: return "OK";
    case StatusCode::InvalidArgument: return "INVALID_ARGUMENT";
    case StatusCode::InvalidState: return "INVALID_STATE";
    case StatusCode::NotFound: return "NOT_FOUND";
    case StatusCode::AlreadyExists: return "ALREADY_EXISTS";
    case StatusCode::Unsupported: return "UNSUPPORTED";
    case StatusCode::WouldBlock: return "WOULD_BLOCK";
    case StatusCode::NoCapacity: return "NO_CAPACITY";
    case StatusCode::NoRoute: return "NO_ROUTE";
    case StatusCode::Expired: return "DEADLINE_EXPIRED";
    case StatusCode::TimeUncertain: return "TIME_UNCERTAIN";
    case StatusCode::AuthenticationFailed: return "AUTHENTICATION_FAILED";
    case StatusCode::AuthorizationFailed: return "AUTHORIZATION_FAILED";
    case StatusCode::ReplayRejected: return "REPLAY_REJECTED";
    case StatusCode::CounterExhausted: return "COUNTER_EXHAUSTED";
    case StatusCode::StorageFailure: return "STORAGE_FAILURE";
    case StatusCode::RadioFailure: return "RADIO_FAILURE";
    case StatusCode::DriverResultUnknown: return "DRIVER_RESULT_UNKNOWN";
    case StatusCode::ProtocolError: return "PROTOCOL_ERROR";
    case StatusCode::IntegrityError: return "INTEGRITY_ERROR";
    case StatusCode::Conflict: return "CONFLICT";
    case StatusCode::Busy: return "BUSY";
    case StatusCode::InternalError: return "INTERNAL_ERROR";
    case StatusCode::DiscoveryBudgetExhausted: return "DISCOVERY_BUDGET_EXHAUSTED";
    case StatusCode::AuthRequired: return "AUTH_REQUIRED";
    case StatusCode::ApprovalRequired: return "APPROVAL_REQUIRED";
    case StatusCode::BindingConflict: return "BINDING_CONFLICT";
    case StatusCode::PeerCapacity: return "PEER_CAPACITY";
    case StatusCode::Congested: return "CONGESTED";
    case StatusCode::RemoteBusy: return "REMOTE_BUSY";
    case StatusCode::NoFeasibleAlternative: return "NO_FEASIBLE_ALTERNATIVE";
    case StatusCode::SurveyRequiresOutagePermission: return "SURVEY_REQUIRES_OUTAGE_PERMISSION";
    case StatusCode::LegacyParticipant: return "LEGACY_PARTICIPANT";
    case StatusCode::ClockUncertain: return "CLOCK_UNCERTAIN";
    case StatusCode::PlanNotCommitted: return "PLAN_NOT_COMMITTED";
    case StatusCode::RecoveryRequired: return "RECOVERY_REQUIRED";
    case StatusCode::AuthProfileUnavailable: return "AUTH_PROFILE_UNAVAILABLE";
    case StatusCode::NetworkRequired: return "NETWORK_REQUIRED";
  }
  return "UNKNOWN";
}

std::uint16_t reason_code(const char* const name) noexcept {
  struct Entry {
    const char* name;
    std::uint16_t id;
  };
#define RL_REASON_ENTRY(entry_name, id) {#entry_name, id},
  // Names reach this lookup from Status details and delivery reasons only;
  // transport areas (hostlink, ...) are emitted as ids and never looked up.
  static constexpr Entry kTable[] = {ROUTELOOM_REASON_COMMON_TABLE(RL_REASON_ENTRY)
                                         ROUTELOOM_REASON_DELIVERY_TABLE(RL_REASON_ENTRY)};
#undef RL_REASON_ENTRY
  if (name == nullptr) return ROUTELOOM_REASON_NONE;
  for (const Entry& entry : kTable) {
    if (std::strcmp(entry.name, name) == 0) return entry.id;
  }
  return ROUTELOOM_REASON_NONE;
}

}  // namespace routeloom
