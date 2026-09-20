#include "routeloom/status.hpp"

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
  }
  return "UNKNOWN";
}

}  // namespace routeloom
