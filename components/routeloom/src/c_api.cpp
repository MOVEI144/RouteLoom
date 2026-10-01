#include "routeloom/routeloom.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>

#include "routeloom/group.hpp"
#include "routeloom/node.hpp"
#include "routeloom/version.h"

namespace {
using namespace routeloom;

// ABI 3 header rule (routeloom.h): exact major, at least this header's size.
template <typename T>
bool sized(const T* object) noexcept {
  return object != nullptr && object->struct_size >= sizeof(T) &&
         object->version == RL_ABI_VERSION;
}

template <typename T>
void set_header(T& object) noexcept {
  object.struct_size = sizeof(T);
  object.version = RL_ABI_VERSION;
}

rl_status_code_t to_c(const StatusCode code) noexcept {
  return static_cast<rl_status_code_t>(code);
}

// to_c/from_c rely on numeric parity between the two enums; pin both
// ends so a reordered or extended StatusCode breaks the build, not the
// ABI silently.
static_assert(static_cast<rl_status_code_t>(StatusCode::NetworkRequired) ==
                  RL_STATUS_NETWORK_REQUIRED,
              "rl_status_code_t must mirror StatusCode order and range");

Status from_c(const rl_status_code_t code, const char* detail) noexcept {
  return code == RL_STATUS_OK
      ? Status::success()
      : Status::error(static_cast<StatusCode>(code), detail);
}

rl_message_id_t to_c(const MessageId& id) noexcept { return {id.session, id.sequence}; }
MessageId from_c(const rl_message_id_t id) noexcept { return {id.session, id.sequence}; }

rl_security_context_t to_c(const SecurityContext& context) noexcept {
  rl_security_context_t out{};
  set_header(out);
  out.scope = static_cast<rl_security_scope_t>(context.scope);
  out.epoch = context.epoch;
  out.network = context.network;
  out.sender = context.sender;
  out.receiver = context.receiver;
  return out;
}

rl_delivery_result_t to_c(const DeliveryResult& result) noexcept {
  rl_delivery_result_t out{};
  set_header(out);
  out.id = to_c(result.id);
  out.state = static_cast<rl_delivery_state_t>(result.state);
  out.reason_id = reason_code(result.reason);
  out.reason = result.reason;
  return out;
}

class CBridge final : public RadioPort,
                      public SecurityProvider,
                      public NodeObserver,
                      public AppliedEndpointSink {
 public:
  CBridge(const rl_radio_vtable_t& radio, const rl_security_vtable_t& security,
          const rl_observer_vtable_t& observer) noexcept
      : radio_(radio), security_(security), observer_(observer) {}

  Status send(const NodeId peer, const std::uint64_t token,
              const ByteView frame) noexcept override {
    if (radio_.send == nullptr) return Status::error(StatusCode::InvalidState, "radio.send missing");
    return from_c(radio_.send(radio_.user, peer, token, frame.data, frame.size), "radio.send");
  }

  Status recover() noexcept override {
    if (radio_.recover == nullptr) return Status::error(StatusCode::Unsupported, "radio.recover missing");
    return from_c(radio_.recover(radio_.user), "radio.recover");
  }

  bool ready() const noexcept override {
    return security_.ready != nullptr && security_.ready(security_.user);
  }

  Status next_counter(const SecurityContext& context, std::uint64_t& counter) noexcept override {
    if (security_.next_counter == nullptr) {
      return Status::error(StatusCode::InvalidState, "security.next_counter missing");
    }
    const auto c = to_c(context);
    return from_c(security_.next_counter(security_.user, &c, &counter), "security.next_counter");
  }

  Status seal(const SecurityContext& context, const std::uint64_t counter,
              const ByteView aad, const ByteView plaintext,
              const MutableByteView ciphertext,
              std::array<std::uint8_t, kAeadTagSize>& tag) noexcept override {
    if (security_.seal == nullptr) return Status::error(StatusCode::InvalidState, "security.seal missing");
    const auto c = to_c(context);
    return from_c(security_.seal(security_.user, &c, counter, aad.data, aad.size,
                                 plaintext.data, plaintext.size, ciphertext.data,
                                 ciphertext.size, tag.data()), "security.seal");
  }

  Status open(const SecurityContext& context, const std::uint64_t counter,
              const ByteView aad, const ByteView ciphertext,
              const std::array<std::uint8_t, kAeadTagSize>& tag,
              const MutableByteView plaintext) noexcept override {
    if (security_.open == nullptr) return Status::error(StatusCode::InvalidState, "security.open missing");
    const auto c = to_c(context);
    return from_c(security_.open(security_.user, &c, counter, aad.data, aad.size,
                                 ciphertext.data, ciphertext.size, tag.data(),
                                 plaintext.data, plaintext.size), "security.open");
  }

  void on_message(const MessageKey& key, const NodeId source,
                  const ByteView payload) noexcept override {
    if (observer_.on_message != nullptr) {
      observer_.on_message(observer_.user, source, to_c(key.id), payload.data, payload.size);
    }
  }

  void on_delivery(const DeliveryResult& result) noexcept override {
    if (observer_.on_delivery != nullptr) {
      const rl_delivery_result_t c = to_c(result);
      observer_.on_delivery(observer_.user, &c);
    }
  }

  // The C endpoint is always asynchronous: it gets the ticket and answers
  // with rl_complete_applied after the callback returned.
  void on_applied_request(const AppliedRequest& request,
                          AppliedReply& reply) noexcept override {
    rl_applied_request_t c{};
    set_header(c);
    c.ticket = request.ticket;
    c.origin = request.source;
    c.id = to_c(request.key.id);
    c.remaining_ms = request.remaining_ms;
    c.payload = request.payload.data;
    c.payload_size = request.payload.size;
    observer_.on_applied_request(observer_.user, &c);
    reply.deferred = true;
  }

  bool has_applied_endpoint() const noexcept { return observer_.on_applied_request != nullptr; }

  void on_diagnostic(const char* reason, const NodeId peer,
                     const MessageId* message) noexcept override {
    if (observer_.on_diagnostic != nullptr) {
      const auto c = message != nullptr ? to_c(*message) : rl_message_id_t{};
      observer_.on_diagnostic(observer_.user, reason, peer, message != nullptr ? &c : nullptr);
    }
  }

 private:
  rl_radio_vtable_t radio_{};
  rl_security_vtable_t security_{};
  rl_observer_vtable_t observer_{};
};

// Non-reentrant guard for the C reply-port bridge: a C port function that
// calls back into the node re-enters through here and must see Busy.
struct BridgeGuard {
  explicit BridgeGuard(bool& flag) noexcept : flag_(flag) { flag_ = true; }
  ~BridgeGuard() noexcept { flag_ = false; }
  BridgeGuard(const BridgeGuard&) = delete;
  BridgeGuard& operator=(const BridgeGuard&) = delete;
  bool& flag_;
};

// C++ ReplyPeerPort over a C reply-peer vtable (issue #117). A missing C
// function reports Unsupported.
class CReplyPeerBridge final : public ReplyPeerPort {
 public:
  CReplyPeerBridge() noexcept = default;

  void install(const rl_reply_peer_vtable_t& vtable) noexcept { vtable_ = vtable; }
  void clear() noexcept { vtable_ = {}; }

  Status acquire(const ReplyBinding captured, const MonotonicMs deadline,
                 const MonotonicMs now, ReplyLeaseToken& out) noexcept override {
    if (in_call_) return Status::error(StatusCode::Busy, "reply_port reentered");
    BridgeGuard guard(in_call_);
    out = kInvalidReplyLeaseToken;
    if (vtable_.acquire == nullptr) {
      return Status::error(StatusCode::Unsupported, "reply_port.acquire missing");
    }
    std::uint32_t slot = 0;
    std::uint32_t serial = 0;
    const Status status =
        from_c(vtable_.acquire(vtable_.user, captured.peer, captured.id.value,
                               captured.generation.value, captured.rx_context_id,
                               deadline, now, &slot, &serial),
               "reply_port.acquire");
    if (status) {
      out.use_slot = slot;
      out.serial = serial;
    }
    return status;
  }

  Status release(const ReplyLeaseToken token) noexcept override {
    if (in_call_) return Status::error(StatusCode::Busy, "reply_port reentered");
    BridgeGuard guard(in_call_);
    if (vtable_.release == nullptr) {
      return Status::error(StatusCode::Unsupported, "reply_port.release missing");
    }
    return from_c(vtable_.release(vtable_.user, token.use_slot, token.serial),
                  "reply_port.release");
  }

  Status validate(const ReplyLeaseToken token,
                  const MonotonicMs now) noexcept override {
    if (in_call_) return Status::error(StatusCode::Busy, "reply_port reentered");
    BridgeGuard guard(in_call_);
    if (vtable_.validate == nullptr) {
      return Status::error(StatusCode::Unsupported, "reply_port.validate missing");
    }
    return from_c(vtable_.validate(vtable_.user, token.use_slot, token.serial, now),
                  "reply_port.validate");
  }

  Status send_reply(const ReplyLeaseToken token, const std::uint64_t tx_token,
                    const ByteView frame,
                    const MonotonicMs now) noexcept override {
    if (in_call_) return Status::error(StatusCode::Busy, "reply_port reentered");
    BridgeGuard guard(in_call_);
    if (vtable_.send_reply == nullptr) {
      return Status::error(StatusCode::Unsupported, "reply_port.send_reply missing");
    }
    return from_c(vtable_.send_reply(vtable_.user, token.use_slot, token.serial,
                                     tx_token, frame.data, frame.size, now),
                  "reply_port.send_reply");
  }

  Status snapshot_binding(const NodeId peer, ReplyBinding& out) noexcept override {
    if (in_call_) return Status::error(StatusCode::Busy, "reply_port reentered");
    BridgeGuard guard(in_call_);
    out = ReplyBinding{};
    if (vtable_.snapshot_binding == nullptr) {
      return Status::error(StatusCode::Unsupported, "reply_port.snapshot missing");
    }
    std::uint32_t id = 0;
    std::uint32_t generation = 0;
    std::uint32_t rx_context = 0;
    const Status status = from_c(vtable_.snapshot_binding(vtable_.user, peer, &id,
                                                           &generation,
                                                           &rx_context),
                                 "reply_port.snapshot_binding");
    if (status) {
      out.peer = peer;
      out.id = BindingId{id};
      out.generation = BindingGeneration{generation};
      out.rx_context_id = rx_context;
    }
    return status;
  }

  Status send_bound(const ReplyBinding binding, const std::uint64_t tx_token,
                    const ByteView frame) noexcept override {
    if (in_call_) return Status::error(StatusCode::Busy, "reply_port reentered");
    BridgeGuard guard(in_call_);
    if (vtable_.send_bound == nullptr) {
      return Status::error(StatusCode::Unsupported, "reply_port.send_bound missing");
    }
    return from_c(vtable_.send_bound(vtable_.user, binding.peer, binding.id.value,
                                     binding.generation.value,
                                     binding.rx_context_id, tx_token, frame.data,
                                     frame.size),
                  "reply_port.send_bound");
  }

 private:
  rl_reply_peer_vtable_t vtable_{};
  bool in_call_{false};
};

static_assert(RL_MAX_ROUTE_GATEWAYS == kMaxRouteGateways,
              "C gateway capacity must mirror kMaxRouteGateways");
static_assert(RL_APPLIED_LEASE_SIZE == endpoint::kAppliedLeaseBytes, "APPLIED lease size");
static_assert(RL_APPLIED_PAYLOAD_MAX == kAppliedUserPayloadMax, "APPLIED payload limit");
static_assert(RL_APPLIED_RESULT_DATA_MAX == endpoint::kAppResultDataMax, "APPLIED result data");
static_assert(RL_APPLIED_SDK_CODE_BASE == endpoint::kAppResultSdkCodeBase &&
                  RL_APPLIED_CODE_INTERNAL_ERROR ==
                      static_cast<std::uint32_t>(endpoint::AppResultRefusal::InternalError) &&
                  RL_APPLIED_CODE_STALE_LEASE ==
                      static_cast<std::uint32_t>(endpoint::AppResultRefusal::StaleLease) &&
                  RL_APPLIED_CODE_NO_ENDPOINT ==
                      static_cast<std::uint32_t>(endpoint::AppResultRefusal::NoEndpoint) &&
                  RL_APPLIED_CODE_CAPACITY ==
                      static_cast<std::uint32_t>(endpoint::AppResultRefusal::Capacity) &&
                  RL_APPLIED_CODE_MALFORMED_REQUEST ==
                      static_cast<std::uint32_t>(endpoint::AppResultRefusal::MalformedRequest),
              "APPLIED SDK codes must mirror AppResultRefusal");
static_assert(RL_APPLIED_SUCCESS == static_cast<int>(endpoint::AppResultOutcome::Success) &&
                  RL_APPLIED_FAILURE == static_cast<int>(endpoint::AppResultOutcome::Failure),
              "rl_applied_outcome_t must mirror AppResultOutcome");

// Shape checks the C boundary owns (routeloom.h): a count within capacity,
// no zero id (it would silently shrink the list) and no duplicate. The lease
// rule and reserved ids stay with MeshNode::validate_config() at start.
bool valid_config(const rl_node_config_t* config) noexcept {
  if (!sized(config)) return false;
  const rl_node_config_t& input = *config;
  if (input.route_gateway_count > RL_MAX_ROUTE_GATEWAYS) return false;
  for (std::size_t i = 0; i < input.route_gateway_count; ++i) {
    if (input.route_gateways[i] == kInvalidNodeId) return false;
    for (std::size_t j = 0; j < i; ++j) {
      if (input.route_gateways[j] == input.route_gateways[i]) return false;
    }
  }
  return true;
}

NodeConfig convert_config(const rl_node_config_t& input) noexcept {
  NodeConfig output{};
  output.network = input.network;
  output.node = input.node;
  output.message_session = input.message_session;
  output.link_epoch = input.link_epoch;
  output.end_epoch = input.end_epoch;
  output.route_generation = input.route_generation;
  output.route_advertisement_period_ms = input.route_advertisement_period_ms;
  output.route_lifetime_ms = input.route_lifetime_ms;
  output.control_budget_gate_enabled = input.control_budget_gate_enabled != 0;
  output.hop_accept_timeout_ms = input.hop_accept_timeout_ms;
  output.callback_watchdog_ms = input.callback_watchdog_ms;
  output.max_link_attempts = input.max_link_attempts;
  output.max_end_to_end_rounds = input.max_end_to_end_rounds;
  for (std::size_t i = 0; i < input.route_gateway_count; ++i) {
    output.route_gateways[i] = input.route_gateways[i];
  }
  if (input.route_refresh_ticks != 0) output.route_refresh_ticks = input.route_refresh_ticks;
  return output;
}

SendOptions convert_options(const rl_send_options_t& input) noexcept {
  SendOptions output{};
  output.delivery = static_cast<DeliveryClass>(input.delivery);
  output.priority = static_cast<Priority>(input.priority);
  output.lifetime_ms = input.lifetime_ms;
  output.hop_limit = input.hop_limit;
  output.ordered = input.ordered != 0;
  return output;
}

// Group delivery constants mirror the C++ core (group.hpp, node.hpp).
static_assert(RL_SECURITY_GROUP == static_cast<int>(SecurityScope::Group),
              "rl_security_scope_t must mirror SecurityScope");
static_assert(RL_SECURITY_GROUP_LINK == static_cast<int>(SecurityScope::GroupLink),
              "rl_security_scope_t must mirror SecurityScope");
static_assert(RL_GROUP_ALL == kGroupAll, "group ALL id");
static_assert(RL_GROUP_ADDRESS_BASE == kGroupAddressBase, "group address base");
static_assert(RL_GROUP_SEQUENCE_FLAG == kGroupSequenceFlag, "group sequence flag");
static_assert(RL_GROUP_PAYLOAD_MAX == kGroupPayloadMax, "group payload limit");
static_assert(RL_GROUP_MISSING_MAX == kGroupReportMissingMax, "group missing ids");
static_assert(RL_GROUP_MEMBERSHIP_MAX == kGroupMembershipMax, "group membership limit");

// Validates a C verdict the way the synchronous endpoint path would accept it.
bool to_reply(const rl_applied_result_t* result, AppliedReply& reply) noexcept {
  if (!sized(result) || result->data_size > RL_APPLIED_RESULT_DATA_MAX ||
      result->outcome > RL_APPLIED_FAILURE) {
    return false;
  }
  reply.outcome = static_cast<endpoint::AppResultOutcome>(result->outcome);
  reply.code = result->code;
  reply.size = result->data_size;
  std::memcpy(reply.data.data(), result->data, result->data_size);
  return true;
}
}  // namespace

struct rl_context {
  CBridge bridge;
  CReplyPeerBridge reply_peer;
  MeshNode node;

  rl_context(const NodeConfig& config, const rl_radio_vtable_t& radio,
             const rl_security_vtable_t& security,
             const rl_observer_vtable_t& observer) noexcept
      : bridge(radio, security, observer), node(config, bridge, bridge, bridge) {}
};

extern "C" {

void rl_abi_version(uint32_t* out_major, uint32_t* out_minor) {
  if (out_major != nullptr) *out_major = RL_ABI_VERSION;
  if (out_minor != nullptr) *out_minor = RL_ABI_VERSION_MINOR;
}

void rl_struct_init(void* object, const size_t struct_size) {
  if (object == nullptr || struct_size < 2 * sizeof(std::uint32_t)) return;
  std::memset(object, 0, struct_size);
  const std::uint32_t header[2] = {static_cast<std::uint32_t>(struct_size), RL_ABI_VERSION};
  std::memcpy(object, header, sizeof(header));
}

size_t rl_context_size(void) { return sizeof(rl_context); }
size_t rl_context_alignment(void) { return alignof(rl_context); }

void rl_node_config_init(rl_node_config_t* config) {
  if (config == nullptr) return;
  rl_struct_init(config, sizeof(*config));
  config->link_epoch = 1;
  config->end_epoch = 1;
  config->route_generation = 1;
  config->route_advertisement_period_ms = 5000;
  config->route_lifetime_ms = 15000;
  config->hop_accept_timeout_ms = 60;
  config->callback_watchdog_ms = 1000;
  config->max_link_attempts = 2;
  config->max_end_to_end_rounds = 3;
  config->route_refresh_ticks = kScopedDefaultRefreshTicks;
}

void rl_send_options_init(rl_send_options_t* options) {
  if (options == nullptr) return;
  rl_struct_init(options, sizeof(*options));
  options->delivery = RL_DELIVERY_RELIABLE;
  options->priority = RL_PRIORITY_NORMAL;
  options->lifetime_ms = 5000;
  options->hop_limit = 10;
}

rl_status_code_t rl_init(void* storage, const size_t storage_size,
                         const rl_node_config_t* config,
                         const rl_radio_vtable_t* radio,
                         const rl_security_vtable_t* security,
                         const rl_observer_vtable_t* observer,
                         rl_context_t** out_context) {
  if (storage == nullptr || out_context == nullptr || storage_size < sizeof(rl_context) ||
      reinterpret_cast<std::uintptr_t>(storage) % alignof(rl_context) != 0 ||
      !valid_config(config) || !sized(radio) || !sized(security) || !sized(observer)) {
    return RL_STATUS_INVALID_ARGUMENT;
  }
  if (radio->send == nullptr || security->ready == nullptr || security->next_counter == nullptr ||
      security->seal == nullptr || security->open == nullptr) {
    return RL_STATUS_INVALID_ARGUMENT;
  }
  auto* context = new (storage) rl_context(convert_config(*config), *radio, *security, *observer);
  if (context->bridge.has_applied_endpoint()) {
    (void)context->node.set_applied_sink(&context->bridge);
  }
  *out_context = context;
  return RL_STATUS_OK;
}

void rl_deinit(rl_context_t* context) {
  if (context != nullptr) context->~rl_context();
}

rl_status_code_t rl_start(rl_context_t* context, const rl_monotonic_ms_t now_ms) {
  return context == nullptr ? RL_STATUS_INVALID_ARGUMENT : to_c(context->node.start(now_ms).code);
}

rl_status_code_t rl_add_neighbor(rl_context_t* context, const rl_node_id_t neighbor,
                                 const uint16_t link_metric,
                                 const rl_monotonic_ms_t now_ms) {
  return context == nullptr ? RL_STATUS_INVALID_ARGUMENT
                            : to_c(context->node.add_neighbor(neighbor, link_metric, now_ms).code);
}

rl_status_code_t rl_remove_neighbor(rl_context_t* context, const rl_node_id_t neighbor,
                                    const rl_monotonic_ms_t now_ms) {
  return context == nullptr ? RL_STATUS_INVALID_ARGUMENT
                            : to_c(context->node.remove_neighbor(neighbor, now_ms).code);
}

rl_status_code_t rl_send(rl_context_t* context, const rl_node_id_t destination,
                         const uint8_t* payload, const size_t payload_size,
                         const rl_send_options_t* options,
                         const rl_monotonic_ms_t now_ms, rl_message_id_t* out_id) {
  if (context == nullptr || options == nullptr || out_id == nullptr ||
      (payload_size != 0 && payload == nullptr) || !sized(options)) {
    return RL_STATUS_INVALID_ARGUMENT;
  }
  MessageId id{};
  const auto status = context->node.send(destination, ByteView{payload, payload_size},
                                         convert_options(*options), now_ms, id);
  if (status) *out_id = to_c(id);
  return to_c(status.code);
}

rl_status_code_t rl_get_capabilities(const rl_context_t* context,
                                     rl_capabilities_t* out_capabilities) {
  if (!sized(out_capabilities)) return RL_STATUS_INVALID_ARGUMENT;
  rl_capabilities_t caps{};
  set_header(caps);
  caps.features = RL_CAP_APPLIED | RL_CAP_ORDERED | RL_CAP_REPLY_PEER;
  if (context != nullptr) {
    if (context->node.gateway_scoped()) caps.features |= RL_CAP_SCOPED_ROUTING;
    if (context->node.group_origin_servable()) caps.features |= RL_CAP_GROUP_SEND;
  }
  caps.max_payload = RL_MAX_APPLICATION_PAYLOAD;
  caps.max_applied_payload = RL_APPLIED_PAYLOAD_MAX;
  caps.max_group_payload = RL_GROUP_PAYLOAD_MAX;
  caps.max_route_gateways = RL_MAX_ROUTE_GATEWAYS;
  caps.max_group_membership = RL_GROUP_MEMBERSHIP_MAX;
  *out_capabilities = caps;
  return RL_STATUS_OK;
}

rl_status_code_t rl_applied_lease(const rl_context_t* context,
                                  uint8_t out_lease[RL_APPLIED_LEASE_SIZE]) {
  if (context == nullptr || out_lease == nullptr) return RL_STATUS_INVALID_ARGUMENT;
  const ExecutionLease lease = context->node.applied_lease();
  std::memcpy(out_lease, lease.data(), lease.size());
  return RL_STATUS_OK;
}

rl_status_code_t rl_send_applied(rl_context_t* context, const rl_node_id_t destination,
                                 const uint8_t lease[RL_APPLIED_LEASE_SIZE],
                                 const uint8_t* payload, const size_t payload_size,
                                 const rl_send_options_t* options,
                                 const rl_monotonic_ms_t now_ms, rl_message_id_t* out_id) {
  if (context == nullptr || lease == nullptr || out_id == nullptr ||
      (payload_size != 0 && payload == nullptr) || !sized(options)) {
    return RL_STATUS_INVALID_ARGUMENT;
  }
  ExecutionLease copy{};
  std::memcpy(copy.data(), lease, copy.size());
  MessageId id{};
  const auto status = context->node.send_applied(destination, ByteView{payload, payload_size},
                                                 copy, convert_options(*options), now_ms, id);
  if (status) *out_id = to_c(id);
  return to_c(status.code);
}

rl_status_code_t rl_complete_applied(rl_context_t* context, const uint64_t ticket,
                                     const rl_applied_result_t* result,
                                     const rl_monotonic_ms_t now_ms) {
  AppliedReply reply{};
  if (context == nullptr || !to_reply(result, reply)) return RL_STATUS_INVALID_ARGUMENT;
  return to_c(context->node.complete_applied(ticket, reply, now_ms).code);
}

rl_status_code_t rl_get_applied_result(const rl_context_t* context, const rl_message_id_t id,
                                       rl_applied_result_t* out_result) {
  if (context == nullptr || !sized(out_result)) return RL_STATUS_INVALID_ARGUMENT;
  AppliedResultView view{};
  if (!context->node.applied_result(from_c(id), view)) return RL_STATUS_NOT_FOUND;
  rl_applied_result_t out{};
  set_header(out);
  out.code = view.code;
  out.outcome = static_cast<std::uint8_t>(view.outcome);
  out.data_size = view.size;
  out.late = view.late ? 1U : 0U;
  std::memcpy(out.data, view.data.data(), view.size);
  *out_result = out;
  return RL_STATUS_OK;
}

size_t rl_route_gateways(const rl_context_t* context, rl_node_id_t* out_gateways,
                         const size_t capacity) {
  if (context == nullptr) return 0;
  std::size_t count = 0;
  for (const NodeId gateway : context->node.config().route_gateways) {
    if (gateway == kInvalidNodeId) continue;
    if (out_gateways != nullptr && count < capacity) out_gateways[count] = gateway;
    ++count;
  }
  return count;
}

void rl_group_send_options_init(rl_group_send_options_t* options) {
  if (options == nullptr) return;
  rl_struct_init(options, sizeof(*options));
  options->priority = RL_PRIORITY_NORMAL;
  options->lifetime_ms = 5000;
  options->hop_limit = 10;
}

rl_status_code_t rl_send_group(rl_context_t* context, const uint16_t group,
                               const uint8_t* payload, const size_t payload_size,
                               const rl_group_send_options_t* options,
                               const rl_monotonic_ms_t now_ms, rl_message_id_t* out_id) {
  if (context == nullptr || options == nullptr || out_id == nullptr ||
      (payload_size != 0 && payload == nullptr) || !sized(options) ||
      static_cast<std::uint32_t>(options->priority) >
          static_cast<std::uint32_t>(RL_PRIORITY_URGENT)) {
    return RL_STATUS_INVALID_ARGUMENT;
  }
  GroupSendOptions converted{};
  converted.priority = static_cast<Priority>(options->priority);
  converted.lifetime_ms = options->lifetime_ms;
  converted.hop_limit = options->hop_limit;
  converted.ordered = options->ordered != 0;
  MessageId id{};
  const auto status = context->node.send_group(group, ByteView{payload, payload_size},
                                               converted, now_ms, id);
  if (status) *out_id = to_c(id);
  return to_c(status.code);
}

rl_status_code_t rl_get_group_result(rl_context_t* context, const rl_message_id_t id,
                                     rl_group_result_t* out_result) {
  if (context == nullptr || !sized(out_result)) return RL_STATUS_INVALID_ARGUMENT;
  const GroupDeliveryResult result = context->node.group_delivery(from_c(id));
  *out_result = {};
  set_header(*out_result);
  out_result->id = to_c(result.id);
  out_result->state = static_cast<rl_delivery_state_t>(result.state);
  out_result->reason_id = reason_code(result.reason);
  out_result->reason = result.reason;
  out_result->group = result.group;
  out_result->rounds = result.rounds;
  out_result->missing_count = result.missing_count;
  out_result->delivered = result.delivered;
  out_result->nonmember = result.nonmember;
  out_result->missing_total = result.missing_total;
  out_result->unaccounted = result.unaccounted;
  out_result->missing_truncated = result.missing_truncated ? 1U : 0U;
  for (std::size_t i = 0; i < result.missing_count && i < RL_GROUP_MISSING_MAX; ++i) {
    out_result->missing[i] = result.missing[i];
  }
  return result.state == DeliveryState::Empty ? RL_STATUS_NOT_FOUND : RL_STATUS_OK;
}

rl_status_code_t rl_set_group_membership(rl_context_t* context, const uint16_t* groups,
                                         const size_t count) {
  if (context == nullptr || (count != 0 && groups == nullptr)) {
    return RL_STATUS_INVALID_ARGUMENT;
  }
  static_assert(sizeof(GroupId) == sizeof(uint16_t), "GroupId is a u16");
  return to_c(context->node.set_group_membership(groups, count).code);
}

rl_status_code_t rl_cancel(rl_context_t* context, const rl_message_id_t id) {
  return context == nullptr ? RL_STATUS_INVALID_ARGUMENT
                            : to_c(context->node.cancel(from_c(id)).code);
}

rl_status_code_t rl_get_delivery(rl_context_t* context, const rl_message_id_t id,
                                 rl_delivery_result_t* out_result) {
  if (context == nullptr || !sized(out_result)) return RL_STATUS_INVALID_ARGUMENT;
  const auto result = context->node.delivery(from_c(id));
  *out_result = to_c(result);
  return result.state == DeliveryState::Empty ? RL_STATUS_NOT_FOUND : RL_STATUS_OK;
}

void rl_poll(rl_context_t* context, const rl_monotonic_ms_t now_ms) {
  if (context != nullptr) context->node.poll(now_ms);
}

rl_monotonic_ms_t rl_next_deadline(const rl_context_t* context,
                                   const rl_monotonic_ms_t now_ms) {
  if (context != nullptr && context->node.started()) return context->node.next_deadline(now_ms);
  return now_ms > UINT64_MAX - RL_POLL_INTERVAL_MAX_MS ? UINT64_MAX
                                                       : now_ms + RL_POLL_INTERVAL_MAX_MS;
}

void rl_on_radio_receive(rl_context_t* context, const rl_node_id_t peer,
                         const uint8_t* frame, const size_t frame_size,
                         const int8_t rssi_dbm, const rl_monotonic_ms_t now_ms) {
  if (context != nullptr && frame != nullptr && frame_size != 0) {
    context->node.on_radio_receive(peer, ByteView{frame, frame_size}, RadioRxMetadata{rssi_dbm}, now_ms);
  }
}

void rl_on_radio_tx_result(rl_context_t* context, const uint64_t token,
                           const bool success, const rl_monotonic_ms_t now_ms) {
  if (context != nullptr) context->node.on_radio_tx_result(token, success, now_ms);
}

rl_status_code_t rl_attach_reply_peer(rl_context_t* context,
                                      const rl_reply_peer_vtable_t* vtable) {
  if (context == nullptr) return RL_STATUS_INVALID_ARGUMENT;
  if (vtable == nullptr) {
    const Status status = context->node.set_reply_peer_port(nullptr);
    if (!status) return to_c(status.code);
    context->reply_peer.clear();
    return RL_STATUS_OK;
  }
  if (!sized(vtable)) return RL_STATUS_INVALID_ARGUMENT;
  const Status status = context->node.set_reply_peer_port(&context->reply_peer);
  if (!status) return to_c(status.code);
  context->reply_peer.install(*vtable);
  return RL_STATUS_OK;
}

void rl_on_radio_receive_with_binding(rl_context_t* context, const rl_node_id_t peer,
                                      const uint8_t* frame, const size_t frame_size,
                                      const int8_t rssi_dbm, const uint32_t binding_id,
                                      const uint32_t binding_generation,
                                      const rl_monotonic_ms_t now_ms) {
  if (context != nullptr && frame != nullptr && frame_size != 0) {
    RadioRxMetadataV2 metadata{};
    metadata.rssi_dbm = rssi_dbm;
    metadata.rssi_valid = true;
    metadata.binding = BindingId{binding_id};
    metadata.binding_generation = BindingGeneration{binding_generation};
    // Unattributed over the C boundary: telemetry must treat this as
    // injected evidence, never as local-driver truth (same rule as the V1
    // entry above).
    metadata.provenance = ObservationProvenance::InjectedTest;
    context->node.on_radio_receive(peer, ByteView{frame, frame_size}, metadata, now_ms);
  }
}

const char* rl_status_code_name(const rl_status_code_t code) {
  return routeloom::status_code_name(static_cast<StatusCode>(code));
}

}  // extern "C"
