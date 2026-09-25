#include "routeloom/routeloom.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <new>

#include "routeloom/node.hpp"

namespace {
using namespace routeloom;

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
  return {static_cast<rl_security_scope_t>(context.scope), context.network,
          context.sender, context.receiver, context.epoch};
}

class CBridge final : public RadioPort, public SecurityProvider, public NodeObserver {
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
      const rl_delivery_result_t c{to_c(result.id),
                                   static_cast<rl_delivery_state_t>(result.state),
                                   result.reason};
      observer_.on_delivery(observer_.user, &c);
    }
  }

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

// rl_node_config_t tail extension (routeloom.h): the base layout is frozen
// at RL_NODE_CONFIG_SIZE_BASE bytes; the scoped-routing fields follow it and
// are read only when the caller's struct_size covers them. A two-gateway
// header (RL_NODE_CONFIG_SIZE_GATEWAY2) keeps working with its own limit.
static_assert(offsetof(rl_node_config_t, route_gateway_count) == RL_NODE_CONFIG_SIZE_BASE,
              "rl_node_config_t base layout must stay frozen");
static_assert(offsetof(rl_node_config_t, route_gateways) == RL_NODE_CONFIG_SIZE_BASE + 8,
              "rl_node_config_t extension layout");
static_assert(sizeof(rl_node_config_t) ==
                  RL_NODE_CONFIG_SIZE_BASE + 8 + 8 * RL_MAX_ROUTE_GATEWAYS,
              "rl_node_config_t size");
static_assert(RL_NODE_CONFIG_SIZE_GATEWAY2 == RL_NODE_CONFIG_SIZE_BASE + 8 + 2 * 8,
              "two-gateway header size");
static_assert(RL_MAX_ROUTE_GATEWAYS == kMaxRouteGateways,
              "C gateway capacity must mirror kMaxRouteGateways");

bool extended_config(const rl_node_config_t& input) noexcept {
  return input.struct_size >= sizeof(rl_node_config_t);
}

bool gateway2_config(const rl_node_config_t& input) noexcept {
  return input.struct_size == RL_NODE_CONFIG_SIZE_GATEWAY2;
}

// Shape checks the C boundary owns (routeloom.h): a count within the
// struct_size-covered capacity, no zero id (it would silently shrink the
// list) and no duplicate. A two-gateway caller asking for three gateways
// is refused — never truncated. The lease rule and reserved ids stay with
// MeshNode::validate_config() at start.
bool valid_config(const rl_node_config_t& input) noexcept {
  if (input.abi_version != RL_ABI_VERSION) return false;
  if (!extended_config(input) && !gateway2_config(input)) {
    return input.struct_size == RL_NODE_CONFIG_SIZE_BASE;
  }
  const std::size_t capacity = extended_config(input) ? RL_MAX_ROUTE_GATEWAYS : 2;
  if (input.route_gateway_count > capacity) return false;
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
  if (extended_config(input) || gateway2_config(input)) {
    // valid_config already limited the count to the covered capacity.
    for (std::size_t i = 0; i < input.route_gateway_count; ++i) {
      output.route_gateways[i] = input.route_gateways[i];
    }
    if (input.route_refresh_ticks != 0) {
      output.route_refresh_ticks = input.route_refresh_ticks;
    }
  }
  return output;
}

SendOptions convert_options(const rl_send_options_t& input) noexcept {
  SendOptions output{static_cast<DeliveryClass>(input.delivery),
                     static_cast<Priority>(input.priority), input.lifetime_ms,
                     input.hop_limit};
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
// `ordered` took the first byte of the former reserved[7]: the layout (and
// the zero default of existing callers) is unchanged.
static_assert(offsetof(rl_send_options_t, ordered) ==
                      offsetof(rl_send_options_t, hop_limit) + 1 &&
                  offsetof(rl_send_options_t, reserved) ==
                      offsetof(rl_send_options_t, hop_limit) + 2 &&
                  sizeof(rl_send_options_t) == 28,
              "rl_send_options_t layout unchanged");

bool valid_header(const std::uint32_t struct_size, const std::uint32_t abi_version,
                  const std::size_t expected) noexcept {
  return struct_size >= expected && abi_version == RL_ABI_VERSION;
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

size_t rl_context_size(void) { return sizeof(rl_context); }
size_t rl_context_alignment(void) { return alignof(rl_context); }

void rl_node_config_init(rl_node_config_t* config) {
  if (config == nullptr) return;
  *config = {};
  config->struct_size = sizeof(*config);
  config->abi_version = RL_ABI_VERSION;
  config->link_epoch = 1;
  config->end_epoch = 1;
  config->route_generation = 1;
  config->route_advertisement_period_ms = 5000;
  config->route_lifetime_ms = 15000;
  config->hop_accept_timeout_ms = 60;
  config->callback_watchdog_ms = 1000;
  config->max_link_attempts = 2;
  config->max_end_to_end_rounds = 3;
  // Flat profile (route_gateway_count 0); the scoped refresh cadence is
  // spelled out so a caller that only adds gateways sees the SDK value.
  config->route_refresh_ticks = kScopedDefaultRefreshTicks;
}

void rl_send_options_init(rl_send_options_t* options) {
  if (options == nullptr) return;
  *options = {};
  options->struct_size = sizeof(*options);
  options->abi_version = RL_ABI_VERSION;
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
  if (storage == nullptr || config == nullptr || radio == nullptr || security == nullptr ||
      observer == nullptr || out_context == nullptr || storage_size < sizeof(rl_context) ||
      reinterpret_cast<std::uintptr_t>(storage) % alignof(rl_context) != 0 ||
      !valid_config(*config)) {
    return RL_STATUS_INVALID_ARGUMENT;
  }
  if (radio->send == nullptr || security->ready == nullptr || security->next_counter == nullptr ||
      security->seal == nullptr || security->open == nullptr) {
    return RL_STATUS_INVALID_ARGUMENT;
  }
  auto* context = new (storage) rl_context(convert_config(*config), *radio, *security, *observer);
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
      (payload_size != 0 && payload == nullptr) ||
      !valid_header(options->struct_size, options->abi_version, sizeof(*options))) {
    return RL_STATUS_INVALID_ARGUMENT;
  }
  MessageId id{};
  const auto status = context->node.send(destination, ByteView{payload, payload_size},
                                         convert_options(*options), now_ms, id);
  if (status) *out_id = to_c(id);
  return to_c(status.code);
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
  *options = {};
  options->struct_size = sizeof(*options);
  options->abi_version = RL_ABI_VERSION;
  options->priority = RL_PRIORITY_NORMAL;
  options->lifetime_ms = 5000;
  options->hop_limit = 10;
}

rl_status_code_t rl_send_group(rl_context_t* context, const uint16_t group,
                               const uint8_t* payload, const size_t payload_size,
                               const rl_group_send_options_t* options,
                               const rl_monotonic_ms_t now_ms, rl_message_id_t* out_id) {
  if (context == nullptr || options == nullptr || out_id == nullptr ||
      (payload_size != 0 && payload == nullptr) ||
      !valid_header(options->struct_size, options->abi_version, sizeof(*options)) ||
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
  if (context == nullptr || out_result == nullptr) return RL_STATUS_INVALID_ARGUMENT;
  const GroupDeliveryResult result = context->node.group_delivery(from_c(id));
  *out_result = {};
  out_result->id = to_c(result.id);
  out_result->state = static_cast<rl_delivery_state_t>(result.state);
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
  if (context == nullptr || out_result == nullptr) return RL_STATUS_INVALID_ARGUMENT;
  const auto result = context->node.delivery(from_c(id));
  out_result->id = to_c(result.id);
  out_result->state = static_cast<rl_delivery_state_t>(result.state);
  out_result->reason = result.reason;
  return result.state == DeliveryState::Empty ? RL_STATUS_NOT_FOUND : RL_STATUS_OK;
}

void rl_poll(rl_context_t* context, const rl_monotonic_ms_t now_ms) {
  if (context != nullptr) context->node.poll(now_ms);
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

void rl_reply_peer_vtable_init(rl_reply_peer_vtable_t* vtable) {
  if (vtable == nullptr) return;
  *vtable = {};
  vtable->struct_size = sizeof(*vtable);
  vtable->version = RL_REPLY_PEER_VERSION;
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
  // The struct is versioned precisely so a short/foreign caller is refused
  // here instead of being read past its size.
  if (vtable->struct_size < sizeof(*vtable) || vtable->version != RL_REPLY_PEER_VERSION) {
    return RL_STATUS_INVALID_ARGUMENT;
  }
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
