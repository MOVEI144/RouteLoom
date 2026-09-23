#include "routeloom/routeloom.h"

#include <array>
#include <cstddef>
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
  return output;
}

SendOptions convert_options(const rl_send_options_t& input) noexcept {
  return {static_cast<DeliveryClass>(input.delivery),
          static_cast<Priority>(input.priority), input.lifetime_ms, input.hop_limit};
}

bool valid_header(const std::uint32_t struct_size, const std::uint32_t abi_version,
                  const std::size_t expected) noexcept {
  return struct_size >= expected && abi_version == RL_ABI_VERSION;
}
}  // namespace

struct rl_context {
  CBridge bridge;
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
      !valid_header(config->struct_size, config->abi_version, sizeof(*config))) {
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

const char* rl_status_code_name(const rl_status_code_t code) {
  return routeloom::status_code_name(static_cast<StatusCode>(code));
}

}  // extern "C"
