// Device C API (device.h): a stateless translation onto routeloom::Device.
// The handle keeps only the copied observer, the posted C jobs in flight
// and whether the APPLIED endpoint is installed; every state read goes to
// the Device.

#include "routeloom/device.h"

#include <atomic>
#include <cstring>

#include "routeloom/device.hpp"
#include "routeloom/status.hpp"
#include "routeloom/secure_clear.hpp"

namespace {
using namespace routeloom;

template <typename T>
bool sized(const T* object, const std::uint32_t version) noexcept {
  return object != nullptr && object->struct_size >= sizeof(T) && object->version == version;
}
template <typename T>
bool dev_sized(const T* object) noexcept {
  return sized(object, RL_DEV_API_VERSION);
}
template <typename T>
bool core_sized(const T* object) noexcept {
  return sized(object, RL_ABI_VERSION);
}
template <typename T>
void dev_header(T& object) noexcept {
  object.struct_size = sizeof(T);
  object.version = RL_DEV_API_VERSION;
}
template <typename T>
void core_header(T& object) noexcept {
  object.struct_size = sizeof(T);
  object.version = RL_ABI_VERSION;
}

// C callers may store integers outside a C++ enum's valid range. Read the
// ABI representation before validating, without loading an invalid enum.
template <typename T>
std::uint32_t enum_value(const T& value) noexcept {
  static_assert(sizeof(T) == sizeof(std::uint32_t), "C API enum width");
  std::uint32_t raw = 0;
  std::memcpy(&raw, &value, sizeof(raw));
  return raw;
}

rl_status_code_t to_c(const Status& status) noexcept {
  return static_cast<rl_status_code_t>(status.code);
}
rl_message_id_t to_c(const MessageId& id) noexcept { return {id.session, id.sequence}; }
MessageId from_c(const rl_message_id_t id) noexcept { return {id.session, id.sequence}; }

rl_dev_membership_t to_c(const MembershipSnapshot& s) noexcept {
  rl_dev_membership_t out{};
  dev_header(out);
  out.stage = static_cast<std::uint8_t>(s.stage);
  out.role = s.role;
  out.reason = s.reason;
  out.generation = s.generation;
  out.site_id = s.site_id;
  out.network = s.network;
  out.node = s.node;
  out.since_ms = s.since_ms;
  out.boot = s.boot;
  out.operation = s.operation;
  return out;
}

rl_dev_connectivity_t to_c(const ConnectivitySnapshot& s) noexcept {
  rl_dev_connectivity_t out{};
  dev_header(out);
  out.state = static_cast<std::uint8_t>(s.state);
  out.scope = static_cast<std::uint8_t>(s.scope);
  out.contact_valid = s.contact_valid ? 1U : 0U;
  out.reason = s.reason;
  out.boot = s.boot;
  out.since_ms = s.since_ms;
  out.last_contact_ms = s.last_contact_ms;
  return out;
}

bool from_c(const rl_dev_send_options_t* input, SendOptions& output) noexcept {
  if (!dev_sized(input)) return false;
  const std::uint32_t delivery = enum_value(input->delivery);
  const std::uint32_t priority = enum_value(input->priority);
  if (delivery > static_cast<std::uint32_t>(RL_DELIVERY_APPLIED) ||
      priority > static_cast<std::uint32_t>(RL_PRIORITY_URGENT)) {
    return false;
  }
  output.delivery = static_cast<DeliveryClass>(delivery);
  output.priority = static_cast<Priority>(priority);
  output.lifetime_ms = input->lifetime_ms;
  output.hop_limit = input->hop_limit;
  output.ordered = input->ordered != 0;
  output.coalesce_key = input->coalesce_key;
  return true;
}

static_assert(RL_DEV_ROLE_GATEWAY == static_cast<int>(profile::Role::Gateway), "rl_dev_role_t");
static_assert(RL_DEV_SECURITY_CANDIDATE == static_cast<int>(SecurityProfile::Candidate),
              "rl_dev_security_profile_t");
static_assert(RL_DEV_STAGE_LEAVING == static_cast<int>(MembershipStage::Leaving), "rl_dev_stage_t");
static_assert(RL_DEV_CONNECTIVITY_SLEEPING == static_cast<int>(Connectivity::Sleeping),
              "rl_dev_connectivity_state_t");
static_assert(RL_APPLIED_LEASE_SIZE == sizeof(ExecutionLease), "APPLIED lease size");
}  // namespace

struct rl_dev final : public NodeObserver, public DeviceObserver, public AppliedEndpointSink {
  // A posted C job waits in one of these until its Owner pass takes it.
  struct Job {
    std::atomic<bool> used{false};
    rl_dev* dev{nullptr};
    rl_dev_job_t fn{nullptr};
    void* ctx{nullptr};
  };

  constexpr rl_dev() noexcept = default;

  bool callback_active() const noexcept { return device->callback_active(); }

  void bind(Device& target, const rl_dev_observer_t* c_observer) noexcept {
    device = &target;
    observer = rl_dev_observer_t{};
    if (dev_sized(c_observer)) std::memcpy(&observer, c_observer, sizeof(observer));
    sink_installed = false;
    target.observe(this);
    target.observe_device(this);
    target.on_poll(&rl_dev::poll, this);
    install_sink();
  }

  // The endpoint needs the started node; retried from each Owner pass.
  void install_sink() noexcept {
    if (sink_installed || observer.on_applied_request == nullptr) return;
    sink_installed = device->set_applied_sink(this).ok();
  }

  static void poll(Device&, const MonotonicMs now_ms, void* self) noexcept {
    rl_dev& dev = *static_cast<rl_dev*>(self);
    dev.install_sink();
    if (dev.observer.on_poll != nullptr) dev.observer.on_poll(dev.observer.user, &dev, now_ms);
  }

  static void run_job(Device&, void* slot) noexcept {
    Job& job = *static_cast<Job*>(slot);
    rl_dev* const dev = job.dev;
    const rl_dev_job_t fn = job.fn;
    void* const ctx = job.ctx;
    job.used.store(false);
    fn(dev, ctx);
  }

  void on_message(const MessageKey& key, const NodeId source,
                  const ByteView payload) noexcept override {
    if (observer.on_message != nullptr) {
      observer.on_message(observer.user, source, to_c(key.id), payload.data, payload.size);
    }
  }
  void on_delivery(const DeliveryResult& result) noexcept override {
    if (observer.on_delivery == nullptr) return;
    rl_delivery_result_t c{};
    core_header(c);
    c.id = to_c(result.id);
    c.state = static_cast<rl_delivery_state_t>(result.state);
    c.reason_id = reason_code(result.reason);
    c.reason = result.reason;
    observer.on_delivery(observer.user, &c);
  }
  void on_diagnostic(const char*, NodeId, const MessageId*) noexcept override {}

  void on_membership(const MembershipSnapshot& snapshot, const std::uint16_t cause) noexcept override {
    if (observer.on_membership == nullptr) return;
    const rl_dev_membership_t c = to_c(snapshot);
    observer.on_membership(observer.user, &c, cause);
  }
  void on_connectivity(const ConnectivitySnapshot& snapshot) noexcept override {
    if (observer.on_connectivity == nullptr) return;
    const rl_dev_connectivity_t c = to_c(snapshot);
    observer.on_connectivity(observer.user, &c);
  }
  void on_operation(const OperationId operation, const std::uint16_t result) noexcept override {
    if (observer.on_operation != nullptr) observer.on_operation(observer.user, operation, result);
  }

  // The C endpoint is always asynchronous: it gets the ticket and answers
  // with rl_dev_complete_applied after the callback returned.
  void on_applied_request(const AppliedRequest& request, AppliedReply& reply) noexcept override {
    rl_applied_request_t c{};
    core_header(c);
    c.ticket = request.ticket;
    c.origin = request.source;
    c.id = to_c(request.key.id);
    c.remaining_ms = request.remaining_ms;
    c.payload = request.payload.data;
    c.payload_size = request.payload.size;
    observer.on_applied_request(observer.user, &c);
    reply.deferred = true;
  }

  Device* device{nullptr};
  rl_dev_observer_t observer{};
  bool sink_installed{false};
  Job jobs[Device::kPostCapacity]{};
};

namespace {
// One Device per image, so one handle. Function-local, so an image that
// never uses the C API links none of it.
rl_dev& handle() noexcept {
  static rl_dev instance;
  return instance;
}
}  // namespace

namespace routeloom {
rl_dev* device_c_bind(Device& device, const rl_dev_observer_t* observer) noexcept {
  if ((observer != nullptr && !dev_sized(observer)) || handle().device != nullptr) return nullptr;
  handle().bind(device, observer);
  return &handle();
}
}  // namespace routeloom

extern "C" {

void rl_dev_struct_init(void* object, const size_t struct_size) {
  if (object == nullptr || struct_size < 2 * sizeof(std::uint32_t)) return;
  std::memset(object, 0, struct_size);
  const std::uint32_t header[2] = {static_cast<std::uint32_t>(struct_size), RL_DEV_API_VERSION};
  std::memcpy(object, header, sizeof(header));
}

void rl_dev_send_options_init(rl_dev_send_options_t* options) {
  if (options == nullptr) return;
  rl_dev_struct_init(options, sizeof(*options));
  const SendOptions defaults{};
  options->delivery = static_cast<rl_delivery_class_t>(defaults.delivery);
  options->priority = static_cast<rl_priority_t>(defaults.priority);
  options->lifetime_ms = defaults.lifetime_ms;
  options->hop_limit = defaults.hop_limit;
}

#if defined(ESP_PLATFORM)
rl_dev_t* rl_dev_start(const rl_dev_observer_t* observer) {
  static Device device;
  rl_dev_t* const dev = routeloom::device_c_bind(device, observer);
  if (dev == nullptr) return nullptr;
  DeviceConfig config = device_config_from_kconfig();
  device.start(config);
  return dev;
}
#endif

rl_status_code_t rl_dev_post(rl_dev_t* device, const rl_dev_job_t job, void* ctx) {
  if (device == nullptr || device->device == nullptr || job == nullptr) {
    return RL_STATUS_INVALID_ARGUMENT;
  }
  for (auto& slot : device->jobs) {
    bool expected = false;
    if (!slot.used.compare_exchange_strong(expected, true)) continue;
    slot.dev = device;
    slot.fn = job;
    slot.ctx = ctx;
    const Status posted = device->device->post(&rl_dev::run_job, &slot);
    if (!posted) slot.used.store(false);
    return to_c(posted);
  }
  return RL_STATUS_BUSY;
}

rl_node_id_t rl_dev_node_id(rl_dev_t* device) {
  return device == nullptr || device->device == nullptr ? kInvalidNodeId
                                                        : device->device->node_id();
}

rl_status_code_t rl_dev_capabilities(rl_dev_t* device, rl_dev_capabilities_t* out) {
  if (device == nullptr || device->device == nullptr || !dev_sized(out)) {
    return RL_STATUS_INVALID_ARGUMENT;
  }
  if (device->callback_active()) return RL_STATUS_BUSY;
  const DeviceCapabilities caps = device->device->capabilities();
  rl_dev_capabilities_t c{};
  dev_header(c);
  c.role = static_cast<std::uint8_t>(caps.role);
  c.member = caps.member ? 1U : 0U;
  c.security_profile = static_cast<std::uint8_t>(caps.security_profile);
  c.usb_gateway = caps.usb_gateway ? 1U : 0U;
  c.scoped_routing = caps.scoped_routing ? 1U : 0U;
  c.group_send = caps.group_send ? 1U : 0U;
  c.max_payload = caps.max_payload;
  c.max_group_payload = caps.max_group_payload;
  c.max_applied_payload = static_cast<std::uint16_t>(kAppliedUserPayloadMax);
  *out = c;
  return RL_STATUS_OK;
}

rl_status_code_t rl_dev_send(rl_dev_t* device, const rl_node_id_t destination,
                             const uint8_t* payload, const size_t payload_size,
                             const rl_dev_send_options_t* options, rl_message_id_t* out_id) {
  SendOptions converted{};
  if (device == nullptr || device->device == nullptr || out_id == nullptr ||
      (payload_size != 0 && payload == nullptr) || !from_c(options, converted)) {
    return RL_STATUS_INVALID_ARGUMENT;
  }
  MessageId id{};
  const Status status =
      device->device->send(destination, ByteView{payload, payload_size}, converted, id);
  if (status) *out_id = to_c(id);
  return to_c(status);
}

rl_status_code_t rl_dev_send_group(rl_dev_t* device, const uint16_t group,
                                   const uint8_t* payload, const size_t payload_size,
                                   const rl_group_send_options_t* options,
                                   rl_message_id_t* out_id) {
  if (device == nullptr || device->device == nullptr || out_id == nullptr ||
      (payload_size != 0 && payload == nullptr) || !core_sized(options)) {
    return RL_STATUS_INVALID_ARGUMENT;
  }
  const std::uint32_t priority = enum_value(options->priority);
  if (priority > static_cast<std::uint32_t>(RL_PRIORITY_URGENT)) {
    return RL_STATUS_INVALID_ARGUMENT;
  }
  GroupSendOptions converted{};
  converted.priority = static_cast<Priority>(priority);
  converted.lifetime_ms = options->lifetime_ms;
  converted.hop_limit = options->hop_limit;
  converted.ordered = options->ordered != 0;
  MessageId id{};
  const Status status =
      device->device->send_group(group, ByteView{payload, payload_size}, converted, id);
  if (status) *out_id = to_c(id);
  return to_c(status);
}

rl_status_code_t rl_dev_cancel(rl_dev_t* device, const rl_message_id_t id) {
  if (device == nullptr || device->device == nullptr) return RL_STATUS_INVALID_ARGUMENT;
  return to_c(device->device->cancel(from_c(id)));
}

rl_status_code_t rl_dev_delivery(rl_dev_t* device, const rl_message_id_t id,
                                 rl_delivery_result_t* out) {
  if (device == nullptr || device->device == nullptr || !core_sized(out)) {
    return RL_STATUS_INVALID_ARGUMENT;
  }
  if (device->callback_active()) return RL_STATUS_BUSY;
  const DeliveryResult result = device->device->delivery(from_c(id));
  rl_delivery_result_t c{};
  core_header(c);
  c.id = to_c(result.id);
  c.state = static_cast<rl_delivery_state_t>(result.state);
  c.reason_id = reason_code(result.reason);
  c.reason = result.reason;
  *out = c;
  return RL_STATUS_OK;
}

rl_status_code_t rl_dev_applied_lease(rl_dev_t* device, uint8_t out_lease[RL_APPLIED_LEASE_SIZE]) {
  if (device == nullptr || device->device == nullptr || out_lease == nullptr) {
    return RL_STATUS_INVALID_ARGUMENT;
  }
  if (device->callback_active()) return RL_STATUS_BUSY;
  const MeshNode* node = device->device->mesh();
  if (node == nullptr) return RL_STATUS_INVALID_STATE;
  const ExecutionLease lease = node->applied_lease();
  std::memcpy(out_lease, lease.data(), lease.size());
  return RL_STATUS_OK;
}

rl_status_code_t rl_dev_send_applied(rl_dev_t* device, const rl_node_id_t destination,
                                     const uint8_t lease[RL_APPLIED_LEASE_SIZE],
                                     const uint8_t* payload, const size_t payload_size,
                                     const rl_dev_send_options_t* options,
                                     rl_message_id_t* out_id) {
  SendOptions converted{};
  if (device == nullptr || device->device == nullptr || lease == nullptr || out_id == nullptr ||
      (payload_size != 0 && payload == nullptr) || !from_c(options, converted)) {
    return RL_STATUS_INVALID_ARGUMENT;
  }
  ExecutionLease copy{};
  std::memcpy(copy.data(), lease, copy.size());
  MessageId id{};
  const Status status =
      device->device->send_applied(destination, ByteView{payload, payload_size}, copy, converted, id);
  if (status) *out_id = to_c(id);
  return to_c(status);
}

rl_status_code_t rl_dev_complete_applied(rl_dev_t* device, const uint64_t ticket,
                                         const rl_applied_result_t* result) {
  if (device == nullptr || device->device == nullptr || !core_sized(result) ||
      result->data_size > RL_APPLIED_RESULT_DATA_MAX || result->outcome > RL_APPLIED_FAILURE) {
    return RL_STATUS_INVALID_ARGUMENT;
  }
  AppliedReply reply{};
  reply.outcome = static_cast<endpoint::AppResultOutcome>(result->outcome);
  reply.code = result->code;
  reply.size = result->data_size;
  std::memcpy(reply.data.data(), result->data, result->data_size);
  return to_c(device->device->complete_applied(ticket, reply));
}

rl_status_code_t rl_dev_applied_result(rl_dev_t* device, const rl_message_id_t id,
                                       rl_applied_result_t* out) {
  if (device == nullptr || device->device == nullptr || !core_sized(out)) {
    return RL_STATUS_INVALID_ARGUMENT;
  }
  if (device->callback_active()) return RL_STATUS_BUSY;
  const MeshNode* node = device->device->mesh();
  AppliedResultView view{};
  if (node == nullptr || !node->applied_result(from_c(id), view)) return RL_STATUS_NOT_FOUND;
  rl_applied_result_t c{};
  core_header(c);
  c.code = view.code;
  c.outcome = static_cast<std::uint8_t>(view.outcome);
  c.data_size = view.size;
  c.late = view.late ? 1U : 0U;
  std::memcpy(c.data, view.data.data(), view.size);
  *out = c;
  return RL_STATUS_OK;
}

rl_status_code_t rl_dev_membership(rl_dev_t* device, rl_dev_membership_t* out) {
  if (device == nullptr || device->device == nullptr || !dev_sized(out)) {
    return RL_STATUS_INVALID_ARGUMENT;
  }
  if (device->callback_active()) return RL_STATUS_BUSY;
  *out = to_c(device->device->membership());
  return RL_STATUS_OK;
}

rl_status_code_t rl_dev_connectivity(rl_dev_t* device, rl_dev_connectivity_t* out) {
  if (device == nullptr || device->device == nullptr || !dev_sized(out)) {
    return RL_STATUS_INVALID_ARGUMENT;
  }
  if (device->callback_active()) return RL_STATUS_BUSY;
  *out = to_c(device->device->connectivity());
  return RL_STATUS_OK;
}

rl_status_code_t rl_dev_join_mark(rl_dev_t* device, uint8_t out[16]) {
  if (device == nullptr || device->device == nullptr || out == nullptr) return RL_STATUS_INVALID_ARGUMENT;
  sdkv1::JoinMark mark{};
  const Status status = device->device->join_mark(mark);
  std::memcpy(out, mark.data(), mark.size());
  secure_clear(mark);
  return to_c(status);
}

rl_status_code_t rl_dev_request_join(rl_dev_t* device, uint32_t* out_operation) {
  if (device == nullptr || device->device == nullptr || out_operation == nullptr) {
    return RL_STATUS_INVALID_ARGUMENT;
  }
  OperationId operation = 0;
  const Status status = device->device->request_join(operation);
  *out_operation = operation;
  return to_c(status);
}

rl_status_code_t rl_dev_leave(rl_dev_t* device, uint32_t* out_operation) {
  if (device == nullptr || device->device == nullptr || out_operation == nullptr) {
    return RL_STATUS_INVALID_ARGUMENT;
  }
  OperationId operation = 0;
  const Status status = device->device->leave(operation);
  *out_operation = operation;
  return to_c(status);
}

rl_status_code_t rl_dev_set_join_policy(rl_dev_t* device, const rl_dev_join_policy_t* policy,
                                        const uint32_t expected_revision, uint32_t* out_revision) {
  if (device == nullptr || device->device == nullptr || policy == nullptr ||
      policy->version != RL_DEV_API_VERSION || policy->struct_size < offsetof(rl_dev_join_policy_t, smart_join) ||
      out_revision == nullptr) {
    return RL_STATUS_INVALID_ARGUMENT;
  }
  JoinPolicy converted{};
  converted.avoid_not_here_s = policy->avoid_not_here_s;
  converted.avoid_blocked_s = policy->avoid_blocked_s;
  converted.removal_holdoff_s = policy->removal_holdoff_s;
  converted.retry_max_s = policy->retry_max_s;
  converted.isolation_notice_s = policy->isolation_notice_s;
  converted.start_jitter_ms = policy->start_jitter_ms;
  converted.role = policy->role;
  if (policy->struct_size >= sizeof(*policy)) {
    if (policy->smart_join > 1 || policy->boot_join > 1 || policy->same_site_only > 1) {
      return RL_STATUS_INVALID_ARGUMENT;
    }
    converted.smart_join = policy->smart_join != 0;
    converted.boot_join = policy->boot_join != 0;
    converted.same_site_only = policy->same_site_only != 0;
    converted.listen_ms = policy->smart_join ? policy->listen_ms : 3000;
    converted.search_ms = policy->smart_join ? policy->search_ms : 60000;
  }
  std::uint32_t revision = 0;
  const Status status = device->device->set_join_policy(converted, expected_revision, revision);
  *out_revision = revision;
  return to_c(status);
}

rl_status_code_t rl_dev_join_policy(rl_dev_t* device, rl_dev_join_policy_t* out,
                                    uint32_t* out_revision) {
  if (device == nullptr || device->device == nullptr || out == nullptr || out->version != RL_DEV_API_VERSION ||
      out->struct_size < offsetof(rl_dev_join_policy_t, smart_join) ||
      out_revision == nullptr) {
    return RL_STATUS_INVALID_ARGUMENT;
  }
  if (device->callback_active()) return RL_STATUS_BUSY;
  JoinPolicy policy{};
  std::uint32_t revision = 0;
  const Status status = device->device->join_policy(policy, revision);
  if (!status) return to_c(status);
  rl_dev_join_policy_t c{};
  dev_header(c);
  c.avoid_not_here_s = policy.avoid_not_here_s;
  c.avoid_blocked_s = policy.avoid_blocked_s;
  c.removal_holdoff_s = policy.removal_holdoff_s;
  c.retry_max_s = policy.retry_max_s;
  c.isolation_notice_s = policy.isolation_notice_s;
  c.start_jitter_ms = policy.start_jitter_ms;
  c.role = policy.role;
  c.smart_join = policy.smart_join;
  c.boot_join = policy.boot_join;
  c.same_site_only = policy.same_site_only;
  c.listen_ms = policy.listen_ms;
  c.search_ms = policy.search_ms;
  c.struct_size = out->struct_size;
  std::memcpy(out, &c, out->struct_size < sizeof(c) ? out->struct_size : sizeof(c));
  *out_revision = revision;
  return RL_STATUS_OK;
}

}  // extern "C"
