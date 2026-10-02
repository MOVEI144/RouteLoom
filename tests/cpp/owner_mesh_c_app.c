/* The mesh peer's C application (P05-C): join, send, APPLIED, leave and
   post through the Device C API only, compiled as C11. */

#include <string.h>
#include "owner_mesh_c_app.h"
#include "routeloom/version.h"

static void posted(rl_dev_t* device, void* ctx);

static void try_reentry(mesh_c_app_t* app) {
  rl_dev_send_options_t options;
  rl_message_id_t id;
  uint32_t operation = 0;
  const uint8_t byte = 0x5A;
  rl_dev_send_options_init(&options);
  app->reentry_calls += 2;
  if (rl_dev_send(app->device, 0x00A1000000000001ULL, &byte, 1, &options, &id) ==
      RL_STATUS_BUSY) {
    ++app->reentry_busy;
  }
  if (rl_dev_leave(app->device, &operation) == RL_STATUS_BUSY) ++app->reentry_busy;
  rl_dev_capabilities_t caps;
  rl_dev_membership_t membership;
  rl_dev_connectivity_t connectivity;
  rl_dev_join_policy_t policy;
  rl_delivery_result_t delivery;
  rl_applied_result_t applied;
  uint8_t lease[RL_APPLIED_LEASE_SIZE];
  uint32_t revision;
  rl_dev_struct_init(&caps, sizeof(caps));
  rl_dev_struct_init(&membership, sizeof(membership));
  rl_dev_struct_init(&connectivity, sizeof(connectivity));
  rl_dev_struct_init(&policy, sizeof(policy));
  rl_struct_init(&delivery, sizeof(delivery));
  rl_struct_init(&applied, sizeof(applied));
  app->reentry_calls += 7;
  if (rl_dev_capabilities(app->device, &caps) == RL_STATUS_BUSY) ++app->reentry_busy;
  if (rl_dev_membership(app->device, &membership) == RL_STATUS_BUSY) ++app->reentry_busy;
  if (rl_dev_connectivity(app->device, &connectivity) == RL_STATUS_BUSY) ++app->reentry_busy;
  if (rl_dev_join_policy(app->device, &policy, &revision) == RL_STATUS_BUSY) ++app->reentry_busy;
  if (rl_dev_delivery(app->device, (rl_message_id_t){0, 0}, &delivery) == RL_STATUS_BUSY)
    ++app->reentry_busy;
  if (rl_dev_applied_result(app->device, (rl_message_id_t){0, 0}, &applied) == RL_STATUS_BUSY)
    ++app->reentry_busy;
  if (rl_dev_applied_lease(app->device, lease) == RL_STATUS_BUSY) ++app->reentry_busy;
}

static void count(mesh_c_app_t* app, int ok) {
  ++app->checks;
  if (!ok) ++app->check_failures;
}

/* Short and unknown-version structs are refused; a valid one is served. */
static void check_boundaries(mesh_c_app_t* app) {
  rl_dev_capabilities_t caps;
  rl_dev_membership_t membership;
  rl_dev_send_options_t options;
  rl_message_id_t id;
  const uint8_t byte = 1;

  rl_dev_struct_init(&caps, offsetof(rl_dev_capabilities_t, object_transfer) - 1);
  count(app, rl_dev_capabilities(app->device, &caps) == RL_STATUS_INVALID_ARGUMENT);
  rl_dev_struct_init(&caps, sizeof(caps));
  caps.version = RL_DEV_API_VERSION + 1;
  count(app, rl_dev_capabilities(app->device, &caps) == RL_STATUS_INVALID_ARGUMENT);
  rl_dev_struct_init(&caps, sizeof(caps));
  count(app, rl_dev_capabilities(app->device, &caps) == RL_STATUS_OK &&
                 caps.member == 1 && caps.security_profile == RL_DEV_SECURITY_CANDIDATE &&
                 caps.max_payload == RL_MAX_APPLICATION_PAYLOAD &&
                 caps.max_applied_payload == RL_APPLIED_PAYLOAD_MAX);
  memset(&caps, 0xa5, sizeof(caps));
  caps.struct_size = offsetof(rl_dev_capabilities_t, object_transfer); caps.version = RL_DEV_API_VERSION;
  count(app, rl_dev_capabilities(app->device, &caps) == RL_STATUS_OK && caps.object_transfer == 0xa5 && caps.struct_size == offsetof(rl_dev_capabilities_t, object_transfer));
  count(app, rl_dev_capabilities(app->device, &caps) == RL_STATUS_OK && caps.object_transfer == 0xa5);
  rl_dev_struct_init(&membership, sizeof(membership));
  count(app, rl_dev_membership(app->device, &membership) == RL_STATUS_OK &&
                 membership.node == rl_dev_node_id(app->device));
  /* API 1's original 32-byte policy prefix stays writable without touching the tail. */
  rl_dev_join_policy_t policy;
  uint32_t revision;
  rl_dev_struct_init(&policy, sizeof(policy));
  policy.struct_size = offsetof(rl_dev_join_policy_t, smart_join);
  policy.smart_join = 0xA5;
  count(app, rl_dev_join_policy(app->device, &policy, &revision) == RL_STATUS_OK &&
                 policy.smart_join == 0xA5);
  count(app, rl_dev_set_join_policy(app->device, &policy, revision, &revision) == RL_STATUS_OK);
  --policy.struct_size;
  count(app, rl_dev_join_policy(app->device, &policy, &revision) == RL_STATUS_INVALID_ARGUMENT);
  rl_dev_send_options_init(&options);
  options.version = RL_ABI_VERSION;
  count(app, rl_dev_send(app->device, 1, &byte, 1, &options, &id) ==
                 RL_STATUS_INVALID_ARGUMENT);
  const int invalid_values[] = {-1, 99};
  for (size_t i = 0; i < sizeof(invalid_values) / sizeof(invalid_values[0]); ++i) {
    const int invalid = invalid_values[i];
    rl_dev_send_options_init(&options);
    options.delivery = (rl_delivery_class_t)invalid;
    count(app, rl_dev_send(app->device, 1, &byte, 1, &options, &id) ==
                   RL_STATUS_INVALID_ARGUMENT);
    rl_dev_send_options_init(&options);
    options.priority = (rl_priority_t)invalid;
    count(app, rl_dev_send(app->device, 1, &byte, 1, &options, &id) ==
                   RL_STATUS_INVALID_ARGUMENT);
    rl_group_send_options_t group;
    rl_group_send_options_init(&group);
    group.priority = (rl_priority_t)invalid;
    count(app, rl_dev_send_group(app->device, 1, &byte, 1, &group, &id) ==
                   RL_STATUS_INVALID_ARGUMENT);
  }
}

static void posted(rl_dev_t* device, void* ctx) {
  mesh_c_app_t* app = (mesh_c_app_t*)ctx;
  rl_dev_membership_t membership;
  rl_dev_struct_init(&membership, sizeof(membership));
  if (device == app->device && rl_dev_membership(device, &membership) == RL_STATUS_OK) {
    ++app->posted_runs;
  }
}

static void posted_from_membership(rl_dev_t* device, void* ctx) {
  mesh_c_app_t* app = (mesh_c_app_t*)ctx;
  count(app, app->poll_passes > app->membership_post_pass);
  posted(device, ctx);
}

static void on_message(void* user, rl_node_id_t origin, rl_message_id_t id,
                       const uint8_t* payload, size_t payload_size) {
  mesh_c_app_t* app = (mesh_c_app_t*)user;
  (void)origin;
  (void)id;
  (void)payload;
  (void)payload_size;
  ++app->messages;
}

static void on_delivery(void* user, const rl_delivery_result_t* result) {
  mesh_c_app_t* app = (mesh_c_app_t*)user;
  if (result->reason_id == ROUTELOOM_REASON_APP_APPLIED) {
    count(app, result->state == RL_DELIVERY_STATE_DELIVERED);
    app->applied_id = result->id;
    app->applied_result_pending = 1;
  }
}

static void on_membership(void* user, const rl_dev_membership_t* snapshot, uint16_t cause) {
  mesh_c_app_t* app = (mesh_c_app_t*)user;
  ++app->membership_events;
  app->last_cause = cause;
  try_reentry(app);
  app->membership_post_pass = app->poll_passes;
  count(app, rl_dev_post(app->device,
                        snapshot->since_ms > app->now_ms ? posted_from_membership : posted,
                        app) == RL_STATUS_OK);
}

static void on_connectivity(void* user, const rl_dev_connectivity_t* snapshot) {
  mesh_c_app_t* app = (mesh_c_app_t*)user;
  (void)snapshot;
  ++app->connectivity_events;
}

static void on_operation(void* user, uint32_t operation, uint16_t result) {
  mesh_c_app_t* app = (mesh_c_app_t*)user;
  app->op_last = operation;
  app->op_result = result;
}

static void on_applied_request(void* user, const rl_applied_request_t* request) {
  mesh_c_app_t* app = (mesh_c_app_t*)user;
  ++app->applied_requests;
  try_reentry(app);
  if (app->open_count == MESH_C_APP_OPEN_MAX) return; /* the SDK holds at most four */
  app->open_ticket[app->open_count] = request->ticket;
  /* on_poll supplies the current Owner-pass time after this callback. */
  app->open_due[app->open_count] = 0;
  ++app->open_count;
}

/* Owner pass: the first one runs the boundary checks, every one completes
   the tickets that are due (Success). */
static void on_poll(void* user, rl_dev_t* device, rl_monotonic_ms_t now_ms) {
  mesh_c_app_t* app = (mesh_c_app_t*)user;
  uint8_t i = 0;
  (void)device;
  app->now_ms = now_ms;
  ++app->poll_passes;
  if (app->checks == 0) {
    check_boundaries(app);
    for (uint8_t n = 0; n < 8; ++n)
      count(app, rl_dev_post(app->device, posted, app) == RL_STATUS_OK);
    count(app, rl_dev_post(app->device, posted, app) == RL_STATUS_BUSY);
    count(app, app->posted_runs == 0);
  }
  if (app->applied_result_pending) {
    rl_applied_result_t result;
    rl_delivery_result_t delivery;
    rl_struct_init(&result, sizeof(result));
    rl_struct_init(&delivery, sizeof(delivery));
    count(app, rl_dev_applied_result(device, app->applied_id, &result) == RL_STATUS_OK &&
                   result.outcome == RL_APPLIED_SUCCESS && result.code == 0 && !result.late);
    count(app, rl_dev_delivery(device, app->applied_id, &delivery) == RL_STATUS_OK &&
                   delivery.state == RL_DELIVERY_STATE_DELIVERED &&
                   delivery.reason_id == ROUTELOOM_REASON_APP_APPLIED);
    app->applied_result_pending = 0;
  }
  while (i < app->open_count) {
    rl_applied_result_t result;
    if (app->open_due[i] == 0) app->open_due[i] = now_ms + app->delay_ms;
    if (now_ms < app->open_due[i]) {
      ++i;
      continue;
    }
    rl_struct_init(&result, sizeof(result));
    result.outcome = RL_APPLIED_SUCCESS;
    if (rl_dev_complete_applied(app->device, app->open_ticket[i], &result) == RL_STATUS_OK) {
      ++app->applied_completed;
      count(app, rl_dev_complete_applied(app->device, app->open_ticket[i], &result) ==
                     RL_STATUS_NOT_FOUND);
    } else {
      ++app->applied_refused;
    }
    --app->open_count;
    app->open_ticket[i] = app->open_ticket[app->open_count];
    app->open_due[i] = app->open_due[app->open_count];
  }
}

static void on_object(void* user, const rl_dev_object_rx_t* info, const uint8_t* bytes, size_t size) {
  mesh_c_app_t* app = (mesh_c_app_t*)user;
  count(app, info->version == RL_DEV_API_VERSION && size <= sizeof(app->object_data));
  if (size > sizeof(app->object_data)) return;
  memcpy(app->object_data, bytes, size); app->object_size = (uint16_t)size; ++app->objects;
}
static void on_object_result(void* user, const rl_dev_object_result_t* result) {
  mesh_c_app_t* app = (mesh_c_app_t*)user;
  app->object_state = result->state; ++app->object_results;
}
rl_status_code_t mesh_c_app_object_send(mesh_c_app_t* app, rl_node_id_t destination,
    const uint8_t* payload, size_t size, uint32_t deadline, uint32_t* id) {
  rl_dev_object_options_t options; rl_dev_object_options_init(&options); options.deadline_ms = deadline;
  app->object_results = 0;
  return rl_dev_send_object(app->device, destination, payload, size, &options, id);
}
rl_status_code_t mesh_c_app_object_buffer(mesh_c_app_t* app, uint8_t* bytes, size_t size) {
  return rl_dev_register_object_buffer(app->device, bytes, size);
}
rl_status_code_t mesh_c_app_object_cancel(mesh_c_app_t* app, uint32_t id) {
  return rl_dev_cancel_object(app->device, id);
}

void mesh_c_app_observer(mesh_c_app_t* app, rl_dev_observer_t* out) {
  rl_dev_struct_init(out, sizeof(*out));
  out->user = app;
  out->on_object = on_object; out->on_object_result = on_object_result;
  out->on_message = on_message;
  out->on_delivery = on_delivery;
  out->on_membership = on_membership;
  out->on_connectivity = on_connectivity;
  out->on_operation = on_operation;
  out->on_applied_request = on_applied_request;
  out->on_poll = on_poll;
}

rl_status_code_t mesh_c_app_send(mesh_c_app_t* app, rl_node_id_t destination,
                                 const uint8_t* payload, size_t size, uint8_t delivery,
                                 uint16_t coalesce_key, uint32_t lifetime_ms,
                                 rl_message_id_t* out_id) {
  rl_dev_send_options_t options;
  rl_dev_send_options_init(&options);
  options.delivery = (rl_delivery_class_t)delivery;
  options.coalesce_key = coalesce_key;
  options.lifetime_ms = lifetime_ms;
  return rl_dev_send(app->device, destination, payload, size, &options, out_id);
}

rl_status_code_t mesh_c_app_send_applied(mesh_c_app_t* app, rl_node_id_t destination,
                                         const uint8_t lease[RL_APPLIED_LEASE_SIZE],
                                         const uint8_t* payload, size_t size,
                                         rl_message_id_t* out_id) {
  rl_dev_send_options_t options;
  rl_dev_send_options_init(&options);
  options.delivery = RL_DELIVERY_APPLIED;
  options.lifetime_ms = 10000;
  return rl_dev_send_applied(app->device, destination, lease, payload, size, &options, out_id);
}

rl_status_code_t mesh_c_app_operation(mesh_c_app_t* app, int leave, uint32_t* out_operation) {
  return leave ? rl_dev_leave(app->device, out_operation)
               : rl_dev_request_join(app->device, out_operation);
}
