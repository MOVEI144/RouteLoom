#ifndef ROUTELOOM_OWNER_MESH_C_APP_H
#define ROUTELOOM_OWNER_MESH_C_APP_H

/* The mesh peer's C application (--c-app, P05-C): every application call
   of the node goes through the Device C API (device.h) from C code. */

#include <stdint.h>

#include "routeloom/device.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_C_APP_OPEN_MAX 4u

typedef struct mesh_c_app {
  rl_dev_t* device;
  /* Device events (restored across restarts by the peer). */
  uint32_t membership_events;
  uint16_t last_cause;
  uint16_t op_result;
  uint32_t op_last;
  uint32_t connectivity_events;
  /* Calls from inside callbacks and how many answered BUSY. */
  uint32_t reentry_calls;
  uint32_t reentry_busy;
  /* Deferred APPLIED endpoint: completes each request `delay_ms` after it
     arrived (0: not yet enabled, requests stay open until then). */
  uint32_t delay_ms;
  uint32_t applied_requests;
  uint32_t applied_completed;
  uint32_t applied_refused;
  uint8_t open_count;
  uint64_t open_ticket[MESH_C_APP_OPEN_MAX];
  uint64_t open_due[MESH_C_APP_OPEN_MAX];
  uint64_t now_ms;
  /* struct_size/version boundary checks run at the first Owner pass. */
  uint32_t checks;
  uint32_t check_failures;
  /* Jobs posted from membership callbacks that ran on a later pass. */
  uint32_t posted_runs;
  /* Application messages received through on_message. */
  uint32_t messages;
} mesh_c_app_t;

void mesh_c_app_observer(mesh_c_app_t* app, rl_dev_observer_t* out);
/* delivery: rl_delivery_class_t; coalesce_key only for BEST_EFFORT. */
rl_status_code_t mesh_c_app_send(mesh_c_app_t* app, rl_node_id_t destination,
                                 const uint8_t* payload, size_t size, uint8_t delivery,
                                 uint16_t coalesce_key, uint32_t lifetime_ms,
                                 rl_message_id_t* out_id);
rl_status_code_t mesh_c_app_send_applied(mesh_c_app_t* app, rl_node_id_t destination,
                                         const uint8_t lease[RL_APPLIED_LEASE_SIZE],
                                         const uint8_t* payload, size_t size,
                                         rl_message_id_t* out_id);
rl_status_code_t mesh_c_app_operation(mesh_c_app_t* app, int leave, uint32_t* out_operation);

#ifdef __cplusplus
}
#endif

#endif
