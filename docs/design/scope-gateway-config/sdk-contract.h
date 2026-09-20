#ifndef ROUTELOOM_ENDPOINT_DESIGN_CONTRACT_H
#define ROUTELOOM_ENDPOINT_DESIGN_CONTRACT_H
/* DESIGN DECLARATIONS ONLY. Not an installed header or a linkable library.
 * Syntax checking is not a runtime/ABI compatibility qualification.
 * Existing types and status numbers come from the current public C header. */
#include "routeloom/routeloom.h"
#ifdef __cplusplus
extern "C" {
#endif
#define RL_ENDPOINT_DESIGN_VERSION 1u
#define RL_GATEWAY_PAYLOAD_LIMIT 96u
#define RL_CONFIG_PATCH_LIMIT 512u

typedef uint64_t rl_extension_ticket_t;
typedef uint64_t rl_scope_ref_t; /* provider-owned handle; never raw key bytes */
typedef struct rl_gateway_endpoint rl_gateway_endpoint_t;
typedef struct rl_extension_message_key {
  rl_node_id_t origin;
  rl_message_id_t id;
} rl_extension_message_key_t;

typedef struct rl_scope_policy_request {
  uint32_t struct_size;
  uint32_t version;
  rl_scope_ref_t scope;
  uint8_t mode; /* 0 Off, 1 OpenLegacy, 2 OptionalMigration, 3 Required */
  uint8_t scope_class; /* 1 Member, 2 Commissioning */
  uint8_t reserved[2];
  uint32_t migration_remaining_ms; /* only for explicitly allowed transition */
} rl_scope_policy_request_t;

/* Must validate policy/credentials. Failure never enables legacy fallback. */
rl_status_code_t rl_scope_set_policy(rl_context_t*,
    const rl_scope_policy_request_t*, rl_extension_ticket_t*);

typedef struct rl_gateway_resolve_request {
  uint32_t struct_size;
  uint32_t version;
  rl_node_id_t gateway;
  uint8_t receipt_scope; /* 1 GATEWAY_SDK_RAM, 2 HOST_RECEIVE_RAM */
  uint8_t reserved[3];
  uint8_t expected_host_digest[32]; /* zeros for scope 1; authenticated pin for 2 */
  uint32_t deadline_ms;
} rl_gateway_resolve_request_t;

typedef struct rl_gateway_receipt {
  uint32_t struct_size;
  uint32_t version;
  rl_extension_message_key_t message;
  rl_node_id_t gateway;
  uint8_t receipt_scope;
  uint8_t reserved[3];
  rl_delivery_state_t state;
  rl_status_code_t status;
  uint16_t detail_reason;
  uint16_t reserved2;
} rl_gateway_receipt_t;

typedef void (*rl_gateway_resolved_fn)(void*, rl_extension_ticket_t,
    rl_status_code_t, rl_gateway_endpoint_t*);
/* Successful resolution transfers one bounded reference to caller.
 * Failed resolution passes NULL. Release via owner task after use.
 * Accepted send copies payload and retains its own endpoint reference. */
rl_status_code_t rl_gateway_resolve(rl_context_t*,
    const rl_gateway_resolve_request_t*, rl_gateway_resolved_fn, void*,
    rl_extension_ticket_t*);
void rl_gateway_endpoint_release(rl_context_t*, rl_gateway_endpoint_t*);
rl_status_code_t rl_gateway_send(rl_context_t*, const rl_gateway_endpoint_t*,
    const uint8_t*, size_t, const rl_send_options_t*, rl_message_id_t*);
rl_status_code_t rl_gateway_get_delivery(rl_context_t*, rl_message_id_t,
    rl_gateway_receipt_t*);

typedef struct rl_config_request {
  uint32_t struct_size;
  uint32_t version;
  rl_node_id_t target;
  uint16_t namespace_id;
  uint16_t schema;
  uint64_t expected_revision;
  uint8_t base_hash[32];
  uint8_t operation_id[16];
  const uint8_t* patch;
  size_t patch_size;
  uint32_t deadline_ms;
} rl_config_request_t;

typedef struct rl_config_result {
  uint32_t struct_size;
  uint32_t version;
  rl_node_id_t target;
  uint8_t operation_id[16];
  uint64_t decision_revision;
  uint64_t active_revision;
  uint8_t active_hash[32];
  uint8_t phase;
  uint8_t reserved[3];
  rl_status_code_t status;
  uint16_t detail_reason;
  uint16_t reserved2;
} rl_config_result_t;

typedef void (*rl_config_result_fn)(void*, rl_extension_ticket_t,
    const rl_config_result_t*); /* result borrowed during callback only */
/* Requires an authenticated issuer capability bound during local setup.
 * No public verified=true parameter. Copies patch only after full reservation.
 * Completion reports DECIDED separately from ACTIVE; callback never blocks radio. */
rl_status_code_t rl_config_propose(rl_context_t*, const rl_config_request_t*,
    rl_config_result_fn, void*, rl_extension_ticket_t*);
rl_status_code_t rl_config_query(rl_context_t*, rl_node_id_t, uint16_t,
    const uint8_t operation_id[16], rl_config_result_fn, void*,
    rl_extension_ticket_t*);
#ifdef __cplusplus
}
#endif
#endif
