#ifndef ROUTELOOM_ROUTELOOM_H
#define ROUTELOOM_ROUTELOOM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RL_ABI_VERSION 2u  /* 2: Wire v2 — 32-bit epochs and route generation */
#define RL_MAX_APPLICATION_PAYLOAD 128u
#define RL_MAX_ESPNOW_BODY 250u
#define RL_AEAD_TAG_SIZE 16u

typedef uint64_t rl_node_id_t;
typedef uint64_t rl_network_id_t;
typedef uint64_t rl_monotonic_ms_t;

typedef enum rl_status_code {
  RL_STATUS_OK = 0,
  RL_STATUS_INVALID_ARGUMENT,
  RL_STATUS_INVALID_STATE,
  RL_STATUS_NOT_FOUND,
  RL_STATUS_ALREADY_EXISTS,
  RL_STATUS_UNSUPPORTED,
  RL_STATUS_WOULD_BLOCK,
  RL_STATUS_NO_CAPACITY,
  RL_STATUS_NO_ROUTE,
  RL_STATUS_EXPIRED,
  RL_STATUS_TIME_UNCERTAIN,
  RL_STATUS_AUTHENTICATION_FAILED,
  RL_STATUS_AUTHORIZATION_FAILED,
  RL_STATUS_REPLAY_REJECTED,
  RL_STATUS_COUNTER_EXHAUSTED,
  RL_STATUS_STORAGE_FAILURE,
  RL_STATUS_RADIO_FAILURE,
  RL_STATUS_DRIVER_RESULT_UNKNOWN,
  RL_STATUS_PROTOCOL_ERROR,
  RL_STATUS_INTEGRITY_ERROR,
  RL_STATUS_CONFLICT,
  RL_STATUS_BUSY,
  RL_STATUS_INTERNAL_ERROR,
  /* Autonomous-mesh reason codes — appended in the same order as
     StatusCode (status.hpp); numeric parity is asserted in c_api.cpp. */
  RL_STATUS_DISCOVERY_BUDGET_EXHAUSTED,
  RL_STATUS_AUTH_REQUIRED,
  RL_STATUS_APPROVAL_REQUIRED,
  RL_STATUS_BINDING_CONFLICT,
  RL_STATUS_PEER_CAPACITY,
  RL_STATUS_CONGESTED,
  RL_STATUS_REMOTE_BUSY,
  RL_STATUS_NO_FEASIBLE_ALTERNATIVE,
  RL_STATUS_SURVEY_REQUIRES_OUTAGE_PERMISSION,
  RL_STATUS_LEGACY_PARTICIPANT,
  RL_STATUS_CLOCK_UNCERTAIN,
  RL_STATUS_PLAN_NOT_COMMITTED,
  RL_STATUS_RECOVERY_REQUIRED,
  RL_STATUS_AUTH_PROFILE_UNAVAILABLE,
  RL_STATUS_NETWORK_REQUIRED
} rl_status_code_t;

typedef enum rl_delivery_class {
  RL_DELIVERY_BEST_EFFORT = 0,
  RL_DELIVERY_RELIABLE = 1,
  /* APPLIED is not yet exposed over the C ABI: rl_send rejects it with
     RL_STATUS_UNSUPPORTED. Use the C++ send_applied()/applied_result()
     surface; a dedicated rl_send_applied may follow. */
  RL_DELIVERY_APPLIED = 2
} rl_delivery_class_t;

typedef enum rl_delivery_state {
  RL_DELIVERY_STATE_EMPTY = 0,
  RL_DELIVERY_STATE_ACCEPTED,
  RL_DELIVERY_STATE_WAITING_FOR_ROUTE,
  RL_DELIVERY_STATE_QUEUED,
  RL_DELIVERY_STATE_WAITING_FOR_MAC,
  RL_DELIVERY_STATE_WAITING_FOR_HOP_ACCEPT,
  RL_DELIVERY_STATE_WAITING_FOR_END_RECEIPT,
  RL_DELIVERY_STATE_DELIVERED,
  RL_DELIVERY_STATE_FAILED,
  RL_DELIVERY_STATE_EXPIRED,
  RL_DELIVERY_STATE_CANCELLED_BEFORE_TX,
  RL_DELIVERY_STATE_INDETERMINATE
} rl_delivery_state_t;

typedef enum rl_priority {
  RL_PRIORITY_BULK = 0,
  RL_PRIORITY_NORMAL = 1,
  RL_PRIORITY_MANAGEMENT = 2,
  RL_PRIORITY_URGENT = 3
} rl_priority_t;

typedef enum rl_security_scope {
  RL_SECURITY_LINK = 0,
  RL_SECURITY_END_TO_END = 1
} rl_security_scope_t;

typedef struct rl_message_id {
  uint32_t session;
  uint64_t sequence;
} rl_message_id_t;

typedef struct rl_security_context {
  rl_security_scope_t scope;
  rl_network_id_t network;
  rl_node_id_t sender;
  rl_node_id_t receiver;
  uint32_t epoch;
} rl_security_context_t;

typedef struct rl_node_config {
  uint32_t struct_size;
  uint32_t abi_version;
  rl_network_id_t network;
  rl_node_id_t node;
  uint32_t message_session;
  uint32_t link_epoch;
  uint32_t end_epoch;
  uint32_t route_advertisement_period_ms;
  uint32_t route_lifetime_ms;
  uint32_t hop_accept_timeout_ms;
  uint32_t callback_watchdog_ms;
  uint8_t max_link_attempts;
  uint8_t max_end_to_end_rounds;
  /* Origin generation of this node's route source; persisted monotonic, +1 per boot. */
  uint32_t route_generation;
  /* Nonzero: the §14 management airtime budget gate applies (calibrated
     profile only — see NodeConfig::control_budget_gate_enabled). */
  uint8_t control_budget_gate_enabled;
  uint8_t reserved[3];
} rl_node_config_t;

typedef struct rl_send_options {
  uint32_t struct_size;
  uint32_t abi_version;
  rl_delivery_class_t delivery;
  rl_priority_t priority;
  /* 1..30000; larger values are refused with RL_STATUS_INVALID_ARGUMENT. */
  uint32_t lifetime_ms;
  uint8_t hop_limit;
  uint8_t reserved[7];
} rl_send_options_t;

typedef struct rl_delivery_result {
  rl_message_id_t id;
  rl_delivery_state_t state;
  const char* reason;
} rl_delivery_result_t;

typedef struct rl_radio_vtable {
  void* user;
  rl_status_code_t (*send)(void* user, rl_node_id_t peer, uint64_t token,
                           const uint8_t* frame, size_t frame_size);
  rl_status_code_t (*recover)(void* user);
} rl_radio_vtable_t;

typedef struct rl_security_vtable {
  void* user;
  bool (*ready)(void* user);
  rl_status_code_t (*next_counter)(void* user, const rl_security_context_t* context,
                                   uint64_t* counter);
  rl_status_code_t (*seal)(void* user, const rl_security_context_t* context, uint64_t counter,
                           const uint8_t* aad, size_t aad_size,
                           const uint8_t* plaintext, size_t plaintext_size,
                           uint8_t* ciphertext, size_t ciphertext_capacity,
                           uint8_t tag[RL_AEAD_TAG_SIZE]);
  rl_status_code_t (*open)(void* user, const rl_security_context_t* context, uint64_t counter,
                           const uint8_t* aad, size_t aad_size,
                           const uint8_t* ciphertext, size_t ciphertext_size,
                           const uint8_t tag[RL_AEAD_TAG_SIZE],
                           uint8_t* plaintext, size_t plaintext_capacity);
} rl_security_vtable_t;

typedef struct rl_observer_vtable {
  void* user;
  void (*on_message)(void* user, rl_node_id_t origin, rl_message_id_t id,
                     const uint8_t* payload, size_t payload_size);
  void (*on_delivery)(void* user, const rl_delivery_result_t* result);
  void (*on_diagnostic)(void* user, const char* reason, rl_node_id_t peer,
                        const rl_message_id_t* message);
} rl_observer_vtable_t;

typedef struct rl_context rl_context_t;

size_t rl_context_size(void);
size_t rl_context_alignment(void);
void rl_node_config_init(rl_node_config_t* config);
void rl_send_options_init(rl_send_options_t* options);

rl_status_code_t rl_init(void* storage, size_t storage_size,
                         const rl_node_config_t* config,
                         const rl_radio_vtable_t* radio,
                         const rl_security_vtable_t* security,
                         const rl_observer_vtable_t* observer,
                         rl_context_t** out_context);
void rl_deinit(rl_context_t* context);
rl_status_code_t rl_start(rl_context_t* context, rl_monotonic_ms_t now_ms);
rl_status_code_t rl_add_neighbor(rl_context_t* context, rl_node_id_t neighbor,
                                 uint16_t link_metric, rl_monotonic_ms_t now_ms);
rl_status_code_t rl_remove_neighbor(rl_context_t* context, rl_node_id_t neighbor,
                                    rl_monotonic_ms_t now_ms);
rl_status_code_t rl_send(rl_context_t* context, rl_node_id_t destination,
                         const uint8_t* payload, size_t payload_size,
                         const rl_send_options_t* options,
                         rl_monotonic_ms_t now_ms, rl_message_id_t* out_id);
rl_status_code_t rl_cancel(rl_context_t* context, rl_message_id_t id);
rl_status_code_t rl_get_delivery(rl_context_t* context, rl_message_id_t id,
                                 rl_delivery_result_t* out_result);
void rl_poll(rl_context_t* context, rl_monotonic_ms_t now_ms);
void rl_on_radio_receive(rl_context_t* context, rl_node_id_t peer,
                         const uint8_t* frame, size_t frame_size, int8_t rssi_dbm,
                         rl_monotonic_ms_t now_ms);
void rl_on_radio_tx_result(rl_context_t* context, uint64_t token, bool success,
                           rl_monotonic_ms_t now_ms);
const char* rl_status_code_name(rl_status_code_t code);

#ifdef __cplusplus
}
#endif

#endif
