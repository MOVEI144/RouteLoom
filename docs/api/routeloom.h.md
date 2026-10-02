# routeloom.h 宣言 reference

生成元を編集し、`python3 tools/gen_user_reference.py` で更新する。

[components/routeloom/include/routeloom/routeloom.h](../../components/routeloom/include/routeloom/routeloom.h) の全宣言と契約コメント。
使い方は [API 案内](README.md)。HTML reference は Doxygen artifact を参照。

```c
#ifndef ROUTELOOM_ROUTELOOM_H
#define ROUTELOOM_ROUTELOOM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Core C ABI 3 (docs/spec/compatibility.md §4). Every public struct and
   vtable starts with {struct_size, version}: version must be RL_ABI_VERSION
   and struct_size at least the size this header declares, otherwise the
   call returns RL_STATUS_INVALID_ARGUMENT. A larger struct_size is accepted
   and its tail ignored. 3.x grows by appending tail fields and functions
   only; layouts are pinned by protocol/abi-golden (ILP32 and LP64).
   rl_struct_init() zeroes a struct and fills its header. */
#define RL_ABI_VERSION 3u
#define RL_ABI_VERSION_MINOR 0u
#define RL_MAX_APPLICATION_PAYLOAD 128u
#define RL_MAX_ESPNOW_BODY 250u
#define RL_AEAD_TAG_SIZE 16u
/* Gateway-scoped routing profile: gateways per site (kMaxRouteGateways). */
#define RL_MAX_ROUTE_GATEWAYS 4u

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
  RL_STATUS_NETWORK_REQUIRED,
  RL_STATUS_TOO_LARGE
} rl_status_code_t;

typedef enum rl_delivery_class {
  RL_DELIVERY_BEST_EFFORT = 0,
  RL_DELIVERY_RELIABLE = 1,
  /* APPLIED goes through rl_send_applied; rl_send refuses it with
     RL_STATUS_UNSUPPORTED. */
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

/* A security vtable must refuse (RL_STATUS_UNSUPPORTED) a scope it does not
   implement. RL_SECURITY_GROUP (group delivery, docs/design/sdk-v1/
   group-delivery.md §7): sender = the group message's origin. The wire
   destination is RL_GROUP_ADDRESS_BASE | group id and is authenticated by
   the end AAD. The vtable receiver is always
   RL_GROUP_ADDRESS_BASE | RL_GROUP_ALL (the site broadcast key domain),
   including non-ALL groups; the context does not carry the group id. Keys
   MUST be per (sender, epoch): the nonce carries no sender, so sharing a
   key would reuse nonces. */
typedef enum rl_security_scope {
  RL_SECURITY_LINK = 0,
  RL_SECURITY_END_TO_END = 1,
  RL_SECURITY_GROUP = 2,
  /* Reserved (docs/design/sdk-v1/03-key-hierarchy.md §8): group-key
     broadcast link scope. The node does not issue it yet; refuse it. */
  RL_SECURITY_GROUP_LINK = 3
} rl_security_scope_t;

/* A plain value identifier; the only public struct without a header. */
typedef struct rl_message_id {
  uint32_t session;
  uint64_t sequence;
} rl_message_id_t;

typedef struct rl_security_context {
  uint32_t struct_size;
  uint32_t version;
  rl_security_scope_t scope;
  uint32_t epoch;
  rl_network_id_t network;
  rl_node_id_t sender;
  rl_node_id_t receiver;
} rl_security_context_t;

typedef struct rl_node_config {
  uint32_t struct_size;
  uint32_t version;
  rl_network_id_t network;
  rl_node_id_t node;
  uint32_t message_session;
  uint32_t link_epoch;
  uint32_t end_epoch;
  /* Origin generation of this node's route source; persisted monotonic, +1 per boot. */
  uint32_t route_generation;
  uint32_t route_advertisement_period_ms;
  uint32_t route_lifetime_ms;
  uint32_t hop_accept_timeout_ms;
  uint32_t callback_watchdog_ms;
  uint8_t max_link_attempts;
  uint8_t max_end_to_end_rounds;
  /* Nonzero: the §14 management airtime budget gate applies (calibrated
     profile only — see NodeConfig::control_budget_gate_enabled). */
  uint8_t control_budget_gate_enabled;
  /* Gateway-scoped routing profile (docs/design/sdk-v1/routing-scale.md).
     0 (the default) keeps the flat profile. 1..RL_MAX_ROUTE_GATEWAYS
     selects the scoped profile with route_gateways[0..count-1] (in
     preference order; a gateway lists itself; every node of a site carries
     the same set). rl_init rejects a larger count and a zero or duplicate
     id inside the count; entries at or beyond the count are ignored.
     rl_start rejects a scoped config whose lease is below
     (2 * route_refresh_ticks + 2) * route_advertisement_period_ms — the
     product values are 5000 ms / 90000 ms, not the flat defaults
     rl_node_config_init() sets. */
  uint8_t route_gateway_count;
  /* Scoped profile only: per-link refresh cadence in advertisement periods;
     0 selects the SDK default (6). */
  uint8_t route_refresh_ticks;
  uint8_t reserved[3];
  rl_node_id_t route_gateways[RL_MAX_ROUTE_GATEWAYS];
} rl_node_config_t;

typedef struct rl_send_options {
  uint32_t struct_size;
  uint32_t version;
  rl_delivery_class_t delivery;
  rl_priority_t priority;
  /* 1..30000; larger values are refused with RL_STATUS_INVALID_ARGUMENT. */
  uint32_t lifetime_ms;
  uint8_t hop_limit;
  /* Nonzero: per-source ordering (RELIABLE only; group-delivery.md §6) — not
     transmitted until the previous ordered message to the same destination
     is delivered or past its own deadline. */
  uint8_t ordered;
  uint8_t reserved[2];
} rl_send_options_t;

/* Delivery results carry reason_id, the u16 id of `reason` in the reason
   registry (protocol/manifest.json, ROUTELOOM_REASON_* in version.h); 0
   (NONE) when the reason has no registered id. `reason` is a static
   string, valid for the program's lifetime. */
typedef struct rl_delivery_result {
  uint32_t struct_size;
  uint32_t version;
  rl_message_id_t id;
  rl_delivery_state_t state;
  uint16_t reason_id;
  uint16_t reserved;
  const char* reason;
} rl_delivery_result_t;

/* ---- Group delivery (docs/design/sdk-v1/group-delivery.md) --------------
   Only a configured route gateway of the gateway-scoped profile may send
   (rl_send_group returns RL_STATUS_UNSUPPORTED otherwise). Received group
   messages reach rl_observer_vtable_t.on_message with a group message id:
   its sequence has RL_GROUP_SEQUENCE_FLAG set (never equal to a unicast id). */
#define RL_GROUP_ALL 0xFFFFu
#define RL_GROUP_ADDRESS_BASE 0xFFFFFFFFFFFF0000ull
#define RL_GROUP_SEQUENCE_FLAG 0x8000000000000000ull
#define RL_GROUP_PAYLOAD_MAX 127u
#define RL_GROUP_MISSING_MAX 12u
#define RL_GROUP_MEMBERSHIP_MAX 8u

typedef struct rl_group_send_options {
  uint32_t struct_size;
  uint32_t version;
  rl_priority_t priority;  /* RL_PRIORITY_URGENT bypasses the source queue/budget */
  uint32_t lifetime_ms;    /* 1..30000 */
  uint8_t hop_limit;       /* 1..254 */
  uint8_t ordered;         /* nonzero: in-order at every receiver (bounded hold) */
  uint8_t reserved[2];
} rl_group_send_options_t;

typedef struct rl_group_result {
  uint32_t struct_size;
  uint32_t version;
  rl_message_id_t id;
  rl_delivery_state_t state;  /* QUEUED, WAITING_FOR_END_RECEIPT, DELIVERED (complete),
                                 FAILED (incomplete/superseded), EXPIRED (never sent) */
  uint16_t reason_id;         /* as rl_delivery_result_t */
  uint16_t group;
  const char* reason;
  uint16_t delivered;         /* members that accepted it */
  uint16_t nonmember;         /* reached, not members */
  uint16_t missing_total;     /* known in the tree, unconfirmed */
  uint16_t unaccounted;       /* known to the source, in no report */
  uint8_t rounds;
  uint8_t missing_count;      /* ids in missing[] */
  uint8_t missing_truncated;  /* missing_total > missing_count */
  uint8_t reserved;
  rl_node_id_t missing[RL_GROUP_MISSING_MAX];
} rl_group_result_t;

/* ---- APPLIED delivery (docs/design/sdk-completion/01-applied-delivery.md)
   The origin sends with rl_send_applied and the destination's execution
   lease (rl_applied_lease at that node; a stale lease is refused with a
   RESULT carrying the current one, readable with rl_get_applied_result).
   The destination's observer receives on_applied_request with a ticket and
   answers later — after the callback returned — with rl_complete_applied.
   Until then the origin's QUERY is answered Pending. A completion after the
   request deadline (RL_STATUS_EXPIRED), a second completion or one for an
   unknown or previous-boot ticket (RL_STATUS_NOT_FOUND) is never applied. */
#define RL_APPLIED_LEASE_SIZE 16u
#define RL_APPLIED_PAYLOAD_MAX 112u
#define RL_APPLIED_RESULT_DATA_MAX 48u
/* Application codes at or above this value are reserved for SDK refusals
   (outcome FAILURE). A STALE_LEASE refusal carries the destination's current
   lease as its data. */
#define RL_APPLIED_SDK_CODE_BASE 0xFFFF0000u
#define RL_APPLIED_CODE_INTERNAL_ERROR 0xFFFF0000u
#define RL_APPLIED_CODE_STALE_LEASE 0xFFFF0001u
#define RL_APPLIED_CODE_NO_ENDPOINT 0xFFFF0002u
#define RL_APPLIED_CODE_CAPACITY 0xFFFF0003u
#define RL_APPLIED_CODE_MALFORMED_REQUEST 0xFFFF0004u

typedef enum rl_applied_outcome {
  RL_APPLIED_SUCCESS = 0,
  RL_APPLIED_FAILURE = 1
} rl_applied_outcome_t;

typedef struct rl_applied_request {
  uint32_t struct_size;
  uint32_t version;
  uint64_t ticket;
  rl_node_id_t origin;
  rl_message_id_t id;
  uint32_t remaining_ms;  /* request deadline left at dispatch */
  uint32_t reserved;
  const uint8_t* payload; /* borrowed for the callback only; the lease is stripped */
  size_t payload_size;
} rl_applied_request_t;

/* The verdict: input of rl_complete_applied, output of rl_get_applied_result
   (`late`: the RESULT arrived after the delivery went terminal). */
typedef struct rl_applied_result {
  uint32_t struct_size;
  uint32_t version;
  uint32_t code;          /* application-chosen, below RL_APPLIED_SDK_CODE_BASE */
  uint8_t outcome;        /* rl_applied_outcome_t */
  uint8_t data_size;      /* 0..RL_APPLIED_RESULT_DATA_MAX */
  uint8_t late;
  uint8_t reserved;
  uint8_t data[RL_APPLIED_RESULT_DATA_MAX];
} rl_applied_result_t;

/* ---- Capabilities: what this build and context implement. A bit is never
   set for a feature the context cannot serve. */
#define RL_CAP_APPLIED (1u << 0)        /* rl_send_applied and the async endpoint */
#define RL_CAP_ORDERED (1u << 1)        /* rl_send_options_t.ordered */
#define RL_CAP_REPLY_PEER (1u << 2)     /* rl_attach_reply_peer */
/* Context only: the gateway-scoped profile, which also delivers group
   messages to on_message. */
#define RL_CAP_SCOPED_ROUTING (1u << 3)
#define RL_CAP_GROUP_SEND (1u << 4)     /* context only: a route gateway may rl_send_group */

typedef struct rl_capabilities {
  uint32_t struct_size;
  uint32_t version;
  uint32_t features;                /* RL_CAP_* */
  uint16_t max_payload;             /* rl_send */
  uint16_t max_applied_payload;     /* rl_send_applied */
  uint16_t max_group_payload;       /* rl_send_group */
  uint8_t max_route_gateways;
  uint8_t max_group_membership;
} rl_capabilities_t;

typedef struct rl_radio_vtable {
  uint32_t struct_size;
  uint32_t version;
  void* user;
  rl_status_code_t (*send)(void* user, rl_node_id_t peer, uint64_t token,
                           const uint8_t* frame, size_t frame_size);
  rl_status_code_t (*recover)(void* user);
} rl_radio_vtable_t;

/* Test and porting use only. The provider seals with static keys under the
   configured link_epoch/end_epoch and is treated as always holding them;
   there are no session callbacks. Production security (MemberEdhoc, group
   keys, rekey) is the ESP-IDF Device API, not this vtable. */
typedef struct rl_security_vtable {
  uint32_t struct_size;
  uint32_t version;
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

/* Callbacks run on the owner task inside rl_poll/rl_on_radio_*; arguments
   are borrowed for the call. A callback must not call back into the
   context (such calls return RL_STATUS_BUSY or are ignored). Any function
   may be NULL. A NULL on_applied_request makes the node refuse APPLIED
   requests with a NoEndpoint RESULT. */
typedef struct rl_observer_vtable {
  uint32_t struct_size;
  uint32_t version;
  void* user;
  void (*on_message)(void* user, rl_node_id_t origin, rl_message_id_t id,
                     const uint8_t* payload, size_t payload_size);
  void (*on_delivery)(void* user, const rl_delivery_result_t* result);
  void (*on_diagnostic)(void* user, const char* reason, rl_node_id_t peer,
                        const rl_message_id_t* message);
  void (*on_applied_request)(void* user, const rl_applied_request_t* request);
} rl_observer_vtable_t;

/* ---- ExpectedReply peer leases (issue #117, design-q116 §6.4) ------------
   Mirrors ReplyPeerPort (reply_peer_leases.hpp). A NULL function behaves as
   RL_STATUS_UNSUPPORTED. Tokens are (use_slot, use_serial) pairs; see the
   C++ header for the handle contract. Callbacks must not re-enter the node:
   the bridge reports RL_STATUS_BUSY and changes nothing while one runs. */
typedef struct rl_reply_peer_vtable {
  uint32_t struct_size;
  uint32_t version;
  void* user;
  rl_status_code_t (*acquire)(void* user, rl_node_id_t peer, uint32_t binding_id,
                              uint32_t binding_generation, uint32_t rx_context_id,
                              rl_monotonic_ms_t deadline_ms, rl_monotonic_ms_t now_ms,
                              uint32_t* out_use_slot, uint32_t* out_use_serial);
  rl_status_code_t (*release)(void* user, uint32_t use_slot, uint32_t use_serial);
  rl_status_code_t (*validate)(void* user, uint32_t use_slot, uint32_t use_serial,
                               rl_monotonic_ms_t now_ms);
  rl_status_code_t (*send_reply)(void* user, uint32_t use_slot, uint32_t use_serial,
                                 uint64_t tx_token, const uint8_t* frame,
                                 size_t frame_size, rl_monotonic_ms_t now_ms);
  rl_status_code_t (*snapshot_binding)(void* user, rl_node_id_t peer,
                                       uint32_t* out_binding_id,
                                       uint32_t* out_binding_generation,
                                       uint32_t* out_rx_context_id);
  rl_status_code_t (*send_bound)(void* user, rl_node_id_t peer, uint32_t binding_id,
                                 uint32_t binding_generation, uint32_t rx_context_id,
                                 uint64_t tx_token, const uint8_t* frame,
                                 size_t frame_size);
} rl_reply_peer_vtable_t;

typedef struct rl_context rl_context_t;

/* The library's ABI: major == RL_ABI_VERSION for a matching header. */
void rl_abi_version(uint32_t* out_major, uint32_t* out_minor);
/* Zeroes `struct_size` bytes of `object` and writes its header (any public
   struct or vtable). */
void rl_struct_init(void* object, size_t struct_size);
/* rl_struct_init plus the defaults. */
void rl_node_config_init(rl_node_config_t* config);
void rl_send_options_init(rl_send_options_t* options);
void rl_group_send_options_init(rl_group_send_options_t* options);

size_t rl_context_size(void);
size_t rl_context_alignment(void);
rl_status_code_t rl_init(void* storage, size_t storage_size,
                         const rl_node_config_t* config,
                         const rl_radio_vtable_t* radio,
                         const rl_security_vtable_t* security,
                         const rl_observer_vtable_t* observer,
                         rl_context_t** out_context);
void rl_deinit(rl_context_t* context);
rl_status_code_t rl_start(rl_context_t* context, rl_monotonic_ms_t now_ms);
/* A NULL context reports what the library implements; a context adds its
   configured profile (group send, scoped routing). */
rl_status_code_t rl_get_capabilities(const rl_context_t* context,
                                     rl_capabilities_t* out_capabilities);
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
/* APPLIED (see the block above rl_applied_request_t). options->delivery
   must be RL_DELIVERY_APPLIED. */
rl_status_code_t rl_applied_lease(const rl_context_t* context,
                                  uint8_t out_lease[RL_APPLIED_LEASE_SIZE]);
rl_status_code_t rl_send_applied(rl_context_t* context, rl_node_id_t destination,
                                 const uint8_t lease[RL_APPLIED_LEASE_SIZE],
                                 const uint8_t* payload, size_t payload_size,
                                 const rl_send_options_t* options,
                                 rl_monotonic_ms_t now_ms, rl_message_id_t* out_id);
rl_status_code_t rl_complete_applied(rl_context_t* context, uint64_t ticket,
                                     const rl_applied_result_t* result,
                                     rl_monotonic_ms_t now_ms);
/* RL_STATUS_NOT_FOUND until a verified RESULT is stored for `id`. */
rl_status_code_t rl_get_applied_result(const rl_context_t* context, rl_message_id_t id,
                                       rl_applied_result_t* out_result);
/* Owner-task contract (issue #60-3): rl_poll, rl_on_radio_receive and
   rl_on_radio_tx_result must run on the node's single owner task — the
   same context that calls rl_poll. Radio driver TX/RX callbacks are NOT
   the owner task: a callback must only capture/stage the event, hand it
   to the owner task (queue, notification, etc.), and return. The owner
   task drains staged events — invoking these handlers — and then calls
   rl_poll, which is where the next frame is submitted. Calling
   rl_on_radio_tx_result from inside a driver completion callback is
   unsupported: the completion would be resolved on the driver's context
   and any future dispatch there would re-enter a non-reentrant radio
   driver through vtable send(). */
void rl_poll(rl_context_t* context, rl_monotonic_ms_t now_ms);
/* The latest time the owner task must call rl_poll again when no radio
   event or API call arrives first; ask again after every owner pass. Until
   the core tracks its timers this is now_ms + RL_POLL_INTERVAL_MAX_MS. */
#define RL_POLL_INTERVAL_MAX_MS 2u
rl_monotonic_ms_t rl_next_deadline(const rl_context_t* context, rl_monotonic_ms_t now_ms);
void rl_on_radio_receive(rl_context_t* context, rl_node_id_t peer,
                         const uint8_t* frame, size_t frame_size, int8_t rssi_dbm,
                         rl_monotonic_ms_t now_ms);
/* Resolves the in-flight send only — the next submission comes from the
   following rl_poll, after the events the Owner staged for that pass
   (including RX, whose control replies keep lane priority over queued
   DATA). An Owner drains a bounded number of events per pass (the ESP-NOW
   runtime: 48); the rest are fed before the pass after. */
void rl_on_radio_tx_result(rl_context_t* context, uint64_t token, bool success,
                           rl_monotonic_ms_t now_ms);
/* ExpectedReply port wiring (see the block above rl_reply_peer_vtable_t).
   rl_attach_reply_peer installs the port (a NULL vtable detaches).
   rl_on_radio_receive_with_binding is rl_on_radio_receive plus the
   Owner-captured binding id/generation; its provenance is unattributed over
   the C boundary, so telemetry treats it as injected, never as driver
   evidence. Same owner-task contract as rl_on_radio_receive. */
rl_status_code_t rl_attach_reply_peer(rl_context_t* context,
                                      const rl_reply_peer_vtable_t* vtable);
void rl_on_radio_receive_with_binding(rl_context_t* context, rl_node_id_t peer,
                                      const uint8_t* frame, size_t frame_size,
                                      int8_t rssi_dbm, uint32_t binding_id,
                                      uint32_t binding_generation,
                                      rl_monotonic_ms_t now_ms);
/* Effective routing profile of an initialised context: copies up to
   `capacity` configured gateway ids into `out_gateways` (may be NULL when
   capacity is 0) and returns the number configured — 0 means the flat
   profile. Returns 0 for a NULL context. */
size_t rl_route_gateways(const rl_context_t* context, rl_node_id_t* out_gateways,
                         size_t capacity);
/* Group delivery (see the block above rl_group_send_options_t). */
rl_status_code_t rl_send_group(rl_context_t* context, uint16_t group,
                               const uint8_t* payload, size_t payload_size,
                               const rl_group_send_options_t* options,
                               rl_monotonic_ms_t now_ms, rl_message_id_t* out_id);
/* RL_STATUS_NOT_FOUND once the source's record was reclaimed. */
rl_status_code_t rl_get_group_result(rl_context_t* context, rl_message_id_t id,
                                     rl_group_result_t* out_result);
/* Replaces the local group set (ALL is implicit; ids 1..0xFFFE, no
   duplicates, at most RL_GROUP_MEMBERSHIP_MAX). */
rl_status_code_t rl_set_group_membership(rl_context_t* context, const uint16_t* groups,
                                         size_t count);
const char* rl_status_code_name(rl_status_code_t code);

#ifdef __cplusplus
}
#endif

#endif
```
