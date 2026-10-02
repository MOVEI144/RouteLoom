#ifndef ROUTELOOM_DEVICE_H
#define ROUTELOOM_DEVICE_H

#include <stddef.h>
#include <stdint.h>

#include "routeloom/routeloom.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Device C API 1 (docs/spec/sdk-api.md §3, compatibility.md §4): the C form
   of routeloom::Device (device.hpp). It holds no mesh state of its own;
   every call delegates to the one Device of the image.

   Threads: rl_dev_post() is the only call another task may make. Every
   other call belongs to the Owner task (the observer's on_poll or a posted
   job). A call made from inside an rl_dev_observer_t callback returns
   RL_STATUS_BUSY and changes nothing, except rl_dev_post (allowed) and
   rl_dev_node_id (a read-only identity).

   Structs: every struct starts with {struct_size, version}. version must be
   RL_DEV_API_VERSION and struct_size at least the required prefix, otherwise
   the call returns RL_STATUS_INVALID_ARGUMENT. The prefix is sizeof the
   struct except for API 1's additive tails: capabilities before
   object_transfer, observer before on_object, and join_policy before
   smart_join (offsetof each field). Only supplied tail fields are read or
   written; a larger struct_size is accepted and its excess tail ignored.
   1.x grows by appending tail
   fields and functions only; layouts are pinned by
   protocol/abi-golden/device-api1.json (ILP32 and LP64).
   rl_dev_struct_init() zeroes a struct and fills its header. Shared value
   types (rl_message_id_t, rl_delivery_result_t, rl_applied_*_t,
   rl_group_send_options_t) are the core ABI 3 ones and carry
   RL_ABI_VERSION. */
#define RL_DEV_API_VERSION 1u

typedef struct rl_dev rl_dev_t;

/* profile::Role */
typedef enum rl_dev_role {
  RL_DEV_ROLE_ENDPOINT = 1,
  RL_DEV_ROLE_RELAY = 2,
  RL_DEV_ROLE_GATEWAY = 3
} rl_dev_role_t;

/* SecurityProfile: DevRam is Development, MemberEdhoc is Candidate until
   its certification record exists. */
typedef enum rl_dev_security_profile {
  RL_DEV_SECURITY_DEVELOPMENT = 0,
  RL_DEV_SECURITY_PRODUCTION = 1,
  RL_DEV_SECURITY_CANDIDATE = 2
} rl_dev_security_profile_t;

/* MembershipStage */
typedef enum rl_dev_stage {
  RL_DEV_STAGE_UNPROVISIONED = 0,
  RL_DEV_STAGE_JOINING = 1,
  RL_DEV_STAGE_PENDING_AUTHORITY = 2,
  RL_DEV_STAGE_MEMBER = 3,
  RL_DEV_STAGE_REMOVED = 4,
  RL_DEV_STAGE_RECOVERY = 5,
  RL_DEV_STAGE_LEAVING = 6
} rl_dev_stage_t;

/* Connectivity toward the site's gateways (authenticated evidence only). */
typedef enum rl_dev_connectivity_state {
  RL_DEV_CONNECTIVITY_UNKNOWN = 0,
  RL_DEV_CONNECTIVITY_REACHABLE = 1,
  RL_DEV_CONNECTIVITY_DEGRADED = 2,
  RL_DEV_CONNECTIVITY_ISOLATED = 3,
  RL_DEV_CONNECTIVITY_SLEEPING = 4
} rl_dev_connectivity_state_t;

typedef struct rl_dev_capabilities {
  uint32_t struct_size;
  uint32_t version;
  uint8_t role;             /* rl_dev_role_t */
  uint8_t member;           /* nonzero: MemberEdhoc (zero: DevRam) */
  uint8_t security_profile; /* rl_dev_security_profile_t */
  uint8_t usb_gateway;      /* USB bridge attached */
  uint8_t scoped_routing;   /* gateway-scoped route profile in force */
  uint8_t group_send;       /* rl_dev_send_group admissible now */
  uint16_t max_payload;
  uint16_t max_group_payload;
  uint16_t max_applied_payload;
  uint8_t object_transfer;
  uint8_t object_rx_slots;
  uint16_t max_object_bytes;
} rl_dev_capabilities_t;

typedef struct rl_dev_membership {
  uint32_t struct_size;
  uint32_t version;
  uint8_t stage;       /* rl_dev_stage_t */
  uint8_t role;        /* granted member role bits */
  uint16_t reason;     /* reason id of the last stage change */
  uint32_t generation; /* assignment generation */
  uint64_t site_id;
  rl_network_id_t network; /* full 64-bit network */
  rl_node_id_t node;
  rl_monotonic_ms_t since_ms; /* this boot's monotonic clock only */
  uint32_t boot;              /* boot incarnation */
  uint32_t operation;         /* request_join/leave in progress, 0 none */
} rl_dev_membership_t;

typedef struct rl_dev_connectivity {
  uint32_t struct_size;
  uint32_t version;
  uint8_t state;         /* rl_dev_connectivity_state_t */
  uint8_t scope;         /* 0: site gateways */
  uint8_t contact_valid; /* last_contact_ms holds verified gateway evidence */
  uint8_t reserved;
  uint16_t reason;
  uint16_t reserved2;
  uint32_t boot;
  rl_monotonic_ms_t since_ms;
  rl_monotonic_ms_t last_contact_ms;
} rl_dev_connectivity_t;

/* rl_send_options_t plus the latest-value key. */
typedef struct rl_dev_send_options {
  uint32_t struct_size;
  uint32_t version;
  rl_delivery_class_t delivery;
  rl_priority_t priority;
  uint32_t lifetime_ms; /* 1..30000 */
  uint8_t hop_limit;
  uint8_t ordered;      /* RELIABLE only: per-destination order */
  /* BEST_EFFORT only (0 = none): replaces an untransmitted send to the same
     destination with the same key, which ends CANCELLED_SUPERSEDED. */
  uint16_t coalesce_key;
} rl_dev_send_options_t;

/* JoinPolicy (sdk-api.md §3): range-checked, stored in RLJP1. */
typedef struct rl_dev_join_policy {
  uint32_t struct_size;
  uint32_t version;
  uint32_t avoid_not_here_s;   /* 300..86400 */
  uint32_t avoid_blocked_s;    /* 3600..604800 */
  uint32_t removal_holdoff_s;  /* 60..3600 */
  uint32_t retry_max_s;        /* 60..3600 */
  uint32_t isolation_notice_s; /* 0 off, 300..2592000 */
  uint16_t start_jitter_ms;    /* 0..60000 */
  uint8_t role;                /* requested role bits, 0 = image default */
  uint8_t reserved;
  uint8_t smart_join;          /* 0 legacy, 1 listen/probe/finite search */
  uint8_t boot_join;           /* 0 API only, 1 boot trigger */
  uint8_t same_site_only;
  uint8_t reserved2;
  uint32_t listen_ms;          /* 0..60000 */
  uint32_t search_ms;          /* 1000..600000 */
} rl_dev_join_policy_t;

typedef struct rl_dev_object_options {
  uint32_t struct_size;
  uint32_t version;
  uint32_t deadline_ms;
  uint16_t app_tag;
  uint8_t content_encoding;
  uint8_t reserved;
} rl_dev_object_options_t;

/* ObjectState: 1 Delivered (digest and whole-object callback acknowledged),
   2 Expired, 3 CancelledBeforeTx, 4 Indeterminate, 5 Failed, 6 Unsupported.
   This is distinct from a normal message's END_RECEIVED and from APPLIED. */
typedef struct rl_dev_object_result {
  uint32_t struct_size;
  uint32_t version;
  uint32_t object_id;
  uint16_t reason; /* rl_status_code_t */
  uint8_t state;
  uint8_t reserved;
} rl_dev_object_result_t;

typedef struct rl_dev_object_rx {
  uint32_t struct_size;
  uint32_t version;
  rl_node_id_t source;
  uint32_t object_id;
  uint32_t source_boot;
  uint32_t end_context;
  uint16_t app_tag;
  uint8_t content_encoding;
  uint8_t reserved;
} rl_dev_object_rx_t;

/* Callbacks run on the Owner task; arguments are borrowed for the call.
   Any function may be NULL. on_applied_request receives every APPLIED
   request as a ticket that the application answers later — outside the
   callback — with rl_dev_complete_applied (at most four open at once); a
   NULL on_applied_request refuses APPLIED requests with NoEndpoint.
   Received group messages reach on_message with RL_GROUP_SEQUENCE_FLAG set
   in id.sequence. on_poll runs once per Owner pass, outside any callback:
   Device calls are allowed there. */
typedef struct rl_dev_observer {
  uint32_t struct_size;
  uint32_t version;
  void* user;
  void (*on_message)(void* user, rl_node_id_t origin, rl_message_id_t id,
                     const uint8_t* payload, size_t payload_size);
  void (*on_delivery)(void* user, const rl_delivery_result_t* result);
  /* Each stage change once; cause is a reason id (JOINED, LEFT, ...). */
  void (*on_membership)(void* user, const rl_dev_membership_t* snapshot, uint16_t cause);
  void (*on_connectivity)(void* user, const rl_dev_connectivity_t* snapshot);
  /* A request_join or leave ended: JOINED, JOIN_DENIED, JOIN_PENDING,
     JOIN_TIMEOUT, LEFT or RECOVERY_REQUIRED (reason ids). */
  void (*on_operation)(void* user, uint32_t operation, uint16_t result);
  void (*on_applied_request)(void* user, const rl_applied_request_t* request);
  void (*on_poll)(void* user, rl_dev_t* device, rl_monotonic_ms_t now_ms);
  void (*on_object)(void* user, const rl_dev_object_rx_t* info,
                    const uint8_t* data, size_t size);
  void (*on_object_result)(void* user, const rl_dev_object_result_t* result);
} rl_dev_observer_t;

void rl_dev_struct_init(void* object, size_t struct_size);
/* rl_dev_struct_init plus the Device defaults (RELIABLE, Normal, 5 s). */
void rl_dev_send_options_init(rl_dev_send_options_t* options);

#if defined(ESP_PLATFORM)
/* Boots the image's Device from the component Kconfig on its own Owner
   task (device_config_from_kconfig) and returns its handle. `observer`
   (may be NULL) is copied. Call once; boot failures take the Device's
   fail-streak restart path. Returns NULL for an invalid observer header
   or if the C handle is already bound; no task starts on rejection. */
rl_dev_t* rl_dev_start(const rl_dev_observer_t* observer);
#endif

/* The only call another task may make: `job` runs on the Owner task at its
   next pass. RL_STATUS_BUSY when eight jobs are waiting. */
typedef void (*rl_dev_job_t)(rl_dev_t* device, void* ctx);
rl_status_code_t rl_dev_post(rl_dev_t* device, rl_dev_job_t job, void* ctx);

/* 0 before the node starts. */
rl_node_id_t rl_dev_node_id(rl_dev_t* device);
rl_status_code_t rl_dev_capabilities(rl_dev_t* device, rl_dev_capabilities_t* out);

/* Accepted only: the result arrives through on_delivery and
   rl_dev_delivery. APPLIED goes through rl_dev_send_applied. */
rl_status_code_t rl_dev_send(rl_dev_t* device, rl_node_id_t destination,
                             const uint8_t* payload, size_t payload_size,
                             const rl_dev_send_options_t* options, rl_message_id_t* out_id);
/* Immutable send loan until on_object_result. RX loan is 4096 bytes and
   outlives the Device; callbacks borrow it only for their duration. OFF
   returns Unsupported. One TX object and at most object_rx_slots RX loans. */
void rl_dev_object_options_init(rl_dev_object_options_t* options);
rl_status_code_t rl_dev_send_object(rl_dev_t* device, rl_node_id_t destination,
                                    const uint8_t* data, size_t size,
                                    const rl_dev_object_options_t* options, uint32_t* out_id);
rl_status_code_t rl_dev_cancel_object(rl_dev_t* device, uint32_t object_id);
rl_status_code_t rl_dev_register_object_buffer(rl_dev_t* device, uint8_t* storage, size_t size);
rl_status_code_t rl_dev_send_group(rl_dev_t* device, uint16_t group, const uint8_t* payload,
                                   size_t payload_size, const rl_group_send_options_t* options,
                                   rl_message_id_t* out_id);
rl_status_code_t rl_dev_cancel(rl_dev_t* device, rl_message_id_t id);
rl_status_code_t rl_dev_delivery(rl_dev_t* device, rl_message_id_t id,
                                 rl_delivery_result_t* out);

/* APPLIED: `lease` is the destination's current lease (its
   rl_dev_applied_lease, or the data of a STALE_LEASE result). */
rl_status_code_t rl_dev_applied_lease(rl_dev_t* device,
                                      uint8_t out_lease[RL_APPLIED_LEASE_SIZE]);
rl_status_code_t rl_dev_send_applied(rl_dev_t* device, rl_node_id_t destination,
                                     const uint8_t lease[RL_APPLIED_LEASE_SIZE],
                                     const uint8_t* payload, size_t payload_size,
                                     const rl_dev_send_options_t* options,
                                     rl_message_id_t* out_id);
/* A completion after the request deadline (RL_STATUS_EXPIRED), a second
   one, or one for a revoked, left or previous-boot ticket
   (RL_STATUS_NOT_FOUND) is never applied. */
rl_status_code_t rl_dev_complete_applied(rl_dev_t* device, uint64_t ticket,
                                         const rl_applied_result_t* result);
/* RL_STATUS_NOT_FOUND until a verified RESULT is stored for `id`. */
rl_status_code_t rl_dev_applied_result(rl_dev_t* device, rl_message_id_t id,
                                       rl_applied_result_t* out);

rl_status_code_t rl_dev_membership(rl_dev_t* device, rl_dev_membership_t* out);
rl_status_code_t rl_dev_connectivity(rl_dev_t* device, rl_dev_connectivity_t* out);
/* Unassigned: the zero-touch scan starts now. Member: re-verifies the
   membership with the site. Ends with on_operation. */
/* Private opaque mark for ProxyPolicySet, never a permission. */
rl_status_code_t rl_dev_join_mark(rl_dev_t* device, uint8_t out[16]);
rl_status_code_t rl_dev_request_join(rl_dev_t* device, uint32_t* out_operation);
/* Leaves the site: the intent is durable before anything is erased; the
   device then restarts unassigned (on_operation(LEFT) first). */
rl_status_code_t rl_dev_leave(rl_dev_t* device, uint32_t* out_operation);
/* Compare-and-set: RL_STATUS_CONFLICT unless `expected_revision` is the
   stored revision (0 before any). */
rl_status_code_t rl_dev_set_join_policy(rl_dev_t* device, const rl_dev_join_policy_t* policy,
                                        uint32_t expected_revision, uint32_t* out_revision);
rl_status_code_t rl_dev_join_policy(rl_dev_t* device, rl_dev_join_policy_t* out,
                                    uint32_t* out_revision);

#ifdef __cplusplus
}
#endif

#endif
