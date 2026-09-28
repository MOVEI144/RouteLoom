/* C-only consumer of the core C ABI 3 (routeloom.h): built as C11 against
   the public include directory alone. Two contexts talk over an in-memory
   radio: header/size/version boundaries, capabilities, RELIABLE send and
   receive, and APPLIED through the stale-lease retry, the asynchronous
   ticket (completed 2 s later, 20 times), the expired and previous-boot
   tickets and a completion from inside the callback. */
#include <stdalign.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "routeloom/routeloom.h"
#include "routeloom/version.h"

_Static_assert(ROUTELOOM_CORE_C_ABI == RL_ABI_VERSION, "protocol/manifest.json core_c_abi");

static int failures = 0;
#define CHECK(expr)                                                     \
  do {                                                                  \
    if (!(expr)) {                                                      \
      fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__, #expr); \
      ++failures;                                                       \
    }                                                                   \
  } while (0)

enum { kNodes = 2, kQueue = 64, kSlots = 16, kStorage = 1 << 20 };
static const rl_network_id_t kNetwork = 7;

typedef struct Frame {
  rl_node_id_t from;
  rl_node_id_t to;
  uint64_t token;
  size_t size;
  uint8_t bytes[RL_MAX_ESPNOW_BODY];
} Frame;

typedef struct Slot {
  int used;
  uint32_t serial;
  rl_node_id_t peer;
  rl_monotonic_ms_t deadline;
} Slot;

typedef struct Node {
  rl_node_id_t id;
  rl_context_t* context;
  alignas(16) uint8_t storage[kStorage];
  Slot slots[kSlots];
  uint32_t serial;
  uint64_t counter;
  /* Observations. */
  int messages;
  uint8_t last_message[RL_MAX_APPLICATION_PAYLOAD];
  size_t last_message_size;
  int requests;
  uint64_t ticket;
  uint8_t request_payload[RL_APPLIED_PAYLOAD_MAX];
  size_t request_payload_size;
  int complete_in_callback;
  rl_status_code_t callback_complete_status;
  rl_message_id_t watched;
  int watched_delivered;
  int watched_terminal;
  rl_delivery_result_t last_watched;
} Node;

static Node nodes[kNodes];
static Frame queue[kQueue];
static size_t queued = 0;
static rl_monotonic_ms_t now = 0;

static Node* node_by_id(rl_node_id_t id) {
  for (size_t i = 0; i < kNodes; ++i) {
    if (nodes[i].id == id) return &nodes[i];
  }
  return NULL;
}

static rl_status_code_t enqueue(rl_node_id_t from, rl_node_id_t to, uint64_t token,
                                const uint8_t* frame, size_t size) {
  if (queued == kQueue || size > RL_MAX_ESPNOW_BODY) return RL_STATUS_WOULD_BLOCK;
  Frame* out = &queue[queued++];
  out->from = from;
  out->to = to;
  out->token = token;
  out->size = size;
  memcpy(out->bytes, frame, size);
  return RL_STATUS_OK;
}

/* ---- radio -------------------------------------------------------------- */
static rl_status_code_t radio_send(void* user, rl_node_id_t peer, uint64_t token,
                                   const uint8_t* frame, size_t size) {
  return enqueue(((Node*)user)->id, peer, token, frame, size);
}
static rl_status_code_t radio_recover(void* user) {
  (void)user;
  return RL_STATUS_OK;
}

/* ---- static-key test security: identity cipher, fixed tag ---------------- */
static bool security_ready(void* user) {
  (void)user;
  return true;
}
static rl_status_code_t security_next_counter(void* user, const rl_security_context_t* context,
                                              uint64_t* counter) {
  if (context->struct_size < sizeof(*context) || context->version != RL_ABI_VERSION) {
    return RL_STATUS_INVALID_ARGUMENT;
  }
  *counter = ((Node*)user)->counter++;
  return RL_STATUS_OK;
}
static rl_status_code_t security_seal(void* user, const rl_security_context_t* context,
                                      uint64_t counter, const uint8_t* aad, size_t aad_size,
                                      const uint8_t* plaintext, size_t plaintext_size,
                                      uint8_t* ciphertext, size_t capacity,
                                      uint8_t tag[RL_AEAD_TAG_SIZE]) {
  (void)user, (void)context, (void)counter, (void)aad, (void)aad_size;
  if (capacity < plaintext_size) return RL_STATUS_NO_CAPACITY;
  if (plaintext_size != 0) memcpy(ciphertext, plaintext, plaintext_size);
  memset(tag, 0x5a, RL_AEAD_TAG_SIZE);
  return RL_STATUS_OK;
}
static rl_status_code_t security_open(void* user, const rl_security_context_t* context,
                                      uint64_t counter, const uint8_t* aad, size_t aad_size,
                                      const uint8_t* ciphertext, size_t ciphertext_size,
                                      const uint8_t tag[RL_AEAD_TAG_SIZE], uint8_t* plaintext,
                                      size_t capacity) {
  (void)user, (void)context, (void)counter, (void)aad, (void)aad_size;
  if (capacity < ciphertext_size) return RL_STATUS_NO_CAPACITY;
  for (size_t i = 0; i < RL_AEAD_TAG_SIZE; ++i) {
    if (tag[i] != 0x5a) return RL_STATUS_AUTHENTICATION_FAILED;
  }
  if (ciphertext_size != 0) memcpy(plaintext, ciphertext, ciphertext_size);
  return RL_STATUS_OK;
}

/* ---- observer ----------------------------------------------------------- */
static void on_message(void* user, rl_node_id_t origin, rl_message_id_t id,
                       const uint8_t* payload, size_t size) {
  Node* node = (Node*)user;
  (void)origin, (void)id;
  ++node->messages;
  node->last_message_size = size;
  memcpy(node->last_message, payload, size);
}
static int same_id(rl_message_id_t a, rl_message_id_t b) {
  return a.session == b.session && a.sequence == b.sequence;
}
static void on_delivery(void* user, const rl_delivery_result_t* result) {
  Node* node = (Node*)user;
  if (result->struct_size != sizeof(*result) || result->version != RL_ABI_VERSION) {
    ++failures;
    return;
  }
  if (!same_id(result->id, node->watched)) return;
  node->last_watched = *result;
  if (result->state == RL_DELIVERY_STATE_DELIVERED) ++node->watched_delivered;
  if (result->state >= RL_DELIVERY_STATE_DELIVERED) ++node->watched_terminal;
}
static void on_applied_request(void* user, const rl_applied_request_t* request) {
  Node* node = (Node*)user;
  ++node->requests;
  node->ticket = request->ticket;
  node->request_payload_size = request->payload_size;
  memcpy(node->request_payload, request->payload, request->payload_size);
  if (node->complete_in_callback) {
    rl_applied_result_t result;
    rl_struct_init(&result, sizeof(result));
    node->callback_complete_status =
        rl_complete_applied(node->context, request->ticket, &result, now);
  }
}

/* ---- reply-peer port: one static binding per peer (id = peer id) --------- */
static rl_status_code_t reply_acquire(void* user, rl_node_id_t peer, uint32_t binding_id,
                                      uint32_t generation, uint32_t rx_context,
                                      rl_monotonic_ms_t deadline, rl_monotonic_ms_t at,
                                      uint32_t* out_slot, uint32_t* out_serial) {
  Node* node = (Node*)user;
  (void)at;
  if (binding_id != (uint32_t)peer || generation != 1 || rx_context == 0) {
    return RL_STATUS_CONFLICT;
  }
  for (uint32_t i = 0; i < kSlots; ++i) {
    if (node->slots[i].used) continue;
    node->slots[i].used = 1;
    node->slots[i].serial = ++node->serial;
    node->slots[i].peer = peer;
    node->slots[i].deadline = deadline;
    *out_slot = i;
    *out_serial = node->slots[i].serial;
    return RL_STATUS_OK;
  }
  return RL_STATUS_NO_CAPACITY;
}
static Slot* live_slot(Node* node, uint32_t slot, uint32_t serial) {
  if (slot >= kSlots || !node->slots[slot].used || node->slots[slot].serial != serial) {
    return NULL;
  }
  return &node->slots[slot];
}
static rl_status_code_t reply_release(void* user, uint32_t slot, uint32_t serial) {
  Slot* live = live_slot((Node*)user, slot, serial);
  if (live == NULL) return RL_STATUS_NOT_FOUND;
  live->used = 0;
  return RL_STATUS_OK;
}
static rl_status_code_t reply_validate(void* user, uint32_t slot, uint32_t serial,
                                       rl_monotonic_ms_t at) {
  Slot* live = live_slot((Node*)user, slot, serial);
  if (live == NULL) return RL_STATUS_NOT_FOUND;
  return at >= live->deadline ? RL_STATUS_EXPIRED : RL_STATUS_OK;
}
static rl_status_code_t reply_send(void* user, uint32_t slot, uint32_t serial, uint64_t token,
                                   const uint8_t* frame, size_t size, rl_monotonic_ms_t at) {
  Node* node = (Node*)user;
  Slot* live = live_slot(node, slot, serial);
  if (live == NULL) return RL_STATUS_NOT_FOUND;
  if (at >= live->deadline) return RL_STATUS_EXPIRED;
  return enqueue(node->id, live->peer, token, frame, size);
}
static rl_status_code_t reply_snapshot(void* user, rl_node_id_t peer, uint32_t* out_id,
                                       uint32_t* out_generation, uint32_t* out_context) {
  (void)user;
  *out_id = (uint32_t)peer;
  *out_generation = 1;
  *out_context = 1;
  return RL_STATUS_OK;
}
static rl_status_code_t reply_send_bound(void* user, rl_node_id_t peer, uint32_t binding_id,
                                         uint32_t generation, uint32_t rx_context,
                                         uint64_t token, const uint8_t* frame, size_t size) {
  (void)rx_context;
  if (binding_id != (uint32_t)peer || generation != 1) return RL_STATUS_CONFLICT;
  return enqueue(((Node*)user)->id, peer, token, frame, size);
}

/* ---- world -------------------------------------------------------------- */
static void fill_vtables(Node* node, rl_radio_vtable_t* radio, rl_security_vtable_t* security,
                         rl_observer_vtable_t* observer) {
  rl_struct_init(radio, sizeof(*radio));
  radio->user = node;
  radio->send = radio_send;
  radio->recover = radio_recover;
  rl_struct_init(security, sizeof(*security));
  security->user = node;
  security->ready = security_ready;
  security->next_counter = security_next_counter;
  security->seal = security_seal;
  security->open = security_open;
  rl_struct_init(observer, sizeof(*observer));
  observer->user = node;
  observer->on_message = on_message;
  observer->on_delivery = on_delivery;
  observer->on_applied_request = on_applied_request;
}

static void base_config(rl_node_config_t* config, rl_node_id_t id, uint32_t session) {
  rl_node_config_init(config);
  config->network = kNetwork;
  config->node = id;
  config->message_session = session;
  config->route_generation = session;  /* grows with every restart here */
  config->route_advertisement_period_ms = 100;
}

static rl_status_code_t start_node(Node* node, rl_node_id_t id, uint32_t session) {
  rl_node_config_t config;
  rl_radio_vtable_t radio;
  rl_security_vtable_t security;
  rl_observer_vtable_t observer;
  rl_reply_peer_vtable_t reply;
  rl_status_code_t status;
  memset(node, 0, sizeof(*node));
  node->id = id;
  base_config(&config, id, session);
  fill_vtables(node, &radio, &security, &observer);
  status = rl_init(node->storage, sizeof(node->storage), &config, &radio, &security, &observer,
                   &node->context);
  if (status != RL_STATUS_OK) return status;
  rl_struct_init(&reply, sizeof(reply));
  reply.user = node;
  reply.acquire = reply_acquire;
  reply.release = reply_release;
  reply.validate = reply_validate;
  reply.send_reply = reply_send;
  reply.snapshot_binding = reply_snapshot;
  reply.send_bound = reply_send_bound;
  status = rl_attach_reply_peer(node->context, &reply);
  if (status != RL_STATUS_OK) return status;
  return rl_start(node->context, now);
}

/* One owner pass per node, then deliver every queued frame (TX result to the
   sender, RX with the receiver's binding) and poll again, boundedly. */
static void step(void) {
  now += 5;
  for (size_t i = 0; i < kNodes; ++i) rl_poll(nodes[i].context, now);
  for (int round = 0; round < 32 && queued != 0; ++round) {
    Frame batch[kQueue];
    const size_t count = queued;
    memcpy(batch, queue, count * sizeof(Frame));
    queued = 0;
    for (size_t i = 0; i < count; ++i) {
      Node* from = node_by_id(batch[i].from);
      rl_on_radio_tx_result(from->context, batch[i].token, true, now);
      for (size_t j = 0; j < kNodes; ++j) {
        Node* to = &nodes[j];
        if (to == from || (batch[i].to != to->id && batch[i].to != UINT64_MAX)) continue;
        rl_on_radio_receive_with_binding(to->context, from->id, batch[i].bytes, batch[i].size,
                                         -40, (uint32_t)from->id, 1, now);
      }
    }
    for (size_t i = 0; i < kNodes; ++i) rl_poll(nodes[i].context, now);
  }
}

static void run(rl_monotonic_ms_t duration) {
  const rl_monotonic_ms_t end = now + duration;
  while (now < end) step();
}

static int run_until_terminal(Node* origin, rl_monotonic_ms_t budget) {
  const rl_monotonic_ms_t end = now + budget;
  while (origin->watched_terminal == 0 && now < end) step();
  return origin->watched_terminal != 0;
}

/* ---- scenarios ---------------------------------------------------------- */
static void check_boundaries(void) {
  uint32_t major = 0;
  uint32_t minor = 99;
  rl_abi_version(&major, &minor);
  CHECK(major == RL_ABI_VERSION && minor == RL_ABI_VERSION_MINOR);

  Node* node = &nodes[0];
  rl_node_config_t config;
  rl_radio_vtable_t radio;
  rl_security_vtable_t security;
  rl_observer_vtable_t observer;
  base_config(&config, 1, 11);
  fill_vtables(node, &radio, &security, &observer);
  CHECK(config.struct_size == sizeof(config) && config.version == RL_ABI_VERSION);
  CHECK(rl_context_size() <= kStorage && rl_context_alignment() <= 16);

  /* A short struct_size or an unknown version is refused on every input. */
  config.struct_size -= 1;
  CHECK(rl_init(node->storage, kStorage, &config, &radio, &security, &observer,
                &node->context) == RL_STATUS_INVALID_ARGUMENT);
  config.struct_size += 1;
  config.version = 2;
  CHECK(rl_init(node->storage, kStorage, &config, &radio, &security, &observer,
                &node->context) == RL_STATUS_INVALID_ARGUMENT);
  config.version = RL_ABI_VERSION;
  radio.struct_size = sizeof(radio) - sizeof(void*);
  CHECK(rl_init(node->storage, kStorage, &config, &radio, &security, &observer,
                &node->context) == RL_STATUS_INVALID_ARGUMENT);
  radio.struct_size = sizeof(radio);
  security.version = RL_ABI_VERSION + 1;
  CHECK(rl_init(node->storage, kStorage, &config, &radio, &security, &observer,
                &node->context) == RL_STATUS_INVALID_ARGUMENT);
  security.version = RL_ABI_VERSION;
  observer.struct_size = 8;
  CHECK(rl_init(node->storage, kStorage, &config, &radio, &security, &observer,
                &node->context) == RL_STATUS_INVALID_ARGUMENT);
  observer.struct_size = sizeof(observer);

  /* A larger struct from a newer header is accepted; its tail is ignored. */
  {
    struct {
      rl_node_config_t config;
      uint64_t tail;
    } bigger;
    bigger.config = config;
    bigger.config.struct_size = sizeof(bigger);
    bigger.tail = UINT64_MAX;
    CHECK(rl_init(node->storage, kStorage, &bigger.config, &radio, &security, &observer,
                  &node->context) == RL_STATUS_OK);
    rl_deinit(node->context);
  }

  /* Library capabilities, and a short output struct. */
  {
    rl_capabilities_t caps;
    rl_struct_init(&caps, sizeof(caps));
    CHECK(rl_get_capabilities(NULL, &caps) == RL_STATUS_OK);
    CHECK(caps.struct_size == sizeof(caps) && caps.version == RL_ABI_VERSION);
    CHECK(caps.features == (RL_CAP_APPLIED | RL_CAP_ORDERED | RL_CAP_REPLY_PEER));
    CHECK(caps.max_payload == RL_MAX_APPLICATION_PAYLOAD &&
          caps.max_applied_payload == RL_APPLIED_PAYLOAD_MAX &&
          caps.max_group_payload == RL_GROUP_PAYLOAD_MAX &&
          caps.max_route_gateways == RL_MAX_ROUTE_GATEWAYS);
    caps.struct_size = sizeof(caps) - 1;
    CHECK(rl_get_capabilities(NULL, &caps) == RL_STATUS_INVALID_ARGUMENT);
  }
  CHECK(rl_next_deadline(NULL, 100) == 100 + RL_POLL_INTERVAL_MAX_MS);
  CHECK(rl_status_code_name(RL_STATUS_OK) != NULL);
}

static void check_reliable(Node* a, Node* b) {
  rl_send_options_t options;
  rl_message_id_t id;
  const uint8_t payload[] = {'h', 'i'};
  rl_send_options_init(&options);
  options.struct_size = sizeof(options) - 1;
  CHECK(rl_send(a->context, b->id, payload, sizeof(payload), &options, now, &id) ==
        RL_STATUS_INVALID_ARGUMENT);
  options.struct_size = sizeof(options);
  CHECK(rl_send(a->context, b->id, payload, sizeof(payload), &options, now, &id) ==
        RL_STATUS_OK);
  a->watched = id;
  CHECK(run_until_terminal(a, 2000));
  CHECK(a->watched_delivered == 1);
  CHECK(a->last_watched.reason_id == ROUTELOOM_REASON_END_RECEIVED);
  CHECK(strcmp(a->last_watched.reason, "END_RECEIVED") == 0);
  CHECK(b->messages == 1 && b->last_message_size == sizeof(payload) &&
        memcmp(b->last_message, payload, sizeof(payload)) == 0);
  {
    rl_delivery_result_t result;
    rl_struct_init(&result, sizeof(result));
    CHECK(rl_get_delivery(a->context, id, &result) == RL_STATUS_OK);
    CHECK(result.state == RL_DELIVERY_STATE_DELIVERED &&
          result.reason_id == ROUTELOOM_REASON_END_RECEIVED);
    result.version = 2;
    CHECK(rl_get_delivery(a->context, id, &result) == RL_STATUS_INVALID_ARGUMENT);
  }
}

static rl_message_id_t send_applied(Node* a, Node* b, const uint8_t lease[RL_APPLIED_LEASE_SIZE],
                                    uint8_t tag, uint32_t lifetime_ms) {
  rl_send_options_t options;
  rl_message_id_t id = {0, 0};
  rl_send_options_init(&options);
  options.delivery = RL_DELIVERY_APPLIED;
  options.lifetime_ms = lifetime_ms;
  CHECK(rl_send_applied(a->context, b->id, lease, &tag, 1, &options, now, &id) == RL_STATUS_OK);
  a->watched = id;
  a->watched_delivered = 0;
  a->watched_terminal = 0;
  return id;
}

static void check_applied(Node* a, Node* b, uint8_t lease[RL_APPLIED_LEASE_SIZE]) {
  rl_applied_result_t result;
  rl_message_id_t id;
  uint8_t expected[RL_APPLIED_LEASE_SIZE];

  /* No lease yet: the destination refuses without running the endpoint and
     returns its current lease. */
  memset(lease, 0, RL_APPLIED_LEASE_SIZE);
  id = send_applied(a, b, lease, 0, 5000);
  CHECK(run_until_terminal(a, 2000));
  CHECK(a->last_watched.state == RL_DELIVERY_STATE_FAILED &&
        a->last_watched.reason_id == ROUTELOOM_REASON_APP_REJECTED);
  rl_struct_init(&result, sizeof(result));
  CHECK(rl_get_applied_result(a->context, id, &result) == RL_STATUS_OK);
  CHECK(result.outcome == RL_APPLIED_FAILURE && result.code == RL_APPLIED_CODE_STALE_LEASE &&
        result.data_size == RL_APPLIED_LEASE_SIZE);
  CHECK(rl_applied_lease(b->context, expected) == RL_STATUS_OK);
  CHECK(memcmp(result.data, expected, RL_APPLIED_LEASE_SIZE) == 0);
  CHECK(b->requests == 0);
  memcpy(lease, result.data, RL_APPLIED_LEASE_SIZE);

  /* The asynchronous ticket, completed 2 s after the request, 20 times. */
  for (uint8_t round = 1; round <= 20; ++round) {
    const int before = b->requests;
    id = send_applied(a, b, lease, round, 5000);
    run(2000);
    CHECK(b->requests == before + 1 && b->request_payload_size == 1 &&
          b->request_payload[0] == round);
    /* No premature verdict: the origin still waits for the application. */
    CHECK(a->watched_terminal == 0);
    CHECK(a->last_watched.reason_id == ROUTELOOM_REASON_APP_RESULT_PENDING);
    rl_struct_init(&result, sizeof(result));
    CHECK(rl_get_applied_result(a->context, id, &result) == RL_STATUS_NOT_FOUND);

    rl_struct_init(&result, sizeof(result));
    result.outcome = RL_APPLIED_SUCCESS;
    result.code = round;
    result.data_size = 1;
    result.data[0] = (uint8_t)(round ^ 0xff);
    CHECK(rl_complete_applied(b->context, b->ticket, &result, now) == RL_STATUS_OK);
    CHECK(rl_complete_applied(b->context, b->ticket, &result, now) == RL_STATUS_NOT_FOUND);
    CHECK(run_until_terminal(a, 1000));
    run(500);
    CHECK(a->watched_delivered == 1 && a->watched_terminal == 1);
    CHECK(a->last_watched.reason_id == ROUTELOOM_REASON_APP_APPLIED);
    rl_struct_init(&result, sizeof(result));
    CHECK(rl_get_applied_result(a->context, id, &result) == RL_STATUS_OK);
    CHECK(result.outcome == RL_APPLIED_SUCCESS && result.code == round && !result.late &&
          result.data_size == 1 && result.data[0] == (uint8_t)(round ^ 0xff));
    /* The destination admits 8 held results per 60 s retention window. */
    run(6200);
  }

  /* Invalid verdicts are refused and leave the ticket open. */
  id = send_applied(a, b, lease, 0x55, 1000);
  run(200);
  rl_struct_init(&result, sizeof(result));
  result.data_size = RL_APPLIED_RESULT_DATA_MAX + 1;
  CHECK(rl_complete_applied(b->context, b->ticket, &result, now) == RL_STATUS_INVALID_ARGUMENT);
  result.data_size = 0;
  result.code = RL_APPLIED_SDK_CODE_BASE;
  CHECK(rl_complete_applied(b->context, b->ticket, &result, now) == RL_STATUS_INVALID_ARGUMENT);
  result.code = 0;
  result.struct_size = 12;
  CHECK(rl_complete_applied(b->context, b->ticket, &result, now) == RL_STATUS_INVALID_ARGUMENT);

  /* Past the request deadline the ticket is dead: nothing is applied. */
  CHECK(run_until_terminal(a, 2000));
  run(100);
  rl_struct_init(&result, sizeof(result));
  CHECK(rl_complete_applied(b->context, b->ticket, &result, now) == RL_STATUS_EXPIRED);
  run(500);
  CHECK(a->watched_delivered == 0);
  CHECK(a->last_watched.state == RL_DELIVERY_STATE_INDETERMINATE &&
        a->last_watched.reason_id == ROUTELOOM_REASON_APP_RESULT_TIMEOUT);
  CHECK(rl_get_applied_result(a->context, id, &result) == RL_STATUS_NOT_FOUND);

  /* Completing from inside the callback re-enters the node: refused. */
  b->complete_in_callback = 1;
  b->callback_complete_status = RL_STATUS_OK;
  (void)send_applied(a, b, lease, 0x66, 3000);
  run(200);
  CHECK(b->callback_complete_status == RL_STATUS_BUSY);
  b->complete_in_callback = 0;
}

static void check_previous_boot_ticket(Node* a, Node* b, uint8_t lease[RL_APPLIED_LEASE_SIZE]) {
  rl_applied_result_t result;
  uint64_t ticket;
  /* The destination restarts with a new message session (22 -> 23). */
  rl_deinit(b->context);
  CHECK(start_node(b, b->id, 23) == RL_STATUS_OK);
  CHECK(rl_add_neighbor(b->context, a->id, 1, now) == RL_STATUS_OK);
  run(300);
  CHECK(rl_applied_lease(b->context, lease) == RL_STATUS_OK);
  (void)send_applied(a, b, lease, 0x77, 3000);
  run(300);
  CHECK(b->requests == 1);
  ticket = b->ticket;
  CHECK((ticket >> 32) == 23);
  /* The same serial under the previous boot's session names nothing. */
  rl_struct_init(&result, sizeof(result));
  CHECK(rl_complete_applied(b->context, (22ull << 32) | (ticket & 0xffffffffu), &result, now) ==
        RL_STATUS_NOT_FOUND);
  CHECK(rl_complete_applied(b->context, 0, &result, now) == RL_STATUS_INVALID_ARGUMENT);
  CHECK(rl_complete_applied(b->context, ticket, &result, now) == RL_STATUS_OK);
  CHECK(run_until_terminal(a, 1000));
  CHECK(a->watched_delivered == 1);
}

int main(void) {
  static uint8_t lease[RL_APPLIED_LEASE_SIZE];
  Node* a = &nodes[0];
  Node* b = &nodes[1];
  check_boundaries();

  CHECK(start_node(a, 1, 11) == RL_STATUS_OK);
  CHECK(start_node(b, 2, 22) == RL_STATUS_OK);
  CHECK(rl_add_neighbor(a->context, b->id, 1, now) == RL_STATUS_OK);
  CHECK(rl_add_neighbor(b->context, a->id, 1, now) == RL_STATUS_OK);
  run(300);
  {
    rl_capabilities_t caps;
    rl_struct_init(&caps, sizeof(caps));
    CHECK(rl_get_capabilities(a->context, &caps) == RL_STATUS_OK);
    CHECK((caps.features & (RL_CAP_SCOPED_ROUTING | RL_CAP_GROUP_SEND)) == 0);
    CHECK(rl_next_deadline(a->context, now) == now + RL_POLL_INTERVAL_MAX_MS);
  }
  check_reliable(a, b);
  check_applied(a, b, lease);
  check_previous_boot_ticket(a, b, lease);
  rl_deinit(a->context);
  rl_deinit(b->context);
  if (failures != 0) {
    fprintf(stderr, "%d C ABI checks failed\n", failures);
    return 1;
  }
  puts("RouteLoom C ABI consumer tests passed");
  return 0;
}
