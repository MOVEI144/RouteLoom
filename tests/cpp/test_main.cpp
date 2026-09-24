#include <array>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <map>
#include <set>
#include <string>
#include <tuple>
#include <vector>

#ifndef _WIN32
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "routeloom/admission.hpp"
#include "routeloom/authority.hpp"
#include "routeloom/byte_io.hpp"
#include "routeloom/deadline.hpp"
#include "routeloom/routeloom.h"
#include "routeloom/counter_store.hpp"
#include "routeloom/node.hpp"
#include "routeloom/reply_peer_leases.hpp"
#include "routeloom/routing.hpp"
#include "routeloom/wire.hpp"

#include "test_autonomy.hpp"
#include "test_ledger.hpp"
#include "test_security.hpp"
#include "test_sim.hpp"

namespace {

int failures = 0;
#define CHECK(expr) do { if (!(expr)) { std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__, #expr); ++failures; } } while (false)
#define CHECK_OK(expr) do { const auto _status = (expr); if (!_status.ok()) { std::fprintf(stderr, "STATUS failed %s:%d: %s (%s)\n", __FILE__, __LINE__, #expr, _status.detail); ++failures; } } while (false)

using namespace routeloom;
using routeloom_test::TestSecurity;
using routeloom_test::CapturingObserver;
using routeloom_test::SimNetwork;
using routeloom_test::SimRadio;
using routeloom_test::SimReplyPort;
using routeloom_test::sim_rx_metadata;

class MemoryCounterStore final : public CounterStore {
 public:
  Status load(std::uint32_t slot, CounterRecord& record, bool& found) noexcept override {
    const auto it = records.find(slot);
    found = it != records.end();
    if (found) record = it->second;
    return Status::success();
  }
  Status commit(std::uint32_t slot, const CounterRecord& record) noexcept override {
    records[slot] = record;
    return Status::success();
  }
  std::map<std::uint32_t, CounterRecord> records;
};

void run_network(std::vector<MeshNode*>& nodes, SimNetwork& network,
                 MonotonicMs begin, MonotonicMs end, MonotonicMs step = 5) {
  for (MonotonicMs now = begin; now <= end; now += step) {
    for (auto* node : nodes) node->poll(now);
    network.flush(now);
  }
}


void test_admission_contract() {
  CHECK(frame_allowed(MembershipState::Unprovisioned, FrameType::Discover));
  CHECK(!frame_allowed(MembershipState::Unprovisioned, FrameType::Data));
  CHECK(frame_allowed(MembershipState::Authenticating, FrameType::BootstrapAuth));
  CHECK(!frame_allowed(MembershipState::Authenticating, FrameType::RouteUpdate));
  CHECK(frame_allowed(MembershipState::Member, FrameType::Data));
  CHECK(!frame_allowed(MembershipState::Revoked, FrameType::Data));
}

void test_deadline_resume() {
  std::uint32_t remaining = 0;
  CHECK_OK(resume_remaining_lifetime(DeadlinePolicy::WallElapsedValidity, 5000,
                                     ElapsedInterval{1000, 1200, true}, remaining));
  CHECK(remaining == 3800);
  CHECK(resume_remaining_lifetime(DeadlinePolicy::WallElapsedValidity, 5000,
                                  ElapsedInterval{0, 0, false}, remaining).code ==
        StatusCode::TimeUncertain);
  CHECK(resume_remaining_lifetime(DeadlinePolicy::WallElapsedValidity, 5000,
                                  ElapsedInterval{5000, 5001, true}, remaining).code ==
        StatusCode::Expired);
  CHECK_OK(resume_remaining_lifetime(DeadlinePolicy::RunningTimeOnly, 5000,
                                     ElapsedInterval{}, remaining));
  CHECK(remaining == 5000);
}

void test_single_authority() {
  routeloom_test::FaultyLedgerStorage store;
  SingleAuthority authority(1, 99, store);
  CHECK_OK(authority.initialize());
  AuthorityOperation op{};
  op.network = 1;
  op.authority = 99;
  op.generation = 1;
  op.sequence = 1;
  op.previous_state_hash = authority.state().state_hash;
  op.operation_hash[0] = 7;
  Digest256 result_hash{};
  result_hash[0] = 9;
  CHECK(authority.validate(op, false).code == StatusCode::AuthenticationFailed);
  CHECK_OK(authority.commit(op, result_hash, true));
  CHECK(authority.state().applied_sequence == 1);
  CHECK(authority.commit(op, result_hash, true).code == StatusCode::Conflict);

  SingleAuthority reboot(1, 99, store);
  CHECK_OK(reboot.initialize());
  CHECK(reboot.state().applied_sequence == 1);
  AuthorityOperation gap = op;
  gap.sequence = 3;
  gap.previous_state_hash = result_hash;
  CHECK(reboot.validate(gap, true).code == StatusCode::InvalidState);
}

struct CApiState {
  std::uint64_t counter{0};
};

// Minimal ExpectedReply Owner for the C ABI tests (issue #117): a stable
// per-peer binding directory over the portable lease table. Static
// single-context identity — the captured epoch is a membership check.
struct CApiReplyPort {
  ExpectedReplyLeases leases{};
  std::map<std::uint64_t, ReplyBinding> directory{};
  std::uint32_t next_id{1};
};

ReplyBinding capi_mapping(CApiReplyPort* port, std::uint64_t peer) {
  const auto it = port->directory.find(peer);
  if (it != port->directory.end()) return it->second;
  BindingId id{0};
  (void)mint_binding_id(port->next_id, id);
  const ReplyBinding fresh{static_cast<NodeId>(peer), id, BindingGeneration{1}, 1};
  port->directory[peer] = fresh;
  return fresh;
}

rl_status_code_t capi_reply_acquire(void* user, rl_node_id_t peer, uint32_t binding_id,
                                    uint32_t binding_generation, uint32_t rx_context_id,
                                    rl_monotonic_ms_t deadline_ms, rl_monotonic_ms_t now_ms,
                                    uint32_t* out_use_slot, uint32_t* out_use_serial) {
  auto* port = static_cast<CApiReplyPort*>(user);
  const ReplyBinding live = capi_mapping(port, peer);
  if (live.id.value != binding_id || live.generation.value != binding_generation ||
      rx_context_id == 0) {
    return RL_STATUS_CONFLICT;
  }
  ReplyLeaseToken token{};
  const Status status = port->leases.acquire(
      ReplyBinding{static_cast<NodeId>(peer), live.id, live.generation, 1},
      deadline_ms, now_ms, token);
  if (!status.ok()) return RL_STATUS_NO_CAPACITY;
  *out_use_slot = token.use_slot;
  *out_use_serial = token.serial;
  return RL_STATUS_OK;
}
rl_status_code_t capi_reply_release(void* user, uint32_t use_slot, uint32_t use_serial) {
  auto* port = static_cast<CApiReplyPort*>(user);
  return port->leases.release(ReplyLeaseToken{use_slot, use_serial}).ok()
             ? RL_STATUS_OK
             : RL_STATUS_NOT_FOUND;
}
rl_status_code_t capi_reply_validate(void* user, uint32_t use_slot, uint32_t use_serial,
                                     rl_monotonic_ms_t now_ms) {
  auto* port = static_cast<CApiReplyPort*>(user);
  const Status status =
      port->leases.validate(ReplyLeaseToken{use_slot, use_serial}, now_ms);
  if (status.ok()) return RL_STATUS_OK;
  if (status.code == StatusCode::Expired) return RL_STATUS_EXPIRED;
  if (status.code == StatusCode::Conflict) return RL_STATUS_CONFLICT;
  return RL_STATUS_NOT_FOUND;
}
rl_status_code_t capi_reply_send(void*, uint32_t, uint32_t, uint64_t, const uint8_t*,
                                 size_t, rl_monotonic_ms_t) {
  return RL_STATUS_OK;
}
rl_status_code_t capi_reply_snapshot(void* user, rl_node_id_t peer, uint32_t* out_id,
                                     uint32_t* out_gen, uint32_t* out_ctx) {
  if (peer == 0 || peer == kInvalidNodeId) return RL_STATUS_INVALID_ARGUMENT;
  const ReplyBinding live =
      capi_mapping(static_cast<CApiReplyPort*>(user), peer);
  *out_id = live.id.value;
  *out_gen = live.generation.value;
  *out_ctx = live.rx_context_id;
  return RL_STATUS_OK;
}
rl_status_code_t capi_reply_send_bound(void* user, rl_node_id_t peer, uint32_t id,
                                       uint32_t gen, uint32_t, uint64_t,
                                       const uint8_t*, size_t) {
  const ReplyBinding live =
      capi_mapping(static_cast<CApiReplyPort*>(user), peer);
  return (live.id.value == id && live.generation.value == gen)
             ? RL_STATUS_OK
             : RL_STATUS_CONFLICT;
}

void capi_attach_reply_port(rl_context_t* context, CApiReplyPort* port) {
  rl_reply_peer_vtable_t vtable{};
  rl_reply_peer_vtable_init(&vtable);
  vtable.user = port;
  vtable.acquire = &capi_reply_acquire;
  vtable.release = &capi_reply_release;
  vtable.validate = &capi_reply_validate;
  vtable.send_reply = &capi_reply_send;
  vtable.snapshot_binding = &capi_reply_snapshot;
  vtable.send_bound = &capi_reply_send_bound;
  CHECK(rl_attach_reply_peer(context, &vtable) == RL_STATUS_OK);
}

rl_status_code_t capi_radio_send(void*, rl_node_id_t, uint64_t, const uint8_t*, size_t) {
  return RL_STATUS_OK;
}
rl_status_code_t capi_radio_recover(void*) { return RL_STATUS_OK; }
bool capi_security_ready(void*) { return true; }
rl_status_code_t capi_next_counter(void* user, const rl_security_context_t*, uint64_t* counter) {
  *counter = static_cast<CApiState*>(user)->counter++;
  return RL_STATUS_OK;
}
rl_status_code_t capi_seal(void*, const rl_security_context_t*, uint64_t,
                           const uint8_t*, size_t, const uint8_t* plaintext,
                           size_t plaintext_size, uint8_t* ciphertext,
                           size_t ciphertext_capacity, uint8_t tag[RL_AEAD_TAG_SIZE]) {
  if (ciphertext_capacity < plaintext_size) return RL_STATUS_NO_CAPACITY;
  std::memcpy(ciphertext, plaintext, plaintext_size);
  std::memset(tag, 0x5a, RL_AEAD_TAG_SIZE);
  return RL_STATUS_OK;
}
rl_status_code_t capi_open(void*, const rl_security_context_t*, uint64_t,
                           const uint8_t*, size_t, const uint8_t* ciphertext,
                           size_t ciphertext_size, const uint8_t tag[RL_AEAD_TAG_SIZE],
                           uint8_t* plaintext, size_t plaintext_capacity) {
  if (plaintext_capacity < ciphertext_size) return RL_STATUS_NO_CAPACITY;
  for (size_t i = 0; i < RL_AEAD_TAG_SIZE; ++i) {
    if (tag[i] != 0x5a) return RL_STATUS_AUTHENTICATION_FAILED;
  }
  std::memcpy(plaintext, ciphertext, ciphertext_size);
  return RL_STATUS_OK;
}

void test_c_api_lifecycle() {
  rl_node_config_t config{};
  rl_node_config_init(&config);
  config.network = 1;
  config.node = 7;
  config.message_session = 77;
  CApiState state{};
  const rl_radio_vtable_t radio{nullptr, capi_radio_send, capi_radio_recover};
  const rl_security_vtable_t security{&state, capi_security_ready, capi_next_counter,
                                       capi_seal, capi_open};
  const rl_observer_vtable_t observer{};
  std::vector<std::max_align_t> storage(
      (rl_context_size() + sizeof(std::max_align_t) - 1) / sizeof(std::max_align_t));
  rl_context_t* context = nullptr;
  CHECK(rl_init(storage.data(), storage.size() * sizeof(std::max_align_t), &config,
                &radio, &security, &observer, &context) == RL_STATUS_OK);
  CHECK(context != nullptr);
  CApiReplyPort reply_port{};
  capi_attach_reply_port(context, &reply_port);
  CHECK(rl_start(context, 0) == RL_STATUS_OK);
  CHECK(rl_add_neighbor(context, 8, 1, 0) == RL_STATUS_OK);
  rl_send_options_t options{};
  rl_send_options_init(&options);
  rl_message_id_t id{};
  const uint8_t payload[] = {1, 2};
  CHECK(rl_send(context, 8, payload, sizeof(payload), &options, 1, &id) == RL_STATUS_OK);
  rl_poll(context, 1);
  rl_on_radio_tx_result(context, 1, true, 2);
  rl_deinit(context);
}

// Gateway-scoped routing profile over the C ABI (routeloom.h tail extension).
struct CApiNode {
  CApiState state{};
  rl_radio_vtable_t radio{nullptr, capi_radio_send, capi_radio_recover};
  rl_security_vtable_t security{&state, capi_security_ready, capi_next_counter,
                                capi_seal, capi_open};
  rl_observer_vtable_t observer{};
  std::vector<std::max_align_t> storage = std::vector<std::max_align_t>(
      (rl_context_size() + sizeof(std::max_align_t) - 1) / sizeof(std::max_align_t));
  rl_context_t* context{nullptr};
  CApiReplyPort reply_port{};

  rl_status_code_t init(const rl_node_config_t& config) {
    const rl_status_code_t status =
        rl_init(storage.data(), storage.size() * sizeof(std::max_align_t), &config,
                &radio, &security, &observer, &context);
    if (status != RL_STATUS_OK) return status;
    capi_attach_reply_port(context, &reply_port);
    return RL_STATUS_OK;
  }
  ~CApiNode() {
    if (context != nullptr) rl_deinit(context);
  }
};

rl_node_config_t capi_scoped_base() {
  rl_node_config_t config{};
  rl_node_config_init(&config);
  config.network = 1;
  config.node = 7;
  config.message_session = 77;
  return config;
}

// Group delivery over the C ABI (routeloom.h, group-delivery.md §8):
// additive symbols, RL_ABI_VERSION unchanged.
void test_c_api_group() {
  rl_group_send_options_t options{};
  rl_group_send_options_init(&options);
  CHECK(options.struct_size == sizeof(options) && options.abi_version == RL_ABI_VERSION);
  CHECK(options.priority == RL_PRIORITY_NORMAL && options.lifetime_ms == 5000 &&
        options.hop_limit == 10 && options.ordered == 0);
  rl_send_options_t send_options{};
  rl_send_options_init(&send_options);
  CHECK(send_options.ordered == 0);
  const uint8_t payload[] = {'A', 'L', 'A', 'R', 'M'};
  rl_message_id_t id{};
  // Flat profile: explicit UNSUPPORTED.
  {
    CApiNode node;
    CHECK(node.init(capi_scoped_base()) == RL_STATUS_OK);
    CHECK(rl_start(node.context, 0) == RL_STATUS_OK);
    CHECK(rl_send_group(node.context, RL_GROUP_ALL, payload, sizeof(payload), &options, 1,
                        &id) == RL_STATUS_UNSUPPORTED);
  }
  // The configured gateway sources a group message; a board may not.
  {
    rl_node_config_t config = capi_scoped_base();
    config.route_gateway_count = 1;
    config.route_gateways[0] = 7;  // this node
    config.route_advertisement_period_ms = kScopedProductPeriodMs;
    config.route_lifetime_ms = kScopedProductLifetimeMs;
    CApiNode node;
    CHECK(node.init(config) == RL_STATUS_OK);
    CHECK(rl_start(node.context, 0) == RL_STATUS_OK);
    options.priority = RL_PRIORITY_URGENT;
    CHECK(rl_send_group(node.context, RL_GROUP_ALL, payload, sizeof(payload), &options, 1,
                        &id) == RL_STATUS_OK);
    CHECK((id.sequence & RL_GROUP_SEQUENCE_FLAG) != 0 && id.session == 77);
    rl_group_result_t result{};
    CHECK(rl_get_group_result(node.context, id, &result) == RL_STATUS_OK);
    CHECK(result.group == RL_GROUP_ALL && result.id.sequence == id.sequence);
    // No neighbors: nothing to reach — an honest terminal verdict.
    rl_poll(node.context, 2);
    CHECK(rl_get_group_result(node.context, id, &result) == RL_STATUS_OK);
    CHECK(result.state == RL_DELIVERY_STATE_FAILED && result.delivered == 0);
    rl_message_id_t unknown{77, RL_GROUP_SEQUENCE_FLAG | 99};
    CHECK(rl_get_group_result(node.context, unknown, &result) == RL_STATUS_NOT_FOUND);
    // Argument checks.
    CHECK(rl_send_group(node.context, 0, payload, sizeof(payload), &options, 1, &id) ==
          RL_STATUS_INVALID_ARGUMENT);
    options.struct_size = 4;
    CHECK(rl_send_group(node.context, 1, payload, sizeof(payload), &options, 1, &id) ==
          RL_STATUS_INVALID_ARGUMENT);
    rl_group_send_options_init(&options);
    // Membership.
    const uint16_t groups[] = {3, 9};
    CHECK(rl_set_group_membership(node.context, groups, 2) == RL_STATUS_OK);
    const uint16_t reserved[] = {RL_GROUP_ALL};
    CHECK(rl_set_group_membership(node.context, reserved, 1) == RL_STATUS_INVALID_ARGUMENT);
    CHECK(rl_set_group_membership(node.context, nullptr, 1) == RL_STATUS_INVALID_ARGUMENT);
    CHECK(rl_set_group_membership(node.context, nullptr, 0) == RL_STATUS_OK);
  }
  {
    rl_node_config_t config = capi_scoped_base();
    config.route_gateway_count = 1;
    config.route_gateways[0] = 1;  // another node is the gateway
    config.route_advertisement_period_ms = kScopedProductPeriodMs;
    config.route_lifetime_ms = kScopedProductLifetimeMs;
    CApiNode node;
    CHECK(node.init(config) == RL_STATUS_OK);
    CHECK(rl_start(node.context, 0) == RL_STATUS_OK);
    CHECK(rl_send_group(node.context, RL_GROUP_ALL, payload, sizeof(payload), &options, 1,
                        &id) == RL_STATUS_UNSUPPORTED);
    // Ordered unicast must be RELIABLE.
    send_options.ordered = 1;
    send_options.delivery = RL_DELIVERY_BEST_EFFORT;
    CHECK(rl_add_neighbor(node.context, 1, 1, 0) == RL_STATUS_OK);
    CHECK(rl_send(node.context, 1, payload, sizeof(payload), &send_options, 1, &id) ==
          RL_STATUS_INVALID_ARGUMENT);
    send_options.delivery = RL_DELIVERY_RELIABLE;
    CHECK(rl_send(node.context, 1, payload, sizeof(payload), &send_options, 1, &id) ==
          RL_STATUS_OK);
  }
}

void test_c_api_route_profile() {
  // Defaults: the full struct, flat profile, SDK refresh cadence.
  {
    const rl_node_config_t config = capi_scoped_base();
    CHECK(config.struct_size == sizeof(rl_node_config_t));
    CHECK(config.route_gateway_count == 0);
    CHECK(config.route_refresh_ticks == kScopedDefaultRefreshTicks);
    CHECK(config.route_gateways[0] == 0 && config.route_gateways[1] == 0);
    CHECK(config.route_advertisement_period_ms == 5000);
    CHECK(config.route_lifetime_ms == 15000);
    CApiNode node;
    CHECK(node.init(config) == RL_STATUS_OK);
    CHECK(rl_route_gateways(node.context, nullptr, 0) == 0);
    CHECK(rl_start(node.context, 0) == RL_STATUS_OK);
  }
  // One gateway (this node lists itself) with the product timers.
  {
    rl_node_config_t config = capi_scoped_base();
    config.route_gateway_count = 1;
    config.route_gateways[0] = 7;
    config.route_gateways[1] = 0x55;  // beyond the count: ignored
    config.route_advertisement_period_ms = kScopedProductPeriodMs;
    config.route_lifetime_ms = kScopedProductLifetimeMs;
    CApiNode node;
    CHECK(node.init(config) == RL_STATUS_OK);
    std::array<rl_node_id_t, RL_MAX_ROUTE_GATEWAYS> out{};
    CHECK(rl_route_gateways(node.context, out.data(), out.size()) == 1);
    CHECK(out[0] == 7 && out[1] == 0);
    CHECK(rl_start(node.context, 0) == RL_STATUS_OK);
  }
  // Two gateways, preference order kept; a short buffer still reports the
  // configured count.
  {
    rl_node_config_t config = capi_scoped_base();
    config.route_gateway_count = 2;
    config.route_gateways[0] = 1;
    config.route_gateways[1] = 9;
    config.route_advertisement_period_ms = kScopedProductPeriodMs;
    config.route_lifetime_ms = kScopedProductLifetimeMs;
    CApiNode node;
    CHECK(node.init(config) == RL_STATUS_OK);
    std::array<rl_node_id_t, RL_MAX_ROUTE_GATEWAYS> out{};
    CHECK(rl_route_gateways(node.context, out.data(), out.size()) == 2);
    CHECK(out[0] == 1 && out[1] == 9);
    rl_node_id_t first = 0;
    CHECK(rl_route_gateways(node.context, &first, 1) == 2);
    CHECK(first == 1);
    CHECK(rl_start(node.context, 0) == RL_STATUS_OK);
    CHECK(rl_add_neighbor(node.context, 1, 1, 0) == RL_STATUS_OK);
    rl_poll(node.context, 10000);
  }
  // Shape errors are refused at rl_init: count over capacity, a zero id
  // inside the count, a duplicate id.
  {
    rl_node_config_t config = capi_scoped_base();
    config.route_gateway_count = RL_MAX_ROUTE_GATEWAYS + 1;
    config.route_gateways[0] = 1;
    config.route_gateways[1] = 2;
    CApiNode over;
    CHECK(over.init(config) == RL_STATUS_INVALID_ARGUMENT);
    CHECK(over.context == nullptr);
    config.route_gateway_count = 2;
    config.route_gateways[1] = 0;
    CApiNode zero;
    CHECK(zero.init(config) == RL_STATUS_INVALID_ARGUMENT);
    config.route_gateways[1] = 1;
    CApiNode duplicate;
    CHECK(duplicate.init(config) == RL_STATUS_INVALID_ARGUMENT);
  }
  // Lease rule (routing-scale.md §5) surfaces as rl_start's status: the flat
  // 5 s / 15 s defaults are below (2 * 6 + 2) * 5 s for a scoped node.
  {
    rl_node_config_t config = capi_scoped_base();
    config.route_gateway_count = 1;
    config.route_gateways[0] = 1;
    CApiNode node;
    CHECK(node.init(config) == RL_STATUS_OK);
    CHECK(rl_start(node.context, 0) == RL_STATUS_INVALID_ARGUMENT);
    // Just below / at the bound with the default cadence.
    config.route_lifetime_ms = 70000 - 1;
    CApiNode below;
    CHECK(below.init(config) == RL_STATUS_OK);
    CHECK(rl_start(below.context, 0) == RL_STATUS_INVALID_ARGUMENT);
    config.route_lifetime_ms = 70000;
    CApiNode at;
    CHECK(at.init(config) == RL_STATUS_OK);
    CHECK(rl_start(at.context, 0) == RL_STATUS_OK);
    // route_refresh_ticks reaches the core: 2 ticks need (2*2+2)*5 s = 30 s;
    // 0 means the SDK default (6), which 30 s does not satisfy.
    config.route_lifetime_ms = 30000;
    config.route_refresh_ticks = 2;
    CApiNode fast;
    CHECK(fast.init(config) == RL_STATUS_OK);
    CHECK(rl_start(fast.context, 0) == RL_STATUS_OK);
    config.route_refresh_ticks = 0;
    CApiNode defaulted;
    CHECK(defaulted.init(config) == RL_STATUS_OK);
    CHECK(rl_start(defaulted.context, 0) == RL_STATUS_INVALID_ARGUMENT);
    // Reserved ids are the core's to refuse, also at start.
    config.route_lifetime_ms = kScopedProductLifetimeMs;
    config.route_gateways[0] = UINT64_MAX;
    CApiNode broadcast;
    CHECK(broadcast.init(config) == RL_STATUS_OK);
    CHECK(rl_start(broadcast.context, 0) == RL_STATUS_INVALID_ARGUMENT);
  }
  // struct_size: the pre-extension size is still accepted and never reads
  // the tail (flat profile whatever those bytes hold); a size between the
  // two layouts is refused; a larger (future) size is accepted.
  {
    rl_node_config_t config = capi_scoped_base();
    config.route_gateway_count = 1;
    config.route_gateways[0] = 1;
    config.struct_size = RL_NODE_CONFIG_SIZE_BASE;
    CApiNode legacy;
    CHECK(legacy.init(config) == RL_STATUS_OK);
    CHECK(rl_route_gateways(legacy.context, nullptr, 0) == 0);
    CHECK(rl_start(legacy.context, 0) == RL_STATUS_OK);
    config.struct_size = RL_NODE_CONFIG_SIZE_BASE + 8;
    CApiNode partial;
    CHECK(partial.init(config) == RL_STATUS_INVALID_ARGUMENT);
    config.struct_size = RL_NODE_CONFIG_SIZE_BASE - 4;
    CApiNode truncated;
    CHECK(truncated.init(config) == RL_STATUS_INVALID_ARGUMENT);
    config.struct_size = sizeof(rl_node_config_t) + 8;
    CApiNode larger;
    CHECK(larger.init(config) == RL_STATUS_OK);
    CHECK(rl_route_gateways(larger.context, nullptr, 0) == 1);
    config.struct_size = sizeof(rl_node_config_t);
    config.abi_version = RL_ABI_VERSION + 1;
    CApiNode future_abi;
    CHECK(future_abi.init(config) == RL_STATUS_INVALID_ARGUMENT);
  }
  CHECK(rl_route_gateways(nullptr, nullptr, 0) == 0);
}

void test_byte_io() {
  std::array<std::uint8_t, 32> buffer{};
  ByteWriter writer(MutableByteView{buffer.data(), buffer.size()});
  CHECK_OK(writer.write_u8(7));
  CHECK_OK(writer.write_u16(0x1234));
  CHECK_OK(writer.write_u32(0x89abcdef));
  CHECK_OK(writer.write_u64(0x0123456789abcdefULL));
  ByteReader reader(ByteView{buffer.data(), writer.size()});
  std::uint8_t a = 0; std::uint16_t b = 0; std::uint32_t c = 0; std::uint64_t d = 0;
  CHECK_OK(reader.read_u8(a)); CHECK_OK(reader.read_u16(b)); CHECK_OK(reader.read_u32(c)); CHECK_OK(reader.read_u64(d));
  CHECK(a == 7 && b == 0x1234 && c == 0x89abcdef && d == 0x0123456789abcdefULL);
  CHECK(reader.remaining() == 0);
}

void test_counter_lease() {
  MemoryCounterStore store;
  CounterLease first(store, 1, 99, 1, 0, 4);
  CHECK_OK(first.initialize());
  std::uint64_t value = 0;
  CHECK_OK(first.next(value)); CHECK(value == 0);
  CHECK_OK(first.next(value)); CHECK(value == 1);
  CounterLease reboot(store, 1, 99, 1, 0, 4);
  CHECK_OK(reboot.initialize());
  CHECK_OK(reboot.next(value)); CHECK(value == 4);
}

void test_wire_forwarding() {
  TestSecurity a_security, b_security, c_security;
  wire::PlainFrame plain{};
  plain.header.type = FrameType::Data;
  plain.header.flags = wire::kFlagEndProtected;
  plain.header.delivery = DeliveryClass::Reliable;
  plain.header.hop_remaining = 4;
  plain.header.network = 1;
  plain.header.origin = 1;
  plain.header.destination = 3;
  plain.header.previous_hop = 1;
  plain.header.next_hop = 2;
  plain.header.message = MessageId{7, 9};
  plain.header.remaining_deadline_ms = 5000;
  plain.header.original_lifetime_ms = 5000;
  plain.header.link_epoch = 1;
  plain.header.end_epoch = 1;
  const char* text = "route-loom";
  plain.payload_size = std::strlen(text);
  std::memcpy(plain.payload.data(), text, plain.payload_size);

  wire::EncodedFrame first{};
  CHECK_OK(wire::encode_new(plain, a_security, first));
  CHECK(first.size <= kMaxEspNowBody);
  wire::LinkOpenedFrame at_b{};
  CHECK_OK(wire::open_link(first.view(), 2, b_security, at_b));
  wire::EncodedFrame second{};
  CHECK_OK(wire::forward(at_b, 2, 3, /*link_epoch=*/1, 4900, b_security, second));
  wire::LinkOpenedFrame at_c{};
  CHECK_OK(wire::open_link(second.view(), 3, c_security, at_c));
  wire::PlainFrame opened{};
  CHECK_OK(wire::open_end(at_c, 3, c_security, opened));
  CHECK(opened.payload_size == std::strlen(text));
  CHECK(std::memcmp(opened.payload.data(), text, opened.payload_size) == 0);

  second.bytes[100] ^= 1;
  CHECK(!wire::open_link(second.view(), 3, c_security, at_c));
}

void test_wire_forwarding_link_epoch() {
  // Boot-advancing epochs: origin A runs epoch 7, forwarder B runs epoch 3.
  // The B->C hop MUST carry B's epoch — inheriting A's 7 would ratchet C's
  // replay floor for the B->C context above B's own probes and wedge the
  // link (REPLAY_EPOCH_STALE / REPLAY_STATE_LOST).
  TestSecurity a_security, b_security, c_security;
  wire::PlainFrame plain{};
  plain.header.type = FrameType::Data;
  plain.header.flags = wire::kFlagEndProtected;
  plain.header.delivery = DeliveryClass::Reliable;
  plain.header.hop_remaining = 4;
  plain.header.network = 1;
  plain.header.origin = 1;
  plain.header.destination = 3;
  plain.header.previous_hop = 1;
  plain.header.next_hop = 2;
  plain.header.message = MessageId{7, 9};
  plain.header.remaining_deadline_ms = 5000;
  plain.header.original_lifetime_ms = 5000;
  plain.header.link_epoch = 7;
  plain.header.end_epoch = 7;
  const char* text = "route-loom";
  plain.payload_size = std::strlen(text);
  std::memcpy(plain.payload.data(), text, plain.payload_size);

  wire::EncodedFrame first{};
  CHECK_OK(wire::encode_new(plain, a_security, first));
  wire::LinkOpenedFrame at_b{};
  CHECK_OK(wire::open_link(first.view(), 2, b_security, at_b));
  CHECK(at_b.header.link_epoch == 7);
  wire::EncodedFrame second{};
  CHECK_OK(wire::forward(at_b, 2, 3, /*link_epoch=*/3, 4900, b_security, second));
  wire::LinkOpenedFrame at_c{};
  CHECK_OK(wire::open_link(second.view(), 3, c_security, at_c));
  CHECK(at_c.header.link_epoch == 3);
  CHECK(at_c.header.end_epoch == 7);  // end epoch is the ORIGIN's, untouched
  wire::PlainFrame opened{};
  CHECK_OK(wire::open_end(at_c, 3, c_security, opened));
  CHECK(opened.payload_size == std::strlen(text));
}

void test_routing() {
  RouteTable table;
  CHECK(table.consider(RouteAdvertisement{9, 1, 100, 0}, 2, 10, 0, 1000) == RouteUpdateResult::Accepted);
  CHECK(table.best(9).next_hop == 2);
  CHECK(table.mark_advertised(9));
  CHECK(table.consider(RouteAdvertisement{9, 1, 100, 20}, 3, 10, 1, 1000) == RouteUpdateResult::Infeasible);
  CHECK(!table.needs_sequence_request(9));  // the feasible route via 2 still exists
  table.invalidate_next_hop(2, 2);
  CHECK(table.needs_sequence_request(9));
  // The infeasible via-3 candidate is retained (it can carry a SeqNoRequest),
  // so accepting a newer sequence through it reports Updated, not Accepted.
  CHECK(table.consider(RouteAdvertisement{9, 1, 101, 20}, 3, 10, 3, 1000) == RouteUpdateResult::Updated);
  CHECK(table.best(9).next_hop == 3);
  table.invalidate_next_hop(3, 4);
  CHECK(!table.best(9).valid);
}

void test_three_hop_delivery() {
  SimNetwork network;
  TestSecurity sec1, sec2, sec3;
  CapturingObserver obs1, obs2, obs3;
  SimRadio radio1(network, 1), radio2(network, 2), radio3(network, 3);
  NodeConfig c1{1, 1, 101};
  NodeConfig c2{1, 2, 102};
  NodeConfig c3{1, 3, 103};
  c1.route_advertisement_period_ms = c2.route_advertisement_period_ms = c3.route_advertisement_period_ms = 100;
  c1.route_lifetime_ms = c2.route_lifetime_ms = c3.route_lifetime_ms = 1000;
  SimReplyPort port1(radio1, 1, c1.link_epoch), port2(radio2, 2, c2.link_epoch),
      port3(radio3, 3, c3.link_epoch);
  MeshNode n1(c1, radio1, sec1, obs1), n2(c2, radio2, sec2, obs2), n3(c3, radio3, sec3, obs3);
  CHECK_OK(n1.set_reply_peer_port(&port1));
  CHECK_OK(n2.set_reply_peer_port(&port2));
  CHECK_OK(n3.set_reply_peer_port(&port3));
  network.register_node(1, &n1); network.register_node(2, &n2); network.register_node(3, &n3);
  network.register_reply_port(1, &port1); network.register_reply_port(2, &port2);
  network.register_reply_port(3, &port3);
  network.connect(1, 2); network.connect(2, 3);
  CHECK_OK(n1.start(0)); CHECK_OK(n2.start(0)); CHECK_OK(n3.start(0));
  CHECK_OK(n1.add_neighbor(2, 1, 0));
  CHECK_OK(n2.add_neighbor(1, 1, 0)); CHECK_OK(n2.add_neighbor(3, 1, 0));
  CHECK_OK(n3.add_neighbor(2, 1, 0));
  std::vector<MeshNode*> nodes{&n1, &n2, &n3};
  run_network(nodes, network, 0, 800);
  CHECK(n1.routes().best(3).valid);
  const std::array<std::uint8_t, 5> payload{{1, 2, 3, 4, 5}};
  MessageId id{};
  CHECK_OK(n1.send(3, ByteView{payload.data(), payload.size()}, SendOptions{}, 805, id));
  run_network(nodes, network, 805, 2000);
  CHECK(obs3.messages.size() == 1);
  CHECK(obs3.messages[0] == std::vector<std::uint8_t>(payload.begin(), payload.end()));
  CHECK(n1.delivery(id).state == DeliveryState::Delivered);
}

void test_diamond_repair() {
  SimNetwork network;
  TestSecurity s1, s2, s3, s4;
  CapturingObserver o1, o2, o3, o4;
  SimRadio r1(network,1), r2(network,2), r3(network,3), r4(network,4);
  NodeConfig a{1,1,201}, b{1,2,202}, c{1,3,203}, d{1,4,204};
  for (auto* cfg : {&a,&b,&c,&d}) { cfg->route_advertisement_period_ms=100; cfg->route_lifetime_ms=800; }
  SimReplyPort p1(r1,1,a.link_epoch), p2(r2,2,b.link_epoch), p3(r3,3,c.link_epoch),
      p4(r4,4,d.link_epoch);
  MeshNode n1(a,r1,s1,o1), n2(b,r2,s2,o2), n3(c,r3,s3,o3), n4(d,r4,s4,o4);
  CHECK_OK(n1.set_reply_peer_port(&p1)); CHECK_OK(n2.set_reply_peer_port(&p2));
  CHECK_OK(n3.set_reply_peer_port(&p3)); CHECK_OK(n4.set_reply_peer_port(&p4));
  network.register_node(1,&n1); network.register_node(2,&n2); network.register_node(3,&n3); network.register_node(4,&n4);
  network.register_reply_port(1,&p1); network.register_reply_port(2,&p2);
  network.register_reply_port(3,&p3); network.register_reply_port(4,&p4);
  for (auto edge : {std::pair<NodeId,NodeId>{1,2},{2,4},{1,3},{3,4}}) network.connect(edge.first,edge.second);
  CHECK_OK(n1.start(0)); CHECK_OK(n2.start(0)); CHECK_OK(n3.start(0)); CHECK_OK(n4.start(0));
  CHECK_OK(n1.add_neighbor(2,1,0)); CHECK_OK(n1.add_neighbor(3,2,0));
  CHECK_OK(n2.add_neighbor(1,1,0)); CHECK_OK(n2.add_neighbor(4,1,0));
  CHECK_OK(n3.add_neighbor(1,2,0)); CHECK_OK(n3.add_neighbor(4,2,0));
  CHECK_OK(n4.add_neighbor(2,1,0)); CHECK_OK(n4.add_neighbor(3,2,0));
  std::vector<MeshNode*> nodes{&n1,&n2,&n3,&n4};
  run_network(nodes,network,0,800);
  CHECK(n1.routes().best(4).valid);
  network.disconnect(2,4);
  n2.remove_neighbor(4, 805); n4.remove_neighbor(2, 805);
  run_network(nodes,network,805,4000);
  const std::array<std::uint8_t,3> payload{{9,8,7}};
  MessageId id{};
  CHECK_OK(n1.send(4,ByteView{payload.data(),payload.size()},SendOptions{},4005,id));
  run_network(nodes,network,4005,14000);
  CHECK(o4.messages.size() == 1);
  CHECK(n1.delivery(id).state == DeliveryState::Delivered);
}

void test_delivery_terminal_eviction() {
  // kDeliveryCapacity is 8. Terminal records are history, not live work:
  // without eviction the table wedges after eight sends and every later
  // send() fails with NoCapacity forever.
  SimNetwork network;
  TestSecurity sec;
  CapturingObserver obs;
  SimRadio radio(network, 1);
  NodeConfig cfg{1, 1, 301};
  SimReplyPort port(radio, 1, cfg.link_epoch);
  MeshNode node(cfg, radio, sec, obs);
  CHECK_OK(node.set_reply_peer_port(&port));
  network.register_node(1, &node);
  network.register_reply_port(1, &port);
  CHECK_OK(node.start(0));
  const std::array<std::uint8_t, 4> payload{{1, 2, 3, 4}};

  // Eight live (non-terminal) sends fill the table; the ninth must fail —
  // live records are never evicted.
  std::array<MessageId, 8> ids{};
  for (int i = 0; i < 8; ++i) {
    CHECK_OK(node.send(2, ByteView{payload.data(), payload.size()},
                       SendOptions{}, static_cast<MonotonicMs>(i), ids[i]));
  }
  {
    MessageId id{};
    CHECK(node.send(2, ByteView{payload.data(), payload.size()}, SendOptions{},
                    100, id)
              .code == StatusCode::NoCapacity);
  }
  // Cancelling an entry turns it into terminal history. The next send must
  // evict that record and succeed instead of staying wedged — forever.
  for (int round = 0; round < 8; ++round) {
    CHECK_OK(node.cancel(ids[round]));  // → CancelledBeforeTx (terminal)
    CHECK_OK(node.send(2, ByteView{payload.data(), payload.size()},
                       SendOptions{}, static_cast<MonotonicMs>(200 + round),
                       ids[round]));
  }
  // Steady state: cancel+send cycles keep recovering, evicting one terminal
  // record per send.
  for (int round = 0; round < 8; ++round) {
    CHECK_OK(node.cancel(ids[round]));
    MessageId id{};
    CHECK_OK(node.send(2, ByteView{payload.data(), payload.size()},
                       SendOptions{}, static_cast<MonotonicMs>(400 + round), id));
  }
}

// End-protected transit DATA `prev` -> `relay` bound for `destination` —
// the kind of inbound frame whose receive queues a HOP_ACCEPT on the
// control lane (same construction as test_congestion's craft_transit).
wire::EncodedFrame craft_transit_frame(TestSecurity& cipher, NodeId prev,
                                       NodeId relay, NodeId origin,
                                       NodeId destination, std::uint64_t seq,
                                       ByteView payload) {
  wire::PlainFrame plain{};
  wire::Header& h = plain.header;
  h.type = FrameType::Data;
  h.flags = wire::kFlagEndProtected;
  h.delivery = DeliveryClass::Reliable;
  h.hop_remaining = kDefaultHopLimit;
  h.network = 1;
  h.origin = origin;
  h.destination = destination;
  h.previous_hop = prev;
  h.next_hop = relay;
  h.message = MessageId{42, seq};
  h.remaining_deadline_ms = 5000;
  h.original_lifetime_ms = 5000;
  h.link_epoch = 1;
  h.end_epoch = 1;
  plain.payload_size = payload.size;
  std::memcpy(plain.payload.data(), payload.data, payload.size);
  wire::EncodedFrame out{};
  CHECK_OK(wire::encode_new(plain, cipher, out));
  return out;
}

void test_tx_result_dispatch() {
  // Issue #60-3: a driver TX completion is staged, not handled inline —
  // the owner task wakes on the event (EspNowRuntime::wait_for_event on
  // the firmware queue), drains every staged event, and the following
  // poll() submits the next frame. FakeRadioPort stamps each submission;
  // OwnerPump models the firmware loop end to end — post -> wait -> drain
  // -> poll — running the same shared wait gate as firmware
  // (owner_pump.hpp).
  TestSecurity security;
  CapturingObserver observer;
  routeloom_test::FakeRadioPort radio;
  routeloom_test::OwnerPump pump;
  NodeConfig config{1, 1, 901};
  SimReplyPort port(radio, 1, config.link_epoch);
  MeshNode node(config, radio, security, observer);
  CHECK_OK(node.set_reply_peer_port(&port));
  CHECK_OK(node.start(0));
  CHECK_OK(node.add_neighbor(2, 1, 0));
  const std::array<std::uint8_t, 4> payload{{1, 2, 3, 4}};
  const ByteView body{payload.data(), payload.size()};
  const auto sight_of = [](const routeloom_test::FakeRadioPort::SentFrame& f,
                           routeloom_test::FrameSight& sight) {
    return routeloom_test::sight_frame(
        ByteView{f.bytes.data(), f.bytes.size()}, sight);
  };

  // --- callback -> next-submit latency ------------------------------------
  // Three queued sends, one pass at t=0 puts the first frame in the
  // driver, then the owner task sleeps. A completion posted mid-sleep at
  // t=1 wakes the task AT t=1 — not the 2 ms tick the fixed vTaskDelay
  // loop waited out — and the drained pass submits the next frame with no
  // tick tax, so the queue drains at the callback rate.
  SendOptions best{};
  best.delivery = DeliveryClass::BestEffort;
  for (int i = 0; i < 3; ++i) {
    MessageId id{};
    CHECK_OK(node.send(2, body, best, 0, id));
  }
  radio.now_ms = 0;
  pump.run_once(0, node);
  CHECK(radio.sent.size() == 1);  // the boot advertisement is in flight
  // With nothing staged, the wait still bounds idle at one poll period —
  // the shared gate both sides execute (owner_pump.hpp).
  CHECK(owner_wait_timeout_ms(kOwnerPollPeriodMs, false) == kOwnerPollPeriodMs);
  CHECK(owner_wait_timeout_ms(kOwnerPollPeriodMs, true) == 0);
  constexpr MonotonicMs kCompletedAt = 1;
  pump.post_tx_result(radio.sent.back().token, true, kCompletedAt);
  CHECK(pump.wake_at(0) == kCompletedAt);  // the event beats the tick
  radio.now_ms = pump.wake_at(0);
  pump.run_once(radio.now_ms, node);
  CHECK(radio.sent.size() == 2);
  CHECK(radio.sent.back().at_ms == kCompletedAt);  // submitted on the wake —
                                                   // 0 ms of idle airtime
  // Two more completions at t=1 chain the remaining sends at the same
  // instant — the fixed-tick loop would have paid a tick per frame.
  for (int i = 0; i < 2; ++i) {
    pump.post_tx_result(radio.sent.back().token, true, kCompletedAt);
    pump.run_once(kCompletedAt, node);
  }
  CHECK(radio.sent.size() == 4);
  CHECK(radio.sent.back().at_ms == kCompletedAt);
  routeloom_test::FrameSight sight{};
  CHECK(sight_of(radio.sent.back(), sight) && sight.type == FrameType::Data);

  // The pause mask still gates the pump's dispatch: a staged completion
  // frees nothing while kDataDispatch is held.
  {
    MessageId paused_a{}, paused_b{};
    CHECK_OK(node.send(2, body, best, 4, paused_a));
    CHECK_OK(node.send(2, body, best, 4, paused_b));
    CHECK_OK(node.set_pause(PauseReason::SurveyVisit, pause::kDataDispatch));
    pump.post_tx_result(radio.sent.back().token, true, 4);
    // Idle since t=1: the tick (t=3) beats the event's t=4 post — the task
    // wakes, finds nothing staged, and sleeps again until the event lands.
    radio.now_ms = pump.wake_at(1);
    CHECK(radio.now_ms == 3);
    pump.run_once(radio.now_ms, node);
    radio.now_ms = pump.wake_at(radio.now_ms);
    CHECK(radio.now_ms == 4);
    pump.run_once(radio.now_ms, node);  // resolved, nothing dispatched
    CHECK(radio.sent.size() == 4);
    CHECK_OK(node.clear_pause(PauseReason::SurveyVisit));
    radio.now_ms = 5;
    pump.run_once(radio.now_ms, node);
    CHECK(radio.sent.size() == 5 && radio.sent.back().at_ms == 5);
  }

  // --- staged completion skips the wait ------------------------------------
  // The completion lands on a full driver queue AFTER the pass's entry
  // check, so it is staged outside the queue (firmware: lost_node_tx_;
  // here: post_staged_tx_result) while the queue itself drains empty.
  // The wait still returns immediately — an empty queue must not idle a
  // resolvable job — and the next pass submits with no gap.
  // wait_for_event runs this same gate on the firmware side
  // (owner_pump.hpp).
  pump.post_staged_tx_result(radio.sent.back().token, true, 5);
  radio.now_ms = pump.wake_at(5);
  CHECK(radio.now_ms == 5);  // staged work never sleeps out the tick
  pump.run_once(radio.now_ms, node);
  CHECK(radio.sent.size() == 6);
  CHECK(radio.sent.back().at_ms == 5);  // resolved + redispatched, no gap

  // --- mixed TX/RX drain order --------------------------------------------
  // A TX completion and an inbound transit DATA (which owes a HOP_ACCEPT)
  // are both staged while the owner sleeps. The pass must drain BOTH and
  // only then let poll() dispatch: the accept takes the control lane
  // ahead of the queued DATA. Dispatching inside on_radio_tx_result
  // would put the DATA on the air before the RX was even decoded, so a
  // completion resolves the in-flight attempt only and the next
  // submission always comes from poll() after the drain.
  {
    TestSecurity security2;
    CapturingObserver observer2;
    routeloom_test::FakeRadioPort radio2;
    routeloom_test::OwnerPump pump2;
    NodeConfig config2{1, 7, 902};
    SimReplyPort port2(radio2, 7, config2.link_epoch);
    MeshNode node2(config2, radio2, security2, observer2);
    CHECK_OK(node2.set_reply_peer_port(&port2));
    pump2.set_reply_port(&port2);
    CHECK_OK(node2.start(0));
    CHECK_OK(node2.add_neighbor(2, 1, 0));
    CHECK_OK(node2.add_neighbor(9, 1, 0));  // next hop for the transit forward
    MessageId q1{}, q2{};
    CHECK_OK(node2.send(2, body, best, 0, q1));
    CHECK_OK(node2.send(2, body, best, 0, q2));
    radio2.now_ms = 0;
    pump2.run_once(0, node2);  // boot ad in flight; resolve it so DATA can go
    pump2.post_tx_result(radio2.sent.back().token, true, 1);
    radio2.now_ms = pump2.wake_at(0);
    CHECK(radio2.now_ms == 1);
    pump2.run_once(radio2.now_ms, node2);  // DATA #1 is with the driver now
    CHECK(radio2.sent.back().at_ms == 1);
    const std::size_t sent_before = radio2.sent.size();
    // Both events land while the owner sleeps: completion first, then RX.
    pump2.post_tx_result(radio2.sent.back().token, true, 2);
    const wire::EncodedFrame inbound = craft_transit_frame(
        security2, /*prev=*/2, /*relay=*/7, /*origin=*/2, /*destination=*/9,
        /*seq=*/9001, body);
    pump2.post_rx(2,
                  std::vector<std::uint8_t>(
                      inbound.view().data,
                      inbound.view().data + inbound.view().size),
                  -55, 2);
    radio2.now_ms = pump2.wake_at(1);
    CHECK(radio2.now_ms == 2);
    pump2.run_once(radio2.now_ms, node2);
    // First post-drain submission is the HOP_ACCEPT, not the queued DATA.
    CHECK(radio2.sent.size() > sent_before);
    routeloom_test::FrameSight first{};
    CHECK(sight_of(radio2.sent[sent_before], first));
    CHECK(first.type == FrameType::HopAccept);
    // The queued DATA follows once the accept's own completion arrives.
    pump2.post_tx_result(radio2.sent.back().token, true, 3);
    radio2.now_ms = 3;
    pump2.run_once(radio2.now_ms, node2);
    CHECK(radio2.sent.size() > sent_before + 1);
    routeloom_test::FrameSight second{};
    CHECK(sight_of(radio2.sent[sent_before + 1], second));
    CHECK(second.type == FrameType::Data);
  }

  // --- already-queued event never rewinds the clock -------------------------
  // The completion lands at t=1 while the owner is still busy, so the
  // wait starts at t=2 with the event already queued. Firmware's
  // xQueuePeek returns immediately at t=2 — the wake must not rewind to
  // the t=1 post time and under-measure the submit gap.
  {
    routeloom_test::OwnerPump pump3;
    pump3.post_tx_result(7, true, 1);
    CHECK(pump3.wake_at(2) == 2);
  }
}

// Issue #60-3 over the public C ABI: rl_on_radio_tx_result resolves the
// in-flight attempt ONLY — the next submission always comes from the
// owner task's rl_poll, after any same-cycle RX/control work. A driver
// completion callback that invoked the handler inline can therefore never
// re-enter the driver's own send() — the staged hand-off the header now
// documents is the supported path.
struct CApiTxProbe {
  CApiState security{};
  int send_calls{0};
  std::uint64_t last_token{0};
};

rl_status_code_t capi_probe_send(void* user, rl_node_id_t, uint64_t token,
                                 const uint8_t*, size_t) {
  auto* probe = static_cast<CApiTxProbe*>(user);
  ++probe->send_calls;
  probe->last_token = token;
  return RL_STATUS_OK;
}

void test_c_api_tx_result_owner_task() {
  CApiTxProbe probe{};
  rl_node_config_t config{};
  rl_node_config_init(&config);
  config.network = 1;
  config.node = 7;
  config.message_session = 77;
  const rl_radio_vtable_t radio{&probe, capi_probe_send, capi_radio_recover};
  const rl_security_vtable_t security{&probe.security, capi_security_ready,
                                      capi_next_counter, capi_seal, capi_open};
  const rl_observer_vtable_t observer{};
  std::vector<std::max_align_t> storage(
      (rl_context_size() + sizeof(std::max_align_t) - 1) / sizeof(std::max_align_t));
  rl_context_t* context = nullptr;
  CHECK(rl_init(storage.data(), storage.size() * sizeof(std::max_align_t), &config,
                &radio, &security, &observer, &context) == RL_STATUS_OK);
  CHECK(context != nullptr);
  CApiReplyPort probe_reply_port{};
  capi_attach_reply_port(context, &probe_reply_port);
  CHECK(rl_start(context, 0) == RL_STATUS_OK);
  CHECK(rl_add_neighbor(context, 8, 1, 0) == RL_STATUS_OK);
  rl_send_options_t options{};
  rl_send_options_init(&options);
  options.delivery = RL_DELIVERY_BEST_EFFORT;
  const uint8_t payload[] = {1, 2};
  for (int i = 0; i < 3; ++i) {
    rl_message_id_t id{};
    CHECK(rl_send(context, 8, payload, sizeof(payload), &options, 0, &id) ==
          RL_STATUS_OK);
  }
  // Owner pump on the C ABI: each pass submits at most one frame, and only
  // rl_poll submits — the completion handed to the owner task resolves the
  // attempt without ever calling back into the driver.
  int submitted = 0;
  for (rl_monotonic_ms_t now = 0; now < 8 && submitted < 3; ++now) {
    rl_poll(context, now);
    if (probe.send_calls > submitted) {
      submitted = probe.send_calls;
      const int before = probe.send_calls;
      rl_on_radio_tx_result(context, probe.last_token, true, now);
      CHECK(probe.send_calls == before);
    }
  }
  CHECK(submitted >= 3);
  rl_deinit(context);
}

void test_sim_flush_truncation_aborts() {
#ifdef _WIN32
  return;  // the death check needs fork(); POSIX CI covers it
#else
  // A flush() that hits the dequeue bound with frames still queued must
  // fail the test, not return a partial drain — the child overflows the
  // bound with senderless frames (no nodes registered, so every dequeue
  // drops without touching a MeshNode) and the parent expects SIGABRT.
  const pid_t pid = fork();
  CHECK(pid >= 0);
  if (pid < 0) return;
  if (pid == 0) {
    SimNetwork net;
    const std::uint8_t byte = 0;
    const ByteView view{&byte, 1};
    for (int i = 0; i < 10001; ++i) {
      net.enqueue(1, 2, static_cast<std::uint64_t>(i), view);
    }
    net.flush(0);
    _exit(42);  // returned past the bound: the check did not fire
  }
  int status = 0;
  CHECK(waitpid(pid, &status, 0) == pid);
  CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT);
#endif
}

}  // namespace

int main() {
  test_admission_contract();
  test_deadline_resume();
  test_single_authority();
  test_c_api_lifecycle();
  test_c_api_route_profile();
  test_c_api_group();
  test_byte_io();
  test_counter_lease();
  test_wire_forwarding();
  test_wire_forwarding_link_epoch();
  test_routing();
  test_three_hop_delivery();
  test_diamond_repair();
  test_delivery_terminal_eviction();
  test_tx_result_dispatch();
  test_c_api_tx_result_owner_task();
  test_sim_flush_truncation_aborts();
  if (failures != 0) {
    std::fprintf(stderr, "%d test checks failed\n", failures);
    return 1;
  }
  std::puts("RouteLoom portable core tests passed");
  return 0;
}
