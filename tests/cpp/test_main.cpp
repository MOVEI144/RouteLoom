#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <map>
#include <set>
#include <string>
#include <tuple>
#include <vector>

#include "routeloom/admission.hpp"
#include "routeloom/authority.hpp"
#include "routeloom/byte_io.hpp"
#include "routeloom/deadline.hpp"
#include "routeloom/routeloom.h"
#include "routeloom/counter_store.hpp"
#include "routeloom/node.hpp"
#include "routeloom/routing.hpp"
#include "routeloom/wire.hpp"

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

  rl_status_code_t init(const rl_node_config_t& config) {
    return rl_init(storage.data(), storage.size() * sizeof(std::max_align_t), &config,
                   &radio, &security, &observer, &context);
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
  MeshNode n1(c1, radio1, sec1, obs1), n2(c2, radio2, sec2, obs2), n3(c3, radio3, sec3, obs3);
  network.register_node(1, &n1); network.register_node(2, &n2); network.register_node(3, &n3);
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
  MeshNode n1(a,r1,s1,o1), n2(b,r2,s2,o2), n3(c,r3,s3,o3), n4(d,r4,s4,o4);
  network.register_node(1,&n1); network.register_node(2,&n2); network.register_node(3,&n3); network.register_node(4,&n4);
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
  MeshNode node(cfg, radio, sec, obs);
  network.register_node(1, &node);
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

void test_tx_result_dispatch() {
  // Issue #60-3: a resolved send frees the driver's single in-flight slot,
  // so the next queued job is submitted inside the same task turn
  // (on_radio_tx_result -> dispatch_next), not at the next poll() tick.
  // The tick wait used to leave ~1 poll period of idle airtime between
  // back-to-back frames — the runtime's ~2ms cadence against a ~6ms
  // HOP_ACCEPT-class exchange is the 25-30% throughput loss the issue
  // measured. In this harness the gap shows up as "how many frames went
  // on the air inside ONE net.flush()": every in-flush submission is a
  // dispatch that needed no poll tick.
  SimNetwork network;
  TestSecurity s1, s2;
  CapturingObserver o1, o2;
  SimRadio r1(network, 1), r2(network, 2);
  NodeConfig c1{1, 1, 901}, c2{1, 2, 902};
  MeshNode n1(c1, r1, s1, o1), n2(c2, r2, s2, o2);
  network.register_node(1, &n1); network.register_node(2, &n2);
  network.connect(1, 2);
  CHECK_OK(n1.start(0)); CHECK_OK(n2.start(0));
  CHECK_OK(n1.add_neighbor(2, 1, 0)); CHECK_OK(n2.add_neighbor(1, 1, 0));
  const std::array<std::uint8_t, 4> payload{{1, 2, 3, 4}};
  const ByteView body{payload.data(), payload.size()};
  const auto data_frames = [&]() { return network.tx_by_type[FrameType::Data].frames; };

  // Three BestEffort sends chain inside ONE flush: each TX result submits
  // the next queued job in the same task turn, so all three reach the air
  // without an intervening poll.
  {
    SendOptions opts{};
    opts.delivery = DeliveryClass::BestEffort;
    for (int i = 0; i < 3; ++i) {
      MessageId id{};
      CHECK_OK(n1.send(2, body, opts, 10, id));
    }
    n1.poll(10);            // only the first job reaches the driver here
    network.flush(10);      // one drain pass, no poll() inside
    CHECK(data_frames() == 3);
    CHECK(o2.messages.size() == 3);
  }

  // The immediate dispatch still honours the pause mask: while
  // kDataDispatch is held, a resolved send frees nothing to the scheduler.
  {
    SendOptions opts{};
    opts.delivery = DeliveryClass::BestEffort;
    MessageId a{}, b{};
    CHECK_OK(n1.send(2, body, opts, 20, a));
    CHECK_OK(n1.send(2, body, opts, 20, b));
    n1.poll(20);            // job A is with the driver before the pause lands
    CHECK_OK(n1.set_pause(PauseReason::SurveyVisit, pause::kDataDispatch));
    network.flush(20);      // A's TX result resolves — B must NOT dispatch
    CHECK(data_frames() == 4);
    CHECK_OK(n1.clear_pause(PauseReason::SurveyVisit));
    n1.poll(20);
    network.flush(20);
    CHECK(data_frames() == 5);
  }

  // And the congestion rules still gate it: three RELIABLE sends to the
  // same peer exceed the initial peer window (two in-flight exchanges), so
  // the immediate dispatch puts the second on the air but the third waits.
  {
    SendOptions opts{};     // Reliable: each send owes a HOP_ACCEPT exchange
    for (int i = 0; i < 3; ++i) {
      MessageId id{};
      CHECK_OK(n1.send(2, body, opts, 30, id));
    }
    n1.poll(30);
    network.flush(30);
    CHECK(data_frames() == 7);  // 5 + 2 — the peer window held the third
  }
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
  if (failures != 0) {
    std::fprintf(stderr, "%d test checks failed\n", failures);
    return 1;
  }
  std::puts("RouteLoom portable core tests passed");
  return 0;
}
