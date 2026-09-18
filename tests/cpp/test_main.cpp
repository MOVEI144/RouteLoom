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

namespace {

int failures = 0;
#define CHECK(expr) do { if (!(expr)) { std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__, #expr); ++failures; } } while (false)
#define CHECK_OK(expr) do { const auto _status = (expr); if (!_status.ok()) { std::fprintf(stderr, "STATUS failed %s:%d: %s (%s)\n", __FILE__, __LINE__, #expr, _status.detail); ++failures; } } while (false)

using namespace routeloom;

std::uint64_t mix(std::uint64_t state, std::uint64_t value) {
  state ^= value + 0x9e3779b97f4a7c15ULL + (state << 6U) + (state >> 2U);
  state *= 0xbf58476d1ce4e5b9ULL;
  return state;
}

class TestSecurity final : public SecurityProvider {
 public:
  bool ready() const noexcept override { return true; }

  Status next_counter(const SecurityContext& context, std::uint64_t& counter) noexcept override {
    auto key = std::make_tuple(static_cast<int>(context.scope), context.network,
                               context.sender, context.receiver, context.epoch);
    counter = counters_[key]++;
    return Status::success();
  }

  Status seal(const SecurityContext& context, const std::uint64_t counter,
              const ByteView aad, const ByteView plaintext,
              const MutableByteView ciphertext,
              std::array<std::uint8_t, kAeadTagSize>& tag) noexcept override {
    if (ciphertext.size < plaintext.size) return Status::error(StatusCode::NoCapacity, "test ciphertext");
    auto state = seed(context, counter);
    for (std::size_t i = 0; i < plaintext.size; ++i) {
      state = mix(state, i + 1);
      ciphertext.data[i] = plaintext.data[i] ^ static_cast<std::uint8_t>(state >> 56U);
    }
    make_tag(context, counter, aad, ByteView{ciphertext.data, plaintext.size}, tag);
    return Status::success();
  }

  Status open(const SecurityContext& context, const std::uint64_t counter,
              const ByteView aad, const ByteView ciphertext,
              const std::array<std::uint8_t, kAeadTagSize>& tag,
              const MutableByteView plaintext) noexcept override {
    if (plaintext.size < ciphertext.size) return Status::error(StatusCode::NoCapacity, "test plaintext");
    std::array<std::uint8_t, kAeadTagSize> expected{};
    make_tag(context, counter, aad, ciphertext, expected);
    std::uint8_t diff = 0;
    for (std::size_t i = 0; i < tag.size(); ++i) diff |= expected[i] ^ tag[i];
    if (diff != 0) return Status::error(StatusCode::AuthenticationFailed, "test tag mismatch");
    auto state = seed(context, counter);
    for (std::size_t i = 0; i < ciphertext.size; ++i) {
      state = mix(state, i + 1);
      plaintext.data[i] = ciphertext.data[i] ^ static_cast<std::uint8_t>(state >> 56U);
    }
    return Status::success();
  }

 private:
  using Key = std::tuple<int, NetworkId, NodeId, NodeId, std::uint16_t>;
  std::map<Key, std::uint64_t> counters_{};

  static std::uint64_t seed(const SecurityContext& context, std::uint64_t counter) {
    std::uint64_t state = 0x726f7574656c6f6fULL;
    state = mix(state, static_cast<std::uint64_t>(context.scope));
    state = mix(state, context.network);
    state = mix(state, context.sender);
    state = mix(state, context.receiver);
    state = mix(state, context.epoch);
    return mix(state, counter);
  }

  static void make_tag(const SecurityContext& context, std::uint64_t counter,
                       ByteView aad, ByteView ciphertext,
                       std::array<std::uint8_t, kAeadTagSize>& tag) {
    std::uint64_t left = seed(context, counter);
    std::uint64_t right = mix(left, 0x746167ULL);
    for (std::size_t i = 0; i < aad.size; ++i) left = mix(left, aad.data[i]);
    for (std::size_t i = 0; i < ciphertext.size; ++i) right = mix(right, ciphertext.data[i]);
    for (int i = 0; i < 8; ++i) {
      tag[i] = static_cast<std::uint8_t>(left >> (56 - i * 8));
      tag[8 + i] = static_cast<std::uint8_t>(right >> (56 - i * 8));
    }
  }
};

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

struct CapturingObserver final : NodeObserver {
  std::vector<std::vector<std::uint8_t>> messages;
  std::vector<DeliveryResult> delivery_events;
  std::vector<std::string> diagnostics;

  void on_message(const MessageKey&, NodeId, ByteView payload) noexcept override {
    messages.emplace_back(payload.data, payload.data + payload.size);
  }
  void on_delivery(const DeliveryResult& result) noexcept override { delivery_events.push_back(result); }
  void on_diagnostic(const char* reason, NodeId, const MessageId*) noexcept override {
    diagnostics.emplace_back(reason);
  }
};

class SimNetwork;
class SimRadio final : public RadioPort {
 public:
  SimRadio(SimNetwork& network, NodeId owner) : network_(network), owner_(owner) {}
  Status send(NodeId peer, std::uint64_t token, ByteView frame) noexcept override;
  Status recover() noexcept override { return Status::success(); }
 private:
  SimNetwork& network_;
  NodeId owner_;
};

class SimNetwork {
 public:
  struct Pending {
    NodeId from;
    NodeId to;
    std::uint64_t token;
    std::vector<std::uint8_t> frame;
  };

  void register_node(NodeId id, MeshNode* node) { nodes[id] = node; }
  void connect(NodeId a, NodeId b) { links.insert(normalize(a, b)); }
  void disconnect(NodeId a, NodeId b) { links.erase(normalize(a, b)); }
  bool connected(NodeId a, NodeId b) const { return links.count(normalize(a, b)) != 0; }

  Status enqueue(NodeId from, NodeId to, std::uint64_t token, ByteView frame) {
    queue.push_back(Pending{from, to, token, std::vector<std::uint8_t>(frame.data, frame.data + frame.size)});
    return Status::success();
  }

  void flush(MonotonicMs now) {
    std::size_t safety = 0;
    while (!queue.empty() && safety++ < 10000) {
      Pending pending = std::move(queue.front());
      queue.pop_front();
      const bool success = connected(pending.from, pending.to) && nodes.count(pending.to) != 0;
      nodes.at(pending.from)->on_radio_tx_result(pending.token, success, now);
      if (success) {
        nodes.at(pending.to)->on_radio_receive(
            pending.from, ByteView{pending.frame.data(), pending.frame.size()}, RadioRxMetadata{-60}, now);
      }
    }
    CHECK(safety < 10000);
  }

 private:
  static std::pair<NodeId, NodeId> normalize(NodeId a, NodeId b) {
    return a < b ? std::make_pair(a, b) : std::make_pair(b, a);
  }
  std::map<NodeId, MeshNode*> nodes;
  std::set<std::pair<NodeId, NodeId>> links;
  std::deque<Pending> queue;
};

Status SimRadio::send(NodeId peer, std::uint64_t token, ByteView frame) noexcept {
  return network_.enqueue(owner_, peer, token, frame);
}

void run_network(std::vector<MeshNode*>& nodes, SimNetwork& network,
                 MonotonicMs begin, MonotonicMs end, MonotonicMs step = 5) {
  for (MonotonicMs now = begin; now <= end; now += step) {
    for (auto* node : nodes) node->poll(now);
    network.flush(now);
  }
}


class MemoryAuthorityStore final : public AuthorityStore {
 public:
  Status load(AuthorityRecord& record, bool& found) noexcept override {
    found = has_record;
    if (found) record = stored;
    return Status::success();
  }
  Status commit(const AuthorityRecord& record) noexcept override {
    stored = record;
    has_record = true;
    return Status::success();
  }
  AuthorityRecord stored{};
  bool has_record{false};
};

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
  MemoryAuthorityStore store;
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
  CHECK_OK(wire::forward(at_b, 2, 3, 4900, b_security, second));
  wire::LinkOpenedFrame at_c{};
  CHECK_OK(wire::open_link(second.view(), 3, c_security, at_c));
  wire::PlainFrame opened{};
  CHECK_OK(wire::open_end(at_c, 3, c_security, opened));
  CHECK(opened.payload_size == std::strlen(text));
  CHECK(std::memcmp(opened.payload.data(), text, opened.payload_size) == 0);

  second.bytes[100] ^= 1;
  CHECK(!wire::open_link(second.view(), 3, c_security, at_c));
}

void test_routing() {
  RouteTable table;
  CHECK(table.consider(RouteAdvertisement{9, 100, 0}, 2, 10, 0, 1000) == RouteUpdateResult::Accepted);
  CHECK(table.best(9).next_hop == 2);
  CHECK(table.mark_advertised(9));
  CHECK(table.consider(RouteAdvertisement{9, 100, 20}, 3, 10, 1, 1000) == RouteUpdateResult::Infeasible);
  CHECK(!table.needs_sequence_request(9));  // the feasible route via 2 still exists
  table.invalidate_next_hop(2);
  CHECK(table.needs_sequence_request(9));
  CHECK(table.consider(RouteAdvertisement{9, 101, 20}, 3, 10, 2, 1000) == RouteUpdateResult::Accepted);
  CHECK(table.best(9).next_hop == 3);
  table.invalidate_next_hop(3);
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
  n2.remove_neighbor(4); n4.remove_neighbor(2);
  run_network(nodes,network,805,1500);
  const std::array<std::uint8_t,3> payload{{9,8,7}};
  MessageId id{};
  CHECK_OK(n1.send(4,ByteView{payload.data(),payload.size()},SendOptions{},1505,id));
  run_network(nodes,network,1505,3000);
  CHECK(o4.messages.size() == 1);
  CHECK(n1.delivery(id).state == DeliveryState::Delivered);
}

}  // namespace

int main() {
  test_admission_contract();
  test_deadline_resume();
  test_single_authority();
  test_c_api_lifecycle();
  test_byte_io();
  test_counter_lease();
  test_wire_forwarding();
  test_routing();
  test_three_hop_delivery();
  test_diamond_repair();
  if (failures != 0) {
    std::fprintf(stderr, "%d test checks failed\n", failures);
    return 1;
  }
  std::puts("RouteLoom portable core tests passed");
  return 0;
}
