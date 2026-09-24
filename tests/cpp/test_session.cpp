// Provider-owned sessions (docs/design/sdk-v1/03-key-hierarchy.md §8–§9,
// plan P4-1): SecurityProvider::tx_epoch / context_state, SessionInstaller,
// the reserved GroupLink scope, and the MeshNode wiring.
//  (a) a provider that does not own sessions (the default, the development
//      PSK provider, TestSecurity) reports the configured epochs and Ready,
//      and the node's frames stay byte-identical;
//  (b) a session provider sets the epochs, and a missing / pending session
//      makes the node hold the frame with explicit diagnostics — no counter
//      is drawn for a refused frame and no (key, counter) is ever reused;
//  (c) V1-K10: every shared Wire v2 golden vector is reproduced byte for
//      byte through the provider-epoch path.

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "routeloom/group.hpp"
#include "routeloom/node.hpp"
#include "routeloom/security.hpp"
#include "routeloom/wire.hpp"

#include "test_security.hpp"
#include "test_sim.hpp"

#ifndef ROUTELOOM_GOLDEN_DIR
#define ROUTELOOM_GOLDEN_DIR "protocol/golden"
#endif

namespace {

int failures = 0;
#define CHECK(expr) do { if (!(expr)) { std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__, #expr); ++failures; } } while (false)
#define CHECK_OK(expr) do { const auto _status = (expr); if (!_status.ok()) { std::fprintf(stderr, "STATUS failed %s:%d: %s (%s)\n", __FILE__, __LINE__, #expr, _status.detail); ++failures; } } while (false)

using namespace routeloom;
using routeloom_test::CapturingObserver;
using routeloom_test::SimNetwork;
using routeloom_test::SimRadio;
using routeloom_test::SimReplyPort;
using routeloom_test::sim_rx_metadata;
using routeloom_test::TestSecurity;

constexpr NetworkId kNet = 1;

// Overrides both new hooks with exactly the default behaviour and counts the
// calls: proves the node/wire path really consults them while every byte
// stays identical.
class ConfiguredEpochSecurity final : public SecurityProvider {
 public:
  std::uint32_t tx_epoch_calls{0};

  bool ready() const noexcept override { return inner_.ready(); }
  Status tx_epoch(SecurityScope, NodeId, std::uint32_t&) noexcept override {
    ++tx_epoch_calls;
    return Status::success();
  }
  ContextState context_state(SecurityScope, NodeId) const noexcept override {
    return ContextState::Ready;
  }
  Status next_counter(const SecurityContext& context, std::uint64_t& counter) noexcept override {
    return inner_.next_counter(context, counter);
  }
  Status seal(const SecurityContext& context, const std::uint64_t counter, const ByteView aad,
              const ByteView plaintext, const MutableByteView ciphertext,
              std::array<std::uint8_t, kAeadTagSize>& tag) noexcept override {
    return inner_.seal(context, counter, aad, plaintext, ciphertext, tag);
  }
  Status open(const SecurityContext& context, const std::uint64_t counter, const ByteView aad,
              const ByteView ciphertext, const std::array<std::uint8_t, kAeadTagSize>& tag,
              const MutableByteView plaintext) noexcept override {
    return inner_.open(context, counter, aad, ciphertext, tag, plaintext);
  }

 private:
  TestSecurity inner_{};
};

// A RAM session provider in miniature: contexts per (scope, peer) with
// receiver-chosen ids (03 §4.2), installed only through SessionInstaller.
// The cipher is the deterministic TestSecurity keyed by the full context
// (epoch included), so a new context id is a new key.
class SessionSecurity final : public SecurityProvider, public SessionInstaller {
 public:
  struct Entry {
    ContextState state{ContextState::None};
    std::uint32_t tx_id{0};
    std::uint32_t rx_id{0};
  };
  using SealKey = std::tuple<int, NetworkId, NodeId, NodeId, std::uint32_t, std::uint64_t>;

  // Refuse frames whose (scope, sender, epoch) is not an installed rx
  // context (03 §9: unknown context id -> AuthRequired).
  bool strict_rx{false};
  // Misbehaving mode: tx_epoch refuses while context_state claims Ready.
  bool refuse_while_ready{false};
  std::map<std::pair<int, NodeId>, Entry> contexts;
  std::set<SealKey> sealed;
  bool nonce_reuse{false};
  std::vector<SecurityContext> counters_drawn;

  bool ready() const noexcept override { return true; }

  Status tx_epoch(const SecurityScope scope, const NodeId peer,
                  std::uint32_t& epoch) noexcept override {
    if (refuse_while_ready) {
      return Status::error(StatusCode::AuthRequired, "TEST_KEY_LOST");
    }
    const auto it = contexts.find({static_cast<int>(scope), peer});
    if (it == contexts.end() || !context_usable(it->second.state)) {
      return Status::error(StatusCode::AuthRequired, "TEST_NO_SESSION");
    }
    epoch = it->second.tx_id;
    return Status::success();
  }
  Status current_rx_epoch(const SecurityScope scope, const NodeId peer,
                          std::uint32_t& epoch) const noexcept override {
    const auto it = contexts.find({static_cast<int>(scope), peer});
    if (it == contexts.end() || !context_usable(it->second.state)) {
      return Status::error(StatusCode::AuthRequired, "TEST_NO_RX_SESSION");
    }
    epoch = it->second.rx_id;
    return Status::success();
  }
  ContextState context_state(const SecurityScope scope, const NodeId peer) const noexcept override {
    if (refuse_while_ready) return ContextState::Ready;
    const auto it = contexts.find({static_cast<int>(scope), peer});
    return it == contexts.end() ? ContextState::None : it->second.state;
  }
  Status next_counter(const SecurityContext& context, std::uint64_t& counter) noexcept override {
    counters_drawn.push_back(context);
    return inner_.next_counter(context, counter);
  }
  Status seal(const SecurityContext& context, const std::uint64_t counter, const ByteView aad,
              const ByteView plaintext, const MutableByteView ciphertext,
              std::array<std::uint8_t, kAeadTagSize>& tag) noexcept override {
    const SealKey key{static_cast<int>(context.scope), context.network, context.sender,
                      context.receiver, context.epoch, counter};
    if (!sealed.insert(key).second) nonce_reuse = true;
    return inner_.seal(context, counter, aad, plaintext, ciphertext, tag);
  }
  Status open(const SecurityContext& context, const std::uint64_t counter, const ByteView aad,
              const ByteView ciphertext, const std::array<std::uint8_t, kAeadTagSize>& tag,
              const MutableByteView plaintext) noexcept override {
    if (strict_rx) {
      const auto it = contexts.find({static_cast<int>(context.scope), context.sender});
      if (it == contexts.end() || !context_usable(it->second.state) ||
          it->second.rx_id != context.epoch) {
        return Status::error(StatusCode::AuthRequired, "TEST_UNKNOWN_CONTEXT");
      }
    }
    return inner_.open(context, counter, aad, ciphertext, tag, plaintext);
  }

  Status install(const ContextKeys& keys) noexcept override {
    const Status status = check_context_keys(keys);
    if (!status) return status;
    const std::pair<int, NodeId> slot{static_cast<int>(keys.scope), keys.peer};
    for (const auto& [other, entry] : contexts) {
      if (other != slot && entry.rx_id == keys.rx_context_id) {
        return Status::error(StatusCode::Conflict, "TEST_CONTEXT_ID_LIVE");
      }
    }
    contexts[slot] = Entry{ContextState::Ready, keys.tx_context_id, keys.rx_context_id};
    return Status::success();
  }
  Status retire(const SecurityScope scope, const NodeId peer) noexcept override {
    contexts.erase({static_cast<int>(scope), peer});
    return Status::success();
  }
  Status retire_all(const NodeId peer) noexcept override {
    for (auto it = contexts.begin(); it != contexts.end();) {
      it = it->first.second == peer ? contexts.erase(it) : std::next(it);
    }
    return Status::success();
  }
  // Test hook for states the installer never produces (Establishing) and for
  // the group scope, whose keys come from the GK schedule (P5), not install().
  void set_context(const SecurityScope scope, const NodeId peer, const Entry entry) {
    contexts[{static_cast<int>(scope), peer}] = entry;
  }

 private:
  TestSecurity inner_{};
};

// The handshake engine's side (P4-2 stand-in): one exchange yields matching
// contexts at both ends — a's tx id is b's rx id and vice versa.
void establish(SessionSecurity& a, const NodeId a_id, SessionSecurity& b, const NodeId b_id,
               const SecurityScope scope, const std::uint32_t id_chosen_by_a,
               const std::uint32_t id_chosen_by_b) {
  ContextKeys at_a{};
  at_a.scope = scope;
  at_a.network = kNet;
  at_a.peer = b_id;
  at_a.tx_context_id = id_chosen_by_b;
  at_a.rx_context_id = id_chosen_by_a;
  CHECK_OK(a.install(at_a));
  ContextKeys at_b{};
  at_b.scope = scope;
  at_b.network = kNet;
  at_b.peer = a_id;
  at_b.tx_context_id = id_chosen_by_a;
  at_b.rx_context_id = id_chosen_by_b;
  CHECK_OK(b.install(at_b));
}

// Every frame put on the simulated air, in order.
struct AirFrame {
  NodeId from;
  NodeId to;
  std::vector<std::uint8_t> bytes;
};
std::vector<AirFrame>* g_air = nullptr;
bool capture_frame(const SimNetwork::Pending& pending) {
  if (g_air != nullptr) g_air->push_back(AirFrame{pending.from, pending.to, pending.frame});
  return false;  // never drop
}

// Header of a captured frame (TestSecurity opens any context).
bool air_header(const AirFrame& frame, wire::Header& header) {
  TestSecurity reader;
  wire::LinkOpenedFrame opened{};
  if (!wire::open_link(ByteView{frame.bytes.data(), frame.bytes.size()}, frame.to, reader, opened)) {
    return false;
  }
  header = opened.header;
  return true;
}

std::size_t count_diag(const CapturingObserver& observer, const char* reason, const NodeId peer) {
  std::size_t count = 0;
  for (std::size_t i = 0; i < observer.diagnostics.size(); ++i) {
    if (observer.diagnostics[i] == reason && observer.diagnostic_peers[i] == peer) ++count;
  }
  return count;
}

NodeConfig node_config(const NodeId id) {
  NodeConfig config{};
  config.network = kNet;
  config.node = id;
  config.message_session = 100 + static_cast<std::uint32_t>(id);
  config.boot_incarnation = 0xB000 + static_cast<std::uint32_t>(id);
  config.route_generation = 1;
  config.link_epoch = 7;
  config.end_epoch = 9;
  config.route_advertisement_period_ms = 100;
  config.route_lifetime_ms = 1000;
  return config;
}

// Two directly linked nodes (1, 2) over any provider type.
template <class Provider>
struct Pair {
  SimNetwork net;
  Provider sec_a{};
  Provider sec_b{};
  CapturingObserver obs_a;
  CapturingObserver obs_b;
  SimRadio radio_a{net, 1};
  SimRadio radio_b{net, 2};
  SimReplyPort port_a{radio_a, 1, node_config(1).link_epoch};
  SimReplyPort port_b{radio_b, 2, node_config(2).link_epoch};
  std::unique_ptr<MeshNode> a;
  std::unique_ptr<MeshNode> b;
  std::vector<AirFrame> air;
  MonotonicMs now{0};

  Pair() {
    a = std::make_unique<MeshNode>(node_config(1), radio_a, sec_a, obs_a);
    b = std::make_unique<MeshNode>(node_config(2), radio_b, sec_b, obs_b);
    CHECK_OK(a->set_reply_peer_port(&port_a));
    CHECK_OK(b->set_reply_peer_port(&port_b));
    net.register_node(1, a.get());
    net.register_node(2, b.get());
    net.register_reply_port(1, &port_a);
    net.register_reply_port(2, &port_b);
    net.drop_frame = &capture_frame;
    net.connect(1, 2);
    CHECK_OK(a->start(now));
    CHECK_OK(b->start(now));
    CHECK_OK(a->add_neighbor(2, 1, now));
    CHECK_OK(b->add_neighbor(1, 1, now));
  }
  ~Pair() { net.drop_frame = nullptr; }

  void run(const MonotonicMs duration_ms) {
    g_air = &air;
    const MonotonicMs end = now + duration_ms;
    for (; now <= end; now += 5) {
      a->poll(now);
      b->poll(now);
      net.flush(now);
    }
    g_air = nullptr;
  }

  MessageId send(const char* text, const std::uint32_t lifetime_ms = 5000) {
    SendOptions options{};
    options.lifetime_ms = lifetime_ms;
    MessageId id{};
    CHECK_OK(a->send(2, ByteView{reinterpret_cast<const std::uint8_t*>(text), std::strlen(text)},
                     options, now, id));
    return id;
  }
};

bool received(const CapturingObserver& observer, const char* text) {
  const std::vector<std::uint8_t> expected(text, text + std::strlen(text));
  return std::find(observer.messages.begin(), observer.messages.end(), expected) !=
         observer.messages.end();
}

// --- (a) defaults -------------------------------------------------------------

void test_default_provider_reports_configured_values() {
  TestSecurity security;  // does not override the new hooks
  for (const SecurityScope scope : {SecurityScope::Link, SecurityScope::EndToEnd,
                                    SecurityScope::Group, SecurityScope::GroupLink}) {
    std::uint32_t epoch = 0x01020304;
    CHECK_OK(security.tx_epoch(scope, 5, epoch));
    CHECK(epoch == 0x01020304);
    CHECK(security.context_state(scope, 5) == ContextState::Ready);
  }
  // Scope values on the wire are fixed: Group stays 2 (nonce byte 0, key
  // derivation, golden vectors); the reserved GroupLink takes 3.
  CHECK(static_cast<int>(SecurityScope::Link) == 0);
  CHECK(static_cast<int>(SecurityScope::EndToEnd) == 1);
  CHECK(static_cast<int>(SecurityScope::Group) == 2);
  CHECK(static_cast<int>(SecurityScope::GroupLink) == 3);
  // Zero is None: a default-initialised state never claims a session.
  CHECK(ContextState{} == ContextState::None);
  CHECK(!context_usable(ContextState::None));
  CHECK(!context_usable(ContextState::Establishing));
  CHECK(context_usable(ContextState::Ready));
  CHECK(context_usable(ContextState::Rekeying));
}

// The same two-node exchange under TestSecurity (inherits the defaults) and
// under a provider that overrides both hooks with default behaviour: the
// air carries the same bytes in the same order, and no session statistic
// moves.
void test_default_hooks_keep_node_bytes_identical() {
  Pair<TestSecurity> baseline;
  baseline.send("same-bytes");
  baseline.run(600);
  Pair<ConfiguredEpochSecurity> hooked;
  hooked.send("same-bytes");
  hooked.run(600);

  CHECK(received(baseline.obs_b, "same-bytes"));
  CHECK(received(hooked.obs_b, "same-bytes"));
  CHECK(!baseline.air.empty());
  CHECK(baseline.air.size() == hooked.air.size());
  bool identical = baseline.air.size() == hooked.air.size();
  for (std::size_t i = 0; identical && i < baseline.air.size(); ++i) {
    identical = baseline.air[i].from == hooked.air[i].from &&
                baseline.air[i].to == hooked.air[i].to &&
                baseline.air[i].bytes == hooked.air[i].bytes;
  }
  CHECK(identical);
  // The configured epochs are what went on the air.
  for (const auto& frame : hooked.air) {
    wire::Header header{};
    CHECK(air_header(frame, header));
    CHECK(header.link_epoch == 7 && header.end_epoch == 9);
  }
  CHECK(hooked.sec_a.tx_epoch_calls > 0 && hooked.sec_b.tx_epoch_calls > 0);
  for (const MeshNode* node : {baseline.a.get(), baseline.b.get(), hooked.a.get(), hooked.b.get()}) {
    CHECK(node->session_stats().tx_deferred == 0);
    CHECK(node->session_stats().tx_unavailable == 0);
    CHECK(node->session_stats().rx_auth_required == 0);
  }
  CHECK(!baseline.obs_a.has_diag("SESSION_") && !hooked.obs_a.has_diag("SESSION_"));
}

// --- (c) V1-K10 ------------------------------------------------------------------

std::string read_text(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  std::ostringstream contents;
  contents << input.rdbuf();
  return contents.str();
}

// Value of a flat-JSON key (string contents or bare number), "" if absent.
std::string json_value(const std::string& text, const std::string& key) {
  const std::string quoted = "\"" + key + "\"";
  const std::size_t at = text.find(quoted);
  if (at == std::string::npos) return "";
  std::size_t cursor = text.find(':', at + quoted.size());
  if (cursor == std::string::npos) return "";
  ++cursor;
  while (cursor < text.size() && (text[cursor] == ' ' || text[cursor] == '\n')) ++cursor;
  if (cursor < text.size() && text[cursor] == '"') {
    const std::size_t end = text.find('"', cursor + 1);
    return end == std::string::npos ? "" : text.substr(cursor + 1, end - cursor - 1);
  }
  std::size_t end = cursor;
  while (end < text.size() && text[end] >= '0' && text[end] <= '9') ++end;
  return text.substr(cursor, end - cursor);
}

std::vector<std::uint8_t> hex_bytes(const std::string& hex) {
  std::vector<std::uint8_t> out;
  for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
    out.push_back(static_cast<std::uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
  }
  return out;
}

bool same(const std::vector<std::uint8_t>& expected, const wire::EncodedFrame& actual) {
  return expected.size() == actual.size &&
         std::equal(expected.begin(), expected.end(), actual.bytes.begin());
}

void test_v1_k10_golden_vectors_unchanged() {
  std::vector<std::filesystem::path> files;
  for (const auto& entry :
       std::filesystem::directory_iterator(std::filesystem::path(ROUTELOOM_GOLDEN_DIR) / "valid")) {
    if (entry.path().extension() == ".json") files.push_back(entry.path());
  }
  std::sort(files.begin(), files.end());
  CHECK(files.size() >= 6);
  std::size_t forwarded = 0;
  for (const auto& path : files) {
    const std::string text = read_text(path);
    const auto encoded = hex_bytes(json_value(text, "encoded_hex"));
    const auto payload = hex_bytes(json_value(text, "payload_hex"));
    CHECK(!encoded.empty());
    // Recover the plain frame from the golden bytes themselves.
    TestSecurity reader;
    wire::LinkOpenedFrame opened{};
    const NodeId next_hop = std::stoull(json_value(text, "next_hop"));
    CHECK_OK(wire::open_link(ByteView{encoded.data(), encoded.size()}, next_hop, reader, opened));
    wire::PlainFrame plain{};
    plain.header = opened.header;
    plain.header.link_counter = 0;
    plain.header.end_counter = 0;
    plain.payload_size = payload.size();
    std::copy(payload.begin(), payload.end(), plain.payload.begin());

    // Through the provider-epoch path with (1) inherited defaults and (2)
    // explicit default-behaving hooks: both reproduce the golden bytes.
    TestSecurity inherited;
    wire::EncodedFrame out1{};
    CHECK_OK(wire::encode_new(plain, inherited, out1));
    CHECK(same(encoded, out1));
    ConfiguredEpochSecurity hooked;
    wire::EncodedFrame out2{};
    CHECK_OK(wire::encode_new(plain, hooked, out2));
    CHECK(same(encoded, out2));
    CHECK(hooked.tx_epoch_calls == ((plain.header.flags & wire::kFlagEndProtected) != 0 ? 2U : 1U));

    const std::string fwd_hex = json_value(text, "fwd_encoded_hex");
    if (!fwd_hex.empty()) {
      ++forwarded;
      const auto expected_fwd = hex_bytes(fwd_hex);
      const NodeId local = std::stoull(json_value(text, "fwd_local_node"));
      const NodeId next = std::stoull(json_value(text, "fwd_next_hop"));
      const auto budget = static_cast<std::uint32_t>(
          std::stoul(json_value(text, "fwd_remaining_deadline_ms")));
      const std::string fwd_epoch = json_value(text, "fwd_link_epoch");
      const auto epoch = static_cast<std::uint32_t>(
          std::stoul(fwd_epoch.empty() ? json_value(text, "link_epoch") : fwd_epoch));
      ConfiguredEpochSecurity forwarder;
      wire::EncodedFrame out3{};
      CHECK_OK(wire::forward(opened, local, next, epoch, budget, forwarder, out3));
      CHECK(same(expected_fwd, out3));
      CHECK(forwarder.tx_epoch_calls == 1);
    }
  }
  CHECK(forwarded >= 1);
}

// --- (b) session provider: wire level ------------------------------------------

wire::PlainFrame data_frame(const std::uint8_t flags) {
  wire::PlainFrame plain{};
  plain.header.type = FrameType::Data;
  plain.header.flags = flags;
  plain.header.delivery = DeliveryClass::Reliable;
  plain.header.hop_remaining = 4;
  plain.header.network = kNet;
  plain.header.origin = 1;
  plain.header.destination = 3;
  plain.header.previous_hop = 1;
  plain.header.next_hop = 2;
  plain.header.message = MessageId{7, 42};
  plain.header.remaining_deadline_ms = 5000;
  plain.header.original_lifetime_ms = 5000;
  plain.header.link_epoch = 7;
  plain.header.end_epoch = 9;
  plain.payload_size = 4;
  return plain;
}

void test_wire_refusal_draws_no_counter() {
  SessionSecurity security;
  wire::EncodedFrame out{};
  // No link context: refused before any counter.
  auto status = wire::encode_new(data_frame(wire::kFlagEndProtected), security, out);
  CHECK(status.code == StatusCode::AuthRequired);
  CHECK(security.counters_drawn.empty() && security.sealed.empty());
  // Link but no end context: still nothing drawn (both epochs precede counters).
  security.set_context(SecurityScope::Link, 2, {ContextState::Ready, 0x0A0A0001, 0x0B0B0001});
  status = wire::encode_new(data_frame(wire::kFlagEndProtected), security, out);
  CHECK(status.code == StatusCode::AuthRequired);
  CHECK(security.counters_drawn.empty() && security.sealed.empty());
  // A link-only frame never asks for an end context.
  CHECK_OK(wire::encode_new(data_frame(0), security, out));
  // Both present: the context ids are what goes on the wire.
  security.set_context(SecurityScope::EndToEnd, 3, {ContextState::Rekeying, 0x0C0C0002, 0x0D0D0002});
  CHECK_OK(wire::encode_new(data_frame(wire::kFlagEndProtected), security, out));
  TestSecurity reader;
  wire::LinkOpenedFrame opened{};
  CHECK_OK(wire::open_link(out.view(), 2, reader, opened));
  CHECK(opened.header.link_epoch == 0x0A0A0001);
  CHECK(opened.header.end_epoch == 0x0C0C0002);

  // forward(): the configured epoch argument is replaced by the outgoing
  // hop's context id; no context -> refused, no counter.
  SessionSecurity relay;
  const std::size_t before = relay.counters_drawn.size();
  wire::LinkOpenedFrame at_relay = opened;
  CHECK(wire::forward(at_relay, 2, 3, 7, 1000, relay, out).code == StatusCode::AuthRequired);
  CHECK(relay.counters_drawn.size() == before);
  relay.set_context(SecurityScope::Link, 3, {ContextState::Ready, 0x0E0E0003, 0x0F0F0003});
  CHECK_OK(wire::forward(at_relay, 2, 3, 7, 1000, relay, out));
  wire::LinkOpenedFrame at_next{};
  CHECK_OK(wire::open_link(out.view(), 3, reader, at_next));
  CHECK(at_next.header.link_epoch == 0x0E0E0003);
  CHECK(at_next.header.end_epoch == 0x0C0C0002);  // end layer untouched

  // seal_group(): the group context (receiver = site group domain) is asked
  // for the end epoch before the group counter is drawn.
  SessionSecurity group;
  wire::PlainFrame g{};
  g.header.type = FrameType::GroupData;
  g.header.flags = wire::kFlagEndProtected;
  g.header.hop_remaining = 4;
  g.header.network = kNet;
  g.header.origin = 1;
  g.header.destination = group_address(7);
  g.header.previous_hop = 1;
  g.header.next_hop = 1;
  g.header.message = MessageId{7, kGroupSequenceFlag | 1U};
  g.header.remaining_deadline_ms = 1000;
  g.header.original_lifetime_ms = 1000;
  g.header.end_epoch = 9;
  g.payload_size = 3;
  wire::LinkOpenedFrame sealed{};
  CHECK(wire::seal_group(g, 1, group, sealed).code == StatusCode::AuthRequired);
  CHECK(group.counters_drawn.empty());
  group.set_context(SecurityScope::Group, kBroadcastNodeId, {ContextState::Ready, 0x60000001, 0});
  CHECK_OK(wire::seal_group(g, 1, group, sealed));
  CHECK(sealed.header.end_epoch == 0x60000001);
  CHECK(group.counters_drawn.size() == 1 && group.counters_drawn[0].scope == SecurityScope::Group &&
        group.counters_drawn[0].epoch == 0x60000001);
}

void test_context_keys_checks() {
  ContextKeys keys{};
  keys.scope = SecurityScope::Link;
  keys.network = kNet;
  keys.peer = 2;
  keys.tx_context_id = 1;
  keys.rx_context_id = 2;
  CHECK_OK(check_context_keys(keys));
  keys.scope = SecurityScope::EndToEnd;
  CHECK_OK(check_context_keys(keys));
  // Group keys come from the GK schedule, never from a pairwise handshake.
  for (const SecurityScope scope : {SecurityScope::Group, SecurityScope::GroupLink}) {
    ContextKeys group = keys;
    group.scope = scope;
    CHECK(check_context_keys(group).code == StatusCode::Unsupported);
  }
  ContextKeys bad = keys;
  bad.peer = kInvalidNodeId;
  CHECK(check_context_keys(bad).code == StatusCode::InvalidArgument);
  bad = keys;
  bad.peer = kBroadcastNodeId;
  CHECK(check_context_keys(bad).code == StatusCode::InvalidArgument);
  bad = keys;
  bad.network = 0;
  CHECK(check_context_keys(bad).code == StatusCode::InvalidArgument);
  bad = keys;
  bad.tx_context_id = 0;
  CHECK(check_context_keys(bad).code == StatusCode::InvalidArgument);
  bad = keys;
  bad.rx_context_id = 0;
  CHECK(check_context_keys(bad).code == StatusCode::InvalidArgument);

  // The test installer honours the documented contract: a live rx id is
  // not reused by another context, and re-installing a slot replaces it.
  SessionSecurity installer;
  CHECK_OK(installer.install(keys));
  ContextKeys other = keys;
  other.peer = 3;
  CHECK(installer.install(other).code == StatusCode::Conflict);
  other.rx_context_id = 99;
  CHECK_OK(installer.install(other));
  CHECK(installer.context_state(SecurityScope::EndToEnd, 3) == ContextState::Ready);
  CHECK_OK(installer.retire(SecurityScope::EndToEnd, 3));
  CHECK(installer.context_state(SecurityScope::EndToEnd, 3) == ContextState::None);
  CHECK_OK(installer.retire_all(2));
  CHECK(installer.contexts.empty());
}

// --- (b) session provider: node level -----------------------------------------

void establish_all(Pair<SessionSecurity>& pair, const std::uint32_t base) {
  establish(pair.sec_a, 1, pair.sec_b, 2, SecurityScope::Link, base + 0x11, base + 0x21);
  pair.port_a.set_rx_context(2, base + 0x11);
  pair.port_b.set_rx_context(1, base + 0x21);
  establish(pair.sec_a, 1, pair.sec_b, 2, SecurityScope::EndToEnd, base + 0x12, base + 0x22);
}

// Epochs come from the provider: A stamps the ids B chose, B those A chose.
void check_air_epochs(const std::vector<AirFrame>& air, const std::size_t from_index,
                      const std::uint32_t base) {
  std::size_t checked = 0;
  for (std::size_t i = from_index; i < air.size(); ++i) {
    wire::Header header{};
    CHECK(air_header(air[i], header));
    const bool from_a = air[i].from == 1;
    CHECK(header.link_epoch == base + (from_a ? 0x21U : 0x11U));
    if ((header.flags & wire::kFlagEndProtected) != 0) {
      CHECK(header.end_epoch == base + (from_a ? 0x22U : 0x12U));
    }
    ++checked;
  }
  CHECK(checked > 0);
}

void test_node_uses_provider_epochs() {
  Pair<SessionSecurity> pair;
  pair.sec_a.strict_rx = true;
  pair.sec_b.strict_rx = true;
  establish_all(pair, 0x10000000);
  const MessageId id = pair.send("provider-epochs");
  pair.run(600);
  CHECK(received(pair.obs_b, "provider-epochs"));
  CHECK(pair.a->delivery(id).state == DeliveryState::Delivered);
  check_air_epochs(pair.air, 0, 0x10000000);
  CHECK(!pair.sec_a.nonce_reuse && !pair.sec_b.nonce_reuse);
  for (const MeshNode* node : {pair.a.get(), pair.b.get()}) {
    CHECK(node->session_stats().tx_deferred == 0);
    CHECK(node->session_stats().rx_auth_required == 0);
  }
}

void test_node_defers_until_session_installed() {
  Pair<SessionSecurity> pair;
  pair.sec_a.strict_rx = true;
  pair.sec_b.strict_rx = true;
  const MessageId id = pair.send("after-handshake", 5000);
  pair.run(300);
  // Nothing reached the air and no counter was drawn: every job waits.
  CHECK(pair.air.empty());
  CHECK(pair.sec_a.counters_drawn.empty() && pair.sec_b.counters_drawn.empty());
  CHECK(!received(pair.obs_b, "after-handshake"));
  CHECK(pair.a->delivery(id).state == DeliveryState::Queued);
  // Diagnosed once per held job (not once per poll), naming the peer.
  const std::uint32_t deferred = pair.a->session_stats().tx_deferred;
  CHECK(deferred >= 1);
  CHECK(count_diag(pair.obs_a, "SESSION_REQUIRED", 2) == deferred);
  CHECK(!pair.obs_a.has_diag("SESSION_PENDING"));
  pair.run(100);
  CHECK(pair.a->session_stats().tx_deferred >= deferred);
  CHECK(count_diag(pair.obs_a, "SESSION_REQUIRED", 2) == pair.a->session_stats().tx_deferred);

  // The handshake engine installs the contexts: the held DATA goes out
  // under the new context ids and is delivered.
  establish_all(pair, 0x20000000);
  pair.run(600);
  CHECK(received(pair.obs_b, "after-handshake"));
  CHECK(pair.a->delivery(id).state == DeliveryState::Delivered);
  CHECK(!pair.air.empty());
  check_air_epochs(pair.air, 0, 0x20000000);
  CHECK(!pair.sec_a.nonce_reuse && !pair.sec_b.nonce_reuse);
}

void test_node_pending_session_times_out() {
  Pair<SessionSecurity> pair;
  // A handshake is in flight for every context A needs, and never finishes.
  pair.sec_a.set_context(SecurityScope::Link, 2, {ContextState::Establishing, 0, 0});
  pair.sec_a.set_context(SecurityScope::EndToEnd, 2, {ContextState::Establishing, 0, 0});
  const MessageId id = pair.send("never", 400);
  pair.run(1500);
  // Held, diagnosed as pending (not as a new session request), then bounded
  // by the deadline: control jobs fail SESSION_UNAVAILABLE, the delivery
  // expires, and no frame from A ever reached the air.
  CHECK(count_diag(pair.obs_a, "SESSION_PENDING", 2) >= 1);
  CHECK(count_diag(pair.obs_a, "SESSION_REQUIRED", 2) == 0);
  CHECK(pair.a->session_stats().tx_unavailable >= 1);
  CHECK(pair.a->session_stats().tx_unavailable <= pair.a->session_stats().tx_deferred);
  const auto result = pair.a->delivery(id);
  CHECK(result.state == DeliveryState::Expired || result.state == DeliveryState::Failed);
  for (const auto& frame : pair.air) CHECK(frame.from != 1);
  CHECK(pair.sec_a.counters_drawn.empty());
  CHECK(!received(pair.obs_b, "never"));
}

void test_node_rekey_and_retire() {
  Pair<SessionSecurity> pair;
  pair.sec_a.strict_rx = true;
  pair.sec_b.strict_rx = true;
  establish_all(pair, 0x30000000);
  const MessageId first = pair.send("first");
  pair.run(400);
  CHECK(pair.a->delivery(first).state == DeliveryState::Delivered);
  check_air_epochs(pair.air, 0, 0x30000000);

  // Rekey (RLRES1 stand-in): both ends move to new context ids; the new key
  // restarts its counters at 0, which is safe only because the key is new.
  // (Low 16 bits differ too: TestSecurity keys its counters by u16 epoch.)
  establish_all(pair, 0x40000100);
  const std::size_t mark = pair.air.size();
  const MessageId second = pair.send("second");
  pair.run(400);
  CHECK(pair.a->delivery(second).state == DeliveryState::Delivered);
  CHECK(received(pair.obs_b, "second"));
  CHECK(pair.air.size() > mark);
  check_air_epochs(pair.air, mark, 0x40000100);
  CHECK(!pair.sec_a.nonce_reuse && !pair.sec_b.nonce_reuse);
  bool restarted = false;
  for (const auto& key : pair.sec_a.sealed) {
    if (std::get<4>(key) == 0x40000121U && std::get<5>(key) == 0) restarted = true;
  }
  CHECK(restarted);

  // Revocation (retire_all, sdk-v1/04 §5): the node holds new traffic again.
  pair.sec_a.retire_all(2);
  CHECK(pair.sec_a.context_state(SecurityScope::Link, 2) == ContextState::None);
  const std::uint32_t before = pair.a->session_stats().tx_deferred;
  const std::size_t sent_before = pair.air.size();
  const MessageId third = pair.send("third");
  pair.run(200);
  CHECK(pair.a->session_stats().tx_deferred > before);
  CHECK(!received(pair.obs_b, "third"));
  CHECK(pair.a->delivery(third).state != DeliveryState::Delivered);
  for (std::size_t i = sent_before; i < pair.air.size(); ++i) CHECK(pair.air[i].from != 1);
}

void test_node_counts_unknown_rx_context() {
  Pair<SessionSecurity> pair;
  // A believes it has contexts with B; B has none (it rebooted, 03 §4.3):
  // B refuses the frames with AuthRequired, counts them, keeps running.
  pair.sec_b.strict_rx = true;
  pair.sec_a.set_context(SecurityScope::Link, 2, {ContextState::Ready, 0x51, 0x52});
  pair.sec_a.set_context(SecurityScope::EndToEnd, 2, {ContextState::Ready, 0x53, 0x54});
  pair.send("to-a-rebooted-peer");
  pair.run(300);
  CHECK(!pair.air.empty());
  CHECK(pair.b->session_stats().rx_auth_required >= 1);
  CHECK(pair.obs_b.has_diag("TEST_UNKNOWN_CONTEXT"));
  CHECK(!received(pair.obs_b, "to-a-rebooted-peer"));
  CHECK(pair.a->session_stats().rx_auth_required == 0);
}

void test_refusal_with_usable_context_is_a_failure() {
  // AuthRequired while context_state says Ready is not "no session yet":
  // the job fails exactly as any seal failure did before (no deferral).
  Pair<SessionSecurity> pair;
  pair.sec_a.refuse_while_ready = true;
  const MessageId id = pair.send("lost-key");
  pair.run(50);
  CHECK(pair.a->session_stats().tx_deferred == 0);
  CHECK(!pair.obs_a.has_diag("SESSION_REQUIRED") && !pair.obs_a.has_diag("SESSION_PENDING"));
  CHECK(pair.obs_a.has_diag("TEST_KEY_LOST") ||
        std::strcmp(pair.a->delivery(id).reason, "TEST_KEY_LOST") == 0);
  CHECK(pair.sec_a.counters_drawn.empty());
}

}  // namespace

int main() {
  test_default_provider_reports_configured_values();
  test_default_hooks_keep_node_bytes_identical();
  test_v1_k10_golden_vectors_unchanged();
  test_wire_refusal_draws_no_counter();
  test_context_keys_checks();
  test_node_uses_provider_epochs();
  test_node_defers_until_session_installed();
  test_node_pending_session_times_out();
  test_node_rekey_and_retire();
  test_node_counts_unknown_rx_context();
  test_refusal_with_usable_context_is_a_failure();
  if (failures != 0) {
    std::fprintf(stderr, "%d session checks failed\n", failures);
    return 1;
  }
  std::puts("RouteLoom session provider tests passed");
  return 0;
}
