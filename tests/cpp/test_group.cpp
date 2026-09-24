// Group delivery + per-source ordering (docs/design/sdk-v1/group-delivery.md).
//
// unit : payload codecs and golden parity, the group security scope, small
//        gateway-scoped meshes (delivery, membership, reports, repair after
//        loss, dead nodes, NOT_CHILD de-duplication, capacity/admission),
//        group ordering (reorder, skip, late, unordered never held) and
//        unicast ordering (predecessor wait, bounded by its lifetime).
// scale: the 100-node product site (10x10 grid, gateway on a wall, 5 s /
//        90 s timers): an Urgent ALARM to ALL, the same under injected loss
//        with repair, and a 20-message burst with concurrent uplink traffic —
//        airtime measured against the §14 envelope and the group budget.
//
// Usage: routeloom_group_tests [unit|scale]  (no argument: both)

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "routeloom/group.hpp"
#include "routeloom/group_replay.hpp"
#include "routeloom/node.hpp"
#include "routeloom/routing.hpp"
#include "routeloom/types.hpp"
#include "routeloom/wire.hpp"

#include "test_sim.hpp"

namespace {

int failures = 0;
#define CHECK(expr) do { if (!(expr)) { std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__, #expr); ++failures; } } while (false)
#define CHECK_OK(expr) do { const auto _status = (expr); if (!_status.ok()) { std::fprintf(stderr, "STATUS failed %s:%d: %s (%s)\n", __FILE__, __LINE__, #expr, _status.detail); ++failures; } } while (false)

using namespace routeloom;
using routeloom_test::SimNetwork;
using routeloom_test::SimWorld;

#ifndef ROUTELOOM_GOLDEN_DIR
#define ROUTELOOM_GOLDEN_DIR "protocol/golden"
#endif

constexpr std::uint32_t kFastPeriodMs = 500;
constexpr std::uint32_t kFastLifetimeMs = 9000;
static_assert(scoped_lifetime_sufficient(kFastPeriodMs, kFastLifetimeMs,
                                         kScopedDefaultRefreshTicks),
              "fast test timers satisfy the scoped lease rule");

// §14 airtime model (radio.md §9/§14): (encoded bytes + fixed MAC/LR
// preamble/MAC ACK byte equivalent) x 32 us at LR 250 kbps.
constexpr std::uint64_t kUsPerByte = 32;
std::uint64_t airtime_us(const SimNetwork::TxTally& tally) {
  return (tally.bytes + tally.frames * kTxFrameFixedCostBytes) * kUsPerByte;
}

void scoped_profile(SimWorld& w, const NodeId gateway, const std::uint32_t period_ms,
                    const std::uint32_t lifetime_ms) {
  w.configure = [=](NodeConfig& config) {
    config.route_gateways = {gateway, kInvalidNodeId};
    config.route_advertisement_period_ms = period_ms;
    config.route_lifetime_ms = lifetime_ms;
    config.route_refresh_ticks = kScopedDefaultRefreshTicks;
  };
}

// ---------------------------------------------------------------------------
// Golden helpers
// ---------------------------------------------------------------------------

std::string read_file(const std::string& path) {
  std::ifstream input(path, std::ios::binary);
  std::ostringstream contents;
  contents << input.rdbuf();
  return contents.str();
}

std::string json_string(const std::string& text, const std::string& key) {
  const std::string needle = "\"" + key + "\": \"";
  const auto at = text.find(needle);
  if (at == std::string::npos) return {};
  const auto begin = at + needle.size();
  return text.substr(begin, text.find('"', begin) - begin);
}

std::string hex(const std::uint8_t* data, const std::size_t size) {
  static const char* digits = "0123456789abcdef";
  std::string out;
  for (std::size_t i = 0; i < size; ++i) {
    out.push_back(digits[data[i] >> 4U]);
    out.push_back(digits[data[i] & 0x0FU]);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Unit: codecs, golden parity, security scope
// ---------------------------------------------------------------------------

void test_group_addressing() {
  CHECK(group_address(kGroupAll) == kBroadcastNodeId);
  CHECK(is_group_address(group_address(1)));
  CHECK(!is_group_address(kGroupAddressBase));  // group 0 reserved
  CHECK(group_of_address(group_address(0x1234)) == 0x1234);
  CHECK(reserved_node_id(kInvalidNodeId));
  CHECK(reserved_node_id(kGroupAddressBase));
  CHECK(reserved_node_id(kBroadcastNodeId));
  CHECK(!reserved_node_id(kGroupAddressBase - 1));
  CHECK(is_group_sequence(kGroupSequenceFlag | 1));
  CHECK(!is_group_sequence(kGroupSequenceFlag));
  CHECK(!is_group_sequence(1));
  CHECK(!is_group_sequence(kGroupSequenceFlag | (1ULL << 32)));
  CHECK(group_stream_seq(kGroupSequenceFlag | 77) == 77);

  // A node can never carry a group address as its identity.
  SimWorld w;
  w.configure = [](NodeConfig& config) { config.node = kGroupAddressBase | 5; };
  w.add(3);
  CHECK(!w.at(3)->start(0).ok());
}

void test_group_data_codec() {
  std::array<std::uint8_t, kMaxApplicationPayload> buffer{};
  std::size_t written = 0;
  const std::uint8_t app[] = {'A', 'L', 'A', 'R', 'M'};
  GroupDataHeader head{};
  head.ordered = true;
  head.priority = Priority::Urgent;
  CHECK_OK(encode_group_data(head, ByteView{app, sizeof(app)},
                             MutableByteView{buffer.data(), buffer.size()}, written));
  CHECK(written == 1 + sizeof(app));
  CHECK(buffer[0] == 0x07);
  GroupDataHeader decoded{};
  ByteView out{};
  CHECK_OK(decode_group_data(ByteView{buffer.data(), written}, decoded, out));
  CHECK(decoded.ordered && decoded.priority == Priority::Urgent);
  CHECK(out.size == sizeof(app) && std::memcmp(out.data, app, sizeof(app)) == 0);
  // Reserved flag bits, empty payload and oversize input are refused.
  buffer[0] = 0x08;
  CHECK(!decode_group_data(ByteView{buffer.data(), written}, decoded, out).ok());
  CHECK(!decode_group_data(ByteView{buffer.data(), 0}, decoded, out).ok());
  std::array<std::uint8_t, kGroupPayloadMax + 1> big{};
  CHECK(!encode_group_data(head, ByteView{big.data(), big.size()},
                           MutableByteView{buffer.data(), buffer.size()}, written)
             .ok());
  CHECK_OK(encode_group_data(head, ByteView{big.data(), kGroupPayloadMax},
                             MutableByteView{buffer.data(), buffer.size()}, written));
  CHECK(written == kMaxApplicationPayload);
}

void test_group_report_codec() {
  GroupReportPayload report{};
  report.key = MessageKey{1, MessageId{101, kGroupSequenceFlag | 3}};
  report.round = 1;
  report.flags = kGroupReportTruncated;
  report.delivered = 40;
  report.nonmember = 3;
  report.missing_total = 5;
  report.missing_count = 2;
  report.missing[0] = 11;
  report.missing[1] = 12;
  std::array<std::uint8_t, kMaxApplicationPayload> buffer{};
  std::size_t written = 0;
  CHECK_OK(encode_group_report(report, MutableByteView{buffer.data(), buffer.size()}, written));
  CHECK(written == kGroupReportFixedBytes + 16);
  GroupReportPayload decoded{};
  CHECK_OK(decode_group_report(ByteView{buffer.data(), written}, decoded));
  CHECK(decoded.key == report.key && decoded.round == 1 && decoded.delivered == 40 &&
        decoded.nonmember == 3 && decoded.missing_total == 5 && decoded.missing_count == 2 &&
        decoded.missing[0] == 11 && decoded.missing[1] == 12);
  // Exact length for missing_count.
  CHECK(!decode_group_report(ByteView{buffer.data(), written - 1}, decoded).ok());
  CHECK(!decode_group_report(ByteView{buffer.data(), kGroupReportFixedBytes - 1}, decoded).ok());
  // Flag / count consistency is enforced on both sides.
  GroupReportPayload bad = report;
  bad.flags = 0;  // missing_total > count but not TRUNCATED
  CHECK(!encode_group_report(bad, MutableByteView{buffer.data(), buffer.size()}, written).ok());
  bad = report;
  bad.flags = kGroupReportNotChild;  // NOT_CHILD with counts
  CHECK(!encode_group_report(bad, MutableByteView{buffer.data(), buffer.size()}, written).ok());
  bad = report;
  bad.key.id.sequence = 3;  // not a group stream id
  CHECK(!encode_group_report(bad, MutableByteView{buffer.data(), buffer.size()}, written).ok());
  bad = report;
  bad.missing[1] = kBroadcastNodeId;
  CHECK(!encode_group_report(bad, MutableByteView{buffer.data(), buffer.size()}, written).ok());
  bad = report;
  bad.missing_count = static_cast<std::uint8_t>(kGroupReportMissingMax + 1);
  CHECK(!encode_group_report(bad, MutableByteView{buffer.data(), buffer.size()}, written).ok());
  // Wire-level mutation: a reserved flag bit on the encoded bytes.
  CHECK_OK(encode_group_report(report, MutableByteView{buffer.data(), buffer.size()}, written));
  buffer[21] |= 0x80;
  CHECK(!decode_group_report(ByteView{buffer.data(), written}, decoded).ok());
}

void test_group_golden_payloads() {
  // The Rust generator (host/routeloom-wire/examples/gen_golden.rs) wrote
  // these payloads with its own codec; the C++ encoders must match them.
  const std::string dir = ROUTELOOM_GOLDEN_DIR;
  const std::string data_json = read_file(dir + "/valid/group_data.json");
  CHECK(!data_json.empty());
  std::array<std::uint8_t, kMaxApplicationPayload> buffer{};
  std::size_t written = 0;
  const char app[] = "PUMP3 OVERTEMP";
  GroupDataHeader head{};
  head.ordered = true;
  head.priority = Priority::Urgent;
  CHECK_OK(encode_group_data(head,
                             ByteView{reinterpret_cast<const std::uint8_t*>(app), sizeof(app) - 1},
                             MutableByteView{buffer.data(), buffer.size()}, written));
  CHECK(json_string(data_json, "payload_hex") == hex(buffer.data(), written));

  const std::string report_json = read_file(dir + "/valid/group_report.json");
  CHECK(!report_json.empty());
  GroupReportPayload report{};
  report.key = MessageKey{1, MessageId{101, kGroupSequenceFlag | 3}};
  report.round = 1;
  report.flags = kGroupReportTruncated;
  report.delivered = 40;
  report.nonmember = 3;
  report.missing_total = 5;
  report.missing_count = 2;
  report.missing[0] = 11;
  report.missing[1] = 12;
  CHECK_OK(encode_group_report(report, MutableByteView{buffer.data(), buffer.size()}, written));
  CHECK(json_string(report_json, "payload_hex") == hex(buffer.data(), written));
}

// Records every SecurityContext the wire layer asks for.
class ScopeRecorder final : public SecurityProvider {
 public:
  bool ready() const noexcept override { return true; }
  Status next_counter(const SecurityContext& context, std::uint64_t& counter) noexcept override {
    contexts.push_back(context);
    return inner.next_counter(context, counter);
  }
  Status seal(const SecurityContext& context, std::uint64_t counter, ByteView aad,
              ByteView plaintext, MutableByteView ciphertext,
              std::array<std::uint8_t, kAeadTagSize>& tag) noexcept override {
    return inner.seal(context, counter, aad, plaintext, ciphertext, tag);
  }
  Status open(const SecurityContext& context, std::uint64_t counter, ByteView aad,
              ByteView ciphertext, const std::array<std::uint8_t, kAeadTagSize>& tag,
              MutableByteView plaintext) noexcept override {
    contexts.push_back(context);
    return inner.open(context, counter, aad, ciphertext, tag, plaintext);
  }
  routeloom_test::TestSecurity inner;
  std::vector<SecurityContext> contexts;
};

void test_group_security_scope() {
  wire::PlainFrame plain{};
  plain.header.type = FrameType::GroupData;
  plain.header.flags = wire::kFlagEndProtected;
  plain.header.delivery = DeliveryClass::Reliable;
  plain.header.hop_remaining = 10;
  plain.header.network = 1;
  plain.header.origin = 1;
  plain.header.destination = group_address(7);
  plain.header.previous_hop = 1;
  plain.header.next_hop = 1;
  plain.header.message = MessageId{101, kGroupSequenceFlag | 1};
  plain.header.remaining_deadline_ms = 5000;
  plain.header.original_lifetime_ms = 5000;
  plain.header.link_epoch = 1;
  plain.header.end_epoch = 9;
  plain.payload[0] = 0x02;  // Normal priority, unordered
  plain.payload[1] = 'x';
  plain.payload_size = 2;

  ScopeRecorder source;
  wire::LinkOpenedFrame sealed{};
  CHECK_OK(wire::seal_group(plain, 1, source, sealed));
  CHECK(source.contexts.size() == 1);
  CHECK(source.contexts[0].scope == SecurityScope::Group);
  // The key domain is the sender's site-group context, not the destination
  // group (which the end AAD authenticates — see the retarget check below).
  CHECK(source.contexts[0].sender == 1 && source.contexts[0].receiver == kBroadcastNodeId &&
        source.contexts[0].epoch == 9);
  // Shaped like a frame the source received: forward() spends one hop.
  CHECK(sealed.header.hop_remaining == 11 && sealed.header.next_hop == 1);
  // Only the source may seal its own group frame; non-group frames refused.
  CHECK(!wire::seal_group(plain, 2, source, sealed).ok());
  wire::PlainFrame unicast = plain;
  unicast.header.type = FrameType::Data;
  CHECK(!wire::seal_group(unicast, 1, source, sealed).ok());
  CHECK_OK(wire::seal_group(plain, 1, source, sealed));

  // Two children get link re-wraps of ONE end ciphertext (same end counter).
  wire::EncodedFrame to_a{};
  wire::EncodedFrame to_b{};
  CHECK_OK(wire::forward(sealed, 1, 2, 1, 5000, source.inner, to_a));
  CHECK_OK(wire::forward(sealed, 1, 3, 1, 5000, source.inner, to_b));
  routeloom_test::TestSecurity rx_a;
  routeloom_test::TestSecurity rx_b;
  wire::LinkOpenedFrame at_a{};
  wire::LinkOpenedFrame at_b{};
  CHECK_OK(wire::open_link(to_a.view(), 2, rx_a, at_a));
  CHECK_OK(wire::open_link(to_b.view(), 3, rx_b, at_b));
  CHECK(at_a.header.end_counter == at_b.header.end_counter);
  CHECK(at_a.header.hop_remaining == 10);
  ScopeRecorder opener;
  wire::PlainFrame out{};
  CHECK_OK(wire::open_group(at_a, opener, out));
  CHECK(opener.contexts.back().scope == SecurityScope::Group);
  CHECK(out.payload_size == 2 && out.payload[1] == 'x');
  // A second open of the same (sender, group, epoch, counter) is a replay.
  CHECK(wire::open_group(at_a, opener, out).code == StatusCode::ReplayRejected);
  // Unicast open_end never accepts a group frame; a different group address
  // (end AAD) or group scope confusion fails authentication.
  routeloom_test::TestSecurity plain_rx;
  CHECK(wire::open_end(at_b, 3, plain_rx, out).code == StatusCode::AuthorizationFailed);
  wire::LinkOpenedFrame retargeted = at_b;
  retargeted.header.destination = group_address(8);
  CHECK(!wire::open_group(retargeted, plain_rx, out).ok());
  wire::LinkOpenedFrame as_unicast = at_b;
  as_unicast.header.type = FrameType::Data;
  CHECK(!wire::open_group(as_unicast, plain_rx, out).ok());
}

void test_group_replay_table() {
  // The bounded RAM receive window the development PSK provider uses for
  // SecurityScope::Group (group_replay.hpp).
  GroupReplayTable table;
  const SecurityContext g1{SecurityScope::Group, 1, 10, group_address(7), 5};
  CHECK_OK(table.accept(g1, 100));
  CHECK(table.accept(g1, 100).code == StatusCode::ReplayRejected);  // exact replay
  CHECK_OK(table.accept(g1, 99));                                    // in-window straggler
  CHECK(table.accept(g1, 99).code == StatusCode::ReplayRejected);
  CHECK_OK(table.accept(g1, 100 + GroupReplayTable::kWindow));       // slides the window
  CHECK(table.accept(g1, 100).code == StatusCode::ReplayRejected);   // fell out: refused
  CHECK(table.replays() == 3);
  // A different group or sender is a different context.
  CHECK_OK(table.accept(SecurityContext{SecurityScope::Group, 1, 10, group_address(8), 5}, 100));
  CHECK_OK(table.accept(SecurityContext{SecurityScope::Group, 1, 11, group_address(7), 5}, 100));
  // Sender reboot: a newer epoch restarts the window, an older one is refused.
  const SecurityContext rebooted{SecurityScope::Group, 1, 10, group_address(7), 6};
  CHECK_OK(table.accept(rebooted, 0));
  CHECK(table.accept(g1, 500).code == StatusCode::ReplayRejected);
  CHECK(table.stale_epochs() == 1);
  // Only group contexts.
  CHECK(!table.accept(SecurityContext{SecurityScope::EndToEnd, 1, 10, 20, 5}, 1).ok());
  // Bounded: a new pair beyond capacity is refused, never admitted by
  // evicting (eviction would re-open the evicted pair to replay).
  GroupReplayTable full;
  for (std::size_t i = 0; i < GroupReplayTable::kCapacity; ++i) {
    CHECK_OK(full.accept(
        SecurityContext{SecurityScope::Group, 1, 100 + i, group_address(1), 1}, 0));
  }
  CHECK(full.size() == GroupReplayTable::kCapacity);
  const auto refused =
      full.accept(SecurityContext{SecurityScope::Group, 1, 999, group_address(1), 1}, 0);
  CHECK(refused.code == StatusCode::NoCapacity);
  CHECK(full.capacity_refusals() == 1);
  CHECK(full.accept(SecurityContext{SecurityScope::Group, 1, 100, group_address(1), 1}, 0).code ==
        StatusCode::ReplayRejected);  // existing pairs keep their state
}

void test_many_groups_share_one_sender_context() {
  // Regression: every node opens every GROUP_DATA it relays, member or not,
  // so the replay table must not grow with the number of groups a site uses.
  // One sender addressing more groups than the table holds stays one entry,
  // with distinct counters under its single key.
  ScopeRecorder source;
  GroupReplayTable table;
  const std::size_t groups = GroupReplayTable::kCapacity + 8;
  for (std::size_t i = 0; i < groups; ++i) {
    wire::PlainFrame plain{};
    plain.header.type = FrameType::GroupData;
    plain.header.flags = wire::kFlagEndProtected;
    plain.header.delivery = DeliveryClass::Reliable;
    plain.header.hop_remaining = 10;
    plain.header.network = 1;
    plain.header.origin = 1;
    plain.header.destination = group_address(static_cast<GroupId>(i + 1));
    plain.header.previous_hop = 1;
    plain.header.next_hop = 1;
    plain.header.message = MessageId{101, kGroupSequenceFlag | (i + 1)};
    plain.header.remaining_deadline_ms = 5000;
    plain.header.original_lifetime_ms = 5000;
    plain.header.link_epoch = 1;
    plain.header.end_epoch = 9;
    plain.payload[0] = 0x02;
    plain.payload_size = 1;
    wire::LinkOpenedFrame sealed{};
    CHECK_OK(wire::seal_group(plain, 1, source, sealed));
    CHECK(source.contexts.back().receiver == kBroadcastNodeId);
    CHECK_OK(table.accept(source.contexts.back(), sealed.header.end_counter));
  }
  CHECK(table.size() == 1);
  CHECK(table.capacity_refusals() == 0);
}

// ---------------------------------------------------------------------------
// Small meshes
// ---------------------------------------------------------------------------

std::size_t group_count(const SimWorld& w, const NodeId node, const MessageId& id) {
  std::size_t n = 0;
  for (const auto& receipt : w.obs(node)->group_messages) {
    if (receipt.info.key.id == id) ++n;
  }
  return n;
}

// Gateway 1; 2 and 3 under it; 4, 5 under 2; 6 under 3; 7 under 6.
//        1
//      /   \.
//     2     3
//    / \     \.
//   4   5     6
//              \.
//               7
void build_tree(SimWorld& w) {
  scoped_profile(w, 1, kFastPeriodMs, kFastLifetimeMs);
  for (NodeId id = 1; id <= 7; ++id) w.add(id);
  w.start_all();
  w.link(1, 2, 1, 1);
  w.link(1, 3, 1, 1);
  w.link(2, 4, 1, 1);
  w.link(2, 5, 1, 1);
  w.link(3, 6, 1, 1);
  w.link(6, 7, 1, 1);
  w.run(8000);
}

bool send_group(SimWorld& w, const NodeId from, const GroupId group, MessageId& id,
                const Priority priority = Priority::Normal, const bool ordered = false,
                const std::uint32_t lifetime_ms = 10000, const char* text = "mode=B") {
  GroupSendOptions options{};
  options.priority = priority;
  options.ordered = ordered;
  options.lifetime_ms = lifetime_ms;
  const auto status = w.at(from)->send_group(
      group, ByteView{reinterpret_cast<const std::uint8_t*>(text), std::strlen(text)}, options,
      w.now, id);
  if (!status.ok()) {
    std::fprintf(stderr, "  send_group refused: %s\n", status.detail);
  }
  return status.ok();
}

void test_small_tree_all() {
  SimWorld w;
  build_tree(w);
  CHECK(w.at(1)->scoped_child(2) && w.at(1)->scoped_child(3) && w.at(6)->scoped_child(7));
  MessageId id{};
  CHECK(send_group(w, 1, kGroupAll, id, Priority::Urgent));
  CHECK(is_group_sequence(id.sequence) && group_stream_seq(id.sequence) == 1);
  CHECK(w.at(1)->group_delivery(id).state == DeliveryState::WaitingForEndReceipt);
  w.run(1000);
  for (NodeId node = 2; node <= 7; ++node) {
    CHECK(group_count(w, node, id) == 1);
    const auto& got = w.obs(node)->group_messages.back();
    CHECK(got.payload == std::vector<std::uint8_t>({'m', 'o', 'd', 'e', '=', 'B'}));
    CHECK(got.info.group == kGroupAll && got.info.priority == Priority::Urgent &&
          !got.info.ordered && !got.info.late && got.info.key.origin == 1);
    CHECK(w.security.at(node)->group_replays() == 0);
  }
  CHECK(w.obs(1)->group_messages.empty());  // the source never delivers to itself
  const auto result = w.at(1)->group_delivery(id);
  CHECK(result.state == DeliveryState::Delivered);
  CHECK(std::string(result.reason) == "GROUP_COMPLETE");
  CHECK(result.delivered == 6 && result.nonmember == 0 && result.missing_total == 0 &&
        result.unaccounted == 0 && result.rounds == 1 && result.missing_count == 0);
  CHECK(!w.obs(1)->group_results.empty() &&
        w.obs(1)->group_results.back().state == DeliveryState::Delivered);
  // One copy + one report per tree edge, no NOT_CHILD, no HOP_ACCEPT.
  std::uint64_t copies = 0;
  std::uint64_t reports = 0;
  for (const auto& [node, ptr] : w.nodes) {
    copies += ptr->group_stats().copies_queued;
    reports += ptr->group_stats().reports_sent;
    CHECK(ptr->group_stats().not_child_sent == 0);
  }
  CHECK(copies == 6 && reports == 6);
  CHECK(w.net.tx_by_type[FrameType::GroupData].frames == 6);
  CHECK(w.net.tx_by_type[FrameType::GroupReport].frames == 6);
}

void test_membership_counts() {
  SimWorld w;
  build_tree(w);
  const GroupId g = 7;
  // Members: 4 and 7 (a leaf behind two non-member relays).
  CHECK_OK(w.at(4)->set_group_membership(&g, 1));
  CHECK_OK(w.at(7)->set_group_membership(&g, 1));
  CHECK(w.at(4)->group_member(g) && w.at(4)->group_member(kGroupAll) &&
        !w.at(5)->group_member(g));
  const GroupId bad[] = {0};
  CHECK(!w.at(5)->set_group_membership(bad, 1).ok());
  const GroupId all[] = {kGroupAll};
  CHECK(!w.at(5)->set_group_membership(all, 1).ok());
  const GroupId dup[] = {3, 3};
  CHECK(!w.at(5)->set_group_membership(dup, 2).ok());
  std::array<GroupId, kGroupMembershipMax + 1> many{};
  for (std::size_t i = 0; i < many.size(); ++i) many[i] = static_cast<GroupId>(i + 1);
  CHECK(!w.at(5)->set_group_membership(many.data(), many.size()).ok());

  MessageId id{};
  CHECK(send_group(w, 1, g, id));
  w.run(1000);
  CHECK(group_count(w, 4, id) == 1);
  CHECK(group_count(w, 7, id) == 1);
  for (const NodeId other : {2, 3, 5, 6}) CHECK(group_count(w, other, id) == 0);
  const auto result = w.at(1)->group_delivery(id);
  CHECK(result.state == DeliveryState::Delivered);
  CHECK(result.delivered == 2 && result.nonmember == 4 && result.missing_total == 0);
  CHECK(w.obs(7)->group_messages.back().info.group == g);
}

void test_profile_and_source_rules() {
  // Flat profile: explicit Unsupported, and a flat node drops group frames.
  {
    SimWorld w;
    w.add(1);
    w.add(2);
    w.start_all();
    w.link(1, 2, 1, 1);
    w.run(500);
    MessageId id{};
    GroupSendOptions options{};
    const std::uint8_t b = 1;
    const auto status = w.at(1)->send_group(kGroupAll, ByteView{&b, 1}, options, w.now, id);
    CHECK(status.code == StatusCode::Unsupported);
    CHECK(std::string(status.detail) == "GROUP_REQUIRES_GATEWAY_SCOPED");
  }
  // Scoped profile: only a configured gateway sources group messages;
  // argument checks.
  SimWorld w;
  build_tree(w);
  MessageId id{};
  GroupSendOptions options{};
  const std::uint8_t b = 1;
  auto status = w.at(2)->send_group(kGroupAll, ByteView{&b, 1}, options, w.now, id);
  CHECK(status.code == StatusCode::Unsupported);
  CHECK(std::string(status.detail) == "GROUP_SOURCE_NOT_GATEWAY");
  CHECK(!w.at(1)->send_group(0, ByteView{&b, 1}, options, w.now, id).ok());
  std::array<std::uint8_t, kGroupPayloadMax + 1> big{};
  CHECK(!w.at(1)->send_group(kGroupAll, ByteView{big.data(), big.size()}, options, w.now, id).ok());
  options.lifetime_ms = kMaxMessageLifetimeMs + 1;
  CHECK(!w.at(1)->send_group(kGroupAll, ByteView{&b, 1}, options, w.now, id).ok());
  options.lifetime_ms = 0;
  CHECK(!w.at(1)->send_group(kGroupAll, ByteView{&b, 1}, options, w.now, id).ok());
  CHECK(w.at(1)->group_delivery(MessageId{1, 2}).state == DeliveryState::Empty);
}

void test_source_queue_and_urgent_reserve() {
  SimWorld w;
  build_tree(w);
  // Normal traffic may hold at most capacity - 1 slots; the last one is the
  // Urgent reserve. The first message is in flight, the second queued.
  MessageId a{};
  MessageId b{};
  MessageId c{};
  MessageId alarm{};
  CHECK(send_group(w, 1, kGroupAll, a));
  CHECK(send_group(w, 1, kGroupAll, b));
  GroupSendOptions options{};
  const std::uint8_t byte = 1;
  const auto refused = w.at(1)->send_group(kGroupAll, ByteView{&byte, 1}, options, w.now, c);
  CHECK(refused.code == StatusCode::WouldBlock);
  CHECK(w.at(1)->group_delivery(b).state == DeliveryState::Queued);
  // The alarm overtakes the queued message (and the in-flight window).
  CHECK(send_group(w, 1, kGroupAll, alarm, Priority::Urgent, false, 10000, "ALARM"));
  CHECK(w.at(1)->group_delivery(alarm).state == DeliveryState::WaitingForEndReceipt);
  w.run(2000);
  for (const MessageId& id : {a, b, alarm}) {
    CHECK(w.at(1)->group_delivery(id).state == DeliveryState::Delivered);
  }
  // Every board saw the alarm before the queued Normal message b.
  for (NodeId node = 2; node <= 7; ++node) {
    std::size_t at_alarm = 0;
    std::size_t at_b = 0;
    const auto& got = w.obs(node)->group_messages;
    for (std::size_t i = 0; i < got.size(); ++i) {
      if (got[i].info.key.id == alarm) at_alarm = i + 1;
      if (got[i].info.key.id == b) at_b = i + 1;
    }
    CHECK(at_alarm != 0 && at_b != 0 && at_alarm < at_b);
  }
  // Terminal records are history: a new send reclaims one.
  CHECK(send_group(w, 1, kGroupAll, c));
  w.run(1000);
  CHECK(w.at(1)->group_delivery(c).state == DeliveryState::Delivered);
}

// Deterministic loss hook state: drop the first `drop_left` GROUP_DATA
// copies addressed to `drop_to` (round-limited when `drop_round` >= 0).
struct LossPlan {
  NodeId drop_to{kInvalidNodeId};
  int drop_left{0};
  int drop_round{-1};
  std::uint64_t only_sequence{0};
  bool drop_reports_from{false};
  NodeId report_from{kInvalidNodeId};
  int reports_left{0};
};
LossPlan g_loss{};

bool loss_hook(const SimNetwork::Pending& pending) {
  if (pending.frame.size() < 88) return false;
  routeloom_test::FrameSight sight{};
  if (!routeloom_test::sight_frame(ByteView{pending.frame.data(), pending.frame.size()}, sight)) {
    return false;
  }
  if (sight.type == FrameType::GroupData && pending.to == g_loss.drop_to &&
      g_loss.drop_left > 0 &&
      (g_loss.drop_round < 0 || sight.round == g_loss.drop_round) &&
      (g_loss.only_sequence == 0 || sight.sequence == g_loss.only_sequence)) {
    --g_loss.drop_left;
    return true;
  }
  if (g_loss.drop_reports_from && sight.type == FrameType::GroupReport &&
      pending.from == g_loss.report_from && g_loss.reports_left > 0) {
    --g_loss.reports_left;
    return true;
  }
  return false;
}

void test_repair_after_loss() {
  SimWorld w;
  build_tree(w);
  w.net.drop_frame = loss_hook;
  // Every round-0 attempt (both link tries) toward leaf 7 is lost: 6 reports
  // 7 missing, the source repairs only the 1-3-6-7 branch in round 1.
  g_loss = LossPlan{};
  g_loss.drop_to = 7;
  g_loss.drop_left = 2;
  g_loss.drop_round = 0;
  MessageId id{};
  CHECK(send_group(w, 1, kGroupAll, id));
  w.run(150);
  auto result = w.at(1)->group_delivery(id);
  CHECK(result.rounds == 1 && result.delivered == 5 && result.missing_total == 1 &&
        result.missing_count == 1 && result.missing[0] == 7 && !result.missing_truncated);
  CHECK(std::string(result.reason) == "GROUP_REPAIR_PENDING");
  CHECK(group_count(w, 7, id) == 0);
  const auto copies_before = w.net.tx_by_type[FrameType::GroupData].frames;
  w.run(1500);
  result = w.at(1)->group_delivery(id);
  CHECK(result.state == DeliveryState::Delivered);
  CHECK(result.rounds == 2 && result.delivered == 6 && result.missing_total == 0);
  CHECK(group_count(w, 7, id) == 1);
  for (NodeId node = 2; node <= 6; ++node) CHECK(group_count(w, node, id) == 1);
  // Targeted: round 1 went down 1 -> 3 -> 6 -> 7 only (3 copies, not 6).
  CHECK(w.net.tx_by_type[FrameType::GroupData].frames - copies_before == 3);
  CHECK(w.at(1)->group_stats().repair_rounds == 1);
  for (const auto& [node, sec] : w.security) CHECK(sec->group_replays() == 0);

  // A lost REPORT (not data): 2's report never reaches the gateway; the
  // repair round re-sends to 2, which answers from its stored state without
  // forwarding again, and nobody delivers twice.
  g_loss = LossPlan{};
  g_loss.drop_reports_from = true;
  g_loss.report_from = 2;
  g_loss.reports_left = 2;  // both link attempts of the round-0 report
  MessageId second{};
  CHECK(send_group(w, 1, kGroupAll, second));
  w.run(2500);
  result = w.at(1)->group_delivery(second);
  CHECK(result.state == DeliveryState::Delivered && result.delivered == 6 &&
        result.rounds == 2);
  for (NodeId node = 2; node <= 7; ++node) CHECK(group_count(w, node, second) == 1);
  w.net.drop_frame = nullptr;
}

void test_dead_node_summary() {
  SimWorld w;
  build_tree(w);
  // Leaf 5 dies silently (radio gone, routes still leased).
  w.net.unregister_node(5);
  MessageId id{};
  CHECK(send_group(w, 1, kGroupAll, id, Priority::Normal, false, 6000));
  w.run(7000);
  const auto result = w.at(1)->group_delivery(id);
  CHECK(result.state == DeliveryState::Failed);
  CHECK(std::string(result.reason) == "GROUP_INCOMPLETE");
  CHECK(result.delivered == 5 && result.missing_total == 1 && result.missing_count == 1 &&
        result.missing[0] == 5);
  CHECK(result.rounds == kGroupMaxRounds);
  // Repairs were targeted at the 1 -> 2 -> 5 branch only.
  CHECK(w.at(1)->group_stats().repair_rounds == kGroupMaxRounds - 1U);
  for (const NodeId node : {3, 4, 6, 7}) CHECK(group_count(w, node, id) == 1);
}

void test_not_child_is_counted_once() {
  // Diamond: 4 hangs off 2 (cheaper) and 3. Child flags lag a parent
  // switch by up to the release delay, so right after 4 re-parents to 3 both
  // relays forward to it. 4 follows the first sender and answers the other
  // with NOT_CHILD: the summary counts it exactly once.
  SimWorld w;
  scoped_profile(w, 1, kFastPeriodMs, kFastLifetimeMs);
  for (NodeId id = 1; id <= 4; ++id) w.add(id);
  w.start_all();
  w.link(1, 2, 3, 3);  // old parent 2: a costly uplink
  w.link(1, 3, 1, 1);
  w.link(2, 4, 1, 1);
  w.run(6000);
  CHECK(w.at(4)->routes().best(1).next_hop == 2);
  CHECK(w.at(2)->scoped_child(4));
  // A cheaper relay comes into range; 4 re-parents to 3 and, within the 3 s
  // release delay, 2 still counts 4 as its child.
  w.link(3, 4, 1, 1);
  bool both = false;
  for (int step = 0; step < 2000 && !both; ++step) {
    w.run(0);
    both = w.at(4)->routes().best(1).next_hop == 3 && w.at(3)->scoped_child(4) &&
           w.at(2)->scoped_child(4);
  }
  CHECK(both);
  MessageId id{};
  CHECK(send_group(w, 1, kGroupAll, id));
  w.run(1000);
  const auto result = w.at(1)->group_delivery(id);
  CHECK(result.state == DeliveryState::Delivered);
  CHECK(result.delivered == 3 && result.missing_total == 0 && result.unaccounted == 0);
  CHECK(group_count(w, 4, id) == 1);
  CHECK(w.at(4)->group_stats().not_child_sent == 1);
  CHECK(w.security.at(4)->group_replays() == 0);
}

// ---------------------------------------------------------------------------
// Ordering
// ---------------------------------------------------------------------------

std::vector<std::uint32_t> group_order(const SimWorld& w, const NodeId node) {
  std::vector<std::uint32_t> order;
  for (const auto& receipt : w.obs(node)->group_messages) order.push_back(receipt.info.group_seq);
  return order;
}

void test_group_ordering_reorder() {
  // Stream 2 is lost toward leaf 7 in round 0: 7 receives 1 and 3 first,
  // holds 3, and delivers 2, 3 once the repair round brings 2.
  SimWorld w;
  build_tree(w);
  w.net.drop_frame = loss_hook;
  g_loss = LossPlan{};
  g_loss.drop_to = 7;
  g_loss.drop_left = 2;
  g_loss.drop_round = 0;
  g_loss.only_sequence = kGroupSequenceFlag | 2;
  MessageId m1{};
  MessageId m2{};
  MessageId m3{};
  CHECK(send_group(w, 1, kGroupAll, m1, Priority::Normal, true));
  w.run(150);
  CHECK(send_group(w, 1, kGroupAll, m2, Priority::Normal, true));
  // m3 is Urgent (skips the source queue), ordered: it reaches 7 before m2.
  CHECK(send_group(w, 1, kGroupAll, m3, Priority::Urgent, true));
  w.run(80);
  CHECK(group_order(w, 7) == std::vector<std::uint32_t>({1}));
  CHECK(w.at(7)->group_stats().held == 1);
  w.run(2000);
  CHECK(group_order(w, 7) == std::vector<std::uint32_t>({1, 2, 3}));
  for (const auto& receipt : w.obs(7)->group_messages) CHECK(!receipt.info.late);
  for (NodeId node = 2; node <= 6; ++node) {
    CHECK(group_order(w, node) == std::vector<std::uint32_t>({1, 2, 3}));
  }
  CHECK(w.at(1)->group_delivery(m2).state == DeliveryState::Delivered);
  w.net.drop_frame = nullptr;
}

void test_group_ordering_skip_and_late() {
  SimWorld w;
  build_tree(w);
  w.net.drop_frame = loss_hook;
  // Stream 2 never reaches 7 while 3 is held: 3's own short lifetime bounds
  // the hold, the gap is skipped, and when 2 finally arrives (a later repair
  // round) it is delivered flagged late.
  g_loss = LossPlan{};
  g_loss.drop_to = 7;
  g_loss.drop_left = 8;  // rounds 0-3 (two link attempts each); round 4 lands
  g_loss.only_sequence = kGroupSequenceFlag | 2;
  MessageId m1{};
  MessageId m2{};
  MessageId m3{};
  CHECK(send_group(w, 1, kGroupAll, m1, Priority::Normal, true));
  w.run(150);
  CHECK(send_group(w, 1, kGroupAll, m2, Priority::Normal, true, 20000));
  CHECK(send_group(w, 1, kGroupAll, m3, Priority::Urgent, true, 600));
  const MonotonicMs sent_at = w.now;
  w.run(80);
  CHECK(group_order(w, 7) == std::vector<std::uint32_t>({1}));
  // Held no longer than m3's remaining lifetime (~600 ms), never forever.
  MonotonicMs released_at = 0;
  while (w.now < sent_at + 3000 && released_at == 0) {
    w.run(0);
    if (group_order(w, 7).size() >= 2) released_at = w.now;
  }
  CHECK(released_at != 0 && released_at - sent_at <= 700);
  CHECK(group_order(w, 7) == std::vector<std::uint32_t>({1, 3}));
  CHECK(w.at(7)->group_stats().gaps_skipped >= 1);
  w.run(4000);
  const auto order = group_order(w, 7);
  CHECK(order == std::vector<std::uint32_t>({1, 3, 2}));
  if (order.size() == 3) {
    CHECK(w.obs(7)->group_messages[2].info.late);
    CHECK(!w.obs(7)->group_messages[1].info.late);
  }
  CHECK(w.at(7)->group_stats().late == 1);
  CHECK(w.at(1)->group_delivery(m2).state == DeliveryState::Delivered);
  w.net.drop_frame = nullptr;
}

// The ordered subsequence of a node's group receipts is strictly increasing
// and nothing was flagged late.
bool ordered_subsequence_in_order(const SimWorld& w, const NodeId node) {
  std::uint32_t last = 0;
  for (const auto& receipt : w.obs(node)->group_messages) {
    if (receipt.info.late) return false;
    if (!receipt.info.ordered) continue;
    if (receipt.info.group_seq <= last) return false;
    last = receipt.info.group_seq;
  }
  return true;
}

void test_unordered_never_held() {
  // An unordered message (the ALARM case) behind an ordered gap is handed
  // to the application at once; the ordered successor still waits.
  SimWorld w;
  build_tree(w);
  MessageId m0{};
  CHECK(send_group(w, 1, kGroupAll, m0, Priority::Normal, true));  // stream 1 everywhere
  w.run(150);
  w.net.drop_frame = loss_hook;
  g_loss = LossPlan{};
  g_loss.drop_to = 7;
  g_loss.drop_left = 2;
  g_loss.drop_round = 0;
  g_loss.only_sequence = kGroupSequenceFlag | 2;
  MessageId m1{};
  MessageId m2{};
  MessageId m3{};
  CHECK(send_group(w, 1, kGroupAll, m1, Priority::Normal, true));                  // 2
  CHECK(send_group(w, 1, kGroupAll, m2, Priority::Urgent, false, 10000, "ALARM"));  // 3
  CHECK(send_group(w, 1, kGroupAll, m3, Priority::Urgent, true));                   // 4
  w.run(60);
  // 7 lost 2: the unordered alarm (3) is delivered at once, 4 is held.
  CHECK(group_order(w, 7) == std::vector<std::uint32_t>({1, 3}));
  CHECK(w.at(7)->group_stats().held == 1);
  w.run(2000);
  CHECK(group_order(w, 7) == std::vector<std::uint32_t>({1, 3, 2, 4}));
  for (NodeId node = 2; node <= 7; ++node) {
    CHECK(group_order(w, node).size() == 4);
    CHECK(ordered_subsequence_in_order(w, node));
  }
  w.net.drop_frame = nullptr;
}

// ---------------------------------------------------------------------------
// Stream state commits only after Group end authentication (issue #106)
// ---------------------------------------------------------------------------

// Seals a GROUP_DATA frame exactly as gateway `source` would build it — the
// end tag is genuine for the header given. A caller that then edits the
// sealed header (e.g. the session field, which the end AAD covers) gets a
// frame whose link wrap can still be honest while the end tag is not.
wire::LinkOpenedFrame seal_group_frame(SecurityProvider& sealer, const NodeId source,
                                       const MessageId& message, const char* text) {
  wire::PlainFrame plain{};
  plain.header.type = FrameType::GroupData;
  plain.header.flags = wire::kFlagEndProtected;
  plain.header.delivery = DeliveryClass::Reliable;
  plain.header.hop_remaining = 8;
  plain.header.network = 1;
  plain.header.origin = source;
  plain.header.destination = group_address(kGroupAll);
  plain.header.previous_hop = source;
  plain.header.next_hop = source;
  plain.header.message = message;
  plain.header.remaining_deadline_ms = 5000;
  plain.header.original_lifetime_ms = 5000;
  plain.header.link_epoch = 1;
  plain.header.end_epoch = 1;
  GroupDataHeader head{};
  head.priority = Priority::Normal;
  wire::LinkOpenedFrame sealed{};
  CHECK_OK(encode_group_data(head,
                             ByteView{reinterpret_cast<const std::uint8_t*>(text),
                                      std::strlen(text)},
                             MutableByteView{plain.payload.data(), plain.payload.size()},
                             plain.payload_size));
  CHECK_OK(wire::seal_group(plain, source, sealer, sealed));
  return sealed;
}

// The frame as relay `via` received it, then re-wrapped in `via`'s own
// honest link protection toward `to` (wire::forward never re-computes the
// end tag — whatever the mutation did to it stays).
wire::EncodedFrame link_wrap(wire::LinkOpenedFrame& frame, SimWorld& w, const NodeId via,
                             const NodeId to) {
  frame.header.next_hop = via;
  wire::EncodedFrame encoded{};
  CHECK_OK(wire::forward(frame, via, to, 1, frame.header.remaining_deadline_ms,
                         *w.security.at(via), encoded));
  return encoded;
}

void test_unauthenticated_session_jump_is_ignored() {
  // Issue #106 regression: a link-valid GROUP_DATA whose Group end tag is
  // invalid must not move the sender's stream. Before the fix it advanced
  // the session to UINT32_MAX, and every later legitimate frame from the
  // gateway was refused GROUP_STALE_SESSION.
  SimWorld w;
  build_tree(w);
  MessageId first{};
  CHECK(send_group(w, 1, kGroupAll, first));
  w.run(1000);
  CHECK(group_count(w, 4, first) == 1);
  CHECK(group_count(w, 5, first) == 1);

  // Genuine group ciphertext from the gateway's provider, then the
  // AAD-covered session field raised to UINT32_MAX without resealing.
  wire::LinkOpenedFrame forged = seal_group_frame(
      *w.security.at(1), 1, MessageId{101, kGroupSequenceFlag | 9}, "FORGED");
  forged.header.message.session = UINT32_MAX;
  wire::EncodedFrame injected = link_wrap(forged, w, 2, 4);
  // Inspection provider: the link layer opens, the Group end layer cannot.
  routeloom_test::TestSecurity inspect;
  wire::LinkOpenedFrame at_leaf{};
  CHECK_OK(wire::open_link(injected.view(), 4, inspect, at_leaf));
  wire::PlainFrame opened{};
  const auto invalid_group = wire::open_group(at_leaf, inspect, opened);
  CHECK(!invalid_group.ok());

  const GroupStats before = w.at(4)->group_stats();
  const std::size_t receipts_before = w.obs(4)->group_messages.size();
  const std::size_t diags_before = w.obs(4)->diagnostics.size();
  w.at(4)->on_radio_receive(2, injected.view(), RadioRxMetadata{-60}, w.now);
  // The end layer refused: one open failure, the refusal detail — and
  // NOTHING else. Stream, session, holds and dedup are bit-invariant.
  GroupStats after = w.at(4)->group_stats();
  CHECK(after.open_failures == before.open_failures + 1);
  after.open_failures = before.open_failures;
  CHECK(std::memcmp(&before, &after, sizeof(GroupStats)) == 0);
  CHECK(w.obs(4)->group_messages.size() == receipts_before);
  CHECK(w.obs(4)->diagnostics.size() == diags_before + 1);
  CHECK(w.obs(4)->diagnostics.back() == std::string(invalid_group.detail));

  // The same gateway keeps working: its next legitimate ALL reaches leaf 4
  // (and leaf 5, which never saw the forged frame).
  MessageId second{};
  CHECK(send_group(w, 1, kGroupAll, second));
  w.run(1000);
  CHECK(group_count(w, 4, second) == 1);
  CHECK(group_count(w, 5, second) == 1);
  CHECK(!w.obs(4)->has_diag("GROUP_STALE_SESSION"));
  CHECK(w.at(1)->group_delivery(second).state == DeliveryState::Delivered);
}

void test_authenticated_session_switch_commits() {
  // The same gate from the other side: while the forged session jump leaves
  // the stream AND the held ordered message untouched, a properly sealed
  // newer session still commits — switching the stream and draining the
  // old session's holds in order.
  SimWorld w;
  build_tree(w);
  MessageId m1{};
  CHECK(send_group(w, 1, kGroupAll, m1, Priority::Normal, true));
  w.run(150);
  CHECK(group_order(w, 4) == std::vector<std::uint32_t>({1}));
  // Stream 2's copies to leaf 4 are lost in round 0; stream 3 (Urgent,
  // ordered) arrives behind the gap and is held.
  w.net.drop_frame = loss_hook;
  g_loss = LossPlan{};
  g_loss.drop_to = 4;
  g_loss.drop_left = 2;
  g_loss.drop_round = 0;
  g_loss.only_sequence = kGroupSequenceFlag | 2;
  MessageId m2{};
  MessageId m3{};
  CHECK(send_group(w, 1, kGroupAll, m2, Priority::Normal, true));
  CHECK(send_group(w, 1, kGroupAll, m3, Priority::Urgent, true));
  for (int step = 0; step < 200 && w.at(4)->group_stats().held == 0; ++step) w.run(0);
  w.net.drop_frame = nullptr;
  CHECK(w.at(4)->group_stats().held == 1);
  CHECK(group_order(w, 4) == std::vector<std::uint32_t>({1}));

  // Forged jump to UINT32_MAX: refused, and stream + session + hold +
  // dedup are bit-identical — the held message is NOT drained.
  wire::LinkOpenedFrame forged = seal_group_frame(
      *w.security.at(1), 1, MessageId{101, kGroupSequenceFlag | 9}, "FORGED");
  forged.header.message.session = UINT32_MAX;
  wire::EncodedFrame injected = link_wrap(forged, w, 2, 4);
  const GroupStats before = w.at(4)->group_stats();
  w.at(4)->on_radio_receive(2, injected.view(), RadioRxMetadata{-60}, w.now);
  GroupStats after = w.at(4)->group_stats();
  CHECK(after.open_failures == before.open_failures + 1);
  after.open_failures = before.open_failures;
  CHECK(std::memcmp(&before, &after, sizeof(GroupStats)) == 0);
  CHECK(group_order(w, 4) == std::vector<std::uint32_t>({1}));

  // A properly sealed newer session commits: the old hold drains in order
  // and the new session's first message lands. Sealed by the gateway's own
  // provider, so the end counter is fresh for leaf 4's replay check.
  wire::LinkOpenedFrame reboot = seal_group_frame(
      *w.security.at(1), 1, MessageId{9999, kGroupSequenceFlag | 1}, "BOOT2");
  wire::EncodedFrame valid = link_wrap(reboot, w, 2, 4);
  routeloom_test::TestSecurity inspect;
  wire::LinkOpenedFrame at_leaf{};
  CHECK_OK(wire::open_link(valid.view(), 4, inspect, at_leaf));
  wire::PlainFrame opened{};
  CHECK_OK(wire::open_group(at_leaf, inspect, opened));
  w.at(4)->on_radio_receive(2, valid.view(), RadioRxMetadata{-60}, w.now);
  const auto& got = w.obs(4)->group_messages;
  CHECK(got.size() == 3);
  if (got.size() == 3) {
    CHECK(got[0].info.key.id.session == 101 && got[0].info.group_seq == 1);
    CHECK(got[1].info.key.id.session == 101 && got[1].info.group_seq == 3);  // drained hold
    CHECK(got[2].info.key.id.session == 9999 && got[2].info.group_seq == 1);  // new session
  }
  CHECK(w.at(4)->group_stats().open_failures == before.open_failures + 1);

  // The switch is real: the gateway's pre-reboot session is now stale at
  // leaf 4, while leaf 5 (never saw the new session) still accepts it.
  w.run(500);  // let m3's report settle so the non-urgent slot is free
  MessageId m4{};
  CHECK(send_group(w, 1, kGroupAll, m4));
  w.run(1000);
  CHECK(group_count(w, 4, m4) == 0);
  CHECK(w.obs(4)->has_diag("GROUP_STALE_SESSION"));
  CHECK(group_count(w, 5, m4) == 1);
}

void test_unicast_ordering() {
  // 1 - 2 - 3 line under gateway 1. Three ordered RELIABLE messages to 3:
  // each successor is held (ORDER_WAIT) until its predecessor is Delivered,
  // so 3's application sees A, B, C in send order.
  SimWorld w;
  scoped_profile(w, 1, kFastPeriodMs, kFastLifetimeMs);
  for (NodeId id = 1; id <= 3; ++id) w.add(id);
  w.start_all();
  w.link(1, 2, 1, 1);
  w.link(2, 3, 1, 1);
  w.run(6000);
  SendOptions options{};
  options.ordered = true;
  options.lifetime_ms = 3000;
  MessageId a{};
  MessageId b{};
  MessageId c{};
  const std::uint8_t pa = 'A';
  const std::uint8_t pb = 'B';
  const std::uint8_t pc = 'C';
  CHECK_OK(w.at(1)->send(3, ByteView{&pa, 1}, options, w.now, a));
  CHECK_OK(w.at(1)->send(3, ByteView{&pb, 1}, options, w.now, b));
  CHECK_OK(w.at(1)->send(3, ByteView{&pc, 1}, options, w.now, c));
  CHECK(w.at(1)->delivery(b).state == DeliveryState::WaitingForRoute);
  CHECK(std::string(w.at(1)->delivery(b).reason) == "ORDER_WAIT");
  CHECK(std::string(w.at(1)->delivery(c).reason) == "ORDER_WAIT");
  const auto waiting = [](const DeliveryResult& r) {
    return r.state == DeliveryState::WaitingForRoute && std::string(r.reason) == "ORDER_WAIT";
  };
  int early_release = 0;
  for (int step = 0; step < 400; ++step) {
    w.run(0);
    // B never leaves its hold before A is Delivered, nor C before B.
    if (!waiting(w.at(1)->delivery(b)) &&
        w.at(1)->delivery(a).state != DeliveryState::Delivered) {
      ++early_release;
    }
    if (!waiting(w.at(1)->delivery(c)) &&
        w.at(1)->delivery(b).state != DeliveryState::Delivered) {
      ++early_release;
    }
  }
  CHECK(early_release == 0);
  for (const MessageId& id : {a, b, c}) {
    CHECK(w.at(1)->delivery(id).state == DeliveryState::Delivered);
  }
  std::string order;
  for (const auto& message : w.obs(3)->messages) order.push_back(static_cast<char>(message.at(0)));
  CHECK(order == "ABC");
  // Ordering is per destination: an ordered message to 2 is not held behind
  // the stream to 3.
  MessageId d{};
  MessageId e{};
  CHECK_OK(w.at(1)->send(3, ByteView{&pa, 1}, options, w.now, d));
  CHECK_OK(w.at(1)->send(2, ByteView{&pb, 1}, options, w.now, e));
  CHECK(std::string(w.at(1)->delivery(e).reason) != "ORDER_WAIT");
  w.run(500);

  // Skip / timeout: the predecessor's arrival is never confirmed (every
  // END_RECEIPT for it is lost), so its successor is released at the
  // predecessor's own deadline — not earlier (it might still be in flight),
  // not later (head-of-line blocking is bounded by the lifetime).
  static std::uint64_t lost_sequence = 0;
  MessageId lost{};
  options.lifetime_ms = 800;
  const std::uint8_t pl = 'L';
  CHECK_OK(w.at(1)->send(3, ByteView{&pl, 1}, options, w.now, lost));
  lost_sequence = lost.sequence;
  w.net.drop_frame = [](const SimNetwork::Pending& pending) {
    routeloom_test::FrameSight sight{};
    return routeloom_test::sight_frame(ByteView{pending.frame.data(), pending.frame.size()},
                                       sight) &&
           sight.type == FrameType::EndReceipt && sight.origin == 3 &&
           sight.sequence == lost_sequence;
  };
  const MonotonicMs start = w.now;
  options.lifetime_ms = 5000;
  MessageId next{};
  const std::uint8_t pn = 'N';
  const std::size_t before = w.obs(3)->messages.size();
  CHECK_OK(w.at(1)->send(3, ByteView{&pn, 1}, options, w.now, next));
  MonotonicMs next_at = 0;
  for (int step = 0; step < 600 && next_at == 0; ++step) {
    w.run(0);
    for (std::size_t i = before; i < w.obs(3)->messages.size(); ++i) {
      if (w.obs(3)->messages[i].at(0) == 'N') next_at = w.now;
    }
  }
  CHECK(next_at != 0);
  CHECK(next_at >= start + 800);        // waited for the predecessor's deadline...
  CHECK(next_at <= start + 800 + 100);  // ...and not longer
  CHECK(w.at(1)->delivery(lost).state != DeliveryState::Delivered);
  w.net.drop_frame = nullptr;
  // Invalid combinations.
  SendOptions best_effort{};
  best_effort.ordered = true;
  best_effort.delivery = DeliveryClass::BestEffort;
  MessageId dummy{};
  CHECK(!w.at(1)->send(3, ByteView{&pn, 1}, best_effort, w.now, dummy).ok());
  SendOptions durable{};
  durable.ordered = true;
  durable.persist_across_sleep = true;
  CHECK(!w.at(1)->send(3, ByteView{&pn, 1}, durable, w.now, dummy).ok());
}

// ---------------------------------------------------------------------------
// 100-node site
// ---------------------------------------------------------------------------

struct Site {
  static constexpr int kSide = 10;
  static NodeId id(const int x, const int y) { return static_cast<NodeId>(1 + x * kSide + y); }
  NodeId gateway{id(0, 4)};  // outer wall: depth 9
  std::vector<NodeId> boards;
};

bool site_converged(const SimWorld& w, const Site& site) {
  for (const NodeId board : site.boards) {
    if (!w.at(board)->routes().best(site.gateway).valid) return false;
    if (!w.at(site.gateway)->routes().best(board).valid) return false;
  }
  return true;
}

void build_site(SimWorld& w, Site& site) {
  w.net.record_sights = false;
  scoped_profile(w, site.gateway, kScopedProductPeriodMs, kScopedProductLifetimeMs);
  for (int x = 0; x < Site::kSide; ++x) {
    for (int y = 0; y < Site::kSide; ++y) w.add(Site::id(x, y));
  }
  w.start_all();
  for (int x = 0; x < Site::kSide; ++x) {
    for (int y = 0; y < Site::kSide; ++y) {
      for (const auto& [dx, dy] : {std::pair{1, 0}, std::pair{0, 1}, std::pair{1, 1},
                                   std::pair{1, -1}}) {
        const int nx = x + dx;
        const int ny = y + dy;
        if (nx < 0 || ny < 0 || nx >= Site::kSide || ny >= Site::kSide) continue;
        w.link(Site::id(x, y), Site::id(nx, ny), 1, 1);
      }
    }
  }
  for (const auto& [node, ptr] : w.nodes) {
    if (node != site.gateway) site.boards.push_back(node);
  }
  while (w.now <= 120000 && !site_converged(w, site)) w.run(1000 - 50, 50);
  CHECK(site_converged(w, site));
  w.run(30000, 50);  // one refresh cycle of settling
}

SimNetwork::TxTally tally_of(const SimWorld& w, const FrameType type) {
  const auto it = w.net.tx_by_type.find(type);
  return it == w.net.tx_by_type.end() ? SimNetwork::TxTally{} : it->second;
}

SimNetwork::TxTally route_control(const SimWorld& w) {
  SimNetwork::TxTally sum{};
  for (const FrameType type :
       {FrameType::RouteUpdate, FrameType::SeqnoRequest, FrameType::RouteRequest}) {
    const auto t = tally_of(w, type);
    sum.frames += t.frames;
    sum.bytes += t.bytes;
  }
  return sum;
}

SimNetwork::TxTally minus(const SimNetwork::TxTally& a, const SimNetwork::TxTally& b) {
  return SimNetwork::TxTally{a.frames - b.frames, a.bytes - b.bytes};
}

std::uint64_t lcg_state = 0xC0FFEEULL;
std::uint32_t lcg_next() {
  lcg_state = lcg_state * 6364136223846793005ULL + 1442695040888963407ULL;
  return static_cast<std::uint32_t>(lcg_state >> 33);
}

std::uint32_t g_loss_percent = 0;
bool random_group_loss(const SimNetwork::Pending& pending) {
  if (pending.frame.size() < 5) return false;
  const auto type = static_cast<FrameType>(pending.frame[4]);
  if (type != FrameType::GroupData && type != FrameType::GroupReport) return false;
  return lcg_next() % 100 < g_loss_percent;
}

std::uint32_t g_silent_percent = 0;
bool random_group_silent(const SimNetwork::Pending& pending) {
  if (pending.frame.size() < 5) return false;
  const auto type = static_cast<FrameType>(pending.frame[4]);
  if (type != FrameType::GroupData && type != FrameType::GroupReport) return false;
  return lcg_next() % 100 < g_silent_percent;
}

// Terminal summary of a group message as the source's observer saw it (the
// source table keeps only the newest records; history is evicted).
bool terminal_result(const SimWorld& w, const NodeId source, const MessageId& id,
                     GroupDeliveryResult& out) {
  bool found = false;
  for (const auto& result : w.obs(source)->group_results) {
    if (result.id == id && (result.state == DeliveryState::Delivered ||
                            result.state == DeliveryState::Failed ||
                            result.state == DeliveryState::Expired)) {
      out = result;
      found = true;
    }
  }
  return found;
}

struct LossRun {
  MonotonicMs reached_all_ms{0};
  MonotonicMs complete_ms{0};
  std::size_t reached_by_1s{0};
  std::size_t not_exactly_once{0};
  GroupDeliveryResult result{};
  SimNetwork::TxTally data{};
  SimNetwork::TxTally reports{};
};

LossRun run_alarm_under_loss(SimWorld& w, const Site& site) {
  LossRun run{};
  const NodeId gw = site.gateway;
  const auto data_before = tally_of(w, FrameType::GroupData);
  const auto report_before = tally_of(w, FrameType::GroupReport);
  MessageId id{};
  CHECK(send_group(w, gw, kGroupAll, id, Priority::Urgent, false, 30000, "PUMP3 OVERTEMP"));
  const MonotonicMs sent = w.now;
  while (w.now < sent + 30000 && run.complete_ms == 0) {
    w.run(0, 5);
    std::size_t reached = 0;
    for (const NodeId board : site.boards) reached += group_count(w, board, id) > 0 ? 1 : 0;
    if (w.now <= sent + 1000) run.reached_by_1s = reached;
    if (run.reached_all_ms == 0 && reached == site.boards.size()) run.reached_all_ms = w.now - sent;
    if (terminal_result(w, gw, id, run.result)) run.complete_ms = w.now - sent;
  }
  for (const NodeId board : site.boards) {
    run.not_exactly_once += group_count(w, board, id) != 1 ? 1 : 0;
    CHECK(w.security.at(board)->group_replays() == 0);
  }
  run.data = minus(tally_of(w, FrameType::GroupData), data_before);
  run.reports = minus(tally_of(w, FrameType::GroupReport), report_before);
  return run;
}

void test_hundred_node_alarm() {
  SimWorld w;
  Site site;
  build_site(w, site);
  const NodeId gw = site.gateway;
  std::fprintf(stderr, "  group: 100-node site converged and settled at %llu ms\n",
               static_cast<unsigned long long>(w.now));

  // --- Urgent ALARM to ALL, lossless ---------------------------------------
  const auto hop_before = tally_of(w, FrameType::HopAccept);
  const auto data_before = tally_of(w, FrameType::GroupData);
  const auto report_before = tally_of(w, FrameType::GroupReport);
  MessageId alarm{};
  CHECK(send_group(w, gw, kGroupAll, alarm, Priority::Urgent, false, 30000, "PUMP3 OVERTEMP"));
  const MonotonicMs sent = w.now;
  MonotonicMs p99_at = 0;
  MonotonicMs all_at = 0;
  MonotonicMs complete_at = 0;
  while (w.now < sent + 3000) {
    w.run(0, 5);
    std::size_t reached = 0;
    for (const NodeId board : site.boards) reached += group_count(w, board, alarm) > 0 ? 1 : 0;
    if (p99_at == 0 && reached * 100 >= site.boards.size() * 99) p99_at = w.now;
    if (all_at == 0 && reached == site.boards.size()) all_at = w.now;
    if (complete_at == 0 &&
        w.at(gw)->group_delivery(alarm).state == DeliveryState::Delivered) {
      complete_at = w.now;
    }
  }
  CHECK(p99_at != 0 && p99_at - sent <= 1000);
  CHECK(all_at != 0 && all_at - sent <= 1000);
  const auto result = w.at(gw)->group_delivery(alarm);
  CHECK(result.state == DeliveryState::Delivered);
  CHECK(result.delivered == 99 && result.nonmember == 0 && result.missing_total == 0 &&
        result.unaccounted == 0 && result.rounds == 1);
  std::size_t not_once = 0;
  for (const NodeId board : site.boards) {
    not_once += group_count(w, board, alarm) != 1 ? 1 : 0;
    CHECK(w.security.at(board)->group_replays() == 0);
  }
  CHECK(not_once == 0);
  const auto data = minus(tally_of(w, FrameType::GroupData), data_before);
  const auto reports = minus(tally_of(w, FrameType::GroupReport), report_before);
  CHECK(data.frames == 99 && reports.frames == 99);  // one copy + one report per tree edge
  CHECK(tally_of(w, FrameType::HopAccept).frames == hop_before.frames);  // MAC ACK only
  const double alarm_air_s =
      static_cast<double>(airtime_us(data) + airtime_us(reports)) / 1e6;
  std::fprintf(stderr,
               "  group: ALARM to ALL: 99%% at %llu ms, all 99 at %llu ms, summary complete at "
               "%llu ms; %llu copies + %llu reports = %.2f s network air time\n",
               static_cast<unsigned long long>(p99_at - sent),
               static_cast<unsigned long long>(all_at - sent),
               static_cast<unsigned long long>(complete_at - sent),
               static_cast<unsigned long long>(data.frames),
               static_cast<unsigned long long>(reports.frames), alarm_air_s);
  CHECK(alarm_air_s <= 1.6);

  // --- MAC-level loss (drop_frame): 10 % of every group frame attempt -------
  // Both link attempts of a copy fail ~1 % of the time: those subtrees are
  // repaired in later rounds, and the summary is exact.
  lcg_state = 0x5EEDULL;
  g_loss_percent = 10;
  w.net.drop_frame = random_group_loss;
  const LossRun mac = run_alarm_under_loss(w, site);
  w.net.drop_frame = nullptr;
  CHECK(mac.reached_all_ms != 0);
  CHECK(mac.not_exactly_once == 0);
  CHECK(mac.result.state == DeliveryState::Delivered);
  CHECK(mac.result.delivered == 99 && mac.result.nonmember == 0 &&
        mac.result.missing_total == 0 && mac.result.unaccounted == 0);
  CHECK(mac.result.rounds >= 2);  // repair actually exercised
  CHECK(mac.reached_by_1s * 100 >= site.boards.size() * 80);
  std::fprintf(stderr,
               "  group: ALARM under 10%% MAC-level loss: %zu/99 by 1 s, all 99 at %llu ms, "
               "exact summary after %u rounds at %llu ms; %llu copies + %llu reports = %.2f s air\n",
               mac.reached_by_1s, static_cast<unsigned long long>(mac.reached_all_ms),
               static_cast<unsigned>(mac.result.rounds),
               static_cast<unsigned long long>(mac.complete_ms),
               static_cast<unsigned long long>(mac.data.frames),
               static_cast<unsigned long long>(mac.reports.frames),
               static_cast<double>(airtime_us(mac.data) + airtime_us(mac.reports)) / 1e6);
  // MAC failures move routes (consecutive failures invalidate a next hop):
  // let the tree heal before the next run.
  const MonotonicMs heal_start = w.now;
  while (!site_converged(w, site) && w.now < heal_start + 60000) w.run(1000 - 50, 50);
  CHECK(site_converged(w, site));
  w.run(30000, 50);

  // --- Silent loss after the MAC ACK: 5 % of group frames ------------------
  // Link retries cannot see this loss; only the report deadlines and the
  // repair rounds recover it.
  lcg_state = 0x51E7ULL;
  g_silent_percent = 5;
  w.net.silent_drop = random_group_silent;
  const LossRun silent = run_alarm_under_loss(w, site);
  w.net.silent_drop = nullptr;
  CHECK(silent.reached_all_ms != 0);
  CHECK(silent.not_exactly_once == 0);
  CHECK(silent.result.state == DeliveryState::Delivered);
  CHECK(silent.result.delivered == 99 && silent.result.missing_total == 0 &&
        silent.result.unaccounted == 0);
  CHECK(silent.result.rounds >= 2);
  CHECK(silent.complete_ms <= 30000);
  std::fprintf(stderr,
               "  group: ALARM under 5%% silent loss: %zu/99 by 1 s, all 99 at %llu ms, exact "
               "summary after %u rounds at %llu ms; %llu copies + %llu reports = %.2f s air\n",
               silent.reached_by_1s, static_cast<unsigned long long>(silent.reached_all_ms),
               static_cast<unsigned>(silent.result.rounds),
               static_cast<unsigned long long>(silent.complete_ms),
               static_cast<unsigned long long>(silent.data.frames),
               static_cast<unsigned long long>(silent.reports.frames),
               static_cast<double>(airtime_us(silent.data) + airtime_us(silent.reports)) / 1e6);
  CHECK(site_converged(w, site));
}

struct Uplink {
  NodeId from;
  MessageId id;
  MonotonicMs at;
  MonotonicMs delivered_at;
};

struct BurstRun {
  double window_s{0};
  std::size_t refusals{0};
  std::size_t complete{0};
  std::size_t order_failures{0};
  SimNetwork::TxTally route{};
  SimNetwork::TxTally data{};
  SimNetwork::TxTally reports{};
  std::vector<Uplink> uplinks;
};

// 20 ordered display updates to group 3, submitted back-to-back (the host
// retries on WouldBlock every step), optionally with two occupancy events
// per second from random boards to the gateway for the first 120 s.
BurstRun run_burst(SimWorld& w, const Site& site, const GroupId display,
                   const std::size_t members, const bool group, const bool uplink) {
  BurstRun run{};
  const NodeId gw = site.gateway;
  const auto route_before = route_control(w);
  const auto data_before = tally_of(w, FrameType::GroupData);
  const auto report_before = tally_of(w, FrameType::GroupReport);
  std::map<NodeId, std::size_t> seen_before;
  for (const NodeId board : site.boards) seen_before[board] = w.obs(board)->group_messages.size();
  const MonotonicMs start = w.now;
  std::vector<MessageId> sent;
  MonotonicMs next_uplink = start;
  while (w.now < start + 240000) {
    if (group && sent.size() < 20) {
      MessageId id{};
      char text[32];
      std::snprintf(text, sizeof(text), "display:%02zu", sent.size());
      GroupSendOptions options{};
      options.ordered = true;
      options.lifetime_ms = 30000;
      const auto status = w.at(gw)->send_group(
          display, ByteView{reinterpret_cast<const std::uint8_t*>(text), std::strlen(text)},
          options, w.now, id);
      if (status.ok()) {
        sent.push_back(id);
      } else {
        CHECK(status.code == StatusCode::WouldBlock);
        ++run.refusals;
      }
    }
    if (uplink && w.now >= next_uplink && w.now < start + 120000) {
      next_uplink = w.now + 500;
      const NodeId from = site.boards[lcg_next() % site.boards.size()];
      const std::uint8_t occupied = 1;
      SendOptions options{};
      options.lifetime_ms = 5000;
      MessageId id{};
      if (w.at(from)->send(gw, ByteView{&occupied, 1}, options, w.now, id).ok()) {
        run.uplinks.push_back(Uplink{from, id, w.now, 0});
      }
    }
    w.run(0, 10);
    for (auto& up : run.uplinks) {
      if (up.delivered_at == 0 &&
          w.at(up.from)->delivery(up.id).state == DeliveryState::Delivered) {
        up.delivered_at = w.now;
      }
    }
    std::size_t terminal = 0;
    GroupDeliveryResult ignored{};
    for (const MessageId& id : sent) terminal += terminal_result(w, gw, id, ignored) ? 1 : 0;
    // Uplinks: 120 s of events plus a 10 s drain for the last receipts.
    if ((!group || terminal == 20) && (!uplink || w.now >= start + 130000)) break;
  }
  run.window_s = static_cast<double>(w.now - start) / 1000.0;
  for (const MessageId& id : sent) {
    GroupDeliveryResult result{};
    if (terminal_result(w, gw, id, result) && result.state == DeliveryState::Delivered &&
        result.delivered == members && result.nonmember == site.boards.size() - members &&
        result.missing_total == 0 && result.unaccounted == 0) {
      ++run.complete;
    }
  }
  // Every member saw the 20 in stream order, exactly once; non-members none.
  for (const NodeId board : site.boards) {
    std::vector<std::uint32_t> order;
    const auto& got = w.obs(board)->group_messages;
    for (std::size_t i = seen_before[board]; i < got.size(); ++i) {
      if (got[i].info.group == display) order.push_back(got[i].info.group_seq);
    }
    if (w.at(board)->group_member(display)) {
      bool sorted = order.size() == 20;
      for (std::size_t i = 1; i < order.size(); ++i) {
        sorted = sorted && order[i] == order[i - 1] + 1;
      }
      run.order_failures += sorted ? 0 : 1;
    } else {
      run.order_failures += order.empty() ? 0 : 1;
    }
  }
  run.route = minus(route_control(w), route_before);
  run.data = minus(tally_of(w, FrameType::GroupData), data_before);
  run.reports = minus(tally_of(w, FrameType::GroupReport), report_before);
  return run;
}

void test_hundred_node_burst() {
  // Two identical worlds: A runs the group burst alone, then the burst with
  // concurrent uplink occupancy events; B runs the same first phase and then
  // the same uplink pattern WITHOUT group traffic — the uplink baseline.
  SimWorld a;
  SimWorld b;
  Site site_a;
  Site site_b;
  build_site(a, site_a);
  build_site(b, site_b);
  const NodeId gw = site_a.gateway;
  // Half the boards subscribe to display group 3.
  const GroupId display = 3;
  std::size_t members = 0;
  for (const NodeId board : site_a.boards) {
    if (board % 2 == 0) {
      CHECK_OK(a.at(board)->set_group_membership(&display, 1));
      CHECK_OK(b.at(board)->set_group_membership(&display, 1));
      ++members;
    }
  }
  const double budget_us_per_s = static_cast<double>(a.at(gw)->config().group_airtime_us_per_s);

  // --- Phase 1: the burst alone — it must not disturb route maintenance ----
  const auto deferrals_before = a.at(gw)->group_stats().budget_deferrals;
  const BurstRun alone = run_burst(a, site_a, display, members, true, false);
  (void)run_burst(b, site_b, display, members, true, false);
  const double alone_route = static_cast<double>(airtime_us(alone.route)) / alone.window_s;
  const double alone_group =
      static_cast<double>(airtime_us(alone.data) + airtime_us(alone.reports));
  const double alone_bound =
      static_cast<double>(kGroupBudgetCapacityUs) + budget_us_per_s * alone.window_s;
  CHECK(alone.complete == 20);
  CHECK(alone.order_failures == 0);
  CHECK(alone_route <= kControlBudgetNetworkUsPerS);  // §14 management envelope
  CHECK(alone_group <= alone_bound);                   // the source's airtime bucket
  CHECK(a.at(gw)->group_stats().budget_deferrals > deferrals_before);  // it actually paced
  std::fprintf(stderr,
               "  group: burst of 20 ordered updates (%zu members), alone: %.1f s, %zu "
               "WouldBlock, %llu copies + %llu reports; group air %.0f us/s (bucket bound "
               "%.0f), route control %.0f us/s\n",
               members, alone.window_s, alone.refusals,
               static_cast<unsigned long long>(alone.data.frames),
               static_cast<unsigned long long>(alone.reports.frames),
               alone_group / alone.window_s, alone_bound / alone.window_s, alone_route);

  // --- Phase 2: burst + 2 uplinks/s (A) vs the same uplinks alone (B) ------
  lcg_state = 0xBEEFULL;
  const BurstRun mixed = run_burst(a, site_a, display, members, true, true);
  lcg_state = 0xBEEFULL;
  const BurstRun baseline = run_burst(b, site_b, display, members, false, true);
  CHECK(mixed.complete == 20);
  CHECK(mixed.order_failures == 0);
  struct UplinkStats {
    std::size_t lost{0};
    MonotonicMs p95{0};
    MonotonicMs worst{0};
  };
  const auto uplink_stats = [](const BurstRun& run) {
    UplinkStats out{};
    std::vector<MonotonicMs> latencies;
    for (const auto& up : run.uplinks) {
      if (up.delivered_at == 0) {
        ++out.lost;
        continue;
      }
      latencies.push_back(up.delivered_at - up.at);
      out.worst = std::max(out.worst, up.delivered_at - up.at);
    }
    std::sort(latencies.begin(), latencies.end());
    out.p95 = latencies.empty() ? 0 : latencies[latencies.size() * 95 / 100];
    return out;
  };
  const UplinkStats with_group = uplink_stats(mixed);
  const UplinkStats without_group = uplink_stats(baseline);
  CHECK(mixed.uplinks.size() >= 200 && mixed.uplinks.size() == baseline.uplinks.size());
  // No uplink starvation: the burst neither loses nor delays occupancy
  // events relative to the same traffic without it, and they stay fast.
  // (The few end-to-end failures of the baseline itself come from
  // load-coupled parent switching under this uplink pattern —
  // routing-scale.md §11 — identical with and without group traffic.)
  CHECK(with_group.lost <= without_group.lost);
  CHECK(with_group.lost * 100 <= mixed.uplinks.size() * 5);  // >= 95 % delivered
  CHECK(with_group.p95 <= without_group.p95 + 20);
  CHECK(with_group.p95 <= 200);
  const double mixed_group =
      static_cast<double>(airtime_us(mixed.data) + airtime_us(mixed.reports));
  CHECK(mixed_group <=
        static_cast<double>(kGroupBudgetCapacityUs) + budget_us_per_s * mixed.window_s);
  const double mixed_route = static_cast<double>(airtime_us(mixed.route)) / mixed.window_s;
  const double baseline_route =
      static_cast<double>(airtime_us(baseline.route)) / baseline.window_s;
  std::fprintf(stderr,
               "  group: burst + 2 uplinks/s: %.1f s, %llu copies + %llu reports, group air "
               "%.0f us/s, route control %.0f us/s (uplinks alone: %.0f us/s); %zu uplinks: "
               "p95 %llu ms (alone %llu), worst %llu ms (alone %llu), lost %zu (alone %zu)\n",
               mixed.window_s, static_cast<unsigned long long>(mixed.data.frames),
               static_cast<unsigned long long>(mixed.reports.frames),
               mixed_group / mixed.window_s, mixed_route, baseline_route,
               mixed.uplinks.size(), static_cast<unsigned long long>(with_group.p95),
               static_cast<unsigned long long>(without_group.p95),
               static_cast<unsigned long long>(with_group.worst),
               static_cast<unsigned long long>(without_group.worst), with_group.lost,
               without_group.lost);
  std::fprintf(stderr, "  group: sizeof(MeshNode) = %zu bytes\n", sizeof(MeshNode));
}

}  // namespace

int main(int argc, char** argv) {
  const std::string mode = argc > 1 ? argv[1] : "";
  if (mode.empty() || mode == "unit") {
    test_group_addressing();
    test_group_data_codec();
    test_group_report_codec();
    test_group_golden_payloads();
    test_group_security_scope();
    test_group_replay_table();
    test_many_groups_share_one_sender_context();
    test_small_tree_all();
    test_membership_counts();
    test_profile_and_source_rules();
    test_source_queue_and_urgent_reserve();
    test_repair_after_loss();
    test_dead_node_summary();
    test_not_child_is_counted_once();
    test_group_ordering_reorder();
    test_group_ordering_skip_and_late();
    test_unordered_never_held();
    test_unauthenticated_session_jump_is_ignored();
    test_authenticated_session_switch_commits();
    test_unicast_ordering();
  }
  if (mode.empty() || mode == "scale") {
    test_hundred_node_alarm();
    test_hundred_node_burst();
  }
  if (failures != 0) {
    std::fprintf(stderr, "%d group checks failed\n", failures);
    return 1;
  }
  std::puts("RouteLoom group delivery tests passed");
  return 0;
}
