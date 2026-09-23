// APPLIED delivery tests (docs/design/sdk-completion/01-applied-delivery.md):
//  - APP_RESULT body codecs: RESULT/QUERY/RESULT_ACK/STATUS round-trips and
//    strict rejects (§1.2), digest determinism, lease layout.
//  - send_applied admission checks (§1.3, §1.6).
//  - Origin state machine on the sim mesh: END_RECEIPT never promotes an
//    Applied delivery, bounded QUERY recovery, Indeterminate timeout, late
//    RESULT handling, RESULT replay/conflict discipline (§1.3/§1.5).
//  - Terminal state machine: single endpoint invocation, stored-verdict
//    replays, refusal RESULTs, STATUS answers, RESULT_ACK validation
//    (§1.4/§1.5).
//  - Multi-hop APPLIED request + RESULT traversal (§1.2 routed lane).

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "routeloom/byte_io.hpp"
#include "routeloom/endpoint_wire.hpp"
#include "routeloom/node.hpp"
#include "routeloom/types.hpp"
#include "routeloom/wire.hpp"

#include "test_security.hpp"
#include "test_sim.hpp"

namespace {

int failures = 0;
#define CHECK(expr) do { if (!(expr)) { std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__, #expr); ++failures; } } while (false)
#define CHECK_OK(expr) do { const auto _status = (expr); if (!_status.ok()) { std::fprintf(stderr, "STATUS failed %s:%d: %s (%s)\n", __FILE__, __LINE__, #expr, _status.detail); ++failures; } } while (false)

using namespace routeloom;
using routeloom_test::FrameSight;
using routeloom_test::SimNetwork;
using routeloom_test::TestSecurity;
using routeloom_test::sight_frame;
namespace ep = routeloom::endpoint;

constexpr NetworkId kNet = 7;

// ---------------------------------------------------------------- fixtures

// NodeObserver with the APPLIED surface captured (CapturingObserver in
// test_sim.hpp is final, so this is a parallel implementation).
struct AppliedObserver final : NodeObserver {
  std::vector<std::vector<std::uint8_t>> messages;
  std::vector<DeliveryResult> delivery_events;
  std::vector<std::string> diagnostics;
  std::vector<std::pair<MessageKey, AppliedResultView>> applied;

  void on_message(const MessageKey&, NodeId, ByteView payload) noexcept override {
    messages.emplace_back(payload.data, payload.data + payload.size);
  }
  void on_delivery(const DeliveryResult& result) noexcept override {
    delivery_events.push_back(result);
  }
  void on_diagnostic(const char* reason, NodeId, const MessageId*) noexcept override {
    diagnostics.emplace_back(reason);
  }
  void on_applied_result(const MessageKey& key,
                         const AppliedResultView& view) noexcept override {
    applied.emplace_back(key, view);
  }
  bool has_diag(const char* prefix) const {
    for (const auto& d : diagnostics) {
      if (d.rfind(prefix, 0) == 0) return true;
    }
    return false;
  }
  std::size_t diag_count(const char* prefix) const {
    std::size_t n = 0;
    for (const auto& d : diagnostics) {
      if (d.rfind(prefix, 0) == 0) ++n;
    }
    return n;
  }
};

// Synchronous counting endpoint for the terminal side (§1.4).
struct CountingSink final : AppliedEndpointSink {
  int calls{0};
  ep::AppResultOutcome outcome{ep::AppResultOutcome::Success};
  std::uint32_t code{7};
  std::vector<std::uint8_t> data{0xde, 0xad};
  // Captured request fields (payload copied — the view dangles otherwise).
  MessageKey last_key{};
  NodeId last_source{kInvalidNodeId};
  std::uint32_t last_remaining_ms{0};
  std::vector<std::uint8_t> last_payload;

  void on_applied_request(const AppliedRequest& request,
                          AppliedReply& reply) noexcept override {
    ++calls;
    last_key = request.key;
    last_source = request.source;
    last_remaining_ms = request.remaining_ms;
    last_payload.assign(request.payload.data,
                        request.payload.data + request.payload.size);
    reply.outcome = outcome;
    reply.code = code;
    reply.size = static_cast<std::uint8_t>(
        std::min<std::size_t>(data.size(), ep::kAppResultDataMax));
    std::copy_n(data.begin(), reply.size, reply.data.data());
  }
};

// Radio that records every submitted frame and can swallow a bounded number
// of physical sends of one frame type — the sender sees a successful TX that
// the peer never receives (RF loss), reported through lost_tokens exactly
// like a driver TX-complete (mirrors FlakyRadio/DropTypeRadio precedent).
class TapRadio final : public RadioPort {
 public:
  TapRadio(SimNetwork& net, NodeId owner) : net_(net), owner_(owner) {}

  std::vector<std::vector<std::uint8_t>> sent;
  std::deque<std::uint64_t> lost_tokens;
  FrameType drop_type{FrameType::AppResult};
  int drop_sends{0};  // number of matching physical sends to swallow

  Status send(NodeId peer, std::uint64_t token, ByteView frame) noexcept override {
    sent.emplace_back(frame.data, frame.data + frame.size);
    FrameSight sight{};
    if (drop_sends > 0 && sight_frame(frame, sight) && sight.type == drop_type) {
      --drop_sends;
      lost_tokens.push_back(token);
      return Status::success();
    }
    return net_.enqueue(owner_, peer, token, frame);
  }
  Status recover() noexcept override { return Status::success(); }

  std::size_t sent_type(FrameType type, NodeId to = kInvalidNodeId) const {
    std::size_t n = 0;
    for (const auto& frame : sent) {
      FrameSight sight{};
      if (sight_frame(ByteView{frame.data(), frame.size()}, sight) &&
          sight.type == type &&
          (to == kInvalidNodeId || sight.to == to)) {
        ++n;
      }
    }
    return n;
  }

 private:
  SimNetwork& net_;
  NodeId owner_;
};

struct World {
  struct Bundle {
    std::unique_ptr<TestSecurity> sec;
    std::unique_ptr<AppliedObserver> obs;
    std::unique_ptr<TapRadio> radio;
    std::unique_ptr<MeshNode> node;
    std::unique_ptr<CountingSink> sink;
  };
  SimNetwork net;
  std::map<NodeId, Bundle> nodes;
  MonotonicMs now{0};
  TestSecurity scratch;  // interchangeable cipher for crafting/cracking frames

  MeshNode* add(NodeId id, std::uint32_t hop_timeout_ms = 60) {
    NodeConfig cfg{};
    cfg.network = kNet;
    cfg.node = id;
    cfg.message_session = 100 + static_cast<std::uint32_t>(id);
    cfg.boot_incarnation = 0xB000 + static_cast<std::uint32_t>(id);
    cfg.route_generation = 1;
    cfg.route_advertisement_period_ms = 100;
    cfg.route_lifetime_ms = 15000;
    cfg.hop_accept_timeout_ms = hop_timeout_ms;
    cfg.max_link_attempts = 2;
    cfg.max_end_to_end_rounds = 3;
    auto& b = nodes[id];
    b.sec = std::make_unique<TestSecurity>();
    b.obs = std::make_unique<AppliedObserver>();
    b.radio = std::make_unique<TapRadio>(net, id);
    b.node = std::make_unique<MeshNode>(cfg, *b.radio, *b.sec, *b.obs);
    net.register_node(id, b.node.get());
    return b.node.get();
  }
  MeshNode* at(NodeId id) const { return nodes.at(id).node.get(); }
  AppliedObserver* obs(NodeId id) const { return nodes.at(id).obs.get(); }
  TapRadio* radio(NodeId id) const { return nodes.at(id).radio.get(); }
  CountingSink* install_sink(NodeId id) {
    auto& b = nodes.at(id);
    b.sink = std::make_unique<CountingSink>();
    b.node->set_applied_sink(b.sink.get());
    return b.sink.get();
  }
  void link(NodeId a, NodeId b) {
    net.connect(a, b);
    CHECK_OK(at(a)->add_neighbor(b, 1, now));
    CHECK_OK(at(b)->add_neighbor(a, 1, now));
  }
  void start_all() {
    for (auto& [id, b] : nodes) CHECK_OK(b.node->start(now));
  }
  // One step: poll every node, flush the radio queue, then report the
  // driver-level "TX ok, frame lost in RF" completions for swallowed sends.
  void step() {
    for (auto& [id, b] : nodes) b.node->poll(now);
    net.flush(now);
    for (auto& [id, b] : nodes) {
      while (!b.radio->lost_tokens.empty()) {
        b.node->on_radio_tx_result(b.radio->lost_tokens.front(), true, now);
        b.radio->lost_tokens.pop_front();
      }
    }
  }
  void run(MonotonicMs duration_ms, MonotonicMs step_ms = 5) {
    const MonotonicMs end = now + duration_ms;
    while (now < end) {
      now += step_ms;
      step();
    }
  }
  // Steps until `pred` or the budget elapses; returns pred's result.
  template <typename Pred>
  bool run_until(Pred pred, MonotonicMs budget_ms) {
    const MonotonicMs end = now + budget_ms;
    while (!pred() && now < end) {
      now += 5;
      step();
    }
    return pred();
  }
};

// ------------------------------------------------------------ craft helpers

wire::EncodedFrame craft_frame(TestSecurity& sec, const wire::Header& header,
                               ByteView payload) {
  wire::PlainFrame plain{};
  plain.header = header;
  plain.payload_size = payload.size;
  if (payload.size > 0) {
    std::memcpy(plain.payload.data(), payload.data, payload.size);
  }
  wire::EncodedFrame out{};
  CHECK_OK(wire::encode_new(plain, sec, out));
  return out;
}

wire::Header app_result_carrier(NodeId issuer, NodeId origin,
                                MessageId wire_id) {
  wire::Header h{};
  h.type = FrameType::AppResult;
  h.flags = wire::kFlagEndProtected;
  h.delivery = DeliveryClass::Reliable;  // carrier is never Applied itself
  h.delivery_round = 0;
  h.hop_remaining = kDefaultHopLimit;
  h.network = kNet;
  h.origin = issuer;
  h.destination = origin;
  h.previous_hop = issuer;
  h.next_hop = origin;
  h.message = wire_id;
  h.remaining_deadline_ms = 4000;
  h.original_lifetime_ms = 4000;
  h.link_epoch = 1;
  h.end_epoch = 1;
  return h;
}

ep::AppResultHead result_head(const MessageId& request_id, NodeId origin,
                              NodeId issuer, ByteView request_body,
                              std::uint32_t lifetime_ms) {
  ep::AppResultHead head{};
  head.subtype = ep::AppResultSubtype::Result;
  head.outcome = static_cast<std::uint8_t>(ep::AppResultOutcome::Success);
  head.network = static_cast<std::uint32_t>(kNet);
  head.original_origin = origin;
  head.original_session = request_id.session;
  head.original_sequence = request_id.sequence;
  head.original_destination = issuer;
  ep::applied_request_digest(kNet, origin, issuer, request_id.session,
                             request_id.sequence, DeliveryClass::Applied,
                             lifetime_ms, request_body, head.request_digest);
  return head;
}

// Decrypt a captured wire frame addressed to `receiver` (direct-hop frames
// only — next_hop must be the bound destination for open_end).
bool crack_frame(TestSecurity& sec, const std::vector<std::uint8_t>& bytes,
                 wire::PlainFrame& out) {
  FrameSight sight{};
  if (!sight_frame(ByteView{bytes.data(), bytes.size()}, sight)) return false;
  wire::LinkOpenedFrame link{};
  if (!wire::open_link(ByteView{bytes.data(), bytes.size()}, sight.to, sec, link)) {
    return false;
  }
  return wire::open_end(link, sight.to, sec, out).ok();
}

std::vector<std::uint8_t> request_body(const ExecutionLease& lease,
                                       ByteView payload) {
  std::vector<std::uint8_t> body(lease.begin(), lease.end());
  body.insert(body.end(), payload.data, payload.data + payload.size);
  return body;
}

SendOptions applied_options(std::uint32_t lifetime_ms = 5000,
                            std::uint8_t hop_limit = 1) {
  SendOptions options{};
  options.delivery = DeliveryClass::Applied;
  options.lifetime_ms = lifetime_ms;
  options.hop_limit = hop_limit;
  return options;
}

const std::array<std::uint8_t, 4> kUserPayload{{0x61, 0x62, 0x63, 0x64}};
ByteView user_payload() {
  return ByteView{kUserPayload.data(), kUserPayload.size()};
}

// ------------------------------------------------------- codec tests (§1.2)

ep::AppResultBody sample_result(std::uint16_t data_size = 3) {
  ep::AppResultBody body{};
  body.head.subtype = ep::AppResultSubtype::Result;
  body.head.outcome = static_cast<std::uint8_t>(ep::AppResultOutcome::Failure);
  body.head.network = 7;
  body.head.original_origin = 0x11;
  body.head.original_session = 0x22;
  body.head.original_sequence = 0x33445566778899aaULL;
  body.head.original_destination = 0x99;
  for (std::size_t i = 0; i < body.head.request_digest.size(); ++i) {
    body.head.request_digest[i] = static_cast<std::uint8_t>(i);
  }
  body.application_code = 0x01020304;
  body.data_size = data_size;
  for (std::size_t i = 0; i < data_size; ++i) {
    body.data[i] = static_cast<std::uint8_t>(0xA0 + i);
  }
  return body;
}

ep::AppResultHead sample_head(ep::AppResultSubtype subtype) {
  ep::AppResultHead head{};
  head.subtype = subtype;
  head.outcome = 0;
  head.network = 7;
  head.original_origin = 0x11;
  head.original_session = 0x22;
  head.original_sequence = 0x33445566778899aaULL;
  head.original_destination = 0x99;
  for (std::size_t i = 0; i < head.request_digest.size(); ++i) {
    head.request_digest[i] = static_cast<std::uint8_t>(i * 3 + 1);
  }
  return head;
}

std::vector<std::uint8_t> mutated(const ep::EncodedServicePayload& enc,
                                  std::size_t offset, std::uint8_t value) {
  std::vector<std::uint8_t> bytes(enc.bytes.begin(), enc.bytes.begin() + enc.size);
  bytes[offset] = value;
  return bytes;
}

ByteView view_of(const std::vector<std::uint8_t>& bytes) {
  return ByteView{bytes.data(), bytes.size()};
}

void test_result_codec() {
  // Round-trip with a partial data tail and with a full 48B tail.
  for (const std::uint16_t size : {0, 3, 48}) {
    ep::AppResultBody body = sample_result(size);
    ep::EncodedServicePayload enc{};
    CHECK_OK(ep::app_result_encode(body, enc));
    CHECK(enc.size == ep::kAppResultBodyMinSize + size);
    // Head field byte offsets (§1.2): version|subtype|outcome|flags.
    CHECK(enc.bytes[0] == 1);
    CHECK(enc.bytes[1] == static_cast<std::uint8_t>(ep::AppResultSubtype::Result));
    CHECK(enc.bytes[2] == static_cast<std::uint8_t>(ep::AppResultOutcome::Failure));
    CHECK(enc.bytes[3] == 0);
    ep::AppResultBody decoded{};
    CHECK_OK(ep::app_result_decode(enc.view(), decoded));
    CHECK(decoded.head.subtype == ep::AppResultSubtype::Result);
    CHECK(decoded.head.outcome == body.head.outcome);
    CHECK(decoded.head.network == 7);
    CHECK(decoded.head.original_origin == body.head.original_origin);
    CHECK(decoded.head.original_session == body.head.original_session);
    CHECK(decoded.head.original_sequence == body.head.original_sequence);
    CHECK(decoded.head.original_destination == body.head.original_destination);
    CHECK(decoded.head.request_digest == body.head.request_digest);
    CHECK(decoded.application_code == body.application_code);
    CHECK(decoded.data_size == size);
    CHECK(std::equal(decoded.data.begin(), decoded.data.begin() + size,
                     body.data.begin()));
    // Deterministic re-encode: byte-identical canonical form.
    ep::EncodedServicePayload reenc{};
    CHECK_OK(ep::app_result_encode(decoded, reenc));
    CHECK(reenc.size == enc.size);
    CHECK(std::equal(reenc.bytes.begin(), reenc.bytes.begin() + reenc.size,
                     enc.bytes.begin()));
  }

  ep::AppResultBody body = sample_result(2);
  ep::EncodedServicePayload enc{};
  CHECK_OK(ep::app_result_encode(body, enc));

  // Rejects: version, subtype shadowing, outcome range, flags, sizes.
  ep::AppResultBody decoded{};
  CHECK(!ep::app_result_decode(view_of(mutated(enc, 0, 0)), decoded).ok());
  CHECK(!ep::app_result_decode(view_of(mutated(enc, 0, 2)), decoded).ok());
  CHECK(!ep::app_result_decode(view_of(mutated(enc, 1, 2)), decoded).ok());   // QUERY under RESULT decoder
  CHECK(!ep::app_result_decode(view_of(mutated(enc, 1, 5)), decoded).ok());   // subtype out of range
  CHECK(!ep::app_result_decode(view_of(mutated(enc, 2, 2)), decoded).ok());   // outcome > Failure
  CHECK(!ep::app_result_decode(view_of(mutated(enc, 3, 1)), decoded).ok());   // flags != 0
  // Network/origin/destination/sequence are reserved-nonzero head fields.
  auto zeroed = [&](std::size_t off, std::size_t len) {
    std::vector<std::uint8_t> b(enc.bytes.begin(), enc.bytes.begin() + enc.size);
    std::fill(b.begin() + off, b.begin() + off + len, 0);
    return b;
  };
  CHECK(!ep::app_result_decode(view_of(zeroed(4, 4)), decoded).ok());    // network
  CHECK(!ep::app_result_decode(view_of(zeroed(8, 8)), decoded).ok());    // origin
  CHECK(!ep::app_result_decode(view_of(zeroed(28, 8)), decoded).ok());   // destination
  CHECK(!ep::app_result_decode(view_of(zeroed(20, 8)), decoded).ok());   // sequence
  // Length discipline: below min, trailing bytes, result_len mismatch.
  CHECK(!ep::app_result_decode(
            ByteView{enc.bytes.data(), ep::kAppResultBodyMinSize - 1}, decoded)
            .ok());
  {
    std::vector<std::uint8_t> extra(enc.bytes.begin(), enc.bytes.begin() + enc.size);
    extra.push_back(0xEE);
    CHECK(!ep::app_result_decode(view_of(extra), decoded).ok());
    // result_len smaller than the tail -> trailing bytes rejected.
    std::vector<std::uint8_t> short_len = mutated(enc, ep::kAppResultHeadSize + 4 + 1, 1);
    CHECK(!ep::app_result_decode(view_of(short_len), decoded).ok());
    // result_len beyond kAppResultDataMax rejected outright.
    std::vector<std::uint8_t> big_len(enc.bytes.begin(), enc.bytes.begin() + enc.size);
    big_len[ep::kAppResultHeadSize + 4] = 0;
    big_len[ep::kAppResultHeadSize + 5] = ep::kAppResultDataMax + 1;
    big_len.resize(ep::kAppResultBodyMinSize + ep::kAppResultDataMax + 1);
    CHECK(!ep::app_result_decode(view_of(big_len), decoded).ok());
  }
  // Encode-side rejects: data over kAppResultDataMax, bad subtype/outcome/head.
  ep::AppResultBody bad = sample_result(0);
  bad.data_size = ep::kAppResultDataMax + 1;
  CHECK(!ep::app_result_encode(bad, enc).ok());
  bad = sample_result(0);
  bad.head.subtype = ep::AppResultSubtype::Query;
  CHECK(!ep::app_result_encode(bad, enc).ok());
  bad = sample_result(0);
  bad.head.outcome = 2;
  CHECK(!ep::app_result_encode(bad, enc).ok());
  bad = sample_result(0);
  bad.head.network = 0;
  CHECK(!ep::app_result_encode(bad, enc).ok());
  bad = sample_result(0);
  bad.head.original_sequence = 0;
  CHECK(!ep::app_result_encode(bad, enc).ok());
}

void test_query_status_ack_codecs() {
  // QUERY round-trip (76B, nonce u64 tail).
  ep::AppResultQuery query{};
  query.head = sample_head(ep::AppResultSubtype::Query);
  query.query_nonce = 0x0102030405060708ULL;
  ep::EncodedServicePayload enc{};
  CHECK_OK(ep::app_result_query_encode(query, enc));
  CHECK(enc.size == ep::kAppResultQuerySize);
  CHECK(enc.bytes[1] == static_cast<std::uint8_t>(ep::AppResultSubtype::Query));
  ep::AppResultQuery qdec{};
  CHECK_OK(ep::app_result_query_decode(enc.view(), qdec));
  CHECK(qdec.query_nonce == query.query_nonce);
  CHECK(qdec.head.original_sequence == query.head.original_sequence);
  CHECK(qdec.head.request_digest == query.head.request_digest);
  // Rejects: nonce 0 (both sides), wrong size, nonzero outcome, wrong subtype.
  query.query_nonce = 0;
  CHECK(!ep::app_result_query_encode(query, enc).ok());
  CHECK(!ep::app_result_query_decode(
            ByteView{enc.bytes.data(), ep::kAppResultQuerySize - 1}, qdec).ok());
  CHECK(!ep::app_result_query_decode(view_of(mutated(enc, 2, 1)), qdec).ok());
  CHECK(!ep::app_result_query_decode(view_of(mutated(enc, 1, 4)), qdec).ok());
  {
    auto tail = mutated(enc, ep::kAppResultQuerySize - 1, 0);
    std::fill(tail.begin() + ep::kAppResultHeadSize, tail.end(), 0);
    CHECK(!ep::app_result_query_decode(view_of(tail), qdec).ok());
  }

  // STATUS round-trip: nonce echo, outcome is the status code band.
  for (const auto code : {ep::AppResultStatusCode::Pending,
                          ep::AppResultStatusCode::Indeterminate,
                          ep::AppResultStatusCode::Expired,
                          ep::AppResultStatusCode::NotRetained}) {
    ep::AppResultStatus status{};
    status.head = sample_head(ep::AppResultSubtype::Status);
    status.head.outcome = static_cast<std::uint8_t>(code);
    status.query_nonce = 0xCAFEBABEULL;
    CHECK_OK(ep::app_result_status_encode(status, enc));
    CHECK(enc.size == ep::kAppResultStatusSize);
    ep::AppResultStatus sdec{};
    CHECK_OK(ep::app_result_status_decode(enc.view(), sdec));
    CHECK(sdec.query_nonce == status.query_nonce);
    CHECK(sdec.head.outcome == status.head.outcome);
  }
  ep::AppResultStatus status{};
  status.head = sample_head(ep::AppResultSubtype::Status);
  status.head.outcome = static_cast<std::uint8_t>(ep::AppResultStatusCode::Expired);
  status.query_nonce = 9;
  CHECK_OK(ep::app_result_status_encode(status, enc));
  ep::AppResultStatus sdec{};
  CHECK(!ep::app_result_status_decode(view_of(mutated(enc, 2, 0)), sdec).ok());  // outcome 0
  CHECK(!ep::app_result_status_decode(view_of(mutated(enc, 2, 5)), sdec).ok());  // outcome > NotRetained
  CHECK(!ep::app_result_status_decode(view_of(mutated(enc, 1, 1)), sdec).ok());  // RESULT under STATUS decoder
  status.query_nonce = 0;
  CHECK(!ep::app_result_status_encode(status, enc).ok());
  status.query_nonce = 9;
  status.head.outcome = 0;
  CHECK(!ep::app_result_status_encode(status, enc).ok());

  // RESULT_ACK round-trip (100B, digest tail).
  ep::AppResultAck ack{};
  ack.head = sample_head(ep::AppResultSubtype::ResultAck);
  for (std::size_t i = 0; i < ack.result_digest.size(); ++i) {
    ack.result_digest[i] = static_cast<std::uint8_t>(0xF0 - i);
  }
  CHECK_OK(ep::app_result_ack_encode(ack, enc));
  CHECK(enc.size == ep::kAppResultAckSize);
  ep::AppResultAck adec{};
  CHECK_OK(ep::app_result_ack_decode(enc.view(), adec));
  CHECK(adec.result_digest == ack.result_digest);
  CHECK(adec.head.original_destination == ack.head.original_destination);
  CHECK(!ep::app_result_ack_decode(view_of(mutated(enc, 2, 1)), adec).ok());  // outcome must be 0
  CHECK(!ep::app_result_ack_decode(
            ByteView{enc.bytes.data(), ep::kAppResultAckSize - 1}, adec).ok());
  ack.head.outcome = 1;
  CHECK(!ep::app_result_ack_encode(ack, enc).ok());
}

void test_digests() {
  const std::array<std::uint8_t, 6> payload{{1, 2, 3, 4, 5, 6}};
  std::array<std::uint8_t, 32> a{};
  std::array<std::uint8_t, 32> b{};
  ep::applied_request_digest(kNet, 1, 2, 100, 5, DeliveryClass::Applied, 5000,
                             ByteView{payload.data(), payload.size()}, a);
  ep::applied_request_digest(kNet, 1, 2, 100, 5, DeliveryClass::Applied, 5000,
                             ByteView{payload.data(), payload.size()}, b);
  CHECK(a == b);  // deterministic
  // Every bound field perturbs the digest.
  ep::applied_request_digest(kNet, 1, 2, 100, 6, DeliveryClass::Applied, 5000,
                             ByteView{payload.data(), payload.size()}, b);
  CHECK(a != b);  // sequence
  ep::applied_request_digest(kNet, 1, 3, 100, 5, DeliveryClass::Applied, 5000,
                             ByteView{payload.data(), payload.size()}, b);
  CHECK(a != b);  // destination
  ep::applied_request_digest(kNet, 1, 2, 100, 5, DeliveryClass::Reliable, 5000,
                             ByteView{payload.data(), payload.size()}, b);
  CHECK(a != b);  // delivery class
  ep::applied_request_digest(kNet, 1, 2, 100, 5, DeliveryClass::Applied, 5001,
                             ByteView{payload.data(), payload.size()}, b);
  CHECK(a != b);  // original lifetime
  ep::applied_request_digest(kNet, 1, 2, 100, 5, DeliveryClass::Applied, 5000,
                             ByteView{payload.data(), payload.size() - 1}, b);
  CHECK(a != b);  // payload
  // Result digest: domain-separated, deterministic.
  ep::applied_result_digest(ByteView{payload.data(), payload.size()}, a);
  ep::applied_result_digest(ByteView{payload.data(), payload.size()}, b);
  CHECK(a == b);
  std::array<std::uint8_t, 32> c{};
  ep::applied_request_digest(kNet, 1, 2, 100, 5, DeliveryClass::Applied, 5000,
                             ByteView{payload.data(), payload.size()}, c);
  CHECK(a != c);  // different domain strings
}

void test_lease_layout() {
  World w;
  MeshNode* node = w.add(2);
  // Wire v2: message_session u32 | end_epoch u32 | boot_incarnation u64.
  const ExecutionLease lease = node->applied_lease();
  ByteReader reader(ByteView{lease.data(), lease.size()});
  std::uint32_t session = 0;
  std::uint32_t epoch = 0;
  std::uint64_t boot = 0;
  CHECK_OK(reader.read_u32(session));
  CHECK_OK(reader.read_u32(epoch));
  CHECK_OK(reader.read_u64(boot));
  CHECK(reader.remaining() == 0);
  CHECK(session == 102);
  CHECK(epoch == 1);
  CHECK(boot == 0xB002);
  // The nonzero message session guarantees a computed lease is never all-zero.
  bool nonzero = false;
  for (const auto byte : lease) nonzero |= byte != 0;
  CHECK(nonzero);
  // A different boot incarnation produces a different lease.
  w.add(3);
  CHECK(w.at(3)->applied_lease() != lease);
}

void test_send_applied_validation() {
  World w;
  MeshNode* a = w.add(1);
  MeshNode* b = w.add(2);
  w.start_all();
  w.link(1, 2);
  const ExecutionLease lease = b->applied_lease();
  MessageId id{};

  // delivery class must be Applied.
  SendOptions wrong_class{};
  wrong_class.delivery = DeliveryClass::Reliable;
  CHECK(a->send_applied(2, user_payload(), lease, wrong_class, w.now, id).code ==
        StatusCode::InvalidArgument);
  // send() never accepts Applied — no silent downgrade path (§1.3).
  SendOptions applied = applied_options();
  CHECK(a->send(2, user_payload(), applied, w.now, id).code ==
        StatusCode::Unsupported);
  // persist_across_sleep is deferred (§1.10).
  applied.persist_across_sleep = true;
  CHECK(a->send_applied(2, user_payload(), lease, applied, w.now, id).code ==
        StatusCode::Unsupported);
  applied.persist_across_sleep = false;
  // Payload bound: 112B ok, 113B refused (§1.6).
  std::array<std::uint8_t, kAppliedUserPayloadMax> max_payload{};
  std::array<std::uint8_t, kAppliedUserPayloadMax + 1> over_payload{};
  CHECK_OK(a->send_applied(2, ByteView{max_payload.data(), max_payload.size()},
                           lease, applied, w.now, id));
  CHECK(a->send_applied(2, ByteView{over_payload.data(), over_payload.size()},
                        lease, applied, w.now, id)
            .code == StatusCode::InvalidArgument);
  // Identity guards: self/invalid destination, zero lifetime/hop_limit.
  CHECK(a->send_applied(1, user_payload(), lease, applied, w.now, id).code ==
        StatusCode::InvalidArgument);
  CHECK(a->send_applied(kInvalidNodeId, user_payload(), lease, applied, w.now, id)
            .code == StatusCode::InvalidArgument);
  SendOptions no_life = applied_options(0);
  CHECK(a->send_applied(2, user_payload(), lease, no_life, w.now, id).code ==
        StatusCode::InvalidArgument);
  SendOptions no_hops = applied_options(5000, 0);
  CHECK(a->send_applied(2, user_payload(), lease, no_hops, w.now, id).code ==
        StatusCode::InvalidArgument);
  // The accepted 112B send resolves normally once the world runs.
  w.install_sink(2);
  w.run(500);
  CHECK(a->delivery(id).state == DeliveryState::Delivered);
}

// ------------------------------------------------------- mesh-level helpers

// Performs a full successful APPLIED exchange 1 -> 2 and returns the id.
MessageId applied_exchange(World& w, std::uint32_t lifetime_ms = 5000,
                           std::uint8_t hop_limit = 1,
                           const ExecutionLease* lease = nullptr) {
  const ExecutionLease real =
      lease != nullptr ? *lease : w.at(2)->applied_lease();
  MessageId id{};
  CHECK_OK(w.at(1)->send_applied(2, user_payload(), real,
                                 applied_options(lifetime_ms, hop_limit), w.now,
                                 id));
  return id;
}

// Counts APP_RESULT frames a node's radio submitted toward `to`.
std::size_t app_frames_to(const TapRadio& radio, NodeId to) {
  return radio.sent_type(FrameType::AppResult, to);
}

void test_happy_path() {
  World w;
  MeshNode* a = w.add(1);
  MeshNode* b = w.add(2);
  w.start_all();
  w.link(1, 2);
  CountingSink* sink = w.install_sink(2);

  const MessageId id = applied_exchange(w);
  w.run(500);

  // Terminal verdict at the origin (§1.3): applied, not merely received.
  const auto result = a->delivery(id);
  CHECK(result.state == DeliveryState::Delivered);
  CHECK(std::strcmp(result.reason, "APP_APPLIED") == 0);

  // Endpoint invoked exactly once, with the lease stripped from the payload.
  CHECK(sink->calls == 1);
  CHECK(sink->last_source == 1);
  CHECK(sink->last_key.origin == 1 && sink->last_key.id == id);
  CHECK(sink->last_payload ==
        std::vector<std::uint8_t>(kUserPayload.begin(), kUserPayload.end()));
  CHECK(sink->last_remaining_ms > 0 && sink->last_remaining_ms <= 5000);

  // APPLIED payloads never reach the on_message application path (§1.4).
  CHECK(w.obs(2)->messages.empty());

  // applied_result() exposes outcome+code+data (§1.3).
  AppliedResultView view{};
  CHECK(a->applied_result(id, view));
  CHECK(view.present && !view.late);
  CHECK(view.outcome == ep::AppResultOutcome::Success);
  CHECK(view.code == 7);
  CHECK(view.size == 2 && view.data[0] == 0xde && view.data[1] == 0xad);
  // Observer fired exactly once with the same view.
  CHECK(w.obs(1)->applied.size() == 1);
  CHECK(w.obs(1)->applied[0].second.code == 7);
  CHECK(w.obs(1)->applied[0].first.id == id);

  // Counters on both ends (§1.6 bookkeeping).
  const auto& dstats = b->applied_stats();
  CHECK(dstats.requests_dispatched == 1);
  CHECK(dstats.results_committed == 1);
  CHECK(dstats.results_emitted == 1);
  CHECK(dstats.result_acks == 1);  // RESULT_ACK validated against the record
  const auto& ostats = a->applied_stats();
  CHECK(ostats.results_accepted == 1);
  CHECK(ostats.queries_sent == 0);

  // Wire-level check: exactly one RESULT frame 2 -> 1, decodes to the verdict.
  const TapRadio* dradio = w.radio(2);
  std::size_t result_frames = 0;
  for (const auto& frame : dradio->sent) {
    FrameSight sight{};
    if (!sight_frame(ByteView{frame.data(), frame.size()}, sight) ||
        sight.type != FrameType::AppResult || sight.to != 1) {
      continue;
    }
    wire::PlainFrame plain{};
    CHECK(crack_frame(w.scratch, frame, plain));
    CHECK(plain.payload_size <= ep::kAppResultBodyMaxSize);
    ep::AppResultBody body{};
    CHECK_OK(ep::app_result_decode(
        ByteView{plain.payload.data(), plain.payload_size}, body));
    CHECK(body.head.subtype == ep::AppResultSubtype::Result);
    CHECK(body.head.original_origin == 1);
    CHECK(body.head.original_destination == 2);
    CHECK(body.head.original_session == id.session);
    CHECK(body.head.original_sequence == id.sequence);
    CHECK(body.application_code == 7);
    CHECK(body.data_size == 2);
    ++result_frames;
    // Worst-case RESULT stays inside the 250B ESP-NOW envelope.
    CHECK(frame.size() <= kMaxEspNowBody);
  }
  CHECK(result_frames == 1);
  // The origin answered with exactly one RESULT_ACK toward the terminal.
  CHECK(app_frames_to(*w.radio(1), 2) == 1);
}

void test_end_receipt_alone_never_promotes() {
  World w;
  MeshNode* a = w.add(1);
  w.add(2);
  w.start_all();
  w.link(1, 2);
  CountingSink* sink = w.install_sink(2);
  w.radio(2)->drop_sends = 1000000;  // every RESULT is lost in RF

  const MessageId id = applied_exchange(w);
  // Wait for the END_RECEIPT to land: the delivery reports APP_RESULT_PENDING
  // and must sit in WaitingForEndReceipt — never promoted on receipt alone.
  CHECK(w.run_until(
      [&] {
        const auto r = a->delivery(id);
        return r.state == DeliveryState::WaitingForEndReceipt &&
               std::strcmp(r.reason, "APP_RESULT_PENDING") == 0;
      },
      2000));
  w.run(600);  // spans the 250ms app window twice — still pending
  const auto mid = a->delivery(id);
  CHECK(mid.state == DeliveryState::WaitingForEndReceipt);
  CHECK(std::strcmp(mid.reason, "APP_RESULT_PENDING") == 0);
  for (const auto& e : w.obs(1)->delivery_events) {
    CHECK(e.state != DeliveryState::Delivered);
    CHECK(e.state != DeliveryState::Failed);
  }
  AppliedResultView view{};
  CHECK(!a->applied_result(id, view));
  CHECK(sink->calls == 1);  // verdict committed at the terminal, just lost
}

void test_result_timeout_indeterminate() {
  World w;
  MeshNode* a = w.add(1);
  MeshNode* b = w.add(2);
  w.start_all();
  w.link(1, 2);
  w.install_sink(2);
  w.radio(2)->drop_sends = 1000000;

  const MessageId id = applied_exchange(w, 3000);
  w.run(4000);  // outlive the delivery deadline

  const auto result = a->delivery(id);
  CHECK(result.state == DeliveryState::Indeterminate);
  CHECK(std::strcmp(result.reason, "APP_RESULT_TIMEOUT") == 0);
  for (const auto& e : w.obs(1)->delivery_events) {
    CHECK(e.state != DeliveryState::Delivered);
    CHECK(e.state != DeliveryState::Failed);
  }
  // Bounded QUERY recovery was attempted: exactly kAppliedMaxQueries, each
  // with a fresh nonce, each seen at the terminal (§1.3/§1.6).
  CHECK(a->applied_stats().queries_sent == kAppliedMaxQueries);
  CHECK(b->applied_stats().queries_received == kAppliedMaxQueries);
  std::vector<std::uint64_t> nonces;
  for (const auto& frame : w.radio(1)->sent) {
    FrameSight sight{};
    if (!sight_frame(ByteView{frame.data(), frame.size()}, sight) ||
        sight.type != FrameType::AppResult || sight.to != 2) {
      continue;
    }
    wire::PlainFrame plain{};
    CHECK(crack_frame(w.scratch, frame, plain));
    if (plain.payload_size < 2 ||
        plain.payload[1] != static_cast<std::uint8_t>(ep::AppResultSubtype::Query)) {
      continue;
    }
    ep::AppResultQuery query{};
    CHECK_OK(ep::app_result_query_decode(
        ByteView{plain.payload.data(), plain.payload_size}, query));
    CHECK(query.head.original_origin == 1);
    CHECK(query.head.original_destination == 2);
    nonces.push_back(query.query_nonce);
  }
  CHECK(nonces.size() == kAppliedMaxQueries);
  CHECK(std::adjacent_find(nonces.begin(), nonces.end()) == nonces.end());
  AppliedResultView view{};
  CHECK(!a->applied_result(id, view));
  CHECK(w.obs(1)->applied.empty());
}

void test_late_result_after_timeout() {
  World w;
  MeshNode* a = w.add(1);
  MeshNode* b = w.add(2);
  w.start_all();
  w.link(1, 2);
  CountingSink* sink = w.install_sink(2);  // commits {Success, 7, dead}
  w.radio(2)->drop_sends = 1000000;

  const ExecutionLease lease = b->applied_lease();
  MessageId id{};
  CHECK_OK(a->send_applied(2, user_payload(), lease, applied_options(3000),
                           w.now, id));
  w.run(4000);
  CHECK(a->delivery(id).state == DeliveryState::Indeterminate);

  // A RESULT arriving after the deadline is validated, stored as late
  // evidence, ACKed and surfaced — the terminal state never flips (§1.3).
  const std::vector<std::uint8_t> body = request_body(lease, user_payload());
  ep::AppResultBody result{};
  result.head = result_head(id, 1, 2, ByteView{body.data(), body.size()}, 3000);
  result.head.outcome = static_cast<std::uint8_t>(ep::AppResultOutcome::Success);
  result.application_code = 7;
  result.data_size = 2;
  result.data[0] = 0xde;
  result.data[1] = 0xad;
  ep::EncodedServicePayload enc{};
  CHECK_OK(ep::app_result_encode(result, enc));
  const auto frame = craft_frame(
      w.scratch, app_result_carrier(2, 1, MessageId{0xA11E, 1}), enc.view());
  w.at(1)->on_radio_receive(2, frame.view(), RadioRxMetadata{-60}, w.now);
  w.run(50);

  const auto after = a->delivery(id);
  CHECK(after.state == DeliveryState::Indeterminate);
  CHECK(std::strcmp(after.reason, "APP_RESULT_LATE") == 0);
  AppliedResultView view{};
  CHECK(a->applied_result(id, view));
  CHECK(view.present && view.late);
  CHECK(view.outcome == ep::AppResultOutcome::Success && view.code == 7);
  CHECK(w.obs(1)->applied.size() == 1);
  CHECK(w.obs(1)->applied[0].second.late);
  CHECK(a->applied_stats().results_late == 1);
  // The late RESULT was answered with a RESULT_ACK the terminal accepts:
  // the stored record recomputes the same canonical body + digest.
  CHECK(w.run_until([&] { return b->applied_stats().result_acks == 1; }, 1000));
  CHECK(sink->calls == 1);
}

void test_app_rejected_verdict() {
  World w;
  MeshNode* a = w.add(1);
  MeshNode* b = w.add(2);
  w.start_all();
  w.link(1, 2);
  CountingSink* sink = w.install_sink(2);
  sink->outcome = ep::AppResultOutcome::Failure;
  sink->code = 0x1234;
  sink->data = {9, 9};

  const MessageId id = applied_exchange(w);
  w.run(500);
  const auto result = a->delivery(id);
  CHECK(result.state == DeliveryState::Failed);
  CHECK(std::strcmp(result.reason, "APP_REJECTED") == 0);
  AppliedResultView view{};
  CHECK(a->applied_result(id, view));
  CHECK(view.present && !view.late);
  CHECK(view.outcome == ep::AppResultOutcome::Failure);
  CHECK(view.code == 0x1234);
  CHECK(view.size == 2 && view.data[0] == 9);
  CHECK(w.obs(1)->applied.size() == 1);
  CHECK(b->applied_stats().result_acks == 1);
}

void test_no_sink_commits_no_endpoint() {
  World w;
  MeshNode* a = w.add(1);
  MeshNode* b = w.add(2);
  w.start_all();
  w.link(1, 2);
  // No applied sink installed at 2: explicit refusal, never a silent
  // timeout and never an on_message delivery (§1.4/§1.9).
  const MessageId id = applied_exchange(w);
  w.run(500);
  const auto result = a->delivery(id);
  CHECK(result.state == DeliveryState::Failed);
  CHECK(std::strcmp(result.reason, "APP_REJECTED") == 0);
  AppliedResultView view{};
  CHECK(a->applied_result(id, view));
  CHECK(view.present);
  CHECK(view.code ==
        static_cast<std::uint32_t>(ep::AppResultRefusal::NoEndpoint));
  CHECK(w.obs(2)->messages.empty());
  CHECK(b->applied_stats().refusals_no_endpoint == 1);
  CHECK(b->applied_stats().requests_dispatched == 0);
  CHECK(b->applied_stats().results_committed == 1);
  CHECK(w.obs(1)->applied.size() == 1);
}

void test_stale_lease_refusal_and_bootstrap() {
  World w;
  MeshNode* a = w.add(1);
  MeshNode* b = w.add(2);
  w.start_all();
  w.link(1, 2);
  CountingSink* sink = w.install_sink(2);

  // A stale lease refuses without running the endpoint; the committed
  // RESULT carries the CURRENT lease so the origin can retry (§1.2/§1.9).
  ExecutionLease wrong = b->applied_lease();
  wrong[15] ^= 0xFF;
  MessageId id1{};
  CHECK_OK(a->send_applied(2, user_payload(), wrong, applied_options(), w.now,
                           id1));
  w.run(500);
  auto result = a->delivery(id1);
  CHECK(result.state == DeliveryState::Failed);
  CHECK(std::strcmp(result.reason, "APP_REJECTED") == 0);
  AppliedResultView view{};
  CHECK(a->applied_result(id1, view));
  CHECK(view.code == static_cast<std::uint32_t>(ep::AppResultRefusal::StaleLease));
  CHECK(view.size == ep::kAppliedLeaseBytes);
  const ExecutionLease hinted = b->applied_lease();
  CHECK(std::equal(view.data.begin(), view.data.begin() + view.size,
                   hinted.begin()));
  CHECK(sink->calls == 0);
  CHECK(b->applied_stats().refusals_stale_lease == 1);

  // An all-zero "no assertion" lease refuses the same way.
  ExecutionLease zero{};
  MessageId id2{};
  CHECK_OK(a->send_applied(2, user_payload(), zero, applied_options(), w.now,
                           id2));
  w.run(500);
  CHECK(a->delivery(id2).state == DeliveryState::Failed);
  CHECK(b->applied_stats().refusals_stale_lease == 2);
  CHECK(sink->calls == 0);

  // Bootstrap: resend with the learned lease succeeds.
  const MessageId id3 = applied_exchange(w);
  w.run(500);
  CHECK(a->delivery(id3).state == DeliveryState::Delivered);
  CHECK(std::strcmp(a->delivery(id3).reason, "APP_APPLIED") == 0);
  CHECK(sink->calls == 1);
}

void test_malformed_body_refusal() {
  World w;
  MeshNode* a = w.add(1);
  MeshNode* b = w.add(2);
  w.start_all();
  w.link(1, 2);
  CountingSink* sink = w.install_sink(2);

  // Craft an APPLIED DATA whose body is shorter than the 16B lease:
  // committed Malformed refusal RESULT, endpoint never invoked (§1.2).
  wire::Header h{};
  h.type = FrameType::Data;
  h.flags = wire::kFlagEndProtected;
  h.delivery = DeliveryClass::Applied;
  h.delivery_round = 0;
  h.hop_remaining = 1;
  h.network = kNet;
  h.origin = 1;
  h.destination = 2;
  h.previous_hop = 1;
  h.next_hop = 2;
  h.message = MessageId{101, 4242};
  h.remaining_deadline_ms = 4000;
  h.original_lifetime_ms = 4000;
  h.link_epoch = 1;
  h.end_epoch = 1;
  const std::array<std::uint8_t, 5> short_body{{1, 2, 3, 4, 5}};
  const auto frame = craft_frame(w.scratch, h, ByteView{short_body.data(),
                                                      short_body.size()});
  b->on_radio_receive(1, frame.view(), RadioRxMetadata{-60}, w.now);
  w.run(200);
  CHECK(b->applied_stats().refusals_malformed == 1);
  CHECK(b->applied_stats().results_committed == 1);
  CHECK(sink->calls == 0);
  // The refusal RESULT travels back; the origin has no such delivery and
  // counts it as an orphan — malformed evidence, never a crash.
  w.run(300);
  CHECK(a->applied_stats().mismatched >= 1);
  CHECK(w.obs(1)->has_diag("APPLIED_RESULT_ORPHAN"));
}

void test_query_recovery_resends_result() {
  World w;
  MeshNode* a = w.add(1);
  MeshNode* b = w.add(2);
  w.start_all();
  w.link(1, 2);
  CountingSink* sink = w.install_sink(2);
  // Lose the FIRST RESULT emission entirely (both link attempts of its job).
  w.radio(2)->drop_sends = 2;

  const MessageId id = applied_exchange(w, 5000, 1);
  w.run(3000);
  const auto result = a->delivery(id);
  CHECK(result.state == DeliveryState::Delivered);
  CHECK(std::strcmp(result.reason, "APP_APPLIED") == 0);
  // The origin emitted bounded QUERYs after its app window lapsed; the
  // terminal saw them and re-emitted the stored RESULT within budget.
  CHECK(a->applied_stats().queries_sent >= 1);
  CHECK(a->applied_stats().queries_sent <= kAppliedMaxQueries);
  CHECK(b->applied_stats().queries_received >= 1);
  CHECK(b->applied_stats().results_emitted >= 2);
  CHECK(sink->calls == 1);
}

void test_query_triggers_stored_replay() {
  World w;
  MeshNode* a = w.add(1);
  MeshNode* b = w.add(2);
  w.start_all();
  w.link(1, 2);
  w.install_sink(2);
  w.radio(2)->drop_sends = 2;  // first RESULT emission lost

  const MessageId id = applied_exchange(w, 20000, 1);
  // Record when the first emit lands (≤5ms granularity is enough: the emit
  // spacing is 1200ms).
  CHECK(w.run_until([&] { return b->applied_stats().results_emitted == 1; },
                    2000));
  const MonotonicMs emit_t = w.now;
  // Approach but do not cross the next scheduled emit (~emit_t+1200).
  w.run(1100);
  CHECK(b->applied_stats().results_emitted == 1);
  // Jump past the emit spacing, then a QUERY for the held record must
  // synchronously replay the stored RESULT (§1.4 item 5).
  w.now = emit_t + 1250;
  const ExecutionLease lease = b->applied_lease();
  const std::vector<std::uint8_t> body = request_body(lease, user_payload());
  ep::AppResultQuery query{};
  query.head = result_head(id, 1, 2, ByteView{body.data(), body.size()}, 20000);
  query.head.subtype = ep::AppResultSubtype::Query;
  query.head.outcome = 0;
  query.query_nonce = 0x5157;
  ep::EncodedServicePayload enc{};
  CHECK_OK(ep::app_result_query_encode(query, enc));
  const auto frame = craft_frame(
      w.scratch, app_result_carrier(1, 2, MessageId{0x9E1, 1}), enc.view());
  b->on_radio_receive(1, frame.view(), RadioRxMetadata{-60}, w.now);
  CHECK(b->applied_stats().queries_received >= 1);
  CHECK(b->applied_stats().results_emitted == 2);  // QUERY-driven emit
  w.run(500);
  CHECK(a->delivery(id).state == DeliveryState::Delivered);
  CHECK(std::strcmp(a->delivery(id).reason, "APP_APPLIED") == 0);
}

void test_result_replay_dedup_and_conflict() {
  World w;
  MeshNode* a = w.add(1);
  MeshNode* b = w.add(2);
  w.start_all();
  w.link(1, 2);
  CountingSink* sink = w.install_sink(2);
  const MessageId id = applied_exchange(w);
  w.run(500);
  CHECK(a->delivery(id).state == DeliveryState::Delivered);
  CHECK(a->applied_stats().results_accepted == 1);
  CHECK(w.obs(1)->applied.size() == 1);

  // Locate the captured RESULT frame bytes the terminal sent.
  const std::vector<std::uint8_t>* captured = nullptr;
  for (const auto& frame : w.radio(2)->sent) {
    FrameSight sight{};
    if (sight_frame(ByteView{frame.data(), frame.size()}, sight) &&
        sight.type == FrameType::AppResult && sight.to == 1) {
      captured = &frame;
      break;
    }
  }
  CHECK(captured != nullptr);
  const std::size_t origin_acks_before = app_frames_to(*w.radio(1), 2);

  // Same-round replay: the routed dedup suppresses it before the handler —
  // no second verdict, no second ACK even after the job queue drains (§1.5).
  a->on_radio_receive(2, ByteView{captured->data(), captured->size()},
                      RadioRxMetadata{-60}, w.now);
  w.step();  // let any queued ACK dispatch
  CHECK(a->applied_stats().results_accepted == 1);
  CHECK(w.obs(1)->applied.size() == 1);
  CHECK(app_frames_to(*w.radio(1), 2) == origin_acks_before);

  // New-round replay of the SAME verdict: re-validated, idempotent — an ACK
  // is emitted but the stored outcome/observer count never move.
  const ExecutionLease lease = b->applied_lease();
  const std::vector<std::uint8_t> req_body =
      request_body(lease, user_payload());
  const auto emit_result = [&](std::uint8_t outcome, std::uint32_t code,
                               std::uint64_t wire_seq) {
    ep::AppResultBody res{};
    res.head = result_head(id, 1, 2, ByteView{req_body.data(), req_body.size()},
                           5000);
    res.head.outcome = outcome;
    res.application_code = code;
    res.data_size = 2;
    res.data[0] = 0xde;
    res.data[1] = 0xad;
    ep::EncodedServicePayload enc{};
    CHECK_OK(ep::app_result_encode(res, enc));
    const auto f = craft_frame(
        w.scratch,
        app_result_carrier(2, 1, MessageId{0xBEEF, wire_seq}), enc.view());
    a->on_radio_receive(2, f.view(), RadioRxMetadata{-60}, w.now);
  };
  emit_result(static_cast<std::uint8_t>(ep::AppResultOutcome::Success), 7, 1);
  // The terminal path queues HopAccept + RESULT_ACK and the serial driver
  // drains one job per poll — run briefly to let the ACK hit the wire.
  w.run(50);
  CHECK(a->applied_stats().results_accepted == 1);
  CHECK(w.obs(1)->applied.size() == 1);
  CHECK(app_frames_to(*w.radio(1), 2) == origin_acks_before + 1);
  CHECK(!w.obs(1)->has_diag("APPLIED_RESULT_CONFLICT"));

  // A DIFFERENT verdict under the same key/digest is a conflict: the first
  // committed outcome stands (§1.5).
  emit_result(static_cast<std::uint8_t>(ep::AppResultOutcome::Failure), 0x99, 2);
  CHECK(w.obs(1)->has_diag("APPLIED_RESULT_CONFLICT"));
  CHECK(a->applied_stats().mismatched >= 1);
  CHECK(a->delivery(id).state == DeliveryState::Delivered);
  AppliedResultView view{};
  CHECK(a->applied_result(id, view));
  CHECK(view.outcome == ep::AppResultOutcome::Success && view.code == 7);
  CHECK(w.obs(1)->applied.size() == 1);

  // Terminal-side replay: a NEW-round retransmission of the DATA replays the
  // stored RESULT — the endpoint is never invoked twice (§1.4/§1.5). Jump
  // past the emit spacing so the replay is not pacing-suppressed.
  w.now += 1300;
  wire::Header dup{};
  dup.type = FrameType::Data;
  dup.flags = wire::kFlagEndProtected;
  dup.delivery = DeliveryClass::Applied;
  dup.delivery_round = 1;
  dup.hop_remaining = 1;
  dup.network = kNet;
  dup.origin = 1;
  dup.destination = 2;
  dup.previous_hop = 1;
  dup.next_hop = 2;
  dup.message = id;
  dup.remaining_deadline_ms = 3000;
  dup.original_lifetime_ms = 5000;
  dup.link_epoch = 1;
  dup.end_epoch = 1;
  const auto dup_frame = craft_frame(
      w.scratch, dup, ByteView{req_body.data(), req_body.size()});
  const auto emits_before = b->applied_stats().results_emitted;
  b->on_radio_receive(1, dup_frame.view(), RadioRxMetadata{-60}, w.now);
  CHECK(sink->calls == 1);
  CHECK(b->applied_stats().results_emitted == emits_before + 1);
  w.run(300);
  CHECK(sink->calls == 1);
  CHECK(w.obs(1)->applied.size() == 1);
}

void test_result_binding_rejects() {
  World w;
  MeshNode* a = w.add(1);
  MeshNode* b = w.add(2);
  w.start_all();
  w.link(1, 2);
  w.install_sink(2);
  const ExecutionLease lease = b->applied_lease();
  const MessageId id = applied_exchange(w);
  w.run(500);
  CHECK(a->delivery(id).state == DeliveryState::Delivered);
  const std::vector<std::uint8_t> req_body =
      request_body(lease, user_payload());
  const std::uint32_t mismatched_before = a->applied_stats().mismatched;

  const auto inject_result = [&](ep::AppResultHead head, NodeId issuer,
                                 NodeId peer, std::uint64_t wire_seq) {
    ep::AppResultBody res{};
    res.head = head;
    res.head.subtype = ep::AppResultSubtype::Result;
    res.application_code = 7;
    ep::EncodedServicePayload enc{};
    CHECK_OK(ep::app_result_encode(res, enc));
    const auto f =
        craft_frame(w.scratch, app_result_carrier(issuer, head.original_origin,
                                                  MessageId{0xBAD, wire_seq}),
                    enc.view());
    a->on_radio_receive(peer, f.view(), RadioRxMetadata{-60}, w.now);
  };

  // (a) request_digest that does not match the stored request -> MISMATCH.
  {
    auto head = result_head(id, 1, 2, ByteView{req_body.data(), req_body.size()},
                            5000);
    head.request_digest[0] ^= 0xFF;
    inject_result(head, 2, 2, 1);
    CHECK(w.obs(1)->has_diag("APPLIED_RESULT_MISMATCH"));
  }
  // (b) digest computed over a DIFFERENT lease — the binding covers the
  // exact request bytes (§1.8).
  {
    ExecutionLease wrong = lease;
    wrong[15] ^= 0xFF;
    const std::vector<std::uint8_t> wrong_body =
        request_body(wrong, user_payload());
    auto head =
        result_head(id, 1, 2, ByteView{wrong_body.data(), wrong_body.size()},
                    5000);
    inject_result(head, 2, 2, 2);
  }
  // (c) head.original_destination disagrees with the frame issuer.
  {
    auto head = result_head(id, 1, 2, ByteView{req_body.data(), req_body.size()},
                            5000);
    head.original_destination = 9;  // claims issuer 9, frame origin is 2
    inject_result(head, 2, 2, 3);
  }
  // (d) a RESULT issued by a node that is not the bound destination —
  // digest/key are honest but delivery->destination != frame.origin.
  {
    auto head = result_head(id, 1, 5, ByteView{req_body.data(), req_body.size()},
                            5000);
    head.original_destination = 5;
    inject_result(head, 5, 5, 4);
    CHECK(w.obs(1)->has_diag("APPLIED_RESULT_ORPHAN"));
  }
  // (e) RESULT for an unknown MessageId -> orphan, never acted on.
  {
    MessageId other{101, 7777};
    auto head =
        result_head(other, 1, 2, ByteView{req_body.data(), req_body.size()},
                    5000);
    inject_result(head, 2, 2, 5);
    CHECK(w.obs(1)->diag_count("APPLIED_RESULT_ORPHAN") >= 2);
  }

  CHECK(a->applied_stats().mismatched > mismatched_before);
  CHECK(a->applied_stats().results_accepted == 1);
  CHECK(a->delivery(id).state == DeliveryState::Delivered);
  CHECK(std::strcmp(a->delivery(id).reason, "APP_APPLIED") == 0);
  CHECK(w.obs(1)->applied.size() == 1);
}

void test_status_answers_and_ack_validation() {
  World w;
  MeshNode* a = w.add(1);
  MeshNode* b = w.add(2);
  w.start_all();
  w.link(1, 2);
  w.install_sink(2);
  const MessageId id = applied_exchange(w);
  w.run(500);
  CHECK(a->delivery(id).state == DeliveryState::Delivered);
  CHECK(b->applied_stats().result_acks == 1);

  const ExecutionLease lease = b->applied_lease();
  const std::vector<std::uint8_t> req_body =
      request_body(lease, user_payload());
  const auto craft_query = [&](const MessageId& req_id, std::uint64_t nonce,
                               std::uint64_t wire_seq) {
    ep::AppResultQuery query{};
    query.head =
        result_head(req_id, 1, 2, ByteView{req_body.data(), req_body.size()},
                    5000);
    query.head.subtype = ep::AppResultSubtype::Query;
    query.head.outcome = 0;
    query.query_nonce = nonce;
    ep::EncodedServicePayload enc{};
    CHECK_OK(ep::app_result_query_encode(query, enc));
    return craft_frame(w.scratch,
                       app_result_carrier(1, 2, MessageId{0xE11, wire_seq}),
                       enc.view());
  };

  // QUERY for an unknown key -> STATUS NotRetained (§1.4 item 5); the
  // negative answer is rate-gated per peer (200ms).
  const MessageId unknown{101, 9090};
  const auto q1 = craft_query(unknown, 0x51, 1);
  b->on_radio_receive(1, q1.view(), RadioRxMetadata{-60}, w.now);
  CHECK(b->applied_stats().status_sent == 1);
  const auto q2 = craft_query(MessageId{101, 9091}, 0x52, 2);
  b->on_radio_receive(1, q2.view(), RadioRxMetadata{-60}, w.now);
  CHECK(b->applied_stats().status_sent == 1);  // gated
  w.now += kAppliedAnswerMinIntervalMs;
  const auto q3 = craft_query(MessageId{101, 9092}, 0x53, 3);
  b->on_radio_receive(1, q3.view(), RadioRxMetadata{-60}, w.now);
  CHECK(b->applied_stats().status_sent == 2);

  // The STATUSes reach the origin; they name no live delivery -> orphan.
  w.run(500);
  CHECK(a->applied_stats().statuses_received >= 1);
  CHECK(w.obs(1)->has_diag("APPLIED_STATUS_ORPHAN"));

  // RESULT_ACK with a wrong result_digest -> dropped + diagnosed.
  ep::AppResultAck ack{};
  ack.head = result_head(id, 1, 2, ByteView{req_body.data(), req_body.size()},
                         5000);
  ack.head.subtype = ep::AppResultSubtype::ResultAck;
  ack.head.outcome = 0;
  ack.result_digest.fill(0x5A);
  ep::EncodedServicePayload ack_enc{};
  CHECK_OK(ep::app_result_ack_encode(ack, ack_enc));
  auto ack_frame = craft_frame(
      w.scratch, app_result_carrier(1, 2, MessageId{0xACC, 1}), ack_enc.view());
  b->on_radio_receive(1, ack_frame.view(), RadioRxMetadata{-60}, w.now);
  CHECK(w.obs(2)->has_diag("APPLIED_ACK_MISMATCH"));

  // RESULT_ACK with the digest of the canonical RESULT body -> accepted.
  ep::AppResultBody stored{};
  stored.head = result_head(id, 1, 2, ByteView{req_body.data(), req_body.size()},
                            5000);
  stored.application_code = 7;
  stored.data_size = 2;
  stored.data[0] = 0xde;
  stored.data[1] = 0xad;
  ep::EncodedServicePayload canonical{};
  CHECK_OK(ep::app_result_encode(stored, canonical));
  ep::applied_result_digest(canonical.view(), ack.result_digest);
  const auto acks_before = b->applied_stats().result_acks;
  CHECK_OK(ep::app_result_ack_encode(ack, ack_enc));
  ack_frame = craft_frame(w.scratch,
                          app_result_carrier(1, 2, MessageId{0xACC, 2}),
                          ack_enc.view());
  b->on_radio_receive(1, ack_frame.view(), RadioRxMetadata{-60}, w.now);
  CHECK(b->applied_stats().result_acks == acks_before + 1);
}

void test_status_nonce_matching() {
  World w;
  MeshNode* a = w.add(1);
  MeshNode* b = w.add(2);
  w.start_all();
  w.link(1, 2);
  w.install_sink(2);
  w.radio(2)->drop_sends = 1000000;  // RESULTs/STATUSes from 2 never arrive

  const ExecutionLease lease = b->applied_lease();
  MessageId id{};
  CHECK_OK(a->send_applied(2, user_payload(), lease, applied_options(6000),
                           w.now, id));
  // Both QUERYs fire (bounded); the LATEST nonce is the only one matched.
  CHECK(w.run_until(
      [&] { return a->applied_stats().queries_sent == kAppliedMaxQueries; },
      4000));
  // Sniff the QUERY bodies to learn the current nonce.
  std::uint64_t nonce = 0;
  for (const auto& frame : w.radio(1)->sent) {
    FrameSight sight{};
    if (!sight_frame(ByteView{frame.data(), frame.size()}, sight) ||
        sight.type != FrameType::AppResult || sight.to != 2) {
      continue;
    }
    wire::PlainFrame plain{};
    CHECK(crack_frame(w.scratch, frame, plain));
    if (plain.payload_size >= 2 &&
        plain.payload[1] ==
            static_cast<std::uint8_t>(ep::AppResultSubtype::Query)) {
      ep::AppResultQuery q{};
      CHECK_OK(ep::app_result_query_decode(
          ByteView{plain.payload.data(), plain.payload_size}, q));
      nonce = q.query_nonce;
    }
  }
  CHECK(nonce != 0);
  const std::vector<std::uint8_t> req_body =
      request_body(lease, user_payload());
  const auto inject_status = [&](std::uint64_t echo, std::uint8_t outcome,
                                 std::uint64_t wire_seq) {
    ep::AppResultStatus st{};
    st.head = result_head(id, 1, 2, ByteView{req_body.data(), req_body.size()},
                          6000);
    st.head.subtype = ep::AppResultSubtype::Status;
    st.head.outcome = outcome;
    st.query_nonce = echo;
    ep::EncodedServicePayload enc{};
    CHECK_OK(ep::app_result_status_encode(st, enc));
    const auto f = craft_frame(
        w.scratch, app_result_carrier(2, 1, MessageId{0x57A, wire_seq}),
        enc.view());
    a->on_radio_receive(2, f.view(), RadioRxMetadata{-60}, w.now);
  };

  // Unmatched nonce -> diagnostic, delivery keeps waiting.
  inject_status(nonce + 7,
                static_cast<std::uint8_t>(ep::AppResultStatusCode::Expired), 1);
  CHECK(w.obs(1)->has_diag("APPLIED_STATUS_UNMATCHED"));
  CHECK(a->delivery(id).state == DeliveryState::WaitingForEndReceipt);
  // Nonce-matched Pending: extends nothing, keeps waiting (§1.9 matrix).
  inject_status(nonce,
                static_cast<std::uint8_t>(ep::AppResultStatusCode::Pending), 2);
  CHECK(a->delivery(id).state == DeliveryState::WaitingForEndReceipt);
  // Nonce-matched terminal status resolves the wait honestly.
  inject_status(nonce,
                static_cast<std::uint8_t>(ep::AppResultStatusCode::Expired), 3);
  const auto result = a->delivery(id);
  CHECK(result.state == DeliveryState::Indeterminate);
  CHECK(std::strcmp(result.reason, "APP_RESULT_EXPIRED") == 0);
  CHECK(a->applied_stats().statuses_received >= 3);
}

void test_sdk_band_code_clamped() {
  World w;
  MeshNode* a = w.add(1);
  w.add(2);
  w.start_all();
  w.link(1, 2);
  CountingSink* sink = w.install_sink(2);
  // An endpoint reply inside the reserved 0xFFFF0000 band is rewritten to
  // InternalError so app bytes never impersonate an SDK refusal (§1.2).
  sink->code = 0xFFFF0001u;  // tries to forge StaleLease
  const MessageId id = applied_exchange(w);
  w.run(500);
  const auto result = a->delivery(id);
  CHECK(result.state == DeliveryState::Failed);
  CHECK(std::strcmp(result.reason, "APP_REJECTED") == 0);
  AppliedResultView view{};
  CHECK(a->applied_result(id, view));
  CHECK(view.code ==
        static_cast<std::uint32_t>(ep::AppResultRefusal::InternalError));
  CHECK(view.outcome == ep::AppResultOutcome::Failure);
}

void test_capacity_refusal() {
  World w;
  MeshNode* a = w.add(1);
  MeshNode* b = w.add(2);
  w.start_all();
  w.link(1, 2);
  // No sink + all RESULTs lost: every accepted request commits an unacked
  // NoEndpoint record that fills the bounded terminal pool (8, §1.6).
  w.radio(2)->drop_sends = 1000000;
  const ExecutionLease lease = b->applied_lease();
  std::vector<MessageId> ids;
  for (int i = 0; i < 8; ++i) {
    MessageId id{};
    CHECK_OK(a->send_applied(2, user_payload(), lease, applied_options(1500),
                             w.now, id));
    ids.push_back(id);
    w.run(150);  // let the DATA land + commit before the next send
  }
  CHECK(w.run_until(
      [&] { return b->applied_stats().results_committed == kAppliedResultCapacity; },
      2000));
  // Let the eight deliveries time out honestly (RESULTs are all lost).
  CHECK(w.run_until(
      [&] {
        for (const auto& id : ids) {
          if (a->delivery(id).state != DeliveryState::Indeterminate) return false;
        }
        return true;
      },
      4000));

  // Ninth request: the full pool of unacked in-window records refuses
  // admission pre-acceptance with BUSY + diagnostic (§1.4 item 2, §1.6).
  MessageId id9{};
  CHECK_OK(a->send_applied(2, user_payload(), lease, applied_options(4000),
                           w.now, id9));
  CHECK(w.run_until([&] { return b->applied_stats().refusals_capacity >= 1; },
                    8000));
  CHECK(w.obs(2)->has_diag("APPLIED_NO_RESULT_SLOT"));
  CHECK(b->applied_stats().refusals_no_endpoint == 8);
  // The refused send is never silently delivered: retries expire into an
  // honest non-Delivered terminal state.
  CHECK(w.run_until(
      [&] {
        const auto s = a->delivery(id9).state;
        return s == DeliveryState::Indeterminate || s == DeliveryState::Failed;
      },
      15000));
  CHECK(a->delivery(id9).state != DeliveryState::Delivered);
}

void test_multihop_applied() {
  World w;
  MeshNode* a = w.add(1);
  w.add(2);
  MeshNode* c = w.add(3);
  w.start_all();
  w.link(1, 2);
  w.link(2, 3);
  CountingSink* sink = w.install_sink(3);
  w.run(4000);  // route advertisements propagate over both hops
  CHECK(a->routes().best(3).valid);
  CHECK(c->routes().best(1).valid);

  const ExecutionLease lease = c->applied_lease();
  MessageId id{};
  CHECK_OK(a->send_applied(3, user_payload(), lease,
                           applied_options(30000, kDefaultHopLimit), w.now, id));
  w.run(4000);
  const auto result = a->delivery(id);
  CHECK(result.state == DeliveryState::Delivered);
  CHECK(std::strcmp(result.reason, "APP_APPLIED") == 0);
  CHECK(sink->calls == 1);
  AppliedResultView view{};
  CHECK(a->applied_result(id, view));
  CHECK(view.present && view.code == 7);

  // The RESULT traversed both hops 3->2->1 on the routed lane; hop counters
  // decrement along the chain (§1.2: routed end-protected transit).
  bool saw_first = false;
  bool saw_second = false;
  std::uint8_t first_hop_remaining = 0;
  for (const auto& s : w.net.sights) {
    if (s.type == FrameType::AppResult && s.origin == 3) {
      if (s.from == 3 && s.to == 2) {
        saw_first = true;
        first_hop_remaining = s.hop_remaining;
      }
      if (s.from == 2 && s.to == 1) {
        saw_second = true;
        CHECK(s.hop_remaining + 1 == first_hop_remaining);
      }
    }
  }
  CHECK(saw_first && saw_second);
  // RESULT_ACK made the return trip too.
  bool ack_hop1 = false;
  bool ack_hop2 = false;
  for (const auto& s : w.net.sights) {
    if (s.type == FrameType::AppResult && s.origin == 1) {
      if (s.from == 1 && s.to == 2) ack_hop1 = true;
      if (s.from == 2 && s.to == 3) ack_hop2 = true;
    }
  }
  CHECK(ack_hop1 && ack_hop2);
  CHECK(c->applied_stats().result_acks == 1);
  // DATA and END_RECEIPT also traversed the two hops.
  bool data_relayed = false;
  bool receipt_relayed = false;
  for (const auto& s : w.net.sights) {
    if (s.type == FrameType::Data && s.from == 2 && s.to == 3) data_relayed = true;
    if (s.type == FrameType::EndReceipt && s.from == 2 && s.to == 1) {
      receipt_relayed = true;
    }
  }
  CHECK(data_relayed && receipt_relayed);
}

}  // namespace

int main() {
  test_result_codec();
  test_query_status_ack_codecs();
  test_digests();
  test_lease_layout();
  test_send_applied_validation();
  test_happy_path();
  test_end_receipt_alone_never_promotes();
  test_result_timeout_indeterminate();
  test_late_result_after_timeout();
  test_app_rejected_verdict();
  test_no_sink_commits_no_endpoint();
  test_stale_lease_refusal_and_bootstrap();
  test_malformed_body_refusal();
  test_query_recovery_resends_result();
  test_query_triggers_stored_replay();
  test_result_replay_dedup_and_conflict();
  test_result_binding_rejects();
  test_status_answers_and_ack_validation();
  test_status_nonce_matching();
  test_sdk_band_code_clamped();
  test_capacity_refusal();
  test_multihop_applied();
  if (failures != 0) {
    std::fprintf(stderr, "%d applied-delivery checks failed\n", failures);
    return 1;
  }
  std::puts("RouteLoom applied-delivery tests passed");
  return 0;
}
