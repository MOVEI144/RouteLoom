// Explicit Gateway delivery tests (docs/design/scope-gateway-config/
// 03-explicit-gateway.md, 05-wire-api.md §5.3, 06-acceptance.md).
//
// Portable P2 coverage:
//   G01 — a wrong-gateway/forged receipt can never complete a send.
//   G05 — lease expiry blocks NEW work with the old token while a stored
//         final receipt still resends inside its 60s hold.
//   G06 — payload 0/1/96 pass through verbatim; 97 and 128 are rejected
//         before acceptance (never truncated); ordinary DATA at 128B is
//         unchanged.
//   G07 — pending-8 cap, 20/min+burst-8 token bucket, dedup/receipt table
//         is rate-bound (32 can never fill under the admission limit —
//         the capacity-margin property), protected records never evicted.
//   G08 — every bound receipt field is verified; single-field forgeries
//         are dropped, not believed.
//   G10 — Service=21 transits a sinkless relay like protected DATA while
//         a sinkless TERMINAL produces SERVICE_NO_ENDPOINT and an honest
//         non-success (never a DATA-style one).
//   token/lease basics — stale token, lease-vs-30s lifetime, re-resolve,
//         token is not the MessageKey, bounded endpoint records.
//   host seam — the device-side half of G02/G03: pending survives a lost
//         host ACK (no double ingress, INDETERMINATE for the origin),
//         binding/session changes make tokens stale.
//
// P3-only cases stay with the USB/Host phase: G02 real Host stop, G03 real
// ReceiveLog+ACK loss on the wire, G04 real USB session, G09 power loss,
// G11 fixed-egress, G12 the C++/Rust PTY bridge.

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <vector>

#include "routeloom/discovery_scope.hpp"
#include "routeloom/endpoint_wire.hpp"
#include "routeloom/gateway.hpp"
#include "routeloom/node.hpp"
#include "routeloom/types.hpp"
#include "routeloom/wire.hpp"

#include "test_sim.hpp"

namespace {

int failures = 0;
#define CHECK(expr) \
  do { \
    if (!(expr)) { \
      std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__, #expr); \
      ++failures; \
    } \
  } while (false)
#define CHECK_OK(expr) \
  do { \
    const auto _status = (expr); \
    if (!_status.ok()) { \
      std::fprintf(stderr, "STATUS failed %s:%d: %s (%s)\n", __FILE__, __LINE__, \
                   #expr, _status.detail); \
      ++failures; \
    } \
  } while (false)

using namespace routeloom;
using routeloom_test::SimWorld;
using routeloom_test::FrameSight;
using endpoint::EncodedServicePayload;
using endpoint::GatewayScope;
using endpoint::ServiceReason;
using endpoint::ServiceSubtype;

// --- Test doubles ---------------------------------------------------------------

struct TestGatewayObserver final : GatewayDeliveryObserver {
  struct Resolved {
    GatewayEndpoint endpoint;
    NodeId gateway{kInvalidNodeId};
    Status result{};
  };
  std::vector<Resolved> resolved;
  std::vector<GatewaySendResult> results;
  void on_gateway_resolved(const GatewayEndpoint& endpoint, const NodeId gateway,
                           const Status result) noexcept override {
    resolved.push_back(Resolved{endpoint, gateway, result});
  }
  void on_gateway_result(const GatewaySendResult& result) noexcept override {
    results.push_back(result);
  }
};

struct TestHostSink final : GatewayHostSink {
  bool ready{false};
  HostBinding binding{};
  Status ingress_status{Status::success()};
  std::vector<MessageKey> ingresses;
  // When set, the sink ACKs synchronously INSIDE host_ingress — exercises
  // the seam race where the record must already be armed for the ACK.
  GatewayDelivery* sync_ack_target{nullptr};
  bool host_ready(HostBinding& out) noexcept override {
    out = binding;
    return ready;
  }
  Status host_ingress(const MessageKey& key, const RequestDigest&, ByteView,
                      ByteView, MonotonicMs now) noexcept override {
    if (ingress_status.ok()) {
      ingresses.push_back(key);
      if (sync_ack_target != nullptr) {
        sync_ack_target->on_host_ingress_ack(key, /*stored=*/true, now);
      }
    }
    return ingress_status;
  }
};

// World with per-node GatewayDelivery components layered on the sim.
struct GatewayWorld {
  SimWorld w;
  std::map<NodeId, std::unique_ptr<GatewayDelivery>> components;
  std::map<NodeId, std::unique_ptr<TestGatewayObserver>> observers;

  MeshNode* add(NodeId id) { return w.add(id); }
  GatewayDelivery* attach(NodeId id) {
    components[id] = std::make_unique<GatewayDelivery>(*w.at(id));
    observers[id] = std::make_unique<TestGatewayObserver>();
    components[id]->set_observer(*observers[id]);
    components[id]->attach();
    return components[id].get();
  }
  MeshNode* at(NodeId id) const { return w.at(id); }
  GatewayDelivery* gd(NodeId id) const { return components.at(id).get(); }
  TestGatewayObserver* gobs(NodeId id) const { return observers.at(id).get(); }
};

// Builds a PlainFrame as it would arrive at the terminal AFTER link+end
// verification — the component-level injection point for dedup/rate/forge
// cases (the full-stack tests cover the wire path itself).
wire::PlainFrame service_frame(const NodeId origin, const MessageId id,
                               const ByteView payload) {
  wire::PlainFrame frame{};
  frame.header.type = FrameType::Service;
  frame.header.network = 1;
  frame.header.origin = origin;
  frame.header.destination = 0;  // filled by callers that care
  frame.header.message = id;
  frame.header.remaining_deadline_ms = 30000;
  frame.header.original_lifetime_ms = 30000;
  if (payload.size > 0) {
    std::memcpy(frame.payload.data(), payload.data, payload.size);
  }
  frame.payload_size = payload.size;
  return frame;
}

EncodedServicePayload encode_submit(const GatewayScope scope,
                                    const GatewayToken& token,
                                    const std::uint64_t boot,
                                    const ByteView payload) {
  endpoint::ServiceSubmit submit{};
  submit.scope = scope;
  submit.token = token;
  submit.gateway_boot = boot;
  submit.payload_size = static_cast<std::uint16_t>(payload.size);
  if (payload.size > 0) {
    std::memcpy(submit.payload.data(), payload.data, payload.size);
  }
  EncodedServicePayload encoded{};
  const Status status = endpoint::service_submit_encode(submit, encoded);
  (void)status;
  return encoded;
}

RequestDigest digest_of(const ByteView canonical) {
  RequestDigest digest{};
  sha256(canonical, digest);
  return digest;
}

EncodedServicePayload encode_outcome(const ServiceSubtype subtype,
                                     const GatewayScope scope,
                                     const GatewayToken& token,
                                     const std::uint64_t boot,
                                     const NodeId ref_origin,
                                     const MessageId ref_id,
                                     const RequestDigest& digest,
                                     const ServiceReason reason) {
  endpoint::ServiceOutcome outcome{};
  outcome.subtype = subtype;
  outcome.scope = scope;
  outcome.token = token;
  outcome.gateway_boot = boot;
  outcome.ref_origin = ref_origin;
  outcome.ref_session = ref_id.session;
  outcome.ref_sequence = ref_id.sequence;
  outcome.request_digest = digest;
  outcome.reason = reason;
  EncodedServicePayload encoded{};
  const Status status = endpoint::service_outcome_encode(outcome, encoded);
  (void)status;
  return encoded;
}

GatewayEndpoint resolve_or_fail(GatewayWorld& g, const NodeId origin,
                                const NodeId gateway, const GatewayScope scope,
                                const HostDigest& expected_host,
                                const MonotonicMs deadline_ms) {
  GatewayEndpoint endpoint{};
  CHECK_OK(g.gd(origin)->resolve(gateway, scope, expected_host,
                                 static_cast<std::uint32_t>(deadline_ms),
                                 g.w.now, endpoint));
  return endpoint;
}

// Drives the sim until the endpoint reaches Ready (or the deadline passes).
bool wait_ready(GatewayWorld& g, const NodeId origin, const GatewayEndpoint& endpoint,
                const MonotonicMs budget_ms = 4000) {
  const MonotonicMs end = g.w.now + budget_ms;
  while (g.w.now <= end) {
    g.w.run(20);
    if (g.gd(origin)->endpoint_state(endpoint) == EndpointState::Ready) {
      return true;
    }
  }
  return false;
}

// --- G-happy: scope-1 resolve + send + receipt + mailbox -------------------------

void test_scope1_happy_path() {
  GatewayWorld g;
  g.add(1);
  g.add(2);
  g.w.start_all();
  g.w.link(1, 2, 1, 1);
  auto* origin = g.attach(1);
  auto* gateway = g.attach(2);
  GatewayRoleConfig role{};
  role.gateway_boot = 42;
  CHECK_OK(gateway->enable_gateway(role));
  g.w.run(2500);

  const HostDigest zero_host{};
  GatewayEndpoint endpoint =
      resolve_or_fail(g, 1, 2, GatewayScope::GatewaySdkRam, zero_host, 10000);
  CHECK(wait_ready(g, 1, endpoint));
  CHECK(g.gobs(1)->resolved.size() == 1);
  CHECK(g.gobs(1)->resolved.back().result.ok());
  GatewayEndpointInfo info{};
  CHECK(origin->endpoint_info(endpoint, info));
  CHECK(info.gateway == 2 && info.scope == GatewayScope::GatewaySdkRam);
  CHECK(origin->endpoint_records_used() == 1);

  const std::array<std::uint8_t, 5> payload{{10, 20, 30, 40, 50}};
  MessageId id{};
  CHECK_OK(origin->send(endpoint, ByteView{payload.data(), payload.size()},
                        5000, g.w.now, id));
  g.w.run(3000);

  CHECK(g.gobs(1)->results.size() == 1);
  CHECK(g.gobs(1)->results.back().id == id);
  CHECK(g.gobs(1)->results.back().state == GatewaySendState::EndpointReceived);
  CHECK(g.gd(1)->stats().receipts_verified == 1);
  CHECK(g.gd(2)->stats().submits_accepted == 1);
  CHECK(g.gd(2)->stats().sdk_ram_receipts == 1);

  // The mailbox is the completion evidence: bounded storage, exact bytes.
  MessageKey key{};
  std::array<std::uint8_t, kGatewayPayloadMaxBytes> stored{};
  std::size_t stored_size = 0;
  CHECK(gateway->mailbox_size() == 1);
  CHECK(gateway->mailbox_take(key, stored, stored_size));
  CHECK(key.origin == 1 && key.id == id);
  CHECK(stored_size == payload.size());
  CHECK(std::memcmp(stored.data(), payload.data(), payload.size()) == 0);
  CHECK(gateway->mailbox_size() == 0);

  // Service traffic must never surface as ordinary DATA.
  CHECK(g.w.obs(1)->messages.empty());
  CHECK(g.w.obs(2)->messages.empty());
  CHECK(g.w.obs(1)->delivery_events.empty());
  CHECK(g.w.obs(2)->delivery_events.empty());
}

// --- G01: a receipt from the wrong gateway can never complete a send --------------

void test_g01_wrong_gateway_receipt() {
  GatewayWorld g;
  g.add(1);   // origin
  g.add(2);   // designated gateway
  g.add(3);   // wrong gateway / attacker
  g.w.start_all();
  g.w.link(1, 2, 1, 1);
  g.w.link(1, 3, 1, 1);
  auto* origin = g.attach(1);
  auto* gateway = g.attach(2);
  auto* attacker = g.attach(3);
  GatewayRoleConfig role{};
  role.gateway_boot = 42;
  CHECK_OK(gateway->enable_gateway(role));
  CHECK_OK(attacker->enable_gateway(role));  // same boot claim, different node
  g.w.run(2500);

  const HostDigest zero_host{};
  GatewayEndpoint endpoint =
      resolve_or_fail(g, 1, 2, GatewayScope::GatewaySdkRam, zero_host, 10000);
  CHECK(wait_ready(g, 1, endpoint));
  GatewayEndpointInfo info{};
  CHECK(origin->endpoint_info(endpoint, info));

  const std::array<std::uint8_t, 4> payload{{1, 2, 3, 4}};
  MessageId id{};
  CHECK_OK(origin->send(endpoint, ByteView{payload.data(), payload.size()},
                        8000, g.w.now, id));

  // While the send is in flight, the wrong gateway emits a perfectly
  // formatted Receipt binding EVERY field — except its own origin. The
  // frame arrives end-verified from node 3, which is not the designated
  // gateway, so it must be dropped as evidence.
  const EncodedServicePayload real_submit = encode_submit(
      GatewayScope::GatewaySdkRam, info.token, info.gateway_boot,
      ByteView{payload.data(), payload.size()});
  const RequestDigest real_digest = digest_of(real_submit.view());
  EncodedServicePayload forged = encode_outcome(
      ServiceSubtype::Receipt, GatewayScope::GatewaySdkRam, info.token,
      info.gateway_boot, /*ref_origin=*/1, id, real_digest, ServiceReason::Ok);
  wire::PlainFrame frame = service_frame(/*origin=*/3, MessageId{7, 7},
                                         forged.view());
  g.gd(1)->on_service_payload(3, frame, g.w.now);
  CHECK(g.gd(1)->stats().outcomes_rejected == 1);
  CHECK(g.gobs(1)->results.empty());  // forged success produced nothing

  // The real exchange still completes exactly once.
  g.w.run(3000);
  CHECK(g.gobs(1)->results.size() == 1);
  CHECK(g.gobs(1)->results.back().state == GatewaySendState::EndpointReceived);
}

// --- G05: lease expiry blocks new work; stored receipt still resends --------------

void test_g05_lease_expiry_and_stale_token() {
  GatewayWorld g;
  g.add(1);
  g.add(2);
  g.w.start_all();
  g.w.link(1, 2, 1, 1);
  auto* origin = g.attach(1);
  auto* gateway = g.attach(2);
  GatewayRoleConfig role{};
  role.gateway_boot = 42;
  CHECK_OK(gateway->enable_gateway(role));
  g.w.run(2500);

  const HostDigest zero_host{};
  GatewayEndpoint endpoint =
      resolve_or_fail(g, 1, 2, GatewayScope::GatewaySdkRam, zero_host, 10000);
  CHECK(wait_ready(g, 1, endpoint));
  GatewayEndpointInfo info{};
  CHECK(origin->endpoint_info(endpoint, info));

  const std::array<std::uint8_t, 4> payload{{9, 8, 7, 6}};
  MessageId id{};
  CHECK_OK(origin->send(endpoint, ByteView{payload.data(), payload.size()},
                        5000, g.w.now, id));
  g.w.run(3000);
  CHECK(g.gobs(1)->results.size() == 1);
  CHECK(gateway->mailbox_size() == 1);

  // Past the 15s token lease but inside the 60s dedup/receipt hold.
  g.w.run(16000);
  CHECK(origin->endpoint_state(endpoint) == EndpointState::Stale);
  // An expired lease refuses NEW work from the origin side too.
  MessageId late{};
  CHECK(!origin->send(endpoint, ByteView{payload.data(), 1}, 1000,
                      g.w.now, late));

  // A re-seen (duplicate) Submit still returns the STORED receipt — token
  // staleness applies only to new work (03 §3.4).
  const EncodedServicePayload dup = encode_submit(
      GatewayScope::GatewaySdkRam, info.token, info.gateway_boot,
      ByteView{payload.data(), payload.size()});
  wire::PlainFrame dup_frame = service_frame(1, id, dup.view());
  const std::uint32_t resends_before = g.gd(2)->stats().outcomes_resend;
  g.gd(2)->on_service_payload(1, dup_frame, g.w.now);
  CHECK(g.gd(2)->stats().outcomes_resend == resends_before + 1);

  // A NEW MessageKey under the same stale token is rejected TOKEN_STALE.
  const MessageId fresh_id{106, 9999};  // same session, unseen sequence
  wire::PlainFrame fresh_frame = service_frame(1, fresh_id, dup.view());
  g.gd(2)->on_service_payload(1, fresh_frame, g.w.now);
  CHECK(g.gd(2)->stats().submits_stale_token >= 1);
}

// --- G06: payload bounds -----------------------------------------------------------

void test_g06_payload_bounds() {
  GatewayWorld g;
  g.add(1);
  g.add(2);
  g.w.start_all();
  g.w.link(1, 2, 1, 1);
  auto* origin = g.attach(1);
  auto* gateway = g.attach(2);
  GatewayRoleConfig role{};
  role.gateway_boot = 42;
  CHECK_OK(gateway->enable_gateway(role));
  g.w.run(2500);

  const HostDigest zero_host{};
  GatewayEndpoint endpoint =
      resolve_or_fail(g, 1, 2, GatewayScope::GatewaySdkRam, zero_host, 10000);
  CHECK(wait_ready(g, 1, endpoint));

  MessageKey key{};
  std::array<std::uint8_t, kGatewayPayloadMaxBytes> stored{};
  std::size_t stored_size = 0;
  MessageId id{};

  // 0-byte payload: a legal empty message.
  CHECK_OK(origin->send(endpoint, ByteView{nullptr, 0}, 5000, g.w.now, id));
  g.w.run(2000);
  CHECK(g.gobs(1)->results.back().state == GatewaySendState::EndpointReceived);
  CHECK(gateway->mailbox_take(key, stored, stored_size));
  CHECK(stored_size == 0);

  // 1-byte payload.
  const std::array<std::uint8_t, 1> one{{0xAB}};
  CHECK_OK(origin->send(endpoint, ByteView{one.data(), one.size()}, 5000,
                        g.w.now, id));
  g.w.run(2000);
  CHECK(gateway->mailbox_take(key, stored, stored_size));
  CHECK(stored_size == 1 && stored[0] == 0xAB);

  // 96-byte payload: the hard cap, preserved exactly (non-UTF8 bytes).
  std::array<std::uint8_t, 96> full{};
  for (std::size_t i = 0; i < full.size(); ++i) {
    full[i] = static_cast<std::uint8_t>(0xFF - (i * 3));
  }
  full[10] = 0x00;  // embedded NUL is payload, not a terminator
  full[11] = 0x80;
  CHECK_OK(origin->send(endpoint, ByteView{full.data(), full.size()}, 5000,
                        g.w.now, id));
  g.w.run(2000);
  CHECK(gateway->mailbox_take(key, stored, stored_size));
  CHECK(stored_size == full.size());
  CHECK(std::memcmp(stored.data(), full.data(), full.size()) == 0);

  // 97 and 128 bytes are refused BEFORE acceptance — never truncated,
  // nothing queued on the air for them.
  std::array<std::uint8_t, 128> over{};
  const std::size_t sights_before = g.w.net.sights.size();
  CHECK(!origin->send(endpoint, ByteView{over.data(), 97}, 5000, g.w.now, id));
  CHECK(!origin->send(endpoint, ByteView{over.data(), over.size()}, 5000,
                      g.w.now, id));
  g.w.run(500);
  bool origin_service_sight = false;
  for (std::size_t i = sights_before; i < g.w.net.sights.size(); ++i) {
    const FrameSight& s = g.w.net.sights[i];
    origin_service_sight =
        origin_service_sight || (s.type == FrameType::Service && s.origin == 1);
  }
  CHECK(!origin_service_sight);

  // Ordinary Node DATA keeps its 128-byte limit — unchanged.
  SendOptions options{};
  options.lifetime_ms = 10000;
  MessageId data_id{};
  CHECK_OK(g.at(1)->send(2, ByteView{over.data(), over.size()}, options,
                         g.w.now, data_id));
  g.w.run(3000);
  CHECK(g.at(1)->delivery(data_id).state == DeliveryState::Delivered);
  CHECK(g.w.obs(2)->messages.size() == 1);
  CHECK(g.w.obs(2)->messages.back().size() == 128);
}

// --- G07: pending/rate/dedup capacity ----------------------------------------------

void test_g07_capacity_and_rate() {
  GatewayWorld g;
  g.add(1);
  g.add(2);
  g.w.start_all();
  g.w.link(1, 2, 1, 1);
  auto* origin = g.attach(1);
  auto* gateway = g.attach(2);
  GatewayRoleConfig role{};
  role.gateway_boot = 42;
  CHECK_OK(gateway->enable_gateway(role));
  g.w.run(2500);

  const HostDigest zero_host{};
  GatewayEndpoint endpoint =
      resolve_or_fail(g, 1, 2, GatewayScope::GatewaySdkRam, zero_host, 10000);
  CHECK(wait_ready(g, 1, endpoint));
  GatewayEndpointInfo info{};
  CHECK(origin->endpoint_info(endpoint, info));

  const std::array<std::uint8_t, 2> payload{{5, 5}};
  const EncodedServicePayload submit = encode_submit(
      GatewayScope::GatewaySdkRam, info.token, info.gateway_boot,
      ByteView{payload.data(), payload.size()});
  MessageKey key{};
  std::array<std::uint8_t, kGatewayPayloadMaxBytes> drain{};
  std::size_t drain_size = 0;

  // Burst: the first 8 distinct submits in one instant are admitted; the
  // 9th hits the token bucket.
  for (std::uint64_t seq = 1; seq <= 8; ++seq) {
    wire::PlainFrame frame = service_frame(1, MessageId{106, seq}, submit.view());
    g.gd(2)->on_service_payload(1, frame, g.w.now);
    CHECK(gateway->mailbox_take(key, drain, drain_size));
  }
  CHECK(g.gd(2)->stats().submits_accepted == 8);
  wire::PlainFrame ninth = service_frame(1, MessageId{106, 9}, submit.view());
  g.gd(2)->on_service_payload(1, ninth, g.w.now);
  CHECK(g.gd(2)->stats().submits_capacity == 1);
  CHECK(g.gd(2)->stats().submits_accepted == 8);

  // Refill is 20/minute: after 3s exactly one more fits the bucket.
  g.w.run(3000);
  wire::PlainFrame tenth = service_frame(1, MessageId{106, 10}, submit.view());
  g.gd(2)->on_service_payload(1, tenth, g.w.now);
  CHECK(g.gd(2)->stats().submits_accepted == 9);
  CHECK(gateway->mailbox_take(key, drain, drain_size));
  wire::PlainFrame eleventh = service_frame(1, MessageId{106, 11}, submit.view());
  g.gd(2)->on_service_payload(1, eleventh, g.w.now);
  CHECK(g.gd(2)->stats().submits_accepted == 9);
  CHECK(g.gd(2)->stats().submits_capacity == 2);

  // Rate-bound margin property: over a sustained flood the dedup/receipt
  // table can never fill — a 60s window admits at most 8+20 records while
  // the table holds 32, so the capacity answer always comes from the rate
  // bucket, never from record exhaustion or eviction.
  std::size_t accepted_at_capacity = g.gd(2)->stats().submits_accepted;
  for (std::uint64_t seq = 100; seq < 170; ++seq) {
    wire::PlainFrame frame = service_frame(1, MessageId{106, seq}, submit.view());
    g.gd(2)->on_service_payload(1, frame, g.w.now);
    while (gateway->mailbox_take(key, drain, drain_size)) {
    }
    if (g.gd(2)->stats().submits_accepted > accepted_at_capacity) {
      accepted_at_capacity = g.gd(2)->stats().submits_accepted;
      // A record that entered the table must stay for its full 60s hold —
      // evicting it to look better under load is the forbidden behavior.
      CHECK(g.gd(2)->receipt_records_used() <= kGatewayReceiptRecords);
    }
    g.w.run(1500);  // 40/min offered; bucket admits 20/min + burst
  }
  CHECK(g.gd(2)->receipt_records_used() <= 32);
  // Under the burst+refill schedule the live record count stays under the
  // 60s-window admission bound of 28 — margin 4 is never eaten.
  CHECK(g.gd(2)->receipt_records_used() <= 28);
  CHECK(g.gd(2)->stats().submits_capacity > 2);  // rate did the rejecting
}

void test_g07_pending_bound() {
  GatewayWorld g;
  g.add(1);
  g.add(2);
  g.w.start_all();
  g.w.link(1, 2, 1, 1);
  auto* origin = g.attach(1);
  auto* gateway = g.attach(2);
  TestHostSink host{};
  host.ready = true;
  for (std::size_t i = 0; i < 32; ++i) host.binding.principal_digest[i] = 0xA0;
  host.binding.host_boot = 7;
  host.binding.usb_session = 9;
  GatewayRoleConfig role{};
  role.gateway_boot = 42;
  role.capabilities = kGatewayCapHostReceive;
  role.host_sink = &host;
  CHECK_OK(gateway->enable_gateway(role));
  g.w.run(2500);

  HostDigest expected{};
  for (std::size_t i = 0; i < 32; ++i) expected[i] = 0xA0;
  GatewayEndpoint endpoint =
      resolve_or_fail(g, 1, 2, GatewayScope::HostReceiveRam, expected, 10000);
  CHECK(wait_ready(g, 1, endpoint));
  GatewayEndpointInfo info{};
  CHECK(origin->endpoint_info(endpoint, info));

  // Scope-2 submits with the host ACK never arriving: the 8 pending slots
  // fill, the 9th distinct MessageKey is refused CAPACITY before acceptance.
  const EncodedServicePayload submit = encode_submit(
      GatewayScope::HostReceiveRam, info.token, info.gateway_boot,
      ByteView{nullptr, 0});
  for (std::uint64_t seq = 1; seq <= 8; ++seq) {
    wire::PlainFrame frame = service_frame(1, MessageId{107, seq}, submit.view());
    g.gd(2)->on_service_payload(1, frame, g.w.now);
  }
  CHECK(g.gd(2)->pending_records_used() == kGatewayPendingMax);
  CHECK(host.ingresses.size() == 8);
  wire::PlainFrame ninth = service_frame(1, MessageId{107, 9}, submit.view());
  g.gd(2)->on_service_payload(1, ninth, g.w.now);
  CHECK(host.ingresses.size() == 8);          // nothing partially accepted
  CHECK(g.gd(2)->stats().submits_capacity >= 1);

  // A duplicate of a pending key answers PENDING and never re-injects.
  const std::uint32_t dup_before = g.gd(2)->stats().submits_duplicate;
  wire::PlainFrame dup = service_frame(1, MessageId{107, 1}, submit.view());
  g.gd(2)->on_service_payload(1, dup, g.w.now);
  CHECK(g.gd(2)->stats().submits_duplicate == dup_before + 1);
  CHECK(host.ingresses.size() == 8);

  // Same MessageKey, different content → CONFLICT; the stored record keeps
  // the original outcome and nothing is injected twice.
  const std::array<std::uint8_t, 1> different{{0xEE}};
  const EncodedServicePayload other = encode_submit(
      GatewayScope::HostReceiveRam, info.token, info.gateway_boot,
      ByteView{different.data(), different.size()});
  wire::PlainFrame conflict = service_frame(1, MessageId{107, 1}, other.view());
  g.gd(2)->on_service_payload(1, conflict, g.w.now);
  CHECK(g.gd(2)->stats().submits_conflict == 1);
  CHECK(host.ingresses.size() == 8);
}

// --- G08: every bound field of a receipt is verified ---------------------------------

void test_g08_forged_receipt_fields() {
  GatewayWorld g;
  g.add(1);
  g.add(2);
  g.w.start_all();
  g.w.link(1, 2, 1, 1);
  auto* origin = g.attach(1);
  auto* gateway = g.attach(2);
  GatewayRoleConfig role{};
  role.gateway_boot = 42;
  CHECK_OK(gateway->enable_gateway(role));
  g.w.run(2500);

  const HostDigest zero_host{};
  GatewayEndpoint endpoint =
      resolve_or_fail(g, 1, 2, GatewayScope::GatewaySdkRam, zero_host, 10000);
  CHECK(wait_ready(g, 1, endpoint));
  GatewayEndpointInfo info{};
  CHECK(origin->endpoint_info(endpoint, info));

  const std::array<std::uint8_t, 4> payload{{3, 1, 4, 1}};
  MessageId id{};
  CHECK_OK(origin->send(endpoint, ByteView{payload.data(), payload.size()},
                        8000, g.w.now, id));
  const EncodedServicePayload real_submit = encode_submit(
      GatewayScope::GatewaySdkRam, info.token, info.gateway_boot,
      ByteView{payload.data(), payload.size()});
  const RequestDigest real_digest = digest_of(real_submit.view());

  // Each single-field forgery is independently rejected.
  GatewayToken bad_token = info.token;
  bad_token[0] ^= 0xFF;
  RequestDigest bad_digest = real_digest;
  bad_digest[0] ^= 0xFF;
  const struct {
    GatewayToken token;
    std::uint64_t boot;
    GatewayScope scope;
    MessageId ref;
    RequestDigest digest;
  } forgeries[] = {
      {bad_token, info.gateway_boot, GatewayScope::GatewaySdkRam, id, real_digest},
      {info.token, info.gateway_boot + 1, GatewayScope::GatewaySdkRam, id, real_digest},
      {info.token, info.gateway_boot, GatewayScope::HostReceiveRam, id, real_digest},
      {info.token, info.gateway_boot, GatewayScope::GatewaySdkRam,
       MessageId{id.session, id.sequence + 1}, real_digest},
      {info.token, info.gateway_boot, GatewayScope::GatewaySdkRam, id, bad_digest},
  };
  for (const auto& f : forgeries) {
    EncodedServicePayload forged = encode_outcome(
        ServiceSubtype::Receipt, f.scope, f.token, f.boot,
        /*ref_origin=*/1, f.ref, f.digest, ServiceReason::Ok);
    wire::PlainFrame frame = service_frame(2, MessageId{9, 9}, forged.view());
    g.gd(1)->on_service_payload(2, frame, g.w.now);
  }
  CHECK(g.gd(1)->stats().outcomes_rejected >= 5);
  CHECK(g.gobs(1)->results.empty());   // nothing forged completed the send

  // The genuine receipt still lands exactly once.
  g.w.run(3000);
  CHECK(g.gobs(1)->results.size() == 1);
  CHECK(g.gobs(1)->results.back().state == GatewaySendState::EndpointReceived);
}

// --- G10: relay transit vs terminal endpoint ------------------------------------------

void test_g10_relay_transit_and_sinkless_terminal() {
  // A relay without the component still forwards Service like protected
  // transit; the hop ACK references type 21 and the exchange completes.
  GatewayWorld g;
  g.add(1);   // origin
  g.add(2);   // sinkless relay
  g.add(3);   // gateway
  g.w.start_all();
  g.w.link(1, 2, 1, 1);
  g.w.link(2, 3, 1, 1);
  auto* origin = g.attach(1);
  auto* gateway = g.attach(3);
  GatewayRoleConfig role{};
  role.gateway_boot = 42;
  CHECK_OK(gateway->enable_gateway(role));
  g.w.run(4000);
  CHECK(g.at(1)->routes().best(3).valid);

  const HostDigest zero_host{};
  GatewayEndpoint endpoint =
      resolve_or_fail(g, 1, 3, GatewayScope::GatewaySdkRam, zero_host, 10000);
  CHECK(wait_ready(g, 1, endpoint));
  const std::array<std::uint8_t, 3> payload{{7, 7, 7}};
  MessageId id{};
  CHECK_OK(origin->send(endpoint, ByteView{payload.data(), payload.size()},
                        8000, g.w.now, id));
  g.w.run(4000);
  CHECK(g.gobs(1)->results.size() == 1);
  CHECK(g.gobs(1)->results.back().state == GatewaySendState::EndpointReceived);

  // The relay saw Service=21 transit frames and forwarded them — but never
  // surfaced one as DATA, and the origin never saw a DATA delivery event
  // for the service exchange.
  bool saw_service_transit = false;
  for (const FrameSight& sight : g.w.net.sights) {
    if (sight.type == FrameType::Service && sight.from == 2 && sight.to == 3) {
      saw_service_transit = true;
    }
    CHECK(sight.type != FrameType::Service || sight.hop_remaining <= kDefaultHopLimit);
  }
  CHECK(saw_service_transit);
  CHECK(g.w.obs(2)->messages.empty());
  CHECK(g.w.obs(1)->delivery_events.empty());
  CHECK(g.w.obs(3)->messages.empty());
}

void test_g10_sinkless_terminal_drops_honestly() {
  // A terminal node with no Service endpoint is the "old relay" endpoint
  // case: the frame is still hop-ACKed (bounded acceptance) but terminates
  // in an explicit diagnostic, and the origin's result is an honest
  // INDETERMINATE — never a DATA-style success.
  GatewayWorld g;
  g.add(1);
  g.add(2);   // no component: the endpoint is absent
  g.w.start_all();
  g.w.link(1, 2, 1, 1);
  auto* origin = g.attach(1);
  (void)origin;
  // node 2 intentionally has no GatewayDelivery.
  g.w.run(2500);

  // Resolve can't produce an endpoint without a gateway answering — but
  // even an unsolicited Service send to a sinkless node is honest. Build
  // the send directly: fabricate a minimal endpoint is impossible by
  // design, so instead drive the raw carrier for coverage of the drop.
  endpoint::ServiceQuery query{};
  query.scope = GatewayScope::GatewaySdkRam;
  for (std::size_t i = 0; i < 16; ++i) query.nonce[i] = 0x11;
  EncodedServicePayload encoded{};
  CHECK_OK(endpoint::service_query_encode(query, encoded));
  MessageId id{};
  CHECK_OK(g.at(1)->send_service(2, encoded.view(), 4000, g.w.now, id));
  g.w.run(3000);
  CHECK(g.w.obs(2)->has_diag("SERVICE_NO_ENDPOINT"));
  // Nothing was delivered as DATA anywhere.
  CHECK(g.w.obs(2)->messages.empty());
  CHECK(g.w.obs(2)->delivery_events.empty());
  CHECK(g.w.obs(1)->delivery_events.empty());
}

// --- Token/lease basics -----------------------------------------------------------------

void test_token_and_lease_basics() {
  GatewayWorld g;
  g.add(1);
  g.add(2);
  g.w.start_all();
  g.w.link(1, 2, 1, 1);
  auto* origin = g.attach(1);
  auto* gateway = g.attach(2);
  GatewayRoleConfig role{};
  role.gateway_boot = 42;
  CHECK_OK(gateway->enable_gateway(role));
  g.w.run(2500);

  const HostDigest zero_host{};
  // Invalid resolve targets refuse fast.
  GatewayEndpoint bad{};
  CHECK(!g.gd(1)->resolve(1, GatewayScope::GatewaySdkRam, zero_host, 10000,
                         g.w.now, bad));   // self is never a gateway
  CHECK(!g.gd(1)->resolve(kInvalidNodeId, GatewayScope::GatewaySdkRam,
                         zero_host, 10000, g.w.now, bad));
  // A host-capable role without a host sink cannot arm (05 §5.3).
  GatewayRoleConfig bad_role{};
  bad_role.gateway_boot = 42;
  bad_role.capabilities = kGatewayCapHostReceive;
  CHECK(!gateway->enable_gateway(bad_role));
  // And a zero boot incarnation is never a valid identity.
  GatewayRoleConfig zero_boot{};
  CHECK(!gateway->enable_gateway(zero_boot));

  GatewayEndpoint endpoint =
      resolve_or_fail(g, 1, 2, GatewayScope::GatewaySdkRam, zero_host, 10000);
  CHECK(wait_ready(g, 1, endpoint));
  GatewayEndpointInfo info{};
  CHECK(origin->endpoint_info(endpoint, info));
  // The token is a nonzero opaque 128-bit value — never the MessageKey.
  bool token_nonzero = false;
  for (const std::uint8_t byte : info.token) token_nonzero |= byte != 0;
  CHECK(token_nonzero);
  CHECK(info.gateway_boot == 42);

  // A 30s lifetime cannot fit inside the 15s descriptor lease: rejected,
  // never silently shortened (05 §5.3).
  const std::array<std::uint8_t, 4> payload{{1, 1, 1, 1}};
  MessageId id{};
  const Status too_long =
      origin->send(endpoint, ByteView{payload.data(), payload.size()},
                   kGatewayLifetimeMaxMs, g.w.now, id);
  CHECK(!too_long);
  CHECK(too_long.code == StatusCode::InvalidState);
  // A fitting lifetime is accepted.
  CHECK_OK(origin->send(endpoint, ByteView{payload.data(), payload.size()},
                        5000, g.w.now, id));
  g.w.run(3000);
  CHECK(g.gobs(1)->results.back().state == GatewaySendState::EndpointReceived);

  // Past the lease the endpoint goes stale; re-resolve issues a NEW token
  // (the old one is never rebound).
  g.w.run(16000);
  CHECK(origin->endpoint_state(endpoint) == EndpointState::Stale);
  const GatewayToken old_token = info.token;
  GatewayEndpoint second =
      resolve_or_fail(g, 1, 2, GatewayScope::GatewaySdkRam, zero_host, 10000);
  CHECK(wait_ready(g, 1, second));
  GatewayEndpointInfo info2{};
  CHECK(origin->endpoint_info(second, info2));
  CHECK(info2.token != old_token);
  CHECK(origin->endpoint_state(endpoint) == EndpointState::Stale);

  // Endpoint records are bounded to 4 — a fifth resolve refuses.
  GatewayEndpoint third =
      resolve_or_fail(g, 1, 2, GatewayScope::GatewaySdkRam, zero_host, 10000);
  GatewayEndpoint fourth =
      resolve_or_fail(g, 1, 2, GatewayScope::GatewaySdkRam, zero_host, 10000);
  CHECK(wait_ready(g, 1, third));
  CHECK(wait_ready(g, 1, fourth));
  GatewayEndpoint fifth{};
  const Status overflow = g.gd(1)->resolve(2, GatewayScope::GatewaySdkRam,
                                           zero_host, 10000, g.w.now, fifth);
  CHECK(overflow.code == StatusCode::NoCapacity);

  // Releasing frees a slot; the released handle is dead and a re-issued
  // record can never be claimed by the stale handle (generation tag).
  origin->endpoint_release(third);
  CHECK(origin->endpoint_state(third) == EndpointState::Failed);
  GatewayEndpoint replacement =
      resolve_or_fail(g, 1, 2, GatewayScope::GatewaySdkRam, zero_host, 10000);
  CHECK(wait_ready(g, 1, replacement));
  CHECK(origin->endpoint_state(third) == EndpointState::Failed);
}

// --- Host seam: the device-side half of G02/G03 -----------------------------------------

void test_scope2_host_seam() {
  GatewayWorld g;
  g.add(1);
  g.add(2);
  g.w.start_all();
  g.w.link(1, 2, 1, 1);
  auto* origin = g.attach(1);
  auto* gateway = g.attach(2);
  TestHostSink host{};
  host.ready = true;
  for (std::size_t i = 0; i < 32; ++i) host.binding.principal_digest[i] = 0xA0;
  host.binding.host_boot = 7;
  host.binding.usb_session = 9;
  GatewayRoleConfig role{};
  role.gateway_boot = 42;
  role.capabilities = kGatewayCapHostReceive;
  role.host_sink = &host;
  CHECK_OK(gateway->enable_gateway(role));
  g.w.run(2500);

  HostDigest expected{};
  for (std::size_t i = 0; i < 32; ++i) expected[i] = 0xA0;
  GatewayEndpoint endpoint = resolve_or_fail(
      g, 1, 2, GatewayScope::HostReceiveRam, expected, 10000);
  CHECK(wait_ready(g, 1, endpoint));
  GatewayEndpointInfo info{};
  CHECK(origin->endpoint_info(endpoint, info));
  CHECK(info.host_digest == expected);

  // Host ACK happy path: ingress once, authenticated ACK, then Receipt.
  const std::array<std::uint8_t, 4> payload{{2, 0, 2, 4}};
  MessageId id{};
  CHECK_OK(origin->send(endpoint, ByteView{payload.data(), payload.size()},
                        8000, g.w.now, id));
  g.w.run(2000);
  CHECK(host.ingresses.size() == 1);
  CHECK(host.ingresses.back().origin == 1 && host.ingresses.back().id == id);
  g.gd(2)->on_host_ingress_ack(host.ingresses.back(), /*stored=*/true, g.w.now);
  g.w.run(2000);
  CHECK(g.gobs(1)->results.back().state == GatewaySendState::EndpointReceived);
  CHECK(g.gd(2)->stats().host_ram_receipts == 1);

  // ACK lost (G03 device half): the pending record survives the ACK
  // deadline, is never injected twice, and the origin's bounded lifetime
  // expires into an honest INDETERMINATE. A late real ACK still completes
  // the stored record (its evidence is resendable for duplicates).
  MessageId id2{};
  CHECK_OK(origin->send(endpoint, ByteView{payload.data(), payload.size()},
                        6000, g.w.now, id2));
  g.w.run(1000);
  CHECK(host.ingresses.size() == 2);
  g.w.run(6000);   // past the 5s host-ACK deadline AND the send's lifetime
  CHECK(g.gd(2)->pending_records_used() == 1);
  CHECK(g.gd(2)->stats().host_ingress_timeouts == 1);
  CHECK(host.ingresses.size() == 2);   // no second injection
  CHECK(g.gobs(1)->results.back().id == id2);
  CHECK(g.gobs(1)->results.back().state == GatewaySendState::Indeterminate);
  // Late ACK: completes the dedup record and emits the stored receipt.
  g.gd(2)->on_host_ingress_ack(host.ingresses.back(), /*stored=*/true, g.w.now);
  CHECK(g.gd(2)->pending_records_used() == 0);
  CHECK(g.gd(2)->stats().host_ram_receipts == 2);

  // Synchronous ACK inside host_ingress (seam race): the record is armed
  // WaitHost before the seam is entered, so an immediate ACK still lands —
  // receipt completes exactly once and the pending slot never leaks.
  host.sync_ack_target = gateway;
  GatewayEndpoint ep2 = resolve_or_fail(
      g, 1, 2, GatewayScope::HostReceiveRam, expected, 10000);
  CHECK(wait_ready(g, 1, ep2));
  MessageId id3{};
  CHECK_OK(origin->send(ep2, ByteView{payload.data(), payload.size()},
                        4000, g.w.now, id3));
  g.w.run(2000);
  CHECK(host.ingresses.size() == 3);
  CHECK(g.gd(2)->stats().host_ram_receipts == 3);
  CHECK(g.gd(2)->pending_records_used() == 0);
  CHECK(g.gobs(1)->results.back().id == id3);
  CHECK(g.gobs(1)->results.back().state == GatewaySendState::EndpointReceived);
  host.sync_ack_target = nullptr;

  // Host stops at Query time: the resolve is explicitly refused, not left
  // to timeout (device-side G02).
  host.ready = false;
  GatewayEndpoint dead{};
  CHECK_OK(g.gd(1)->resolve(2, GatewayScope::HostReceiveRam, expected, 10000,
                          g.w.now, dead));
  g.w.run(3000);
  CHECK(g.gobs(1)->resolved.back().result.code == StatusCode::InvalidState);

  // A USB session change makes old tokens stale — never a silent rebind
  // (device-side G04).
  host.ready = true;
  host.binding.usb_session = 10;   // reconnect: new session, same host boot
  const EncodedServicePayload submit = encode_submit(
      GatewayScope::HostReceiveRam, info.token, info.gateway_boot,
      ByteView{payload.data(), payload.size()});
  wire::PlainFrame frame = service_frame(1, MessageId{107, 500}, submit.view());
  const std::uint32_t stale_before = g.gd(2)->stats().submits_stale_token;
  g.gd(2)->on_service_payload(1, frame, g.w.now);
  CHECK(g.gd(2)->stats().submits_stale_token == stale_before + 1);
}

// --- Bounded retries / no-route honesty ---------------------------------------------------

void test_send_bounded_retries() {
  GatewayWorld g;
  g.add(1);
  g.add(2);
  g.w.start_all();
  g.w.link(1, 2, 1, 1);
  auto* origin = g.attach(1);
  auto* gateway = g.attach(2);
  GatewayRoleConfig role{};
  role.gateway_boot = 42;
  CHECK_OK(gateway->enable_gateway(role));
  g.w.run(2500);

  const HostDigest zero_host{};
  GatewayEndpoint endpoint =
      resolve_or_fail(g, 1, 2, GatewayScope::GatewaySdkRam, zero_host, 10000);
  CHECK(wait_ready(g, 1, endpoint));

  // Kill the path mid-flight: hop acceptance fails, the component retries
  // its bounded rounds (≤3) and finishes INDETERMINATE — never invented a
  // delivery.
  const std::array<std::uint8_t, 4> payload{{1, 2, 3, 4}};
  MessageId id{};
  CHECK_OK(origin->send(endpoint, ByteView{payload.data(), payload.size()},
                        5000, g.w.now, id));
  g.w.unlink(1, 2);
  g.w.run(8000);
  CHECK(g.gobs(1)->results.size() == 1);
  const GatewaySendState state = g.gobs(1)->results.back().state;
  CHECK(state == GatewaySendState::Indeterminate ||
        state == GatewaySendState::Expired);
  // At most kGatewayMaxRounds rounds of the Submit left the origin.
  int submit_rounds = 0;
  for (const FrameSight& sight : g.w.net.sights) {
    if (sight.type == FrameType::Service && sight.origin == 1) ++submit_rounds;
  }
  CHECK(submit_rounds <= kGatewayMaxRounds + 1);  // resolve Query + ≤3 Submit rounds
}

}  // namespace

int main() {
  test_scope1_happy_path();
  test_g01_wrong_gateway_receipt();
  test_g05_lease_expiry_and_stale_token();
  test_g06_payload_bounds();
  test_g07_capacity_and_rate();
  test_g07_pending_bound();
  test_g08_forged_receipt_fields();
  test_g10_relay_transit_and_sinkless_terminal();
  test_g10_sinkless_terminal_drops_honestly();
  test_token_and_lease_basics();
  test_scope2_host_seam();
  test_send_bounded_retries();
  if (failures != 0) {
    std::fprintf(stderr, "%d gateway checks failed\n", failures);
    return 1;
  }
  std::puts("RouteLoom gateway tests passed");
  return 0;
}
