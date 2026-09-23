// CAP-I2 device dispatch-window tests: BootLease, the host_ops_v1
// SUBMIT/QUERY_DISPATCH/RETIRE_THROUGH/SKIP/TIME_SAMPLE codec, canonical
// request parsing, DispatchWindow admit/floor/retire/skip/lease rules, and
// UsbBridge integration (receipts, reconnect persistence, mesh-outcome
// mapping, capability gating).

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <string>
#include <set>
#include <vector>

#include "routeloom/byte_io.hpp"
#include "routeloom/node.hpp"
#include "routeloom/usb_bridge.hpp"
#include "routeloom/usb_codec.hpp"
#include "routeloom/usb_host_ops.hpp"
#include "routeloom/usb_session.hpp"

#include "test_security.hpp"
#include "test_sim.hpp"

namespace {

int failures = 0;
#define CHECK(expr) do { if (!(expr)) { std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__, #expr); ++failures; } } while (false)

using namespace routeloom;
using namespace routeloom::usb;
using routeloom_test::TestSecurity;
using routeloom_test::CapturingObserver;
using routeloom_test::SimNetwork;
using routeloom_test::SimRadio;

const std::uint8_t kSecret[] = "routeloom-dev-secret";
constexpr std::size_t kSecretLen = 20;

ByteView secret_view() { return ByteView{kSecret, kSecretLen}; }

// ------------------------------------------------------------------ fixtures

BootLease test_lease() { return BootLease::derive(0xB0071D0001ULL, 1); }

std::array<std::uint8_t, 16> test_dispatcher() {
  std::array<std::uint8_t, 16> id{};
  const char* text = "host-dispatcher1";
  std::memcpy(id.data(), text, 16);
  return id;
}

std::array<std::uint8_t, 16> other_dispatcher() {
  std::array<std::uint8_t, 16> id{};
  const char* text = "other-dispatchr2";
  std::memcpy(id.data(), text, 16);
  return id;
}

std::array<std::uint8_t, 32> test_hash(std::uint8_t base = 0x10) {
  std::array<std::uint8_t, 32> hash{};
  for (std::size_t i = 0; i < hash.size(); ++i) {
    hash[i] = static_cast<std::uint8_t>(base + i);
  }
  return hash;
}

std::array<std::uint8_t, 24> test_operation_id(std::uint64_t seq = 1) {
  std::array<std::uint8_t, 24> id{};
  for (std::size_t i = 0; i < 16; ++i) id[i] = static_cast<std::uint8_t>(0xA0 + i);
  for (int i = 0; i < 8; ++i) {
    id[static_cast<std::size_t>(16 + i)] =
        static_cast<std::uint8_t>(seq >> (56 - i * 8));
  }
  return id;
}

// Canonical send request per 03-send-api.md §3 (mirrors the host builder).
std::vector<std::uint8_t> build_canonical(std::uint32_t network = 7,
                                          std::uint8_t dest_kind = 0,
                                          NodeId dest = 2,
                                          std::uint8_t delivery = 1,
                                          std::uint8_t priority = 1,
                                          std::uint8_t storage = 1,
                                          std::uint32_t ttl = 5000,
                                          std::uint8_t hop = 10,
                                          std::uint8_t persist = 0,
                                          ByteView payload = ByteView{}) {
  std::vector<std::uint8_t> out(26 + payload.size, 0);
  out[0] = 1;
  out[1] = static_cast<std::uint8_t>(network >> 24);
  out[2] = static_cast<std::uint8_t>(network >> 16);
  out[3] = static_cast<std::uint8_t>(network >> 8);
  out[4] = static_cast<std::uint8_t>(network);
  out[5] = dest_kind;
  for (int i = 0; i < 8; ++i) {
    out[static_cast<std::size_t>(6 + i)] =
        static_cast<std::uint8_t>(dest >> (56 - i * 8));
  }
  out[14] = delivery;
  out[15] = priority;
  out[16] = 0;
  out[17] = storage;
  out[18] = static_cast<std::uint8_t>(ttl >> 24);
  out[19] = static_cast<std::uint8_t>(ttl >> 16);
  out[20] = static_cast<std::uint8_t>(ttl >> 8);
  out[21] = static_cast<std::uint8_t>(ttl);
  out[22] = hop;
  out[23] = persist;
  out[24] = static_cast<std::uint8_t>(payload.size >> 8);
  out[25] = static_cast<std::uint8_t>(payload.size & 0xFF);
  if (payload.size > 0) {
    std::memcpy(out.data() + 26, payload.data, payload.size);
  }
  return out;
}

// Canonical gateway send request (schema 2, 05-wire-api.md §5.4): the same
// 24B head with dest_kind=1, then the 34B destination extension —
// scope:u8, reserved:u8, token:16, gateway_boot:u64, egress_gateway:u64 —
// before payload_len/payload. Fixed part is 60B, payload is ≤96B.
std::vector<std::uint8_t> build_canonical_v2(
    std::uint32_t network = 7, NodeId dest = 2, std::uint8_t scope = 2,
    const std::array<std::uint8_t, 16>& token = {},
    std::uint64_t gateway_boot = 0xB0071D0001ULL, NodeId egress = 1,
    std::uint8_t delivery = 1, std::uint32_t ttl = 5000,
    ByteView payload = ByteView{}) {
  std::vector<std::uint8_t> out(60 + payload.size, 0);
  out[0] = 2;
  out[1] = static_cast<std::uint8_t>(network >> 24);
  out[2] = static_cast<std::uint8_t>(network >> 16);
  out[3] = static_cast<std::uint8_t>(network >> 8);
  out[4] = static_cast<std::uint8_t>(network);
  out[5] = 1;
  for (int i = 0; i < 8; ++i) {
    out[static_cast<std::size_t>(6 + i)] =
        static_cast<std::uint8_t>(dest >> (56 - i * 8));
  }
  out[14] = delivery;
  out[15] = 1;
  out[16] = 0;
  out[17] = 1;
  out[18] = static_cast<std::uint8_t>(ttl >> 24);
  out[19] = static_cast<std::uint8_t>(ttl >> 16);
  out[20] = static_cast<std::uint8_t>(ttl >> 8);
  out[21] = static_cast<std::uint8_t>(ttl);
  out[22] = 10;
  out[23] = 0;
  out[24] = scope;
  out[25] = 0;
  std::array<std::uint8_t, 16> real_token = token;
  if (real_token == std::array<std::uint8_t, 16>{}) {
    for (std::size_t i = 0; i < real_token.size(); ++i) {
      real_token[i] = static_cast<std::uint8_t>(0x7A + i);
    }
  }
  std::memcpy(out.data() + 26, real_token.data(), 16);
  for (int i = 0; i < 8; ++i) {
    out[static_cast<std::size_t>(42 + i)] =
        static_cast<std::uint8_t>(gateway_boot >> (56 - i * 8));
    out[static_cast<std::size_t>(50 + i)] =
        static_cast<std::uint8_t>(egress >> (56 - i * 8));
  }
  out[58] = static_cast<std::uint8_t>(payload.size >> 8);
  out[59] = static_cast<std::uint8_t>(payload.size & 0xFF);
  if (payload.size > 0) {
    std::memcpy(out.data() + 60, payload.data, payload.size);
  }
  return out;
}

SubmitRequest make_submit(std::uint64_t seq, ByteView canonical,
                          std::uint64_t deadline = 60000) {
  SubmitRequest req{};
  req.lease = test_lease();
  req.dispatcher = test_dispatcher();
  req.dispatch_seq = seq;
  req.operation_id = test_operation_id(seq);
  req.canonical_hash = test_hash();
  req.device_deadline = deadline;
  req.canonical = canonical;
  return req;
}

std::vector<std::uint8_t> encode_submit_bytes(const SubmitRequest& req) {
  std::array<std::uint8_t, kSubmitMaxSize> out{};
  std::size_t written = 0;
  if (!encode_submit(req, MutableByteView{out.data(), out.size()}, written)) {
    return {};
  }
  return std::vector<std::uint8_t>(out.begin(), out.begin() + written);
}

// ------------------------------------------------------------------ BootLease

void test_boot_lease() {
  const BootLease lease = test_lease();
  CHECK(lease.valid());
  // Layout: boot_generation BE || node BE.
  std::uint64_t generation = 0;
  std::uint64_t node = 0;
  for (int i = 0; i < 8; ++i) {
    generation = (generation << 8U) | lease.bytes[static_cast<std::size_t>(i)];
    node = (node << 8U) | lease.bytes[static_cast<std::size_t>(8 + i)];
  }
  CHECK(generation == 0xB0071D0001ULL);
  CHECK(node == 1);
  // Reserved halves invalidate the lease: firmware must not enable sends.
  CHECK(!BootLease::derive(0, 1).valid());
  CHECK(!BootLease::derive(UINT64_MAX, 1).valid());
  CHECK(!BootLease::derive(9, 0).valid());
  CHECK(!BootLease::derive(9, UINT64_MAX).valid());
  CHECK(BootLease::derive(9, 1) != BootLease::derive(10, 1));  // reboot rotates
  CHECK(BootLease::derive(9, 1) == BootLease::derive(9, 1));
}

// ------------------------------------------------------------------ codec

void test_submit_codec() {
  const std::array<std::uint8_t, 9> payload{{'g', 'w', '-', 's', 'u', 'b', 'm', 'i', 't'}};
  const auto canonical = build_canonical(7, 0, 2, 1, 1, 1, 5000, 10, 0,
                                         ByteView{payload.data(), payload.size()});
  const SubmitRequest req =
      make_submit(3, ByteView{canonical.data(), canonical.size()});
  const auto bytes = encode_submit_bytes(req);
  CHECK(bytes.size() == kSubmitFixedSize + canonical.size());

  SubmitRequest decoded{};
  CHECK(decode_submit(ByteView{bytes.data(), bytes.size()}, decoded));
  CHECK(decoded.lease == req.lease);
  CHECK(decoded.dispatcher == req.dispatcher);
  CHECK(decoded.dispatch_seq == 3);
  CHECK(decoded.operation_id == req.operation_id);
  CHECK(decoded.canonical_hash == req.canonical_hash);
  CHECK(decoded.device_deadline == 60000);
  CHECK(decoded.canonical.size == canonical.size());
  CHECK(std::memcmp(decoded.canonical.data, canonical.data(), canonical.size()) == 0);

  // Empty-payload and maximum-payload boundaries.
  const auto empty = build_canonical();
  const SubmitRequest req_empty = make_submit(1, ByteView{empty.data(), empty.size()});
  const auto bytes_empty = encode_submit_bytes(req_empty);
  CHECK(bytes_empty.size() == kSubmitFixedSize + 26);
  SubmitRequest decoded_empty{};
  CHECK(decode_submit(ByteView{bytes_empty.data(), bytes_empty.size()}, decoded_empty));

  std::array<std::uint8_t, 128> big{};
  const auto full = build_canonical(7, 0, 2, 1, 1, 1, 5000, 10, 0,
                                    ByteView{big.data(), big.size()});
  const SubmitRequest req_full = make_submit(2, ByteView{full.data(), full.size()});
  const auto bytes_full = encode_submit_bytes(req_full);
  // Schema-1 maximum (26+128=154B canonical → 262B submit); the 264B bound
  // covers the schema-2 form (60+96=156B canonical) as well.
  CHECK(bytes_full.size() == kSubmitFixedSize + full.size());
  SubmitRequest decoded_full{};
  CHECK(decode_submit(ByteView{bytes_full.data(), bytes_full.size()}, decoded_full));

  // Oversize canonical is refused at encode time.
  std::array<std::uint8_t, 200> too_big{};
  SubmitRequest req_oversize =
      make_submit(4, ByteView{too_big.data(), too_big.size()});
  std::array<std::uint8_t, kSubmitMaxSize + 64> out{};
  std::size_t written = 0;
  CHECK(!encode_submit(req_oversize, MutableByteView{out.data(), out.size()},
                       written));

  // Malformed inputs: truncation at every sensitive cut, length lies,
  // trailing garbage, bad schema/subcommand.
  for (const std::size_t cut : {std::size_t{0}, std::size_t{1}, std::size_t{107},
                                std::size_t{108}, bytes.size() - 1}) {
    SubmitRequest bad{};
    CHECK(!decode_submit(ByteView{bytes.data(), cut}, bad));
  }
  auto mutated = bytes;
  mutated[106] ^= 0xFF;  // canonical_length high byte
  mutated[107] ^= 0xFF;  // canonical_length low byte
  SubmitRequest bad{};
  CHECK(!decode_submit(ByteView{mutated.data(), mutated.size()}, bad));
  mutated = bytes;
  mutated.push_back(0);  // trailing garbage past the length field
  CHECK(!decode_submit(ByteView{mutated.data(), mutated.size()}, bad));
  mutated = bytes;
  mutated[0] = 2;  // bad schema
  CHECK(!decode_submit(ByteView{mutated.data(), mutated.size()}, bad));
  mutated = bytes;
  mutated[1] = 0x02;  // wrong subcommand
  CHECK(!decode_submit(ByteView{mutated.data(), mutated.size()}, bad));

  // A short output buffer fails cleanly instead of truncating.
  std::array<std::uint8_t, 64> small{};
  CHECK(!encode_submit(req, MutableByteView{small.data(), small.size()}, written));
}

void test_lane_codec() {
  for (const HostOpsSub sub :
       {HostOpsSub::QueryDispatch, HostOpsSub::RetireThrough, HostOpsSub::Skip}) {
    LaneRequest req{};
    req.lease = test_lease();
    req.dispatcher = test_dispatcher();
    req.seq = 17;
    std::array<std::uint8_t, kLaneRequestSize> out{};
    std::size_t written = 0;
    CHECK(encode_lane_request(sub, req, MutableByteView{out.data(), out.size()},
                              written));
    CHECK(written == kLaneRequestSize);
    LaneRequest decoded{};
    CHECK(decode_lane_request(ByteView{out.data(), written}, sub, decoded));
    CHECK(decoded.lease == req.lease);
    CHECK(decoded.dispatcher == req.dispatcher);
    CHECK(decoded.seq == 17);

    LaneRequest bad{};
    CHECK(!decode_lane_request(ByteView{out.data(), written - 1}, sub, bad));
    std::array<std::uint8_t, kLaneRequestSize + 1> trailing{};
    std::memcpy(trailing.data(), out.data(), written);
    CHECK(!decode_lane_request(
        ByteView{trailing.data(), trailing.size()}, sub, bad));
    auto mutated = out;
    mutated[1] ^= 0xFF;
    CHECK(!decode_lane_request(ByteView{mutated.data(), mutated.size()}, sub, bad));
    const HostOpsSub other = sub == HostOpsSub::QueryDispatch
                                 ? HostOpsSub::Skip
                                 : HostOpsSub::QueryDispatch;
    CHECK(!decode_lane_request(ByteView{out.data(), written}, other, bad));
  }
}

void test_time_sample_codec() {
  TimeSampleRequest req{};
  req.lease = test_lease();
  req.nonce = 0x1234;
  std::array<std::uint8_t, kTimeSampleRequestSize> out{};
  std::size_t written = 0;
  CHECK(encode_time_sample_request(req, MutableByteView{out.data(), out.size()},
                                   written));
  CHECK(written == kTimeSampleRequestSize);
  TimeSampleRequest decoded{};
  CHECK(decode_time_sample_request(ByteView{out.data(), written}, decoded));
  CHECK(decoded.lease == req.lease);
  CHECK(decoded.nonce == req.nonce);

  TimeSampleRequest bad{};
  CHECK(!decode_time_sample_request(ByteView{out.data(), written - 1}, bad));

  TimeSampleResponse resp{};
  resp.result = HostOpsResult::Ok;
  resp.lease = test_lease();
  resp.nonce = 9;
  resp.device_time = 4242;
  std::array<std::uint8_t, kTimeSampleResponseSize> rout{};
  CHECK(encode_time_sample_response(
      resp, MutableByteView{rout.data(), rout.size()}, written));
  CHECK(written == kTimeSampleResponseSize);
  TimeSampleResponse rdecoded{};
  CHECK(decode_time_sample_response(ByteView{rout.data(), written}, rdecoded));
  CHECK(rdecoded.result == HostOpsResult::Ok);
  CHECK(rdecoded.lease == test_lease());
  CHECK(rdecoded.nonce == 9);
  CHECK(rdecoded.device_time == 4242);

  TimeSampleResponse rbad{};
  CHECK(!decode_time_sample_response(ByteView{rout.data(), written - 1}, rbad));
  auto mutated = rout;
  mutated[2] = static_cast<std::uint8_t>(HostOpsResult::Unsupported) + 1;
  CHECK(!decode_time_sample_response(ByteView{mutated.data(), mutated.size()},
                                     rbad));
}

void test_response_codecs() {
  DispatchReceipt receipt{};
  receipt.sub = HostOpsSub::Submit;
  receipt.result = HostOpsResult::Ok;
  receipt.state = DispatchWindow::State::Sent;
  receipt.lease = test_lease();
  receipt.dispatch_seq = 5;
  receipt.hash = test_hash();
  receipt.msg_session = 7001;
  receipt.msg_seq = 2;
  receipt.msg_valid = true;
  receipt.evidence = DispatchWindow::Evidence::GatewayAccepted;
  std::array<std::uint8_t, kReceiptSize> out{};
  std::size_t written = 0;
  CHECK(encode_receipt(receipt, MutableByteView{out.data(), out.size()}, written));
  CHECK(written == kReceiptSize);
  DispatchReceipt decoded{};
  CHECK(decode_receipt(ByteView{out.data(), written}, HostOpsSub::Submit, decoded));
  CHECK(decoded.result == HostOpsResult::Ok);
  CHECK(decoded.state == DispatchWindow::State::Sent);
  CHECK(decoded.lease == test_lease());
  CHECK(decoded.dispatch_seq == 5);
  CHECK(decoded.hash == test_hash());
  CHECK(decoded.msg_session == 7001 && decoded.msg_seq == 2 && decoded.msg_valid);
  CHECK(decoded.evidence == DispatchWindow::Evidence::GatewayAccepted);

  DispatchReceipt bad{};
  CHECK(!decode_receipt(ByteView{out.data(), written - 1}, HostOpsSub::Submit, bad));
  CHECK(!decode_receipt(ByteView{out.data(), written}, HostOpsSub::Skip, bad));
  auto mutated = out;
  mutated[2] = 14;  // unknown result
  CHECK(!decode_receipt(ByteView{mutated.data(), mutated.size()},
                        HostOpsSub::Submit, bad));
  mutated = out;
  mutated[3] = 7;  // unknown state
  CHECK(!decode_receipt(ByteView{mutated.data(), mutated.size()},
                        HostOpsSub::Submit, bad));
  mutated = out;
  mutated[72] = 2;  // msg_valid must be 0/1
  CHECK(!decode_receipt(ByteView{mutated.data(), mutated.size()},
                        HostOpsSub::Submit, bad));
  mutated = out;
  mutated[73] = 5;  // unknown evidence (4 is HostRamReceived)
  CHECK(!decode_receipt(ByteView{mutated.data(), mutated.size()},
                        HostOpsSub::Submit, bad));

  QueryResponse query{};
  query.result = HostOpsResult::Ok;
  query.state = DispatchWindow::State::Delivered;
  query.lease = test_lease();
  query.dispatch_seq = 6;
  query.hash = test_hash(0x20);
  query.operation_id = test_operation_id(6);
  query.msg_session = 7001;
  query.msg_seq = 3;
  query.msg_valid = true;
  query.evidence = DispatchWindow::Evidence::EndSdkReceived;
  std::array<std::uint8_t, kQueryResponseSize> qout{};
  CHECK(encode_query_response(query, MutableByteView{qout.data(), qout.size()},
                              written));
  CHECK(written == kQueryResponseSize);
  QueryResponse qdecoded{};
  CHECK(decode_query_response(ByteView{qout.data(), written}, qdecoded));
  CHECK(qdecoded.result == HostOpsResult::Ok);
  CHECK(qdecoded.operation_id == test_operation_id(6));
  CHECK(qdecoded.evidence == DispatchWindow::Evidence::EndSdkReceived);
  QueryResponse qbad{};
  CHECK(!decode_query_response(ByteView{qout.data(), written - 1}, qbad));

  RetireResponse retire{};
  retire.result = HostOpsResult::Ok;
  retire.lease = test_lease();
  retire.retired_through = 11;
  std::array<std::uint8_t, kRetireResponseSize> rrout{};
  CHECK(encode_retire_response(retire, MutableByteView{rrout.data(), rrout.size()},
                               written));
  CHECK(written == kRetireResponseSize);
  RetireResponse rrdecoded{};
  CHECK(decode_retire_response(ByteView{rrout.data(), written}, rrdecoded));
  CHECK(rrdecoded.result == HostOpsResult::Ok);
  CHECK(rrdecoded.retired_through == 11);
  RetireResponse rrbad{};
  CHECK(!decode_retire_response(ByteView{rrout.data(), written - 1}, rrbad));
}

// ------------------------------------------------------------------ canonical

void test_canonical_parser() {
  const std::array<std::uint8_t, 3> payload{{0xAA, 0x00, 0xFF}};
  const auto bytes = build_canonical(7, 0, 2, 1, 1, 1, 5000, 10, 0,
                                     ByteView{payload.data(), payload.size()});
  CanonicalFields fields{};
  CHECK(parse_canonical_request(ByteView{bytes.data(), bytes.size()}, fields));
  CHECK(fields.network == 7);
  CHECK(fields.dest_kind == 0 && fields.destination == 2);
  CHECK(fields.delivery == 1 && fields.priority == 1 && fields.storage == 1);
  CHECK(fields.ttl_ms == 5000 && fields.hop_limit == 10 && !fields.persist_sleep);
  CHECK(fields.payload.size == 3);
  CHECK(std::memcmp(fields.payload.data, payload.data(), 3) == 0);

  CanonicalFields bad{};
  CHECK(!parse_canonical_request(ByteView{bytes.data(), 25}, bad));  // short
  auto mutated = bytes;
  mutated[0] = 2;
  CHECK(!parse_canonical_request(ByteView{mutated.data(), mutated.size()}, bad));
  mutated = bytes;
  mutated[25] ^= 0x01;  // payload length lie
  CHECK(!parse_canonical_request(ByteView{mutated.data(), mutated.size()}, bad));
  mutated = bytes;
  mutated[14] = 3;  // delivery out of range
  CHECK(!parse_canonical_request(ByteView{mutated.data(), mutated.size()}, bad));
  mutated = bytes;
  mutated[15] = 4;  // priority out of range
  CHECK(!parse_canonical_request(ByteView{mutated.data(), mutated.size()}, bad));
  mutated = bytes;
  mutated[16] = 1;  // unknown deadline policy
  CHECK(!parse_canonical_request(ByteView{mutated.data(), mutated.size()}, bad));
  mutated = bytes;
  mutated[17] = 2;  // storage out of range
  CHECK(!parse_canonical_request(ByteView{mutated.data(), mutated.size()}, bad));
  mutated = bytes;
  mutated[5] = 2;  // destination kind out of range
  CHECK(!parse_canonical_request(ByteView{mutated.data(), mutated.size()}, bad));
  mutated = bytes;
  mutated[23] = 2;  // persist out of range
  CHECK(!parse_canonical_request(ByteView{mutated.data(), mutated.size()}, bad));
  for (const std::uint8_t hop : {std::uint8_t{0}, std::uint8_t{11}}) {
    mutated = bytes;
    mutated[22] = hop;
    CHECK(!parse_canonical_request(ByteView{mutated.data(), mutated.size()}, bad));
  }
  // ttl 0 and ttl 30001.
  mutated = bytes;
  mutated[18] = mutated[19] = mutated[20] = mutated[21] = 0;
  CHECK(!parse_canonical_request(ByteView{mutated.data(), mutated.size()}, bad));
  mutated = bytes;
  mutated[18] = 0;
  mutated[19] = 0;
  mutated[20] = 0x75;
  mutated[21] = 0x31;
  CHECK(!parse_canonical_request(ByteView{mutated.data(), mutated.size()}, bad));
  // Reserved node destinations.
  for (int i = 6; i < 14; ++i) {
    mutated = bytes;
    std::memset(mutated.data() + 6, 0, 8);
    CHECK(!parse_canonical_request(ByteView{mutated.data(), mutated.size()}, bad));
    mutated = bytes;
    std::memset(mutated.data() + 6, 0xFF, 8);
    CHECK(!parse_canonical_request(ByteView{mutated.data(), mutated.size()}, bad));
    (void)i;
  }
  // Structurally valid but phase-disabled values PARSE (the bridge gates
  // them to Unsupported): applied delivery, non-normal priority, persist.
  mutated = bytes;
  mutated[14] = 2;
  CHECK(parse_canonical_request(ByteView{mutated.data(), mutated.size()}, fields));
  CHECK(fields.delivery == 2);
  mutated = bytes;
  mutated[15] = 3;
  CHECK(parse_canonical_request(ByteView{mutated.data(), mutated.size()}, fields));
  mutated = bytes;
  mutated[23] = 1;
  CHECK(parse_canonical_request(ByteView{mutated.data(), mutated.size()}, fields));
  CHECK(fields.persist_sleep);
  // Gateway-kind destinations are schema-2 only: a schema-1 body carrying
  // dest_kind=1 is malformed (the schema-1 shape has nowhere to bind an
  // endpoint token), and schema 2 with a node destination is malformed too.
  mutated = bytes;
  mutated[5] = 1;
  CHECK(!parse_canonical_request(ByteView{mutated.data(), mutated.size()}, bad));
  const auto gw = build_canonical_v2(7, 2, 2, {}, 0xB0071D0001ULL, 1);
  CHECK(parse_canonical_request(ByteView{gw.data(), gw.size()}, fields));
  CHECK(fields.schema == 2 && fields.dest_kind == 1 && fields.destination == 2);
  CHECK(fields.gateway_scope == 2);
  CHECK(fields.gateway_boot == 0xB0071D0001ULL && fields.egress_gateway == 1);
  const std::array<std::uint8_t, 16> zero_token{};
  CHECK(fields.gateway_token != zero_token);
  // A schema-2 body bound to a node destination is never reinterpreted.
  auto gw_bad = gw;
  gw_bad[5] = 0;
  CHECK(!parse_canonical_request(ByteView{gw_bad.data(), gw_bad.size()}, bad));
  // Reserved extension fields fail structurally: bad scope, nonzero
  // reserved byte, all-zero token, reserved boot/egress ids.
  gw_bad = gw;
  gw_bad[24] = 3;
  CHECK(!parse_canonical_request(ByteView{gw_bad.data(), gw_bad.size()}, bad));
  gw_bad = gw;
  gw_bad[25] = 1;
  CHECK(!parse_canonical_request(ByteView{gw_bad.data(), gw_bad.size()}, bad));
  gw_bad = gw;
  std::memset(gw_bad.data() + 26, 0, 16);
  CHECK(!parse_canonical_request(ByteView{gw_bad.data(), gw_bad.size()}, bad));
  gw_bad = gw;
  std::memset(gw_bad.data() + 42, 0, 8);
  CHECK(!parse_canonical_request(ByteView{gw_bad.data(), gw_bad.size()}, bad));
  gw_bad = gw;
  std::memset(gw_bad.data() + 50, 0xFF, 8);
  CHECK(!parse_canonical_request(ByteView{gw_bad.data(), gw_bad.size()}, bad));
  // Schema-2 payload bound is 96B — 97B is malformed, never truncated.
  std::array<std::uint8_t, 97> over{};
  const auto gw_over = build_canonical_v2(7, 2, 2, {}, 0xB0071D0001ULL, 1, 1,
                                          5000, ByteView{over.data(), 97});
  CHECK(!parse_canonical_request(ByteView{gw_over.data(), gw_over.size()}, bad));
}

// ------------------------------------------------------------------ window

using WindowState = DispatchWindow::State;

void test_window_admit_replay_conflict() {
  DispatchWindow window(test_lease());
  const auto dispatcher = test_dispatcher();
  const auto hash = test_hash();
  CHECK(window.check_submit(test_lease(), dispatcher, 1, hash,
                            test_operation_id(1)) ==
        DispatchWindow::SubmitCheck::Admit);
  CHECK(window.record_sent(dispatcher, 1, hash, test_operation_id(1), 1, 7001, 1));
  CHECK(window.used() == 1);
  const DispatchWindow::Slot* slot = window.find(1);
  CHECK(slot != nullptr && slot->state == WindowState::Sent);
  CHECK(slot->msg_valid && slot->msg_session == 7001 && slot->msg_seq == 1);
  CHECK(slot->evidence == DispatchWindow::Evidence::GatewayAccepted);

  // Same seq + same hash replays; same seq + other hash conflicts.
  CHECK(window.check_submit(test_lease(), dispatcher, 1, hash,
                            test_operation_id(1)) ==
        DispatchWindow::SubmitCheck::Replay);
  CHECK(window.check_submit(test_lease(), dispatcher, 1, test_hash(0x50),
                            test_operation_id(1)) ==
        DispatchWindow::SubmitCheck::Conflict);
  // Recording twice is refused: admit is check-then-record, never overwrite.
  CHECK(!window.record_sent(dispatcher, 1, hash, test_operation_id(1), 1, 7001, 9));
  CHECK(window.find(1)->msg_seq == 1);

  // Reserved identities never admit.
  CHECK(window.check_submit(test_lease(), dispatcher, 0, hash,
                            test_operation_id(2)) ==
        DispatchWindow::SubmitCheck::InvalidId);
  CHECK(window.check_submit(test_lease(), dispatcher, UINT64_MAX, hash,
                            test_operation_id(2)) ==
        DispatchWindow::SubmitCheck::InvalidId);
  const std::array<std::uint8_t, 16> zero{};
  std::array<std::uint8_t, 16> maxed{};
  maxed.fill(0xFF);
  CHECK(window.check_submit(test_lease(), zero, 2, hash,
                            test_operation_id(2)) ==
        DispatchWindow::SubmitCheck::InvalidId);
  CHECK(window.check_submit(test_lease(), maxed, 2, hash,
                            test_operation_id(2)) ==
        DispatchWindow::SubmitCheck::InvalidId);
}

void test_window_capacity_bound() {
  DispatchWindow window(test_lease());
  const auto dispatcher = test_dispatcher();
  // Positions 1..32 admit; the 33rd is backpressure, not an eviction.
  for (std::uint64_t seq = 1; seq <= DispatchWindow::kCapacity; ++seq) {
    CHECK(window.check_submit(test_lease(), dispatcher, seq, test_hash(),
                              test_operation_id(seq)) ==
          DispatchWindow::SubmitCheck::Admit);
    CHECK(window.record_sent(dispatcher, seq, test_hash(), test_operation_id(seq),
                             1, 7001, seq));
  }
  CHECK(window.used() == DispatchWindow::kCapacity);
  CHECK(window.check_submit(test_lease(), dispatcher, 33, test_hash(),
                            test_operation_id(33)) ==
        DispatchWindow::SubmitCheck::WindowFull);
  // Nothing was evicted to make room: every protected record is intact.
  CHECK(window.used() == DispatchWindow::kCapacity);
  for (std::uint64_t seq = 1; seq <= DispatchWindow::kCapacity; ++seq) {
    CHECK(window.find(seq) != nullptr);
  }
}

void test_window_retire_prefix() {
  DispatchWindow window(test_lease());
  const auto dispatcher = test_dispatcher();
  for (std::uint64_t seq = 1; seq <= 4; ++seq) {
    CHECK(window.check_submit(test_lease(), dispatcher, seq, test_hash(),
                              test_operation_id(seq)) ==
          DispatchWindow::SubmitCheck::Admit);
    CHECK(window.record_sent(dispatcher, seq, test_hash(), test_operation_id(seq),
                             1, 7001, seq));
  }
  // A Sent (non-terminal) position pins the prefix: retire refuses.
  CHECK(window.retire_through(test_lease(), dispatcher, 1) ==
        DispatchWindow::RetireOutcome::RefusedSpan);
  CHECK(window.retired_through() == 0);

  // Terminate 1..2 via mesh outcomes; 3 stays Sent.
  CHECK(window.note_mesh_outcome(7001, 1, DeliveryState::Delivered));
  CHECK(window.note_mesh_outcome(7001, 2, DeliveryState::Failed));
  CHECK(window.find(1)->state == WindowState::Delivered);
  CHECK(window.find(2)->state == WindowState::Failed);

  // Retire cannot jump over the Sent position 3.
  CHECK(window.retire_through(test_lease(), dispatcher, 4) ==
        DispatchWindow::RetireOutcome::RefusedSpan);
  CHECK(window.retire_through(test_lease(), dispatcher, 2) ==
        DispatchWindow::RetireOutcome::Advanced);
  CHECK(window.retired_through() == 2);
  CHECK(window.find(1) == nullptr && window.find(2) == nullptr);
  CHECK(window.find(3) != nullptr);  // pinned survivor untouched

  // Re-RETIRE at/below the floor is an idempotent no-op (CAP09) — but
  // reserved `through` values are InvalidId, never a blessed no-op.
  CHECK(window.retire_through(test_lease(), dispatcher, 2) ==
        DispatchWindow::RetireOutcome::NoopFloor);
  CHECK(window.retire_through(test_lease(), dispatcher, 0) ==
        DispatchWindow::RetireOutcome::InvalidId);
  CHECK(window.retire_through(test_lease(), dispatcher, UINT64_MAX) ==
        DispatchWindow::RetireOutcome::InvalidId);
  CHECK(window.retired_through() == 2);

  // The window slides: 33..34 admit now, 35 is past the new edge.
  CHECK(window.check_submit(test_lease(), dispatcher, 33, test_hash(),
                            test_operation_id(33)) ==
        DispatchWindow::SubmitCheck::Admit);
  CHECK(window.check_submit(test_lease(), dispatcher, 34, test_hash(),
                            test_operation_id(34)) ==
        DispatchWindow::SubmitCheck::Admit);
  CHECK(window.check_submit(test_lease(), dispatcher, 35, test_hash(),
                            test_operation_id(35)) ==
        DispatchWindow::SubmitCheck::WindowFull);
  // Retired seqs stay retired: never re-admitted, never re-sent.
  CHECK(window.check_submit(test_lease(), dispatcher, 1, test_hash(),
                            test_operation_id(1)) ==
        DispatchWindow::SubmitCheck::Retired);
  CHECK(window.check_submit(test_lease(), dispatcher, 2, test_hash(),
                            test_operation_id(2)) ==
        DispatchWindow::SubmitCheck::Retired);

  // Empty holes block retirement exactly like Sent positions.
  CHECK(window.retire_through(test_lease(), dispatcher, 4) ==
        DispatchWindow::RetireOutcome::RefusedSpan);
  // Retire past the tracked window is refused (untracked != terminal).
  CHECK(window.retire_through(test_lease(), dispatcher, 2 + 33) ==
        DispatchWindow::RetireOutcome::RefusedSpan);
}

void test_window_retire_ring_wrap() {
  DispatchWindow window(test_lease());
  const auto dispatcher = test_dispatcher();
  // Fill and expire the whole first window, then retire it in one span.
  for (std::uint64_t seq = 1; seq <= 32; ++seq) {
    CHECK(window.record_expired(dispatcher, seq, test_hash(),
                                test_operation_id(seq), 1));
  }
  CHECK(window.retire_through(test_lease(), dispatcher, 32) ==
        DispatchWindow::RetireOutcome::Advanced);
  CHECK(window.used() == 0);
  // The ring aliases (seq+32 shares a slot): stale data must be gone.
  for (std::uint64_t seq = 33; seq <= 64; ++seq) {
    CHECK(window.check_submit(test_lease(), dispatcher, seq, test_hash(0x77),
                              test_operation_id(seq)) ==
          DispatchWindow::SubmitCheck::Admit);
    CHECK(window.record_sent(dispatcher, seq, test_hash(0x77),
                             test_operation_id(seq), 0, 7001, seq));
    CHECK(window.find(seq)->hash == test_hash(0x77));
  }
  CHECK(window.used() == 32);
}

void test_window_skip() {
  DispatchWindow window(test_lease());
  const auto dispatcher = test_dispatcher();
  CHECK(window.skip(test_lease(), dispatcher, 1) == DispatchWindow::SkipOutcome::Skipped);
  CHECK(window.find(1)->state == WindowState::Skipped);
  // Re-SKIP is idempotent; SUBMIT onto a SKIP conflicts (hashes differ).
  CHECK(window.skip(test_lease(), dispatcher, 1) ==
        DispatchWindow::SkipOutcome::ReplaySkipped);
  CHECK(window.check_submit(test_lease(), dispatcher, 1, test_hash(),
                            test_operation_id(1)) ==
        DispatchWindow::SubmitCheck::Conflict);

  // SKIP never overwrites an accepted record.
  CHECK(window.record_sent(dispatcher, 2, test_hash(), test_operation_id(2), 1,
                           7001, 2));
  CHECK(window.skip(test_lease(), dispatcher, 2) ==
        DispatchWindow::SkipOutcome::Occupied);
  CHECK(window.find(2)->state == WindowState::Sent);

  // Skipped holes retire like any terminal span.
  CHECK(window.skip(test_lease(), dispatcher, 3) == DispatchWindow::SkipOutcome::Skipped);
  CHECK(window.retire_through(test_lease(), dispatcher, 1) ==
        DispatchWindow::RetireOutcome::Advanced);
  CHECK(window.skip(test_lease(), dispatcher, 1) == DispatchWindow::SkipOutcome::Retired);
  CHECK(window.skip(test_lease(), dispatcher, 99) ==
        DispatchWindow::SkipOutcome::WindowFull);
}

void test_window_query() {
  DispatchWindow window(test_lease());
  const auto dispatcher = test_dispatcher();
  CHECK(window.record_sent(dispatcher, 1, test_hash(), test_operation_id(1), 1,
                           7001, 7));
  DispatchWindow::Slot slot{};
  CHECK(window.query(test_lease(), dispatcher, 1, slot) ==
        DispatchWindow::QueryOutcome::Found);
  CHECK(slot.msg_seq == 7 && slot.operation_id == test_operation_id(1));
  // Read-only: the query changed nothing.
  CHECK(window.used() == 1);
  CHECK(window.query(test_lease(), dispatcher, 1, slot) ==
        DispatchWindow::QueryOutcome::Found);

  CHECK(window.query(test_lease(), dispatcher, 2, slot) ==
        DispatchWindow::QueryOutcome::NotRetained);
  CHECK(window.query(test_lease(), dispatcher, 999, slot) ==
        DispatchWindow::QueryOutcome::NotRetained);
  CHECK(window.query(test_lease(), dispatcher, 0, slot) ==
        DispatchWindow::QueryOutcome::InvalidId);

  CHECK(window.note_mesh_outcome(7001, 7, DeliveryState::Delivered));
  CHECK(window.retire_through(test_lease(), dispatcher, 1) ==
        DispatchWindow::RetireOutcome::Advanced);
  CHECK(window.query(test_lease(), dispatcher, 1, slot) ==
        DispatchWindow::QueryOutcome::Retired);
}

void test_window_lease_and_lane() {
  const BootLease other = BootLease::derive(0xB0071D0002ULL, 1);  // next boot
  const auto dispatcher = test_dispatcher();
  const auto hash = test_hash();

  // A rebooted device rejects the old lease on every operation; the old
  // window's records are unreachable under the new lease (host marks them
  // indeterminate — it must never silently resubmit them).
  DispatchWindow rebooted(other);
  CHECK(rebooted.check_submit(test_lease(), dispatcher, 1, hash,
                              test_operation_id(1)) ==
        DispatchWindow::SubmitCheck::LeaseMismatch);
  DispatchWindow::Slot slot{};
  CHECK(rebooted.query(test_lease(), dispatcher, 1, slot) ==
        DispatchWindow::QueryOutcome::LeaseMismatch);
  CHECK(rebooted.retire_through(test_lease(), dispatcher, 1) ==
        DispatchWindow::RetireOutcome::LeaseMismatch);
  CHECK(rebooted.skip(test_lease(), dispatcher, 1) ==
        DispatchWindow::SkipOutcome::LeaseMismatch);

  // An invalid local lease (boot persistence failed) mismatches everything,
  // including itself: sends are not enabled.
  DispatchWindow unbooted(BootLease::derive(0, 1));
  CHECK(unbooted.check_submit(BootLease::derive(0, 1), dispatcher, 1, hash,
                              test_operation_id(1)) ==
        DispatchWindow::SubmitCheck::LeaseMismatch);

  // Lane binding: the first actual send claims the lane for its
  // dispatcher; a second dispatcher is refused on all four lane operations.
  DispatchWindow window(test_lease());
  CHECK(!window.lane_bound());
  CHECK(window.check_submit(test_lease(), dispatcher, 1, hash,
                            test_operation_id(1)) ==
        DispatchWindow::SubmitCheck::Admit);
  CHECK(!window.lane_bound());  // checks don't bind; sends do
  CHECK(window.record_sent(dispatcher, 1, hash, test_operation_id(1), 1, 7001, 1));
  CHECK(window.lane_bound());
  const auto other_disp = other_dispatcher();
  CHECK(window.check_submit(test_lease(), other_disp, 2, hash,
                            test_operation_id(2)) ==
        DispatchWindow::SubmitCheck::LaneMismatch);
  CHECK(window.query(test_lease(), other_disp, 1, slot) ==
        DispatchWindow::QueryOutcome::LaneMismatch);
  CHECK(window.retire_through(test_lease(), other_disp, 1) ==
        DispatchWindow::RetireOutcome::LaneMismatch);
  CHECK(window.skip(test_lease(), other_disp, 2) ==
        DispatchWindow::SkipOutcome::LaneMismatch);
  // The owner is unaffected.
  CHECK(window.query(test_lease(), dispatcher, 1, slot) ==
        DispatchWindow::QueryOutcome::Found);
}

void test_window_mesh_outcomes() {
  DispatchWindow window(test_lease());
  const auto dispatcher = test_dispatcher();
  // Unknown MessageKeys correlate to nothing.
  CHECK(!window.note_mesh_outcome(7001, 999, DeliveryState::Delivered));

  CHECK(window.record_sent(dispatcher, 1, test_hash(), test_operation_id(1), 1,
                           7001, 11));
  CHECK(window.record_sent(dispatcher, 2, test_hash(), test_operation_id(2), 0,
                           7001, 12));
  // Non-terminal mesh states keep Sent — and still correlate.
  CHECK(window.note_mesh_outcome(7001, 11, DeliveryState::Queued));
  CHECK(window.find(1)->state == WindowState::Sent);
  // Reliable Delivered is an end receipt; best-effort Delivered is a MAC
  // attempt — the evidence must not be confused (03 §5).
  CHECK(window.note_mesh_outcome(7001, 11, DeliveryState::Delivered));
  CHECK(window.find(1)->state == WindowState::Delivered);
  CHECK(window.find(1)->evidence == DispatchWindow::Evidence::EndSdkReceived);
  CHECK(window.note_mesh_outcome(7001, 12, DeliveryState::Delivered));
  CHECK(window.find(2)->state == WindowState::Delivered);
  CHECK(window.find(2)->evidence == DispatchWindow::Evidence::MacAttemptReported);
  // Terminal slots ignore late duplicates but still correlate.
  CHECK(window.note_mesh_outcome(7001, 11, DeliveryState::Failed));
  CHECK(window.find(1)->state == WindowState::Delivered);

  CHECK(window.record_sent(dispatcher, 3, test_hash(), test_operation_id(3), 1,
                           7001, 13));
  CHECK(window.note_mesh_outcome(7001, 13, DeliveryState::Failed));
  CHECK(window.find(3)->state == WindowState::Failed);
  CHECK(window.find(3)->evidence == DispatchWindow::Evidence::GatewayAccepted);

  CHECK(window.record_sent(dispatcher, 4, test_hash(), test_operation_id(4), 1,
                           7001, 14));
  CHECK(window.note_mesh_outcome(7001, 14, DeliveryState::Expired));
  CHECK(window.find(4)->state == WindowState::Expired);

  CHECK(window.record_sent(dispatcher, 5, test_hash(), test_operation_id(5), 1,
                           7001, 15));
  CHECK(window.note_mesh_outcome(7001, 15, DeliveryState::Indeterminate));
  CHECK(window.find(5)->state == WindowState::Indeterminate);

  CHECK(window.record_sent(dispatcher, 6, test_hash(), test_operation_id(6), 1,
                           7001, 16));
  CHECK(window.note_mesh_outcome(7001, 16, DeliveryState::CancelledBeforeTx));
  CHECK(window.find(6)->state == WindowState::Indeterminate);

  // Every terminal mesh outcome retires.
  CHECK(window.retire_through(test_lease(), dispatcher, 6) ==
        DispatchWindow::RetireOutcome::Advanced);
}

void test_window_reserved_submit_fields() {
  DispatchWindow window(test_lease());
  const auto dispatcher = test_dispatcher();
  const auto hash = test_hash();
  // Reserved canonical_hash space (all-zero / all-ones) is InvalidId —
  // the same rule as reserved seqs and dispatcher ids (01 §3).
  std::array<std::uint8_t, 32> zero_hash{};
  std::array<std::uint8_t, 32> max_hash{};
  max_hash.fill(0xFF);
  CHECK(window.check_submit(test_lease(), dispatcher, 1, zero_hash,
                            test_operation_id(1)) ==
        DispatchWindow::SubmitCheck::InvalidId);
  CHECK(window.check_submit(test_lease(), dispatcher, 1, max_hash,
                            test_operation_id(1)) ==
        DispatchWindow::SubmitCheck::InvalidId);
  // Reserved operation_id (all-zero / all-0xFF 24B) is refused too: it is
  // echoed back via QUERY, so reserved values must never be stored.
  std::array<std::uint8_t, 24> zero_op{};
  std::array<std::uint8_t, 24> max_op{};
  max_op.fill(0xFF);
  CHECK(window.check_submit(test_lease(), dispatcher, 1, hash, zero_op) ==
        DispatchWindow::SubmitCheck::InvalidId);
  CHECK(window.check_submit(test_lease(), dispatcher, 1, hash, max_op) ==
        DispatchWindow::SubmitCheck::InvalidId);
  // ...and nothing was admitted: the positions stay free.
  CHECK(window.used() == 0);
}

void test_window_submit_onto_skip_is_conflict() {
  DispatchWindow window(test_lease());
  const auto dispatcher = test_dispatcher();
  CHECK(window.skip(test_lease(), dispatcher, 1) ==
        DispatchWindow::SkipOutcome::Skipped);
  // SUBMIT onto a SKIP is Conflict per design — the skipped slot stores a
  // zeroed hash, so this must NEVER classify as a Replay/Existing even
  // when the submitted hash is itself all zeros (that one is caught
  // earlier by the reserved-id gate as InvalidId).
  CHECK(window.check_submit(test_lease(), dispatcher, 1, test_hash(),
                            test_operation_id(1)) ==
        DispatchWindow::SubmitCheck::Conflict);
  const std::array<std::uint8_t, 32> zero_hash{};
  CHECK(window.check_submit(test_lease(), dispatcher, 1, zero_hash,
                            test_operation_id(1)) ==
        DispatchWindow::SubmitCheck::InvalidId);
  // A same-content replay of the SKIP itself is still idempotent.
  CHECK(window.skip(test_lease(), dispatcher, 1) ==
        DispatchWindow::SkipOutcome::ReplaySkipped);
}

void test_window_lane_binds_on_first_send() {
  DispatchWindow window(test_lease());
  const auto first = test_dispatcher();
  const auto second = other_dispatcher();
  // A lone SKIP records the hole but must NOT claim the lane for the boot.
  CHECK(window.skip(test_lease(), first, 1) == DispatchWindow::SkipOutcome::Skipped);
  CHECK(!window.lane_bound());
  // Neither does a terminal Expired record — nothing was ever sent.
  CHECK(window.record_expired(first, 2, test_hash(), test_operation_id(2), 1));
  CHECK(!window.lane_bound());
  // The first actual SEND binds the lane — whichever dispatcher sends it.
  CHECK(window.record_sent(second, 3, test_hash(), test_operation_id(3), 1,
                           7001, 3));
  CHECK(window.lane_bound());
  // From now on the first dispatcher mismatches on every lane operation.
  CHECK(window.skip(test_lease(), first, 4) == DispatchWindow::SkipOutcome::LaneMismatch);
  CHECK(window.check_submit(test_lease(), first, 4, test_hash(),
                            test_operation_id(4)) ==
        DispatchWindow::SubmitCheck::LaneMismatch);
  // The earlier terminal records still retire — under the bound owner.
  CHECK(window.retire_through(test_lease(), second, 2) ==
        DispatchWindow::RetireOutcome::Advanced);
}

void test_window_record_indeterminate() {
  DispatchWindow window(test_lease());
  const auto dispatcher = test_dispatcher();
  // Degraded-path record: a live send with no Sent bookkeeping becomes a
  // terminal Indeterminate slot that still correlates the MessageKey.
  CHECK(window.record_indeterminate(dispatcher, 5, test_hash(),
                                    test_operation_id(5), 1, 7001, 55));
  const DispatchWindow::Slot* slot = window.find(5);
  CHECK(slot != nullptr && slot->state == WindowState::Indeterminate);
  CHECK(slot->msg_valid && slot->msg_session == 7001 && slot->msg_seq == 55);
  // It never binds the lane and never re-admits: same hash replays as
  // Existing, a different hash Conflicts — no clean re-send is possible.
  CHECK(!window.lane_bound());
  CHECK(window.check_submit(test_lease(), dispatcher, 5, test_hash(),
                            test_operation_id(5)) ==
        DispatchWindow::SubmitCheck::Replay);
  CHECK(window.check_submit(test_lease(), dispatcher, 5, test_hash(0x50),
                            test_operation_id(5)) ==
        DispatchWindow::SubmitCheck::Conflict);
  // Late outcomes still correlate (suppressed from the legacy event path)
  // without changing the honest Indeterminate state.
  CHECK(window.note_mesh_outcome(7001, 55, DeliveryState::Delivered));
  CHECK(window.find(5)->state == WindowState::Indeterminate);
  // Occupied positions refuse the fallback record — never overwritten.
  CHECK(!window.record_indeterminate(dispatcher, 5, test_hash(),
                                     test_operation_id(5), 1, 7001, 56));
  // Empty holes still block the prefix; certify them, then the whole
  // terminal span retires under the (still unbound) lane.
  for (std::uint64_t seq = 1; seq <= 4; ++seq) {
    CHECK(window.skip(test_lease(), dispatcher, seq) ==
          DispatchWindow::SkipOutcome::Skipped);
  }
  CHECK(!window.lane_bound());
  CHECK(window.retire_through(test_lease(), dispatcher, 5) ==
        DispatchWindow::RetireOutcome::Advanced);
}

// -------------------------------------------------------- bridge integration

class FakeStream final : public ByteStream {
 public:
  std::deque<std::uint8_t> out;

  Status write(const ByteView data, std::size_t& written) noexcept override {
    written = 0;
    for (std::size_t i = 0; i < data.size; ++i) out.push_back(data.data[i]);
    written = data.size;
    return Status::success();
  }

  std::vector<std::uint8_t> take() {
    std::vector<std::uint8_t> bytes(out.begin(), out.end());
    out.clear();
    return bytes;
  }
};

struct DecodedRecord {
  UsbFrame frame{};
  std::vector<std::uint8_t> body;
};

class CollectSink final : public UsbFrameSink {
 public:
  std::vector<DecodedRecord> frames;

  void on_frame(const UsbFrame& frame) noexcept override {
    DecodedRecord record{};
    record.frame = frame;
    record.body.assign(frame.body.data, frame.body.data + frame.body.size);
    record.frame.body = ByteView{record.body.data(), record.body.size()};
    frames.push_back(std::move(record));
  }
  void on_stream_error(const Status) noexcept override {}
};

std::vector<std::uint8_t> encode(FrameKind kind, std::uint16_t flags,
                                 std::uint64_t session, std::uint64_t request,
                                 ByteView body) {
  std::array<std::uint8_t, kMaxDecodedFrame> scratch{};
  std::array<std::uint8_t, kMaxEncodedFrame> out{};
  std::size_t written = 0;
  if (!encode_frame(kind, flags, session, request, body,
                    MutableByteView{scratch.data(), scratch.size()},
                    MutableByteView{out.data(), out.size()}, written)) {
    return {};
  }
  return std::vector<std::uint8_t>(out.begin(), out.begin() + written);
}

std::uint64_t read_u64(const std::uint8_t* p) {
  std::uint64_t v = 0;
  for (int i = 0; i < 8; ++i) v = (v << 8U) | p[i];
  return v;
}

void write_u64(std::uint8_t* p, std::uint64_t v) {
  for (int i = 7; i >= 0; --i) {
    p[i] = static_cast<std::uint8_t>(v & 0xFFU);
    v >>= 8U;
  }
}

struct HostDriver {
  SessionProof proof{};
  std::uint64_t h2d_counter{0};
  std::uint64_t session{0};

  std::vector<std::uint8_t> plain(FrameKind kind, std::uint16_t flags,
                                  std::uint64_t request, ByteView body) {
    return encode(kind, flags, 0, request, body);
  }
  std::vector<std::uint8_t> sealed(FrameKind kind, std::uint64_t request,
                                   ByteView inner) {
    std::array<std::uint8_t, 1200> body{};
    std::size_t body_size = 0;
    if (!seal_body(proof.key, kDirHostToDevice, h2d_counter, kind, 0, request,
                   inner, MutableByteView{body.data(), body.size()}, body_size)) {
      return {};
    }
    ++h2d_counter;
    return encode(kind, 0, session, request, ByteView{body.data(), body_size});
  }
};

struct World {
  FakeStream stream;
  std::vector<std::uint8_t> secret{kSecret, kSecret + kSecretLen};
  UsbBridge bridge;
  SimNetwork net;
  TestSecurity sec1, sec2;
  CapturingObserver obs2;
  SimRadio r1, r2;
  MeshNode n1, n2;
  CollectSink device_sink;
  StreamDecoder device_decoder;

  explicit World(std::uint32_t capability = 0x3 | kCapHostOpsV1, bool scoped = false)
      : bridge(config(capability), stream),
        r1(net, 1), r2(net, 2),
        n1(node_config(1, 7001, scoped), r1, sec1, bridge),
        n2(node_config(2, 2002, scoped), r2, sec2, obs2),
        device_decoder(device_sink) {
    bridge.set_mesh(&n1);
    net.register_node(1, &n1);
    net.register_node(2, &n2);
    net.connect(1, 2);
    n1.start(0);
    n2.start(0);
    n1.add_neighbor(2, 1, 0);
    n2.add_neighbor(1, 1, 0);
  }

  UsbBridge::Config config(std::uint32_t capability) {
    UsbBridge::Config cfg{};
    cfg.secret = ByteView{secret.data(), secret.size()};
    cfg.node = 1;
    cfg.network = 7;
    cfg.boot_id = 0xB0071D0001ULL;
    cfg.capability = capability;
    cfg.device_nonce = 0xA0B0C0D0E0F00102ULL;
    return cfg;
  }
  static NodeConfig node_config(NodeId node, std::uint32_t session, bool scoped = false) {
    NodeConfig cfg{};
    cfg.network = 7;
    cfg.node = node;
    cfg.message_session = session;
    if (scoped) {
      // Gateway-scoped profile with node 1 (the bridge node) as the route
      // gateway — the only profile group delivery runs on.
      cfg.route_gateways = {1, kInvalidNodeId};
      cfg.route_advertisement_period_ms = 500;
      cfg.route_lifetime_ms = 9000;
      cfg.route_refresh_ticks = kScopedDefaultRefreshTicks;
    }
    return cfg;
  }

  void feed(const std::vector<std::uint8_t>& wire, MonotonicMs now) {
    bridge.on_bytes(ByteView{wire.data(), wire.size()}, now);
  }
  void drain(MonotonicMs now) {
    for (int i = 0; i < 16; ++i) bridge.poll(now);
    const auto bytes = stream.take();
    if (!bytes.empty()) device_decoder.push(ByteView{bytes.data(), bytes.size()}, now);
  }
};

std::uint64_t host_handshake(World& world, HostDriver& host, MonotonicMs& now,
                             std::uint64_t host_nonce, std::uint64_t request_base) {
  std::array<std::uint8_t, 64> hello_body{};
  write_u64(hello_body.data(), host_nonce);
  hello_body[8] = 1;
  hello_body[9] = 1;
  const char* principal = "host-operator";
  hello_body[10] = 13;
  std::memcpy(hello_body.data() + 11, principal, 13);
  world.feed(host.plain(FrameKind::Hello, 0, request_base,
                        ByteView{hello_body.data(), 24}), now);
  world.drain(now);
  now += 200;
  if (world.device_sink.frames.size() != 1) return 0;
  const auto& ack = world.device_sink.frames.back().frame;
  if (ack.kind != FrameKind::HelloAck || ack.body.size != 53) return 0;
  std::array<std::uint8_t, 64> ack_body{};
  std::memcpy(ack_body.data(), ack.body.data, ack.body.size);
  world.device_sink.frames.clear();

  SessionTranscript transcript{};
  transcript.host_nonce = host_nonce;
  transcript.device_nonce = read_u64(ack_body.data());
  transcript.version = ack_body[8];
  transcript.node = read_u64(ack_body.data() + 9);
  transcript.boot_id = read_u64(ack_body.data() + 17);
  transcript.network = read_u64(ack_body.data() + 25);
  transcript.capability =
      (static_cast<std::uint32_t>(ack_body[33]) << 24U) |
      (static_cast<std::uint32_t>(ack_body[34]) << 16U) |
      (static_cast<std::uint32_t>(ack_body[35]) << 8U) | ack_body[36];
  transcript.principal_len = 13;
  std::memcpy(transcript.principal.data(), principal, 13);
  std::array<std::uint8_t, kTranscriptSize> encoded{};
  std::size_t size = 0;
  if (!encode_transcript(transcript,
                         MutableByteView{encoded.data(), encoded.size()}, size)) {
    return 0;
  }
  host.proof = derive_session_proof(secret_view(), ByteView{encoded.data(), size});
  host.session = host.proof.session_id;
  world.feed(host.plain(FrameKind::Hello, kFlagAuth, request_base + 1,
                        ByteView{host.proof.auth_tag.data(), kDevTagSize}), now);
  world.drain(now);
  now += 200;
  if (world.device_sink.frames.size() != 2) return 0;  // auth_ok + rx grant
  world.device_sink.frames.clear();

  // Generous device->host grant so receipts never stall on credit.
  std::array<std::uint8_t, 17> grant{};
  grant[0] = kCreditGrant;
  write_u64(grant.data() + 1, 64);
  write_u64(grant.data() + 9, 65536);
  world.feed(host.sealed(FrameKind::Credit, request_base + 2,
                         ByteView{grant.data(), grant.size()}), now);
  world.drain(now);
  now += 200;
  world.device_sink.frames.clear();
  return host.session;
}

// Sends one HostOps inner body and returns the opened response inner (or an
// empty vector when the device answered with an Error / nothing). Advances
// `now` past the exchange: the bridge's CONTROL token buckets refill with
// time, so a frozen clock would stall the pump behind unemittable topups.
std::vector<std::uint8_t> transact(World& world, HostDriver& host,
                                   MonotonicMs& now, std::uint64_t request,
                                   ByteView inner, bool& got_error,
                                   std::uint16_t& error_code) {
  got_error = false;
  error_code = 0;
  world.feed(host.sealed(FrameKind::HostOps, request, inner), now);
  world.drain(now);
  now += 200;
  std::vector<std::uint8_t> answer;
  for (const auto& record : world.device_sink.frames) {
    std::uint64_t counter = 0;
    ByteView opened{};
    if (!open_body(host.proof.key, kDirDeviceToHost, record.frame, counter,
                   opened)) {
      continue;
    }
    if (record.frame.kind == FrameKind::HostOps && answer.empty()) {
      answer.assign(opened.data, opened.data + opened.size);
    } else if (record.frame.kind == FrameKind::Error) {
      got_error = true;
      if (opened.size >= 2) {
        error_code = static_cast<std::uint16_t>((opened.data[0] << 8U) |
                                                opened.data[1]);
      }
    }
  }
  world.device_sink.frames.clear();
  return answer;
}

std::vector<std::uint8_t> submit_bytes(std::uint64_t seq, ByteView canonical,
                                       std::uint64_t deadline = 60000) {
  return encode_submit_bytes(make_submit(seq, canonical, deadline));
}

std::vector<std::uint8_t> lane_bytes(HostOpsSub sub, std::uint64_t seq) {
  LaneRequest req{};
  req.lease = test_lease();
  req.dispatcher = test_dispatcher();
  req.seq = seq;
  std::array<std::uint8_t, kLaneRequestSize> out{};
  std::size_t written = 0;
  if (!encode_lane_request(sub, req, MutableByteView{out.data(), out.size()},
                           written)) {
    return {};
  }
  return std::vector<std::uint8_t>(out.begin(), out.begin() + written);
}

void test_bridge_submit_lifecycle() {
  World world;
  HostDriver host;
  MonotonicMs now = 1000;
  CHECK(host_handshake(world, host, now, 0x1111, 10) != 0);
  CHECK(world.bridge.state() == SessionState::Active);

  const std::array<std::uint8_t, 4> payload{{1, 2, 3, 4}};
  const auto canonical = build_canonical(7, 0, 2, 1, 1, 1, 5000, 10, 0,
                                         ByteView{payload.data(), payload.size()});
  bool got_error = false;
  std::uint16_t error_code = 0;

  // SUBMIT admits, mesh-sends and receipts with a stable MessageKey.
  // The synchronous Accepted/Queued mesh callbacks inside send() must NOT
  // surface as DeliveryEvents: only the receipt (+ credit topup) is emitted.
  const auto submit = submit_bytes(1, ByteView{canonical.data(), canonical.size()});
  world.feed(host.sealed(FrameKind::HostOps, 20,
                         ByteView{submit.data(), submit.size()}), now);
  world.drain(now);
  std::vector<std::uint8_t> answer;
  for (const auto& record : world.device_sink.frames) {
    CHECK(record.frame.kind != FrameKind::DeliveryEvent);
    if (record.frame.kind != FrameKind::HostOps) continue;
    std::uint64_t counter = 0;
    ByteView opened{};
    CHECK(open_body(host.proof.key, kDirDeviceToHost, record.frame, counter,
                    opened));
    answer.assign(opened.data, opened.data + opened.size);
  }
  world.device_sink.frames.clear();
  now += 200;
  CHECK(!got_error && answer.size() == kReceiptSize);
  DispatchReceipt receipt{};
  CHECK(decode_receipt(ByteView{answer.data(), answer.size()},
                       HostOpsSub::Submit, receipt));
  CHECK(receipt.result == HostOpsResult::Ok);
  CHECK(receipt.state == WindowState::Sent);
  CHECK(receipt.dispatch_seq == 1 && receipt.hash == test_hash());
  CHECK(receipt.msg_valid && receipt.msg_session == 7001 && receipt.msg_seq == 1);
  CHECK(receipt.evidence == DispatchWindow::Evidence::GatewayAccepted);
  CHECK(receipt.lease == test_lease());

  // Identical resubmit replays; same seq + other hash conflicts (CAP07).
  const auto replay =
      transact(world, host, now, 21, ByteView{submit.data(), submit.size()},
               got_error, error_code);
  DispatchReceipt receipt2{};
  CHECK(decode_receipt(ByteView{replay.data(), replay.size()}, HostOpsSub::Submit,
                       receipt2));
  CHECK(receipt2.result == HostOpsResult::Existing);
  CHECK(receipt2.msg_valid && receipt2.msg_seq == 1);

  SubmitRequest conflicted =
      make_submit(1, ByteView{canonical.data(), canonical.size()});
  conflicted.canonical_hash = test_hash(0x50);
  const auto conflict_bytes = encode_submit_bytes(conflicted);
  const auto conflict_answer = transact(world, host, now, 22,
                                        ByteView{conflict_bytes.data(),
                                                 conflict_bytes.size()},
                                        got_error, error_code);
  DispatchReceipt receipt3{};
  CHECK(decode_receipt(ByteView{conflict_answer.data(), conflict_answer.size()},
                       HostOpsSub::Submit, receipt3));
  CHECK(receipt3.result == HostOpsResult::Conflict);
  CHECK(receipt3.hash == test_hash());  // authoritative stored hash, not ours

  // QUERY reads the record back without side effects.
  const auto query = lane_bytes(HostOpsSub::QueryDispatch, 1);
  const auto query_answer = transact(world, host, now, 23,
                                     ByteView{query.data(), query.size()},
                                     got_error, error_code);
  QueryResponse queried{};
  CHECK(decode_query_response(ByteView{query_answer.data(), query_answer.size()},
                              queried));
  CHECK(queried.result == HostOpsResult::Ok);
  CHECK(queried.state == WindowState::Sent);
  CHECK(queried.operation_id == test_operation_id(1));

  // A hole reads back NOT_RETAINED, never re-executed.
  const auto hole = lane_bytes(HostOpsSub::QueryDispatch, 9);
  const auto hole_answer =
      transact(world, host, now, 24, ByteView{hole.data(), hole.size()},
               got_error, error_code);
  QueryResponse hole_resp{};
  CHECK(decode_query_response(ByteView{hole_answer.data(), hole_answer.size()},
                              hole_resp));
  CHECK(hole_resp.result == HostOpsResult::NotRetained);

  // SKIP refuses to overwrite the accepted record (CAP08).
  const auto skip = lane_bytes(HostOpsSub::Skip, 1);
  const auto skip_answer =
      transact(world, host, now, 25, ByteView{skip.data(), skip.size()},
               got_error, error_code);
  DispatchReceipt skip_resp{};
  CHECK(decode_receipt(ByteView{skip_answer.data(), skip_answer.size()},
                       HostOpsSub::Skip, skip_resp));
  CHECK(skip_resp.result == HostOpsResult::SkipRefused);
  CHECK(skip_resp.state == WindowState::Sent);

  // RETIRE across the Sent position is refused; skipping the hole behind it
  // does not help while 1 is still live.
  const auto skip2 = lane_bytes(HostOpsSub::Skip, 2);
  const auto skip2_answer =
      transact(world, host, now, 26, ByteView{skip2.data(), skip2.size()},
               got_error, error_code);
  DispatchReceipt skip2_resp{};
  CHECK(decode_receipt(ByteView{skip2_answer.data(), skip2_answer.size()},
                       HostOpsSub::Skip, skip2_resp));
  CHECK(skip2_resp.result == HostOpsResult::Ok);
  const auto retire = lane_bytes(HostOpsSub::RetireThrough, 2);
  const auto retire_answer =
      transact(world, host, now, 27, ByteView{retire.data(), retire.size()},
               got_error, error_code);
  RetireResponse retire_resp{};
  CHECK(decode_retire_response(ByteView{retire_answer.data(), retire_answer.size()},
                               retire_resp));
  CHECK(retire_resp.result == HostOpsResult::RetireRefused);
  CHECK(retire_resp.retired_through == 0);
}

void test_bridge_expiry_and_mesh_outcome() {
  World world;
  HostDriver host;
  MonotonicMs now = 5000;
  CHECK(host_handshake(world, host, now, 0x2222, 40) != 0);
  bool got_error = false;
  std::uint16_t error_code = 0;

  const auto canonical = build_canonical();
  // A deadline already past at admission: terminal Expired, never sent.
  const auto late = submit_bytes(
      1, ByteView{canonical.data(), canonical.size()}, now);
  const auto late_answer =
      transact(world, host, now, 50, ByteView{late.data(), late.size()},
               got_error, error_code);
  DispatchReceipt late_resp{};
  CHECK(decode_receipt(ByteView{late_answer.data(), late_answer.size()},
                       HostOpsSub::Submit, late_resp));
  CHECK(late_resp.result == HostOpsResult::Expired);
  CHECK(late_resp.state == WindowState::Expired);
  CHECK(!late_resp.msg_valid);

  // Live submit, then the mesh outcome lands via on_delivery: the slot
  // advances and NO legacy DeliveryEvent is emitted for it.
  const auto live = submit_bytes(
      2, ByteView{canonical.data(), canonical.size()}, now + 5000);
  const auto live_answer =
      transact(world, host, now, 51, ByteView{live.data(), live.size()},
               got_error, error_code);
  DispatchReceipt live_resp{};
  CHECK(decode_receipt(ByteView{live_answer.data(), live_answer.size()},
                       HostOpsSub::Submit, live_resp));
  CHECK(live_resp.result == HostOpsResult::Ok && live_resp.msg_valid);

  world.bridge.on_delivery(DeliveryResult{
      MessageId{live_resp.msg_session,
                static_cast<std::uint64_t>(live_resp.msg_seq)},
      DeliveryState::Delivered, "END_RECEIVED"});
  world.drain(now);
  for (const auto& record : world.device_sink.frames) {
    CHECK(record.frame.kind != FrameKind::DeliveryEvent);
  }
  world.device_sink.frames.clear();

  const auto query = lane_bytes(HostOpsSub::QueryDispatch, 2);
  const auto query_answer =
      transact(world, host, now, 52, ByteView{query.data(), query.size()},
               got_error, error_code);
  QueryResponse queried{};
  CHECK(decode_query_response(ByteView{query_answer.data(), query_answer.size()},
                              queried));
  CHECK(queried.result == HostOpsResult::Ok);
  CHECK(queried.state == WindowState::Delivered);
  CHECK(queried.evidence == DispatchWindow::Evidence::EndSdkReceived);

  // Both terminal now: retire advances over them in one prefix (CAP09).
  const auto retire = lane_bytes(HostOpsSub::RetireThrough, 2);
  const auto retire_answer =
      transact(world, host, now, 53, ByteView{retire.data(), retire.size()},
               got_error, error_code);
  RetireResponse retire_resp{};
  CHECK(decode_retire_response(ByteView{retire_answer.data(), retire_answer.size()},
                               retire_resp));
  CHECK(retire_resp.result == HostOpsResult::Ok);
  CHECK(retire_resp.retired_through == 2);
  // Re-RETIRE is idempotent; retired seqs answer Retired everywhere.
  const auto retire_again = transact(world, host, now, 54,
                                     ByteView{retire.data(), retire.size()},
                                     got_error, error_code);
  RetireResponse retire_again_resp{};
  CHECK(decode_retire_response(
      ByteView{retire_again.data(), retire_again.size()}, retire_again_resp));
  CHECK(retire_again_resp.result == HostOpsResult::Ok);
  CHECK(retire_again_resp.retired_through == 2);

  const auto query_old = lane_bytes(HostOpsSub::QueryDispatch, 1);
  const auto query_old_answer = transact(world, host, now, 55,
                                         ByteView{query_old.data(),
                                                  query_old.size()},
                                         got_error, error_code);
  QueryResponse old_resp{};
  CHECK(decode_query_response(
      ByteView{query_old_answer.data(), query_old_answer.size()}, old_resp));
  CHECK(old_resp.result == HostOpsResult::Retired);

  const auto resubmit = submit_bytes(1, ByteView{canonical.data(),
                                                 canonical.size()},
                                     now + 5000);
  const auto resubmit_answer = transact(world, host, now, 56,
                                        ByteView{resubmit.data(),
                                                 resubmit.size()},
                                        got_error, error_code);
  DispatchReceipt resubmit_resp{};
  CHECK(decode_receipt(ByteView{resubmit_answer.data(), resubmit_answer.size()},
                       HostOpsSub::Submit, resubmit_resp));
  CHECK(resubmit_resp.result == HostOpsResult::Retired);
}

void test_bridge_reconnect_keeps_window() {
  World world;
  HostDriver host;
  MonotonicMs now = 1000;
  CHECK(host_handshake(world, host, now, 0x3333, 60) != 0);
  bool got_error = false;
  std::uint16_t error_code = 0;

  const auto canonical = build_canonical();
  const auto submit = submit_bytes(1, ByteView{canonical.data(),
                                               canonical.size()});
  const auto answer =
      transact(world, host, now, 70, ByteView{submit.data(), submit.size()},
               got_error, error_code);
  DispatchReceipt receipt{};
  CHECK(decode_receipt(ByteView{answer.data(), answer.size()},
                       HostOpsSub::Submit, receipt));
  CHECK(receipt.result == HostOpsResult::Ok);

  // Reconnect: a fresh session against the same boot keeps lane + records.
  HostDriver host2;
  now += 500;
  CHECK(host_handshake(world, host2, now, 0x4444, 80) != 0);
  const auto query = lane_bytes(HostOpsSub::QueryDispatch, 1);
  const auto query_answer =
      transact(world, host2, now, 90, ByteView{query.data(), query.size()},
               got_error, error_code);
  QueryResponse queried{};
  CHECK(decode_query_response(ByteView{query_answer.data(), query_answer.size()},
                              queried));
  CHECK(queried.result == HostOpsResult::Ok);
  CHECK(queried.state == WindowState::Sent);
  CHECK(queried.msg_valid && queried.msg_seq == receipt.msg_seq);
}

void test_bridge_lease_lane_and_validation() {
  World world;
  HostDriver host;
  MonotonicMs now = 1000;
  CHECK(host_handshake(world, host, now, 0x5555, 100) != 0);
  bool got_error = false;
  std::uint16_t error_code = 0;
  const auto canonical = build_canonical();

  // A resubmit under a stale boot lease is LeaseMismatch, never a replay.
  SubmitRequest stale =
      make_submit(1, ByteView{canonical.data(), canonical.size()});
  stale.lease = BootLease::derive(0xB0071D0000ULL, 1);  // previous boot
  const auto stale_bytes = encode_submit_bytes(stale);
  const auto stale_answer = transact(world, host, now, 110,
                                     ByteView{stale_bytes.data(),
                                              stale_bytes.size()},
                                     got_error, error_code);
  DispatchReceipt stale_resp{};
  CHECK(decode_receipt(ByteView{stale_answer.data(), stale_answer.size()},
                       HostOpsSub::Submit, stale_resp));
  CHECK(stale_resp.result == HostOpsResult::LeaseMismatch);
  CHECK(stale_resp.lease == test_lease());  // current lease always reported

  // First submit binds the lane; a second dispatcher is refused.
  const auto submit = submit_bytes(1, ByteView{canonical.data(),
                                               canonical.size()});
  const auto answer =
      transact(world, host, now, 111, ByteView{submit.data(), submit.size()},
               got_error, error_code);
  DispatchReceipt receipt{};
  CHECK(decode_receipt(ByteView{answer.data(), answer.size()},
                       HostOpsSub::Submit, receipt));
  CHECK(receipt.result == HostOpsResult::Ok);

  SubmitRequest foreign =
      make_submit(2, ByteView{canonical.data(), canonical.size()});
  foreign.dispatcher = other_dispatcher();
  const auto foreign_bytes = encode_submit_bytes(foreign);
  const auto foreign_answer = transact(world, host, now, 112,
                                       ByteView{foreign_bytes.data(),
                                                foreign_bytes.size()},
                                       got_error, error_code);
  DispatchReceipt foreign_resp{};
  CHECK(decode_receipt(ByteView{foreign_answer.data(), foreign_answer.size()},
                       HostOpsSub::Submit, foreign_resp));
  CHECK(foreign_resp.result == HostOpsResult::LaneMismatch);

  // Reserved dispatch_seq is InvalidRequest, not a window position.
  const auto zero_seq = submit_bytes(0, ByteView{canonical.data(),
                                                 canonical.size()});
  const auto zero_answer = transact(world, host, now, 113,
                                    ByteView{zero_seq.data(), zero_seq.size()},
                                    got_error, error_code);
  DispatchReceipt zero_resp{};
  CHECK(decode_receipt(ByteView{zero_answer.data(), zero_answer.size()},
                       HostOpsSub::Submit, zero_resp));
  CHECK(zero_resp.result == HostOpsResult::InvalidRequest);

  // Corrupt canonical framing is InvalidRequest.
  auto broken = canonical;
  broken[25] ^= 0xFF;
  const auto broken_submit =
      submit_bytes(3, ByteView{broken.data(), broken.size()});
  const auto broken_answer = transact(world, host, now, 114,
                                      ByteView{broken_submit.data(),
                                               broken_submit.size()},
                                      got_error, error_code);
  DispatchReceipt broken_resp{};
  CHECK(decode_receipt(ByteView{broken_answer.data(), broken_answer.size()},
                       HostOpsSub::Submit, broken_resp));
  CHECK(broken_resp.result == HostOpsResult::InvalidRequest);
  // ... and left no record behind: the position still admits.
  const auto retry = submit_bytes(3, ByteView{canonical.data(),
                                              canonical.size()});
  const auto retry_answer =
      transact(world, host, now, 115, ByteView{retry.data(), retry.size()},
               got_error, error_code);
  DispatchReceipt retry_resp{};
  CHECK(decode_receipt(ByteView{retry_answer.data(), retry_answer.size()},
                       HostOpsSub::Submit, retry_resp));
  CHECK(retry_resp.result == HostOpsResult::Ok);

  // Canonical network != session network is cross-network confusion.
  const auto foreign_net = build_canonical(9, 0, 2);
  const auto net_submit =
      submit_bytes(4, ByteView{foreign_net.data(), foreign_net.size()});
  const auto net_answer =
      transact(world, host, now, 116, ByteView{net_submit.data(),
                                               net_submit.size()},
               got_error, error_code);
  DispatchReceipt net_resp{};
  CHECK(decode_receipt(ByteView{net_answer.data(), net_answer.size()},
                       HostOpsSub::Submit, net_resp));
  CHECK(net_resp.result == HostOpsResult::InvalidRequest);

  // APPLIED delivery and gateway-kind destinations are Unsupported, never
  // downgraded or locally "delivered" without a sink.
  const auto applied = build_canonical(7, 0, 2, 2);
  const auto applied_submit =
      submit_bytes(5, ByteView{applied.data(), applied.size()});
  const auto applied_answer = transact(world, host, now, 117,
                                       ByteView{applied_submit.data(),
                                                applied_submit.size()},
                                       got_error, error_code);
  DispatchReceipt applied_resp{};
  CHECK(decode_receipt(ByteView{applied_answer.data(), applied_answer.size()},
                       HostOpsSub::Submit, applied_resp));
  CHECK(applied_resp.result == HostOpsResult::Unsupported);

  // A well-formed schema-2 gateway destination on a bridge without the
  // gateway endpoint capability is Unsupported — never silently accepted.
  const auto gateway = build_canonical_v2(7, 2);
  const auto gateway_submit =
      submit_bytes(6, ByteView{gateway.data(), gateway.size()});
  const auto gateway_answer = transact(world, host, now, 118,
                                       ByteView{gateway_submit.data(),
                                                gateway_submit.size()},
                                       got_error, error_code);
  DispatchReceipt gateway_resp{};
  CHECK(decode_receipt(ByteView{gateway_answer.data(), gateway_answer.size()},
                       HostOpsSub::Submit, gateway_resp));
  CHECK(gateway_resp.result == HostOpsResult::Unsupported);
}

void test_bridge_time_sample() {
  World world;
  HostDriver host;
  MonotonicMs now = 7777;
  CHECK(host_handshake(world, host, now, 0x6666, 130) != 0);
  bool got_error = false;
  std::uint16_t error_code = 0;

  TimeSampleRequest req{};
  req.lease = test_lease();
  req.nonce = 0xDEAD;
  std::array<std::uint8_t, kTimeSampleRequestSize> inner{};
  std::size_t written = 0;
  CHECK(encode_time_sample_request(
      req, MutableByteView{inner.data(), inner.size()}, written));
  const MonotonicMs fed_at = now;
  const auto answer = transact(world, host, now, 140,
                               ByteView{inner.data(), written}, got_error,
                               error_code);
  CHECK(!got_error && answer.size() == kTimeSampleResponseSize);
  TimeSampleResponse resp{};
  CHECK(decode_time_sample_response(ByteView{answer.data(), answer.size()}, resp));
  CHECK(resp.result == HostOpsResult::Ok);
  CHECK(resp.lease == test_lease());
  CHECK(resp.nonce == 0xDEAD);
  CHECK(resp.device_time == fed_at);

  // Stale lease: mismatch, but the current lease is still reported.
  req.lease = BootLease::derive(0xB0071D0000ULL, 1);
  CHECK(encode_time_sample_request(
      req, MutableByteView{inner.data(), inner.size()}, written));
  const auto stale_answer = transact(world, host, now, 141,
                                     ByteView{inner.data(), written}, got_error,
                                     error_code);
  TimeSampleResponse stale_resp{};
  CHECK(decode_time_sample_response(
      ByteView{stale_answer.data(), stale_answer.size()}, stale_resp));
  CHECK(stale_resp.result == HostOpsResult::LeaseMismatch);
  CHECK(stale_resp.lease == test_lease());
  CHECK(stale_resp.nonce == 0xDEAD);
}

void test_bridge_malformed_and_gating() {
  World world;
  HostDriver host;
  MonotonicMs now = 1000;
  CHECK(host_handshake(world, host, now, 0x7777, 150) != 0);
  bool got_error = false;
  std::uint16_t error_code = 0;

  // Unknown subcommand, bad schema and truncation are Error frames.
  const std::array<std::uint8_t, 4> unknown{{1, 0x09, 0, 0}};
  transact(world, host, now, 160, ByteView{unknown.data(), unknown.size()},
           got_error, error_code);
  CHECK(got_error && error_code == static_cast<std::uint16_t>(UsbErrorCode::Unsupported));

  const std::array<std::uint8_t, 4> bad_schema{{9, 1, 0, 0}};
  transact(world, host, now, 161, ByteView{bad_schema.data(), bad_schema.size()},
           got_error, error_code);
  CHECK(got_error && error_code == static_cast<std::uint16_t>(UsbErrorCode::ProtocolError));

  const std::array<std::uint8_t, 1> tiny{{1}};
  transact(world, host, now, 162, ByteView{tiny.data(), tiny.size()}, got_error,
           error_code);
  CHECK(got_error && error_code == static_cast<std::uint16_t>(UsbErrorCode::ProtocolError));

  const auto canonical = build_canonical();
  const auto submit = submit_bytes(1, ByteView{canonical.data(),
                                               canonical.size()});
  transact(world, host, now, 163,
           ByteView{submit.data(), submit.size() - 1}, got_error, error_code);
  CHECK(got_error && error_code == static_cast<std::uint16_t>(UsbErrorCode::ProtocolError));

  // A device without the host_ops_v1 capability bit answers Unsupported.
  World legacy(0x3);
  HostDriver legacy_host;
  CHECK(host_handshake(legacy, legacy_host, now, 0x8888, 170) != 0);
  const auto legacy_answer =
      transact(legacy, legacy_host, now, 180, ByteView{submit.data(),
                                                       submit.size()},
               got_error, error_code);
  CHECK(got_error && error_code == static_cast<std::uint16_t>(UsbErrorCode::Unsupported));
  CHECK(legacy_answer.empty());
}

void test_bridge_submit_rejections() {
  World world;
  HostDriver host;
  MonotonicMs now = 1000;
  CHECK(host_handshake(world, host, now, 0x9999, 190) != 0);
  bool got_error = false;
  std::uint16_t error_code = 0;
  const auto canonical = build_canonical();

  // WindowFull at the bridge: seq 33 is past floor(0) + capacity(32).
  const auto full = submit_bytes(33, ByteView{canonical.data(), canonical.size()});
  const auto full_answer =
      transact(world, host, now, 200, ByteView{full.data(), full.size()},
               got_error, error_code);
  DispatchReceipt full_resp{};
  CHECK(decode_receipt(ByteView{full_answer.data(), full_answer.size()},
                       HostOpsSub::Submit, full_resp));
  CHECK(full_resp.result == HostOpsResult::WindowFull);

  // Reserved canonical_hash (all-zero) is InvalidRequest — never stored,
  // and never confused with a skipped slot's zeroed hash field.
  SubmitRequest zeroed = make_submit(1, ByteView{canonical.data(), canonical.size()});
  zeroed.canonical_hash = {};
  const auto zeroed_bytes = encode_submit_bytes(zeroed);
  const auto zeroed_answer =
      transact(world, host, now, 201,
               ByteView{zeroed_bytes.data(), zeroed_bytes.size()},
               got_error, error_code);
  DispatchReceipt zeroed_resp{};
  CHECK(decode_receipt(ByteView{zeroed_answer.data(), zeroed_answer.size()},
                       HostOpsSub::Submit, zeroed_resp));
  CHECK(zeroed_resp.result == HostOpsResult::InvalidRequest);

  // Reserved operation_id values (all-zero / all-0xFF) are InvalidRequest.
  SubmitRequest zero_op = make_submit(1, ByteView{canonical.data(), canonical.size()});
  zero_op.operation_id = {};
  const auto zero_op_bytes = encode_submit_bytes(zero_op);
  const auto zero_op_answer =
      transact(world, host, now, 202,
               ByteView{zero_op_bytes.data(), zero_op_bytes.size()},
               got_error, error_code);
  DispatchReceipt zero_op_resp{};
  CHECK(decode_receipt(ByteView{zero_op_answer.data(), zero_op_answer.size()},
                       HostOpsSub::Submit, zero_op_resp));
  CHECK(zero_op_resp.result == HostOpsResult::InvalidRequest);

  SubmitRequest max_op = make_submit(1, ByteView{canonical.data(), canonical.size()});
  max_op.operation_id.fill(0xFF);
  const auto max_op_bytes = encode_submit_bytes(max_op);
  const auto max_op_answer =
      transact(world, host, now, 203,
               ByteView{max_op_bytes.data(), max_op_bytes.size()},
               got_error, error_code);
  DispatchReceipt max_op_resp{};
  CHECK(decode_receipt(ByteView{max_op_answer.data(), max_op_answer.size()},
                       HostOpsSub::Submit, max_op_resp));
  CHECK(max_op_resp.result == HostOpsResult::InvalidRequest);

  // SUBMIT onto a SKIP is Conflict at the bridge too — the receipt reports
  // the authoritative Skipped state, not a replay.
  const auto skip = lane_bytes(HostOpsSub::Skip, 1);
  const auto skip_answer =
      transact(world, host, now, 204, ByteView{skip.data(), skip.size()},
               got_error, error_code);
  DispatchReceipt skip_resp{};
  CHECK(decode_receipt(ByteView{skip_answer.data(), skip_answer.size()},
                       HostOpsSub::Skip, skip_resp));
  CHECK(skip_resp.result == HostOpsResult::Ok);
  const auto onto = submit_bytes(1, ByteView{canonical.data(), canonical.size()});
  const auto onto_answer =
      transact(world, host, now, 205, ByteView{onto.data(), onto.size()},
               got_error, error_code);
  DispatchReceipt onto_resp{};
  CHECK(decode_receipt(ByteView{onto_answer.data(), onto_answer.size()},
                       HostOpsSub::Submit, onto_resp));
  CHECK(onto_resp.result == HostOpsResult::Conflict);
  CHECK(onto_resp.state == WindowState::Skipped);

  // ...including the historical edge: an all-zero hash onto the skipped
  // hole is InvalidRequest (reserved), not Existing.
  const auto zeroed_onto =
      transact(world, host, now, 206,
               ByteView{zeroed_bytes.data(), zeroed_bytes.size()},
               got_error, error_code);
  DispatchReceipt zeroed_onto_resp{};
  CHECK(decode_receipt(
      ByteView{zeroed_onto.data(), zeroed_onto.size()}, HostOpsSub::Submit,
      zeroed_onto_resp));
  CHECK(zeroed_onto_resp.result == HostOpsResult::InvalidRequest);

  // Reserved RETIRE `through` values are InvalidRequest, matching the
  // reserved-seq rule on SUBMIT/QUERY/SKIP.
  const auto retire0 = lane_bytes(HostOpsSub::RetireThrough, 0);
  const auto retire0_answer =
      transact(world, host, now, 207, ByteView{retire0.data(), retire0.size()},
               got_error, error_code);
  RetireResponse retire0_resp{};
  CHECK(decode_retire_response(
      ByteView{retire0_answer.data(), retire0_answer.size()}, retire0_resp));
  CHECK(retire0_resp.result == HostOpsResult::InvalidRequest);

  const auto retire_max = lane_bytes(HostOpsSub::RetireThrough, UINT64_MAX);
  const auto retire_max_answer =
      transact(world, host, now, 208,
               ByteView{retire_max.data(), retire_max.size()},
               got_error, error_code);
  RetireResponse retire_max_resp{};
  CHECK(decode_retire_response(
      ByteView{retire_max_answer.data(), retire_max_answer.size()},
      retire_max_resp));
  CHECK(retire_max_resp.result == HostOpsResult::InvalidRequest);
}

void test_bridge_lifetime_clamped_to_ttl() {
  World world;
  HostDriver host;
  MonotonicMs now = 1000;
  CHECK(host_handshake(world, host, now, 0xAAAA, 220) != 0);
  bool got_error = false;
  std::uint16_t error_code = 0;
  const auto canonical = build_canonical();  // ttl 5000

  // A far-future device_deadline (~11 days out) must NOT translate into an
  // unbounded mesh lifetime: the send is capped by the canonical ttl.
  const auto far = submit_bytes(1, ByteView{canonical.data(), canonical.size()},
                                now + 1000000000ULL);
  const auto far_answer =
      transact(world, host, now, 230, ByteView{far.data(), far.size()},
               got_error, error_code);
  DispatchReceipt far_resp{};
  CHECK(decode_receipt(ByteView{far_answer.data(), far_answer.size()},
                       HostOpsSub::Submit, far_resp));
  CHECK(far_resp.result == HostOpsResult::Ok && far_resp.msg_valid);
  bool found = false;
  world.n1.for_each_delivery([&](const DeliverySnapshot& delivery) {
    if (delivery.id.session == far_resp.msg_session &&
        delivery.id.sequence == far_resp.msg_seq) {
      found = true;
      CHECK(delivery.options.lifetime_ms == 5000);
    }
  });
  CHECK(found);

  // A deadline tighter than the ttl wins instead: lifetime = the actual
  // remaining budget.
  const auto near = submit_bytes(2, ByteView{canonical.data(), canonical.size()},
                                 now + 2000);
  const auto near_answer =
      transact(world, host, now, 231, ByteView{near.data(), near.size()},
               got_error, error_code);
  DispatchReceipt near_resp{};
  CHECK(decode_receipt(ByteView{near_answer.data(), near_answer.size()},
                       HostOpsSub::Submit, near_resp));
  CHECK(near_resp.result == HostOpsResult::Ok && near_resp.msg_valid);
  found = false;
  world.n1.for_each_delivery([&](const DeliverySnapshot& delivery) {
    if (delivery.id.session == near_resp.msg_session &&
        delivery.id.sequence == near_resp.msg_seq) {
      found = true;
      CHECK(delivery.options.lifetime_ms == 2000);
    }
  });
  CHECK(found);
}

void test_bridge_mesh_rejected() {
  World world;
  HostDriver host;
  MonotonicMs now = 1000;
  CHECK(host_handshake(world, host, now, 0xBBBB, 240) != 0);
  bool got_error = false;
  std::uint16_t error_code = 0;
  const auto canonical = build_canonical();

  // The mesh delivery table holds 8 live deliveries; fill it via SUBMITs.
  for (std::uint64_t seq = 1; seq <= 8; ++seq) {
    const auto submit =
        submit_bytes(seq, ByteView{canonical.data(), canonical.size()});
    const auto answer =
        transact(world, host, now, 250 + seq,
                 ByteView{submit.data(), submit.size()}, got_error,
                 error_code);
    DispatchReceipt resp{};
    CHECK(decode_receipt(ByteView{answer.data(), answer.size()},
                         HostOpsSub::Submit, resp));
    CHECK(resp.result == HostOpsResult::Ok);
  }

  // The next send is refused by the mesh: honest MeshRejected, and no
  // half-created record — QUERY proves the position stayed empty.
  const auto ninth = submit_bytes(9, ByteView{canonical.data(), canonical.size()});
  const auto ninth_answer =
      transact(world, host, now, 260, ByteView{ninth.data(), ninth.size()},
               got_error, error_code);
  DispatchReceipt ninth_resp{};
  CHECK(decode_receipt(ByteView{ninth_answer.data(), ninth_answer.size()},
                       HostOpsSub::Submit, ninth_resp));
  CHECK(ninth_resp.result == HostOpsResult::MeshRejected);
  CHECK(!ninth_resp.msg_valid);

  const auto query = lane_bytes(HostOpsSub::QueryDispatch, 9);
  const auto query_answer =
      transact(world, host, now, 261, ByteView{query.data(), query.size()},
               got_error, error_code);
  QueryResponse queried{};
  CHECK(decode_query_response(
      ByteView{query_answer.data(), query_answer.size()}, queried));
  CHECK(queried.result == HostOpsResult::NotRetained);

  // A retry of the same seq is still a clean Admit (here it lands expired
  // because its deadline already passed): never a false Conflict.
  const auto retry = submit_bytes(9, ByteView{canonical.data(), canonical.size()},
                                  now);  // deadline == now → Expired
  const auto retry_answer =
      transact(world, host, now, 262, ByteView{retry.data(), retry.size()},
               got_error, error_code);
  DispatchReceipt retry_resp{};
  CHECK(decode_receipt(ByteView{retry_answer.data(), retry_answer.size()},
                       HostOpsSub::Submit, retry_resp));
  CHECK(retry_resp.result == HostOpsResult::Expired);
  CHECK(retry_resp.state == WindowState::Expired);
}

void test_bridge_stale_delivery_event_after_retire() {
  World world;
  HostDriver host;
  MonotonicMs now = 1000;
  CHECK(host_handshake(world, host, now, 0xCCCC, 270) != 0);
  bool got_error = false;
  std::uint16_t error_code = 0;
  const auto canonical = build_canonical();

  const auto submit = submit_bytes(1, ByteView{canonical.data(), canonical.size()});
  const auto answer =
      transact(world, host, now, 280, ByteView{submit.data(), submit.size()},
               got_error, error_code);
  DispatchReceipt receipt{};
  CHECK(decode_receipt(ByteView{answer.data(), answer.size()},
                       HostOpsSub::Submit, receipt));
  CHECK(receipt.result == HostOpsResult::Ok && receipt.msg_valid);

  // Terminate the record via the mesh outcome (suppressed from the legacy
  // event path), then retire the terminal prefix.
  world.bridge.on_delivery(
      DeliveryResult{MessageId{receipt.msg_session, receipt.msg_seq},
                     DeliveryState::Delivered, "END_RECEIVED"});
  world.drain(now);
  world.device_sink.frames.clear();
  const auto retire = lane_bytes(HostOpsSub::RetireThrough, 1);
  const auto retire_answer =
      transact(world, host, now, 281, ByteView{retire.data(), retire.size()},
               got_error, error_code);
  RetireResponse retire_resp{};
  CHECK(decode_retire_response(
      ByteView{retire_answer.data(), retire_answer.size()}, retire_resp));
  CHECK(retire_resp.result == HostOpsResult::Ok);
  CHECK(retire_resp.retired_through == 1);

  // A duplicate outcome arriving after the record is gone has nothing to
  // correlate to: it surfaces as a STALE DeliveryEvent with request=0 so
  // the host can read it as already-retired evidence.
  world.bridge.on_delivery(
      DeliveryResult{MessageId{receipt.msg_session, receipt.msg_seq},
                     DeliveryState::Delivered, "LATE_DUPLICATE"});
  world.drain(now);
  bool stale_event = false;
  for (const auto& record : world.device_sink.frames) {
    if (record.frame.kind != FrameKind::DeliveryEvent) continue;
    std::uint64_t counter = 0;
    ByteView opened{};
    CHECK(open_body(host.proof.key, kDirDeviceToHost, record.frame, counter,
                    opened));
    CHECK(opened.size >= 21);
    CHECK(read_u64(opened.data) == 0);  // retired records have no request id
    stale_event = true;
  }
  CHECK(stale_event);
  world.device_sink.frames.clear();
}

// ------------------------------------------------------------------ Gateway lane (P3)
//
// USB HostOps subcommands 0x10–0x13 (05-wire-api.md §5.6): host
// registration, scope-2 ingress + ACK-after-storage, and unregister —
// plus the schema-2 SUBMIT paths (loopback to this node's ReceiveLog and
// remote sends through the gateway component's origin path).

std::vector<std::uint8_t> register_bytes(std::uint64_t network,
                                         std::uint64_t host_boot,
                                         std::uint32_t lease_ms) {
  const HostRegisterRequest req{network, host_boot, lease_ms};
  std::array<std::uint8_t, kGatewayInnerHeadSize + kHostRegisterRequestPayload>
      out{};
  std::size_t written = 0;
  if (!encode_host_register(req, MutableByteView{out.data(), out.size()},
                            written)) {
    return {};
  }
  return std::vector<std::uint8_t>(out.begin(), out.begin() + written);
}

std::vector<std::uint8_t> unregister_bytes(
    const std::array<std::uint8_t, 16>& token) {
  const HostUnregisterRequest req{token};
  std::array<std::uint8_t,
             kGatewayInnerHeadSize + kHostUnregisterRequestPayload>
      out{};
  std::size_t written = 0;
  if (!encode_host_unregister(req, MutableByteView{out.data(), out.size()},
                              written)) {
    return {};
  }
  return std::vector<std::uint8_t>(out.begin(), out.begin() + written);
}

std::vector<std::uint8_t> ingress_ack_bytes(
    const GatewayIngress& ingress, const std::array<std::uint8_t, 16>& token,
    const GatewayOpsResult outcome) {
  const GatewayIngressAck ack{token,
                              ingress.ref_origin,
                              ingress.ref_session,
                              ingress.ref_sequence,
                              ingress.request_digest,
                              static_cast<std::uint16_t>(outcome)};
  std::array<std::uint8_t, kGatewayInnerHeadSize + kGatewayIngressAckPayload>
      out{};
  std::size_t written = 0;
  if (!encode_gateway_ingress_ack(
          ack, MutableByteView{out.data(), out.size()}, written)) {
    return {};
  }
  return std::vector<std::uint8_t>(out.begin(), out.begin() + written);
}

using Token16 = std::array<std::uint8_t, 16>;

// Every sealed HostOps frame the device emitted since the last clear,
// opened and paired with its wire request id — device-issued 0x11s arrive
// on THEIR OWN request ids, which the host echoes in its 0x12/0x13.
struct DeviceFrame {
  std::uint64_t request;
  std::vector<std::uint8_t> body;
};

std::vector<DeviceFrame> collect_host_ops(World& world, HostDriver& host) {
  std::vector<DeviceFrame> out;
  for (const auto& record : world.device_sink.frames) {
    if (record.frame.kind != FrameKind::HostOps) continue;
    std::uint64_t counter = 0;
    ByteView opened{};
    if (!open_body(host.proof.key, kDirDeviceToHost, record.frame, counter,
                   opened)) {
      continue;
    }
    out.push_back(DeviceFrame{
        record.frame.request,
        std::vector<std::uint8_t>(opened.data, opened.data + opened.size)});
  }
  world.device_sink.frames.clear();
  return out;
}

// The frame carrying sub `sub` (inner[1]), or nullptr — a submit
// transaction emits BOTH the receipt and any device-issued 0x11, so the
// sub byte is the only honest discriminator.
const DeviceFrame* find_sub(const std::vector<DeviceFrame>& frames,
                            const std::uint8_t sub) {
  for (const auto& frame : frames) {
    if (frame.body.size() > 1 && frame.body[1] == sub) return &frame;
  }
  return nullptr;
}

// feed + drain + collect: the exchange primitive for lanes that emit
// more than one HostOps frame per request.
std::vector<DeviceFrame> exchange(World& world, HostDriver& host,
                                  MonotonicMs& now, std::uint64_t request,
                                  ByteView inner) {
  world.feed(host.sealed(FrameKind::HostOps, request, inner), now);
  world.drain(now);
  now += 200;
  return collect_host_ops(world, host);
}

// The bridge wired as the gateway endpoint: cap bit 3 advertised, the
// component attached (registration + loopback sink + origin path), and a
// second gateway on n2 for remote-send coverage.
struct GatewayWorld : World {
  GatewayDelivery gateway1;
  GatewayDelivery gateway2;
  struct Sink2 final : GatewayHostSink {
    bool ready{false};
    HostBinding binding{};
    std::vector<MessageKey> ingresses;
    bool host_ready(HostBinding& out) noexcept override {
      out = binding;
      return ready;
    }
    Status host_ingress(const MessageKey& key, const RequestDigest&, ByteView,
                        ByteView, MonotonicMs) noexcept override {
      ingresses.push_back(key);
      return Status::success();
    }
  } sink2;

  GatewayWorld()
      : World(0x3 | kCapHostOpsV1 | kCapGatewayEndpointV1),
        gateway1(n1),
        gateway2(n2) {
    if (!bridge.attach_gateway(gateway1).ok()) {
      std::fprintf(stderr, "attach_gateway failed\n");
      ++failures;
    }
    gateway2.attach();  // n2's node needs its gateway sink for wire frames
    GatewayRoleConfig role{};
    role.gateway_boot = 0x2222;
    role.capabilities = kGatewayCapHostReceive;
    role.host_sink = &sink2;
    if (!gateway2.enable_gateway(role).ok()) {
      std::fprintf(stderr, "enable_gateway(n2) failed\n");
      ++failures;
    }
    sink2.ready = true;
  }

  // Pump both mesh nodes and the radio queue alongside the USB pump —
  // resolves, service frames and receipts all ride the sim.
  void run_mesh(MonotonicMs& now, MonotonicMs ms) {
    const MonotonicMs end = now + ms;
    for (; now <= end; now += 5) {
      n1.poll(now);
      n2.poll(now);
      net.flush(now);
      bridge.poll(now);
      const auto bytes = stream.take();
      if (!bytes.empty()) {
        device_decoder.push(ByteView{bytes.data(), bytes.size()}, now);
      }
    }
  }
};

void test_gateway_inner_codecs() {
  // 0x10 roundtrip: exact wire shape, strict payload_len.
  const HostRegisterRequest reg{7, 0x11223344, 15000};
  std::array<std::uint8_t, 256> buf{};
  std::size_t written = 0;
  CHECK(encode_host_register(reg, MutableByteView{buf.data(), buf.size()},
                             written));
  CHECK(written == kGatewayInnerHeadSize + kHostRegisterRequestPayload);
  CHECK(buf[0] == 1 && buf[1] == static_cast<std::uint8_t>(HostOpsSub::HostRegister));
  HostRegisterRequest reg_dec{};
  CHECK(decode_host_register(ByteView{buf.data(), written}, reg_dec));
  CHECK(reg_dec.network == 7 && reg_dec.host_boot == 0x11223344 &&
        reg_dec.lease_ms == 15000);
  HostRegisterRequest bad{};
  CHECK(!decode_host_register(ByteView{buf.data(), written - 1}, bad));
  std::array<std::uint8_t, 256> wrong_sub = buf;
  wrong_sub[1] = static_cast<std::uint8_t>(HostOpsSub::HostUnregister);
  CHECK(!decode_host_register(ByteView{wrong_sub.data(), written}, bad));

  const HostRegisterResponse reg_resp{
      static_cast<std::uint16_t>(GatewayOpsResult::Ok),
      std::array<std::uint8_t, 16>{0xAA},
      0xB0071D0001ULL,
      std::array<std::uint8_t, 32>{0x55},
      15000};
  CHECK(encode_host_register_response(
      reg_resp, MutableByteView{buf.data(), buf.size()}, written));
  CHECK(written == kGatewayInnerHeadSize + kHostRegisterResponsePayload);
  HostRegisterResponse reg_resp_dec{};
  CHECK(decode_host_register_response(ByteView{buf.data(), written},
                                      reg_resp_dec));
  CHECK(reg_resp_dec.result == static_cast<std::uint16_t>(GatewayOpsResult::Ok));
  CHECK(reg_resp_dec.gateway_boot == 0xB0071D0001ULL &&
        reg_resp_dec.lease_ms == 15000);

  // 0x11 roundtrip at both payload bounds (0 and 96).
  for (const std::size_t plen : {std::size_t{0}, std::size_t{96}}) {
    GatewayIngress ingress{};
    ingress.submit_prefix[0] = 1;
    ingress.submit_prefix[1] = 3;
    ingress.submit_prefix[2] = 2;
    ingress.ref_origin = 0x0abc;
    ingress.ref_session = 77;
    ingress.ref_sequence = 0x0102;
    ingress.request_digest = test_hash(0x40);
    std::vector<std::uint8_t> payload(plen, 0x5A);
    ingress.payload = ByteView{payload.data(), payload.size()};
    CHECK(encode_gateway_ingress(
        ingress, MutableByteView{buf.data(), buf.size()}, written));
    CHECK(written == kGatewayInnerHeadSize + kGatewayIngressFixedPayload + plen);
    GatewayIngress dec{};
    CHECK(decode_gateway_ingress(ByteView{buf.data(), written}, dec));
    CHECK(dec.ref_origin == 0x0abc && dec.ref_session == 77 &&
          dec.ref_sequence == 0x0102);
    CHECK(dec.payload.size == plen);
    // 97 bytes never encodes — the cap is enforced before the wire.
    std::vector<std::uint8_t> over(97, 1);
    ingress.payload = ByteView{over.data(), over.size()};
    CHECK(!encode_gateway_ingress(
        ingress, MutableByteView{buf.data(), buf.size()}, written));
  }

  // 0x12 / 0x13 roundtrips.
  const GatewayIngressAck ack{std::array<std::uint8_t, 16>{0x11},
                              0x0abc,
                              77,
                              0x0102,
                              test_hash(0x40),
                              static_cast<std::uint16_t>(GatewayOpsResult::Ok)};
  CHECK(encode_gateway_ingress_ack(
      ack, MutableByteView{buf.data(), buf.size()}, written));
  CHECK(written == kGatewayInnerHeadSize + kGatewayIngressAckPayload);
  GatewayIngressAck ack_dec{};
  CHECK(decode_gateway_ingress_ack(ByteView{buf.data(), written}, ack_dec));
  CHECK(ack_dec.outcome == static_cast<std::uint16_t>(GatewayOpsResult::Ok));
  CHECK(ack_dec.ref_origin == 0x0abc && ack_dec.ref_sequence == 0x0102);
  // An outcome value outside the enum never decodes as a named result.
  buf[written - 1] = 0x7F;
  buf[written - 2] = 0x7F;
  CHECK(!decode_gateway_ingress_ack(ByteView{buf.data(), written}, ack_dec));

  const HostUnregisterRequest unreg{std::array<std::uint8_t, 16>{0x33}};
  CHECK(encode_host_unregister(unreg,
                               MutableByteView{buf.data(), buf.size()}, written));
  CHECK(written == kGatewayInnerHeadSize + kHostUnregisterRequestPayload);
  HostUnregisterRequest unreg_dec{};
  CHECK(decode_host_unregister(ByteView{buf.data(), written}, unreg_dec));
  CHECK(unreg_dec.token == Token16{0x33});

  const HostUnregisterResponse unreg_resp{
      static_cast<std::uint16_t>(GatewayOpsResult::Stale)};
  CHECK(encode_host_unregister_response(
      unreg_resp, MutableByteView{buf.data(), buf.size()}, written));
  CHECK(written == kGatewayInnerHeadSize + kHostUnregisterResponsePayload);
  HostUnregisterResponse unreg_resp_dec{};
  CHECK(decode_host_unregister_response(ByteView{buf.data(), written},
                                        unreg_resp_dec));
  CHECK(unreg_resp_dec.result ==
        static_cast<std::uint16_t>(GatewayOpsResult::Stale));
}

// 0x10 happy path + every honest refusal shape.
void test_bridge_gateway_register() {
  GatewayWorld world;
  HostDriver host;
  MonotonicMs now = 1000;
  CHECK(host_handshake(world, host, now, 0x1111, 10) != 0);
  bool got_error = false;
  std::uint16_t error_code = 0;

  const auto answer =
      transact(world, host, now, 60,
               ByteView{register_bytes(7, 0x99, 15000).data(),
                        kGatewayInnerHeadSize + kHostRegisterRequestPayload},
               got_error, error_code);
  HostRegisterResponse reg{};
  CHECK(decode_host_register_response(ByteView{answer.data(), answer.size()},
                                      reg));
  CHECK(reg.result == static_cast<std::uint16_t>(GatewayOpsResult::Ok));
  CHECK(reg.gateway_boot == 0xB0071D0001ULL);
  CHECK(reg.lease_ms == 15000);
  CHECK(reg.token != Token16{});
  // host_digest = SHA-256("host-operator") — the principal the transcript
  // bound, never a client-declared value.
  HostDigest expected_digest{};
  sha256(ByteView{reinterpret_cast<const std::uint8_t*>("host-operator"), 13},
         expected_digest);
  CHECK(reg.host_digest == expected_digest);

  // Renewal on the same session + host boot keeps the token.
  const auto renew =
      transact(world, host, now, 61,
               ByteView{register_bytes(7, 0x99, 15000).data(),
                        kGatewayInnerHeadSize + kHostRegisterRequestPayload},
               got_error, error_code);
  HostRegisterResponse reg2{};
  CHECK(decode_host_register_response(ByteView{renew.data(), renew.size()},
                                      reg2));
  CHECK(reg2.result == static_cast<std::uint16_t>(GatewayOpsResult::Ok));
  CHECK(reg2.token == reg.token);

  // Wrong network is DENIED — the registration binds the authenticated
  // session's network, not a requested one.
  const auto foreign =
      transact(world, host, now, 62,
               ByteView{register_bytes(9, 0x99, 15000).data(),
                        kGatewayInnerHeadSize + kHostRegisterRequestPayload},
               got_error, error_code);
  HostRegisterResponse denied{};
  CHECK(decode_host_register_response(ByteView{foreign.data(), foreign.size()},
                                      denied));
  CHECK(denied.result == static_cast<std::uint16_t>(GatewayOpsResult::Denied));

  // Reserved host_boot and insane leases are INVALID.
  for (const auto& body : {register_bytes(7, 0, 15000),
                           register_bytes(7, UINT64_MAX, 15000),
                           register_bytes(7, 0x99, 0),
                           register_bytes(7, 0x99, 60001)}) {
    const auto refused =
        transact(world, host, now, 63, ByteView{body.data(), body.size()},
                 got_error, error_code);
    HostRegisterResponse invalid{};
    CHECK(decode_host_register_response(
        ByteView{refused.data(), refused.size()}, invalid));
    CHECK(invalid.result == static_cast<std::uint16_t>(GatewayOpsResult::Invalid));
  }

  // A malformed inner gets a protocol error, never a response payload.
  const std::array<std::uint8_t, 4> malformed{{1, 0x10, 0, 1}};
  const auto error_answer =
      transact(world, host, now, 64,
               ByteView{malformed.data(), malformed.size()}, got_error,
               error_code);
  CHECK(got_error);
}

// 0x10/0x11 without the endpoint capability or a live session is refused,
// never silently served.
void test_bridge_gateway_unsupported() {
  World world(0x3 | kCapHostOpsV1);  // no cap bit 3, no component
  HostDriver host;
  MonotonicMs now = 1000;
  CHECK(host_handshake(world, host, now, 0x1111, 10) != 0);
  bool got_error = false;
  std::uint16_t error_code = 0;
  const auto body = register_bytes(7, 0x99, 15000);
  const auto answer =
      transact(world, host, now, 60, ByteView{body.data(), body.size()},
               got_error, error_code);
  HostRegisterResponse reg{};
  CHECK(decode_host_register_response(ByteView{answer.data(), answer.size()},
                                      reg));
  CHECK(reg.result ==
        static_cast<std::uint16_t>(GatewayOpsResult::Unsupported));
  const auto unreg_body = unregister_bytes(Token16{0x11});
  const auto unreg_answer =
      transact(world, host, now, 61,
               ByteView{unreg_body.data(), unreg_body.size()}, got_error,
               error_code);
  HostUnregisterResponse unreg{};
  CHECK(decode_host_unregister_response(
      ByteView{unreg_answer.data(), unreg_answer.size()}, unreg));
  CHECK(unreg.result ==
        static_cast<std::uint16_t>(GatewayOpsResult::Unsupported));
}

// Loopback: schema-2 SUBMIT to this node — the payload goes straight into
// the session's ingress lane; the host's 0x12 completes the record with
// HOST_RAM_RECEIVED evidence, and only after the ACK.
void test_bridge_gateway_loopback() {
  GatewayWorld world;
  HostDriver host;
  MonotonicMs now = 1000;
  CHECK(host_handshake(world, host, now, 0x1111, 10) != 0);
  bool got_error = false;
  std::uint16_t error_code = 0;

  // Register the host endpoint first — the token binds this session.
  const auto reg_body = register_bytes(7, 0x99, 15000);
  const auto reg_answer =
      transact(world, host, now, 60, ByteView{reg_body.data(), reg_body.size()},
               got_error, error_code);
  HostRegisterResponse reg{};
  CHECK(decode_host_register_response(
      ByteView{reg_answer.data(), reg_answer.size()}, reg));
  CHECK(reg.result == static_cast<std::uint16_t>(GatewayOpsResult::Ok));

  const std::array<std::uint8_t, 4> payload{{0xDE, 0xAD, 0xBE, 0xEF}};
  const auto canonical =
      build_canonical_v2(7, 1, 2, reg.token, 0xB0071D0001ULL, 1, 1, 5000,
                         ByteView{payload.data(), payload.size()});
  const auto submit =
      submit_bytes(1, ByteView{canonical.data(), canonical.size()}, now + 8000);
  // One SUBMIT emits TWO device frames: the 0x11 ingress (its own request
  // id) and the 0x01 receipt — pick each by its sub byte.
  const auto frames = exchange(world, host, now, 61,
                               ByteView{submit.data(), submit.size()});
  const DeviceFrame* receipt_frame =
      find_sub(frames, static_cast<std::uint8_t>(HostOpsSub::Submit));
  const DeviceFrame* ingress_frame =
      find_sub(frames, static_cast<std::uint8_t>(HostOpsSub::GatewayIngress));
  CHECK(receipt_frame != nullptr);
  CHECK(ingress_frame != nullptr);
  DispatchReceipt receipt{};
  CHECK(decode_receipt(
      ByteView{receipt_frame->body.data(), receipt_frame->body.size()},
      HostOpsSub::Submit, receipt));
  CHECK(receipt.result == HostOpsResult::Ok);
  CHECK(receipt.state == WindowState::Sent);
  CHECK(receipt.msg_valid);
  CHECK(receipt.evidence == DispatchWindow::Evidence::GatewayAccepted);

  // The device-issued 0x11 rides its own request id; the host answers on it.
  CHECK(ingress_frame->body.size() ==
        kGatewayInnerHeadSize + kGatewayIngressFixedPayload + payload.size());
  GatewayIngress ingress{};
  CHECK(decode_gateway_ingress(
      ByteView{ingress_frame->body.data(), ingress_frame->body.size()},
      ingress));
  // Prefix shape: ver1 / ServiceSubmit3 / scope2 / token16 / boot8 /
  // plen2 / reserved2 — the digest commits to exactly these bytes.
  CHECK(ingress.submit_prefix[0] == 1 && ingress.submit_prefix[1] == 3);
  CHECK(ingress.submit_prefix[2] == 2);
  CHECK(std::memcmp(ingress.submit_prefix.data() + 4, reg.token.data(), 16) ==
        0);
  std::uint64_t prefix_boot = 0;
  for (int i = 0; i < 8; ++i) {
    prefix_boot = (prefix_boot << 8U) | ingress.submit_prefix[20 + i];
  }
  CHECK(prefix_boot == 0xB0071D0001ULL);
  const std::uint16_t prefix_len =
      static_cast<std::uint16_t>((ingress.submit_prefix[28] << 8U) |
                               ingress.submit_prefix[29]);
  CHECK(prefix_len == payload.size());
  CHECK(ingress.ref_origin == 1);          // this node mints the loopback key
  CHECK(ingress.ref_session == receipt.msg_session);
  CHECK(ingress.ref_sequence == receipt.msg_seq);
  CHECK(ingress.payload.size == payload.size());
  // request_digest = SHA-256(prefix || payload) — recomputed, not trusted.
  std::array<std::uint8_t, 36> digest_input{};
  std::memcpy(digest_input.data(), ingress.submit_prefix.data(), 32);
  std::memcpy(digest_input.data() + 32, payload.data(), payload.size());
  RequestDigest expected_digest{};
  sha256(ByteView{digest_input.data(), digest_input.size()}, expected_digest);
  CHECK(ingress.request_digest == expected_digest);

  // No ACK yet: the position stays Sent (the host never claimed storage).
  const auto pending_query = lane_bytes(HostOpsSub::QueryDispatch, 1);
  const auto pending_answer =
      transact(world, host, now, 62,
               ByteView{pending_query.data(), pending_query.size()},
               got_error, error_code);
  QueryResponse pending{};
  CHECK(decode_query_response(
      ByteView{pending_answer.data(), pending_answer.size()}, pending));
  CHECK(pending.state == WindowState::Sent);

  // A wrong-digest ACK is not evidence: errors counted, slot stays armed.
  GatewayIngressAck forged{reg.token,
                           ingress.ref_origin,
                           ingress.ref_session,
                           ingress.ref_sequence,
                           test_hash(0x66),
                           static_cast<std::uint16_t>(GatewayOpsResult::Ok)};
  std::array<std::uint8_t, kGatewayInnerHeadSize + kGatewayIngressAckPayload>
      forged_body{};
  std::size_t forged_size = 0;
  CHECK(encode_gateway_ingress_ack(
      forged, MutableByteView{forged_body.data(), forged_body.size()},
      forged_size));
  const auto rx_errors_before = world.bridge.stats().rx_errors;
  world.feed(host.sealed(FrameKind::HostOps, ingress_frame->request,
                         ByteView{forged_body.data(), forged_size}),
             now);
  world.drain(now);
  CHECK(world.bridge.stats().rx_errors > rx_errors_before);
  collect_host_ops(world, host);

  // The honest 0x12 completes the record: Delivered + HostRamReceived.
  const auto ack_body =
      ingress_ack_bytes(ingress, reg.token, GatewayOpsResult::Ok);
  world.feed(host.sealed(FrameKind::HostOps, ingress_frame->request,
                         ByteView{ack_body.data(), ack_body.size()}),
             now);
  world.drain(now);
  collect_host_ops(world, host);
  const auto done_query = lane_bytes(HostOpsSub::QueryDispatch, 1);
  const auto done_answer =
      transact(world, host, now, 63,
               ByteView{done_query.data(), done_query.size()}, got_error,
               error_code);
  QueryResponse done{};
  CHECK(decode_query_response(ByteView{done_answer.data(), done_answer.size()},
                              done));
  CHECK(done.result == HostOpsResult::Ok);
  CHECK(done.state == WindowState::Delivered);
  CHECK(done.evidence == DispatchWindow::Evidence::HostRamReceived);

  // A stale-token SUBMIT is refused as InvalidRequest — never rebound.
  const auto stale_canonical = build_canonical_v2(
      7, 1, 2, std::array<std::uint8_t, 16>{0x77}, 0xB0071D0001ULL, 1, 1,
      5000, ByteView{payload.data(), payload.size()});
  const auto stale_submit = submit_bytes(
      2, ByteView{stale_canonical.data(), stale_canonical.size()}, now + 8000);
  const auto stale_answer =
      transact(world, host, now, 64,
               ByteView{stale_submit.data(), stale_submit.size()}, got_error,
               error_code);
  DispatchReceipt stale_receipt{};
  CHECK(decode_receipt(ByteView{stale_answer.data(), stale_answer.size()},
                       HostOpsSub::Submit, stale_receipt));
  CHECK(stale_receipt.result == HostOpsResult::InvalidRequest);
}

// ACK loss: the pending ingress is resent ONCE inside the 5s window —
// the host dedups on the bound MessageKey (G03) — never a third emit.
// Past the registration lease a schema-2 submit is refused (G05).
void test_bridge_gateway_ingress_resend_and_lease() {
  GatewayWorld world;
  HostDriver host;
  MonotonicMs now = 1000;
  CHECK(host_handshake(world, host, now, 0x1111, 10) != 0);
  bool got_error = false;
  std::uint16_t error_code = 0;
  const auto reg_body = register_bytes(7, 0x99, 15000);
  const auto reg_answer =
      transact(world, host, now, 60, ByteView{reg_body.data(), reg_body.size()},
               got_error, error_code);
  HostRegisterResponse reg{};
  CHECK(decode_host_register_response(
      ByteView{reg_answer.data(), reg_answer.size()}, reg));

  const std::array<std::uint8_t, 3> payload{{5, 6, 7}};
  const auto canonical =
      build_canonical_v2(7, 1, 2, reg.token, 0xB0071D0001ULL, 1, 1, 5000,
                         ByteView{payload.data(), payload.size()});
  const auto submit =
      submit_bytes(1, ByteView{canonical.data(), canonical.size()}, now + 8000);
  const auto frames = exchange(world, host, now, 61,
                               ByteView{submit.data(), submit.size()});
  const DeviceFrame* ingress_frame =
      find_sub(frames, static_cast<std::uint8_t>(HostOpsSub::GatewayIngress));
  CHECK(ingress_frame != nullptr);
  if (ingress_frame == nullptr) return;
  const std::uint64_t ingress_request = ingress_frame->request;
  GatewayIngress ingress{};
  CHECK(decode_gateway_ingress(
      ByteView{ingress_frame->body.data(), ingress_frame->body.size()},
      ingress));

  // Inside the window with no 0x12: exactly one resend on the same id.
  now += 1300;  // past the 1200ms resend mark
  world.drain(now);
  const auto resends = collect_host_ops(world, host);
  const DeviceFrame* resent =
      find_sub(resends, static_cast<std::uint8_t>(HostOpsSub::GatewayIngress));
  CHECK(resent != nullptr);
  if (resent != nullptr) {
    CHECK(resent->request == ingress_request);
    CHECK(resent->body == ingress_frame->body);
  }
  // A second wait inside the window emits nothing — the retry is bounded.
  now += 1300;
  world.drain(now);
  const auto none = collect_host_ops(world, host);
  CHECK(find_sub(none, static_cast<std::uint8_t>(HostOpsSub::GatewayIngress)) ==
        nullptr);

  // The real ACK still lands inside the window: Delivered stands.
  const auto ack_body =
      ingress_ack_bytes(ingress, reg.token, GatewayOpsResult::Ok);
  world.feed(host.sealed(FrameKind::HostOps, ingress_request,
                         ByteView{ack_body.data(), ack_body.size()}),
             now);
  world.drain(now);
  collect_host_ops(world, host);
  const auto done_query = lane_bytes(HostOpsSub::QueryDispatch, 1);
  const auto done_answer =
      transact(world, host, now, 62,
               ByteView{done_query.data(), done_query.size()}, got_error,
               error_code);
  QueryResponse done{};
  CHECK(decode_query_response(ByteView{done_answer.data(), done_answer.size()},
                              done));
  CHECK(done.state == WindowState::Delivered);
  CHECK(done.evidence == DispatchWindow::Evidence::HostRamReceived);

  // Lease expiry: the registration granted 15s — a submit after it is
  // refused InvalidRequest even though the token string still matches.
  now += 16000;
  const auto expired_submit = submit_bytes(
      2, ByteView{canonical.data(), canonical.size()}, now + 8000);
  const auto expired_answer =
      transact(world, host, now, 63,
               ByteView{expired_submit.data(), expired_submit.size()},
               got_error, error_code);
  DispatchReceipt expired{};
  CHECK(decode_receipt(ByteView{expired_answer.data(), expired_answer.size()},
                       HostOpsSub::Submit, expired));
  CHECK(expired.result == HostOpsResult::InvalidRequest);
}

// Scope-2 remote send while the destination's host is down (G02): the
// resolve can never name a live endpoint, the send ends Failed — never a
// Delivered claim on gateway reachability alone.
void test_bridge_gateway_host_down() {
  GatewayWorld world;
  HostDriver host;
  MonotonicMs now = 1000;
  world.sink2.ready = false;  // host stopped before the send
  CHECK(host_handshake(world, host, now, 0x1111, 10) != 0);
  bool got_error = false;
  std::uint16_t error_code = 0;
  const auto reg_body = register_bytes(7, 0x99, 15000);
  const auto reg_answer =
      transact(world, host, now, 60, ByteView{reg_body.data(), reg_body.size()},
               got_error, error_code);
  HostRegisterResponse reg{};
  CHECK(decode_host_register_response(
      ByteView{reg_answer.data(), reg_answer.size()}, reg));
  world.sink2.binding.principal_digest = reg.host_digest;
  world.sink2.binding.host_boot = 0x99;

  const std::array<std::uint8_t, 2> payload{{1, 2}};
  const auto canonical =
      build_canonical_v2(7, 2, 2, reg.token, 0xB0071D0001ULL, 1, 1, 8000,
                         ByteView{payload.data(), payload.size()});
  const auto submit =
      submit_bytes(1, ByteView{canonical.data(), canonical.size()}, now + 8000);
  const auto submit_answer =
      transact(world, host, now, 61,
               ByteView{submit.data(), submit.size()}, got_error, error_code);
  DispatchReceipt receipt{};
  CHECK(decode_receipt(ByteView{submit_answer.data(), submit_answer.size()},
                       HostOpsSub::Submit, receipt));
  CHECK(receipt.result == HostOpsResult::Ok);
  CHECK(receipt.state == WindowState::Sent);

  // Drive past the resolve budget: the endpoint never becomes Ready.
  for (int i = 0; i < 60; ++i) world.run_mesh(now, 100);
  CHECK(world.sink2.ingresses.empty());
  const auto done_query = lane_bytes(HostOpsSub::QueryDispatch, 1);
  const auto done_answer =
      transact(world, host, now, 62,
               ByteView{done_query.data(), done_query.size()}, got_error,
               error_code);
  QueryResponse done{};
  CHECK(decode_query_response(ByteView{done_answer.data(), done_answer.size()},
                              done));
  CHECK(done.result == HostOpsResult::Ok);
  CHECK(done.state == WindowState::Failed);
}

// Pending-ingress capacity is honest: the 9th loopback send inside the
// ack window is refused MeshRejected, never silently queued.
void test_bridge_gateway_ingress_busy() {
  GatewayWorld world;
  HostDriver host;
  MonotonicMs now = 1000;
  CHECK(host_handshake(world, host, now, 0x1111, 10) != 0);
  bool got_error = false;
  std::uint16_t error_code = 0;
  const auto reg_body = register_bytes(7, 0x99, 15000);
  const auto reg_answer =
      transact(world, host, now, 60, ByteView{reg_body.data(), reg_body.size()},
               got_error, error_code);
  HostRegisterResponse reg{};
  CHECK(decode_host_register_response(
      ByteView{reg_answer.data(), reg_answer.size()}, reg));

  const std::array<std::uint8_t, 2> payload{{1, 2}};
  std::set<std::uint64_t> ingress_requests;
  std::uint64_t seq = 0;
  for (; seq < 8; ++seq) {
    const auto canonical =
        build_canonical_v2(7, 1, 2, reg.token, 0xB0071D0001ULL, 1, 1, 5000,
                           ByteView{payload.data(), payload.size()});
    const auto submit = submit_bytes(
        seq + 1, ByteView{canonical.data(), canonical.size()}, now + 8000);
    const auto frames =
        exchange(world, host, now, 70 + seq,
                 ByteView{submit.data(), submit.size()});
    const DeviceFrame* receipt_frame =
        find_sub(frames, static_cast<std::uint8_t>(HostOpsSub::Submit));
    CHECK(receipt_frame != nullptr);
    DispatchReceipt receipt{};
    CHECK(decode_receipt(
        ByteView{receipt_frame->body.data(), receipt_frame->body.size()},
        HostOpsSub::Submit, receipt));
    CHECK(receipt.result == HostOpsResult::Ok);
    // Each accepted loopback occupies a pending-ingress slot (the 0x11 is
    // out but no 0x12 ever arrives) — 8 fills the lane. Its resend inside
    // the ack window reuses the same request id.
    const DeviceFrame* ingress_frame = find_sub(
        frames, static_cast<std::uint8_t>(HostOpsSub::GatewayIngress));
    CHECK(ingress_frame != nullptr);
    if (ingress_frame != nullptr) {
      ingress_requests.insert(ingress_frame->request);
    }
  }
  const auto canonical =
      build_canonical_v2(7, 1, 2, reg.token, 0xB0071D0001ULL, 1, 1, 5000,
                         ByteView{payload.data(), payload.size()});
  const auto submit = submit_bytes(
      seq + 1, ByteView{canonical.data(), canonical.size()}, now + 8000);
  const auto frames = exchange(world, host, now, 90,
                               ByteView{submit.data(), submit.size()});
  const DeviceFrame* busy_frame =
      find_sub(frames, static_cast<std::uint8_t>(HostOpsSub::Submit));
  CHECK(busy_frame != nullptr);
  DispatchReceipt busy{};
  CHECK(decode_receipt(
      ByteView{busy_frame->body.data(), busy_frame->body.size()},
      HostOpsSub::Submit, busy));
  CHECK(busy.result == HostOpsResult::MeshRejected);
  // Capacity refusal is honest: any 0x11 on the wire now is a resend of an
  // already-occupied slot, never a ninth queued ingress.
  for (const DeviceFrame& frame : frames) {
    if (frame.body.size() > 1 &&
        frame.body[1] ==
            static_cast<std::uint8_t>(HostOpsSub::GatewayIngress)) {
      CHECK(ingress_requests.count(frame.request) == 1);
    }
  }
}

// Remote scope-2 send: schema-2 SUBMIT to n2's gateway — the bridge
// resolves through its own component, the sim delivers the service frame,
// n2's host sink stores, and the wire receipt completes the window record
// as Delivered with HOST_RAM_RECEIVED evidence.
void test_bridge_gateway_remote_send() {
  GatewayWorld world;
  HostDriver host;
  MonotonicMs now = 1000;
  CHECK(host_handshake(world, host, now, 0x1111, 10) != 0);
  bool got_error = false;
  std::uint16_t error_code = 0;
  const auto reg_body = register_bytes(7, 0x99, 15000);
  const auto reg_answer =
      transact(world, host, now, 60, ByteView{reg_body.data(), reg_body.size()},
               got_error, error_code);
  HostRegisterResponse reg{};
  CHECK(decode_host_register_response(
      ByteView{reg_answer.data(), reg_answer.size()}, reg));
  CHECK(reg.result == static_cast<std::uint16_t>(GatewayOpsResult::Ok));
  // Same-principal delivery: the remote sink must report OUR principal
  // digest for the scope-2 endpoint to resolve.
  world.sink2.binding.principal_digest = reg.host_digest;
  world.sink2.binding.host_boot = 0x99;
  world.sink2.binding.usb_session = host.session;

  const std::array<std::uint8_t, 4> payload{{9, 8, 7, 6}};
  const auto canonical =
      build_canonical_v2(7, 2, 2, reg.token, 0xB0071D0001ULL, 1, 1, 8000,
                         ByteView{payload.data(), payload.size()});
  const auto submit =
      submit_bytes(1, ByteView{canonical.data(), canonical.size()}, now + 8000);
  const auto submit_answer =
      transact(world, host, now, 61,
               ByteView{submit.data(), submit.size()}, got_error, error_code);
  DispatchReceipt receipt{};
  CHECK(decode_receipt(ByteView{submit_answer.data(), submit_answer.size()},
                       HostOpsSub::Submit, receipt));
  CHECK(receipt.result == HostOpsResult::Ok);
  CHECK(receipt.state == WindowState::Sent);
  CHECK(receipt.evidence == DispatchWindow::Evidence::GatewayAccepted);

  // Drive the mesh until n2's sink receives the scope-2 submit.
  for (int i = 0; i < 40 && world.sink2.ingresses.empty(); ++i) {
    world.run_mesh(now, 100);
  }
  CHECK(world.sink2.ingresses.size() == 1);
  // The wire MessageKey is bound into the window record by the send pump.
  const auto bound_query = lane_bytes(HostOpsSub::QueryDispatch, 1);
  const auto bound_answer =
      transact(world, host, now, 62,
               ByteView{bound_query.data(), bound_query.size()}, got_error,
               error_code);
  QueryResponse bound{};
  CHECK(decode_query_response(
      ByteView{bound_answer.data(), bound_answer.size()}, bound));
  CHECK(bound.state == WindowState::Sent);
  CHECK(bound.msg_valid);

  // The remote host's storage ACK is what completes the record — the
  // Service Receipt flows back over the mesh, not over USB.
  world.gateway2.on_host_ingress_ack(world.sink2.ingresses.back(),
                                     /*stored=*/true, now);
  for (int i = 0; i < 40; ++i) world.run_mesh(now, 100);
  const auto done_query = lane_bytes(HostOpsSub::QueryDispatch, 1);
  const auto done_answer =
      transact(world, host, now, 63,
               ByteView{done_query.data(), done_query.size()}, got_error,
               error_code);
  QueryResponse done{};
  CHECK(decode_query_response(ByteView{done_answer.data(), done_answer.size()},
                              done));
  CHECK(done.result == HostOpsResult::Ok);
  CHECK(done.state == WindowState::Delivered);
  CHECK(done.evidence == DispatchWindow::Evidence::HostRamReceived);
}

// 0x13: only the live token releases the registration — a stale token is
// refused and the binding survives.
void test_bridge_gateway_unregister() {
  GatewayWorld world;
  HostDriver host;
  MonotonicMs now = 1000;
  CHECK(host_handshake(world, host, now, 0x1111, 10) != 0);
  bool got_error = false;
  std::uint16_t error_code = 0;
  const auto reg_body = register_bytes(7, 0x99, 15000);
  const auto reg_answer =
      transact(world, host, now, 60, ByteView{reg_body.data(), reg_body.size()},
               got_error, error_code);
  HostRegisterResponse reg{};
  CHECK(decode_host_register_response(
      ByteView{reg_answer.data(), reg_answer.size()}, reg));

  // Foreign token → Stale, registration untouched.
  const auto stale_body = unregister_bytes(Token16{0x77});
  const auto stale_answer =
      transact(world, host, now, 61,
               ByteView{stale_body.data(), stale_body.size()}, got_error,
               error_code);
  HostUnregisterResponse stale{};
  CHECK(decode_host_unregister_response(
      ByteView{stale_answer.data(), stale_answer.size()}, stale));
  CHECK(stale.result == static_cast<std::uint16_t>(GatewayOpsResult::Stale));
  HostBinding bound{};
  CHECK(world.bridge.host_ready(bound));

  // Live token → Ok, the endpoint is gone: the component's readiness
  // check now fails, and new schema-2 submits are refused.
  const auto unreg_body = unregister_bytes(reg.token);
  const auto unreg_answer =
      transact(world, host, now, 62,
               ByteView{unreg_body.data(), unreg_body.size()}, got_error,
               error_code);
  HostUnregisterResponse unreg{};
  CHECK(decode_host_unregister_response(
      ByteView{unreg_answer.data(), unreg_answer.size()}, unreg));
  CHECK(unreg.result == static_cast<std::uint16_t>(GatewayOpsResult::Ok));
  CHECK(!world.bridge.host_ready(bound));

  const std::array<std::uint8_t, 2> payload{{1, 2}};
  const auto canonical =
      build_canonical_v2(7, 1, 2, reg.token, 0xB0071D0001ULL, 1, 1, 5000,
                         ByteView{payload.data(), payload.size()});
  const auto submit =
      submit_bytes(1, ByteView{canonical.data(), canonical.size()}, now + 8000);
  const auto submit_answer =
      transact(world, host, now, 63,
               ByteView{submit.data(), submit.size()}, got_error, error_code);
  DispatchReceipt receipt{};
  CHECK(decode_receipt(ByteView{submit_answer.data(), submit_answer.size()},
                       HostOpsSub::Submit, receipt));
  CHECK(receipt.result == HostOpsResult::InvalidRequest);

  // Unregistering twice is Stale — there is nothing left to release.
  const auto again = transact(world, host, now, 64,
                              ByteView{unreg_body.data(), unreg_body.size()},
                              got_error, error_code);
  HostUnregisterResponse again_resp{};
  CHECK(decode_host_unregister_response(
      ByteView{again.data(), again.size()}, again_resp));
  CHECK(again_resp.result == static_cast<std::uint16_t>(GatewayOpsResult::Stale));
}

// A new USB session kills the registration with it: a canonical still
// bound to the old token is refused InvalidRequest — while the lane is
// empty AND while a fresh session-2 token is live (never rebound).
void test_bridge_gateway_stale_session() {
  GatewayWorld world;
  HostDriver host;
  MonotonicMs now = 1000;
  CHECK(host_handshake(world, host, now, 0x1111, 10) != 0);
  bool got_error = false;
  std::uint16_t error_code = 0;
  const auto reg_body = register_bytes(7, 0x99, 15000);
  const auto reg_answer =
      transact(world, host, now, 60, ByteView{reg_body.data(), reg_body.size()},
               got_error, error_code);
  HostRegisterResponse reg{};
  CHECK(decode_host_register_response(
      ByteView{reg_answer.data(), reg_answer.size()}, reg));
  CHECK(reg.result == static_cast<std::uint16_t>(GatewayOpsResult::Ok));

  const std::array<std::uint8_t, 2> payload{{1, 2}};
  const auto canonical =
      build_canonical_v2(7, 1, 2, reg.token, 0xB0071D0001ULL, 1, 1, 5000,
                         ByteView{payload.data(), payload.size()});
  const auto submit =
      submit_bytes(1, ByteView{canonical.data(), canonical.size()}, now + 8000);

  // Session 2: a fresh handshake clears the session-1 registration.
  HostDriver host2;
  now += 500;
  CHECK(host_handshake(world, host2, now, 0x2222, 70) != 0);
  const auto dead_answer =
      transact(world, host2, now, 71,
               ByteView{submit.data(), submit.size()}, got_error, error_code);
  DispatchReceipt dead{};
  CHECK(decode_receipt(ByteView{dead_answer.data(), dead_answer.size()},
                       HostOpsSub::Submit, dead));
  CHECK(dead.result == HostOpsResult::InvalidRequest);

  // Session 2 registers its own binding — a different token. The stale
  // canonical stays refused: a live registration never resurrects it.
  const auto reg2_answer =
      transact(world, host2, now, 72,
               ByteView{reg_body.data(), reg_body.size()}, got_error,
               error_code);
  HostRegisterResponse reg2{};
  CHECK(decode_host_register_response(
      ByteView{reg2_answer.data(), reg2_answer.size()}, reg2));
  CHECK(reg2.result == static_cast<std::uint16_t>(GatewayOpsResult::Ok));
  CHECK(reg2.token != reg.token);
  const auto stale_answer =
      transact(world, host2, now, 73,
               ByteView{submit.data(), submit.size()}, got_error, error_code);
  DispatchReceipt stale{};
  CHECK(decode_receipt(ByteView{stale_answer.data(), stale_answer.size()},
                       HostOpsSub::Submit, stale));
  CHECK(stale.result == HostOpsResult::InvalidRequest);

  // And the honest path still works: the same canonical re-bound to the
  // session-2 token is admitted.
  const auto fresh =
      build_canonical_v2(7, 1, 2, reg2.token, 0xB0071D0001ULL, 1, 1, 5000,
                         ByteView{payload.data(), payload.size()});
  const auto fresh_submit =
      submit_bytes(2, ByteView{fresh.data(), fresh.size()}, now + 8000);
  const auto frames = exchange(world, host2, now, 74,
                               ByteView{fresh_submit.data(), fresh_submit.size()});
  const DeviceFrame* ok_frame =
      find_sub(frames, static_cast<std::uint8_t>(HostOpsSub::Submit));
  CHECK(ok_frame != nullptr);
  DispatchReceipt ok{};
  CHECK(decode_receipt(
      ByteView{ok_frame->body.data(), ok_frame->body.size()},
      HostOpsSub::Submit, ok));
  CHECK(ok.result == HostOpsResult::Ok);
}

// ------------------------------------------------ group_delivery_v1 (0x50-0x52)

std::vector<std::uint8_t> group_send_bytes(const GroupSendRequest& request) {
  std::array<std::uint8_t, kGatewayInnerHeadSize + kGroupSendMaxPayload> out{};
  std::size_t written = 0;
  if (!encode_group_send(request, MutableByteView{out.data(), out.size()}, written)) {
    return {};
  }
  return std::vector<std::uint8_t>(out.begin(), out.begin() + written);
}

std::vector<std::uint8_t> group_query_bytes(const MessageId& id) {
  std::array<std::uint8_t, kGatewayInnerHeadSize + kGroupQueryPayload> out{};
  std::size_t written = 0;
  GroupQueryRequest query{};
  query.id = id;
  if (!encode_group_query(query, MutableByteView{out.data(), out.size()}, written)) {
    return {};
  }
  return std::vector<std::uint8_t>(out.begin(), out.begin() + written);
}

bool decode_group_status_bytes(const std::vector<std::uint8_t>& inner, GroupStatusReply& out) {
  return decode_group_status(ByteView{inner.data(), inner.size()}, out).ok();
}

std::string group_reason(const GroupStatusReply& reply) {
  return std::string(reply.reason.data(), reply.reason_len);
}

void test_group_ops_codecs() {
  const char* text = "PUMP3 OVERTEMP";
  GroupSendRequest send{};
  send.group = kGroupAll;
  send.priority = Priority::Urgent;
  send.flags = kGroupSendOrdered;
  send.lifetime_ms = 5000;
  send.hop_limit = 10;
  send.data = ByteView{reinterpret_cast<const std::uint8_t*>(text), std::strlen(text)};
  auto bytes = group_send_bytes(send);
  CHECK(bytes.size() == kGatewayInnerHeadSize + kGroupSendFixedPayload + 14);
  CHECK(bytes[0] == kHostOpsSchema && bytes[1] == 0x50);
  GroupSendRequest decoded{};
  CHECK(decode_group_send(ByteView{bytes.data(), bytes.size()}, decoded));
  CHECK(decoded.group == kGroupAll && decoded.priority == Priority::Urgent &&
        decoded.flags == kGroupSendOrdered && decoded.lifetime_ms == 5000 &&
        decoded.hop_limit == 10 && decoded.data.size == 14 &&
        std::memcmp(decoded.data.data, text, 14) == 0);
  // Every field bound is enforced on decode (a mutated byte is refused).
  const auto refuse = [&](std::size_t offset, std::uint8_t value) {
    auto copy = bytes;
    copy[offset] = value;
    GroupSendRequest out{};
    return !decode_group_send(ByteView{copy.data(), copy.size()}, out).ok();
  };
  {
    auto copy = bytes;
    copy[4] = copy[5] = 0;  // group 0x0000
    GroupSendRequest out{};
    CHECK(!decode_group_send(ByteView{copy.data(), copy.size()}, out));
  }
  CHECK(refuse(6, 4));                    // priority beyond Urgent
  CHECK(refuse(7, 0x02));                 // unknown flag
  CHECK(refuse(12, 0));                   // hop_limit 0
  CHECK(refuse(12, 0xFF));                // hop_limit 255
  CHECK(refuse(13, 1));                   // reserved byte
  CHECK(refuse(15, 13));                  // data_len != remaining
  {
    auto copy = bytes;
    copy[8] = copy[9] = copy[10] = copy[11] = 0;  // lifetime 0
    GroupSendRequest out{};
    CHECK(!decode_group_send(ByteView{copy.data(), copy.size()}, out));
    copy[10] = 0x75;
    copy[11] = 0x31;  // 30001 ms > kMaxMessageLifetimeMs
    CHECK(!decode_group_send(ByteView{copy.data(), copy.size()}, out));
  }
  std::array<std::uint8_t, kGroupPayloadMax + 1> big{};
  send.data = ByteView{big.data(), big.size()};
  CHECK(group_send_bytes(send).empty());
  send.data = ByteView{big.data(), kGroupPayloadMax};
  CHECK(group_send_bytes(send).size() == kGatewayInnerHeadSize + kGroupSendMaxPayload);

  const MessageId id{7001, kGroupSequenceFlag | 3};
  const auto query = group_query_bytes(id);
  CHECK(query.size() == kGatewayInnerHeadSize + kGroupQueryPayload);
  GroupQueryRequest query_out{};
  CHECK(decode_group_query(ByteView{query.data(), query.size()}, query_out));
  CHECK(query_out.id == id);
  CHECK(group_query_bytes(MessageId{7001, 3}).empty());  // not a group id

  // 0x51: flags are derived; a refusal carries no id; ids are checked.
  GroupDeliveryResult summary{};
  summary.id = id;
  summary.group = 7;
  summary.state = DeliveryState::Failed;
  summary.rounds = 12;
  summary.delivered = 80;
  summary.nonmember = 3;
  summary.missing_total = 16;
  summary.unaccounted = 1;
  summary.missing_count = 2;
  summary.missing[0] = 41;
  summary.missing[1] = 42;
  const auto reply = group_status_from(0, summary, "GROUP_INCOMPLETE");
  CHECK(reply.flags == (kGroupStatusTruncated | kGroupStatusFinal));
  std::array<std::uint8_t, kGatewayInnerHeadSize + kGroupStatusMaxPayload> wire{};
  std::size_t written = 0;
  CHECK(encode_group_status(reply, MutableByteView{wire.data(), wire.size()}, written));
  CHECK(written == kGatewayInnerHeadSize + kGroupStatusFixedPayload + 16 + 16);
  std::vector<std::uint8_t> status_bytes(wire.begin(), wire.begin() + written);
  GroupStatusReply back{};
  CHECK(decode_group_status_bytes(status_bytes, back));
  CHECK(back.id == id && back.group == 7 && back.state == DeliveryState::Failed &&
        back.rounds == 12 && back.delivered == 80 && back.nonmember == 3 &&
        back.missing_total == 16 && back.unaccounted == 1 && back.missing_count == 2 &&
        back.missing[0] == 41 && back.missing[1] == 42 &&
        group_reason(back) == "GROUP_INCOMPLETE");
  {
    auto copy = status_bytes;
    copy[4 + 26] = kGroupStatusFinal;  // TRUNCATED dropped: inconsistent
    CHECK(!decode_group_status_bytes(copy, back));
    copy = status_bytes;
    copy[4 + 29] = 1;  // reserved
    CHECK(!decode_group_status_bytes(copy, back));
    copy = status_bytes;
    copy[4 + 6] = 0;  // sequence without the group bit
    CHECK(!decode_group_status_bytes(copy, back));
    copy = status_bytes;
    for (int i = 0; i < 8; ++i) copy[4 + 30 + i] = 0;  // reserved missing id 0
    CHECK(!decode_group_status_bytes(copy, back));
    copy = status_bytes;
    copy[copy.size() - 1] = 0x07;  // non-printable reason byte
    CHECK(!decode_group_status_bytes(copy, back));
    copy = status_bytes;
    copy.push_back(0);  // trailing byte
    CHECK(!decode_group_status_bytes(copy, back));
  }
  // A refusal: result non-Ok, no id, no counts, flags zero.
  const auto refusal =
      group_status_from(static_cast<std::uint16_t>(ConfigOpsResult::Busy), summary,
                        "GROUP_QUEUE_FULL");
  CHECK(refusal.id.session == 0 && refusal.id.sequence == 0 && refusal.delivered == 0 &&
        refusal.flags == 0 && refusal.group == 7);
  CHECK(encode_group_status(refusal, MutableByteView{wire.data(), wire.size()}, written));
  GroupStatusReply forged = refusal;
  forged.delivered = 1;
  CHECK(!encode_group_status(forged, MutableByteView{wire.data(), wire.size()}, written));
  // Reasons are clipped to kGroupStatusReasonMax.
  const auto clipped = group_status_from(0, summary, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
  CHECK(clipped.reason_len == kGroupStatusReasonMax);
}

// Sends one sealed HostOps request and returns every opened 0x51 reply the
// device queued (in order) — the immediate answer and, after mesh pumping,
// the FINAL one.
std::vector<GroupStatusReply> opened_group_status(World& world, const HostDriver& host,
                                                  std::uint64_t request) {
  std::vector<GroupStatusReply> out;
  for (const auto& record : world.device_sink.frames) {
    std::uint64_t counter = 0;
    ByteView opened{};
    if (record.frame.kind != FrameKind::HostOps || record.frame.request != request ||
        !open_body(host.proof.key, kDirDeviceToHost, record.frame, counter, opened)) {
      continue;
    }
    GroupStatusReply reply{};
    if (decode_group_status(opened, reply)) out.push_back(reply);
  }
  return out;
}

struct GroupWorld : World {
  GroupWorld() : World(0x3 | kCapHostOpsV1, /*scoped=*/true) {}

  void run_mesh(MonotonicMs& now, MonotonicMs ms) {
    const MonotonicMs end = now + ms;
    for (; now <= end; now += 5) {
      n1.poll(now);
      n2.poll(now);
      net.flush(now);
      bridge.poll(now);
      const auto bytes = stream.take();
      if (!bytes.empty()) device_decoder.push(ByteView{bytes.data(), bytes.size()}, now);
    }
  }
};

void test_bridge_group_send_and_final() {
  GroupWorld world;
  CHECK(world.bridge.attach_group().ok());
  MonotonicMs now = 0;
  world.run_mesh(now, 8000);  // node 2 adopts gateway 1 as its tree parent
  CHECK(world.n1.scoped_child(2));
  world.device_sink.frames.clear();
  HostDriver host;
  CHECK(host_handshake(world, host, now, 0x5151, 10) != 0);

  const char* text = "PUMP3 OVERTEMP";
  GroupSendRequest send{};
  send.group = kGroupAll;
  send.priority = Priority::Urgent;
  send.lifetime_ms = 5000;
  send.hop_limit = 10;
  send.data = ByteView{reinterpret_cast<const std::uint8_t*>(text), std::strlen(text)};
  const auto send_body = group_send_bytes(send);
  bool got_error = false;
  std::uint16_t error_code = 0;
  const auto answer = transact(world, host, now, 70,
                               ByteView{send_body.data(), send_body.size()}, got_error,
                               error_code);
  CHECK(!got_error);
  GroupStatusReply admitted{};
  CHECK(decode_group_status_bytes(answer, admitted));
  CHECK(admitted.result == static_cast<std::uint16_t>(ConfigOpsResult::Ok));
  CHECK(admitted.id.session == 7001 && admitted.id.sequence == (kGroupSequenceFlag | 1));
  CHECK(admitted.group == kGroupAll && (admitted.flags & kGroupStatusFinal) == 0);

  // The mesh settles the message; the device emits exactly one FINAL 0x51
  // under the SAME request id, and node 2 receives the alarm once.
  world.run_mesh(now, 1500);
  const auto finals = opened_group_status(world, host, 70);
  CHECK(finals.size() == 1);
  if (!finals.empty()) {
    const auto& final_reply = finals.front();
    CHECK(final_reply.id == admitted.id);
    CHECK(final_reply.state == DeliveryState::Delivered &&
          (final_reply.flags & kGroupStatusFinal) != 0);
    CHECK(final_reply.delivered == 1 && final_reply.missing_total == 0 &&
          final_reply.unaccounted == 0 && final_reply.rounds == 1);
    CHECK(group_reason(final_reply) == "GROUP_COMPLETE");
  }
  world.device_sink.frames.clear();
  CHECK(world.obs2.group_messages.size() == 1);
  if (!world.obs2.group_messages.empty()) {
    CHECK(world.obs2.group_messages.back().info.key.id == admitted.id);
  }

  // 0x52 reads the same settled summary; an unknown id answers NOT_FOUND.
  const auto query = group_query_bytes(admitted.id);
  const auto polled = transact(world, host, now, 71, ByteView{query.data(), query.size()},
                               got_error, error_code);
  GroupStatusReply snapshot{};
  CHECK(decode_group_status_bytes(polled, snapshot));
  CHECK(snapshot.state == DeliveryState::Delivered && snapshot.delivered == 1 &&
        (snapshot.flags & kGroupStatusFinal) != 0);
  const auto unknown = group_query_bytes(MessageId{7001, kGroupSequenceFlag | 99});
  const auto missing = transact(world, host, now, 72,
                                ByteView{unknown.data(), unknown.size()}, got_error,
                                error_code);
  GroupStatusReply not_found{};
  CHECK(decode_group_status_bytes(missing, not_found));
  CHECK(not_found.result == static_cast<std::uint16_t>(ConfigOpsResult::Ok) &&
        not_found.state == DeliveryState::Empty && group_reason(not_found) == "NOT_FOUND" &&
        not_found.id.sequence == (kGroupSequenceFlag | 99));

  // Invalid through the codec never reaches the node: malformed -> Error.
  auto broken = send_body;
  broken[13] = 1;  // reserved byte
  const auto malformed = transact(world, host, now, 73,
                                  ByteView{broken.data(), broken.size()}, got_error,
                                  error_code);
  CHECK(got_error && malformed.empty());
  // 0x51 is device->host only.
  std::array<std::uint8_t, kGatewayInnerHeadSize + kGroupStatusMaxPayload> wire{};
  std::size_t written = 0;
  CHECK(encode_group_status(snapshot, MutableByteView{wire.data(), wire.size()}, written));
  transact(world, host, now, 74, ByteView{wire.data(), written}, got_error, error_code);
  CHECK(got_error);
  CHECK(world.n1.group_stats().sent == 1);
}

void test_bridge_group_refusals() {
  // Without attach_group the family answers Unsupported and sends nothing.
  {
    GroupWorld world;
    MonotonicMs now = 0;
    world.run_mesh(now, 8000);
    world.device_sink.frames.clear();
    HostDriver host;
    CHECK(host_handshake(world, host, now, 0x5252, 10) != 0);
    GroupSendRequest send{};
    send.group = 5;
    send.lifetime_ms = 3000;
    const auto body = group_send_bytes(send);
    bool got_error = false;
    std::uint16_t error_code = 0;
    const auto answer = transact(world, host, now, 80, ByteView{body.data(), body.size()},
                                 got_error, error_code);
    GroupStatusReply reply{};
    CHECK(decode_group_status_bytes(answer, reply));
    CHECK(reply.result == static_cast<std::uint16_t>(ConfigOpsResult::Unsupported) &&
          reply.id.sequence == 0 && reply.group == 5 &&
          group_reason(reply) == "GROUP_UNSUPPORTED");
    CHECK(world.n1.group_stats().sent == 0);
  }
  // Attached on a flat-profile node: the node refuses (no tree, no flood)
  // and the refusal reason reaches the host.
  {
    World world;
    CHECK(world.bridge.attach_group().ok());
    MonotonicMs now = 1000;
    HostDriver host;
    CHECK(host_handshake(world, host, now, 0x5353, 10) != 0);
    GroupSendRequest send{};
    send.group = kGroupAll;
    send.lifetime_ms = 3000;
    const auto body = group_send_bytes(send);
    bool got_error = false;
    std::uint16_t error_code = 0;
    const auto answer = transact(world, host, now, 81, ByteView{body.data(), body.size()},
                                 got_error, error_code);
    GroupStatusReply reply{};
    CHECK(decode_group_status_bytes(answer, reply));
    CHECK(reply.result == static_cast<std::uint16_t>(ConfigOpsResult::Unsupported) &&
          group_reason(reply) == "GROUP_REQUIRES_GATEWAY_SCOPED");
  }
  // Source table full: Normal sends keep the Urgent reserve -> Busy.
  {
    GroupWorld world;
    CHECK(world.bridge.attach_group().ok());
    MonotonicMs now = 0;
    world.run_mesh(now, 8000);
    world.device_sink.frames.clear();
    HostDriver host;
    CHECK(host_handshake(world, host, now, 0x5454, 10) != 0);
    GroupSendRequest send{};
    send.group = 9;
    send.lifetime_ms = 20000;
    const auto body = group_send_bytes(send);
    bool got_error = false;
    std::uint16_t error_code = 0;
    std::vector<GroupStatusReply> replies;
    for (std::uint64_t request = 90; request < 94; ++request) {
      const auto answer = transact(world, host, now, request,
                                   ByteView{body.data(), body.size()}, got_error, error_code);
      GroupStatusReply reply{};
      CHECK(decode_group_status_bytes(answer, reply));
      replies.push_back(reply);
    }
    std::size_t ok = 0;
    std::size_t busy = 0;
    for (const auto& reply : replies) {
      if (reply.result == static_cast<std::uint16_t>(ConfigOpsResult::Ok)) ++ok;
      if (reply.result == static_cast<std::uint16_t>(ConfigOpsResult::Busy)) {
        ++busy;
        CHECK(group_reason(reply) == "GROUP_QUEUE_FULL");
      }
    }
    CHECK(ok == kGroupOriginCapacity - 1 && busy == replies.size() - ok);
  }
}

}  // namespace

int main() {
  test_boot_lease();
  test_submit_codec();
  test_lane_codec();
  test_time_sample_codec();
  test_response_codecs();
  test_canonical_parser();
  test_window_admit_replay_conflict();
  test_window_capacity_bound();
  test_window_retire_prefix();
  test_window_retire_ring_wrap();
  test_window_skip();
  test_window_query();
  test_window_lease_and_lane();
  test_window_mesh_outcomes();
  test_window_reserved_submit_fields();
  test_window_submit_onto_skip_is_conflict();
  test_window_lane_binds_on_first_send();
  test_window_record_indeterminate();
  test_bridge_submit_lifecycle();
  test_bridge_expiry_and_mesh_outcome();
  test_bridge_reconnect_keeps_window();
  test_bridge_lease_lane_and_validation();
  test_bridge_time_sample();
  test_bridge_malformed_and_gating();
  test_bridge_submit_rejections();
  test_bridge_lifetime_clamped_to_ttl();
  test_bridge_mesh_rejected();
  test_bridge_stale_delivery_event_after_retire();
  test_gateway_inner_codecs();
  test_bridge_gateway_register();
  test_bridge_gateway_unsupported();
  test_bridge_gateway_loopback();
  test_bridge_gateway_ingress_resend_and_lease();
  test_bridge_gateway_host_down();
  test_bridge_gateway_ingress_busy();
  test_bridge_gateway_remote_send();
  test_bridge_gateway_unregister();
  test_bridge_gateway_stale_session();
  test_group_ops_codecs();
  test_bridge_group_send_and_final();
  test_bridge_group_refusals();
  if (failures != 0) {
    std::fprintf(stderr, "%d host-ops checks failed\n", failures);
    return 1;
  }
  std::puts("RouteLoom host-ops dispatch-window tests passed");
  return 0;
}
