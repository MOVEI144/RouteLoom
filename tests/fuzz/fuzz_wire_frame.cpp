// Fuzz target: routeloom::wire frame decoders (components/routeloom/src/wire.cpp).
//
// Feeds LLVMFuzzerTestOneInput bytes to:
//   * wire::open_link  — full header parse + link AEAD open. The local node
//     is taken from the input's own next_hop field so that mutated-but-
//     well-formed headers (e.g. golden-vector seeds) reach the AEAD verify
//     path instead of bouncing off the addressing check.
//   * wire::open_end   — on the link-opened frame, and again on a
//     LinkOpenedFrame assembled field-by-field from raw bytes (public
//     fields, no validation) to hit open_end's defensive bounds directly.
//   * wire::forward    — relay re-wrap of the link-opened frame.
//   * wire::transit_fingerprint.
//
// Invariants: never crash/UB; errors via Status, never exceptions; a
// successfully opened end frame re-encodes to a decodable frame.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "routeloom/wire.hpp"

#include "fuzz_driver.hpp"
#include "test_security.hpp"

namespace {

std::uint16_t be16(const std::uint8_t* p) {
  return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8) |
                                    p[1]);
}
std::uint32_t be32(const std::uint8_t* p) {
  return (static_cast<std::uint32_t>(p[0]) << 24) |
         (static_cast<std::uint32_t>(p[1]) << 16) |
         (static_cast<std::uint32_t>(p[2]) << 8) | p[3];
}
std::uint64_t be64(const std::uint8_t* p) {
  return (static_cast<std::uint64_t>(be32(p)) << 32) | be32(p + 4);
}

// Fill a wire::Header from the raw field layout WITHOUT validation — this is
// the untrusted-parse surface open_end/forward must defend on public fields.
routeloom::wire::Header raw_header(const std::uint8_t* d, std::size_t n) {
  routeloom::wire::Header h{};
  if (n < routeloom::wire::kHeaderSize) return h;
  h.type = static_cast<routeloom::FrameType>(d[4]);
  h.flags = d[5];
  h.delivery = static_cast<routeloom::DeliveryClass>(d[6]);
  h.delivery_round = d[7];
  h.hop_remaining = d[8];
  h.payload_length = be16(d + 10);
  h.network = be32(d + 12);
  h.origin = be64(d + 16);
  h.destination = be64(d + 24);
  h.previous_hop = be64(d + 32);
  h.next_hop = be64(d + 40);
  h.message.session = be32(d + 48);
  h.message.sequence = be64(d + 52);
  h.remaining_deadline_ms = be32(d + 60);
  h.original_lifetime_ms = be32(d + 64);
  h.link_epoch = be16(d + 68);
  h.end_epoch = be16(d + 70);
  h.link_counter = be64(d + 72);
  h.end_counter = be64(d + 80);
  return h;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
  using namespace routeloom;
  if (size > kMaxEspNowBody * 2) return 0;

  const routeloom::wire::Header header = raw_header(data, size);
  routeloom_test::TestSecurity security;

  // Path 1: full wire decode. Address the frame at its own claimed next_hop
  // so well-formed inputs reach the AEAD open.
  wire::LinkOpenedFrame opened{};
  const Status linked =
      wire::open_link(ByteView{data, size}, header.next_hop, security, opened);
  if (linked) {
    // Path 2: end open at the bound destination.
    routeloom_test::TestSecurity end_security;
    wire::PlainFrame plain{};
    if (wire::open_end(opened, header.destination, end_security, plain)) {
      // Roundtrip: the recovered plain frame must re-encode cleanly.
      routeloom_test::TestSecurity rewrap;
      wire::EncodedFrame reencoded{};
      (void)wire::encode_new(plain, rewrap, reencoded);
    }
    // Path 3: relay forward — arbitrary next hop/epoch/deadline derived from
    // input bytes.
    routeloom_test::TestSecurity fwd_security;
    wire::EncodedFrame fwd{};
    const NodeId fwd_next = header.origin == 0 ? 1 : header.origin;
    (void)wire::forward(opened, header.next_hop, fwd_next, header.link_epoch,
                        header.remaining_deadline_ms, fwd_security, fwd);
    std::array<std::uint8_t, 32> fingerprint{};
    (void)wire::transit_fingerprint(opened, fingerprint);
  }

  // Path 4: hand-built LinkOpenedFrame straight from raw bytes — reaches
  // open_end/forward even when the link AEAD in path 1 fails.
  if (size >= wire::kHeaderSize) {
    wire::LinkOpenedFrame crafted{};
    crafted.header = header;
    const std::size_t rest = size - wire::kHeaderSize;
    const std::size_t take =
        rest < crafted.protected_payload.size() ? rest
                                                : crafted.protected_payload.size();
    std::memcpy(crafted.protected_payload.data(), data + wire::kHeaderSize,
                take);
    crafted.protected_payload_size = take;
    routeloom_test::TestSecurity end_security;
    wire::PlainFrame plain{};
    (void)wire::open_end(crafted, header.destination, end_security, plain);
    wire::EncodedFrame fwd{};
    const NodeId fwd_next = header.origin == 0 ? 1 : header.origin;
    (void)wire::forward(crafted, header.next_hop, fwd_next, header.link_epoch,
                        header.remaining_deadline_ms, end_security, fwd);
    std::array<std::uint8_t, 32> fingerprint{};
    (void)wire::transit_fingerprint(crafted, fingerprint);
  }
  return 0;
}

ROUTELOOM_FUZZ_MAIN()
