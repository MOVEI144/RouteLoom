// Fuzz target: routeloom::autonomy payload decoders
// (components/routeloom/src/autonomy_wire.cpp) — the versioned autonomy
// payload registry plus the RLD1 one-hop discovery carrier.
//
// Every decoder runs over the raw input; any that accept get an
// encode→decode→encode idempotence pass. rld1_probe gates rld1_decode the
// same way the node's single classification point does.

#include <cstddef>
#include <cstdint>

#include "routeloom/autonomy_wire.hpp"

#include "fuzz_driver.hpp"

namespace {

using routeloom::ByteView;
using routeloom::autonomy::EncodedPayload;

// decode(encode(decode(x))) must equal decode(x) — a second decode of the
// canonical re-encode is the strongest cheap invariant here.
template <typename Payload, typename Decode, typename Encode>
void roundtrip(const ByteView input, Decode decode, Encode encode) {
  Payload first{};
  if (!decode(input, first)) return;
  EncodedPayload reencoded{};
  if (!encode(first, reencoded)) return;  // decode-only acceptance is fine
  Payload second{};
  if (!decode(reencoded.view(), second)) {
    // decode(x) accepted but decode(encode(decode(x))) rejected — a
    // canonicalization bug. Trap it: fuzzers must see this as a crash.
    std::abort();
  }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
  namespace a = routeloom::autonomy;
  const ByteView input{data, size};

  roundtrip<a::BusyPayload>(input, a::busy_decode,
                            [](const a::BusyPayload& p, EncodedPayload& o) {
                              return a::busy_encode(p, o);
                            });
  roundtrip<a::TimeSyncPayload>(input, a::time_sync_decode,
                                [](const a::TimeSyncPayload& p,
                                   EncodedPayload& o) {
                                  return a::time_sync_encode(p, o);
                                });
  roundtrip<a::ChannelNoticePayload>(
      input, a::channel_notice_decode,
      [](const a::ChannelNoticePayload& p, EncodedPayload& o) {
        return a::channel_notice_encode(p, o);
      });
  roundtrip<a::NeighborProbePayload>(
      input, a::neighbor_probe_decode,
      [](const a::NeighborProbePayload& p, EncodedPayload& o) {
        return a::neighbor_probe_encode(p, o);
      });
  roundtrip<a::NeighborResultPayload>(
      input, a::neighbor_result_decode,
      [](const a::NeighborResultPayload& p, EncodedPayload& o) {
        return a::neighbor_result_encode(p, o);
      });
  roundtrip<a::ControlObjectPayload>(
      input, a::control_object_decode,
      [](const a::ControlObjectPayload& p, EncodedPayload& o) {
        return a::control_object_encode(p, o);
      });
  roundtrip<a::ObjectChunkPayload>(
      input, a::object_chunk_decode,
      [](const a::ObjectChunkPayload& p, EncodedPayload& o) {
        return a::object_chunk_encode(p, o);
      });
  roundtrip<a::ObjectAckPayload>(
      input, a::object_ack_decode,
      [](const a::ObjectAckPayload& p, EncodedPayload& o) {
        return a::object_ack_encode(p, o);
      });
  roundtrip<a::BootstrapAuthBody>(
      input, a::bootstrap_auth_decode,
      [](const a::BootstrapAuthBody& p, EncodedPayload& o) {
        return a::bootstrap_auth_encode(p, o);
      });

  // RLD1 carrier: classify exactly once, then decode — the production rule
  // (a failed RLD1 decode must never fall back into the Wire parser) is a
  // routing-layer concern; here both paths are exercised on the same bytes.
  if (a::rld1_probe(input)) {
    a::Rld1Envelope envelope{};
    if (a::rld1_decode(input, envelope)) {
      a::Rld1Encoded reencoded{};
      if (a::rld1_encode(envelope, reencoded)) {
        a::Rld1Envelope again{};
        if (!a::rld1_decode(reencoded.view(), again)) std::abort();
      }
    }
  } else {
    a::Rld1Envelope envelope{};
    (void)a::rld1_decode(input, envelope);
  }
  return 0;
}

ROUTELOOM_FUZZ_MAIN()
