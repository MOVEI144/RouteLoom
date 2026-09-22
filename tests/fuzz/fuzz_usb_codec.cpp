// Fuzz target: routeloom::usb COBS + CRC32 frame decoders
// (components/routeloom/src/usb_codec.cpp) — the device-bridge wire format.
//
// Three entry surfaces per input:
//   * usb::cobs_decode  — raw segment decode into a bounded buffer.
//   * usb::decode_frame — header/CRC validation of decoded bytes.
//   * usb::StreamDecoder — the push-style byte-stream path: delimiter
//     framing, overlength discard/resync, and the partial-frame timeout via
//     poll(). Input is pushed whole and in a second pass chunked at a
//     fuzzer-chosen stride.
//
// On a successful decode the frame is re-encoded and decoded again to
// exercise encode-side bounds against arbitrary accepted inputs.

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/usb_codec.hpp"

#include "fuzz_driver.hpp"

namespace {

class CountingSink final : public routeloom::usb::UsbFrameSink {
 public:
  void on_frame(const routeloom::usb::UsbFrame& frame) noexcept override {
    ++frames;
    // Touch the aliased body so a bad view can't hide.
    volatile std::uint8_t sink = 0;
    for (std::size_t i = 0; i < frame.body.size; ++i) {
      sink ^= frame.body.data[i];
    }
    (void)sink;
  }
  void on_stream_error(routeloom::Status) noexcept override { ++errors; }
  std::size_t frames{0};
  std::size_t errors{0};
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
  using namespace routeloom;
  using namespace routeloom::usb;
  if (size > kMaxPendingEncoded * 2) return 0;

  const ByteView input{data, size};

  // Raw COBS segment decode.
  std::array<std::uint8_t, kMaxDecodedFrame + 64> cobs_out{};
  std::size_t decoded_len = 0;
  (void)cobs_decode(input,
                    MutableByteView{cobs_out.data(), cobs_out.size()},
                    decoded_len);

  // Decoded-form frame validation (magic/version/kind/length/CRC).
  UsbFrame frame{};
  if (decode_frame(input, frame)) {
    // Accepted: re-encode and decode again — encode must handle any
    // (kind, flags, session, request, body) the decoder emitted.
    std::array<std::uint8_t, kMaxDecodedFrame> scratch{};
    std::array<std::uint8_t, kMaxEncodedFrame> encoded{};
    std::size_t written = 0;
    if (encode_frame(frame.kind, frame.flags, frame.session, frame.request,
                     frame.body,
                     MutableByteView{scratch.data(), scratch.size()},
                     MutableByteView{encoded.data(), encoded.size()},
                     written)) {
      // Strip the delimiter and push through the stream decoder.
      CountingSink sink;
      StreamDecoder decoder{sink};
      decoder.push(ByteView{encoded.data(), written}, 0);
      decoder.poll(0);
    }
  }

  // Stream path over the raw input: whole-buffer push, then a chunked push
  // at a stride taken from the first byte (covers split-delimiter states).
  {
    CountingSink sink;
    StreamDecoder decoder{sink};
    decoder.push(input, 0);
    decoder.poll(kPartialFrameTimeoutMs + 1);  // exercise timeout drop
    decoder.push(input, kPartialFrameTimeoutMs + 2);
  }
  {
    CountingSink sink;
    StreamDecoder decoder{sink};
    const std::size_t stride = size > 0 ? 1 + (data[0] % 8) : 1;
    MonotonicMs now = 0;
    for (std::size_t i = 0; i < size; i += stride) {
      const std::size_t n =
          (size - i) < stride ? (size - i) : stride;
      decoder.push(ByteView{data + i, n}, now);
      now += 7;  // wander across the partial-frame timeout boundary
      if ((i & 0x3ff) == 0) decoder.poll(now);
    }
    decoder.poll(now + kPartialFrameTimeoutMs + 1);
  }
  return 0;
}

ROUTELOOM_FUZZ_MAIN()
