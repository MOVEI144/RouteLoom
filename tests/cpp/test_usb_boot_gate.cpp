#include <array>
#include <cstdio>
#include <cstdlib>

#include "routeloom/byte_io.hpp"
#include "routeloom/usb_bridge.hpp"

using namespace routeloom;
using namespace routeloom::usb;

namespace {
void check(bool ok) {
  if (!ok) std::abort();
}

class Stream final : public ByteStream {
 public:
  Status write(ByteView bytes, std::size_t& written) noexcept override {
    written = bytes.size;
    return Status::success();
  }
};

class Owner final : public UsbBridge::SecurityOwnerUsbSink {
 public:
  bool ready{false};
  bool host_session_ready() const noexcept override { return ready; }
  Status join_down(NodeId, const sdkv1::RelayObject&, ByteView, MonotonicMs) noexcept override {
    return Status::success();
  }
  Status join_abort(NodeId, sdkv1::RelayToken, std::uint8_t, MonotonicMs) noexcept override {
    return Status::success();
  }
  void join_session_down(MonotonicMs) noexcept override {}
};

void feed(UsbBridge& bridge, std::uint16_t flags, ByteView body, MonotonicMs now) {
  std::array<std::uint8_t, 128> wire{}, scratch{};
  std::size_t written = 0;
  check(encode_frame(FrameKind::Hello, flags, 0, 1, body,
                     MutableByteView{scratch.data(), scratch.size()},
                     MutableByteView{wire.data(), wire.size()}, written).ok());
  bridge.on_bytes(ByteView{wire.data(), written}, now);
  bridge.poll(now);
}

void boot_gate(bool timeout) {
  constexpr std::array<std::uint8_t, 4> secret{1, 2, 3, 4};
  Stream stream;
  Owner owner;
  UsbBridge::Config config{};
  config.secret = ByteView{secret.data(), secret.size()};
  config.node = 1;
  config.network = 7;
  config.boot_id = 2;
  config.device_nonce = 3;
  UsbBridge bridge(config, stream);
  check(bridge.attach_security_owner(owner).ok());
  std::array<std::uint8_t, 11> hello{};
  ByteWriter hello_writer(MutableByteView{hello.data(), hello.size()});
  check(hello_writer.write_u64(4).ok());
  hello[8] = kProtocolVersion;
  hello[9] = kProtocolVersion;
  feed(bridge, 0, ByteView{hello.data(), hello.size()}, 0);
  check(bridge.state() == SessionState::Hello);

  SessionTranscript transcript{};
  transcript.host_nonce = 4;
  transcript.device_nonce = config.device_nonce;
  transcript.node = config.node;
  transcript.boot_id = config.boot_id;
  transcript.network = config.network;
  transcript.capability = config.capability | kCapJoinRelayV2;
  std::array<std::uint8_t, kTranscriptSize> encoded{};
  std::size_t written = 0;
  check(encode_transcript(transcript, MutableByteView{encoded.data(), encoded.size()}, written)
            .ok());
  SessionProof proof = derive_session_proof(config.secret, ByteView{encoded.data(), written});
  SessionTag bad = proof.auth_tag;
  bad[0] ^= 1;
  feed(bridge, kFlagAuth, ByteView{bad.data(), bad.size()}, 10);
  check(bridge.state() == SessionState::Hello);
  feed(bridge, kFlagAuth, ByteView{proof.auth_tag.data(), proof.auth_tag.size()}, 20);
  check(bridge.state() == SessionState::Authenticating);
  bridge.poll(100);
  check(bridge.state() == SessionState::Authenticating);
  if (timeout) {
    bridge.poll(5021);
    owner.ready = true;
    bridge.poll(5022);
    check(bridge.state() == SessionState::Disconnected);
  } else {
    owner.ready = true;
    bridge.poll(101);
    check(bridge.state() == SessionState::Active);
  }
  clear_session_proof(proof);
}
}  // namespace

int main() {
  for (const bool timeout : {false, true}) boot_gate(timeout);
  std::puts("USB boot gate passed");
}
