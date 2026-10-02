#include <array>
#include <cassert>
#include <cstring>

#include "routeloom/discovery_scope.hpp"
#include "routeloom/sdkv1_authority_transport.hpp"

using namespace routeloom;
using namespace routeloom::sdkv1;

namespace {
class Port final : public ConfigWirePort {
 public:
  Status config_send(NodeId, FrameType type, ByteView bytes, MonotonicMs) noexcept override {
    assert(type == FrameType::ObjectAck);
    assert(autonomy::object_ack_decode(bytes, ack));
    return Status::success();
  }
  autonomy::ObjectAckPayload ack{};
};
}

int main() {
  // The authority lane accepts its exact timeout boundary. A duplicate
  // manifest must neither reset progress nor extend that boundary.
  for (const MonotonicMs elapsed : {kAuthorityReassemblyTimeoutMs - 1,
                                   kAuthorityReassemblyTimeoutMs,
                                   kAuthorityReassemblyTimeoutMs + 1}) {
    Port port;
    AuthorityEndpoint endpoint(port, 1);
    std::array<std::uint8_t, 180> bytes{};
    for (std::size_t i = 0; i < bytes.size(); ++i) bytes[i] = static_cast<std::uint8_t>(i);
    autonomy::ControlObjectPayload manifest{};
    manifest.kind = autonomy::ControlObjectKind::AuthorityEnvelope;
    manifest.total_len = bytes.size();
    sha256({bytes.data(), bytes.size()}, manifest.object_hash);
    for (const MonotonicMs start : {MonotonicMs{1000}, MonotonicMs{100000}}) {
      endpoint.on_manifest(2, manifest, start);
      autonomy::ObjectChunkPayload chunk{};
      chunk.object_hash = manifest.object_hash;
      chunk.data_size = 90;
      std::memcpy(chunk.data.data(), bytes.data(), 90);
      endpoint.on_chunk(2, chunk, start);
      endpoint.on_manifest(2, manifest, start + elapsed);
      assert(port.ack.received_len == 90);
      chunk.offset = 90;
      std::memcpy(chunk.data.data(), bytes.data() + 90, 90);
      endpoint.on_chunk(2, chunk, start + elapsed);
      const bool completed = elapsed <= kAuthorityReassemblyTimeoutMs;
      assert(port.ack.status == (completed ? autonomy::ObjectAckStatus::Ok
                                          : autonomy::ObjectAckStatus::Failed));
      AuthorityRxCarrier rx{};
      assert(endpoint.take_rx(rx) == completed);
      if (completed) {
        assert(rx.bytes.size == bytes.size());
        assert(std::memcmp(rx.bytes.data, bytes.data(), bytes.size()) == 0);
      }
      assert(endpoint.quiescent());
    }
  }
}
