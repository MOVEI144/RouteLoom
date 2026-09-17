#include "routeloom/wire.hpp"

#include <algorithm>
#include <array>
#include <cstring>

#include "routeloom/byte_io.hpp"

namespace routeloom::wire {
namespace {

constexpr std::size_t kEndAadMax = 64;

bool known_frame_type(const std::uint8_t value) noexcept {
  switch (static_cast<FrameType>(value)) {
    case FrameType::Discover:
    case FrameType::Offer:
    case FrameType::BootstrapAuth:
    case FrameType::MembershipResult:
    case FrameType::Data:
    case FrameType::HopAccept:
    case FrameType::EndReceipt:
    case FrameType::AppResult:
    case FrameType::Busy:
    case FrameType::RouteUpdate:
    case FrameType::RouteWithdraw:
    case FrameType::SeqnoRequest:
    case FrameType::NeighborProbe:
    case FrameType::NeighborResult:
    case FrameType::Diagnostic:
      return true;
  }
  return false;
}

Status write_header(const Header& header, MutableByteView output) noexcept {
  if (output.size < kHeaderSize) {
    return Status::error(StatusCode::NoCapacity, "wire header output too small");
  }
  if (header.network > UINT32_MAX) {
    return Status::error(StatusCode::InvalidArgument, "v0 network id exceeds 32 bits");
  }
  ByteWriter writer(output);
  Status status;
#define RL_WRITE(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE(writer.write_u16(kMagic));
  RL_WRITE(writer.write_u8(kMajor));
  RL_WRITE(writer.write_u8(kMinor));
  RL_WRITE(writer.write_u8(static_cast<std::uint8_t>(header.type)));
  RL_WRITE(writer.write_u8(header.flags));
  RL_WRITE(writer.write_u8(static_cast<std::uint8_t>(header.delivery)));
  RL_WRITE(writer.write_u8(header.delivery_round));
  RL_WRITE(writer.write_u8(header.hop_remaining));
  RL_WRITE(writer.write_u8(0));
  RL_WRITE(writer.write_u16(header.payload_length));
  RL_WRITE(writer.write_u32(static_cast<std::uint32_t>(header.network)));
  RL_WRITE(writer.write_u64(header.origin));
  RL_WRITE(writer.write_u64(header.destination));
  RL_WRITE(writer.write_u64(header.previous_hop));
  RL_WRITE(writer.write_u64(header.next_hop));
  RL_WRITE(writer.write_u32(header.message.session));
  RL_WRITE(writer.write_u64(header.message.sequence));
  RL_WRITE(writer.write_u32(header.remaining_deadline_ms));
  RL_WRITE(writer.write_u32(header.original_lifetime_ms));
  RL_WRITE(writer.write_u16(header.link_epoch));
  RL_WRITE(writer.write_u16(header.end_epoch));
  RL_WRITE(writer.write_u64(header.link_counter));
  RL_WRITE(writer.write_u64(header.end_counter));
#undef RL_WRITE
  if (writer.size() != kHeaderSize) {
    return Status::error(StatusCode::InternalError, "wire header size mismatch");
  }
  return Status::success();
}

Status read_header(ByteView encoded, Header& header) noexcept {
  if (encoded.size < kHeaderSize + kAeadTagSize) {
    return Status::error(StatusCode::ProtocolError, "wire frame too short");
  }
  ByteReader reader(ByteView{encoded.data, kHeaderSize});
  std::uint16_t magic = 0;
  std::uint8_t major = 0;
  std::uint8_t minor = 0;
  std::uint8_t type = 0;
  std::uint8_t delivery = 0;
  std::uint8_t reserved = 0;
  std::uint32_t network = 0;
  Status status;
#define RL_READ(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_READ(reader.read_u16(magic));
  RL_READ(reader.read_u8(major));
  RL_READ(reader.read_u8(minor));
  RL_READ(reader.read_u8(type));
  RL_READ(reader.read_u8(header.flags));
  RL_READ(reader.read_u8(delivery));
  RL_READ(reader.read_u8(header.delivery_round));
  RL_READ(reader.read_u8(header.hop_remaining));
  RL_READ(reader.read_u8(reserved));
  RL_READ(reader.read_u16(header.payload_length));
  RL_READ(reader.read_u32(network));
  RL_READ(reader.read_u64(header.origin));
  RL_READ(reader.read_u64(header.destination));
  RL_READ(reader.read_u64(header.previous_hop));
  RL_READ(reader.read_u64(header.next_hop));
  RL_READ(reader.read_u32(header.message.session));
  RL_READ(reader.read_u64(header.message.sequence));
  RL_READ(reader.read_u32(header.remaining_deadline_ms));
  RL_READ(reader.read_u32(header.original_lifetime_ms));
  RL_READ(reader.read_u16(header.link_epoch));
  RL_READ(reader.read_u16(header.end_epoch));
  RL_READ(reader.read_u64(header.link_counter));
  RL_READ(reader.read_u64(header.end_counter));
#undef RL_READ
  if (magic != kMagic || major != kMajor || minor > kMinor || reserved != 0) {
    return Status::error(StatusCode::ProtocolError, "unsupported wire header");
  }
  if (!known_frame_type(type)) {
    return Status::error(StatusCode::ProtocolError, "unknown frame type");
  }
  if (delivery > static_cast<std::uint8_t>(DeliveryClass::Applied)) {
    return Status::error(StatusCode::ProtocolError, "unknown delivery class");
  }
  header.type = static_cast<FrameType>(type);
  header.delivery = static_cast<DeliveryClass>(delivery);
  header.network = network;
  return validate_header(header);
}

Status make_end_aad(const Header& header,
                    std::array<std::uint8_t, kEndAadMax>& bytes,
                    std::size_t& length) noexcept {
  ByteWriter writer(MutableByteView{bytes.data(), bytes.size()});
  Status status;
#define RL_WRITE(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE(writer.write_u8(kMajor));
  RL_WRITE(writer.write_u8(kMinor));
  RL_WRITE(writer.write_u8(static_cast<std::uint8_t>(header.type)));
  RL_WRITE(writer.write_u8(static_cast<std::uint8_t>(header.delivery)));
  RL_WRITE(writer.write_u32(static_cast<std::uint32_t>(header.network)));
  RL_WRITE(writer.write_u64(header.origin));
  RL_WRITE(writer.write_u64(header.destination));
  RL_WRITE(writer.write_u32(header.message.session));
  RL_WRITE(writer.write_u64(header.message.sequence));
  RL_WRITE(writer.write_u32(header.original_lifetime_ms));
  RL_WRITE(writer.write_u16(header.end_epoch));
  RL_WRITE(writer.write_u64(header.end_counter));
  RL_WRITE(writer.write_u16(header.payload_length));
#undef RL_WRITE
  length = writer.size();
  return Status::success();
}

SecurityContext link_context(const Header& header) noexcept {
  return SecurityContext{SecurityScope::Link, header.network, header.previous_hop,
                         header.next_hop, header.link_epoch};
}

SecurityContext end_context(const Header& header) noexcept {
  return SecurityContext{SecurityScope::EndToEnd, header.network, header.origin,
                         header.destination, header.end_epoch};
}

Status wrap_link(const Header& header,
                 ByteView link_plaintext,
                 SecurityProvider& security,
                 EncodedFrame& output) noexcept {
  const std::size_t total = kHeaderSize + link_plaintext.size + kAeadTagSize;
  if (total > output.bytes.size()) {
    return Status::error(StatusCode::NoCapacity, "encoded frame exceeds ESP-NOW v1 body");
  }
  output.clear();
  auto status = write_header(header, MutableByteView{output.bytes.data(), kHeaderSize});
  if (!status) return status;

  std::array<std::uint8_t, kAeadTagSize> tag{};
  status = security.seal(link_context(header), header.link_counter,
                         ByteView{output.bytes.data(), kHeaderSize}, link_plaintext,
                         MutableByteView{output.bytes.data() + kHeaderSize, link_plaintext.size}, tag);
  if (!status) return status;
  std::memcpy(output.bytes.data() + kHeaderSize + link_plaintext.size, tag.data(), tag.size());
  output.size = total;
  return Status::success();
}

}  // namespace

Status validate_header(const Header& header) noexcept {
  if (header.network == 0 || header.network > UINT32_MAX ||
      header.origin == kInvalidNodeId || header.destination == kInvalidNodeId ||
      header.previous_hop == kInvalidNodeId || header.next_hop == kInvalidNodeId) {
    return Status::error(StatusCode::InvalidArgument, "wire identity field is invalid");
  }
  if (header.payload_length > kMaxApplicationPayload) {
    return Status::error(StatusCode::InvalidArgument, "payload exceeds v0 limit");
  }
  if (header.hop_remaining == 0 && header.destination != header.next_hop) {
    return Status::error(StatusCode::InvalidArgument, "hop budget exhausted before destination");
  }
  if ((header.flags & ~kFlagEndProtected) != 0) {
    return Status::error(StatusCode::ProtocolError, "unknown wire flags");
  }
  if (header.original_lifetime_ms == 0 || header.remaining_deadline_ms > header.original_lifetime_ms) {
    return Status::error(StatusCode::InvalidArgument, "invalid lifetime");
  }
  return Status::success();
}

Status encode_new(const PlainFrame& input,
                  SecurityProvider& security,
                  EncodedFrame& output) noexcept {
  if (!security.ready()) {
    return Status::error(StatusCode::InvalidState, "security provider is not ready");
  }
  if (input.payload_size > kMaxApplicationPayload) {
    return Status::error(StatusCode::InvalidArgument, "application payload too large");
  }

  Header header = input.header;
  header.payload_length = static_cast<std::uint16_t>(input.payload_size);
  auto status = validate_header(header);
  if (!status) return status;

  status = security.next_counter(link_context(header), header.link_counter);
  if (!status) return status;

  std::array<std::uint8_t, kMaxApplicationPayload + kAeadTagSize> link_plaintext{};
  std::size_t link_plaintext_size = input.payload_size;

  if ((header.flags & kFlagEndProtected) != 0) {
    status = security.next_counter(end_context(header), header.end_counter);
    if (!status) return status;
    std::array<std::uint8_t, kEndAadMax> aad{};
    std::size_t aad_size = 0;
    status = make_end_aad(header, aad, aad_size);
    if (!status) return status;
    std::array<std::uint8_t, kAeadTagSize> end_tag{};
    status = security.seal(end_context(header), header.end_counter,
                           ByteView{aad.data(), aad_size},
                           ByteView{input.payload.data(), input.payload_size},
                           MutableByteView{link_plaintext.data(), input.payload_size}, end_tag);
    if (!status) return status;
    std::memcpy(link_plaintext.data() + input.payload_size, end_tag.data(), end_tag.size());
    link_plaintext_size += end_tag.size();
  } else if (input.payload_size > 0) {
    std::memcpy(link_plaintext.data(), input.payload.data(), input.payload_size);
  }

  return wrap_link(header, ByteView{link_plaintext.data(), link_plaintext_size}, security, output);
}

Status open_link(const ByteView encoded,
                 const NodeId local_node,
                 SecurityProvider& security,
                 LinkOpenedFrame& output) noexcept {
  Header header{};
  auto status = read_header(encoded, header);
  if (!status) return status;
  if (header.next_hop != local_node) {
    return Status::error(StatusCode::AuthorizationFailed, "frame is not addressed to this hop");
  }
  const std::size_t expected_plain = static_cast<std::size_t>(header.payload_length) +
      (((header.flags & kFlagEndProtected) != 0) ? kAeadTagSize : 0U);
  const std::size_t expected_total = kHeaderSize + expected_plain + kAeadTagSize;
  if (encoded.size != expected_total || expected_plain > output.protected_payload.size()) {
    return Status::error(StatusCode::ProtocolError, "wire length mismatch");
  }
  std::array<std::uint8_t, kAeadTagSize> tag{};
  std::memcpy(tag.data(), encoded.data + kHeaderSize + expected_plain, tag.size());
  status = security.open(link_context(header), header.link_counter,
                         ByteView{encoded.data, kHeaderSize},
                         ByteView{encoded.data + kHeaderSize, expected_plain}, tag,
                         MutableByteView{output.protected_payload.data(), expected_plain});
  if (!status) return status;
  output.header = header;
  output.protected_payload_size = expected_plain;
  return Status::success();
}

Status open_end(const LinkOpenedFrame& input,
                const NodeId local_node,
                SecurityProvider& security,
                PlainFrame& output) noexcept {
  if (input.header.destination != local_node) {
    return Status::error(StatusCode::AuthorizationFailed, "end payload is not addressed to this node");
  }
  output = PlainFrame{};
  output.header = input.header;
  output.payload_size = input.header.payload_length;

  if ((input.header.flags & kFlagEndProtected) == 0) {
    if (input.protected_payload_size != input.header.payload_length) {
      return Status::error(StatusCode::ProtocolError, "plain control payload length mismatch");
    }
    if (output.payload_size > 0) {
      std::memcpy(output.payload.data(), input.protected_payload.data(), output.payload_size);
    }
    return Status::success();
  }

  if (input.protected_payload_size != input.header.payload_length + kAeadTagSize) {
    return Status::error(StatusCode::ProtocolError, "protected payload length mismatch");
  }
  std::array<std::uint8_t, kEndAadMax> aad{};
  std::size_t aad_size = 0;
  auto status = make_end_aad(input.header, aad, aad_size);
  if (!status) return status;
  std::array<std::uint8_t, kAeadTagSize> end_tag{};
  std::memcpy(end_tag.data(), input.protected_payload.data() + input.header.payload_length,
              end_tag.size());
  return security.open(end_context(input.header), input.header.end_counter,
                       ByteView{aad.data(), aad_size},
                       ByteView{input.protected_payload.data(), input.header.payload_length}, end_tag,
                       MutableByteView{output.payload.data(), output.payload_size});
}

Status forward(const LinkOpenedFrame& input,
               const NodeId local_node,
               const NodeId next_hop,
               const std::uint32_t remaining_deadline_ms,
               SecurityProvider& security,
               EncodedFrame& output) noexcept {
  if (input.header.next_hop != local_node || input.header.destination == local_node) {
    return Status::error(StatusCode::InvalidState, "frame is not forwardable by this node");
  }
  if (input.header.hop_remaining <= 1 || remaining_deadline_ms == 0) {
    return Status::error(StatusCode::Expired, "forwarding budget exhausted");
  }
  Header header = input.header;
  header.previous_hop = local_node;
  header.next_hop = next_hop;
  --header.hop_remaining;
  header.remaining_deadline_ms = std::min(remaining_deadline_ms, header.remaining_deadline_ms);
  auto status = security.next_counter(link_context(header), header.link_counter);
  if (!status) return status;
  return wrap_link(header,
                   ByteView{input.protected_payload.data(), input.protected_payload_size},
                   security, output);
}

}  // namespace routeloom::wire
