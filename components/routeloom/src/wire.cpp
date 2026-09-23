#include "routeloom/wire.hpp"

#include <algorithm>
#include <array>
#include <cstring>

#include "routeloom/byte_io.hpp"
#include "routeloom/discovery_scope.hpp"
#include "routeloom/group.hpp"

namespace routeloom::wire {
namespace {

constexpr std::size_t kEndAadMax = 64;

bool known_frame_type(const std::uint8_t value) noexcept {
  switch (static_cast<FrameType>(value)) {
    case FrameType::Discover:
    case FrameType::Offer:
    case FrameType::BootstrapAuth:
    case FrameType::MembershipResult:
    case FrameType::BootstrapChunk:
    case FrameType::BootstrapReply:
    case FrameType::MembershipQuery:
    case FrameType::Data:
    case FrameType::HopAccept:
    case FrameType::EndReceipt:
    case FrameType::AppResult:
    case FrameType::Busy:
    case FrameType::Service:
    case FrameType::Control:
    case FrameType::TimeSync:
    case FrameType::ChannelNotice:
    case FrameType::GroupData:
    case FrameType::GroupReport:
    case FrameType::RouteUpdate:
    case FrameType::RouteWithdraw:
    case FrameType::SeqnoRequest:
    case FrameType::RouteRequest:
    case FrameType::NeighborProbe:
    case FrameType::NeighborResult:
    case FrameType::Diagnostic:
    case FrameType::ControlObject:
    case FrameType::ObjectChunk:
    case FrameType::ObjectAck:
      return true;
  }
  return false;
}

Status write_header(const Header& header, MutableByteView output) noexcept {
  if (output.size < kHeaderSize) {
    return Status::error(StatusCode::NoCapacity, "wire header output too small");
  }
  if (header.network > UINT32_MAX) {
    return Status::error(StatusCode::InvalidArgument, "v1 network id exceeds 32 bits");
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
  RL_WRITE(writer.write_u32(header.link_epoch));
  RL_WRITE(writer.write_u32(header.end_epoch));
  RL_WRITE(writer.write_u48(header.link_counter));
  RL_WRITE(writer.write_u48(header.end_counter));
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
  RL_READ(reader.read_u32(header.link_epoch));
  RL_READ(reader.read_u32(header.end_epoch));
  RL_READ(reader.read_u48(header.link_counter));
  RL_READ(reader.read_u48(header.end_counter));
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

// End-to-end AAD covers only the end-immutable fields of semantics.json
// (network, origin, message session+sequence, bound destination, delivery
// contract, flags, original lifetime, payload length) plus version, end epoch
// and end counter. Hop-mutable fields (previous/next hop, hop remaining,
// delivery round, remaining deadline, link epoch/counter) must never be added
// here: relays rewrite them and would break the end tag.
Status make_end_aad(const Header& header,
                    std::array<std::uint8_t, kEndAadMax>& bytes,
                    std::size_t& length) noexcept {
  ByteWriter writer(MutableByteView{bytes.data(), bytes.size()});
  Status status;
#define RL_WRITE(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE(writer.write_u8(kMajor));
  RL_WRITE(writer.write_u8(kMinor));
  RL_WRITE(writer.write_u8(static_cast<std::uint8_t>(header.type)));
  RL_WRITE(writer.write_u8(header.flags));
  RL_WRITE(writer.write_u8(static_cast<std::uint8_t>(header.delivery)));
  RL_WRITE(writer.write_u32(static_cast<std::uint32_t>(header.network)));
  RL_WRITE(writer.write_u64(header.origin));
  RL_WRITE(writer.write_u64(header.destination));
  RL_WRITE(writer.write_u32(header.message.session));
  RL_WRITE(writer.write_u64(header.message.sequence));
  RL_WRITE(writer.write_u32(header.original_lifetime_ms));
  RL_WRITE(writer.write_u32(header.end_epoch));
  RL_WRITE(writer.write_u48(header.end_counter));
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
  // GROUP_DATA is end-protected under the group scope: the receiver is the
  // group address, and every key holder may open it (group-delivery.md §7).
  const SecurityScope scope = header.type == FrameType::GroupData
                                  ? SecurityScope::Group
                                  : SecurityScope::EndToEnd;
  return SecurityContext{scope, header.network, header.origin,
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
  // The decoder rejects unknown types and out-of-range delivery classes
  // (read_header): the encoder must never emit a frame its own decoder
  // refuses (wire-protocol.md §unknown-type contract).
  if (!known_frame_type(static_cast<std::uint8_t>(header.type))) {
    return Status::error(StatusCode::InvalidArgument, "unknown frame type");
  }
  if (static_cast<std::uint8_t>(header.delivery) >
      static_cast<std::uint8_t>(DeliveryClass::Applied)) {
    return Status::error(StatusCode::InvalidArgument, "unknown delivery class");
  }
  if (header.network == 0 || header.network > UINT32_MAX ||
      header.origin == kInvalidNodeId || header.destination == kInvalidNodeId ||
      header.previous_hop == kInvalidNodeId || header.next_hop == kInvalidNodeId) {
    return Status::error(StatusCode::InvalidArgument, "wire identity field is invalid");
  }
  if (header.payload_length > kMaxApplicationPayload) {
    return Status::error(StatusCode::InvalidArgument, "payload exceeds v1 limit");
  }
  if (header.hop_remaining == 0 && header.destination != header.next_hop) {
    return Status::error(StatusCode::InvalidArgument, "hop budget exhausted before destination");
  }
  if ((header.flags & ~kFlagEndProtected) != 0) {
    return Status::error(StatusCode::ProtocolError, "unknown wire flags");
  }
  if (header.link_counter > kMaxCryptoCounter ||
      header.end_counter > kMaxCryptoCounter) {
    return Status::error(StatusCode::InvalidArgument, "crypto counter exceeds 48 bits");
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
  if (input.header.type == FrameType::GroupData) {
    // Group frames are opened with open_group(), never as unicast end data.
    return Status::error(StatusCode::AuthorizationFailed, "group frame requires open_group");
  }
  // Callers may build LinkOpenedFrame directly (open_link validates these, but
  // the fields are public): reject sizes that cannot fit the fixed buffers
  // before any length arithmetic or memcpy.
  if (input.header.payload_length > kMaxApplicationPayload ||
      input.protected_payload_size > input.protected_payload.size()) {
    return Status::error(StatusCode::ProtocolError, "frame field out of range");
  }
  output = PlainFrame{};
  output.header = input.header;
  output.payload_size = input.header.payload_length;

  if ((input.header.flags & kFlagEndProtected) == 0) {
    // Link-only frame: the wire layer accepts the plain payload — whether
    // unprotected DATA is admissible is a delivery-layer policy (the mesh
    // node's SecurityProfile drops it in normal mode), not a wire-codec
    // invariant.
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
               const std::uint32_t link_epoch,
               const std::uint32_t remaining_deadline_ms,
               SecurityProvider& security,
               EncodedFrame& output) noexcept {
  if (input.header.next_hop != local_node || input.header.destination == local_node ||
      next_hop == kInvalidNodeId || next_hop == local_node) {
    // next_hop == destination is the normal final hop — only the invalid
    // sentinel and self-forwarding are rejected here.
    return Status::error(StatusCode::InvalidState, "frame is not forwardable by this node");
  }
  // Same defensive bounds as open_end: the fields are public and must be
  // consistent before the protected bytes are re-wrapped.
  const std::size_t expected_plain = static_cast<std::size_t>(input.header.payload_length) +
      (((input.header.flags & kFlagEndProtected) != 0) ? kAeadTagSize : 0U);
  if (input.header.payload_length > kMaxApplicationPayload ||
      input.protected_payload_size != expected_plain) {
    return Status::error(StatusCode::ProtocolError, "frame field out of range");
  }
  if (input.header.hop_remaining <= 1 || remaining_deadline_ms == 0) {
    return Status::error(StatusCode::Expired, "forwarding budget exhausted");
  }
  Header header = input.header;
  header.previous_hop = local_node;
  header.next_hop = next_hop;
  // The link context keys on (previous_hop, next_hop, link_epoch): with
  // boot-advancing epochs the origin's epoch differs from the forwarder's,
  // so the outgoing hop MUST be stamped with OUR epoch — inheriting the
  // incoming one would wedge the downstream link floor either direction
  // (replay REPLAY_EPOCH_STALE, or an irreversible floor ratchet).
  header.link_epoch = link_epoch;
  --header.hop_remaining;
  header.remaining_deadline_ms = std::min(remaining_deadline_ms, header.remaining_deadline_ms);
  auto status = security.next_counter(link_context(header), header.link_counter);
  if (!status) return status;
  return wrap_link(header,
                   ByteView{input.protected_payload.data(), input.protected_payload_size},
                   security, output);
}

Status seal_group(const PlainFrame& input, const NodeId local_node,
                  SecurityProvider& security, LinkOpenedFrame& output) noexcept {
  if (!security.ready()) {
    return Status::error(StatusCode::InvalidState, "security provider is not ready");
  }
  if (input.header.type != FrameType::GroupData ||
      (input.header.flags & kFlagEndProtected) == 0 ||
      !is_group_address(input.header.destination) || local_node == kInvalidNodeId ||
      input.header.origin != local_node || input.header.hop_remaining == UINT8_MAX ||
      input.header.hop_remaining == 0) {
    return Status::error(StatusCode::InvalidArgument, "not a sealable group frame");
  }
  if (input.payload_size > kMaxApplicationPayload) {
    return Status::error(StatusCode::InvalidArgument, "application payload too large");
  }
  Header header = input.header;
  header.payload_length = static_cast<std::uint16_t>(input.payload_size);
  // Shaped like a frame `local_node` just received: forward() re-wraps the
  // link layer per child and spends the extra hop, so children see exactly
  // input.header.hop_remaining.
  header.previous_hop = local_node;
  header.next_hop = local_node;
  header.hop_remaining = static_cast<std::uint8_t>(input.header.hop_remaining + 1U);
  header.link_counter = 0;
  auto status = validate_header(header);
  if (!status) return status;
  status = security.next_counter(end_context(header), header.end_counter);
  if (!status) return status;
  std::array<std::uint8_t, kEndAadMax> aad{};
  std::size_t aad_size = 0;
  status = make_end_aad(header, aad, aad_size);
  if (!status) return status;
  output = LinkOpenedFrame{};
  std::array<std::uint8_t, kAeadTagSize> end_tag{};
  status = security.seal(end_context(header), header.end_counter,
                         ByteView{aad.data(), aad_size},
                         ByteView{input.payload.data(), input.payload_size},
                         MutableByteView{output.protected_payload.data(), input.payload_size},
                         end_tag);
  if (!status) return status;
  std::memcpy(output.protected_payload.data() + input.payload_size, end_tag.data(),
              end_tag.size());
  output.protected_payload_size = input.payload_size + kAeadTagSize;
  output.header = header;
  return Status::success();
}

Status open_group(const LinkOpenedFrame& input, SecurityProvider& security,
                  PlainFrame& output) noexcept {
  if (input.header.type != FrameType::GroupData ||
      (input.header.flags & kFlagEndProtected) == 0 ||
      !is_group_address(input.header.destination)) {
    return Status::error(StatusCode::AuthorizationFailed, "not a group frame");
  }
  if (input.header.payload_length > kMaxApplicationPayload ||
      input.protected_payload_size > input.protected_payload.size() ||
      input.protected_payload_size != input.header.payload_length + kAeadTagSize) {
    return Status::error(StatusCode::ProtocolError, "protected payload length mismatch");
  }
  output = PlainFrame{};
  output.header = input.header;
  output.payload_size = input.header.payload_length;
  std::array<std::uint8_t, kEndAadMax> aad{};
  std::size_t aad_size = 0;
  auto status = make_end_aad(input.header, aad, aad_size);
  if (!status) return status;
  std::array<std::uint8_t, kAeadTagSize> end_tag{};
  std::memcpy(end_tag.data(), input.protected_payload.data() + input.header.payload_length,
              end_tag.size());
  return security.open(end_context(input.header), input.header.end_counter,
                       ByteView{aad.data(), aad_size},
                       ByteView{input.protected_payload.data(), input.header.payload_length},
                       end_tag, MutableByteView{output.payload.data(), output.payload_size});
}

Status transit_fingerprint(const LinkOpenedFrame& frame,
                           std::array<std::uint8_t, 32>& out) noexcept {
  out = {};
  std::array<std::uint8_t, kEndAadMax> aad{};
  std::size_t aad_size = 0;
  Status status = make_end_aad(frame.header, aad, aad_size);
  if (!status) return status;
  if (frame.protected_payload_size > frame.protected_payload.size()) {
    return Status::error(StatusCode::ProtocolError, "protected payload range");
  }
  static constexpr char kDomain[] = "RouteLoom/transit-fingerprint/v1";
  Sha256 hash;
  hash.update(ByteView{reinterpret_cast<const std::uint8_t*>(kDomain),
                       sizeof(kDomain)});  // includes the NUL terminator
  hash.update(ByteView{aad.data(), aad_size});
  hash.update(ByteView{frame.protected_payload.data(),
                       frame.protected_payload_size});
  ScopeDigest digest{};
  hash.finish(digest);
  static_assert(sizeof(digest) == 32, "digest holds a SHA-256");
  std::memcpy(out.data(), digest.data(), 32);
  return Status::success();
}

}  // namespace routeloom::wire
