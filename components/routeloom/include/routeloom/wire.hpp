#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/security.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

// Frozen "Wire v1" frame format for the CORE_FIXED_250 profile. All fields are
// fixed-width big-endian (network byte order). The crypto suite itself is still
// pending (G-SEC); the layout below does not depend on the chosen suite.
//
// Header layout (kHeaderSize = 88 bytes):
//   offset  size  field                        end-immutable / hop-mutable
//   0       2     magic 0x524C "RL"            immutable
//   2       1     major version (= 1)          immutable
//   3       1     minor version (= 0)          immutable
//   4       1     frame type                   immutable
//   5       1     flags                        immutable
//   6       1     delivery class               immutable (delivery contract)
//   7       1     delivery round               hop-mutable
//   8       1     hop remaining                hop-mutable
//   9       1     reserved, must be 0          -
//   10      2     payload length               immutable (excludes AEAD tags)
//   12      4     network id (low 32 bits)     immutable
//   16      8     origin node id               immutable
//   24      8     destination node id          immutable (bound destination)
//   32      8     previous hop                 hop-mutable
//   40      8     next hop                     hop-mutable
//   48      4     message session (boot session of the origin)   immutable
//   52      8     message sequence             immutable
//   60      4     remaining deadline ms        hop-mutable (forwarding budget)
//   64      4     original lifetime ms         immutable
//   68      2     link epoch                   hop-mutable
//   70      2     end epoch                    immutable
//   72      8     link crypto counter          hop-mutable
//   80      8     end crypto counter           immutable
//   88      n     link ciphertext: payload [+ end tag if kFlagEndProtected]
//   88+n    16    link AEAD tag (AAD covers the complete 88-byte header)
//
// Message ID = origin + session + sequence, delivery round, crypto counters and
// the boot session are distinct fields and must not be conflated.
//
// The link (hop) AEAD authenticates the entire header plus the link plaintext.
// The end-to-end AEAD, when kFlagEndProtected is set, authenticates only the
// end-immutable subset listed above (see protocol/semantics.json end_immutable)
// plus version, end epoch/counter and payload length; hop-mutable fields must
// never enter the end AAD, or relays could not update them.
namespace routeloom::wire {

constexpr std::uint16_t kMagic = 0x524c;  // "RL"
constexpr std::uint8_t kMajor = 1;
constexpr std::uint8_t kMinor = 0;
constexpr std::size_t kHeaderSize = 88;
constexpr std::uint8_t kFlagEndProtected = 0x01;  // all other flag bits reserved, must be 0

// A 128-byte application payload plus the header, the end-to-end tag and the
// link tag must fit the 250-byte ESP-NOW body (248 bytes total).
static_assert(kHeaderSize + kMaxApplicationPayload + 2 * kAeadTagSize <= kMaxEspNowBody,
              "wire v1 envelope must fit the 250-byte ESP-NOW body");

struct Header {
  FrameType type{FrameType::Data};
  std::uint8_t flags{0};
  DeliveryClass delivery{DeliveryClass::Reliable};
  std::uint8_t delivery_round{0};
  std::uint8_t hop_remaining{kDefaultHopLimit};
  std::uint16_t payload_length{0};
  NetworkId network{0};  // v1 encodes the low 32 bits; upper bits must be zero.
  NodeId origin{kInvalidNodeId};
  NodeId destination{kInvalidNodeId};
  NodeId previous_hop{kInvalidNodeId};
  NodeId next_hop{kInvalidNodeId};
  MessageId message{};
  std::uint32_t remaining_deadline_ms{0};
  std::uint32_t original_lifetime_ms{0};
  std::uint16_t link_epoch{0};
  std::uint16_t end_epoch{0};
  std::uint64_t link_counter{0};
  std::uint64_t end_counter{0};
};

struct PlainFrame {
  Header header{};
  std::array<std::uint8_t, kMaxApplicationPayload> payload{};
  std::size_t payload_size{0};
};

struct LinkOpenedFrame {
  Header header{};
  std::array<std::uint8_t, kMaxApplicationPayload + kAeadTagSize> protected_payload{};
  std::size_t protected_payload_size{0};
};

using EncodedFrame = ByteBuffer<kMaxEspNowBody>;

Status validate_header(const Header& header) noexcept;
Status encode_new(const PlainFrame& frame,
                  SecurityProvider& security,
                  EncodedFrame& output) noexcept;
// open_link authenticates ONLY the immediate previous-hop peer under the
// SecurityScope::Link context. Success here does NOT verify the claimed
// origin, the origin-to-destination binding or the payload end-to-end: a
// relay must never treat a link-opened frame as origin-verified. End-to-end
// origin verification exists only through open_end success at the bound
// destination.
Status open_link(ByteView encoded,
                 NodeId local_node,
                 SecurityProvider& security,
                 LinkOpenedFrame& output) noexcept;
// open_end verifies the end-immutable header fields and payload under the
// SecurityScope::EndToEnd context bound to (origin, destination). It must be
// called only by the bound destination — it returns AuthorizationFailed for
// any other node, including relays that already opened the link layer.
Status open_end(const LinkOpenedFrame& frame,
                NodeId local_node,
                SecurityProvider& security,
                PlainFrame& output) noexcept;
Status forward(const LinkOpenedFrame& input,
               NodeId local_node,
               NodeId next_hop,
               std::uint32_t remaining_deadline_ms,
               SecurityProvider& security,
               EncodedFrame& output) noexcept;

// TransitFailure fingerprint (m1-completion 04 §4.2): SHA256 over
// "RouteLoom/transit-fingerprint/v1" || NUL || the exact end-AAD encoding ||
// the protected payload including its end tag. Hop-mutable fields are
// excluded, so every relay on the path computes the SAME fingerprint for
// the same protected bytes — a report cannot be retargeted to a different
// operation without invalidating the fingerprint.
Status transit_fingerprint(const LinkOpenedFrame& frame,
                           std::array<std::uint8_t, 32>& out) noexcept;

}  // namespace routeloom::wire
